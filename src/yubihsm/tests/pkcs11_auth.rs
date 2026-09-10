//! Complete channel tests using the same client flow after both preparation paths.
use super::*;
use crate::{
    key_scope::{BoundKey, SymmetricCredential, authentication_aes_template},
    pkcs11_auth::{P256_PARAMS, Pkcs11Auth, ec_template},
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    *,
};

#[derive(Clone, Copy, Debug)]
enum Preparation {
    Private,
    Existing,
}
#[derive(Clone, Copy, Debug)]
enum Protocol {
    Symmetric,
    Asymmetric,
}

struct TemporaryStore(PathBuf);
impl TemporaryStore {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pkcs11-auth-flow-{}-{:016x}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

enum Credential {
    Symmetric(SymmetricCredential),
    Asymmetric(BoundKey),
}
struct Fixture {
    credential: Credential,
    owner: Rc<ProviderSession>,
    keys: Vec<CK_OBJECT_HANDLE>,
    baseline: (Vec<CK_SESSION_HANDLE>, Vec<CK_OBJECT_HANDLE>),
    existing: Option<(
        Arc<std::sync::Mutex<SlotContext>>,
        CK_SESSION_HANDLE,
        TemporaryStore,
    )>,
}
impl Fixture {
    fn new(preparation: Preparation, protocol: Protocol) -> Self {
        let (provider, existing) = match preparation {
            Preparation::Private => (Pkcs11Provider::private_software().unwrap(), None),
            Preparation::Existing => {
                // Provision a normal persistent software slot in the public module.
                // The source has its own application session before auth prepares it.
                let temp = TemporaryStore::new();
                let name = "authentication source".to_owned();
                let store = SoftwareTokenStore::open(name.clone(), temp.0.clone(), None).unwrap();
                let public_master = store.init_token(b"test source SO pin", [b' '; 32]).unwrap();
                store
                    .init_user_pin(b"test source user pin", &public_master)
                    .unwrap();
                drop(public_master);
                drop(store);
                let slot =
                    SoftwareSlot::new_with_storage(name, 0, Some(temp.0.clone()), None).unwrap();
                let _ = api::C_Finalize(std::ptr::null_mut());
                let mut configuration = ModuleConfiguration::private_software().unwrap();
                configuration.software_slots.clear();
                let mut module = ModuleContext::new_with_configuration(configuration).unwrap();
                module.init().unwrap();
                let child = Arc::new(std::sync::Mutex::new(
                    SlotContext::new(
                        99,
                        Box::new(slot),
                        Vec::new(),
                        module.handles.clone(),
                        module.pinentry.clone(),
                        module.trust_store.clone(),
                    )
                    .unwrap(),
                ));
                module
                    .slot_contexts
                    .get_mut()
                    .unwrap()
                    .insert(99, child.clone());
                *crate::lock_context().unwrap() = Some(module);
                let original =
                    api::rust::open_session(99, (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _)
                        .unwrap();
                api::rust::login(
                    original,
                    CKU_USER as _,
                    b"test source user pin".as_ptr(),
                    20,
                )
                .unwrap();
                (
                    Pkcs11Provider::from_slot(child.clone()).unwrap(),
                    Some((child, original, temp)),
                )
            }
        };
        let owner = ProviderSession::open(provider).unwrap();
        let token = matches!(preparation, Preparation::Existing);
        let (credential, keys) = match protocol {
            Protocol::Symmetric => {
                let value = crate::yubico_password_kdf(PASSWORD).unwrap();
                let mut keys = Vec::new();
                // Reverse creation order proves that roles come from labels,
                // not enumeration order or native object IDs.
                for (role, value) in [("mac", &value[16..]), ("enc", &value[..16])] {
                    let mut template = authentication_aes_template();
                    template.token = token;
                    template.label = format!("SCP credential.{role}");
                    keys.push(owner.create(template, &[(CKA_VALUE, value)]).unwrap());
                }
                let pair =
                    SymmetricCredential::find(owner.clone(), "SCP credential", token).unwrap();
                (Credential::Symmetric(pair), keys)
            }
            Protocol::Asymmetric => {
                let private = crate::yubico_kdf::yubico_password_p256_key(PASSWORD).unwrap();
                let value = private.serialized().unwrap();
                let mut template = ec_template();
                template.token = token;
                template.label = "SCP credential".to_owned();
                let key = owner
                    .create(
                        template,
                        &[(CKA_VALUE, &value), (CKA_EC_PARAMS, P256_PARAMS)],
                    )
                    .unwrap();
                (
                    Credential::Asymmetric(BoundKey::from_session(owner.clone(), key).unwrap()),
                    vec![key],
                )
            }
        };
        let baseline = Self::snapshot(&owner);
        let fixture = Self {
            credential,
            owner,
            keys,
            baseline,
            existing,
        };
        fixture.assert_clean();
        fixture
    }
    fn snapshot(owner: &ProviderSession) -> (Vec<CK_SESSION_HANDLE>, Vec<CK_OBJECT_HANDLE>) {
        owner
            .call(|| {
                with_session_context(owner.handle, |ctx| {
                    let mut sessions: Vec<_> = ctx.sessions.keys().copied().collect();
                    let mut objects: Vec<_> = ctx.memory_objects.keys().copied().collect();
                    sessions.sort_unstable();
                    objects.sort_unstable();
                    Ok((sessions, objects))
                })
            })
            .unwrap()
    }
    fn assert_clean(&self) {
        assert_eq!(Self::snapshot(&self.owner), self.baseline);
        for key in &self.keys {
            assert_eq!(
                self.owner.attribute(*key, CKA_TOKEN).unwrap().as_slice(),
                &[u8::from(self.existing.is_some())]
            );
            assert!(
                matches!(self.owner.attribute(*key, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
            );
        }
    }

    fn release(self) {
        self.assert_clean();
        let Self {
            credential,
            owner,
            keys,
            existing,
            ..
        } = self;
        let provider = Rc::downgrade(&owner.provider);
        drop(credential);
        drop(owner);
        assert!(provider.upgrade().is_none());
        if let Some((child, original, temp)) = existing {
            {
                let context = child.lock().unwrap();
                assert_eq!(context.sessions.len(), 1);
                assert!(context.sessions.contains_key(&original));
                for key in keys {
                    assert!(context.resolve_object(key).unwrap().is_some());
                }
                assert!(context.memory_objects.is_empty());
            }
            api::rust::close_session(original).unwrap();
            assert_eq!(api::C_Finalize(std::ptr::null_mut()), CKR_OK as CK_RV);
            drop(child);
            drop(temp);
        }
    }
}

// Both preparations feed exactly this channel-establishment sequence. Only
// the peer implements the other end of SCP; it does not use Pkcs11Auth.
fn authenticate(
    fixture: &Fixture,
    protocol: Protocol,
    peer: &ProtocolPeer,
    bad_receipt: bool,
) -> Result<SecureSession, Error> {
    match (&fixture.credential, protocol) {
        (Credential::Symmetric(credential), Protocol::Symmetric) => {
            let handshake = SecureSession::begin_symmetric(peer, 1, HOST_CHALLENGE)?;
            SecureSession::complete_symmetric_with_static_keys(peer, handshake, credential)
        }
        (Credential::Asymmetric(credential), Protocol::Asymmetric) => {
            let mut exchange = AsymmetricKeys::for_key(credential)?;
            let mut handshake = SecureSession::begin_asymmetric(peer, 1, &exchange.public_key()?)?;
            if bad_receipt {
                handshake.receipt[0] ^= 1;
            }
            let result = (|| {
                // This fixture's static peer key is the explicitly trusted anchor.
                let shared = exchange.static_agreement(credential, &peer.device_public_key()?)?;
                exchange.finish(&shared, &handshake.context, &handshake.receipt)
            })();
            match result {
                Ok(keys) => Ok(SecureSession::complete_asymmetric(handshake, keys)),
                Err(error) => {
                    SecureSession::close_failed_asymmetric_handshake(peer, handshake);
                    Err(error)
                }
            }
        }
        _ => panic!("credential protocol mismatch"),
    }
}

fn target(protocol: Protocol) -> ProtocolPeer {
    let peer = ProtocolPeer::new();
    if matches!(protocol, Protocol::Asymmetric) {
        peer.use_asymmetric_authentication(1);
    }
    peer
}

fn exercise(preparation: Preparation, protocol: Protocol) {
    let fixture = Fixture::new(preparation, protocol);
    let peer = target(protocol);
    let mut channel = authenticate(&fixture, protocol, &peer, false).unwrap();
    fixture.assert_clean();
    let message: Vec<_> = (0..257).map(|i| i as u8).collect();
    for _ in 0..3 {
        assert_eq!(
            channel
                .send_command(&peer, &Command::echo(&message).unwrap())
                .unwrap(),
            message
        );
    }
    assert!(
        channel
            .send_command(&peer, &Command::close_session())
            .unwrap()
            .is_empty()
    );
    assert!(!channel.is_valid());
    assert!(channel.keys.is_empty());
    fixture.assert_clean();

    // The same source credential works after successful handshake cleanup.
    let peer = target(protocol);
    let mut channel = authenticate(&fixture, protocol, &peer, false).unwrap();
    peer.corrupt_response_mac.set(true);
    assert!(
        matches!(channel.send_command(&peer, &Command::echo(b"tamper").unwrap()), Err(Error::Generic(rv)) if rv == CKR_DEVICE_ERROR as CK_RV)
    );
    assert!(!channel.is_valid());
    assert!(channel.keys.is_empty());
    let sent = peer.commands.borrow().len();
    assert!(
        matches!(channel.send_command(&peer, &Command::get_storage_info()),
        Err(Error::Generic(rv)) if rv == CKR_SESSION_CLOSED as CK_RV)
    );
    assert_eq!(peer.commands.borrow().len(), sent);
    fixture.assert_clean();

    let peer = target(protocol);
    if matches!(protocol, Protocol::Symmetric) {
        peer.corrupt_card_cryptogram.set(true);
    }
    let result = authenticate(&fixture, protocol, &peer, true);
    let expected = if matches!(protocol, Protocol::Symmetric) {
        CKR_ENCRYPTED_DATA_INVALID
    } else {
        CKR_SIGNATURE_INVALID
    };
    assert!(matches!(result, Err(Error::Generic(rv)) if rv == expected as CK_RV));
    assert!(!peer.has_active_session());
    fixture.assert_clean();

    // Established channels use their local working keys after all auth-owned
    // sessions and objects are released, including the private slot itself.
    let peer = target(protocol);
    let mut channel = authenticate(&fixture, protocol, &peer, false).unwrap();
    fixture.release();
    assert_eq!(
        channel
            .send_command(&peer, &Command::echo(b"after source release").unwrap())
            .unwrap(),
        b"after source release"
    );
    channel
        .send_command(&peer, &Command::close_session())
        .unwrap();
    assert!(channel.keys.is_empty());
}

#[test]
fn symmetric_complete_channel_uses_private_and_existing_pkcs11_auth() {
    let _guard = crate::test::TEST_LOCK.lock().unwrap();
    for preparation in [Preparation::Private, Preparation::Existing] {
        exercise(preparation, Protocol::Symmetric);
    }
}
#[test]
fn asymmetric_complete_channel_uses_private_and_existing_pkcs11_auth() {
    let _guard = crate::test::TEST_LOCK.lock().unwrap();
    for preparation in [Preparation::Private, Preparation::Existing] {
        exercise(preparation, Protocol::Asymmetric);
    }
}
