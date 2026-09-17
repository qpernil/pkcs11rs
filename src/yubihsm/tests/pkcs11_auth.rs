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
    SymmetricEcb,
    SymmetricCbc,
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
    owner: Arc<ProviderSession>,
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
            Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc => {
                let value = crate::yubico_password_kdf(PASSWORD).unwrap();
                let mut keys = Vec::new();
                // Reverse creation order proves that roles come from labels,
                // not enumeration order or native object IDs.
                for (role, value) in [("mac", &value[16..]), ("enc", &value[..16])] {
                    let mut template = authentication_aes_template();
                    if matches!(protocol, Protocol::SymmetricEcb | Protocol::SymmetricCbc) {
                        template.derive = false;
                        template.encrypt = true;
                        template.allowed_mechanisms =
                            Some(if matches!(protocol, Protocol::SymmetricCbc) {
                                vec![CKM_AES_ECB as _, CKM_AES_CBC as _]
                            } else {
                                vec![CKM_AES_ECB as _]
                            });
                    }
                    template.token = token;
                    template.label = format!("SCP credential.{role}");
                    // AES roles are selected by exact labels, independently of IDs.
                    template.id = role.as_bytes().to_vec();
                    keys.push(owner.create(template, &[(CKA_VALUE, value)]).unwrap());
                }
                let pair =
                    SymmetricCredential::find(owner.clone(), "SCP credential.enc", token).unwrap();
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
        let provider = Arc::downgrade(&owner.provider);
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
        (
            Credential::Symmetric(credential),
            Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc,
        ) => {
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
    if matches!(
        protocol,
        Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc
    ) {
        peer.corrupt_card_cryptogram.set(true);
    }
    let result = authenticate(&fixture, protocol, &peer, true);
    let expected = if matches!(
        protocol,
        Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc
    ) {
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
        exercise(preparation, Protocol::SymmetricEcb);
        exercise(preparation, Protocol::SymmetricCbc);
    }
}
#[test]
fn asymmetric_complete_channel_uses_private_and_existing_pkcs11_auth() {
    let _guard = crate::test::TEST_LOCK.lock().unwrap();
    for preparation in [Preparation::Private, Preparation::Existing] {
        exercise(preparation, Protocol::Asymmetric);
    }
}

#[test]
fn registered_software_source_requires_application_authorization_for_both_protocols() {
    let _serial = crate::test::TEST_LOCK.lock().unwrap();
    for protocol in [
        Protocol::Symmetric,
        Protocol::SymmetricEcb,
        Protocol::SymmetricCbc,
        Protocol::Asymmetric,
    ] {
        let mut fixture = Fixture::new(Preparation::Existing, protocol);
        let child = fixture.existing.as_ref().unwrap().0.clone();
        let serial = child.lock().unwrap().slot.serial().to_owned();
        let peer = Rc::new(target(protocol));
        let mut slot = YubiHsmSlot::new(peer.clone(), (2, 4, 1), Vec::new());
        slot.auth_slots.register(&child).unwrap();
        slot.recreate_sessions = true;
        let object = if matches!(protocol, Protocol::Asymmetric) {
            "SCP%20credential;type=private"
        } else {
            "SCP%20credential.enc;type=secret-key"
        };
        let selector = format!("pkcs11:serial={serial};object={object}?pkcs11rs-authkey=0001");
        assert_eq!(
            fixture.owner.call(|| api::C_Logout(fixture.owner.handle)),
            CKR_OK as CK_RV
        );
        assert!(matches!(
            login_user_slot(&mut slot, 7, selector.as_bytes(), b"not forwarded", &[]),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as CK_RV
        ));
        assert_eq!(peer.create_session_count(), 0);
        assert!(!child.lock().unwrap().slot.login_is_active());
        fixture.owner.login(b"test source user pin").unwrap();
        login_user_slot(
            &mut slot,
            7,
            selector.as_bytes(),
            b"unrelated target pin",
            &[],
        )
        .unwrap();
        assert_eq!(peer.create_session_count(), 1);
        let selected = Slot::authenticated_credential_description(&slot).unwrap();
        let selected = crate::pkcs11_uri::ClientAuthUri::parse(selected.as_bytes()).unwrap();
        assert_eq!(selected.authkey_id, Some(1));
        if matches!(protocol, Protocol::Asymmetric) {
            assert_eq!(
                selected.object.as_deref(),
                Some(b"SCP credential".as_slice())
            );
            assert_eq!(selected.class, Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS));
        } else {
            assert_eq!(
                selected.object.as_deref(),
                Some(b"SCP credential.enc".as_slice())
            );
            assert_eq!(selected.class, Some(CKO_SECRET_KEY as CK_OBJECT_CLASS));
            assert!(selected.id.is_none());
        }
        peer.expire_next_session_message.set(true);
        assert!(
            !send_yubihsm_secure_command(
                peer.as_ref(),
                slot.session.as_ref(),
                &Command::get_storage_info()
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(peer.create_session_count(), 2);
        Slot::logout(&mut slot).unwrap();
        // A source authorized by the application is reused without submitting
        // the target PIN to that source token.
        login_user_slot(&mut slot, 7, selector.as_bytes(), b"not resubmitted", &[]).unwrap();
        Slot::logout(&mut slot).unwrap();
        let discovery_label = if matches!(protocol, Protocol::Asymmetric) {
            "SCP credential"
        } else {
            "SCP credential.enc"
        };
        slot.public_discovery_config = configured_yubihsm_public_discovery_credential(Some(
            format!(":0001{discovery_label}@{serial}:test source user pin").into(),
        ))
        .unwrap();
        assert_eq!(
            fixture.owner.call(|| api::C_Logout(fixture.owner.handle)),
            CKR_OK as CK_RV
        );
        fixture.owner.login(b"test source user pin").unwrap();
        assert!(!Slot::token_objects(&slot, 7).unwrap().is_empty());
        assert!(matches!(
            slot.object_cache.borrow().discovery,
            YubiHsmDiscoveryCache::Available { .. }
        ));
        Slot::clear_session(&mut slot);
        drop(slot);
        // Logout invalidates old private handles; re-resolve the same persistent
        // objects before checking that authentication left the source intact.
        fixture.keys = fixture
            .owner
            .find(&[
                (CKA_TOKEN, &[CK_TRUE as u8]),
                (
                    CKA_CLASS,
                    &((if matches!(
                        protocol,
                        Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc
                    ) {
                        CKO_SECRET_KEY
                    } else {
                        CKO_PRIVATE_KEY
                    }) as CK_ULONG)
                        .to_ne_bytes(),
                ),
            ])
            .unwrap();
        assert_eq!(
            fixture.keys.len(),
            if matches!(
                protocol,
                Protocol::Symmetric | Protocol::SymmetricEcb | Protocol::SymmetricCbc
            ) {
                2
            } else {
                1
            }
        );
        fixture.release();
    }
}

#[test]
fn authorized_yubihsm_source_authenticates_another_yubihsm() {
    nested_yubihsm_authentication(DerivationPersona::SessionObjects);
}

#[test]
fn yubihsm_source_uses_prefixed_ecdh_persona() {
    nested_yubihsm_authentication(DerivationPersona::PrefixedEcdh);
}

#[test]
fn yubihsm_source_uses_basic_ecdh_persona() {
    nested_yubihsm_authentication(DerivationPersona::BasicEcdh);
}

#[test]
fn yubihsm_source_rejects_authentication_without_derivation_permission() {
    nested_yubihsm_authentication(DerivationPersona::Unavailable);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DerivationPersona {
    SessionObjects,
    PrefixedEcdh,
    BasicEcdh,
    Unavailable,
}

fn nested_yubihsm_authentication(persona: DerivationPersona) {
    const SOURCE_AUTHKEY_ID: u16 = 0x1004;
    const TARGET_AUTHKEY_ID: u16 = 0x1101;
    const CLIENT_LABEL: &str = "nested YubiHSM client";

    let _serial = crate::test::TEST_LOCK.lock().unwrap();
    let host_credential = Arc::new(SoftwarePlatformCredential(
        test_private_key(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 7,
        ])
        .unwrap(),
    ));
    let SoftwarePublicKey::Ec {
        uncompressed: host_public,
        ..
    } = host_credential.0.public_key()
    else {
        panic!("host test credential must be P-256")
    };

    let host = crate::backend::host::HostSlot::with_keys(vec![(
        "nested host".to_owned(),
        host_credential,
    )]);
    let host_login = crate::pkcs11_uri::authentication_uri(
        &crate::pkcs11_uri::object_uri_parts(
            &host,
            CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            b"nested host",
            b"",
        ),
        SOURCE_AUTHKEY_ID,
    );
    let host_context = ModuleContext::private_slot(Box::new(host)).unwrap();
    let host_slot = host_context
        .slot_contexts
        .read()
        .unwrap()
        .get(&1)
        .unwrap()
        .clone();
    let host_owner =
        ProviderSession::open(Pkcs11Provider::from_slot(host_slot.clone()).unwrap()).unwrap();
    host_owner.login(b"ignored by Host").unwrap();

    let source_peer = Rc::new(ProtocolPeer::new());
    source_peer
        .native_session_commands
        .set(persona == DerivationPersona::SessionObjects);
    source_peer.native_ecdh_commands.set(true);
    source_peer
        .provision_asymmetric_authentication_public_key(SOURCE_AUTHKEY_ID, &host_public)
        .unwrap();
    let capabilities = virtual_yubihsm_core::CapabilitySet::from_capabilities(
        [virtual_yubihsm_core::Capability::GetPseudoRandom]
            .into_iter()
            .chain(match persona {
                DerivationPersona::SessionObjects => vec![
                    virtual_yubihsm_core::Capability::SessionObjects,
                    virtual_yubihsm_core::Capability::DeriveEcdh,
                ],
                DerivationPersona::PrefixedEcdh => {
                    vec![virtual_yubihsm_core::Capability::DeriveEcdhKdf]
                }
                DerivationPersona::BasicEcdh => {
                    vec![virtual_yubihsm_core::Capability::DeriveEcdh]
                }
                DerivationPersona::Unavailable => Vec::new(),
            }),
    );
    let mut authkey = source_peer
        .device
        .borrow()
        .objects()
        .find(|object| object.info.id == SOURCE_AUTHKEY_ID)
        .unwrap()
        .clone();
    authkey.info.capabilities = capabilities;
    authkey.info.delegated_capabilities = VirtualCapabilitySet::NONE;
    source_peer
        .device
        .borrow_mut()
        .provision_object(authkey)
        .unwrap();
    source_peer
        .visible_authkey_info
        .borrow_mut()
        .get_mut(&SOURCE_AUTHKEY_ID)
        .unwrap()
        .capabilities = capabilities.to_bytes();
    let client_private = crate::yubico_kdf::yubico_password_p256_key(PASSWORD).unwrap();
    let SoftwarePublicKey::Ec {
        uncompressed: client_public,
        ..
    } = client_private.public_key()
    else {
        panic!("client test credential must be P-256")
    };
    let client_capabilities = VirtualCapabilitySet::from_capabilities(match persona {
        DerivationPersona::PrefixedEcdh => {
            vec![virtual_yubihsm_core::Capability::DeriveEcdhKdf]
        }
        DerivationPersona::SessionObjects
        | DerivationPersona::BasicEcdh
        | DerivationPersona::Unavailable => {
            vec![virtual_yubihsm_core::Capability::DeriveEcdh]
        }
    });
    source_peer
        .device
        .borrow_mut()
        .provision_object(VirtualObjectRecord {
            info: VirtualObjectInfo {
                capabilities: client_capabilities,
                id: TARGET_AUTHKEY_ID,
                length: 96,
                domains: u16::MAX,
                object_type: VirtualObjectType::AsymmetricKey,
                algorithm: YUBIHSM_ALGO_EC_P256,
                sequence: 1,
                origin: 2,
                label: CLIENT_LABEL.as_bytes().to_vec(),
                delegated_capabilities: VirtualCapabilitySet::NONE,
            },
            material: VirtualObjectMaterial::SigningKey(client_private),
        })
        .unwrap();
    source_peer.metadata_objects.borrow_mut().insert(
        TARGET_AUTHKEY_ID,
        (
            ObjectInfo {
                capabilities: client_capabilities.to_bytes(),
                id: TARGET_AUTHKEY_ID,
                length: 96,
                domains: u16::MAX,
                object_type: YUBIHSM_ASYMMETRIC_KEY,
                algorithm: YUBIHSM_ALGO_EC_P256,
                sequence: 1,
                origin: 2,
                label: CLIENT_LABEL.to_owned(),
                delegated_capabilities: [0; 8],
            },
            Vec::new(),
        ),
    );
    let source_auth_slots = Arc::new(crate::auth_slots::AuthSlots::default());
    source_auth_slots.register(&host_slot).unwrap();
    let source_backend = YubiHsmSlot::with_auth_slots_and_public_discovery(
        source_peer.clone(),
        (2, 5, 0),
        vec![YUBIHSM_ALGO_EC_P256],
        source_auth_slots,
        None,
    );
    let source_context = ModuleContext::private_slot(Box::new(source_backend)).unwrap();
    let source_slot = source_context
        .slot_contexts
        .read()
        .unwrap()
        .get(&1)
        .unwrap()
        .clone();
    let source_owner =
        ProviderSession::open(Pkcs11Provider::from_slot(source_slot.clone()).unwrap()).unwrap();
    let mut host_login = host_login.into_bytes();
    assert_eq!(
        source_owner.call(|| api::C_LoginUser(
            source_owner.handle,
            CKU_USER as _,
            std::ptr::null_mut(),
            0,
            host_login.as_mut_ptr(),
            host_login.len() as _,
        )),
        CKR_OK as CK_RV
    );
    assert!(!source_owner.authorization_required().unwrap());
    assert_eq!(
        source_owner.supports_native_session_derivation().unwrap(),
        persona == DerivationPersona::SessionObjects,
        "source commands: {:?}",
        source_peer.inner_commands.borrow()
    );
    source_slot
        .lock()
        .unwrap()
        .refresh_slot_token_objects(1)
        .unwrap();
    let private = source_owner
        .find(&[
            (CKA_TOKEN, &[CK_TRUE as u8]),
            (CKA_CLASS, &(CKO_PRIVATE_KEY as CK_ULONG).to_ne_bytes()),
            (CKA_KEY_TYPE, &(CKK_EC as CK_ULONG).to_ne_bytes()),
            (CKA_LABEL, CLIENT_LABEL.as_bytes()),
            (CKA_ID, &TARGET_AUTHKEY_ID.to_be_bytes()),
        ])
        .unwrap();
    let [private] = private.as_slice() else {
        panic!("provisioned YubiHSM private key must be visible after login")
    };
    let mut public_projection = source_slot
        .lock()
        .unwrap()
        .resolve_object(*private)
        .unwrap()
        .unwrap()
        .clone();
    public_projection.unique_id.push_str("-public-test");
    public_projection.class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    public_projection.private = false;
    public_projection.sign = false;
    public_projection.derive = false;
    public_projection.sensitive = false;
    public_projection.extractable = true;
    public_projection.always_sensitive = false;
    public_projection.never_extractable = false;
    public_projection.material = KeyMaterial::Public(PublicKeyMaterial::Ec {
        parameters: P256_PARAMS.to_vec(),
        public_key: client_public[1..].to_vec(),
    });
    source_slot
        .lock()
        .unwrap()
        .insert_object(public_projection)
        .unwrap();
    let public = source_owner
        .find(&[
            (CKA_TOKEN, &[CK_TRUE as u8]),
            (CKA_CLASS, &(CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes()),
            (CKA_KEY_TYPE, &(CKK_EC as CK_ULONG).to_ne_bytes()),
            (CKA_LABEL, CLIENT_LABEL.as_bytes()),
            (CKA_ID, &TARGET_AUTHKEY_ID.to_be_bytes()),
        ])
        .unwrap();
    let [public] = public.as_slice() else {
        panic!("provisioned YubiHSM private key must have one public projection")
    };
    let point = source_owner.attribute(*public, CKA_EC_POINT).unwrap();
    assert_eq!(&point[..3], &[4, 65, 4]);
    let source_uri = String::from_utf8(
        source_owner
            .attribute(*private, CKA_PKCS11RS_URI as u32)
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let target_peer = Rc::new(ProtocolPeer::new());
    target_peer
        .provision_asymmetric_authentication_public_key(TARGET_AUTHKEY_ID, &point[2..])
        .unwrap();
    let mut target = YubiHsmSlot::new(target_peer.clone(), (2, 5, 0), Vec::new());
    target.auth_slots.register(&source_slot).unwrap();
    source_peer.refresh_changes_epoch.set(true);
    let target_login = crate::pkcs11_uri::authentication_uri(&source_uri, TARGET_AUTHKEY_ID);
    crate::key_scope::take_authentication_paths();
    let result = login_user_slot(&mut target, 7, target_login.as_bytes(), b"", &[]);
    if persona == DerivationPersona::Unavailable {
        assert!(result.is_err(), "unexpected result: {result:?}");
        // The source login does not authorize any usable derivation path.
        assert!(!Slot::login_is_active(&target));
        assert_eq!(
            source_peer
                .inner_commands
                .borrow()
                .iter()
                .filter(|(command, _)| { *command == CommandCode::SessionObject as u8 })
                .count(),
            0
        );
        assert!(Slot::login_is_active(&*source_slot.lock().unwrap().slot));
        return;
    }
    result.unwrap();
    let paths = crate::key_scope::take_authentication_paths();
    let expected_path = match persona {
        DerivationPersona::SessionObjects => "native-protected-graph",
        DerivationPersona::PrefixedEcdh => "literal-prefix-derive",
        DerivationPersona::BasicEcdh => "basic-ecdh",
        DerivationPersona::Unavailable => unreachable!(),
    };
    assert!(paths.contains(&expected_path), "observed {paths:?}");
    assert_eq!(
        paths.iter().filter(|path| **path == expected_path).count(),
        1
    );
    assert_eq!(target_peer.create_session_count(), 1);
    assert!(Slot::login_is_active(&target));
    Slot::logout(&mut target).unwrap();
    assert!(Slot::login_is_active(&*source_slot.lock().unwrap().slot));
    drop(source_owner);
    drop(host_owner);
}

#[test]
fn source_eligibility_skips_unauthorized_slots_and_accepts_no_login_slots() {
    let _serial = crate::test::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new(Preparation::Existing, Protocol::Asymmetric);
    let child = fixture.existing.as_ref().unwrap().0.clone();
    let Credential::Asymmetric(private) = &fixture.credential else {
        unreachable!()
    };
    let mut scope = crate::key_scope::Pkcs11KeyScope::for_key(private).unwrap();
    let private = scope.bind(private).unwrap();
    let mut encoded = vec![4, 65];
    encoded.extend_from_slice(&scope.p256_public(&private).unwrap());
    fixture
        .owner
        .create(
            TokenObjectTemplate {
                class: Some(CKO_PUBLIC_KEY as _),
                key_type: Some(CKK_EC as _),
                token: true,
                label: "SCP credential".to_owned(),
                ..Default::default()
            },
            &[(CKA_EC_PARAMS, P256_PARAMS), (CKA_EC_POINT, &encoded)],
        )
        .unwrap();
    drop(scope);
    let sources = crate::auth_slots::AuthSlots::default();
    sources.register(&child).unwrap();
    let selector =
        crate::pkcs11_uri::ClientAuthUri::parse(b"pkcs11:object=SCP%20credential;type=private")
            .unwrap();
    let target = std::sync::Weak::<std::sync::Mutex<SlotContext>>::new();

    assert_eq!(
        fixture.owner.call(|| api::C_Logout(fixture.owner.handle)),
        CKR_OK as CK_RV
    );
    let attempts = std::cell::Cell::new(0);
    assert!(
        sources
            .find_ordinary_credential(&selector, &target, |_| {
                attempts.set(attempts.get() + 1);
                Ok(Some(()))
            })
            .unwrap()
            .is_none()
    );
    assert_eq!(attempts.get(), 0);

    fixture.owner.login(b"test source user pin").unwrap();
    assert!(
        sources
            .find_ordinary_credential(&selector, &target, |_| {
                attempts.set(attempts.get() + 1);
                Ok(Some(()))
            })
            .unwrap()
            .is_some()
    );
    assert_eq!(attempts.get(), 1);
    fixture.keys = fixture
        .owner
        .find(&[
            (CKA_TOKEN, &[CK_TRUE as u8]),
            (CKA_CLASS, &(CKO_PRIVATE_KEY as CK_ULONG).to_ne_bytes()),
        ])
        .unwrap();
    fixture.release();

    let native =
        crate::auth_slots::AuthSlots::from_native_fixtures(vec![symmetric_hsmauth_provider(
            "12345678",
        )]);
    let wildcard = crate::pkcs11_uri::ClientAuthUri::parse(b"pkcs11:").unwrap();
    let native_attempts = std::cell::Cell::new(0);
    assert!(
        native
            .find_hsmauth_credential(&wildcard, false, |_| {
                native_attempts.set(native_attempts.get() + 1);
                Ok(Some(()))
            })
            .unwrap()
            .is_some()
    );
    assert_eq!(native_attempts.get(), 1);
}

#[test]
fn ordinary_asymmetric_pair_requires_both_label_and_id() {
    let _serial = crate::test::TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new(Preparation::Existing, Protocol::Asymmetric);
    let child = fixture.existing.as_ref().unwrap().0.clone();
    let sources = crate::auth_slots::AuthSlots::default();
    sources.register(&child).unwrap();
    let Credential::Asymmetric(key) = &fixture.credential else {
        unreachable!()
    };
    let mut scope = crate::key_scope::Pkcs11KeyScope::for_key(key).unwrap();
    let bound = scope.bind(key).unwrap();
    let point = scope.p256_public(&bound).unwrap();
    drop(scope);
    let mut encoded = vec![4, 65];
    encoded.extend_from_slice(&point);
    let value = crate::yubico_kdf::yubico_password_p256_key(PASSWORD)
        .unwrap()
        .serialized()
        .unwrap();
    // Empty IDs still have to match. A unique ID alone must not authorize
    // a differently named key, even when it has the same public point.
    for (index, (same_label, private_id, public_id, matches)) in [
        (true, b"".as_slice(), b"".as_slice(), true),
        (true, b"private", b"", false),
        (true, b"private", b"public", false),
        (false, b"same", b"same", false),
        (true, b"same", b"same", true),
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("pair {index}");
        let public = fixture
            .owner
            .create(
                TokenObjectTemplate {
                    class: Some(CKO_PUBLIC_KEY as _),
                    key_type: Some(CKK_EC as _),
                    token: true,
                    label: label.clone(),
                    id: public_id.to_vec(),
                    ..Default::default()
                },
                &[(CKA_EC_PARAMS, P256_PARAMS), (CKA_EC_POINT, &encoded)],
            )
            .unwrap();
        let private = fixture
            .owner
            .create(
                TokenObjectTemplate {
                    token: true,
                    label: if same_label {
                        label.clone()
                    } else {
                        format!("{label} other")
                    },
                    id: private_id.to_vec(),
                    ..ec_template()
                },
                &[(CKA_VALUE, &value), (CKA_EC_PARAMS, P256_PARAMS)],
            )
            .unwrap();
        let mut candidates = sources
            .ordinary_credentials(
                &crate::pkcs11_uri::ClientAuthUri {
                    object: Some(label.as_bytes().to_vec()),
                    authkey_id: Some(1),
                    ..Default::default()
                },
                &std::sync::Weak::new(),
            )
            .unwrap();
        assert_eq!(candidates.len(), 1);
        let result = candidates.pop().unwrap().authorize(None);
        if matches {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(Error::Generic(rv)) if rv == CKR_KEY_HANDLE_INVALID as CK_RV)
            );
        }
        drop(result);
        if !same_label {
            // A published EC candidate must not turn into an AES credential
            // just because its private-key pairing failed.
            let mut aes = Vec::new();
            for role in ["enc", "mac"] {
                aes.push(
                    fixture
                        .owner
                        .create(
                            TokenObjectTemplate {
                                token: true,
                                label: format!("{label}.{role}"),
                                ..authentication_aes_template()
                            },
                            &[(CKA_VALUE, &[0x42; 16])],
                        )
                        .unwrap(),
                );
            }
            let selected = sources
                .ordinary_credentials(
                    &crate::pkcs11_uri::ClientAuthUri {
                        object: Some(label.as_bytes().to_vec()),
                        authkey_id: Some(1),
                        ..Default::default()
                    },
                    &std::sync::Weak::new(),
                )
                .unwrap()
                .pop()
                .unwrap();
            assert!(matches!(selected.authorize(None),
                Err(Error::Generic(rv)) if rv == CKR_KEY_HANDLE_INVALID as CK_RV));
            let selected = sources
                .ordinary_credentials(
                    &crate::pkcs11_uri::ClientAuthUri {
                        object: Some(label.as_bytes().to_vec()),
                        class: Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS),
                        authkey_id: Some(1),
                        ..Default::default()
                    },
                    &std::sync::Weak::new(),
                )
                .unwrap()
                .pop()
                .unwrap();
            assert!(matches!(selected.authorize(None),
                Err(Error::Generic(rv)) if rv == CKR_KEY_HANDLE_INVALID as CK_RV));
            let base_secret = sources
                .ordinary_credentials(
                    &crate::pkcs11_uri::ClientAuthUri {
                        object: Some(label.as_bytes().to_vec()),
                        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
                        authkey_id: Some(1),
                        ..Default::default()
                    },
                    &std::sync::Weak::new(),
                )
                .unwrap();
            assert!(base_secret.is_empty());
            let selected = sources
                .ordinary_credentials(
                    &crate::pkcs11_uri::ClientAuthUri {
                        object: Some(format!("{label}.enc").into_bytes()),
                        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
                        authkey_id: Some(1),
                        ..Default::default()
                    },
                    &std::sync::Weak::new(),
                )
                .unwrap()
                .pop()
                .unwrap();
            let selected_uri = selected.description();
            let parsed = crate::pkcs11_uri::ClientAuthUri::parse(selected_uri.as_bytes()).unwrap();
            assert_eq!(
                parsed.object.as_deref(),
                Some(format!("{label}.enc").as_bytes())
            );
            assert!(matches!(
                selected.authorize(None),
                Ok(YubiHsmPkcs11AuthenticationMaterial::Symmetric(_))
            ));
            for invalid_label in [label.clone(), format!("{label}.mac")] {
                assert!(
                    sources
                        .ordinary_credentials(
                            &crate::pkcs11_uri::ClientAuthUri {
                                object: Some(invalid_label.into_bytes()),
                                class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
                                authkey_id: Some(1),
                                ..Default::default()
                            },
                            &std::sync::Weak::new(),
                        )
                        .unwrap()
                        .is_empty()
                );
            }
            for handle in aes {
                fixture.owner.destroy(handle).unwrap();
            }
        }
        fixture.owner.destroy(public).unwrap();
        fixture.owner.destroy(private).unwrap();
    }
    fixture.release();
}
