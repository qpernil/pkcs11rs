use super::*;
use crate::secure_channel_crypto::{aes_cmac, aes_encrypt_block, scp03_kdf};
use software_key_core::{
    secure_channel::x963_kdf_sha256, software_key_agreement::derive_with_signing_key,
};

fn ec(scalar: u8) -> SoftwareSigningKey {
    let mut encoded = [0; 32];
    encoded[31] = scalar;
    SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), &encoded).unwrap()
}
fn public(key: &SoftwareSigningKey) -> Vec<u8> {
    let SoftwarePublicKey::Ec { uncompressed, .. } = key.public_key() else {
        panic!("EC fixture")
    };
    uncompressed
}
fn credential(value: &[u8], mechanism: CK_MECHANISM_TYPE) -> BoundKey {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let handle = scope
        .import_secret(value, generic_template(&[mechanism]))
        .unwrap();
    scope.take_key(&handle).unwrap()
}
fn check_keys(keys: &SessionKeys, enc: &[u8], mac: &[u8], rmac: &[u8]) {
    assert!(!keys.is_empty());
    assert_eq!(
        keys.iv(&[0; 16]).unwrap(),
        aes_encrypt_block(enc, &[0; 16]).unwrap()
    );
    assert_eq!(
        keys.command_mac(b"command").unwrap(),
        aes_cmac(mac, b"command").unwrap()
    );
    let response_mac = aes_cmac(rmac, b"response").unwrap();
    keys.verify_response_mac(b"response", &response_mac[..8])
        .unwrap();
    assert!(
        keys.verify_response_mac(b"tampered", &response_mac[..8])
            .is_err()
    );
}

#[test]
fn symmetric_bound_aes_pair_survives_session_cleanup() {
    let value: Vec<u8> = (0x40..0x60).collect();
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let enc = scope
        .import_secret(
            &value[..16],
            crate::key_scope::authentication_aes_template(),
        )
        .unwrap();
    let mac = scope
        .import_secret(
            &value[16..],
            crate::key_scope::authentication_aes_template(),
        )
        .unwrap();
    let credential =
        SymmetricCredential::new(scope.take_key(&enc).unwrap(), scope.take_key(&mac).unwrap())
            .unwrap();
    drop(scope);
    let mut keys = SessionKeys::derive(&credential, &[1; 16]).unwrap();
    check_keys(
        &keys,
        &scp03_kdf(&value[..16], 4, &[1; 16], 128).unwrap(),
        &scp03_kdf(&value[16..], 6, &[1; 16], 128).unwrap(),
        &scp03_kdf(&value[16..], 7, &[1; 16], 128).unwrap(),
    );
    keys.clear();
    assert!(keys.is_empty());
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential.enc)
            .unwrap()
            .count_provider_objects(),
        2
    );
    let second = SessionKeys::derive(&credential, &[2; 16]).unwrap();
    assert!(!second.is_empty());
    drop(second);
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential.enc)
            .unwrap()
            .count_provider_objects(),
        2
    );
}

#[test]
fn symmetric_pair_derives_through_native_yubihsm_handles_without_export() {
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    use crate::yubihsm::tests::{NIST_AES_KEY_ID, RFC3610_AES_KEY_ID, make_yubihsm_test_slot};
    for (fallback, cbc) in [(false, false), (true, false), (true, true)] {
        let (slot, commands, corrupt, _trust) = make_yubihsm_test_slot();
        let owner = ProviderSession::open(Pkcs11Provider::new(slot).unwrap()).unwrap();
        owner.login(b"0001password").unwrap();
        // These are native handles for the peer fixture's AES keys. The source
        // PKCS #11 objects deliberately have no software key material.
        let insert = |id: u16, role: &str| {
            owner
                .call(|| {
                    with_session_context_mut(owner.handle, |ctx| {
                        let mut object =
                            profile_token_objects(ctx.slot_id, false, false, false).remove(0);
                        object.unique_id = format!("native-auth-{id}");
                        object.class = CKO_SECRET_KEY as _;
                        object.key_type = CKK_AES as _;
                        object.label = format!("native.{role}");
                        object.id = id.to_be_bytes().to_vec();
                        object.private = true;
                        object.sensitive = true;
                        object.extractable = false;
                        object.derive = !fallback;
                        object.encrypt = fallback;
                        object.allowed_mechanisms = Some(if cbc {
                            vec![CKM_AES_ECB as _, CKM_AES_CBC as _]
                        } else if fallback {
                            vec![CKM_AES_ECB as _]
                        } else {
                            vec![CKM_SP800_108_COUNTER_KDF as _]
                        });
                        object.material = KeyMaterial::YubiHsm {
                            id,
                            object_type: YUBIHSM_SYMMETRIC_KEY,
                            algorithm: YUBIHSM_ALGO_AES128,
                            length: 16,
                            domains: 0xffff,
                            capabilities: crate::yubihsm_capabilities(if cbc {
                                &[0x33, 0x35]
                            } else {
                                &[0x33]
                            }),
                            delegated_capabilities: [0; 8],
                            public_key: Vec::new(),
                            value: Rc::new(std::cell::RefCell::new(None)),
                        };
                        ctx.insert_object(object)
                    })
                })
                .unwrap()
        };
        let enc = insert(NIST_AES_KEY_ID, "enc");
        let mac = insert(RFC3610_AES_KEY_ID, "mac");
        let pair = SymmetricCredential::find(owner.clone(), "native", true).unwrap();
        let start = commands.borrow().len();
        let context = [0x42; 16];
        let keys = SessionKeys::derive(&pair, &context).unwrap();
        let expected_enc = crate::parse_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let expected_mac = crate::parse_hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf").unwrap();
        check_keys(
            &keys,
            &scp03_kdf(&expected_enc, 4, &context, 128).unwrap(),
            &scp03_kdf(&expected_mac, 6, &context, 128).unwrap(),
            &scp03_kdf(&expected_mac, 7, &context, 128).unwrap(),
        );
        let trace = commands.borrow();
        use super::super::CommandCode::{EncryptCbc, EncryptEcb};
        assert_eq!(trace.len() - start, if cbc { 6 } else { 9 });
        for (index, (command, data)) in trace[start..].iter().enumerate() {
            assert_eq!(
                *command,
                if cbc && index % 2 == 1 {
                    EncryptCbc as u8
                } else {
                    EncryptEcb as u8
                }
            );
            assert!(
                [NIST_AES_KEY_ID, RFC3610_AES_KEY_ID]
                    .contains(&u16::from_be_bytes(data[..2].try_into().unwrap()))
            );
            if *command == EncryptCbc as u8 {
                assert_eq!(&data[2..18], &[0; 16]);
                assert_eq!(data.len() - 18, 32);
            }
        }
        drop(trace);
        for handle in [enc, mac] {
            assert!(
                matches!(owner.attribute(handle, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
            );
            owner
                .call(|| {
                    with_session_context(owner.handle, |ctx| {
                        let object = ctx.resolve_object(handle)?.unwrap();
                        assert!(!object.sign);
                        assert_eq!(object.encrypt, fallback);
                        assert_eq!(object.derive, !fallback);
                        let KeyMaterial::YubiHsm { value, .. } = object.material else {
                            panic!("native key expected")
                        };
                        assert!(value.borrow().is_none());
                        Ok(())
                    })
                })
                .unwrap();
        }
        if fallback {
            let before = Pkcs11KeyScope::for_key(&pair.enc)
                .unwrap()
                .count_provider_objects();
            let set_capability = |capability| {
                owner
                    .call(|| {
                        with_session_context_mut(owner.handle, |ctx| {
                            let object = ctx.memory_objects.get_mut(&mac).unwrap();
                            object.decrypt = true;
                            let KeyMaterial::YubiHsm { capabilities, .. } = &mut object.material
                            else {
                                panic!("native key expected")
                            };
                            *capabilities = crate::yubihsm_capabilities(&[capability]);
                            Ok(())
                        })
                    })
                    .unwrap();
            };
            // ECB may appear in the key's mechanism list for decryption only.
            // An optimistic CKA_ENCRYPT must not override native capabilities.
            set_capability(0x32);
            assert!(!owner.can_encrypt(mac, CKM_AES_ECB as _).unwrap());
            let start = commands.borrow().len();
            assert!(
                matches!(SessionKeys::derive(&pair, &context), Err(Error::Generic(rv)) if rv == CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV)
            );
            assert_eq!(commands.borrow().len(), start);
            set_capability(0x33);
            let start = commands.borrow().len();
            corrupt.set(true);
            assert!(
                matches!(SessionKeys::derive(&pair, &context), Err(Error::Generic(rv)) if rv == CKR_DEVICE_ERROR as CK_RV)
            );
            assert_eq!(
                commands.borrow()[start..]
                    .iter()
                    .filter(|(command, _)| {
                        *command == super::super::CommandCode::EncryptEcb as u8
                    })
                    .count(),
                1
            );
            assert_eq!(
                Pkcs11KeyScope::for_key(&pair.enc)
                    .unwrap()
                    .count_provider_objects(),
                before
            );
        }
    }
}

type AsymmetricFixture = (
    AsymmetricKeys,
    BoundKey,
    std::rc::Weak<crate::pkcs11_provider::Pkcs11Provider>,
    [u8; 130],
    Zeroizing<Vec<u8>>,
    [u8; 16],
);

fn asymmetric_fixture() -> AsymmetricFixture {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let key = scope.import_p256(ec(1)).unwrap();
    let credential = scope.take_key(&key).unwrap();
    let source = Rc::downgrade(&scope.session.provider);
    let ephemeral = scope.import_p256(ec(2)).unwrap();
    let mut exchange = AsymmetricKeys { scope, ephemeral };
    let static_shared = exchange
        .static_agreement(&credential, &public(&ec(3)))
        .unwrap();
    let mut context = [0; 130];
    context[..65].copy_from_slice(&exchange.public_key().unwrap());
    context[65..].copy_from_slice(&public(&ec(4)));
    // Independent raw-key reference exists only in this test fixture.
    let mut z = derive_with_signing_key(&ec(2), &context[65..]).unwrap();
    z.extend_from_slice(&derive_with_signing_key(&ec(1), &public(&ec(3))).unwrap());
    let expected = x963_kdf_sha256(&z, &super::super::SCP11_SHARED_INFO, 64).unwrap();
    let transcript = [&context[65..], &context[..65]].concat();
    let receipt = aes_cmac(&expected[..16], &transcript).unwrap();
    (exchange, static_shared, source, context, expected, receipt)
}

#[test]
fn asymmetric_bound_key_derives_readable_working_keys_for_local_crypto() {
    let (exchange, static_shared, source, context, expected, receipt) = asymmetric_fixture();
    assert!(source.upgrade().is_some());
    let mut keys = exchange.finish(&static_shared, &context, &receipt).unwrap();
    check_keys(
        &keys,
        &expected[16..32],
        &expected[32..48],
        &expected[48..64],
    );
    assert!(source.upgrade().is_some());
    keys.clear();
    assert!(keys.is_empty());
}

#[test]
fn asymmetric_receipt_and_transcript_rejections_publish_no_session_keys() {
    let (exchange, shared, source, context, _, mut receipt) = asymmetric_fixture();
    receipt[0] ^= 1;
    assert!(
        matches!(exchange.finish(&shared, &context, &receipt), Err(Error::Generic(rv)) if rv == CKR_SIGNATURE_INVALID as CK_RV)
    );
    assert!(source.upgrade().is_some());
    let (exchange, shared, _, mut context, _, receipt) = asymmetric_fixture();
    context[1] ^= 1;
    assert!(
        matches!(exchange.finish(&shared, &context, &receipt), Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as CK_RV)
    );
    let (exchange, shared, _, mut context, _, receipt) = asymmetric_fixture();
    context[65..].fill(0);
    assert!(exchange.finish(&shared, &context, &receipt).is_err());
}

#[test]
fn local_keys_validate_lengths_and_clear_all_operations() {
    for (enc, mac, rmac) in [(15, 16, 16), (16, 17, 16), (16, 16, 32)] {
        assert!(SessionKeys::import(&vec![1; enc], &vec![2; mac], &vec![3; rmac]).is_err());
    }
    let mut keys = SessionKeys::import(&[1; 16], &[2; 16], &[3; 16]).unwrap();
    let iv = keys.iv(&[0; 16]).unwrap();
    let encrypted = keys.cbc(&iv, &[42; 32], true).unwrap();
    assert_eq!(keys.cbc(&iv, &encrypted, false).unwrap(), [42; 32]);
    for signature in [&[][..], &[0; 7], &[0; 9], &[0; 16]] {
        assert!(
            matches!(keys.verify_response_mac(b"response", signature), Err(Error::Generic(rv)) if rv == CKR_SIGNATURE_LEN_RANGE as CK_RV)
        );
    }
    keys.clear();
    assert!(keys.is_empty());
    assert!(keys.iv(&[0; 16]).is_err());
    assert!(keys.cbc(&iv, &encrypted, false).is_err());
    assert!(keys.command_mac(b"command").is_err());
    assert!(keys.verify_response_mac(b"response", &[0; 8]).is_err());
}

#[test]
fn partial_working_key_read_fails_and_releases_the_derivation_scope() {
    let credential = credential(&[0x42; 32], CKM_SHA256_KEY_DERIVATION as _);
    let mut scope = Pkcs11KeyScope::for_key(&credential).unwrap();
    let base = scope.bind(&credential).unwrap();
    let block = scope
        .sha256(
            &base,
            readable(generic_template(&[CKM_EXTRACT_KEY_FROM_KEY as _])),
        )
        .unwrap();
    let enc = scope
        .extract(&block, 0, readable(enc_template()), 16)
        .unwrap();
    // The second read fails after the first has produced a zeroizing value.
    let mac = scope.extract(&block, 0, mac_template(), 16).unwrap();
    let rmac = scope
        .extract(&block, 128, readable(rmac_template()), 16)
        .unwrap();
    assert_eq!(scope.count_provider_objects(), 5);
    assert!(
        matches!(SessionKeys::read_working_keys(scope, enc, mac, rmac),
        Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
    );
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential)
            .unwrap()
            .count_provider_objects(),
        1
    );
}

/// An ordinary source whose advertised mechanism set lacks the extension.
#[derive(Debug)]
struct WithoutMechanismSlot(SoftwareSlot, CK_MECHANISM_TYPE);
impl Slot for WithoutMechanismSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn kind(&self) -> SlotKind {
        self.0.kind()
    }
    fn name(&self) -> String {
        self.0.name()
    }
    fn manufacturer(&self) -> &str {
        self.0.manufacturer()
    }
    fn product(&self) -> &str {
        self.0.product()
    }
    fn serial(&self) -> &str {
        self.0.serial()
    }
    fn major(&self) -> u8 {
        self.0.major()
    }
    fn minor(&self) -> u8 {
        self.0.minor()
    }
    fn is_present(&self) -> bool {
        self.0.is_present()
    }
    fn open_session(&mut self, slot: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        self.0.open_session(slot, flags)
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.0.login(pin)
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.0.logout()
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        self.0.init_slot()
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.0.get_slot_info(info)
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.0.get_token_info(info)
    }
    fn software_mechanism_enabled(&self, mechanism: CK_MECHANISM_TYPE) -> bool {
        mechanism != self.1
    }
}

#[test]
fn asymmetric_prefixed_and_standard_paths_match_independent_reference() {
    use crate::pkcs11_auth::{P256_PARAMS, Pkcs11Auth, ec_template};
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    for (advertised, allowed) in [
        (true, vec![CKM_PKCS11RS_PREFIXED_ECDH_DERIVE]),
        (true, vec![CKM_ECDH1_DERIVE as _]),
        (
            false,
            vec![CKM_ECDH1_DERIVE as _, CKM_PKCS11RS_PREFIXED_ECDH_DERIVE],
        ),
    ] {
        let provider = if advertised {
            Pkcs11Provider::private_software().unwrap()
        } else {
            Pkcs11Provider::new(Box::new(WithoutMechanismSlot(
                SoftwareSlot::new("standard".into(), 0),
                CKM_PKCS11RS_PREFIXED_ECDH_DERIVE,
            )))
            .unwrap()
        };
        let owner = ProviderSession::open(provider).unwrap();
        if !advertised {
            owner.login(b"test source pin").unwrap();
        }
        let handle = owner
            .create(
                TokenObjectTemplate {
                    allowed_mechanisms: Some(allowed),
                    ..ec_template()
                },
                &[
                    (CKA_EC_PARAMS, P256_PARAMS),
                    (CKA_VALUE, &ec(1).serialized().unwrap()),
                ],
            )
            .unwrap();
        let credential = BoundKey::from_session(owner.clone(), handle).unwrap();
        let mut scope = Pkcs11KeyScope::for_key(&credential).unwrap();
        let ephemeral = scope.import_p256(ec(2)).unwrap();
        let exchange = AsymmetricKeys { scope, ephemeral };
        let mut context = [0; 130];
        context[..65].copy_from_slice(&public(&ec(2)));
        context[65..].copy_from_slice(&public(&ec(4)));
        let mut z = derive_with_signing_key(&ec(2), &context[65..]).unwrap();
        z.extend_from_slice(&derive_with_signing_key(&ec(1), &public(&ec(3))).unwrap());
        let expected = x963_kdf_sha256(&z, &super::super::SCP11_SHARED_INFO, 64).unwrap();
        let receipt =
            aes_cmac(&expected[..16], &[&context[65..], &context[..65]].concat()).unwrap();
        let keys = exchange
            .finish_with_credential(&credential, &public(&ec(3)), &context, &receipt)
            .unwrap();
        check_keys(
            &keys,
            &expected[16..32],
            &expected[32..48],
            &expected[48..64],
        );
        assert!(
            matches!(owner.attribute(handle, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
        );
        assert_eq!(
            Pkcs11KeyScope::for_key(&credential)
                .unwrap()
                .count_provider_objects(),
            1
        );
    }
}

#[test]
fn asymmetric_combined_policy_failure_is_not_retried_with_standard_ecdh() {
    use crate::pkcs11_auth::{P256_PARAMS, Pkcs11Auth, ec_template};
    for combined in [true, false] {
        let (mut exchange, _old_shared, _, context, expected, receipt) = asymmetric_fixture();
        let mut template = ec_template();
        let mut policy = crate::key_metadata::KeyAttributes::new();
        policy
            .insert(
                CKA_SENSITIVE as _,
                crate::key_metadata::KeyAttributeValue::Boolean(true),
            )
            .unwrap();
        template.policy_templates.derive = Some(policy);
        let owner = exchange.scope.session.clone();
        let handle = owner
            .create(
                template,
                &[
                    (CKA_EC_PARAMS, P256_PARAMS),
                    (CKA_VALUE, &ec(1).serialized().unwrap()),
                ],
            )
            .unwrap();
        let credential = BoundKey::from_session(owner, handle).unwrap();
        if combined {
            // The preferred operation cannot create readable final material
            // under this source policy. The error must survive selection.
            assert!(
                matches!(exchange.finish_with_credential(&credential, &public(&ec(3)), &context, &receipt),
                Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCONSISTENT as CK_RV)
            );
        } else {
            // A retry really could succeed: the standard graph first creates
            // a sensitive raw agreement and subsequently hashes it. Prove that
            // the failed preferred path above did not silently take this route.
            let shared = exchange
                .static_agreement(&credential, &public(&ec(3)))
                .unwrap();
            let keys = exchange.finish(&shared, &context, &receipt).unwrap();
            check_keys(
                &keys,
                &expected[16..32],
                &expected[32..48],
                &expected[48..64],
            );
        }
    }
}

/// Emulates only the native ECDH APDU; the real PIV/OpenPGP slot, session,
/// object projection, mechanism discovery and PKCS #11 derivation code run.
#[derive(Debug)]
struct AgreementCard {
    calls: Cell<usize>,
}
impl Connector for AgreementCard {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Test"
    }
    fn product(&self) -> &str {
        "Agreement card"
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        7
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        2048
    }
    fn transmit<'a>(
        &self,
        send: &[u8],
        output: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], Error> {
        let mut response = Vec::new();
        match send[1] {
            0x20 | 0xa4 => {} // Authorization status and logout applet selection.
            ins @ (0x87 | 0x2a) => {
                let body = &send[5..5 + send[4] as usize];
                let peer = &body[body.len() - 65..];
                assert_eq!(peer, public(&ec(3)));
                let z = derive_with_signing_key(&ec(1), peer).unwrap();
                if ins == 0x87 {
                    response.extend_from_slice(&[0x7c, 0x22, 0x82, 0x20]);
                }
                response.extend_from_slice(&z);
                self.calls.set(self.calls.get() + 1);
            }
            _ => return Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
        }
        response.extend_from_slice(&[0x90, 0x00]);
        output[..response.len()].copy_from_slice(&response);
        Ok(&output[..response.len()])
    }
}

#[test]
fn piv_and_openpgp_native_keys_select_combined_authentication_and_complete_kdf() {
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    for is_piv in [true, false] {
        let card = Rc::new(AgreementCard {
            calls: Cell::new(0),
        });
        let device = Arc::new(crate::device::DeviceContext::test());
        let slot: Box<dyn Slot> = if is_piv {
            let mut slot = PivSlot::new_with_device(card.clone(), piv::PIV_AID.to_vec(), device);
            slot.version = piv::Version {
                major: 5,
                minor: 7,
                patch: 0,
            };
            slot.keys.push(crate::backend::PivKey {
                slot: piv::Slot::KeyManagement,
                algorithm: piv::Algorithm::EccP256,
                public_key: PivPublicKey::Ec(public(&ec(1))),
                attestation: Rc::new(std::cell::RefCell::new(LazyCache::Missing)),
                pin_policy: 2,
                touch_policy: 1,
                origin: piv::ORIGIN_GENERATED,
            });
            slot.authenticated.set(true);
            Box::new(slot)
        } else {
            let mut slot = OpenPgpSlot::new_with_device(card.clone(), vec![], device);
            slot.keys.push(openpgp::KeyInfo {
                key_ref: OpenPgpKeyRef::Decipher,
                algorithm: OpenPgpAlgorithm::Ecdh(openpgp::Curve::P256),
                public_key: openpgp::PublicKey::Ec {
                    curve: openpgp::Curve::P256,
                    point: public(&ec(1)),
                },
                pin_policy: 0,
                touch_policy: 1,
                local: true,
            });
            slot.authenticated.set(true);
            Box::new(slot)
        };
        let owner = ProviderSession::open(Pkcs11Provider::new(slot).unwrap()).unwrap();
        owner
            .call(|| {
                with_session_context_mut(owner.handle, |ctx| {
                    ctx.refresh_slot_token_objects(ctx.slot_id)
                })
            })
            .unwrap();
        let private = [(CKA_CLASS, (CKO_PRIVATE_KEY as CK_ULONG).to_ne_bytes())];
        assert!(
            owner
                .find(&[(private[0].0, &private[0].1)])
                .unwrap()
                .is_empty()
        );
        // Represent an application's already-authorized source session. Login
        // protocol behavior is covered separately by the native slot tests.
        owner
            .call(|| {
                with_session_context_mut(owner.handle, |ctx| {
                    ctx.login_role = Some(LoginRole::User);
                    Ok(())
                })
            })
            .unwrap();
        let handles = owner.find(&[(private[0].0, &private[0].1)]).unwrap();
        assert_eq!(handles.len(), 1);
        assert!(
            owner
                .can_derive(handles[0], CKM_PKCS11RS_PREFIXED_ECDH_DERIVE)
                .unwrap()
        );
        assert!(owner.can_derive(handles[0], CKM_ECDH1_DERIVE as _).unwrap());
        assert!(
            !owner
                .can_derive(handles[0], CKM_SP800_108_COUNTER_KDF as _)
                .unwrap()
        );
        let credential = BoundKey::from_session(owner.clone(), handles[0]).unwrap();
        let objects_before = Pkcs11KeyScope::for_key(&credential)
            .unwrap()
            .count_provider_objects();
        let exchange = AsymmetricKeys::for_key(&credential).unwrap();
        let mut context = [0; 130];
        context[..65].copy_from_slice(&exchange.public_key().unwrap());
        context[65..].copy_from_slice(&public(&ec(4)));
        let mut z = derive_with_signing_key(&ec(4), &context[..65]).unwrap();
        z.extend_from_slice(&derive_with_signing_key(&ec(3), &public(&ec(1))).unwrap());
        let expected = x963_kdf_sha256(&z, &super::super::SCP11_SHARED_INFO, 64).unwrap();
        let receipt =
            aes_cmac(&expected[..16], &[&context[65..], &context[..65]].concat()).unwrap();
        let keys = exchange
            .finish_with_credential(&credential, &public(&ec(3)), &context, &receipt)
            .unwrap();
        check_keys(
            &keys,
            &expected[16..32],
            &expected[32..48],
            &expected[48..64],
        );
        assert_eq!(card.calls.get(), 1);
        assert!(
            matches!(owner.attribute(handles[0], CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
        );
        assert_eq!(
            Pkcs11KeyScope::for_key(&credential)
                .unwrap()
                .count_provider_objects(),
            objects_before
        );
    }
}

fn symmetric_permission_fixture(
    counter_advertised: bool,
    templates: [TokenObjectTemplate; 2],
) -> (
    SymmetricCredential,
    Rc<crate::pkcs11_provider::ProviderSession>,
) {
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    let provider = if counter_advertised {
        Pkcs11Provider::private_software().unwrap()
    } else {
        Pkcs11Provider::new(Box::new(WithoutMechanismSlot(
            SoftwareSlot::new("ECB source".into(), 0),
            CKM_SP800_108_COUNTER_KDF as _,
        )))
        .unwrap()
    };
    let owner = ProviderSession::open(provider).unwrap();
    owner.authorize(b"test source PIN").unwrap();
    let mut keys = Vec::new();
    for (template, value) in templates.into_iter().zip([0x41u8, 0x42]) {
        let handle = owner
            .create(template, &[(CKA_VALUE, &[value; 16])])
            .unwrap();
        assert!(
            matches!(owner.attribute(handle, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
        );
        keys.push(BoundKey::from_session(owner.clone(), handle).unwrap());
    }
    (
        SymmetricCredential::new(keys.remove(0), keys.remove(0)).unwrap(),
        owner,
    )
}

fn symmetric_permissions(
    derive: bool,
    encrypt: bool,
    mechanisms: &[CK_MECHANISM_TYPE],
) -> TokenObjectTemplate {
    TokenObjectTemplate {
        derive,
        encrypt,
        allowed_mechanisms: Some(mechanisms.to_vec()),
        ..crate::key_scope::authentication_aes_template()
    }
}

#[test]
fn symmetric_counter_and_ecb_paths_obey_slot_and_key_permissions() {
    use crate::key_scope::CounterKdfPath;
    let counter = CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE;
    let ecb = CKM_AES_ECB as CK_MECHANISM_TYPE;
    for (advertised, enc, mac, enc_fallback, mac_fallback) in [
        (
            true,
            symmetric_permissions(true, true, &[counter, ecb]),
            symmetric_permissions(true, true, &[counter, ecb]),
            false,
            false,
        ),
        (
            false,
            symmetric_permissions(true, true, &[counter, ecb]),
            symmetric_permissions(true, true, &[counter, ecb]),
            true,
            true,
        ),
        (
            true,
            symmetric_permissions(true, true, &[ecb]),
            symmetric_permissions(true, true, &[ecb]),
            true,
            true,
        ),
        (
            true,
            symmetric_permissions(false, true, &[counter, ecb]),
            symmetric_permissions(false, true, &[counter, ecb]),
            true,
            true,
        ),
        (
            true,
            symmetric_permissions(true, false, &[counter]),
            symmetric_permissions(false, true, &[ecb]),
            false,
            true,
        ),
        (
            true,
            symmetric_permissions(false, true, &[ecb]),
            symmetric_permissions(true, false, &[counter]),
            true,
            false,
        ),
    ] {
        let (pair, _owner) = symmetric_permission_fixture(advertised, [enc, mac]);
        let mut scope = Pkcs11KeyScope::for_key(&pair.enc).unwrap();
        for (key, fallback) in [(&pair.enc, enc_fallback), (&pair.mac, mac_fallback)] {
            let base = scope.bind(key).unwrap();
            assert_eq!(
                matches!(
                    scope.counter_kdf_path(&base).unwrap(),
                    CounterKdfPath::AesEcb
                ),
                fallback
            );
        }
        let before = scope.count_provider_objects();
        let context = [0x23; 16];
        let keys = SessionKeys::derive(&pair, &context).unwrap();
        check_keys(
            &keys,
            &scp03_kdf(&[0x41; 16], 4, &context, 128).unwrap(),
            &scp03_kdf(&[0x42; 16], 6, &context, 128).unwrap(),
            &scp03_kdf(&[0x42; 16], 7, &context, 128).unwrap(),
        );
        assert_eq!(scope.count_provider_objects(), before);
    }
    for denied in [
        symmetric_permissions(false, false, &[counter, ecb]),
        symmetric_permissions(false, true, &[counter]),
        symmetric_permissions(true, false, &[ecb]),
        symmetric_permissions(true, true, &[]),
    ] {
        let (pair, _owner) = symmetric_permission_fixture(
            true,
            [symmetric_permissions(true, false, &[counter]), denied],
        );
        assert!(
            matches!(SessionKeys::derive(&pair, &[0; 16]), Err(Error::Generic(rv)) if rv == CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV)
        );
        assert_eq!(
            Pkcs11KeyScope::for_key(&pair.enc)
                .unwrap()
                .count_provider_objects(),
            2
        );
    }
}

#[test]
fn symmetric_cbc_selection_respects_slot_and_key_permissions() {
    use crate::key_scope::CounterKdfPath;
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    let ecb = CKM_AES_ECB as CK_MECHANISM_TYPE;
    let cbc = CKM_AES_CBC as CK_MECHANISM_TYPE;
    let counter = CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE;
    for (hidden, allowed, derive, expected) in [
        (0, vec![counter, ecb, cbc], true, "derive"),
        (0, vec![ecb, cbc], false, "cbc"),
        (cbc, vec![ecb, cbc], false, "ecb"),
        (0, vec![ecb], false, "ecb"),
        (0, vec![cbc], false, "denied"),
    ] {
        let owner = ProviderSession::open(
            Pkcs11Provider::new(Box::new(WithoutMechanismSlot(
                SoftwareSlot::new("CBC source".into(), 0),
                hidden,
            )))
            .unwrap(),
        )
        .unwrap();
        owner.authorize(b"test source PIN").unwrap();
        let mut keys = Vec::new();
        for value in [0x41u8, 0x42] {
            let handle = owner
                .create(
                    symmetric_permissions(derive, true, &allowed),
                    &[(CKA_VALUE, &[value; 16])],
                )
                .unwrap();
            keys.push(BoundKey::from_session(owner.clone(), handle).unwrap());
        }
        let pair = SymmetricCredential::new(keys.remove(0), keys.remove(0)).unwrap();
        let mut scope = Pkcs11KeyScope::for_key(&pair.enc).unwrap();
        let base = scope.bind(&pair.enc).unwrap();
        let actual = match scope.counter_kdf_path(&base) {
            Ok(CounterKdfPath::Derive) => "derive",
            Ok(CounterKdfPath::AesCbc) => "cbc",
            Ok(CounterKdfPath::AesEcb) => "ecb",
            Err(Error::Generic(rv)) if rv == CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV => "denied",
            _ => panic!("unexpected selection result"),
        };
        assert_eq!(actual, expected);
        if expected != "denied" {
            let context = [0x23; 16];
            let keys = SessionKeys::derive(&pair, &context).unwrap();
            check_keys(
                &keys,
                &scp03_kdf(&[0x41; 16], 4, &context, 128).unwrap(),
                &scp03_kdf(&[0x42; 16], 6, &context, 128).unwrap(),
                &scp03_kdf(&[0x42; 16], 7, &context, 128).unwrap(),
            );
            assert_eq!(scope.count_provider_objects(), 2);
        }
    }
}

#[test]
fn symmetric_counter_policy_failure_does_not_retry_with_ecb() {
    let counter = CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE;
    let ecb = CKM_AES_ECB as CK_MECHANISM_TYPE;
    let mut restricted = symmetric_permissions(true, true, &[counter, ecb]);
    let mut policy = crate::key_metadata::KeyAttributes::new();
    policy
        .insert(
            CKA_SENSITIVE as _,
            crate::key_metadata::KeyAttributeValue::Boolean(true),
        )
        .unwrap();
    restricted.policy_templates.derive = Some(policy);
    // Fail on the second key, after S-ENC was successfully derived and read.
    let (pair, _owner) = symmetric_permission_fixture(
        true,
        [
            symmetric_permissions(true, true, &[counter, ecb]),
            restricted,
        ],
    );
    assert!(
        matches!(SessionKeys::derive(&pair, &[0x23; 16]), Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCONSISTENT as CK_RV)
    );
    let mut scope = Pkcs11KeyScope::for_key(&pair.mac).unwrap();
    assert_eq!(scope.count_provider_objects(), 2);
    // ECB is actually usable: the preceding failure must not silently use it.
    let base = scope.bind(&pair.mac).unwrap();
    let fields = [CounterKdfField::Counter(IntegerFormat {
        width_bits: 8,
        little_endian: false,
    })];
    assert!(
        scope
            .counter_kdf_aes128(
                &base,
                crate::key_scope::CounterKdfPath::AesEcb,
                &fields,
                readable(mac_template())
            )
            .is_ok()
    );
}
