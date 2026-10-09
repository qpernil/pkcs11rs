use super::*;
use crate::{
    embedded_virtual_yubikey::EmbeddedVirtualYubiKeyConnector,
    pkcs11_auth::{Pkcs11Auth, ec_template},
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    security_domain::{KeyRef, Scp11Administration as Op},
};
use p256::ecdsa::SigningKey;
use spki::EncodePublicKey;
use virtual_yubikey_core::{DeviceProfile, ISSUER_SECURITY_DOMAIN_AID as SD, VirtualYubiKey};

fn diagnostic(owner: &ProviderSession, credential: bool) -> String {
    let mut len = 0;
    let query = |output, len| {
        owner.call(|| {
            if credential {
                api::PKCS11RS_GetAuthenticatedCredential(owner.handle, output, len)
            } else {
                api::PKCS11RS_GetSecureChannel(owner.handle, output, len)
            }
        })
    };
    assert_eq!(query(std::ptr::null_mut(), &mut len), CKR_OK as CK_RV);
    let mut value = vec![0; len as usize];
    assert_eq!(query(value.as_mut_ptr(), &mut len), CKR_OK as CK_RV);
    String::from_utf8(value).unwrap()
}

struct Source {
    owner: Arc<ProviderSession>,
    child: Arc<Mutex<SlotContext>>,
    _store: Store,
}
struct Store(std::path::PathBuf);
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Source {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("ccid-dynamic-{:x}", u64::from_ne_bytes(nonce)));
        std::fs::create_dir(&path).unwrap();
        let store = SoftwareTokenStore::open("card source".into(), path.clone(), None).unwrap();
        let master = store.init_token(b"source SO password", [b' '; 32]).unwrap();
        store
            .init_user_pin(b"source user password", &master)
            .unwrap();
        drop(master);
        drop(store);
        let slot =
            SoftwareSlot::new_with_storage("card source".into(), 0, Some(path.clone()), None)
                .unwrap();
        let module = ModuleContext::private_slot(Box::new(slot)).unwrap();
        let child = module
            .slot_contexts
            .read()
            .unwrap()
            .get(&1)
            .unwrap()
            .clone();
        let owner =
            ProviderSession::open(Pkcs11Provider::from_slot(child.clone()).unwrap()).unwrap();
        owner.login(b"source user password").unwrap();
        Self {
            owner,
            child,
            _store: Store(path),
        }
    }
    fn aes(&self) {
        for suffix in ["enc", "mac", "dek"] {
            let mut template = scp_key_provider::aes_credential_template();
            template.token = true;
            template.label = format!("client.{suffix}");
            if suffix == "dek" {
                template.encrypt = true;
                template.allowed_mechanisms = Some(vec![CKM_AES_CBC as _]);
            }
            self.owner
                .create(template, &[(CKA_VALUE, &crate::scp03::YUBIKEY_FACTORY_KEY)])
                .unwrap();
        }
    }
    fn ec(&self, leaf: &[u8]) -> CK_OBJECT_HANDLE {
        let mut template = ec_template();
        template.token = true;
        template.label = "client".into();
        template.id = b"oce".to_vec();
        let private = scalar(5).to_bytes();
        let key = self
            .owner
            .create(
                template,
                &[
                    (CKA_EC_PARAMS, pkcs11_auth::P256_PARAMS),
                    (CKA_VALUE, &private),
                ],
            )
            .unwrap();
        let mut values = [
            (
                CKA_CLASS,
                (CKO_CERTIFICATE as CK_ULONG).to_ne_bytes().to_vec(),
            ),
            (
                CKA_CERTIFICATE_TYPE,
                (CKC_X_509 as CK_ULONG).to_ne_bytes().to_vec(),
            ),
            (CKA_TOKEN, vec![CK_TRUE as u8]),
            (CKA_PRIVATE, vec![CK_FALSE as u8]),
            (CKA_LABEL, b"different certificate label".to_vec()),
            (CKA_ID, b"oce".to_vec()),
            (CKA_VALUE, leaf.to_vec()),
        ];
        let mut attributes = values
            .iter_mut()
            .map(|(kind, value)| CK_ATTRIBUTE {
                type_: *kind as _,
                pValue: value.as_mut_ptr().cast(),
                ulValueLen: value.len() as _,
            })
            .collect::<Vec<_>>();
        let mut cert = 0;
        self.owner
            .call(|| {
                api::rust::create_object(
                    self.owner.handle,
                    attributes.as_mut_ptr(),
                    attributes.len() as _,
                    &mut cert,
                )
            })
            .unwrap();
        key
    }
}
fn scalar(n: u8) -> SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = n;
    SigningKey::from_slice(&bytes).unwrap()
}
fn version() -> CommandApdu {
    CommandApdu {
        cla: 0,
        ins: 0xfd,
        p1: 0,
        p2: 0,
        data: vec![],
        le: Some(256),
        extended: false,
    }
}
fn base() -> Arc<EmbeddedVirtualYubiKeyConnector> {
    Arc::new(EmbeddedVirtualYubiKeyConnector::from_device(
        VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42)),
    ))
}
fn target(
    base: Arc<EmbeddedVirtualYubiKeyConnector>,
    source: &Source,
    configuration: SecureChannelConfiguration,
    protocol: Option<SecureChannelProtocol>,
) -> (Arc<ProviderSession>, PcscAppletConnector) {
    target_application(base, source, configuration, protocol, CcidApplication::Piv)
}
fn target_application(
    base: Arc<EmbeddedVirtualYubiKeyConnector>,
    source: &Source,
    configuration: SecureChannelConfiguration,
    protocol: Option<SecureChannelProtocol>,
    application: CcidApplication,
) -> (Arc<ProviderSession>, PcscAppletConnector) {
    let aid = match application {
        CcidApplication::Piv => piv::PIV_AID.as_slice(),
        CcidApplication::OpenPgp => openpgp::OPENPGP_AID.as_slice(),
        CcidApplication::Fido2 => ctap::FIDO2_AID.as_slice(),
        CcidApplication::IssuerSecurityDomain => SD.as_slice(),
        _ => unreachable!(),
    };
    let connector = PcscAppletConnector::new_configured(
        base,
        aid,
        protocol,
        Arc::new(PcscReaderState::default()),
        Arc::new(configuration),
        Arc::new(pinentry::Pinentry::unconfigured()),
    );
    let connection: Rc<dyn Connector> = Rc::new(connector.clone());
    let device = connector.state.device.clone();
    let slot: Box<dyn Slot> = match application {
        CcidApplication::Piv => {
            Box::new(PivSlot::new_with_device(connection, aid.to_vec(), device))
        }
        CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new_with_device(
            connection,
            aid.to_vec(),
            device,
        )),
        CcidApplication::Fido2 => {
            Box::new(Fido2Slot::new_with_device(connection, aid.to_vec(), device))
        }
        CcidApplication::IssuerSecurityDomain => Box::new(
            IssuerSecurityDomainSlot::new_with_device(connection, aid.to_vec(), device),
        ),
        _ => unreachable!(),
    };
    let owner = ProviderSession::open(Pkcs11Provider::new(slot).unwrap()).unwrap();
    connector
        .applet
        .authentication
        .lock()
        .unwrap()
        .sources
        .as_ref()
        .unwrap()
        .register(&source.child)
        .unwrap();
    (owner, connector)
}
fn login(owner: &ProviderSession, username: &[u8], pin: &[u8]) -> CK_RV {
    owner.call(|| {
        api::C_LoginUser(
            owner.handle,
            CKU_USER as _,
            pin.as_ptr().cast_mut(),
            pin.len() as _,
            username.as_ptr().cast_mut(),
            username.len() as _,
        )
    })
}
fn switch_away(connector: &PcscAppletConnector) {
    let other =
        PcscAppletConnector::new(connector.base.clone(), &SD, None, connector.state.clone());
    crate::select_application(&other, &SD).unwrap();
}

#[test]
fn ccid_dynamic_scp03_login_uses_applet_pin_and_recovers_selected_provider() {
    let source = Source::new();
    source.aes();
    let (owner, connector) = target(
        base(),
        &source,
        SecureChannelConfiguration::for_test(),
        None,
    );
    let selector = b"pkcs11:token=card%20source;object=client.enc;type=secret-key";
    assert_eq!(diagnostic(&owner, false), "none");
    assert_eq!(diagnostic(&owner, true), "none");
    assert_eq!(
        login(&owner, selector, b"000000"),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_none()
    );
    assert_eq!(login(&owner, selector, b"123456"), CKR_OK as CK_RV);
    assert!(connector.secure_channel_required());
    assert_eq!(diagnostic(&owner, false), "scp03");
    assert!(diagnostic(&owner, true).contains("object=client.enc"));
    assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
    switch_away(&connector);
    // Reconcile lost applet PIN authorization without deleting the SCP selection.
    let mut info = unsafe { std::mem::zeroed() };
    assert_eq!(
        owner.call(|| api::C_GetSessionInfo(owner.handle, &mut info)),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(diagnostic(&owner, false), "none");
    assert_eq!(diagnostic(&owner, true), "none");
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_some()
    );
    assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
    assert_eq!(connector.ccid_login_state(), Some(CcidLoginState::Public));
    assert_eq!(diagnostic(&owner, false), "scp03");
    assert_eq!(diagnostic(&owner, true), "none");
    assert_eq!(
        owner.call(|| api::C_Logout(owner.handle)),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_none()
    );
    assert!(connector.send_apdu(&version()).is_err());
}

#[test]
fn ccid_dynamic_recreation_disabled_and_source_logout_require_fresh_login() {
    for recreate in [false, true] {
        let source = Source::new();
        source.aes();
        let mut config = SecureChannelConfiguration::for_test();
        config.recreate_sessions = recreate;
        let (owner, connector) = target(base(), &source, config, None);
        let selector = b"pkcs11:object=client.enc;type=secret-key";
        assert_eq!(login(&owner, selector, b"123456"), CKR_OK as CK_RV);
        assert_eq!(diagnostic(&owner, false), "scp03");
        assert!(diagnostic(&owner, true).contains("object=client.enc"));
        assert_eq!(
            connector
                .applet
                .authentication
                .lock()
                .unwrap()
                .credential
                .is_some(),
            recreate
        );
        if recreate {
            assert_eq!(
                source.owner.call(|| api::C_Logout(source.owner.handle)),
                CKR_OK as CK_RV
            );
        }
        // Working keys remain usable; a fresh handshake cannot reuse lost source authorization.
        assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
        switch_away(&connector);
        assert!(connector.send_apdu(&version()).is_err());
    }
}

#[test]
fn ccid_dynamic_scp03_login_authenticates_each_target_applet() {
    for application in [
        CcidApplication::OpenPgp,
        CcidApplication::Fido2,
        CcidApplication::IssuerSecurityDomain,
    ] {
        let source = Source::new();
        source.aes();
        let (owner, connector) = target_application(
            base(),
            &source,
            SecureChannelConfiguration::for_test(),
            None,
            application,
        );
        let selector = b"pkcs11:object=client.enc;type=secret-key";
        let pin = if application == CcidApplication::IssuerSecurityDomain {
            b"".as_slice()
        } else {
            b"123456".as_slice()
        };
        assert_eq!(
            login(&owner, selector, pin),
            CKR_OK as CK_RV,
            "{application:?}"
        );
        let mut info = unsafe { std::mem::zeroed() };
        assert_eq!(
            owner.call(|| api::C_GetSessionInfo(owner.handle, &mut info)),
            CKR_OK as CK_RV
        );
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS as CK_STATE);
        assert_eq!(owner.call(|| api::C_Logout(owner.handle)), CKR_OK as CK_RV);
        assert!(
            connector
                .applet
                .authentication
                .lock()
                .unwrap()
                .credential
                .is_none()
        );
    }
}

#[test]
fn ccid_dynamic_rejects_yubihsm_only_selectors_and_protocol_conflicts() {
    let source = Source::new();
    source.aes();
    let (owner, _) = target(
        base(),
        &source,
        SecureChannelConfiguration::for_test(),
        Some(SecureChannelProtocol::Scp03),
    );
    for selector in [
        b"pkcs11:?pkcs11rs-direct=client&pkcs11rs-authkey=0001".as_slice(),
        b"pkcs11:object=client.enc;type=secret-key?pkcs11rs-scp=scp11a".as_slice(),
        b"pkcs11:object=client.enc;type=secret-key?pkcs11rs-authkey=0001".as_slice(),
    ] {
        assert_eq!(
            login(&owner, selector, b"123456"),
            CKR_ARGUMENTS_BAD as CK_RV
        );
    }
    assert_eq!(source.child.lock().unwrap().sessions.len(), 1);
}

#[test]
fn ccid_scp11c_cannot_be_requested_by_username() {
    for configured in [
        None,
        Some(SecureChannelProtocol::Scp11a),
        Some(SecureChannelProtocol::Scp11c),
    ] {
        let source = Source::new();
        let (owner, _) = target(
            base(),
            &source,
            SecureChannelConfiguration::for_test(),
            configured,
        );
        assert_eq!(
            login(
                &owner,
                b"pkcs11:object=client;type=private?pkcs11rs-scp=scp11c",
                b"123456"
            ),
            CKR_ARGUMENTS_BAD as CK_RV
        );
        assert_eq!(source.child.lock().unwrap().sessions.len(), 1);
    }
}

#[test]
fn configured_client_uri_requires_authorization_and_explicit_username_overrides_it() {
    let source = Source::new();
    source.aes();
    let mut config = SecureChannelConfiguration::for_test();
    config.client_uri = Some(b"pkcs11:object=missing.enc;type=secret-key".to_vec());
    let (owner, connector) = target(base(), &source, config, None);
    assert!(connector.secure_channel_required());
    let ordinary_login = || {
        owner.call(|| {
            api::C_Login(
                owner.handle,
                CKU_USER as _,
                b"123456".as_ptr().cast_mut(),
                6,
            )
        })
    };
    // Factory transport keys exist, but failure of the configured lookup cannot fall back to them.
    assert_eq!(ordinary_login(), CKR_KEY_HANDLE_INVALID as CK_RV);
    let selector = b"pkcs11:object=client.enc;type=secret-key";
    assert_eq!(login(&owner, selector, b"123456"), CKR_OK as CK_RV);
    assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
    assert_eq!(owner.call(|| api::C_Logout(owner.handle)), CKR_OK as CK_RV);
    assert_eq!(
        source.owner.call(|| api::C_Logout(source.owner.handle)),
        CKR_OK as CK_RV
    );
    assert_ne!(login(&owner, selector, b"123456"), CKR_OK as CK_RV);
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_none()
    );
}

#[test]
fn ccid_dynamic_configured_scp_requires_login_for_pin_management() {
    for recreate in [true, false] {
        let source = Source::new();
        source.aes();
        let mut config = SecureChannelConfiguration::for_test();
        config.recreate_sessions = recreate;
        let (owner, connector) =
            target(base(), &source, config, Some(SecureChannelProtocol::Scp03));
        assert_eq!(
            owner.call(|| api::C_SetPIN(
                owner.handle,
                b"123456".as_ptr().cast_mut(),
                6,
                b"654321".as_ptr().cast_mut(),
                6
            )),
            CKR_USER_NOT_LOGGED_IN as CK_RV
        );
        assert_eq!(
            owner.call(|| api::C_Login(
                owner.handle,
                CKU_USER as _,
                b"123456".as_ptr().cast_mut(),
                6
            )),
            CKR_OK as CK_RV
        );
        switch_away(&connector);
        let mut info = unsafe { std::mem::zeroed() };
        assert_eq!(
            owner.call(|| api::C_GetSessionInfo(owner.handle, &mut info)),
            CKR_OK as CK_RV
        );
        if recreate {
            assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
        } else {
            assert!(connector.send_apdu(&version()).is_err());
            assert_eq!(
                owner.call(|| api::C_Login(
                    owner.handle,
                    CKU_USER as _,
                    b"123456".as_ptr().cast_mut(),
                    6
                )),
                CKR_OK as CK_RV
            );
            assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
        }
        assert!(
            connector
                .applet
                .authentication
                .lock()
                .unwrap()
                .protocol
                .is_none()
        );
    }
}

fn administer(
    base: &EmbeddedVirtualYubiKeyConnector,
    session: &mut Scp03Session,
    op: Op,
) -> Vec<u8> {
    let prepared = SecurityDomainClient
        .prepare_scp11_administration(session, &op)
        .unwrap();
    SecurityDomainClient
        .execute_scp11_administration(base, session, prepared)
        .unwrap()
}

#[test]
fn ccid_scp11_login_reports_missing_card_credential_on_factory_card() {
    for configured in [None, Some(SecureChannelProtocol::Scp11c)] {
        let base = base();
        crate::select_application(base.as_ref(), &SD).unwrap();
        let inventory = SecurityDomainClient
            .get_key_information(base.as_ref())
            .unwrap();
        assert!(
            inventory
                .iter()
                .any(|key| key.key_ref == KeyRef { kid: 0x13, kvn: 1 })
        );
        assert!(
            inventory
                .iter()
                .all(|key| !matches!(key.key_ref.kid, 0x11 | 0x15))
        );
        assert!(
            !SecurityDomainClient
                .get_certificate_bundle(base.as_ref(), KeyRef { kid: 0x13, kvn: 1 })
                .unwrap()
                .is_empty()
        );

        let source = Source::new();
        let leaf = crate::certificate_builder::p256_scp11_oce_certificate(
            scalar(5).verifying_key(),
            &scalar(4),
            "CN=OCE",
            "CN=CA",
            20,
        );
        source.ec(&leaf);
        let (owner, connector) = target_application(
            base.clone(),
            &source,
            SecureChannelConfiguration::for_test(),
            configured,
            CcidApplication::IssuerSecurityDomain,
        );
        assert_eq!(
            login(&owner, b"pkcs11:", b""),
            CKR_KEY_HANDLE_INVALID as CK_RV
        );
        assert_eq!(diagnostic(&owner, false), "none");
        assert_eq!(diagnostic(&owner, true), "none");
        let mut info = unsafe { std::mem::zeroed() };
        assert_eq!(
            owner.call(|| api::C_GetSessionInfo(owner.handle, &mut info)),
            CKR_OK as CK_RV
        );
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
        assert!(
            connector
                .applet
                .authentication
                .lock()
                .unwrap()
                .credential
                .is_none()
        );
        assert_eq!(
            SecurityDomainClient
                .get_key_information(base.as_ref())
                .unwrap(),
            inventory
        );
    }
}

#[test]
fn ccid_dynamic_scp11_a_and_c_resolve_leaf_by_id_and_recreate() {
    for protocol in [SecureChannelProtocol::Scp11a, SecureChannelProtocol::Scp11c] {
        for intermediates in [None, Some(false), Some(true)] {
            for login_mode in 0..3 {
                let base = base();
                crate::select_application(base.as_ref(), &SD).unwrap();
                let mut session = Scp03Session::authenticate_selected(
                    base.as_ref(),
                    &Scp03KeySet::yubikey_factory(),
                    0x33,
                    &SD,
                )
                .unwrap();
                let kid = if protocol == SecureChannelProtocol::Scp11a {
                    0x11
                } else {
                    0x15
                };
                let card = administer(
                    &base,
                    &mut session,
                    Op::GenerateKey {
                        key_ref: KeyRef { kid, kvn: 2 },
                        replace_kvn: 0,
                        curve: 0,
                    },
                );
                let ca = scalar(4);
                let ca_ref = KeyRef { kid: 0x10, kvn: 1 };
                administer(
                    &base,
                    &mut session,
                    Op::PutPublicKey {
                        key_ref: ca_ref,
                        replace_kvn: 0,
                        encoded: ca
                            .verifying_key()
                            .to_public_key_der()
                            .unwrap()
                            .as_bytes()
                            .to_vec(),
                    },
                );
                administer(
                    &base,
                    &mut session,
                    Op::StoreCaIssuer {
                        key_ref: ca_ref,
                        subject_key_identifier: software_key_core::digest::HashAlgorithm::Sha1
                            .digest(ca.verifying_key().to_sec1_point(false).as_bytes()),
                    },
                );
                let intermediate_key = scalar(6);
                let issuer = if intermediates.is_some() {
                    &intermediate_key
                } else {
                    &ca
                };
                let issuer_name = if intermediates.is_some() {
                    "CN=intermediate"
                } else {
                    "CN=CA"
                };
                let leaf = crate::certificate_builder::p256_scp11_oce_certificate(
                    scalar(5).verifying_key(),
                    issuer,
                    "CN=OCE",
                    issuer_name,
                    20,
                );
                let source = Source::new();
                let key = source.ec(&leaf);
                assert!(source.owner.attribute(key, CKA_VALUE).is_err());
                let mut config = SecureChannelConfiguration::for_test();
                config.scp11.trust = crate::configuration::Scp11TrustConfiguration::PublicKey(card);
                config.scp11.key_version = 2;
                config.scp11.oce_key_id = 0x10;
                config.scp11.oce_key_version = 1;
                if intermediates == Some(true) {
                    config.scp11.oce_intermediates.push(
                        crate::certificate_builder::p256_certificate(
                            intermediate_key.verifying_key(),
                            &ca,
                            "CN=intermediate",
                            "CN=CA",
                            21,
                            true,
                        ),
                    );
                }
                let selector = b"pkcs11:object=client;type=private";
                if login_mode != 0 {
                    config.client_uri = Some(selector.to_vec());
                }
                let configured = (protocol == SecureChannelProtocol::Scp11c).then_some(protocol);
                let (owner, connector) = target(base, &source, config, configured);
                let result = match login_mode {
                    0 => login(&owner, selector, b"123456"),
                    1 => owner.call(|| {
                        api::C_Login(
                            owner.handle,
                            CKU_USER as _,
                            b"123456".as_ptr().cast_mut(),
                            6,
                        )
                    }),
                    _ => owner.call(|| {
                        api::C_LoginUser(
                            owner.handle,
                            CKU_USER as _,
                            b"123456".as_ptr().cast_mut(),
                            6,
                            std::ptr::null_mut(),
                            0,
                        )
                    }),
                };
                if intermediates == Some(false) {
                    assert_ne!(result, CKR_OK as CK_RV);
                    assert!(
                        connector
                            .applet
                            .authentication
                            .lock()
                            .unwrap()
                            .credential
                            .is_none()
                    );
                    assert!(connector.send_apdu(&version()).is_err());
                    continue;
                }
                assert_eq!(
                    result, CKR_OK as CK_RV,
                    "{protocol:?}, intermediates={intermediates:?}, login_mode={login_mode}"
                );
                assert_eq!(diagnostic(&owner, false), protocol.name());
                assert_eq!(
                    diagnostic(&owner, true).as_bytes(),
                    source
                        .owner
                        .attribute(key, CKA_PKCS11RS_URI as _)
                        .unwrap()
                        .as_slice()
                );
                assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
                switch_away(&connector);
                assert_eq!(diagnostic(&owner, false), "none");
                assert_eq!(diagnostic(&owner, true), "none");
                assert_eq!(connector.send_apdu(&version()).unwrap().data, [5, 8, 0]);
                assert!(source.owner.attribute(key, CKA_VALUE).is_err());
                // Applet authorization is lost, but the dynamic selection survives until logout.
                assert_eq!(
                    owner.call(|| api::C_Logout(owner.handle)),
                    CKR_USER_NOT_LOGGED_IN as CK_RV
                );
                assert!(
                    connector
                        .applet
                        .authentication
                        .lock()
                        .unwrap()
                        .credential
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn ccid_dynamic_last_session_close_releases_binding_after_deselection() {
    for all in [false, true] {
        let source = Source::new();
        source.aes();
        let (owner, connector) = target(
            base(),
            &source,
            SecureChannelConfiguration::for_test(),
            None,
        );
        assert_eq!(
            login(
                &owner,
                b"pkcs11:object=client.enc;type=secret-key",
                b"123456"
            ),
            CKR_OK as CK_RV
        );
        switch_away(&connector);
        let result = if all {
            owner.call(|| api::C_CloseAllSessions(1))
        } else {
            owner.call(|| api::C_CloseSession(owner.handle))
        };
        assert_eq!(result, CKR_OK as CK_RV);
        assert!(
            connector
                .applet
                .authentication
                .lock()
                .unwrap()
                .credential
                .is_none()
        );
        assert!(connector.send_apdu(&version()).is_err());
        assert_eq!(source.child.lock().unwrap().sessions.len(), 1);
    }
}

#[test]
fn ccid_dynamic_recreation_does_not_reselect_replacement_key() {
    let source = Source::new();
    source.aes();
    let (owner, connector) = target(
        base(),
        &source,
        SecureChannelConfiguration::for_test(),
        None,
    );
    assert_eq!(
        login(
            &owner,
            b"pkcs11:object=client.enc;type=secret-key",
            b"123456"
        ),
        CKR_OK as CK_RV
    );
    let mac = source.owner.find(&[(CKA_LABEL, b"client.mac")]).unwrap()[0];
    source.owner.destroy(mac).unwrap();
    let mut template = scp_key_provider::aes_credential_template();
    template.token = true;
    template.label = "client.mac".into();
    source
        .owner
        .create(template, &[(CKA_VALUE, &crate::scp03::YUBIKEY_FACTORY_KEY)])
        .unwrap();
    switch_away(&connector);
    assert!(connector.send_apdu(&version()).is_err());
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_none()
    );
}

#[test]
fn ccid_dynamic_scp11_rejects_mismatched_certificate_key() {
    let source = Source::new();
    let leaf = crate::certificate_builder::p256_certificate(
        scalar(6).verifying_key(),
        &scalar(4),
        "CN=OCE",
        "CN=CA",
        20,
        false,
    );
    source.ec(&leaf);
    let (owner, connector) = target(
        base(),
        &source,
        SecureChannelConfiguration::for_test(),
        None,
    );
    assert_eq!(
        login(&owner, b"pkcs11:object=client;type=private", b"123456"),
        CKR_PUBLIC_KEY_INVALID as CK_RV
    );
    assert!(
        connector
            .applet
            .authentication
            .lock()
            .unwrap()
            .credential
            .is_none()
    );
    assert_eq!(source.child.lock().unwrap().sessions.len(), 1);
}

#[test]
fn ccid_dynamic_intermediates_are_resolved_from_bundle_without_transmitting_root() {
    let root_key = scalar(4);
    let intermediate_key = scalar(6);
    let root = crate::certificate_builder::p256_certificate(
        root_key.verifying_key(),
        &root_key,
        "CN=root",
        "CN=root",
        1,
        true,
    );
    let intermediate = crate::certificate_builder::p256_certificate(
        intermediate_key.verifying_key(),
        &root_key,
        "CN=intermediate",
        "CN=root",
        2,
        true,
    );
    let leaf = crate::certificate_builder::p256_scp11_oce_certificate(
        scalar(5).verifying_key(),
        &intermediate_key,
        "CN=OCE",
        "CN=intermediate",
        3,
    );
    assert_eq!(
        oce_chain(leaf.clone(), &[root, intermediate.clone()]).unwrap(),
        vec![leaf.clone(), intermediate]
    );
    assert_eq!(oce_chain(leaf.clone(), &[]).unwrap(), vec![leaf]);
}
