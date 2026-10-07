use crate::{ApduCapabilities, CKR_DEVICE_ERROR, Connector, Error};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(unix)]
use virtual_yubikey_core::storage::{
    DEFAULT_PERSISTENCE_MODE, DevicePersistence, DevicePersistenceHandle, DeviceStorage,
    PersistentApplet,
};
use virtual_yubikey_core::{AppletConfiguration, DeviceProfile, FidoConfiguration, VirtualYubiKey};

#[cfg(test)]
const EMBEDDED_SERIAL: u32 = 1;

#[cfg(test)]
fn device(configuration: FidoConfiguration) -> VirtualYubiKey {
    VirtualYubiKey::with_fido_configuration(
        DeviceProfile::yubikey_5_8_ccid(EMBEDDED_SERIAL),
        configuration,
    )
}

#[cfg(test)]
fn protocol_one_configuration() -> FidoConfiguration {
    FidoConfiguration::default()
        .with_pin_uv_auth_protocols(vec![1])
        .with_permissioned_pin_uv_auth_tokens(false)
}

#[cfg(unix)]
struct PersistentEmbeddedState {
    handle: DevicePersistenceHandle,
    _persistence: DevicePersistence,
}

/// An embedded virtual YubiKey CCID reader visible through a pkcs11rs build
/// compiled with the `embedded-virtual-yubikey` feature.
pub(crate) struct EmbeddedVirtualYubiKeyConnector {
    name: String,
    state: Arc<Mutex<VirtualYubiKey>>,
    #[cfg(unix)]
    persistent: Option<Arc<PersistentEmbeddedState>>,
}

impl std::fmt::Debug for EmbeddedVirtualYubiKeyConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddedVirtualYubiKeyConnector")
            .field("name", &self.name)
            .field("persistent", &{
                #[cfg(unix)]
                {
                    self.persistent.is_some()
                }
                #[cfg(not(unix))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

impl EmbeddedVirtualYubiKeyConnector {
    pub(crate) fn configured(
        name: String,
        serial: u32,
        applets: AppletConfiguration,
        persistent_root: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let profile = DeviceProfile {
            applets,
            ..DeviceProfile::yubikey_5_8_ccid(serial)
        };
        let configuration = FidoConfiguration::default();
        let Some(root) = persistent_root else {
            return Ok(Self {
                name,
                state: Arc::new(Mutex::new(VirtualYubiKey::with_fido_configuration(
                    profile,
                    configuration,
                ))),
                #[cfg(unix)]
                persistent: None,
            });
        };

        #[cfg(not(unix))]
        {
            let _ = root;
            return Err(crate::CKR_ARGUMENTS_BAD.into());
        }

        #[cfg(unix)]
        {
            let (storage, device) = DeviceStorage::open(&root, profile, configuration)?;
            let state = Arc::new(Mutex::new(device));
            let snapshot_state = state.clone();
            let persistence = storage.start(
                DEFAULT_PERSISTENCE_MODE,
                move |applet| {
                    snapshot_state
                        .lock()
                        .map_err(|_| std::io::Error::other("virtual YubiKey state lock poisoned"))?
                        .persistent_applet(applet)
                },
                || tracing::error!("embedded virtual YubiKey persistence failed"),
            )?;
            let handle = persistence.handle();
            Ok(Self {
                name,
                state,
                persistent: Some(Arc::new(PersistentEmbeddedState {
                    handle,
                    _persistence: persistence,
                })),
            })
        }
    }

    #[cfg(test)]
    pub(crate) fn restore_persistent_state(&self, profile: DeviceProfile) {
        let mut state = self.state.lock().unwrap();
        let encoded = state.persistent_state().unwrap();
        *state =
            VirtualYubiKey::from_persistent_state(profile, FidoConfiguration::default(), &encoded)
                .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn from_device(device: VirtualYubiKey) -> Self {
        Self {
            name: "Embedded Virtual YubiKey".to_owned(),
            state: Arc::new(Mutex::new(device)),
            #[cfg(unix)]
            persistent: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            name: "Embedded Virtual YubiKey".to_owned(),
            state: Arc::new(Mutex::new(device(FidoConfiguration::default()))),
            #[cfg(unix)]
            persistent: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn protocol_one_only() -> Result<Self, Error> {
        Ok(Self {
            name: "Embedded Virtual YubiKey".to_owned(),
            state: Arc::new(Mutex::new(device(protocol_one_configuration()))),
            #[cfg(unix)]
            persistent: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn protocol_one_without_pin() -> Result<Self, Error> {
        Ok(Self {
            name: "Embedded Virtual YubiKey".to_owned(),
            state: Arc::new(Mutex::new(device(
                protocol_one_configuration().without_pin(),
            ))),
            #[cfg(unix)]
            persistent: None,
        })
    }

    fn exchange(&self, encoded: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let response = state.transmit(encoded);
        #[cfg(unix)]
        let persistent_changes = state.take_persistent_applets();
        #[cfg(not(unix))]
        state.take_persistent_change();
        #[cfg(unix)]
        let force_fido = persistent_changes.contains(&PersistentApplet::Fido)
            || persistent_changes.contains(&PersistentApplet::Management);
        #[cfg(unix)]
        let receipt = self
            .persistent
            .as_ref()
            .map(|persistent| persistent.handle.record_mutations(persistent_changes))
            .transpose()?
            .flatten();
        drop(state);
        #[cfg(unix)]
        if let Some(receipt) = receipt {
            receipt.wait()?;
            if force_fido && let Some(persistent) = &self.persistent {
                persistent.handle.flush()?;
            }
        }
        Ok(response)
    }
}

impl Connector for EmbeddedVirtualYubiKeyConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Yubico"
    }

    fn product(&self) -> &str {
        "Embedded Virtual YubiKey"
    }

    fn supports_piv_pqc(&self) -> bool {
        true
    }

    fn major(&self) -> u8 {
        0
    }

    fn minor(&self) -> u8 {
        1
    }

    fn hardware_version(&self) -> Option<(u8, u8)> {
        Some((1, 0))
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        Some((5, 8, 0))
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        65_538
    }

    fn apdu_capabilities(&self) -> ApduCapabilities {
        ApduCapabilities::SHORT_ONLY
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = self.exchange(send_buffer)?;
        if response.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scp03::YUBIKEY_SECURITY_LEVEL;
    use crate::{
        CcidCtapTransport, CtapClient, Scp03KeySet, Scp03Session, Scp11KeySet,
        SecurityDomainClient, select_application,
    };
    use std::rc::Rc;

    #[cfg(unix)]
    struct TestDirectory(PathBuf);
    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pkcs11rs-shared-yubikey-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn embedded_openpgp_client_discovers_all_rsa_steps_and_signs_with_an_intermediate_size() {
        use crate::openpgp::{Algorithm, Client, KeyRef, PublicKey};
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        let client = Client;
        client
            .select(&connector, &crate::openpgp::OPENPGP_AID)
            .unwrap();
        client.verify_admin(&connector, b"12345678").unwrap();
        for bits in (2048u16..=4096).step_by(256).chain([2560]) {
            let [high, low] = bits.to_be_bytes();
            assert_eq!(
                connector
                    .send_apdu(&crate::scp03::CommandApdu {
                        cla: 0,
                        ins: 0xda,
                        p1: 0,
                        p2: 0xc1,
                        data: vec![1, high, low, 0, 32, 0],
                        le: None,
                        extended: false,
                    })
                    .unwrap()
                    .status,
                0x9000
            );
            let info = client
                .select(&connector, &crate::openpgp::OPENPGP_AID)
                .unwrap();
            assert_eq!(
                info.algorithm(KeyRef::Signature),
                Some(Algorithm::Rsa {
                    bits: usize::from(bits)
                })
            );
        }
        let PublicKey::Rsa(public) = client
            .generate_key_pair_if_empty(
                &connector,
                &crate::openpgp::OPENPGP_AID,
                KeyRef::Signature,
                Algorithm::Rsa { bits: 2560 },
            )
            .unwrap()
        else {
            panic!("wrong key type")
        };
        client
            .verify_password(
                &connector,
                crate::openpgp::PasswordRef::UserSignature,
                b"123456",
            )
            .unwrap();
        let digest = software_key_core::digest::HashAlgorithm::Sha256.digest(b"intermediate RSA");
        let signature = client.sign(&connector, KeyRef::Signature, &digest).unwrap();
        assert_eq!(signature.len(), 320);
        public
            .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &digest, &signature)
            .unwrap();
        assert!(client.sign(&connector, KeyRef::Signature, &digest).is_err());
    }

    #[test]
    fn embedded_openpgp_client_discovers_generates_signs_and_restores_keys() {
        use crate::openpgp::{Algorithm, Client, Curve, KeyRef, PasswordRef, PublicKey};
        use signature::hazmat::PrehashVerifier;
        #[cfg(unix)]
        let directory = TestDirectory::new();
        #[cfg(unix)]
        let connector = EmbeddedVirtualYubiKeyConnector::configured(
            "Persistent test reader".into(),
            EMBEDDED_SERIAL,
            DeviceProfile::yubikey_5_8_ccid(EMBEDDED_SERIAL).applets,
            Some(directory.path().to_owned()),
        )
        .unwrap();
        #[cfg(not(unix))]
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        let client = Client;
        let info = client
            .select(&connector, &crate::openpgp::OPENPGP_AID)
            .unwrap();
        assert_eq!(info.version, (3, 4));
        assert_eq!(
            info.algorithm(KeyRef::Signature),
            Some(Algorithm::Rsa { bits: 2048 })
        );
        client.verify_admin(&connector, b"12345678").unwrap();
        // The provider deliberately refuses algorithm changes; this isolated virtual
        // fixture provisions an empty slot through the raw connector.
        assert_eq!(
            connector
                .send_apdu(&crate::scp03::CommandApdu {
                    cla: 0,
                    ins: 0xda,
                    p1: 0,
                    p2: 0xc1,
                    data: vec![0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
                    le: None,
                    extended: false
                })
                .unwrap()
                .status,
            0x9000
        );
        let public = client
            .generate_key_pair_if_empty(
                &connector,
                &crate::openpgp::OPENPGP_AID,
                KeyRef::Signature,
                Algorithm::Ecdsa(Curve::P256),
            )
            .unwrap();
        let PublicKey::Ec { point, .. } = public else {
            panic!("wrong key type")
        };
        let digest = software_key_core::digest::HashAlgorithm::Sha256.digest(b"embedded OpenPGP");
        assert!(client.sign(&connector, KeyRef::Signature, &digest).is_err());
        client
            .verify_password(&connector, PasswordRef::UserSignature, b"123456")
            .unwrap();
        let signature = client.sign(&connector, KeyRef::Signature, &digest).unwrap();
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&[vec![4], point.clone()].concat())
            .unwrap()
            .verify_prehash(
                &digest,
                &p256::ecdsa::Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        assert!(client.sign(&connector, KeyRef::Signature, &digest).is_err());
        #[cfg(unix)]
        let connector = {
            connector
                .persistent
                .as_ref()
                .unwrap()
                .handle
                .flush()
                .unwrap();
            drop(connector);
            // Reopen as a USB-style split runtime and compare the actual files,
            // then return them unchanged to the embedded host.
            let profile = DeviceProfile::yubikey_5_8_ccid(EMBEDDED_SERIAL);
            let (storage, loaded) = DeviceStorage::open(
                directory.path(),
                profile.clone(),
                FidoConfiguration::default(),
            )
            .unwrap();
            let expected =
                PersistentApplet::ALL.map(|applet| loaded.persistent_applet(applet).unwrap());
            let (card, fido) = loaded.separate_fido();
            for applet in PersistentApplet::ALL {
                assert_eq!(
                    std::fs::read(storage.path(applet)).unwrap(),
                    expected[applet as usize]
                );
            }
            let persistence = storage
                .start(
                    DEFAULT_PERSISTENCE_MODE,
                    move |applet| {
                        if applet == PersistentApplet::Fido {
                            fido.persistent_state().map_err(std::io::Error::other)
                        } else {
                            card.persistent_applet(applet)
                        }
                    },
                    || {},
                )
                .unwrap();
            persistence
                .handle()
                .record_mutations(PersistentApplet::ALL)
                .unwrap();
            persistence.shutdown().unwrap();
            assert!(!directory.path().join("state.cbor").exists());
            EmbeddedVirtualYubiKeyConnector::configured(
                "Persistent test reader".into(),
                EMBEDDED_SERIAL,
                profile.applets,
                Some(directory.path().to_owned()),
            )
            .unwrap()
        };
        #[cfg(not(unix))]
        connector.restore_persistent_state(DeviceProfile::yubikey_5_8_ccid(EMBEDDED_SERIAL));
        client
            .select(&connector, &crate::openpgp::OPENPGP_AID)
            .unwrap();
        let PublicKey::Ec {
            point: restored, ..
        } = client
            .public_key(&connector, KeyRef::Signature, Algorithm::Ecdsa(Curve::P256))
            .unwrap()
        else {
            panic!("wrong restored key")
        };
        assert_eq!(restored, point);
        assert!(client.sign(&connector, KeyRef::Signature, &digest).is_err());
    }

    #[test]
    fn embedded_connector_answers_fido_get_info_through_ccid() {
        let connector = Rc::new(EmbeddedVirtualYubiKeyConnector::new().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let info = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)))
            .get_info()
            .unwrap();
        assert!(info.versions.iter().any(|version| version == "FIDO_2_1"));
        assert_eq!(info.extensions, ["previewSign"]);
        assert!(info.option("rk"));
        assert!(info.option("clientPin"));
    }

    #[test]
    fn direct_piv_deauthentication_clears_pin_but_not_management_authentication() {
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        let client = crate::PivClient;
        client.select(&connector, &crate::piv::PIV_AID).unwrap();
        let management_key =
            crate::parse_hex("010203040506070801020304050607080102030405060708").unwrap();
        client
            .authenticate_management_key(&connector, &management_key)
            .unwrap();
        client.verify_pin(&connector, b"123456").unwrap();

        client
            .generate_key_pair(
                &connector,
                crate::piv::Slot::Retired1,
                crate::piv::Algorithm::EccP256,
                2,
                1,
            )
            .unwrap();
        client
            .sign(
                &connector,
                crate::piv::Slot::Retired1,
                crate::piv::Algorithm::EccP256,
                &[0x31; 32],
                None,
            )
            .unwrap();

        client.deauthenticate_pin(&connector).unwrap();
        assert!(matches!(
            client.sign(
                &connector,
                crate::piv::Slot::Retired1,
                crate::piv::Algorithm::EccP256,
                &[0x31; 32],
                None,
            ),
            Err(Error::Generic(rv)) if rv == crate::CKR_USER_NOT_LOGGED_IN as crate::CK_RV
        ));

        client
            .generate_key_pair(
                &connector,
                crate::piv::Slot::Retired2,
                crate::piv::Algorithm::EccP256,
                2,
                1,
            )
            .expect("VERIFY FF/80 must not clear management-key authentication");
    }

    #[test]
    fn piv_pin_and_management_authentication_can_coexist_in_either_order() {
        for management_first in [true, false] {
            let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
            let client = crate::PivClient;
            client.select(&connector, &crate::piv::PIV_AID).unwrap();
            let management_key =
                crate::parse_hex("010203040506070801020304050607080102030405060708").unwrap();
            if management_first {
                client
                    .authenticate_management_key(&connector, &management_key)
                    .unwrap();
                client.verify_pin(&connector, b"123456").unwrap();
            } else {
                client.verify_pin(&connector, b"123456").unwrap();
                client
                    .authenticate_management_key(&connector, &management_key)
                    .unwrap();
            }

            client
                .generate_key_pair(
                    &connector,
                    crate::piv::Slot::Retired1,
                    crate::piv::Algorithm::EccP256,
                    2,
                    1,
                )
                .expect("management authentication must remain active");
            client
                .sign(
                    &connector,
                    crate::piv::Slot::Retired1,
                    crate::piv::Algorithm::EccP256,
                    &[0x31; 32],
                    None,
                )
                .expect("PIN authentication must remain active");
        }
    }

    #[test]
    fn pending_management_authentication_is_cleared_by_next_apdu_without_clearing_pin() {
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        let client = crate::PivClient;
        client.select(&connector, &crate::piv::PIV_AID).unwrap();
        let management_key =
            crate::parse_hex("010203040506070801020304050607080102030405060708").unwrap();
        client.verify_pin(&connector, b"123456").unwrap();
        client
            .authenticate_management_key(&connector, &management_key)
            .unwrap();
        client
            .generate_key_pair(
                &connector,
                crate::piv::Slot::Retired1,
                crate::piv::Algorithm::EccP256,
                2,
                1,
            )
            .unwrap();

        client.deauthenticate_management_key(&connector).unwrap();

        client
            .sign(
                &connector,
                crate::piv::Slot::Retired1,
                crate::piv::Algorithm::EccP256,
                &[0x31; 32],
                None,
            )
            .expect("the APDU that cancels pending management auth must still execute normally");
        assert_eq!(
            client
                .management_authentication_probe_status(&connector)
                .unwrap(),
            0x6982
        );
    }

    fn exercise_pin_and_credential_management(connector: Rc<EmbeddedVirtualYubiKeyConnector>) {
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let client = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)));

        let info = client.get_info().unwrap();
        assert!(info.option("clientPin"));

        client
            .create_discoverable_test_credential(&info, b"123456")
            .unwrap();

        let authorization = client
            .authorize_credential_enumeration(&info, b"123456")
            .unwrap();
        let credentials = client.enumerate_credentials(&info, &authorization).unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(
            credentials[0].relying_party.id.as_deref(),
            Some(crate::ctap::FIDO2_TEST_RP_ID)
        );
        let assertion_authorization = client
            .authorize_assertion(&info, b"123456", crate::ctap::FIDO2_TEST_RP_ID)
            .unwrap();
        client
            .get_assertion(
                &assertion_authorization,
                crate::ctap::FIDO2_TEST_RP_ID,
                &credentials[0].credential_id,
                &[0x33; 32],
            )
            .unwrap();
        let preview_authorization = client.authorize_preview_sign(&info, b"123456").unwrap();
        client
            .create_preview_sign_registration(
                &preview_authorization,
                Some("EMBEDDED0001".to_owned()),
            )
            .unwrap();

        client.change_pin(&info, b"123456", b"654321").unwrap();
        assert!(
            client
                .authorize_credential_enumeration(&info, b"123456")
                .is_err()
        );
        client
            .authorize_credential_enumeration(&info, b"654321")
            .unwrap();
    }

    #[test]
    fn embedded_default_pin_can_be_verified_and_changed_through_ctap() {
        exercise_pin_and_credential_management(Rc::new(
            EmbeddedVirtualYubiKeyConnector::new().unwrap(),
        ));
    }

    #[test]
    fn legacy_pin_token_does_not_authorize_modern_credential_management() {
        let connector = Rc::new(EmbeddedVirtualYubiKeyConnector::protocol_one_only().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let client = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)));
        let info = client.get_info().unwrap();
        client
            .create_discoverable_test_credential(&info, b"123456")
            .unwrap();
        let authorization = client
            .authorize_credential_enumeration(&info, b"123456")
            .unwrap();
        assert!(matches!(
            client.enumerate_credentials(&info, &authorization),
            Err(crate::ctap::CtapError::Status(0x33))
        ));
    }

    #[test]
    fn protocol_one_permissioned_tokens_support_credential_management() {
        exercise_pin_and_credential_management(Rc::new(
            EmbeddedVirtualYubiKeyConnector::from_device(device(
                FidoConfiguration::default().with_pin_uv_auth_protocols(vec![1]),
            )),
        ));
    }

    #[test]
    fn protocol_one_only_embedded_device_supports_initial_pin_provisioning() {
        let connector =
            Rc::new(EmbeddedVirtualYubiKeyConnector::protocol_one_without_pin().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let client = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)));
        let info = client.get_info().unwrap();
        assert!(!info.option("clientPin"));
        client.set_initial_pin(&info, b"123456").unwrap();
        let info = client.get_info().unwrap();
        client
            .authorize_credential_enumeration(&info, b"123456")
            .unwrap();
    }

    #[test]
    fn host_scp03_implementation_interoperates_with_the_virtual_yubikey() {
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        select_application(&connector, &crate::piv::PIV_AID).unwrap();
        let keys = Scp03KeySet::yubikey_factory();
        let mut session = Scp03Session::authenticate_selected(
            &connector,
            &keys,
            YUBIKEY_SECURITY_LEVEL,
            &crate::piv::PIV_AID,
        )
        .unwrap();
        let command = crate::CommandApdu {
            cla: 0,
            ins: 0xfd,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(256),
            extended: false,
        };
        assert_eq!(
            session.transmit(&connector, &command).unwrap().data,
            [5, 8, 0]
        );
    }

    #[test]
    fn host_scp11b_validates_the_virtual_chain_and_protects_piv() {
        let connector = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        select_application(
            &connector,
            &virtual_yubikey_core::ISSUER_SECURITY_DOMAIN_AID,
        )
        .unwrap();
        let key_ref = crate::security_domain::KeyRef { kid: 0x13, kvn: 1 };
        let certificates = SecurityDomainClient
            .get_certificate_bundle(&connector, key_ref)
            .unwrap();
        assert_eq!(certificates.len(), 2);
        let keys = Scp11KeySet::scp11b_from_certificates(1, &certificates[1..], &certificates[..1])
            .unwrap();
        select_application(&connector, &crate::piv::PIV_AID).unwrap();
        let mut session = keys.authenticate_selected(&connector).unwrap();
        let command = crate::CommandApdu {
            cla: 0,
            ins: 0xfd,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(256),
            extended: false,
        };
        assert_eq!(
            session.transmit(&connector, &command).unwrap().data,
            [5, 8, 0]
        );
    }
}
