use crate::{ApduCapabilities, CKR_DEVICE_ERROR, Connector, Error};
#[cfg(unix)]
use software_key_core::state_persistence::{
    PersistenceMode, StateLock, StatePersistence, StatePersistenceHandle,
};
#[cfg(unix)]
use std::io;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
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
    handle: StatePersistenceHandle<VirtualYubiKey>,
    _persistence: StatePersistence<VirtualYubiKey>,
    _lock: StateLock,
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
            std::fs::create_dir_all(&root)?;
            let lock = StateLock::acquire(root.join("state.lock"))?;
            let state_path = root.join("state.cbor");
            let (state, created) = match std::fs::read(&state_path) {
                Ok(encoded) => (
                    VirtualYubiKey::from_persistent_state(profile, configuration, &encoded)
                        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
                    false,
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (
                    VirtualYubiKey::with_fido_configuration(profile, configuration),
                    true,
                ),
                Err(error) => return Err(error.into()),
            };
            let persistence = StatePersistence::start(
                state,
                state_path,
                PersistenceMode::Batched(Duration::from_millis(250)),
                |state| state.persistent_state().map_err(io::Error::other),
                || tracing::error!("embedded virtual YubiKey persistence failed"),
            )?;
            let handle = persistence.handle();
            if created {
                handle.record_mutation()?.wait()?;
                persistence.flush()?;
            }
            let state = handle.state().clone();
            Ok(Self {
                name,
                state,
                persistent: Some(Arc::new(PersistentEmbeddedState {
                    handle,
                    _persistence: persistence,
                    _lock: lock,
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
        let persistent_change = state.take_persistent_change();
        #[cfg(unix)]
        let receipt = if persistent_change {
            self.persistent
                .as_ref()
                .map(|persistent| persistent.handle.record_mutation())
                .transpose()?
        } else {
            None
        };
        #[cfg(not(unix))]
        let _ = persistent_change;
        drop(state);
        #[cfg(unix)]
        if let Some(receipt) = receipt {
            receipt.wait()?;
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
