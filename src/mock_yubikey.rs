use crate::{ApduCapabilities, CKR_DEVICE_ERROR, Connector, Error};
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use virtual_yubikey_core::{DeviceProfile, FidoConfiguration, VirtualYubiKey};

const MOCK_SERIAL: u32 = 1;

fn device(configuration: FidoConfiguration) -> VirtualYubiKey {
    VirtualYubiKey::with_fido_configuration(
        DeviceProfile::yubikey_5_8_ccid(MOCK_SERIAL),
        configuration,
    )
}

#[cfg(test)]
fn protocol_one_configuration() -> FidoConfiguration {
    FidoConfiguration::default()
        .with_pin_uv_auth_protocols(vec![1])
        .with_permissioned_pin_uv_auth_tokens(false)
}

static PROCESS_MOCK_STATE: OnceLock<Arc<Mutex<VirtualYubiKey>>> = OnceLock::new();

/// An in-process YubiKey FIDO2 applet visible only through a pkcs11rs build
/// compiled with the `mock-yubikey` feature.
#[derive(Debug)]
pub(crate) struct MockYubiKeyConnector {
    state: Arc<Mutex<VirtualYubiKey>>,
}

impl MockYubiKeyConnector {
    #[cfg(test)]
    pub(crate) fn restore_persistent_state(&self, profile: DeviceProfile) {
        let mut state = self.state.lock().unwrap();
        *state = VirtualYubiKey::from_persistent_states(
            profile,
            &state.piv_persistent_state().unwrap(),
            &state.hsmauth_persistent_state().unwrap(),
            &state.security_domain_persistent_state().unwrap(),
        )
        .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn from_device(device: VirtualYubiKey) -> Self {
        Self {
            state: Arc::new(Mutex::new(device)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            state: Arc::new(Mutex::new(device(FidoConfiguration::default()))),
        })
    }

    pub(crate) fn process_device() -> Result<Self, Error> {
        let state = PROCESS_MOCK_STATE
            .get_or_init(|| Arc::new(Mutex::new(device(FidoConfiguration::default()))))
            .clone();
        state
            .lock()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .reset();
        Ok(Self { state })
    }

    #[cfg(test)]
    pub(crate) fn protocol_one_only() -> Result<Self, Error> {
        Ok(Self {
            state: Arc::new(Mutex::new(device(protocol_one_configuration()))),
        })
    }

    #[cfg(test)]
    pub(crate) fn protocol_one_without_pin() -> Result<Self, Error> {
        Ok(Self {
            state: Arc::new(Mutex::new(device(
                protocol_one_configuration().without_pin(),
            ))),
        })
    }

    fn exchange(&self, encoded: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .transmit(encoded))
    }
}

impl Connector for MockYubiKeyConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Yubico"
    }

    fn product(&self) -> &str {
        "Mock YubiKey FIDO2"
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
        None
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
    fn mock_selects_only_fido_and_answers_get_info_through_ccid() {
        let connector = Rc::new(MockYubiKeyConnector::new().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let info = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)))
            .get_info()
            .unwrap();
        assert!(info.versions.iter().any(|version| version == "FIDO_2_1"));
        assert_eq!(info.extensions, ["previewSign"]);
        assert!(info.option("rk"));
        assert!(info.option("clientPin"));
    }

    fn exercise_pin_and_credential_management(connector: Rc<MockYubiKeyConnector>) {
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
            .create_preview_sign_registration(&preview_authorization, Some("MOCK0001".to_owned()))
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
    fn mock_default_pin_can_be_verified_and_changed_through_ctap() {
        exercise_pin_and_credential_management(Rc::new(MockYubiKeyConnector::new().unwrap()));
    }

    #[test]
    fn protocol_one_only_mock_supports_legacy_pin_and_credential_management() {
        exercise_pin_and_credential_management(Rc::new(
            MockYubiKeyConnector::protocol_one_only().unwrap(),
        ));
    }

    #[test]
    fn protocol_one_only_mock_supports_initial_pin_provisioning() {
        let connector = Rc::new(MockYubiKeyConnector::protocol_one_without_pin().unwrap());
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
        let connector = MockYubiKeyConnector::new().unwrap();
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
        let connector = MockYubiKeyConnector::new().unwrap();
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
