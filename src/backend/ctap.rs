use super::ccid::PcscAppletSession;
use crate::*;

const NFCCTAP_MSG: u8 = 0x10;
const NFCCTAP_GETRESPONSE: u8 = 0x11;
const NFCCTAP_KEEPALIVE_STATUS: u16 = 0x9100;
const ISO7816_SUCCESS: u16 = 0x9000;
const MAX_KEEPALIVE_RESPONSES: usize = 600;

#[derive(Debug)]
pub(crate) struct CcidCtapTransport {
    connector: Rc<dyn Connector>,
}

impl CcidCtapTransport {
    pub(crate) fn new(connector: Rc<dyn Connector>) -> Self {
        Self { connector }
    }
}

impl CtapTransport for CcidCtapTransport {
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if request.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut command = CommandApdu {
            cla: 0x80,
            ins: NFCCTAP_MSG,
            // Advertise NFCCTAP_GETRESPONSE support as specified by CTAP.
            p1: 0x80,
            p2: 0,
            data: request.to_vec(),
            le: Some(256),
            extended: false,
        };
        for _ in 0..=MAX_KEEPALIVE_RESPONSES {
            let response = self.connector.send_apdu(&command)?;
            match response.status {
                ISO7816_SUCCESS => return Ok(response.data),
                NFCCTAP_KEEPALIVE_STATUS if response.data.len() == 1 => {
                    command = CommandApdu {
                        cla: 0x80,
                        ins: NFCCTAP_GETRESPONSE,
                        p1: 0,
                        p2: 0,
                        data: Vec::new(),
                        le: Some(256),
                        extended: false,
                    };
                }
                _ => return Err(CKR_DEVICE_ERROR.into()),
            }
        }
        Err(CKR_DEVICE_ERROR.into())
    }
}

#[derive(Debug)]
pub(crate) struct Fido2Slot {
    connector: Rc<dyn Connector>,
    client: CtapClient,
    info: RefCell<Option<AuthenticatorInfo>>,
}

impl Fido2Slot {
    pub(crate) fn new(connector: Rc<dyn Connector>) -> Self {
        let transport = Rc::new(CcidCtapTransport::new(connector.clone()));
        Self {
            connector,
            client: CtapClient::new(transport),
            info: RefCell::new(None),
        }
    }

    fn discovered_info(&self) -> Result<AuthenticatorInfo, Error> {
        let mut info = self.info.try_borrow_mut()?;
        if info.is_none() {
            *info = Some(self.client.get_info().map_err(CtapError::into_pkcs11)?);
        }
        info.clone().ok_or(CKR_DEVICE_ERROR.into())
    }

    fn primary_protocol_version(&self) -> Option<String> {
        self.info
            .try_borrow()
            .ok()
            .and_then(|info| info.as_ref()?.versions.first().cloned())
    }
}

impl Slot for Fido2Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        match self.primary_protocol_version() {
            Some(version) => format!("{} FIDO2 ({version})", self.connector.name()),
            None => format!("{} FIDO2", self.connector.name()),
        }
    }

    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }

    fn product(&self) -> &str {
        "FIDO2"
    }

    fn model(&self) -> &str {
        self.connector.product()
    }

    fn label(&self) -> String {
        match self.primary_protocol_version() {
            Some(version) => format!("FIDO2 {version} #{}", self.serial()),
            None => format!("FIDO2 #{}", self.serial()),
        }
    }

    fn serial(&self) -> &str {
        self.connector.serial()
    }

    fn major(&self) -> u8 {
        self.connector.major()
    }

    fn minor(&self) -> u8 {
        self.connector.minor()
    }

    fn is_present(&self) -> bool {
        self.connector.is_present()
    }

    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }

    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }

    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PcscAppletSession {
            slotID: slot_id,
            flags,
            connector: self.connector.clone(),
        })
    }

    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    fn logout(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        let info = self.discovered_info()?;
        log!(
            2,
            "FIDO2 authenticator info on {}: versions {:?}, extensions {:?}, AAGUID {:02x?}, options {:?}, max message {:?}, PIN/UV protocols {:?}, transports {:?}",
            self.connector.name(),
            info.versions,
            info.extensions,
            info.aaguid,
            info.options,
            info.max_msg_size,
            info.pin_uv_auth_protocols,
            info.transports
        );
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let _ = self.discovered_info()?;
        self.format_token_info(info);
        info.flags = CKF_TOKEN_INITIALIZED as CK_FLAGS;
        info.ulMaxPinLen = 0;
        info.ulMinPinLen = 0;
        Ok(())
    }

    fn clear_session(&mut self) {
        self.connector.clear_secure_channel();
    }

    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<Vec<u8>>>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiKey"
        }
        fn serial(&self) -> &str {
            "12345678"
        }
        fn major(&self) -> u8 {
            5
        }
        fn minor(&self) -> u8 {
            80
        }
        fn firmware_version(&self) -> Option<(u8, u8, u8)> {
            Some((5, 8, 0))
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn transmit<'a>(
            &self,
            command: &[u8],
            receive: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(command.to_vec());
            let response = self.responses.borrow_mut().pop_front().unwrap();
            receive[..response.len()].copy_from_slice(&response);
            Ok(&receive[..response.len()])
        }
    }

    #[test]
    fn ccid_transport_uses_fido_iso7816_framing() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        let connector = Rc::new(ScriptedConnector::new(vec![vec![0, 0xa0, 0x90, 0x00]]));
        let transport = CcidCtapTransport::new(connector.clone());
        assert_eq!(
            transport.transact(&[AUTHENTICATOR_GET_INFO]).unwrap(),
            [0, 0xa0]
        );
        assert_eq!(
            connector.commands.borrow()[0],
            [0x80, 0x10, 0x80, 0x00, 0x01, AUTHENTICATOR_GET_INFO, 0x00]
        );
    }

    #[test]
    fn ccid_transport_follows_ctap_keepalive_get_response() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        let connector = Rc::new(ScriptedConnector::new(vec![
            vec![0x01, 0x91, 0x00],
            vec![0, 0xa0, 0x90, 0x00],
        ]));
        let transport = CcidCtapTransport::new(connector.clone());
        assert_eq!(
            transport.transact(&[AUTHENTICATOR_GET_INFO]).unwrap(),
            [0, 0xa0]
        );
        let commands = connector.commands.borrow();
        assert_eq!(commands[0][..4], [0x80, 0x10, 0x80, 0x00]);
        assert_eq!(commands[1], [0x80, 0x11, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ccid_transport_rejects_malformed_keepalive_and_apdu_errors() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        for response in [vec![0x91, 0x00], vec![0x6a, 0x80]] {
            let connector = Rc::new(ScriptedConnector::new(vec![response]));
            let transport = CcidCtapTransport::new(connector);
            assert!(transport.transact(&[AUTHENTICATOR_GET_INFO]).is_err());
        }
    }

    #[test]
    fn discovered_slot_reports_ctap_and_yubikey_information() {
        let mut response = vec![
            0x00, 0xa3, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x03,
            0x50,
        ];
        response.extend([0; 16]);
        response.extend([0x09, 0x81, 0x63, b'u', b's', b'b', 0x90, 0x00]);
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![response]));
        let mut slot = Fido2Slot::new(connector);
        slot.init_slot().unwrap();

        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert!(slot_info
            .slotDescription
            .windows(b"FIDO2 (FIDO_2_1)".len())
            .any(|window| window == b"FIDO2 (FIDO_2_1)"));
        assert_eq!(slot_info.firmwareVersion.major, 5);
        assert_eq!(slot_info.firmwareVersion.minor, 80);

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert!(token_info
            .label
            .windows(b"FIDO2 FIDO_2_1 #12345678".len())
            .any(|window| window == b"FIDO2 FIDO_2_1 #12345678"));
        assert_eq!(token_info.flags, CKF_TOKEN_INITIALIZED as CK_FLAGS);
        assert!(slot.backend_mechanisms().is_empty());
    }

    #[test]
    fn get_info_failure_does_not_withdraw_a_selected_slot() {
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![
            vec![0x01, 0x90, 0x00],
            vec![0x01, 0x90, 0x00],
        ]));
        let mut slot = Fido2Slot::new(connector);
        let error = slot.init_slot().unwrap_err();
        slot.set_discovery_error(&error);

        assert!(slot.is_present());
        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert!(slot_info
            .slotDescription
            .windows(b"FIDO2".len())
            .any(|window| window == b"FIDO2"));
        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert!(slot.get_token_info(&mut token_info).is_err());
    }
}
