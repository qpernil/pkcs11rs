use super::ccid::PcscAppletSession;
use crate::ctap::DiscoverableCredential;
use crate::*;
use minicbor::Encoder;

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
    application_aid: Vec<u8>,
    client: CtapClient,
    info: RefCell<Option<AuthenticatorInfo>>,
    credentials: RefCell<Vec<DiscoverableCredential>>,
    authenticated: Cell<bool>,
}

impl Fido2Slot {
    pub(crate) fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let transport = Rc::new(CcidCtapTransport::new(connector.clone()));
        Self {
            connector,
            application_aid,
            client: CtapClient::new(transport),
            info: RefCell::new(None),
            credentials: RefCell::new(Vec::new()),
            authenticated: Cell::new(false),
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
            .and_then(|info| Some(info.as_ref()?.primary_version()?.to_owned()))
    }
}

fn append_optional_text(
    encoder: &mut Encoder<&mut Vec<u8>>,
    key: u8,
    value: Option<&str>,
) -> Result<(), CtapError> {
    if let Some(value) = value {
        encoder.u8(key)?.str(value)?;
    }
    Ok(())
}

fn credential_metadata(credential: &DiscoverableCredential) -> Result<Vec<u8>, CtapError> {
    let optional_count = [
        credential.relying_party.id.as_ref().map(|_| ()),
        credential.relying_party.name.as_ref().map(|_| ()),
        credential.user_name.as_ref().map(|_| ()),
        credential.user_display_name.as_ref().map(|_| ()),
        credential.cred_protect.map(|_| ()),
        credential.third_party_payment.map(|_| ()),
    ]
    .into_iter()
    .flatten()
    .count();
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map((4 + optional_count) as u64)?
        .u8(1)?
        .bytes(&credential.relying_party.id_hash)?;
    append_optional_text(&mut encoder, 2, credential.relying_party.id.as_deref())?;
    append_optional_text(&mut encoder, 3, credential.relying_party.name.as_deref())?;
    encoder.u8(4)?.bytes(&credential.user_id)?;
    append_optional_text(&mut encoder, 5, credential.user_name.as_deref())?;
    append_optional_text(&mut encoder, 6, credential.user_display_name.as_deref())?;
    encoder
        .u8(7)?
        .bytes(&credential.credential_id)?
        .u8(8)?
        .bytes(&credential.public_key_cose)?;
    if let Some(value) = credential.cred_protect {
        encoder.u8(9)?.u64(value)?;
    }
    if let Some(value) = credential.third_party_payment {
        encoder.u8(10)?.bool(value)?;
    }
    Ok(output)
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn credential_label(credential: &DiscoverableCredential) -> String {
    credential
        .user_display_name
        .as_ref()
        .or(credential.user_name.as_ref())
        .or(credential.relying_party.name.as_ref())
        .or(credential.relying_party.id.as_ref())
        .cloned()
        .unwrap_or_else(|| {
            let id = hex(&credential.credential_id);
            format!("FIDO2 credential {}", &id[..id.len().min(16)])
        })
}

fn fido2_token_objects(
    slot_id: CK_SLOT_ID,
    credentials: &[DiscoverableCredential],
) -> Result<Vec<TokenObject>, Error> {
    credentials
        .iter()
        .map(|credential| {
            let rp_id_hash = hex(&credential.relying_party.id_hash);
            let credential_id = hex(&credential.credential_id);
            Ok(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("fido2-credential:{rp_id_hash}:{credential_id}"),
                class: CKO_DATA as CK_OBJECT_CLASS,
                key_type: 0,
                label: credential_label(credential),
                id: credential.credential_id.clone(),
                token: true,
                private: true,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: false,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                creator_session: None,
                material: KeyMaterial::FidoCredential {
                    rp_id_hash: credential.relying_party.id_hash,
                    metadata: credential_metadata(credential).map_err(CtapError::into_pkcs11)?,
                },
            })
        })
        .collect()
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

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        let pin_text = std::str::from_utf8(pin).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        if pin.len() > 63 || pin_text.chars().count() < 4 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.connector.clear_secure_channel();
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = self.discovered_info()?;
            let authorization = self
                .client
                .authorize_credential_enumeration(&info, pin)
                .map_err(CtapError::into_pkcs11)?;
            self.client
                .enumerate_credentials(&info, &authorization)
                .map_err(CtapError::into_pkcs11)
        })();
        match result {
            Ok(credentials) => {
                *self.credentials.get_mut() = credentials;
                self.authenticated.set(true);
                Ok(())
            }
            Err(error) => {
                self.connector.clear_secure_channel();
                Err(error)
            }
        }
    }

    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.connector.clear_secure_channel();
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        let info = self.discovered_info()?;
        log!(
            2,
            "FIDO2 authenticator info on {}: versions {:?}, extensions {:?}, AAGUID {:02x?}, options {:?}, max message {:?}, PIN/UV protocols {:?}, transports {:?}, minimum PIN length {:?}",
            self.connector.name(),
            info.versions,
            info.extensions,
            info.aaguid,
            info.options,
            info.max_msg_size,
            info.pin_uv_auth_protocols,
            info.transports,
            info.min_pin_length
        );
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let discovered = self.discovered_info()?;
        self.format_token_info(info);
        info.flags = (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED) as CK_FLAGS;
        if discovered.option("clientPin") {
            info.flags |= CKF_USER_PIN_INITIALIZED as CK_FLAGS;
        }
        info.ulMaxPinLen = 63;
        info.ulMinPinLen = discovered.min_pin_length.unwrap_or(4) as CK_ULONG;
        Ok(())
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    fn fido2_provision_pin(&mut self, new_pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.connector.clear_secure_channel();
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = self.discovered_info()?;
            self.client
                .provision_pin(&info, new_pin)
                .map_err(CtapError::into_pkcs11)?;
            self.info.get_mut().take();
            let refreshed = self.discovered_info()?;
            if !refreshed.option("clientPin") {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(())
        })();
        self.connector.clear_secure_channel();
        result
    }

    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.connector.clear_secure_channel();
    }

    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }

    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }

    fn mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }

    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if !self.authenticated.get() {
            return Ok(Vec::new());
        }
        let credentials = self
            .credentials
            .try_borrow()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        fido2_token_objects(slot_id, &credentials)
    }

    fn refresh_token_objects_after_login(&self) -> bool {
        true
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    fn is_fido2(&self) -> bool {
        true
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
        let mut slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());
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
        assert_eq!(
            token_info.flags,
            (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED) as CK_FLAGS
        );
        assert_eq!(token_info.ulMinPinLen, 4);
        assert_eq!(token_info.ulMaxPinLen, 63);
        assert!(slot.backend_mechanisms().is_empty());
    }

    #[test]
    fn get_info_failure_does_not_withdraw_a_selected_slot() {
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![
            vec![0x01, 0x90, 0x00],
            vec![0x01, 0x90, 0x00],
        ]));
        let mut slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());
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

    #[test]
    fn discoverable_credentials_are_private_immutable_data_objects() {
        let credential = DiscoverableCredential {
            relying_party: crate::ctap::RelyingParty {
                id: Some("example.com".to_owned()),
                name: Some("Example".to_owned()),
                id_hash: [0x11; 32],
            },
            user_id: b"user-id".to_vec(),
            user_name: Some("alice".to_owned()),
            user_display_name: Some("Alice".to_owned()),
            credential_id: vec![0x22; 32],
            public_key_cose: vec![0xa1, 0x01, 0x02],
            cred_protect: Some(3),
            third_party_payment: Some(true),
        };
        let objects = fido2_token_objects(7, &[credential]).unwrap();
        let object = &objects[0];
        assert_eq!(object.slot_id, Some(7));
        assert_eq!(object.class, CKO_DATA as CK_OBJECT_CLASS);
        assert_eq!(object.label, "Alice");
        assert_eq!(object.id, [0x22; 32]);
        assert!(object.private);
        assert!(!object.sign);
        assert!(object.is_immutable_object());
        assert_eq!(
            object.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
            Some(b"FIDO2 discoverable credential".to_vec())
        );
        assert_eq!(
            object.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
            Some(vec![0x11; 32])
        );

        let metadata = object
            .attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE)
            .unwrap();
        let mut decoder = minicbor::Decoder::new(&metadata);
        assert_eq!(decoder.map().unwrap(), Some(10));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.bytes().unwrap(), &[0x11; 32]);
    }
}
