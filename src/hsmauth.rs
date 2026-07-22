use crate::{
    CommandApdu, Connector, Error, ResponseApdu, CKR_ARGUMENTS_BAD, CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_REJECTED, CKR_OBJECT_HANDLE_INVALID,
    CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_TOKEN_NOT_RECOGNIZED, CKR_USER_NOT_LOGGED_IN, CK_RV,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];

const TAG_LABEL: u8 = 0x71;
const TAG_LABEL_LIST: u8 = 0x72;
const TAG_CREDENTIAL_PASSWORD: u8 = 0x73;
const TAG_ALGORITHM: u8 = 0x74;
const TAG_KEY_ENC: u8 = 0x75;
const TAG_KEY_MAC: u8 = 0x76;
const TAG_CONTEXT: u8 = 0x77;
const TAG_RESPONSE: u8 = 0x78;
const TAG_TOUCH: u8 = 0x7a;
const TAG_MANAGEMENT_KEY: u8 = 0x7b;
const TAG_PUBLIC_KEY: u8 = 0x7c;
const TAG_PRIVATE_KEY: u8 = 0x7d;

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_CALCULATE: u8 = 0x03;
const INS_GET_CHALLENGE: u8 = 0x04;
const INS_LIST: u8 = 0x05;
const INS_RESET: u8 = 0x06;
const INS_GET_VERSION: u8 = 0x07;
const INS_PUT_MANAGEMENT_KEY: u8 = 0x08;
const INS_GET_MANAGEMENT_KEY_RETRIES: u8 = 0x09;
const INS_GET_PUBLIC_KEY: u8 = 0x0a;
const INS_CHANGE_CREDENTIAL_PASSWORD: u8 = 0x0b;

const STATUS_SUCCESS: u16 = 0x9000;
const MANAGEMENT_KEY_LENGTH: usize = 16;
const CREDENTIAL_PASSWORD_LENGTH: usize = 16;
const MIN_LABEL_LENGTH: usize = 1;
const MAX_LABEL_LENGTH: usize = 64;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const SESSION_KEY_LENGTH: usize = 16;
const SESSION_KEYS_LENGTH: usize = SESSION_KEY_LENGTH * 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Algorithm {
    Aes128YubicoAuthentication = 38,
    EcP256YubicoAuthentication = 39,
}

impl TryFrom<u8> for Algorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            38 => Ok(Self::Aes128YubicoAuthentication),
            39 => Ok(Self::EcP256YubicoAuthentication),
            _ => Err(CKR_DATA_INVALID.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Credential {
    pub(crate) label: String,
    pub(crate) algorithm: Algorithm,
    pub(crate) retries: u8,
    pub(crate) touch_required: bool,
    pub(crate) public_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Info {
    pub(crate) version: (u8, u8, u8),
    pub(crate) management_key_retries: u8,
    pub(crate) credentials: Vec<Credential>,
}

pub(crate) struct SessionKeys {
    pub(crate) enc: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
    pub(crate) mac: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
    pub(crate) rmac: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SymmetricCredentialKeys<'a> {
    pub(crate) enc: &'a [u8],
    pub(crate) mac: &'a [u8],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

pub(crate) struct Client;

impl Client {
    pub(crate) fn discover(&self, connector: &dyn Connector) -> Result<Info, Error> {
        log!(2, "YubiHSM Auth discovery started on {}", connector.name());
        let version = self.get_version(connector)?;
        let management_key_retries = self.get_management_key_retries(connector)?;
        let mut credentials = self.list_credentials(connector)?;
        for credential in &mut credentials {
            if credential.algorithm == Algorithm::EcP256YubicoAuthentication {
                credential.public_key = Some(self.get_public_key(connector, &credential.label)?);
            }
        }
        log!(
            2,
            "YubiHSM Auth discovery found version {}.{}.{}, {} management-key retries, and {} credentials",
            version.0,
            version.1,
            version.2,
            management_key_retries,
            credentials.len()
        );
        for credential in &credentials {
            log!(
                2,
                "YubiHSM Auth credential {:?}: algorithm {:?}, {} retries, touch required {}, public key {}",
                credential.label,
                credential.algorithm,
                credential.retries,
                credential.touch_required,
                credential.public_key.is_some()
            );
        }
        Ok(Info {
            version,
            management_key_retries,
            credentials,
        })
    }

    pub(crate) fn get_version(&self, connector: &dyn Connector) -> Result<(u8, u8, u8), Error> {
        let version = self.command(connector, INS_GET_VERSION, 0, 0, Vec::new(), false)?;
        if version.len() != 3 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok((version[0], version[1], version[2]))
    }

    pub(crate) fn list_credentials(
        &self,
        connector: &dyn Connector,
    ) -> Result<Vec<Credential>, Error> {
        let encoded = self.command(connector, INS_LIST, 0, 0, Vec::new(), false)?;
        log!(2, "YubiHSM Auth credential-list metadata: {:02x?}", encoded);
        parse_credentials(&encoded)
    }

    pub(crate) fn get_management_key_retries(
        &self,
        connector: &dyn Connector,
    ) -> Result<u8, Error> {
        let retries = self.command(
            connector,
            INS_GET_MANAGEMENT_KEY_RETRIES,
            0,
            0,
            Vec::new(),
            false,
        )?;
        if retries.len() != 1 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(retries[0])
    }

    pub(crate) fn get_public_key(
        &self,
        connector: &dyn Connector,
        label: &str,
    ) -> Result<Vec<u8>, Error> {
        let public_key = self.command(
            connector,
            INS_GET_PUBLIC_KEY,
            0,
            0,
            encode_tlv(TAG_LABEL, validate_label(label)?)?,
            false,
        )?;
        validate_public_key(&public_key)?;
        Ok(public_key)
    }

    pub(crate) fn get_challenge(
        &self,
        connector: &dyn Connector,
        label: &str,
        credential_password: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        if let Some(password) = credential_password {
            let password = padded_credential_password(password)?;
            data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_slice())?);
        }
        self.command(connector, INS_GET_CHALLENGE, 0, 0, data, true)
    }

    pub(crate) fn calculate_session_keys_symmetric(
        &self,
        connector: &dyn Connector,
        label: &str,
        context: &[u8],
        card_cryptogram: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error> {
        self.calculate_session_keys(
            connector,
            label,
            context,
            None,
            card_cryptogram,
            credential_password,
        )
    }

    pub(crate) fn calculate_session_keys_asymmetric(
        &self,
        connector: &dyn Connector,
        label: &str,
        context: &[u8],
        device_public_key: &[u8],
        receipt: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error> {
        validate_public_key(device_public_key)?;
        self.calculate_session_keys(
            connector,
            label,
            context,
            Some(device_public_key),
            receipt,
            credential_password,
        )
    }

    fn calculate_session_keys(
        &self,
        connector: &dyn Connector,
        label: &str,
        context: &[u8],
        public_key: Option<&[u8]>,
        response: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        data.extend(encode_tlv(TAG_CONTEXT, context)?);
        if let Some(public_key) = public_key {
            data.extend(encode_tlv(TAG_PUBLIC_KEY, public_key)?);
        }
        data.extend(encode_tlv(TAG_RESPONSE, response)?);
        let password = padded_credential_password(credential_password)?;
        data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_slice())?);

        let response = Zeroizing::new(self.command(connector, INS_CALCULATE, 0, 0, data, true)?);
        parse_session_keys(&response)
    }

    #[allow(dead_code)]
    pub(crate) fn put_symmetric_credential(
        &self,
        connector: &dyn Connector,
        management_key: &[u8],
        label: &str,
        keys: SymmetricCredentialKeys<'_>,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<(), Error> {
        if keys.enc.len() != 16 || keys.mac.len() != 16 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut data =
            credential_prefix(management_key, label, Algorithm::Aes128YubicoAuthentication)?;
        data.extend(encode_tlv(TAG_KEY_ENC, keys.enc)?);
        data.extend(encode_tlv(TAG_KEY_MAC, keys.mac)?);
        append_credential_policy(&mut data, credential_password, touch_required)?;
        self.command(connector, INS_PUT, 0, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn put_asymmetric_credential(
        &self,
        connector: &dyn Connector,
        management_key: &[u8],
        label: &str,
        private_key: Option<&[u8]>,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<(), Error> {
        if private_key.is_some_and(|key| key.len() != 32) {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut data =
            credential_prefix(management_key, label, Algorithm::EcP256YubicoAuthentication)?;
        data.extend(encode_tlv(
            TAG_PRIVATE_KEY,
            private_key.unwrap_or_default(),
        )?);
        append_credential_policy(&mut data, credential_password, touch_required)?;
        self.command(connector, INS_PUT, 0, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn delete_credential(
        &self,
        connector: &dyn Connector,
        management_key: &[u8],
        label: &str,
    ) -> Result<(), Error> {
        let mut data = encode_tlv(TAG_MANAGEMENT_KEY, validate_management_key(management_key)?)?;
        data.extend(encode_tlv(TAG_LABEL, validate_label(label)?)?);
        self.command(connector, INS_DELETE, 0, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn change_management_key(
        &self,
        connector: &dyn Connector,
        management_key: &[u8],
        new_management_key: &[u8],
    ) -> Result<(), Error> {
        let mut data = encode_tlv(TAG_MANAGEMENT_KEY, validate_management_key(management_key)?)?;
        data.extend(encode_tlv(
            TAG_MANAGEMENT_KEY,
            validate_management_key(new_management_key)?,
        )?);
        self.command(connector, INS_PUT_MANAGEMENT_KEY, 0, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn change_credential_password(
        &self,
        connector: &dyn Connector,
        label: &str,
        credential_password: &[u8],
        new_credential_password: &[u8],
    ) -> Result<(), Error> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        let password = padded_credential_password(credential_password)?;
        data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_slice())?);
        let new_password = padded_credential_password(new_credential_password)?;
        data.extend(encode_tlv(
            TAG_CREDENTIAL_PASSWORD,
            new_password.as_slice(),
        )?);
        self.command(connector, INS_CHANGE_CREDENTIAL_PASSWORD, 0, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn change_credential_password_admin(
        &self,
        connector: &dyn Connector,
        label: &str,
        management_key: &[u8],
        new_credential_password: &[u8],
    ) -> Result<(), Error> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        data.extend(encode_tlv(
            TAG_MANAGEMENT_KEY,
            validate_management_key(management_key)?,
        )?);
        let new_password = padded_credential_password(new_credential_password)?;
        data.extend(encode_tlv(
            TAG_CREDENTIAL_PASSWORD,
            new_password.as_slice(),
        )?);
        self.command(connector, INS_CHANGE_CREDENTIAL_PASSWORD, 1, 0, data, true)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn reset(&self, connector: &dyn Connector) -> Result<(), Error> {
        self.command(connector, INS_RESET, 0xde, 0xad, Vec::new(), false)
            .map(|_| ())
    }

    fn command(
        &self,
        connector: &dyn Connector,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
        sensitive: bool,
    ) -> Result<Vec<u8>, Error> {
        let name = hsmauth_command_name(ins);
        log!(
            2,
            "YubiHSM Auth sending {} (INS {:02x}, P1 {:02x}, P2 {:02x}, {} data bytes)",
            name,
            ins,
            p1,
            p2,
            data.len()
        );
        let mut command = CommandApdu {
            cla: 0,
            ins,
            p1,
            p2,
            data,
            le: None,
            extended: false,
        };
        let response = connector.send_short_apdu(&command);
        if sensitive {
            command.data.zeroize();
        }
        match response {
            Ok(response) => {
                log!(
                    2,
                    "YubiHSM Auth {} returned status {} with {} data bytes",
                    name,
                    hsmauth_status_diagnostic(response.status),
                    response.data.len()
                );
                require_success(response)
            }
            Err(error) => {
                log!(2, "YubiHSM Auth {} transport failed: {:?}", name, error);
                Err(error)
            }
        }
    }
}

fn hsmauth_command_name(ins: u8) -> &'static str {
    match ins {
        INS_PUT => "put credential",
        INS_DELETE => "delete credential",
        INS_CALCULATE => "calculate session keys",
        INS_GET_CHALLENGE => "get challenge",
        INS_LIST => "list credentials",
        INS_RESET => "reset",
        INS_GET_VERSION => "get version",
        INS_PUT_MANAGEMENT_KEY => "put management key",
        INS_GET_MANAGEMENT_KEY_RETRIES => "get management-key retries",
        INS_GET_PUBLIC_KEY => "get public key",
        INS_CHANGE_CREDENTIAL_PASSWORD => "change credential password",
        _ => "unknown command",
    }
}

fn require_success(response: ResponseApdu) -> Result<Vec<u8>, Error> {
    if response.status == STATUS_SUCCESS {
        return Ok(response.data);
    }
    Err(hsmauth_status_mapping(response.status).0.into())
}

fn hsmauth_status_mapping(status: u16) -> (CK_RV, &'static str) {
    match status {
        0x6100..=0x61ff => (CKR_DEVICE_ERROR as CK_RV, "CKR_DEVICE_ERROR"),
        0x6200 => (CKR_FUNCTION_REJECTED as CK_RV, "CKR_FUNCTION_REJECTED"),
        0x6285 => (CKR_DATA_INVALID as CK_RV, "CKR_DATA_INVALID"),
        0x63c0 => (CKR_PIN_LOCKED as CK_RV, "CKR_PIN_LOCKED"),
        0x63c1..=0x63cf => (CKR_PIN_INCORRECT as CK_RV, "CKR_PIN_INCORRECT"),
        0x6581 => (CKR_DEVICE_MEMORY as CK_RV, "CKR_DEVICE_MEMORY"),
        0x6700 => (CKR_DATA_LEN_RANGE as CK_RV, "CKR_DATA_LEN_RANGE"),
        0x6881 | 0x6882 | 0x6884 => (
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "CKR_FUNCTION_NOT_SUPPORTED",
        ),
        0x6883 => (CKR_FUNCTION_REJECTED as CK_RV, "CKR_FUNCTION_REJECTED"),
        0x6982 => (CKR_USER_NOT_LOGGED_IN as CK_RV, "CKR_USER_NOT_LOGGED_IN"),
        0x6983 => (CKR_PIN_LOCKED as CK_RV, "CKR_PIN_LOCKED"),
        0x6984 => (CKR_DATA_INVALID as CK_RV, "CKR_DATA_INVALID"),
        0x6985 | 0x6986 => (CKR_FUNCTION_REJECTED as CK_RV, "CKR_FUNCTION_REJECTED"),
        0x6999 => (
            CKR_TOKEN_NOT_RECOGNIZED as CK_RV,
            "CKR_TOKEN_NOT_RECOGNIZED",
        ),
        0x6a80 => (CKR_DATA_INVALID as CK_RV, "CKR_DATA_INVALID"),
        0x6a81 => (
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "CKR_FUNCTION_NOT_SUPPORTED",
        ),
        0x6a82 | 0x6a83 => (
            CKR_OBJECT_HANDLE_INVALID as CK_RV,
            "CKR_OBJECT_HANDLE_INVALID",
        ),
        0x6a84 => (CKR_DEVICE_MEMORY as CK_RV, "CKR_DEVICE_MEMORY"),
        0x6a86 => (CKR_ARGUMENTS_BAD as CK_RV, "CKR_ARGUMENTS_BAD"),
        0x6a88 => (
            CKR_OBJECT_HANDLE_INVALID as CK_RV,
            "CKR_OBJECT_HANDLE_INVALID",
        ),
        0x6b00 => (CKR_ARGUMENTS_BAD as CK_RV, "CKR_ARGUMENTS_BAD"),
        0x6c00..=0x6cff => (CKR_DATA_LEN_RANGE as CK_RV, "CKR_DATA_LEN_RANGE"),
        0x6d00 | 0x6e00 => (
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            "CKR_FUNCTION_NOT_SUPPORTED",
        ),
        0x6f00 => (CKR_FUNCTION_FAILED as CK_RV, "CKR_FUNCTION_FAILED"),
        _ => (CKR_DEVICE_ERROR as CK_RV, "CKR_DEVICE_ERROR"),
    }
}

fn hsmauth_status_description(status: u16) -> String {
    match status {
        0x6100..=0x61ff => format!(
            "{} response bytes remaining",
            match status & 0x00ff {
                0 => 256,
                count => count,
            }
        ),
        0x6200 => "warning: state unchanged".to_owned(),
        0x6285 => "no input data".to_owned(),
        0x63c0..=0x63cf => format!(
            "verification failed ({} retries remaining)",
            status & 0x000f
        ),
        0x6581 => "memory failure".to_owned(),
        0x6700 => "wrong length".to_owned(),
        0x6881 => "logical channel not supported".to_owned(),
        0x6882 => "secure messaging not supported".to_owned(),
        0x6883 => "last command expected".to_owned(),
        0x6884 => "command chaining not supported".to_owned(),
        0x6982 => "security condition not satisfied".to_owned(),
        0x6983 => "authentication method blocked".to_owned(),
        0x6984 => "data invalid".to_owned(),
        0x6985 => "conditions not satisfied".to_owned(),
        0x6986 => "command not allowed".to_owned(),
        0x6999 => "applet selection failed".to_owned(),
        0x6a80 => "incorrect parameters in command data".to_owned(),
        0x6a81 => "function not supported".to_owned(),
        0x6a82 => "file not found".to_owned(),
        0x6a83 => "record not found".to_owned(),
        0x6a84 => "not enough memory space".to_owned(),
        0x6a86 => "incorrect P1/P2 parameters".to_owned(),
        0x6a88 => "referenced data not found".to_owned(),
        0x6b00 => "wrong P1/P2 parameters".to_owned(),
        0x6c00..=0x6cff => format!(
            "wrong response length (correct length {})",
            match status & 0x00ff {
                0 => 256,
                length => length,
            }
        ),
        0x6d00 => "instruction not supported".to_owned(),
        0x6e00 => "class not supported".to_owned(),
        0x6f00 => "command aborted".to_owned(),
        _ => "unknown status".to_owned(),
    }
}

fn hsmauth_status_diagnostic(status: u16) -> String {
    if status == STATUS_SUCCESS {
        return "success (9000)".to_owned();
    }
    let (rv, rv_name) = hsmauth_status_mapping(status);
    format!(
        "{} ({status:04x}), PKCS11 {rv_name} ({rv:#x})",
        hsmauth_status_description(status)
    )
}

fn parse_credentials(encoded: &[u8]) -> Result<Vec<Credential>, Error> {
    parse_tlvs(encoded)?
        .into_iter()
        .map(|tlv| {
            if tlv.tag != TAG_LABEL_LIST || tlv.value.len() < 4 {
                return Err(CKR_DATA_INVALID.into());
            }
            let label = &tlv.value[2..tlv.value.len() - 1];
            let label = label.strip_suffix(&[0]).unwrap_or(label);
            let label = std::str::from_utf8(label).map_err(|_| CKR_DATA_INVALID)?;
            validate_label(label)?;
            Ok(Credential {
                label: label.to_owned(),
                algorithm: Algorithm::try_from(tlv.value[0])?,
                touch_required: match tlv.value[1] {
                    0 => false,
                    1 => true,
                    _ => return Err(CKR_DATA_INVALID.into()),
                },
                retries: *tlv.value.last().ok_or(CKR_DATA_INVALID)?,
                public_key: None,
            })
        })
        .collect()
}

fn parse_session_keys(encoded: &[u8]) -> Result<SessionKeys, Error> {
    if encoded.len() != SESSION_KEYS_LENGTH {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(SessionKeys {
        enc: Zeroizing::new(encoded[..16].try_into().map_err(|_| CKR_DEVICE_ERROR)?),
        mac: Zeroizing::new(encoded[16..32].try_into().map_err(|_| CKR_DEVICE_ERROR)?),
        rmac: Zeroizing::new(encoded[32..].try_into().map_err(|_| CKR_DEVICE_ERROR)?),
    })
}

fn credential_prefix(
    management_key: &[u8],
    label: &str,
    algorithm: Algorithm,
) -> Result<Vec<u8>, Error> {
    let mut data = encode_tlv(TAG_MANAGEMENT_KEY, validate_management_key(management_key)?)?;
    data.extend(encode_tlv(TAG_LABEL, validate_label(label)?)?);
    data.extend(encode_tlv(TAG_ALGORITHM, &[algorithm as u8])?);
    Ok(data)
}

fn append_credential_policy(
    data: &mut Vec<u8>,
    credential_password: &[u8],
    touch_required: bool,
) -> Result<(), Error> {
    let password = padded_credential_password(credential_password)?;
    data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_slice())?);
    data.extend(encode_tlv(TAG_TOUCH, &[u8::from(touch_required)])?);
    Ok(())
}

fn validate_management_key(key: &[u8]) -> Result<&[u8], Error> {
    if key.len() != MANAGEMENT_KEY_LENGTH {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(key)
}

fn padded_credential_password(password: &[u8]) -> Result<Zeroizing<[u8; 16]>, Error> {
    if password.len() > CREDENTIAL_PASSWORD_LENGTH {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let mut padded = Zeroizing::new([0; CREDENTIAL_PASSWORD_LENGTH]);
    padded[..password.len()].copy_from_slice(password);
    Ok(padded)
}

fn validate_label(label: &str) -> Result<&[u8], Error> {
    if !(MIN_LABEL_LENGTH..=MAX_LABEL_LENGTH).contains(&label.len())
        || label.chars().any(char::is_control)
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(label.as_bytes())
}

fn validate_public_key(public_key: &[u8]) -> Result<(), Error> {
    if public_key.len() != P256_PUBLIC_KEY_LENGTH || public_key[0] != 0x04 {
        return Err(CKR_DATA_INVALID.into());
    }
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let mut context = openssl::bn::BigNumContext::new()?;
    let point = openssl::ec::EcPoint::from_bytes(&group, public_key, &mut context)?;
    let key = openssl::ec::EcKey::from_public_key(&group, &point)?;
    key.check_key()?;
    Ok(())
}

fn encode_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(tag);
    match value.len() {
        0..=0x7f => encoded.push(value.len() as u8),
        0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<Tlv<'_>>, Error> {
    let mut tlvs = Vec::new();
    while !encoded.is_empty() {
        let tag = *encoded.first().ok_or(CKR_DATA_INVALID)?;
        encoded = &encoded[1..];
        let (length, length_length) = parse_length(encoded)?;
        encoded = &encoded[length_length..];
        let value = encoded.get(..length).ok_or(CKR_DATA_INVALID)?;
        tlvs.push(Tlv { tag, value });
        encoded = &encoded[length..];
    }
    Ok(tlvs)
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    match *encoded.first().ok_or(CKR_DATA_INVALID)? {
        length @ 0..=0x7f => Ok((length as usize, 1)),
        0x81 => {
            let length = *encoded.get(1).ok_or(CKR_DATA_INVALID)? as usize;
            if length < 0x80 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 2))
        }
        0x82 => {
            let length = encoded.get(1..3).ok_or(CKR_DATA_INVALID)?;
            let length = u16::from_be_bytes([length[0], length[1]]) as usize;
            if length <= 0xff {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 3))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApduCapabilities;
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<ResponseApdu>>,
        commands: RefCell<Vec<CommandApdu>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<ResponseApdu>) -> Self {
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
            "123"
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
            4096
        }
        fn apdu_capabilities(&self) -> ApduCapabilities {
            ApduCapabilities::EXTENDED
        }
        fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
            panic!("HSMAuth command was not forced to short APDU mode: {command:?}")
        }
        fn send_short_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
            self.commands.borrow_mut().push(command.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR.into())
        }
        fn transmit<'a>(
            &self,
            _send: &[u8],
            _receive: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            Err(CKR_DEVICE_ERROR.into())
        }
    }

    fn ok(data: Vec<u8>) -> ResponseApdu {
        ResponseApdu {
            data,
            status: STATUS_SUCCESS,
        }
    }

    fn p256_public_key() -> Vec<u8> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        key.public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut context,
            )
            .unwrap()
    }

    #[test]
    fn discovers_symmetric_and_asymmetric_credentials() {
        let symmetric = encode_tlv(
            TAG_LABEL_LIST,
            &[&[38, 1][..], &b"default"[..], &[7][..]].concat(),
        )
        .unwrap();
        let asymmetric = encode_tlv(
            TAG_LABEL_LIST,
            &[&[39, 0][..], &b"asymmetric\0"[..], &[8][..]].concat(),
        )
        .unwrap();
        let public_key = p256_public_key();
        let connector = ScriptedConnector::new(vec![
            ok(vec![5, 7, 1]),
            ok(vec![6]),
            ok([symmetric, asymmetric].concat()),
            ok(public_key.clone()),
        ]);

        let info = Client.discover(&connector).unwrap();
        assert_eq!(info.version, (5, 7, 1));
        assert_eq!(info.management_key_retries, 6);
        assert_eq!(info.credentials.len(), 2);
        assert_eq!(info.credentials[0].label, "default");
        assert!(info.credentials[0].touch_required);
        assert_eq!(info.credentials[1].public_key, Some(public_key));
        let commands = connector.commands.borrow();
        assert_eq!(
            commands
                .iter()
                .map(|command| command.ins)
                .collect::<Vec<_>>(),
            [7, 9, 5, 10]
        );
        assert_eq!(
            commands[3].data,
            encode_tlv(TAG_LABEL, b"asymmetric").unwrap()
        );
    }

    #[test]
    fn parses_yubico_documented_credential_list_response() {
        let credentials = parse_credentials(&[
            0x72, 0x07, 0x26, 0x00, b'a', b'b', b'c', 0x00, 0x04, 0x72, 0x08, 0x26, 0x01, b'w',
            b'x', b'y', b'z', 0x00, 0x00,
        ])
        .unwrap();

        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0].label, "abc");
        assert_eq!(credentials[0].retries, 4);
        assert!(!credentials[0].touch_required);
        assert_eq!(credentials[1].label, "wxyz");
        assert_eq!(credentials[1].retries, 0);
        assert!(credentials[1].touch_required);
    }

    #[test]
    fn session_key_commands_match_yubico_tlv_layout() {
        let public_key = p256_public_key();
        let connector = ScriptedConnector::new(vec![
            ok(vec![0x11; 8]),
            ok(vec![0x22; SESSION_KEYS_LENGTH]),
            ok(public_key.clone()),
            ok(vec![0x33; SESSION_KEYS_LENGTH]),
        ]);
        let challenge = Client.get_challenge(&connector, "symmetric", None).unwrap();
        assert_eq!(challenge, vec![0x11; 8]);
        let symmetric = Client
            .calculate_session_keys_symmetric(
                &connector,
                "symmetric",
                &[0x44; 16],
                &[0x55; 8],
                b"password",
            )
            .unwrap();
        assert_eq!(symmetric.enc.as_slice(), &[0x22; 16]);

        let host_public = Client
            .get_challenge(&connector, "pkcs11rs-asymmetric", Some(b"password"))
            .unwrap();
        assert_eq!(host_public, public_key);
        let asymmetric = Client
            .calculate_session_keys_asymmetric(
                &connector,
                "pkcs11rs-asymmetric",
                &[0x66; 130],
                &public_key,
                &[0x77; 16],
                b"password",
            )
            .unwrap();
        assert_eq!(asymmetric.rmac.as_slice(), &[0x33; 16]);

        let commands = connector.commands.borrow();
        assert_eq!(
            commands
                .iter()
                .map(|command| command.ins)
                .collect::<Vec<_>>(),
            [4, 3, 4, 3]
        );
        assert!(commands[1]
            .data
            .windows(2)
            .any(|value| value == [TAG_RESPONSE, 8]));
        assert!(commands[3]
            .data
            .windows(2)
            .any(|value| value == [TAG_PUBLIC_KEY, 65]));
        assert_eq!(commands[3].data.len(), 257);
        assert!(!commands[3].extended);
    }

    #[test]
    fn management_commands_match_yubico_apdu_vocabulary() {
        let connector = ScriptedConnector::new((0..7).map(|_| ok(Vec::new())).collect());
        let management_key = [0x11; 16];
        Client
            .put_symmetric_credential(
                &connector,
                &management_key,
                "symmetric",
                SymmetricCredentialKeys {
                    enc: &[0x22; 16],
                    mac: &[0x33; 16],
                },
                b"password",
                true,
            )
            .unwrap();
        Client
            .put_asymmetric_credential(
                &connector,
                &management_key,
                "asymmetric",
                None,
                b"password",
                false,
            )
            .unwrap();
        Client
            .delete_credential(&connector, &management_key, "obsolete")
            .unwrap();
        Client
            .change_management_key(&connector, &management_key, &[0x44; 16])
            .unwrap();
        Client
            .change_credential_password(&connector, "symmetric", b"password", b"new")
            .unwrap();
        Client
            .change_credential_password_admin(&connector, "symmetric", &management_key, b"new")
            .unwrap();
        Client.reset(&connector).unwrap();

        let commands = connector.commands.borrow();
        assert_eq!(
            commands
                .iter()
                .map(|command| command.ins)
                .collect::<Vec<_>>(),
            [
                INS_PUT,
                INS_PUT,
                INS_DELETE,
                INS_PUT_MANAGEMENT_KEY,
                INS_CHANGE_CREDENTIAL_PASSWORD,
                INS_CHANGE_CREDENTIAL_PASSWORD,
                INS_RESET,
            ]
        );
        assert!(commands[0]
            .data
            .windows(2)
            .any(|value| value == [TAG_ALGORITHM, 1]));
        assert!(commands[1]
            .data
            .windows(2)
            .any(|value| value == [TAG_PRIVATE_KEY, 0]));
        assert_eq!((commands[5].p1, commands[5].p2), (1, 0));
        assert_eq!((commands[6].p1, commands[6].p2), (0xde, 0xad));
    }

    #[test]
    fn rejects_malformed_credentials_and_statuses() {
        assert!(parse_credentials(&[TAG_LABEL_LIST, 2, 38, 0]).is_err());
        assert!(parse_credentials(&[TAG_LABEL_LIST, 3, 99, 0, 8]).is_err());
        assert!(parse_credentials(&[TAG_LABEL_LIST, 5, 38, 2, b'a', 0, 8]).is_err());
        assert!(parse_credentials(&[TAG_LABEL_LIST, 5, 38, 0, 0xff, 0, 8]).is_err());
        assert!(parse_credentials(&[TAG_LABEL_LIST, 6, 38, 0, b'a', 0, b'b', 8]).is_err());
        assert!(parse_tlvs(&[TAG_LABEL, 0x81, 1, b'a']).is_err());

        let connector = ScriptedConnector::new(vec![ResponseApdu {
            data: Vec::new(),
            status: 0x63c7,
        }]);
        assert!(
            matches!(Client.get_version(&connector), Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _)
        );
    }

    #[test]
    fn maps_all_yubico_status_words_to_pkcs11_errors() {
        let cases = [
            (0x6101, CKR_DEVICE_ERROR as CK_RV),
            (0x6200, CKR_FUNCTION_REJECTED as CK_RV),
            (0x6285, CKR_DATA_INVALID as CK_RV),
            (0x63c0, CKR_PIN_LOCKED as CK_RV),
            (0x63c7, CKR_PIN_INCORRECT as CK_RV),
            (0x6581, CKR_DEVICE_MEMORY as CK_RV),
            (0x6700, CKR_DATA_LEN_RANGE as CK_RV),
            (0x6881, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6882, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6883, CKR_FUNCTION_REJECTED as CK_RV),
            (0x6884, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6982, CKR_USER_NOT_LOGGED_IN as CK_RV),
            (0x6983, CKR_PIN_LOCKED as CK_RV),
            (0x6984, CKR_DATA_INVALID as CK_RV),
            (0x6985, CKR_FUNCTION_REJECTED as CK_RV),
            (0x6986, CKR_FUNCTION_REJECTED as CK_RV),
            (0x6999, CKR_TOKEN_NOT_RECOGNIZED as CK_RV),
            (0x6a80, CKR_DATA_INVALID as CK_RV),
            (0x6a81, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6a82, CKR_OBJECT_HANDLE_INVALID as CK_RV),
            (0x6a83, CKR_OBJECT_HANDLE_INVALID as CK_RV),
            (0x6a84, CKR_DEVICE_MEMORY as CK_RV),
            (0x6a86, CKR_ARGUMENTS_BAD as CK_RV),
            (0x6a88, CKR_OBJECT_HANDLE_INVALID as CK_RV),
            (0x6b00, CKR_ARGUMENTS_BAD as CK_RV),
            (0x6c20, CKR_DATA_LEN_RANGE as CK_RV),
            (0x6d00, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6e00, CKR_FUNCTION_NOT_SUPPORTED as CK_RV),
            (0x6f00, CKR_FUNCTION_FAILED as CK_RV),
            (0xffff, CKR_DEVICE_ERROR as CK_RV),
        ];

        for (status, expected) in cases {
            let error = require_success(ResponseApdu {
                data: vec![0xaa],
                status,
            })
            .unwrap_err();
            assert!(
                matches!(&error, Error::Generic(rv) if *rv == expected),
                "wrong mapping for status {status:04x}: {error:?}"
            );
        }

        assert_eq!(
            require_success(ResponseApdu {
                data: vec![0xaa],
                status: STATUS_SUCCESS,
            })
            .unwrap(),
            [0xaa]
        );
        assert_eq!(
            hsmauth_status_description(0x63c7),
            "verification failed (7 retries remaining)"
        );
        assert_eq!(
            hsmauth_status_description(0x6100),
            "256 response bytes remaining"
        );
        assert_eq!(
            hsmauth_status_description(0x6c20),
            "wrong response length (correct length 32)"
        );
        assert_eq!(hsmauth_status_description(0xffff), "unknown status");
        assert_eq!(hsmauth_status_diagnostic(STATUS_SUCCESS), "success (9000)");
        assert_eq!(
            hsmauth_status_diagnostic(0x63c7),
            "verification failed (7 retries remaining) (63c7), PKCS11 CKR_PIN_INCORRECT (0xa0)"
        );
        assert_eq!(
            hsmauth_status_diagnostic(0xffff),
            "unknown status (ffff), PKCS11 CKR_DEVICE_ERROR (0x30)"
        );
    }
}
