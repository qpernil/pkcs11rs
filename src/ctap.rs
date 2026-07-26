use crate::{Error, CKR_DEVICE_ERROR};
use minicbor::Decoder;
use std::rc::Rc;

pub(crate) const AUTHENTICATOR_GET_INFO: u8 = 0x04;
pub(crate) const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];

#[derive(Debug)]
pub(crate) enum CtapError {
    Transport(Error),
    Status(u8),
    Malformed(&'static str),
}

impl CtapError {
    pub(crate) fn into_pkcs11(self) -> Error {
        match self {
            Self::Transport(error) => error,
            Self::Status(status) => {
                log!(1, "CTAP command failed with status {status:#04x}");
                CKR_DEVICE_ERROR.into()
            }
            Self::Malformed(reason) => {
                log!(1, "CTAP response is malformed: {reason}");
                CKR_DEVICE_ERROR.into()
            }
        }
    }
}

impl From<Error> for CtapError {
    fn from(error: Error) -> Self {
        Self::Transport(error)
    }
}

impl From<minicbor::decode::Error> for CtapError {
    fn from(_error: minicbor::decode::Error) -> Self {
        Self::Malformed("invalid CBOR")
    }
}

pub(crate) trait CtapTransport {
    /// Exchange one CTAP message, including its command/status byte.
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatorInfo {
    pub(crate) versions: Vec<String>,
    pub(crate) extensions: Vec<String>,
    pub(crate) aaguid: [u8; 16],
    pub(crate) options: Vec<(String, bool)>,
    pub(crate) max_msg_size: Option<u64>,
    pub(crate) pin_uv_auth_protocols: Vec<u64>,
    pub(crate) transports: Vec<String>,
}

pub(crate) struct Client {
    transport: Rc<dyn CtapTransport>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("CtapClient").finish_non_exhaustive()
    }
}

impl Client {
    pub(crate) fn new(transport: Rc<dyn CtapTransport>) -> Self {
        Self { transport }
    }

    pub(crate) fn get_info(&self) -> Result<AuthenticatorInfo, CtapError> {
        let response = self.transport.transact(&[AUTHENTICATOR_GET_INFO])?;
        let (&status, data) = response
            .split_first()
            .ok_or(CtapError::Malformed("missing CTAP status"))?;
        if status != 0 {
            return Err(CtapError::Status(status));
        }
        parse_authenticator_info(data)
    }
}

fn definite_map(decoder: &mut Decoder<'_>) -> Result<u64, CtapError> {
    decoder
        .map()?
        .ok_or(CtapError::Malformed("indefinite CBOR map"))
}

fn definite_array(decoder: &mut Decoder<'_>) -> Result<u64, CtapError> {
    decoder
        .array()?
        .ok_or(CtapError::Malformed("indefinite CBOR array"))
}

fn decode_string_array(decoder: &mut Decoder<'_>) -> Result<Vec<String>, CtapError> {
    let count = definite_array(decoder)?;
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= 4096)
        .ok_or(CtapError::Malformed("string array exceeds limit"))?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decoder.str()?.to_owned());
    }
    Ok(values)
}

fn parse_authenticator_info(data: &[u8]) -> Result<AuthenticatorInfo, CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut versions = None;
    let mut extensions = Vec::new();
    let mut aaguid = None;
    let mut options = Vec::new();
    let mut max_msg_size = None;
    let mut pin_uv_auth_protocols = Vec::new();
    let mut transports = Vec::new();
    let mut seen = [false; 10];

    for _ in 0..count {
        let key = decoder.u64()?;
        if key < seen.len() as u64 {
            if seen[key as usize] {
                return Err(CtapError::Malformed("duplicate authenticator info field"));
            }
            seen[key as usize] = true;
        }
        match key {
            0x01 => versions = Some(decode_string_array(&mut decoder)?),
            0x02 => extensions = decode_string_array(&mut decoder)?,
            0x03 => {
                let bytes = decoder.bytes()?;
                aaguid = Some(
                    bytes
                        .try_into()
                        .map_err(|_| CtapError::Malformed("invalid AAGUID length"))?,
                );
            }
            0x04 => {
                let option_count = definite_map(&mut decoder)?;
                for _ in 0..option_count {
                    let name = decoder.str()?.to_owned();
                    let value = decoder.bool()?;
                    if options.iter().any(|(candidate, _)| candidate == &name) {
                        return Err(CtapError::Malformed("duplicate authenticator option"));
                    }
                    options.push((name, value));
                }
            }
            0x05 => max_msg_size = Some(decoder.u64()?),
            0x06 => {
                let protocol_count = definite_array(&mut decoder)?;
                for _ in 0..protocol_count {
                    pin_uv_auth_protocols.push(decoder.u64()?);
                }
            }
            0x09 => transports = decode_string_array(&mut decoder)?,
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing authenticator info data"));
    }
    let versions = versions.ok_or(CtapError::Malformed("missing versions"))?;
    if versions.is_empty() {
        return Err(CtapError::Malformed("empty versions"));
    }
    let aaguid = aaguid.ok_or(CtapError::Malformed("missing AAGUID"))?;
    Ok(AuthenticatorInfo {
        versions,
        extensions,
        aaguid,
        options,
        max_msg_size,
        pin_uv_auth_protocols,
        transports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Debug)]
    struct MockTransport {
        responses: RefCell<VecDeque<Vec<u8>>>,
        requests: RefCell<Vec<Vec<u8>>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl CtapTransport for MockTransport {
        fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.requests.borrow_mut().push(request.to_vec());
            Ok(self.responses.borrow_mut().pop_front().unwrap())
        }
    }

    fn get_info_vector() -> Vec<u8> {
        vec![
            0xa7, 0x01, 0x82, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x66, b'U',
            b'2', b'F', b'_', b'V', b'2', 0x02, 0x81, 0x6b, b'c', b'r', b'e', b'd', b'P', b'r',
            b'o', b't', b'e', b'c', b't', 0x03, 0x50, 0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d,
            0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d, 0x04, 0xa5, 0x62, b'r', b'k',
            0xf5, 0x68, b'c', b'r', b'e', b'd', b'M', b'g', b'm', b't', 0xf5, 0x69, b'c', b'l',
            b'i', b'e', b'n', b't', b'P', b'i', b'n', 0xf5, 0x6e, b'p', b'i', b'n', b'U', b'v',
            b'A', b'u', b't', b'h', b'T', b'o', b'k', b'e', b'n', 0xf5, 0x64, b'p', b'c', b'm',
            b'r', 0xf5, 0x05, 0x19, 0x04, 0xb0, 0x06, 0x82, 0x02, 0x01, 0x09, 0x82, 0x63, b'u',
            b's', b'b', 0x63, b'n', b'f', b'c',
        ]
    }

    #[test]
    fn get_info_request_and_response_match_protocol_vector() {
        let mut response = get_info_vector();
        response.insert(0, 0);
        let transport = Rc::new(MockTransport::new(vec![response]));
        let client = Client::new(transport.clone());
        let info = client.get_info().unwrap();
        assert_eq!(
            &*transport.requests.borrow(),
            &[vec![AUTHENTICATOR_GET_INFO]]
        );
        assert_eq!(info.versions, ["FIDO_2_1", "U2F_V2"]);
        assert_eq!(
            info.aaguid,
            [
                0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e,
                0xdc, 0x7d
            ]
        );
        assert_eq!(info.pin_uv_auth_protocols, [2, 1]);
        assert_eq!(info.transports, ["usb", "nfc"]);
    }

    #[test]
    fn malformed_get_info_responses_are_rejected() {
        let mut missing_aaguid = get_info_vector();
        missing_aaguid[0] = 0xa6;
        missing_aaguid.drain(24..42);
        assert!(parse_authenticator_info(&missing_aaguid).is_err());

        let mut trailing = get_info_vector();
        trailing.push(0);
        assert!(parse_authenticator_info(&trailing).is_err());

        let indefinite = [
            0xbf, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x03, 0x50, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
        ];
        assert!(parse_authenticator_info(&indefinite).is_err());
    }

    #[test]
    fn ctap_status_and_missing_status_are_not_parsed_as_cbor() {
        let transport = Rc::new(MockTransport::new(vec![vec![0x01], Vec::new()]));
        let client = Client::new(transport);
        assert!(matches!(client.get_info(), Err(CtapError::Status(0x01))));
        assert!(matches!(
            client.get_info(),
            Err(CtapError::Malformed("missing CTAP status"))
        ));
    }
}
