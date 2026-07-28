use crate::ctap::AUTHENTICATOR_GET_INFO;
use crate::{
    ApduCapabilities, CommandApdu, Connector, Error, ResponseApdu, CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
};
use minicbor::Encoder;
use std::{sync::Mutex, time::Duration};

const NFCCTAP_MSG: u8 = 0x10;
const ISO7816_SELECT: u8 = 0xa4;
const ISO7816_GET_RESPONSE: u8 = 0xc0;
const ISO7816_SUCCESS: u16 = 0x9000;
const ISO7816_NOT_FOUND: u16 = 0x6a82;
const ISO7816_INSTRUCTION_NOT_SUPPORTED: u16 = 0x6d00;
const CTAP2_OK: u8 = 0;
const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;

#[derive(Debug, Default)]
struct MockYubiKeyState {
    fido_selected: bool,
    chained_command: Vec<u8>,
    pending_response: Vec<u8>,
}

/// An in-process YubiKey FIDO2 applet visible only through a pkcs11rs build
/// compiled with the `mock-yubikey` feature.
#[derive(Debug)]
pub(crate) struct MockYubiKeyConnector {
    state: Mutex<MockYubiKeyState>,
}

impl MockYubiKeyConnector {
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            state: Mutex::new(MockYubiKeyState::default()),
        })
    }

    fn exchange(&self, encoded: &[u8]) -> Result<Vec<u8>, Error> {
        let command = CommandApdu::decode(encoded)?;
        let mut state = self.state.lock().map_err(|_| CKR_DEVICE_ERROR)?;

        if command.cla == 0 && command.ins == ISO7816_GET_RESPONSE {
            return Ok(take_response(&mut state, command.le).encode());
        }

        if command.ins == ISO7816_SELECT && command.p1 == 0x04 {
            state.chained_command.clear();
            state.pending_response.clear();
            if command.data == crate::ctap::FIDO2_AID {
                state.fido_selected = true;
                return Ok(ResponseApdu {
                    data: b"U2F_V2".to_vec(),
                    status: ISO7816_SUCCESS,
                }
                .encode());
            }
            state.fido_selected = false;
            return Ok(ResponseApdu {
                data: Vec::new(),
                status: ISO7816_NOT_FOUND,
            }
            .encode());
        }

        if !state.fido_selected {
            return Ok(ResponseApdu {
                data: Vec::new(),
                status: ISO7816_INSTRUCTION_NOT_SUPPORTED,
            }
            .encode());
        }

        if command.ins != NFCCTAP_MSG || command.p2 != 0 {
            return Ok(ResponseApdu {
                data: Vec::new(),
                status: ISO7816_INSTRUCTION_NOT_SUPPORTED,
            }
            .encode());
        }

        state.chained_command.extend_from_slice(&command.data);
        if command.cla & 0x10 != 0 {
            return Ok(ResponseApdu {
                data: Vec::new(),
                status: ISO7816_SUCCESS,
            }
            .encode());
        }
        let request = std::mem::take(&mut state.chained_command);
        let response = ctap_exchange(&request)?;
        state.pending_response = response;
        Ok(take_response(&mut state, command.le).encode())
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

    fn serial(&self) -> &str {
        "MOCK0001"
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

fn take_response(state: &mut MockYubiKeyState, le: Option<u32>) -> ResponseApdu {
    let requested = le.unwrap_or(256).min(256) as usize;
    let count = requested.min(state.pending_response.len());
    let remaining = state.pending_response.split_off(count);
    let data = std::mem::replace(&mut state.pending_response, remaining);
    let status = if state.pending_response.is_empty() {
        ISO7816_SUCCESS
    } else {
        0x6100 | u16::try_from(state.pending_response.len().min(256)).unwrap_or(0)
    };
    ResponseApdu { data, status }
}

fn ctap_exchange(request: &[u8]) -> Result<Vec<u8>, Error> {
    let (&command, payload) = request.split_first().ok_or(CKR_ARGUMENTS_BAD)?;
    match command {
        AUTHENTICATOR_GET_INFO if payload.is_empty() => authenticator_get_info(),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn authenticator_get_info() -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(8)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("FIDO_2_1")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&[0x50; 16])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("rk")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("clientPin")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("pinUvAuthToken")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("credMgmt")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("perCredMgmtRO")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("plat")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u16(1200)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(9)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("usb")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(13)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{select_application, CcidCtapTransport, CtapClient};
    use std::rc::Rc;

    #[test]
    fn mock_selects_only_fido_and_answers_get_info_through_ccid() {
        let connector = Rc::new(MockYubiKeyConnector::new().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let info = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)))
            .get_info()
            .unwrap();
        assert_eq!(info.versions, ["FIDO_2_1"]);
        assert_eq!(info.extensions, ["previewSign"]);
        assert!(info.option("rk"));
        assert!(!info.option("clientPin"));
    }
}
