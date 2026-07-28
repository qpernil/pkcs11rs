use crate::ctap::{
    AUTHENTICATOR_CLIENT_PIN, AUTHENTICATOR_CREDENTIAL_MANAGEMENT, AUTHENTICATOR_GET_ASSERTION,
    AUTHENTICATOR_GET_INFO, AUTHENTICATOR_MAKE_CREDENTIAL,
};
use crate::{
    is_multiple_of,
    secure_channel_crypto::{aes_cbc, Direction, AES_BLOCK_SIZE},
    ApduCapabilities, CommandApdu, Connector, Error, ResponseApdu, CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::Encoder;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use signature::Signer;
use std::{sync::Mutex, time::Duration};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const NFCCTAP_MSG: u8 = 0x10;
const ISO7816_SELECT: u8 = 0xa4;
const ISO7816_GET_RESPONSE: u8 = 0xc0;
const ISO7816_SUCCESS: u16 = 0x9000;
const ISO7816_NOT_FOUND: u16 = 0x6a82;
const ISO7816_INSTRUCTION_NOT_SUPPORTED: u16 = 0x6d00;
const CTAP2_OK: u8 = 0;
const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;

#[derive(Debug)]
struct MockYubiKeyState {
    fido_selected: bool,
    chained_command: Vec<u8>,
    pending_response: Vec<u8>,
    pin: Option<Zeroizing<Vec<u8>>>,
    key_agreement: Option<SecretKey>,
    pin_uv_auth_token: Zeroizing<[u8; 32]>,
    resident_credential: MockResidentCredential,
    preview_credential: Option<MockPreviewCredential>,
}

#[derive(Debug)]
struct MockResidentCredential {
    rp_id: String,
    rp_name: String,
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    credential_id: Vec<u8>,
    private_key: SecretKey,
    public_key_cose: Vec<u8>,
    counter: u32,
}

#[derive(Debug)]
struct MockPreviewCredential {
    rp_id: String,
    credential_id: Vec<u8>,
    signing_key_handle: Vec<u8>,
}

impl MockYubiKeyState {
    fn new() -> Result<Self, Error> {
        let private_key =
            SecretKey::from_slice(&[0x11; 32]).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let public_key = private_key.public_key().to_sec1_point(false);
        let resident_credential = MockResidentCredential {
            rp_id: "example.com".to_owned(),
            rp_name: "pkcs11rs mock relying party".to_owned(),
            user_id: b"pkcs11rs-mock-user".to_vec(),
            user_name: "mock-user".to_owned(),
            user_display_name: "pkcs11rs mock user".to_owned(),
            credential_id: vec![0x22; 32],
            private_key,
            public_key_cose: encode_mock_ec2(public_key.as_bytes())?,
            counter: 0,
        };
        Ok(Self {
            fido_selected: false,
            chained_command: Vec::new(),
            pending_response: Vec::new(),
            pin: Some(Zeroizing::new(b"123456".to_vec())),
            key_agreement: None,
            pin_uv_auth_token: Zeroizing::new([0x5a; 32]),
            resident_credential,
            preview_credential: None,
        })
    }
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
            state: Mutex::new(MockYubiKeyState::new()?),
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
        let response = ctap_exchange(&mut state, &request)?;
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

fn ctap_exchange(state: &mut MockYubiKeyState, request: &[u8]) -> Result<Vec<u8>, Error> {
    let (&command, payload) = request.split_first().ok_or(CKR_ARGUMENTS_BAD)?;
    match command {
        AUTHENTICATOR_GET_INFO if payload.is_empty() => authenticator_get_info(state),
        AUTHENTICATOR_CLIENT_PIN => authenticator_client_pin(state, payload),
        AUTHENTICATOR_MAKE_CREDENTIAL => authenticator_make_credential(state, payload),
        AUTHENTICATOR_GET_ASSERTION => authenticator_get_assertion(state, payload),
        AUTHENTICATOR_CREDENTIAL_MANAGEMENT => authenticator_credential_management(state, payload),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

#[derive(Default)]
struct PreviewRequest {
    rp_id: Option<String>,
    client_data_hash: Option<Vec<u8>>,
    credential_id: Option<Vec<u8>>,
    signing_key_handle: Option<Vec<u8>>,
    to_be_signed: Option<Vec<u8>>,
    additional_args: Option<Vec<u8>>,
    pin_uv_auth: Option<Vec<u8>>,
    protocol: Option<u8>,
}

fn decode_text_id_map(decoder: &mut minicbor::Decoder<'_>) -> Result<String, u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut id = None;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if id.is_none() => {
                id = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    id.ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

fn decode_allow_list(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<u8>, u8> {
    if decoder
        .array()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?
        != 1
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut id = None;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if id.is_none() => {
                id = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    id.ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

fn decode_preview_extension(
    decoder: &mut minicbor::Decoder<'_>,
    request: &mut PreviewRequest,
) -> Result<(), u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        let name = decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        if name != "previewSign" {
            decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
            continue;
        }
        let count = decoder
            .map()
            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
        for _ in 0..count {
            match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
                2 if request.signing_key_handle.is_none() => {
                    request.signing_key_handle = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                6 if request.to_be_signed.is_none() => {
                    request.to_be_signed = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                7 if request.additional_args.is_none() => {
                    request.additional_args = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
            }
        }
    }
    Ok(())
}

fn decode_preview_request(payload: &[u8], assertion: bool) -> Result<PreviewRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut request = PreviewRequest::default();
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if assertion && request.rp_id.is_none() => {
                request.rp_id = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            1 if !assertion && request.client_data_hash.is_none() => {
                request.client_data_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            2 if assertion && request.client_data_hash.is_none() => {
                request.client_data_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            2 if !assertion && request.rp_id.is_none() => {
                request.rp_id = Some(decode_text_id_map(&mut decoder)?)
            }
            3 if assertion && request.credential_id.is_none() => {
                request.credential_id = Some(decode_allow_list(&mut decoder)?)
            }
            4 if assertion => decode_preview_extension(&mut decoder, &mut request)?,
            6 if !assertion => decode_preview_extension(&mut decoder, &mut request)?,
            6 if assertion && request.pin_uv_auth.is_none() => {
                request.pin_uv_auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            7 if assertion && request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            8 if !assertion && request.pin_uv_auth.is_none() => {
                request.pin_uv_auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            9 if !assertion && request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(request)
}

struct CredentialManagementRequest {
    subcommand: u8,
    parameters: Option<Vec<u8>>,
    protocol: Option<u8>,
    auth: Option<Vec<u8>>,
}

fn decode_credential_management_request(payload: &[u8]) -> Result<CredentialManagementRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut subcommand = None;
    let mut parameters = None;
    let mut protocol = None;
    let mut auth = None;
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if subcommand.is_none() => {
                subcommand = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            2 if parameters.is_none() => {
                let start = decoder.position();
                decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
                parameters = Some(payload[start..decoder.position()].to_vec());
            }
            3 if protocol.is_none() => {
                protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            4 if auth.is_none() => {
                auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(CredentialManagementRequest {
        subcommand: subcommand.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        parameters,
        protocol,
        auth,
    })
}

fn decode_management_rp_id_hash(parameters: &[u8]) -> Result<[u8; 32], u8> {
    let mut decoder = minicbor::Decoder::new(parameters);
    if decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?
        != 1
        || decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? != 1
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let value = decoder
        .bytes()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .try_into()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
    if decoder.position() != parameters.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(value)
}

fn credential_management_rp_response(
    credential: &MockResidentCredential,
) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.rp_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("name")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.rp_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&Sha256::digest(credential.rp_id.as_bytes()))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn credential_management_credential_response(
    credential: &MockResidentCredential,
) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.user_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("name")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.user_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("displayName")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.user_display_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("type")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("public-key")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.credential_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(8)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encoder
        .writer_mut()
        .extend_from_slice(&credential.public_key_cose);
    encoder
        .u8(9)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(10)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(12)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn authenticator_credential_management(
    state: &MockYubiKeyState,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = match decode_credential_management_request(payload) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    match request.subcommand {
        2 | 4 => {
            if request.protocol != Some(2) {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            }
            let mut authenticated = vec![request.subcommand];
            if let Some(parameters) = request.parameters.as_deref() {
                authenticated.extend_from_slice(parameters);
            }
            if !authenticate(
                state.pin_uv_auth_token.as_ref(),
                &authenticated,
                request.auth.as_deref(),
            ) {
                return Ok(vec![CTAP2_ERR_PIN_INVALID]);
            }
        }
        _ => {}
    }
    match request.subcommand {
        2 => credential_management_rp_response(&state.resident_credential),
        3 | 5 => Ok(vec![CTAP2_ERR_NO_CREDENTIALS]),
        4 => {
            let Some(parameters) = request.parameters.as_deref() else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            let rp_id_hash = match decode_management_rp_id_hash(parameters) {
                Ok(value) => value,
                Err(status) => return Ok(vec![status]),
            };
            if rp_id_hash != Sha256::digest(state.resident_credential.rp_id.as_bytes()).as_slice() {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            }
            credential_management_credential_response(&state.resident_credential)
        }
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn encode_mock_ec2(public: &[u8]) -> Result<Vec<u8>, Error> {
    if public.len() != 65 || public[0] != 4 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[1..33])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[33..])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn mock_authenticator_data(
    rp_id: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
    extension_output: &[u8],
    counter: u32,
) -> Result<Vec<u8>, Error> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(0xc5);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(&[0x50; 16]);
    data.extend_from_slice(
        &u16::try_from(credential_id.len())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .to_be_bytes(),
    );
    data.extend_from_slice(credential_id);
    data.extend_from_slice(public_key_cose);
    let mut extensions = Vec::new();
    let mut encoder = Encoder::new(&mut extensions);
    encoder
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encoder.writer_mut().extend_from_slice(extension_output);
    data.extend_from_slice(&extensions);
    Ok(data)
}

fn authenticator_make_credential(
    state: &mut MockYubiKeyState,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = match decode_preview_request(payload, false) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    let client_data_hash = request
        .client_data_hash
        .as_deref()
        .ok_or(CKR_DEVICE_ERROR)?;
    if !authenticate(
        state.pin_uv_auth_token.as_ref(),
        client_data_hash,
        request.pin_uv_auth.as_deref(),
    ) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let rp_id = request.rp_id.ok_or(CKR_DEVICE_ERROR)?;
    let credential_id = vec![0xa5; 32];
    let signing_key_handle = vec![0x5a; 48];
    let parent_secret = random_secret()?;
    let parent_public = parent_secret.public_key().to_sec1_point(false);
    let parent_cose = encode_mock_ec2(parent_public.as_bytes())?;
    let mut algorithm_output = Vec::new();
    Encoder::new(&mut algorithm_output)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i64(-65_539)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let outer_auth_data =
        mock_authenticator_data(&rp_id, &credential_id, &parent_cose, &algorithm_output, 0)?;

    let seed = crate::preview_sign::mock_preview_sign_seed_cose()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut policy_output = Vec::new();
    Encoder::new(&mut policy_output)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let inner_auth_data =
        mock_authenticator_data(&rp_id, &signing_key_handle, &seed, &policy_output, 0)?;
    let mut attestation = Vec::new();
    Encoder::new(&mut attestation)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("none")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&inner_auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(0)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("none")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&outer_auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(0)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&attestation)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    state.preview_credential = Some(MockPreviewCredential {
        rp_id,
        credential_id,
        signing_key_handle,
    });
    Ok(response)
}

fn authenticator_get_assertion(
    state: &mut MockYubiKeyState,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = match decode_preview_request(payload, true) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    let client_data_hash = request
        .client_data_hash
        .as_deref()
        .ok_or(CKR_DEVICE_ERROR)?;
    if !authenticate(
        state.pin_uv_auth_token.as_ref(),
        client_data_hash,
        request.pin_uv_auth.as_deref(),
    ) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    if request.protocol != Some(2) {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    }
    if request.signing_key_handle.is_none() {
        let credential = &mut state.resident_credential;
        if request.rp_id.as_deref() != Some(credential.rp_id.as_str())
            || request.credential_id.as_deref() != Some(credential.credential_id.as_slice())
        {
            return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
        }
        credential.counter = credential.counter.saturating_add(1);
        let mut auth_data = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
        auth_data.push(0x05);
        auth_data.extend_from_slice(&credential.counter.to_be_bytes());
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(client_data_hash);
        let signing_key = SigningKey::from(credential.private_key.clone());
        let signature: DerSignature = signing_key.sign(&signed);
        let mut response = vec![CTAP2_OK];
        Encoder::new(&mut response)
            .map(3)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map(2)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("id")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(&credential.credential_id)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("type")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("public-key")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(2)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(&auth_data)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(3)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(signature.as_bytes())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        return Ok(response);
    }
    let credential = state.preview_credential.as_ref().ok_or(CKR_DEVICE_ERROR)?;
    if request.rp_id.as_deref() != Some(credential.rp_id.as_str())
        || request.credential_id.as_deref() != Some(credential.credential_id.as_slice())
        || request.signing_key_handle.as_deref() != Some(credential.signing_key_handle.as_slice())
    {
        return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
    }
    let signature = crate::preview_sign::mock_preview_sign(
        request.additional_args.as_deref().ok_or(CKR_DEVICE_ERROR)?,
        request.to_be_signed.as_deref().ok_or(CKR_DEVICE_ERROR)?,
    )
    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut extensions = Vec::new();
    Encoder::new(&mut extensions)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&signature)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut auth_data = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
    auth_data.push(0x85);
    auth_data.extend_from_slice(&1_u32.to_be_bytes());
    auth_data.extend_from_slice(&extensions);
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.credential_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("type")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("public-key")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&[0; 64])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn authenticator_get_info(state: &MockYubiKeyState) -> Result<Vec<u8>, Error> {
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
        .bool(state.pin.is_some())
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

#[derive(Default)]
struct ClientPinRequest {
    protocol: Option<u8>,
    subcommand: Option<u8>,
    peer: Option<PublicKey>,
    auth: Option<Vec<u8>>,
    new_pin: Option<Vec<u8>>,
    pin_hash: Option<Vec<u8>>,
}

fn authenticator_client_pin(
    state: &mut MockYubiKeyState,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = match decode_client_pin(payload) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    if request.protocol != Some(2) {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    }
    match request.subcommand {
        Some(2) => key_agreement_response(state),
        Some(3) => set_pin(state, request),
        Some(4) => change_pin(state, request),
        Some(9) => pin_token(state, request),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn decode_client_pin(payload: &[u8]) -> Result<ClientPinRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut request = ClientPinRequest::default();
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            2 if request.subcommand.is_none() => {
                request.subcommand = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            3 if request.peer.is_none() => request.peer = Some(decode_cose_key(&mut decoder)?),
            4 if request.auth.is_none() => {
                request.auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            5 if request.new_pin.is_none() => {
                request.new_pin = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            6 if request.pin_hash.is_none() => {
                request.pin_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(request)
}

fn decode_cose_key(decoder: &mut minicbor::Decoder<'_>) -> Result<PublicKey, u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut x = None;
    let mut y = None;
    for _ in 0..count {
        match decoder.i64().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            -2 if x.is_none() => {
                x = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            -3 if y.is_none() => {
                y = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    let (x, y) = (
        x.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        y.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
    );
    if x.len() != 32 || y.len() != 32 {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(|_| CTAP2_ERR_INVALID_CBOR)
}

fn key_agreement_response(state: &mut MockYubiKeyState) -> Result<Vec<u8>, Error> {
    let secret = random_secret()?;
    let public = secret.public_key().to_sec1_point(false);
    let public = public.as_bytes();
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encode_cose_key(&mut encoder, &public[1..33], &public[33..])?;
    state.key_agreement = Some(secret);
    Ok(response)
}

fn set_pin(state: &mut MockYubiKeyState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    if state.pin.is_some() {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    }
    let shared = match shared_secret(state, request.peer.as_ref()) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let encrypted = match request.new_pin {
        Some(value) => value,
        None => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    if !authenticate(&shared[..32], &encrypted, request.auth.as_deref()) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let plaintext = match decrypt(&shared[..], &encrypted) {
        Ok(value) => value,
        Err(status) => return Ok(vec![status]),
    };
    let Some(pin) = padded_pin(&plaintext) else {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    };
    state.pin = Some(Zeroizing::new(pin));
    state.key_agreement = None;
    Ok(vec![CTAP2_OK])
}

fn change_pin(state: &mut MockYubiKeyState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    let Some(current) = state.pin.as_ref() else {
        return Ok(vec![CTAP2_ERR_PIN_NOT_SET]);
    };
    let shared = match shared_secret(state, request.peer.as_ref()) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let (new_pin, old_hash) = match (request.new_pin, request.pin_hash) {
        (Some(new_pin), Some(old_hash)) => (new_pin, old_hash),
        _ => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    let mut authenticated = new_pin.clone();
    authenticated.extend_from_slice(&old_hash);
    if !authenticate(&shared[..32], &authenticated, request.auth.as_deref())
        || !pin_hash_matches(&shared[..], &old_hash, current)
    {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let plaintext = match decrypt(&shared[..], &new_pin) {
        Ok(value) => value,
        Err(status) => return Ok(vec![status]),
    };
    let Some(pin) = padded_pin(&plaintext) else {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    };
    state.pin = Some(Zeroizing::new(pin));
    state.key_agreement = None;
    Ok(vec![CTAP2_OK])
}

fn pin_token(state: &mut MockYubiKeyState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    let Some(pin) = state.pin.as_ref() else {
        return Ok(vec![CTAP2_ERR_PIN_NOT_SET]);
    };
    let shared = match shared_secret(state, request.peer.as_ref()) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let Some(hash) = request.pin_hash else {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    };
    if !pin_hash_matches(&shared[..], &hash, pin) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let encrypted = encrypt(&shared[..], state.pin_uv_auth_token.as_ref())?;
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&encrypted)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    state.key_agreement = None;
    Ok(response)
}

fn random_secret() -> Result<SecretKey, Error> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn shared_secret(
    state: &MockYubiKeyState,
    peer: Option<&PublicKey>,
) -> Result<Zeroizing<[u8; 64]>, u8> {
    let secret = state
        .key_agreement
        .as_ref()
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let peer = peer.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let z = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z.raw_secret_bytes().as_ref());
    let mut output = Zeroizing::new([0u8; 64]);
    hkdf.expand(b"CTAP2 HMAC key", &mut output[..32])
        .map_err(|_| CTAP2_ERR_PIN_INVALID)?;
    hkdf.expand(b"CTAP2 AES key", &mut output[32..])
        .map_err(|_| CTAP2_ERR_PIN_INVALID)?;
    Ok(output)
}

fn encode_cose_key(encoder: &mut Encoder<&mut Vec<u8>>, x: &[u8], y: &[u8]) -> Result<(), Error> {
    encoder
        .map(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-25)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(x)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(y)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(())
}

fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, u8> {
    if key.len() != 64
        || ciphertext.len() < AES_BLOCK_SIZE * 2
        || !is_multiple_of(ciphertext.len(), AES_BLOCK_SIZE)
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    aes_cbc(
        &key[32..],
        &ciphertext[..AES_BLOCK_SIZE],
        &ciphertext[AES_BLOCK_SIZE..],
        Direction::Decrypt,
    )
    .map(Zeroizing::new)
    .map_err(|_| CTAP2_ERR_PIN_INVALID)
}

fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 64 || !is_multiple_of(plaintext.len(), AES_BLOCK_SIZE) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut iv = [0u8; AES_BLOCK_SIZE];
    getrandom::fill(&mut iv).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let ciphertext = aes_cbc(&key[32..], &iv, plaintext, Direction::Encrypt)?;
    let mut output = iv.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn authenticate(key: &[u8], message: &[u8], supplied: Option<&[u8]>) -> bool {
    let Some(supplied) = supplied else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(message);
    bool::from(mac.finalize().into_bytes().as_slice().ct_eq(supplied))
}

fn padded_pin(plaintext: &[u8]) -> Option<Vec<u8>> {
    let end = plaintext
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(plaintext.len());
    let pin = plaintext.get(..end)?;
    let text = std::str::from_utf8(pin).ok()?;
    if pin.len() > 63 || !(4..=63).contains(&text.chars().count()) {
        return None;
    }
    Some(pin.to_vec())
}

fn pin_hash_matches(shared: &[u8], encrypted: &[u8], pin: &[u8]) -> bool {
    let Ok(mut supplied) = decrypt(shared, encrypted) else {
        return false;
    };
    let expected = Sha256::digest(pin);
    let matches = supplied.len() == 16 && bool::from(supplied.as_slice().ct_eq(&expected[..16]));
    supplied.zeroize();
    matches
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
        assert!(info.option("clientPin"));
    }

    #[test]
    fn mock_default_pin_can_be_verified_and_changed_through_ctap() {
        let connector = Rc::new(MockYubiKeyConnector::new().unwrap());
        select_application(connector.as_ref(), &crate::ctap::FIDO2_AID).unwrap();
        let client = CtapClient::new(Rc::new(CcidCtapTransport::new(connector)));

        let info = client.get_info().unwrap();
        assert!(info.option("clientPin"));

        let authorization = client
            .authorize_credential_enumeration(&info, b"123456")
            .unwrap();
        let credentials = client.enumerate_credentials(&info, &authorization).unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(
            credentials[0].relying_party.id.as_deref(),
            Some("example.com")
        );

        client.change_pin(&info, b"123456", b"654321").unwrap();
        assert!(client
            .authorize_credential_enumeration(&info, b"123456")
            .is_err());
        client
            .authorize_credential_enumeration(&info, b"654321")
            .unwrap();
    }
}
