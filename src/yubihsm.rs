use crate::{
    error::Error, Connector, CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_ENCRYPTED_DATA_INVALID, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_REJECTED, CKR_OBJECT_HANDLE_INVALID, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG,
    CKR_SESSION_CLOSED, CKR_SESSION_COUNT,
};
use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use std::time::Duration;
use zeroize::Zeroizing;

#[allow(dead_code)]
mod commands;
pub(crate) use commands::{
    parse_object_id, parse_object_list, Command, CommandCode, ObjectInfo, ObjectParameters,
    PublicKey,
};

const COMMAND_CREATE_SESSION: u8 = CommandCode::CreateSession as u8;
const COMMAND_AUTHENTICATE_SESSION: u8 = CommandCode::AuthenticateSession as u8;
const COMMAND_SESSION_MESSAGE: u8 = CommandCode::SessionMessage as u8;
const COMMAND_ERROR: u8 = 0x7f;
const RESPONSE_BIT: u8 = 0x80;
const AES_BLOCK_SIZE: usize = 16;
const MAC_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_SALT: &[u8] = b"Yubico";
const DEFAULT_ITERATIONS: usize = 10_000;
const MODERN_MESSAGE_SIZE: usize = 3136;
const LEGACY_MESSAGE_SIZE: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceInfo {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u8,
    pub(crate) serial: u32,
    pub(crate) log_total: u8,
    pub(crate) log_used: u8,
    pub(crate) algorithms: Vec<u8>,
}

#[derive(Debug)]
struct Frame {
    command: u8,
    data: Vec<u8>,
}

impl Frame {
    fn new(command: u8, data: Vec<u8>) -> Result<Self, Error> {
        if data.len() > u16::MAX as usize {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        Ok(Self { command, data })
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(3 + self.data.len());
        encoded.push(self.command);
        encoded.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.data);
        encoded
    }

    fn parse(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() < 3 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let length = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
        if encoded.len() != 3 + length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Self::new(encoded[0], encoded[3..].to_vec())
    }

    fn require_response(self, request: u8) -> Result<Vec<u8>, Error> {
        if self.command == COMMAND_ERROR {
            return Err(map_device_error(self.data.first().copied()));
        }
        if self.command != request | RESPONSE_BIT {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(self.data)
    }
}

pub(crate) fn parse_pin(pin: &[u8]) -> Result<(u16, &[u8]), Error> {
    if !(12..=68).contains(&pin.len()) {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let id = std::str::from_utf8(&pin[..4])
        .ok()
        .and_then(|value| u16::from_str_radix(value, 16).ok())
        .ok_or(CKR_PIN_INCORRECT)?;
    Ok((id, &pin[4..]))
}

pub(crate) fn get_device_info(connector: &dyn Connector) -> Result<DeviceInfo, Error> {
    let data = send_plain(connector, &Command::get_device_info(None))?;
    if data.len() < 9 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(DeviceInfo {
        major: data[0],
        minor: data[1],
        patch: data[2],
        serial: u32::from_be_bytes(data[3..7].try_into().map_err(|_| CKR_DEVICE_ERROR)?),
        log_total: data[7],
        log_used: data[8],
        algorithms: data[9..].to_vec(),
    })
}

fn send_plain(connector: &dyn Connector, command: &Command) -> Result<Vec<u8>, Error> {
    if !command.code().is_bare() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    if 3 + command.data().len() > maximum_message_size(connector.major(), connector.minor()) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let code = command.code() as u8;
    let request = Frame::new(code, command.data().to_vec())?;
    Frame::parse(&connector.send(&request.encode(), DEFAULT_TIMEOUT)?)?.require_response(code)
}

fn send_plain_protocol(
    connector: &dyn Connector,
    command: u8,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = Frame::new(command, data.to_vec())?;
    Frame::parse(&connector.send(&request.encode(), DEFAULT_TIMEOUT)?)?.require_response(command)
}

pub(crate) struct SecureSession {
    sid: u8,
    s_enc: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    s_mac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    s_rmac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    counter: [u8; AES_BLOCK_SIZE],
    mac_chaining_value: [u8; AES_BLOCK_SIZE],
    valid: bool,
}

impl std::fmt::Debug for SecureSession {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("SecureSession")
            .field("sid", &self.sid)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SecureSession {
    pub(crate) fn authenticate(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
    ) -> Result<Self, Error> {
        let mut challenge = [0u8; CHALLENGE_LENGTH];
        rand_bytes(&mut challenge).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        Self::authenticate_with_challenge(connector, authkey_id, password, challenge)
    }

    fn authenticate_with_challenge(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        host_challenge: [u8; CHALLENGE_LENGTH],
    ) -> Result<Self, Error> {
        let mut static_keys = Zeroizing::new([0u8; AES_BLOCK_SIZE * 2]);
        openssl::pkcs5::pbkdf2_hmac(
            password,
            DEFAULT_SALT,
            DEFAULT_ITERATIONS,
            MessageDigest::sha256(),
            static_keys.as_mut(),
        )?;

        let mut create_data = Vec::with_capacity(2 + CHALLENGE_LENGTH);
        create_data.extend_from_slice(&authkey_id.to_be_bytes());
        create_data.extend_from_slice(&host_challenge);
        let response = send_plain_protocol(connector, COMMAND_CREATE_SESSION, &create_data)
            .map_err(map_authentication_error)?;
        if response.len() != 1 + CHALLENGE_LENGTH + MAC_LENGTH {
            return Err(CKR_DEVICE_ERROR.into());
        }

        let sid = response[0];
        let card_cryptogram: [u8; MAC_LENGTH] = response[1 + CHALLENGE_LENGTH..]
            .try_into()
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let mut context = [0u8; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(&host_challenge);
        context[CHALLENGE_LENGTH..].copy_from_slice(&response[1..1 + CHALLENGE_LENGTH]);

        let s_enc = Zeroizing::new(derive_key(&static_keys[..16], 0x04, &context)?);
        let s_mac = Zeroizing::new(derive_key(&static_keys[16..], 0x06, &context)?);
        let s_rmac = Zeroizing::new(derive_key(&static_keys[16..], 0x07, &context)?);
        let expected_card = derive_cryptogram(&s_mac[..], 0x00, &context)?;
        let host = derive_cryptogram(&s_mac[..], 0x01, &context)?;

        let mut session = Self {
            sid,
            s_enc,
            s_mac,
            s_rmac,
            counter: [0; AES_BLOCK_SIZE],
            mac_chaining_value: [0; AES_BLOCK_SIZE],
            valid: true,
        };
        let mut authenticate_data = Vec::with_capacity(1 + MAC_LENGTH);
        authenticate_data.push(sid);
        authenticate_data.extend_from_slice(&host);
        let response = session
            .send_authenticated(
                connector,
                COMMAND_AUTHENTICATE_SESSION,
                &authenticate_data,
                false,
            )
            .map_err(map_authentication_error)?;
        increment_counter(&mut session.counter);
        let authentication_result = response
            .require_response(COMMAND_AUTHENTICATE_SESSION)
            .and_then(|data| {
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(CKR_DEVICE_ERROR.into())
                }
            })
            .map_err(map_authentication_error);
        if let Err(error) = authentication_result {
            let _ = session.send_command(connector, &Command::close_session());
            return Err(error);
        }

        if !memcmp::eq(&expected_card, &card_cryptogram) {
            let _ = session.send_command(connector, &Command::close_session());
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        Ok(session)
    }

    pub(crate) fn send_command(
        &mut self,
        connector: &dyn Connector,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        if !self.valid {
            return Err(CKR_SESSION_CLOSED.into());
        }
        Self::validate_command(connector, command)?;
        let code = command.code() as u8;
        let data = command.data();
        let inner = Frame::new(code, data.to_vec())?.encode();
        let iv = aes_block(&self.s_enc[..], &self.counter)?;
        let ciphertext = aes_cbc(&self.s_enc[..], &iv, &pad(&inner), Mode::Encrypt)?;
        let mut outer_data = Vec::with_capacity(1 + ciphertext.len());
        outer_data.push(self.sid);
        outer_data.extend_from_slice(&ciphertext);
        self.valid = false;
        let outer =
            self.send_authenticated(connector, COMMAND_SESSION_MESSAGE, &outer_data, true)?;
        let encrypted = outer.require_response(COMMAND_SESSION_MESSAGE)?;
        if encrypted.len() < 1 + AES_BLOCK_SIZE
            || encrypted[0] != self.sid
            || !(encrypted.len() - 1).is_multiple_of(AES_BLOCK_SIZE)
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let clear = aes_cbc(&self.s_enc[..], &iv, &encrypted[1..], Mode::Decrypt)?;
        let response = Frame::parse(&unpad(clear)?)?;
        increment_counter(&mut self.counter);
        self.valid = true;
        let result = response.require_response(code);
        if command.code() == CommandCode::CloseSession && result.is_ok() {
            self.valid = false;
        }
        result
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    pub(crate) fn validate_command(
        connector: &dyn Connector,
        command: &Command,
    ) -> Result<(), Error> {
        if command.code().is_session_protocol()
            || matches!(
                command.code(),
                CommandCode::GetDeviceInfo | CommandCode::GetDevicePublicKey
            )
        {
            return Err(CKR_DATA_INVALID.into());
        }
        let maximum_message_size = maximum_message_size(connector.major(), connector.minor());
        if secure_message_length(command.data().len()) > maximum_message_size {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if command.code() == CommandCode::GetPseudoRandom {
            let requested = command
                .data()
                .try_into()
                .map(u16::from_be_bytes)
                .map_err(|_| CKR_DATA_INVALID)? as usize;
            if secure_message_length(requested) > maximum_message_size {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        }
        Ok(())
    }

    fn send_authenticated(
        &mut self,
        connector: &dyn Connector,
        command: u8,
        data: &[u8],
        require_response_mac: bool,
    ) -> Result<Frame, Error> {
        if data.len() + MAC_LENGTH > u16::MAX as usize {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut request = Vec::with_capacity(3 + data.len() + MAC_LENGTH);
        request.push(command);
        request.extend_from_slice(&((data.len() + MAC_LENGTH) as u16).to_be_bytes());
        request.extend_from_slice(data);

        let mut mac_input = Vec::with_capacity(AES_BLOCK_SIZE + request.len());
        mac_input.extend_from_slice(&self.mac_chaining_value);
        mac_input.extend_from_slice(&request);
        self.mac_chaining_value = aes_cmac(&self.s_mac[..], &mac_input)?;
        request.extend_from_slice(&self.mac_chaining_value[..MAC_LENGTH]);

        let encoded_response = connector.send(&request, DEFAULT_TIMEOUT)?;
        let response = Frame::parse(&encoded_response)?;
        if !require_response_mac && response.command == command | RESPONSE_BIT {
            return Ok(response);
        }
        if response.data.len() < MAC_LENGTH {
            if response.command == COMMAND_ERROR && response.data.len() == 1 {
                if command == COMMAND_AUTHENTICATE_SESSION && response.data == [0x04] {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                return Err(map_device_error(response.data.first().copied()));
            }
            return Err(CKR_DEVICE_ERROR.into());
        }

        let payload_length = response.data.len() - MAC_LENGTH;
        let mut authenticated_response = encoded_response[..3 + payload_length].to_vec();
        // The authenticated header carries the length including the trailing R-MAC.
        authenticated_response[1..3].copy_from_slice(&(response.data.len() as u16).to_be_bytes());
        let mut rmac_input = Vec::with_capacity(AES_BLOCK_SIZE + authenticated_response.len());
        rmac_input.extend_from_slice(&self.mac_chaining_value);
        rmac_input.extend_from_slice(&authenticated_response);
        let expected = aes_cmac(&self.s_rmac[..], &rmac_input)?;
        if !memcmp::eq(&expected[..MAC_LENGTH], &response.data[payload_length..]) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Frame::new(response.command, response.data[..payload_length].to_vec())
    }
}

fn secure_message_length(data_length: usize) -> usize {
    let inner_length = 3 + data_length;
    let encrypted_length = (inner_length + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    3 + 1 + encrypted_length + MAC_LENGTH
}

fn maximum_message_size(major: u8, minor: u8) -> usize {
    if major < 2 || (major == 2 && minor < 4) {
        LEGACY_MESSAGE_SIZE
    } else {
        MODERN_MESSAGE_SIZE
    }
}

fn derive_key(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; 16], Error> {
    let mut input = Vec::with_capacity(32);
    input.extend_from_slice(&[0; 11]);
    input.push(constant);
    input.push(0);
    input.extend_from_slice(&128u16.to_be_bytes());
    input.push(1);
    input.extend_from_slice(context);
    aes_cmac(key, &input)
}

fn derive_cryptogram(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; 8], Error> {
    let mut input = Vec::with_capacity(32);
    input.extend_from_slice(&[0; 11]);
    input.push(constant);
    input.push(0);
    input.extend_from_slice(&64u16.to_be_bytes());
    input.push(1);
    input.extend_from_slice(context);
    Ok(aes_cmac(key, &input)?[..MAC_LENGTH]
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR)?)
}

fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    let pkey = PKey::cmac(&Cipher::aes_128_cbc(), key)?;
    let mut signer = Signer::new_without_digest(&pkey)?;
    signer.update(data)?;
    signer
        .sign_to_vec()?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn aes_block(key: &[u8], block: &[u8; AES_BLOCK_SIZE]) -> Result<[u8; 16], Error> {
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
    crypter.pad(false);
    let mut output = [0u8; AES_BLOCK_SIZE * 2];
    let written = crypter.update(block, &mut output)?;
    let final_written = crypter.finalize(&mut output[written..])?;
    if written + final_written != AES_BLOCK_SIZE {
        return Err(CKR_DEVICE_ERROR.into());
    }
    output[..AES_BLOCK_SIZE]
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn aes_cbc(key: &[u8], iv: &[u8], data: &[u8], mode: Mode) -> Result<Vec<u8>, Error> {
    if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), mode, key, Some(iv))?;
    crypter.pad(false);
    let mut output = vec![0; data.len() + AES_BLOCK_SIZE];
    let written = crypter.update(data, &mut output)?;
    let final_written = crypter.finalize(&mut output[written..])?;
    output.truncate(written + final_written);
    Ok(output)
}

fn pad(data: &[u8]) -> Vec<u8> {
    let length = (data.len() + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded = Vec::with_capacity(length);
    padded.extend_from_slice(data);
    padded.push(0x80);
    padded.resize(length, 0);
    padded
}

fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let marker = data
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(CKR_ENCRYPTED_DATA_INVALID)?;
    if data[marker] != 0x80 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    data.truncate(marker);
    Ok(data)
}

fn increment_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn map_device_error(error: Option<u8>) -> Error {
    match error {
        Some(0x03) => CKR_SESSION_CLOSED.into(),
        Some(0x05) => CKR_SESSION_COUNT.into(),
        Some(0x07 | 0x0a) => CKR_DEVICE_MEMORY.into(),
        Some(0x08) => CKR_DATA_LEN_RANGE.into(),
        Some(0x09 | 0x0e | 0x10 | 0x12) => CKR_FUNCTION_REJECTED.into(),
        Some(0x0b | 0x0c) => CKR_OBJECT_HANDLE_INVALID.into(),
        Some(0x11) => CKR_ATTRIBUTE_VALUE_INVALID.into(),
        Some(0xff) => CKR_FUNCTION_FAILED.into(),
        _ => CKR_DEVICE_ERROR.into(),
    }
}

fn map_authentication_error(error: Error) -> Error {
    match error {
        Error::Generic(rv) if rv == CKR_OBJECT_HANDLE_INVALID as _ => CKR_PIN_INCORRECT.into(),
        other => other,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const PASSWORD: &[u8] = b"password";
    const HOST_CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const CARD_CHALLENGE: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    type InnerCommands = std::rc::Rc<RefCell<Vec<(u8, Vec<u8>)>>>;

    #[derive(Debug)]
    struct PeerSession {
        sid: u8,
        s_enc: [u8; 16],
        s_mac: [u8; 16],
        s_rmac: [u8; 16],
        counter: [u8; 16],
        mac_chaining_value: [u8; 16],
        expected_host_cryptogram: [u8; 8],
    }

    #[derive(Debug)]
    struct ProtocolPeer {
        session: RefCell<Option<PeerSession>>,
        commands: RefCell<Vec<Vec<u8>>>,
        inner_commands: InnerCommands,
        objects: RefCell<Vec<u16>>,
        corrupt_card_cryptogram: bool,
        corrupt_response_mac: std::rc::Rc<Cell<bool>>,
        authenticate_payload: Vec<u8>,
        closed_sessions: Cell<usize>,
    }

    impl ProtocolPeer {
        fn new() -> Self {
            Self {
                session: RefCell::new(None),
                commands: RefCell::new(Vec::new()),
                inner_commands: std::rc::Rc::new(RefCell::new(Vec::new())),
                objects: RefCell::new(vec![1]),
                corrupt_card_cryptogram: false,
                corrupt_response_mac: std::rc::Rc::new(Cell::new(false)),
                authenticate_payload: Vec::new(),
                closed_sessions: Cell::new(0),
            }
        }

        fn with_bad_card_cryptogram() -> Self {
            Self {
                corrupt_card_cryptogram: true,
                ..Self::new()
            }
        }

        fn with_authenticate_payload(payload: Vec<u8>) -> Self {
            Self {
                authenticate_payload: payload,
                ..Self::new()
            }
        }

        fn reply(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.commands.borrow_mut().push(request.to_vec());
            match request.first().copied() {
                Some(COMMAND_CREATE_SESSION) => self.create_session(request),
                Some(COMMAND_AUTHENTICATE_SESSION) => self.authenticate_session(request),
                Some(COMMAND_SESSION_MESSAGE) => self.session_message(request),
                Some(value) if value == CommandCode::GetDeviceInfo as u8 => Frame::new(
                    CommandCode::GetDeviceInfo as u8 | RESPONSE_BIT,
                    vec![2, 4, 1, 0x01, 0x02, 0x03, 0x04, 62, 3, 0x01, 0x02],
                )
                .map(|frame| frame.encode()),
                _ => Err(CKR_DEVICE_ERROR.into()),
            }
        }

        fn create_session(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            let frame = Frame::parse(request)?;
            if frame.data.len() != 10 || frame.data[..2] != 1u16.to_be_bytes() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let host_challenge: [u8; 8] = frame.data[2..].try_into().unwrap();
            let mut context = [0u8; 16];
            context[..8].copy_from_slice(&host_challenge);
            context[8..].copy_from_slice(&CARD_CHALLENGE);
            let mut static_keys = Zeroizing::new([0u8; 32]);
            openssl::pkcs5::pbkdf2_hmac(
                PASSWORD,
                DEFAULT_SALT,
                DEFAULT_ITERATIONS,
                MessageDigest::sha256(),
                static_keys.as_mut(),
            )?;
            let s_enc = derive_key(&static_keys[..16], 0x04, &context)?;
            let s_mac = derive_key(&static_keys[16..], 0x06, &context)?;
            let s_rmac = derive_key(&static_keys[16..], 0x07, &context)?;
            let expected_card_cryptogram = derive_cryptogram(&s_mac, 0x00, &context)?;
            let expected_host_cryptogram = derive_cryptogram(&s_mac, 0x01, &context)?;
            *self.session.borrow_mut() = Some(PeerSession {
                sid: 7,
                s_enc,
                s_mac,
                s_rmac,
                counter: [0; 16],
                mac_chaining_value: [0; 16],
                expected_host_cryptogram,
            });

            let mut data = vec![7];
            data.extend_from_slice(&CARD_CHALLENGE);
            let mut card = expected_card_cryptogram;
            if self.corrupt_card_cryptogram {
                card[0] ^= 0x80;
            }
            data.extend_from_slice(&card);
            Frame::new(COMMAND_CREATE_SESSION | RESPONSE_BIT, data).map(|frame| frame.encode())
        }

        fn authenticate_session(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            let frame = Frame::parse(request)?;
            let mut session = self.session.borrow_mut();
            let session = session.as_mut().ok_or(CKR_DEVICE_ERROR)?;
            if frame.data.len() != 1 + MAC_LENGTH + MAC_LENGTH || frame.data[0] != session.sid {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let payload_length = frame.data.len() - MAC_LENGTH;
            let mut mac_input = session.mac_chaining_value.to_vec();
            mac_input.extend_from_slice(&request[..3 + payload_length]);
            let command_mac = aes_cmac(&session.s_mac, &mac_input)?;
            if frame.data[1..9] != session.expected_host_cryptogram
                || !memcmp::eq(&command_mac[..MAC_LENGTH], &frame.data[payload_length..])
            {
                return Frame::new(COMMAND_ERROR, vec![0x04]).map(|frame| frame.encode());
            }
            session.mac_chaining_value = command_mac;
            increment_counter(&mut session.counter);
            Frame::new(
                COMMAND_AUTHENTICATE_SESSION | RESPONSE_BIT,
                self.authenticate_payload.clone(),
            )
            .map(|frame| frame.encode())
        }

        fn session_message(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            let frame = Frame::parse(request)?;
            let mut session_slot = self.session.borrow_mut();
            let session = session_slot.as_mut().ok_or(CKR_DEVICE_ERROR)?;
            if frame.data.len() < 1 + AES_BLOCK_SIZE + MAC_LENGTH {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let payload_length = frame.data.len() - MAC_LENGTH;
            let mut mac_input = session.mac_chaining_value.to_vec();
            mac_input.extend_from_slice(&request[..3 + payload_length]);
            let command_mac = aes_cmac(&session.s_mac, &mac_input)?;
            if !memcmp::eq(&command_mac[..MAC_LENGTH], &frame.data[payload_length..]) {
                return Err(CKR_DEVICE_ERROR.into());
            }
            session.mac_chaining_value = command_mac;
            if frame.data[0] != session.sid {
                return Err(CKR_DEVICE_ERROR.into());
            }

            let iv = aes_block(&session.s_enc, &session.counter)?;
            let clear = aes_cbc(
                &session.s_enc,
                &iv,
                &frame.data[1..payload_length],
                Mode::Decrypt,
            )?;
            let inner = Frame::parse(&unpad(clear)?)?;
            self.inner_commands
                .borrow_mut()
                .push((inner.command, inner.data.clone()));
            let closes_session = inner.command == CommandCode::CloseSession as u8;
            let (response_command, response_data) = match inner.command {
                value if value == CommandCode::GetStorageInfo as u8 => {
                    (inner.command | RESPONSE_BIT, vec![0xaa, 0xbb, 0xcc])
                }
                value if value == CommandCode::GetPseudoRandom as u8 => {
                    if inner.data.len() != 2 {
                        return Err(CKR_DEVICE_ERROR.into());
                    }
                    (
                        inner.command | RESPONSE_BIT,
                        vec![0x5a; u16::from_be_bytes(inner.data.try_into().unwrap()) as usize],
                    )
                }
                value if value == CommandCode::CloseSession as u8 => {
                    (inner.command | RESPONSE_BIT, vec![])
                }
                value if value == CommandCode::ListObjects as u8 => {
                    let mut objects = Vec::new();
                    for id in self.objects.borrow().iter() {
                        objects.extend_from_slice(&id.to_be_bytes());
                        objects.extend_from_slice(&[3, 1]);
                    }
                    (inner.command | RESPONSE_BIT, objects)
                }
                value if value == CommandCode::GetObjectInfo as u8 => {
                    if inner.data.len() != 3 || inner.data[2] != 3 {
                        return Err(CKR_DEVICE_ERROR.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let mut info = vec![0; 66];
                    for bit in [0x05usize, 0x06, 0x09, 0x0a] {
                        info[7 - bit / 8] |= 1 << (bit % 8);
                    }
                    info[8..10].copy_from_slice(&id.to_be_bytes());
                    info[10..12].copy_from_slice(&256u16.to_be_bytes());
                    info[12..14].copy_from_slice(&0xffffu16.to_be_bytes());
                    info[14..18].copy_from_slice(&[3, 9, 1, 1]);
                    info[18..26].copy_from_slice(b"test-rsa");
                    (inner.command | RESPONSE_BIT, info)
                }
                value if value == CommandCode::GetPublicKey as u8 => {
                    let mut key = vec![9, 0xc5];
                    key.resize(257, 0xa5);
                    key[256] |= 1;
                    (inner.command | RESPONSE_BIT, key)
                }
                value
                    if value == CommandCode::GenerateAsymmetricKey as u8
                        || value == CommandCode::PutAsymmetricKey as u8 =>
                {
                    let requested = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let id = if requested == 0 { 2 } else { requested };
                    if !self.objects.borrow().contains(&id) {
                        self.objects.borrow_mut().push(id);
                    }
                    (inner.command | RESPONSE_BIT, id.to_be_bytes().to_vec())
                }
                value if value == CommandCode::DeleteObject as u8 => {
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    self.objects
                        .borrow_mut()
                        .retain(|candidate| *candidate != id);
                    (inner.command | RESPONSE_BIT, vec![])
                }
                value if value == CommandCode::SignPkcs1 as u8 => {
                    (inner.command | RESPONSE_BIT, vec![0x5a; 256])
                }
                value if value == CommandCode::DecryptPkcs1 as u8 => {
                    (inner.command | RESPONSE_BIT, b"plaintext".to_vec())
                }
                value if value == CommandCode::ResetDevice as u8 && inner.data == [0xde] => {
                    (COMMAND_ERROR, vec![0x0b])
                }
                _ => (inner.command | RESPONSE_BIT, inner.data),
            };
            let clear_response = Frame::new(response_command, response_data)?.encode();
            let ciphertext = aes_cbc(&session.s_enc, &iv, &pad(&clear_response), Mode::Encrypt)?;
            let mut response_data = vec![session.sid];
            response_data.extend_from_slice(&ciphertext);

            let mut response = Vec::with_capacity(3 + response_data.len() + MAC_LENGTH);
            response.push(COMMAND_SESSION_MESSAGE | RESPONSE_BIT);
            response.extend_from_slice(&((response_data.len() + MAC_LENGTH) as u16).to_be_bytes());
            response.extend_from_slice(&response_data);
            let mut rmac_input = session.mac_chaining_value.to_vec();
            rmac_input.extend_from_slice(&response);
            let mut response_mac = aes_cmac(&session.s_rmac, &rmac_input)?;
            if self.corrupt_response_mac.replace(false) {
                response_mac[0] ^= 0x80;
            }
            response.extend_from_slice(&response_mac[..MAC_LENGTH]);
            increment_counter(&mut session.counter);
            if closes_session {
                *session_slot = None;
                self.closed_sessions.set(self.closed_sessions.get() + 1);
            }
            Ok(response)
        }
    }

    pub(crate) fn make_yubihsm_test_slot(
    ) -> (Box<dyn crate::Slot>, InnerCommands, std::rc::Rc<Cell<bool>>) {
        let peer = std::rc::Rc::new(ProtocolPeer::new());
        let commands = peer.inner_commands.clone();
        let corrupt_response_mac = peer.corrupt_response_mac.clone();
        (
            Box::new(crate::YubiHsmSlot {
                connector: peer,
                session: std::rc::Rc::new(RefCell::new(None)),
                version: (2, 4, 1),
                algorithms: vec![1, 5, 9, 12, 19, 20, 21, 22, 25, 48, 50, 51, 52, 53, 54],
            }),
            commands,
            corrupt_response_mac,
        )
    }

    impl Connector for ProtocolPeer {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiHSM"
        }
        fn serial(&self) -> &str {
            "16909060"
        }
        fn major(&self) -> u8 {
            2
        }
        fn minor(&self) -> u8 {
            4
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn transmit<'a>(
            &self,
            send_buffer: &[u8],
            receive_buffer: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            let response = self.reply(send_buffer)?;
            if response.len() > receive_buffer.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            receive_buffer[..response.len()].copy_from_slice(&response);
            Ok(&receive_buffer[..response.len()])
        }
    }

    #[test]
    fn frame_parser_requires_exact_length() {
        assert_eq!(Frame::parse(&[0x81, 0, 1, 0xaa]).unwrap().data, [0xaa]);
        assert!(Frame::parse(&[0x81, 0, 2, 0xaa]).is_err());
        assert!(Frame::parse(&[0x81, 0, 0, 0xaa]).is_err());
    }

    #[test]
    fn pin_contains_four_hex_digit_authentication_key_id() {
        let (id, password) = parse_pin(b"00fFpassword").unwrap();
        assert_eq!(id, 0xff);
        assert_eq!(password, PASSWORD);
        assert!(parse_pin(b"xyz1password").is_err());
        assert!(parse_pin(b"0001short").is_err());
    }

    #[test]
    fn password_derivation_matches_yubihsm_defaults() {
        let mut keys = [0u8; 32];
        openssl::pkcs5::pbkdf2_hmac(
            PASSWORD,
            DEFAULT_SALT,
            DEFAULT_ITERATIONS,
            MessageDigest::sha256(),
            &mut keys,
        )
        .unwrap();
        assert_eq!(
            keys,
            [
                0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
                0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                0x05, 0xd2, 0xce, 0x0a,
            ]
        );
    }

    #[test]
    fn parses_device_information() {
        let peer = ProtocolPeer::new();
        let info = get_device_info(&peer).unwrap();
        assert_eq!(info.major, 2);
        assert_eq!(info.minor, 4);
        assert_eq!(info.patch, 1);
        assert_eq!(info.serial, 0x01020304);
        assert_eq!(info.log_total, 62);
        assert_eq!(info.log_used, 3);
        assert_eq!(info.algorithms, [1, 2]);
    }

    #[test]
    fn authenticates_and_exchanges_encrypted_session_messages() {
        let peer = ProtocolPeer::new();
        let mut session =
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
        assert_eq!(
            session
                .send_command(&peer, &Command::get_storage_info())
                .unwrap(),
            [0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            session
                .send_command(&peer, &Command::get_pseudo_random(8))
                .unwrap(),
            [0x5a; 8]
        );
        session
            .send_command(&peer, &Command::close_session())
            .unwrap();
        assert_eq!(peer.commands.borrow().len(), 5);
    }

    #[test]
    fn rejects_card_cryptogram_after_cleaning_up_device_session() {
        let peer = ProtocolPeer::with_bad_card_cryptogram();
        assert!(matches!(
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE),
            Err(Error::Generic(rv)) if rv == CKR_ENCRYPTED_DATA_INVALID as _
        ));
        assert_eq!(peer.commands.borrow().len(), 3);
        assert_eq!(peer.commands.borrow()[1][0], COMMAND_AUTHENTICATE_SESSION);
        assert_eq!(peer.commands.borrow()[2][0], COMMAND_SESSION_MESSAGE);
        assert_eq!(peer.closed_sessions.get(), 1);
        assert!(peer.session.borrow().is_none());
    }

    #[test]
    fn rejects_authentication_success_responses_with_payload() {
        for payload_length in [1, MAC_LENGTH, MAC_LENGTH + 1] {
            let peer = ProtocolPeer::with_authenticate_payload(vec![0xaa; payload_length]);
            assert!(matches!(
                SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE),
                Err(Error::Generic(rv)) if rv == CKR_DEVICE_ERROR as _
            ));
            assert_eq!(peer.commands.borrow().len(), 3);
            assert_eq!(peer.closed_sessions.get(), 1);
        }
    }

    #[test]
    fn wrong_password_is_reported_as_pin_incorrect() {
        let peer = ProtocolPeer::new();
        assert!(matches!(
            SecureSession::authenticate_with_challenge(
                &peer,
                1,
                b"wrong-password",
                HOST_CHALLENGE,
            ),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
    }

    #[test]
    fn secure_message_limits_match_supported_firmware_generations() {
        assert!(secure_message_length(3_116) <= maximum_message_size(2, 4));
        assert!(secure_message_length(3_117) > maximum_message_size(2, 4));
        assert!(secure_message_length(2_028) <= maximum_message_size(2, 3));
        assert!(secure_message_length(2_029) > maximum_message_size(2, 3));
    }

    #[test]
    fn oversized_commands_do_not_mutate_session_state() {
        let peer = ProtocolPeer::new();
        let mut session =
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
        let counter = session.counter;
        let chaining_value = session.mac_chaining_value;
        let command = Command::raw(CommandCode::Echo, &[0; 3_117]).unwrap();
        assert!(matches!(
            session.send_command(&peer, &command),
            Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
        ));
        assert_eq!(session.counter, counter);
        assert_eq!(session.mac_chaining_value, chaining_value);
        assert_eq!(peer.commands.borrow().len(), 2);
        assert!(session.is_valid());

        let random = Command::get_pseudo_random(3_117);
        assert!(matches!(
            session.send_command(&peer, &random),
            Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
        ));
        assert_eq!(session.counter, counter);
        assert_eq!(session.mac_chaining_value, chaining_value);
        assert_eq!(peer.commands.borrow().len(), 2);
        assert!(session.is_valid());
    }

    #[test]
    fn rejects_invalid_response_mac() {
        let peer = ProtocolPeer::new();
        let mut session =
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
        peer.corrupt_response_mac.set(true);
        assert!(session
            .send_command(&peer, &Command::get_storage_info())
            .is_err());
        assert!(!session.is_valid());
        let command_count = peer.commands.borrow().len();
        assert!(matches!(
            session.send_command(&peer, &Command::get_storage_info()),
            Err(Error::Generic(rv)) if rv == CKR_SESSION_CLOSED as _
        ));
        assert_eq!(peer.commands.borrow().len(), command_count);
    }

    #[test]
    fn every_authenticated_command_crosses_the_secure_transport() {
        let peer = ProtocolPeer::new();
        let mut session =
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
        for code in commands::ALL_COMMAND_CODES.iter().copied().filter(|code| {
            !code.is_bare()
                && !code.is_session_protocol()
                && !matches!(
                    code,
                    CommandCode::CloseSession
                        | CommandCode::GetStorageInfo
                        | CommandCode::GetPseudoRandom
                        | CommandCode::ListObjects
                        | CommandCode::GetObjectInfo
                        | CommandCode::GetPublicKey
                        | CommandCode::GenerateAsymmetricKey
                        | CommandCode::PutAsymmetricKey
                        | CommandCode::DeleteObject
                        | CommandCode::SignPkcs1
                        | CommandCode::DecryptPkcs1
                )
        }) {
            let data = [code as u8, 0xa5];
            let command = Command::raw(code, &data).unwrap();
            assert_eq!(session.send_command(&peer, &command).unwrap(), data);
        }
    }

    #[test]
    fn device_command_errors_advance_the_session_counter() {
        let peer = ProtocolPeer::new();
        let mut session =
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
        let failing = Command::raw(CommandCode::ResetDevice, &[0xde]).unwrap();
        assert!(matches!(
            session.send_command(&peer, &failing),
            Err(Error::Generic(rv)) if rv == CKR_OBJECT_HANDLE_INVALID as _
        ));
        assert!(session.is_valid());
        let next = Command::raw(CommandCode::BlinkDevice, &[1]).unwrap();
        assert_eq!(session.send_command(&peer, &next).unwrap(), [1]);
    }
}
