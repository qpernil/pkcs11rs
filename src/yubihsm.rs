#[cfg(test)]
use crate::secure_channel_crypto::aes_ecb;
use crate::{
    CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY, CKR_ENCRYPTED_DATA_INVALID, CKR_FUNCTION_FAILED, CKR_FUNCTION_REJECTED,
    CKR_OBJECT_HANDLE_INVALID, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT, Connector,
    error::Error,
    secure_channel_crypto::{
        AES_BLOCK_SIZE, Direction, aes_cbc, aes_cmac, aes_encrypt_block as aes_block,
        pad_iso7816 as pad, scp03_kdf, unpad_iso7816 as unpad,
    },
};
use software_key_core::{
    secure_channel::x963_kdf_sha256,
    software_key_agreement::derive_with_signing_key,
    software_signing::{EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[allow(dead_code)]
mod commands;
pub(crate) mod trust;
#[cfg(all(test, not(feature = "abi-tests")))]
pub(crate) use commands::ObjectFilter;
pub(crate) use commands::{
    Command, CommandCode, DelegatedObjectParameters, ObjectInfo, ObjectParameters, PublicKey,
    RsaWrapParameters, parse_object_id, parse_object_list,
};

const COMMAND_CREATE_SESSION: u8 = CommandCode::CreateSession as u8;
const COMMAND_AUTHENTICATE_SESSION: u8 = CommandCode::AuthenticateSession as u8;
const COMMAND_SESSION_MESSAGE: u8 = CommandCode::SessionMessage as u8;
const COMMAND_ERROR: u8 = 0x7f;
const RESPONSE_BIT: u8 = 0x80;
const MAC_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const P256_PRIVATE_KEY_LENGTH: usize = 32;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const ASYMMETRIC_RECEIPT_LENGTH: usize = 16;
const EC_P256_AUTHENTICATION_ALGORITHM: u8 = 49;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];
const MODERN_MESSAGE_SIZE: usize = 3136;
const PRE_2_4_MESSAGE_SIZE: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceInfo {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u8,
    pub(crate) serial: u32,
    pub(crate) log_total: u8,
    pub(crate) log_used: u8,
    pub(crate) algorithms: Vec<u8>,
    pub(crate) part_number: Option<String>,
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
            let error = self.data.first().copied();
            log!(
                2,
                "YubiHSM command {:02x} returned device error {}",
                request,
                format_device_error(error)
            );
            return Err(map_device_error(error));
        }
        if self.command != request | RESPONSE_BIT {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(self.data)
    }
}

pub(crate) fn get_device_info(connector: &dyn Connector) -> Result<DeviceInfo, Error> {
    let data = send_plain(connector, &Command::get_device_info(None))?;
    if data.len() < 9 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let major = data[0];
    let minor = data[1];
    let part_number = if major > 2 || (major == 2 && minor >= 4) {
        match get_device_part_number(connector) {
            Ok(part_number) => Some(part_number),
            Err(error) => {
                log!(
                    2,
                    "YubiHSM extended device information unavailable: {:?}",
                    error
                );
                None
            }
        }
    } else {
        None
    };
    Ok(DeviceInfo {
        major,
        minor,
        patch: data[2],
        serial: u32::from_be_bytes(data[3..7].try_into().map_err(|_| CKR_DEVICE_ERROR)?),
        log_total: data[7],
        log_used: data[8],
        algorithms: data[9..].to_vec(),
        part_number,
    })
}

fn get_device_part_number(connector: &dyn Connector) -> Result<String, Error> {
    let data = send_plain(connector, &Command::get_device_info(Some(1)))?;
    let part_number = std::str::from_utf8(&data)
        .map_err(|_| Error::from(CKR_DATA_INVALID))?
        .trim_end_matches(['\0', ' ']);
    if part_number.is_empty() || part_number.chars().any(char::is_control) {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(part_number.to_owned())
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
    Frame::parse(&connector.send(&request.encode(), Duration::ZERO)?)?.require_response(code)
}

fn send_plain_protocol(
    connector: &dyn Connector,
    command: u8,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let name = yubihsm_protocol_command_name(command);
    log!(
        2,
        "YubiHSM sending {} to {} (command {:02x}, {} data bytes)",
        name,
        connector.name(),
        command,
        data.len()
    );
    let result = (|| {
        let request = Frame::new(command, data.to_vec())?;
        Frame::parse(&connector.send(&request.encode(), Duration::ZERO)?)?.require_response(command)
    })();
    match result {
        Ok(response) => {
            log!(2, "YubiHSM {} returned {} data bytes", name, response.len());
            Ok(response)
        }
        Err(error) => {
            log!(2, "YubiHSM {} failed: {:?}", name, error);
            Err(error)
        }
    }
}

fn yubihsm_protocol_command_name(command: u8) -> &'static str {
    match command {
        COMMAND_CREATE_SESSION => "Create Session",
        COMMAND_AUTHENTICATE_SESSION => "Authenticate Session",
        COMMAND_SESSION_MESSAGE => "Session Message",
        _ => "protocol command",
    }
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

pub(crate) struct SymmetricHandshake {
    pub(crate) sid: u8,
    pub(crate) context: [u8; CHALLENGE_LENGTH * 2],
    pub(crate) card_cryptogram: [u8; MAC_LENGTH],
}

pub(crate) struct AsymmetricHandshake {
    pub(crate) sid: u8,
    pub(crate) context: [u8; P256_PUBLIC_KEY_LENGTH * 2],
    pub(crate) receipt: [u8; ASYMMETRIC_RECEIPT_LENGTH],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectAuthenticationAlgorithm {
    Symmetric,
    Asymmetric,
}

pub(crate) enum DirectAuthenticationMaterial {
    Symmetric(Zeroizing<[u8; 32]>),
    Asymmetric(Zeroizing<[u8; P256_PRIVATE_KEY_LENGTH]>),
}

impl std::fmt::Debug for DirectAuthenticationMaterial {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symmetric(_) => fmt.write_str("Symmetric([REDACTED])"),
            Self::Asymmetric(_) => fmt.write_str("Asymmetric([REDACTED])"),
        }
    }
}

impl DirectAuthenticationMaterial {
    pub(crate) fn authenticate(
        &self,
        connector: &dyn Connector,
        authkey_id: u16,
    ) -> Result<SecureSession, Error> {
        match self {
            Self::Symmetric(static_keys) => SecureSession::authenticate_symmetric_with_static_keys(
                connector,
                authkey_id,
                static_keys,
            ),
            Self::Asymmetric(static_secret) => {
                SecureSession::authenticate_asymmetric_with_static_secret(
                    connector,
                    authkey_id,
                    static_secret,
                )
            }
        }
    }
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
    #[cfg(test)]
    pub(crate) fn peer_begin_symmetric(
        encoded: &[u8],
        password: &[u8],
        sid: u8,
        card_challenge: [u8; CHALLENGE_LENGTH],
    ) -> Result<(Self, [u8; MAC_LENGTH], Vec<u8>), Error> {
        let frame = Frame::parse(encoded)?;
        if frame.command != COMMAND_CREATE_SESSION || frame.data.len() != 2 + CHALLENGE_LENGTH {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut context = [0; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(&frame.data[2..]);
        context[CHALLENGE_LENGTH..].copy_from_slice(&card_challenge);
        let static_keys = crate::yubico_password_kdf(password)?;
        let s_enc = derive_key(&static_keys[..16], 0x04, &context)?;
        let s_mac = derive_key(&static_keys[16..], 0x06, &context)?;
        let s_rmac = derive_key(&static_keys[16..], 0x07, &context)?;
        let card_cryptogram = derive_cryptogram(&s_mac, 0x00, &context)?;
        let host_cryptogram = derive_cryptogram(&s_mac, 0x01, &context)?;
        let session = Self::new_peer(
            sid,
            s_enc,
            s_mac,
            s_rmac,
            [0; AES_BLOCK_SIZE],
            [0; AES_BLOCK_SIZE],
        );
        let mut response = Vec::with_capacity(1 + CHALLENGE_LENGTH + MAC_LENGTH);
        response.push(sid);
        response.extend_from_slice(&card_challenge);
        response.extend_from_slice(&card_cryptogram);
        Ok((
            session,
            host_cryptogram,
            Frame::new(COMMAND_CREATE_SESSION | RESPONSE_BIT, response)?.encode(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn new_peer(
        sid: u8,
        s_enc: [u8; AES_BLOCK_SIZE],
        s_mac: [u8; AES_BLOCK_SIZE],
        s_rmac: [u8; AES_BLOCK_SIZE],
        counter: [u8; AES_BLOCK_SIZE],
        mac_chaining_value: [u8; AES_BLOCK_SIZE],
    ) -> Self {
        Self {
            sid,
            s_enc: Zeroizing::new(s_enc),
            s_mac: Zeroizing::new(s_mac),
            s_rmac: Zeroizing::new(s_rmac),
            counter,
            mac_chaining_value,
            valid: true,
        }
    }

    #[cfg(test)]
    fn peer_request(&mut self, encoded: &[u8], command: u8) -> Result<Vec<u8>, Error> {
        if !self.valid {
            return Err(CKR_SESSION_CLOSED.into());
        }
        let frame = Frame::parse(encoded)?;
        if frame.command != command || frame.data.len() < MAC_LENGTH {
            self.valid = false;
            return Err(CKR_DEVICE_ERROR.into());
        }
        let payload_length = frame.data.len() - MAC_LENGTH;
        let mut mac_input = Vec::with_capacity(AES_BLOCK_SIZE + 3 + payload_length);
        mac_input.extend_from_slice(&self.mac_chaining_value);
        mac_input.extend_from_slice(&encoded[..3 + payload_length]);
        let command_mac = aes_cmac(&self.s_mac[..], &mac_input)?;
        if !bool::from(command_mac[..MAC_LENGTH].ct_eq(&frame.data[payload_length..])) {
            self.valid = false;
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        self.mac_chaining_value = command_mac;
        Ok(frame.data[..payload_length].to_vec())
    }

    #[cfg(test)]
    pub(crate) fn peer_authenticate_symmetric(
        &mut self,
        encoded: &[u8],
        expected_host_cryptogram: &[u8; MAC_LENGTH],
        response_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let payload = match self.peer_request(encoded, COMMAND_AUTHENTICATE_SESSION) {
            Ok(payload) => payload,
            Err(_) => {
                self.valid = false;
                return Ok(Frame::new(COMMAND_ERROR, vec![0x04])?.encode());
            }
        };
        let valid = payload.len() == 1 + MAC_LENGTH
            && payload[0] == self.sid
            && bool::from(payload[1..].ct_eq(expected_host_cryptogram));
        if !valid {
            self.valid = false;
            return Ok(Frame::new(COMMAND_ERROR, vec![0x04])?.encode());
        }
        increment_counter(&mut self.counter);
        Frame::new(
            COMMAND_AUTHENTICATE_SESSION | RESPONSE_BIT,
            response_data.to_vec(),
        )
        .map(|frame| frame.encode())
    }

    #[cfg(test)]
    pub(crate) fn peer_exchange(
        &mut self,
        encoded: &[u8],
        handler: impl FnOnce(u8, &[u8]) -> Result<(u8, Vec<u8>), Error>,
    ) -> Result<Vec<u8>, Error> {
        let payload = self.peer_request(encoded, COMMAND_SESSION_MESSAGE)?;
        if payload.len() < 1 + AES_BLOCK_SIZE
            || payload[0] != self.sid
            || !crate::is_multiple_of(payload.len() - 1, AES_BLOCK_SIZE)
        {
            self.valid = false;
            return Err(CKR_DEVICE_ERROR.into());
        }

        let iv = aes_block(&self.s_enc[..], &self.counter)?;
        let clear = aes_cbc(&self.s_enc[..], &iv, &payload[1..], Direction::Decrypt)?;
        let request = Frame::parse(&unpad(clear)?)?;
        let closes_session = request.command == CommandCode::CloseSession as u8;
        let (response_command, response_data) = handler(request.command, &request.data)?;
        let clear_response = Frame::new(response_command, response_data)?.encode();
        let ciphertext = aes_cbc(
            &self.s_enc[..],
            &iv,
            &pad(&clear_response),
            Direction::Encrypt,
        )?;

        let mut response_data = Vec::with_capacity(1 + ciphertext.len() + MAC_LENGTH);
        response_data.push(self.sid);
        response_data.extend_from_slice(&ciphertext);
        let mut response = Vec::with_capacity(3 + response_data.len() + MAC_LENGTH);
        response.push(COMMAND_SESSION_MESSAGE | RESPONSE_BIT);
        response.extend_from_slice(&((response_data.len() + MAC_LENGTH) as u16).to_be_bytes());
        response.extend_from_slice(&response_data);
        let mut rmac_input = Vec::with_capacity(AES_BLOCK_SIZE + response.len());
        rmac_input.extend_from_slice(&self.mac_chaining_value);
        rmac_input.extend_from_slice(&response);
        let response_mac = aes_cmac(&self.s_rmac[..], &rmac_input)?;
        response.extend_from_slice(&response_mac[..MAC_LENGTH]);
        increment_counter(&mut self.counter);
        if closes_session {
            self.valid = false;
        }
        Ok(response)
    }

    pub(crate) fn authenticate_direct(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        trust_prefix: Option<&std::ffi::OsStr>,
        cached_algorithm: Option<DirectAuthenticationAlgorithm>,
    ) -> Result<
        (
            Self,
            DirectAuthenticationAlgorithm,
            DirectAuthenticationMaterial,
        ),
        Error,
    > {
        let first = cached_algorithm.unwrap_or(DirectAuthenticationAlgorithm::Symmetric);
        match first {
            DirectAuthenticationAlgorithm::Symmetric => {
                if let Some((session, material)) =
                    Self::authenticate_symmetric_detect_format(connector, authkey_id, password)?
                {
                    return Ok((session, DirectAuthenticationAlgorithm::Symmetric, material));
                }
                log!(
                    2,
                    "YubiHSM Authentication Key {:04x} rejected symmetric CREATE SESSION with wrong length; trying asymmetric authentication",
                    authkey_id
                );
                let (session, material) = Self::authenticate_asymmetric_detect_format(
                    connector,
                    authkey_id,
                    password,
                    trust_prefix,
                )?
                .ok_or_else(|| Error::from(CKR_DATA_LEN_RANGE))?;
                Ok((session, DirectAuthenticationAlgorithm::Asymmetric, material))
            }
            DirectAuthenticationAlgorithm::Asymmetric => {
                if let Some((session, material)) = Self::authenticate_asymmetric_detect_format(
                    connector,
                    authkey_id,
                    password,
                    trust_prefix,
                )? {
                    return Ok((session, DirectAuthenticationAlgorithm::Asymmetric, material));
                }
                log!(
                    2,
                    "YubiHSM Authentication Key {:04x} rejected asymmetric CREATE SESSION with wrong length; trying symmetric authentication",
                    authkey_id
                );
                let (session, material) =
                    Self::authenticate_symmetric_detect_format(connector, authkey_id, password)?
                        .ok_or_else(|| Error::from(CKR_DATA_LEN_RANGE))?;
                Ok((session, DirectAuthenticationAlgorithm::Symmetric, material))
            }
        }
    }

    #[cfg(test)]
    fn authenticate_with_challenge(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        host_challenge: [u8; CHALLENGE_LENGTH],
    ) -> Result<Self, Error> {
        let handshake = Self::begin_symmetric(connector, authkey_id, host_challenge)?;
        Self::complete_symmetric_with_password(connector, handshake, password)
            .map(|(session, _)| session)
    }

    fn complete_symmetric_with_password(
        connector: &dyn Connector,
        handshake: SymmetricHandshake,
        password: &[u8],
    ) -> Result<(Self, DirectAuthenticationMaterial), Error> {
        let static_keys = crate::yubico_password_kdf(password)?;
        let session =
            Self::complete_symmetric_with_static_keys(connector, handshake, &static_keys)?;
        Ok((
            session,
            DirectAuthenticationMaterial::Symmetric(static_keys),
        ))
    }

    fn complete_symmetric_with_static_keys(
        connector: &dyn Connector,
        handshake: SymmetricHandshake,
        static_keys: &[u8; 32],
    ) -> Result<Self, Error> {
        let s_enc = derive_key(&static_keys[..16], 0x04, &handshake.context)?;
        let s_mac = derive_key(&static_keys[16..], 0x06, &handshake.context)?;
        let s_rmac = derive_key(&static_keys[16..], 0x07, &handshake.context)?;
        let expected_card = derive_cryptogram(&s_mac, 0x00, &handshake.context)?;
        Self::complete_symmetric(
            connector,
            handshake,
            Zeroizing::new(s_enc),
            Zeroizing::new(s_mac),
            Zeroizing::new(s_rmac),
            Some(expected_card),
        )
    }

    fn authenticate_symmetric_with_static_keys(
        connector: &dyn Connector,
        authkey_id: u16,
        static_keys: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut challenge = [0u8; CHALLENGE_LENGTH];
        getrandom::fill(&mut challenge).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        let handshake = Self::begin_symmetric(connector, authkey_id, challenge)?;
        Self::complete_symmetric_with_static_keys(connector, handshake, static_keys)
    }

    fn authenticate_symmetric_detect_format(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
    ) -> Result<Option<(Self, DirectAuthenticationMaterial)>, Error> {
        let mut challenge = [0u8; CHALLENGE_LENGTH];
        getrandom::fill(&mut challenge).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        let handshake = match Self::begin_symmetric(connector, authkey_id, challenge) {
            Ok(handshake) => handshake,
            Err(error) if is_wrong_length_error(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        Self::complete_symmetric_with_password(connector, handshake, password).map(Some)
    }

    pub(crate) fn begin_symmetric(
        connector: &dyn Connector,
        authkey_id: u16,
        host_challenge: [u8; CHALLENGE_LENGTH],
    ) -> Result<SymmetricHandshake, Error> {
        let mut create_data = Vec::with_capacity(2 + CHALLENGE_LENGTH);
        create_data.extend_from_slice(&authkey_id.to_be_bytes());
        create_data.extend_from_slice(&host_challenge);
        let response = send_plain_protocol(connector, COMMAND_CREATE_SESSION, &create_data)
            .map_err(map_authentication_error)?;
        if response.len() != 1 + CHALLENGE_LENGTH + MAC_LENGTH {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut context = [0u8; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(&host_challenge);
        context[CHALLENGE_LENGTH..].copy_from_slice(&response[1..1 + CHALLENGE_LENGTH]);
        Ok(SymmetricHandshake {
            sid: response[0],
            context,
            card_cryptogram: response[1 + CHALLENGE_LENGTH..]
                .try_into()
                .map_err(|_| CKR_DEVICE_ERROR)?,
        })
    }

    pub(crate) fn complete_symmetric_with_session_keys(
        connector: &dyn Connector,
        handshake: SymmetricHandshake,
        s_enc: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_mac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_rmac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    ) -> Result<Self, Error> {
        Self::complete_symmetric(connector, handshake, s_enc, s_mac, s_rmac, None)
    }

    pub(crate) fn finish_failed_symmetric_handshake(
        connector: &dyn Connector,
        handshake: SymmetricHandshake,
    ) {
        let zero_key = || Zeroizing::new([0; AES_BLOCK_SIZE]);
        if let Ok(mut session) = Self::complete_symmetric_with_session_keys(
            connector,
            handshake,
            zero_key(),
            zero_key(),
            zero_key(),
        ) {
            let _ = session.send_command(connector, &Command::close_session());
        }
    }

    fn complete_symmetric(
        connector: &dyn Connector,
        handshake: SymmetricHandshake,
        s_enc: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_mac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_rmac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        expected_card: Option<[u8; MAC_LENGTH]>,
    ) -> Result<Self, Error> {
        let host = derive_cryptogram(&s_mac[..], 0x01, &handshake.context)?;

        let mut session = Self {
            sid: handshake.sid,
            s_enc,
            s_mac,
            s_rmac,
            counter: [0; AES_BLOCK_SIZE],
            mac_chaining_value: [0; AES_BLOCK_SIZE],
            valid: true,
        };
        let mut authenticate_data = Vec::with_capacity(1 + MAC_LENGTH);
        authenticate_data.push(handshake.sid);
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
        if expected_card
            .is_some_and(|expected| !bool::from(expected.ct_eq(&handshake.card_cryptogram)))
        {
            let _ = session.send_command(connector, &Command::close_session());
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }

        Ok(session)
    }

    pub(crate) fn begin_asymmetric(
        connector: &dyn Connector,
        authkey_id: u16,
        host_ephemeral_public: &[u8],
    ) -> Result<AsymmetricHandshake, Error> {
        parse_p256_public_key(host_ephemeral_public)?;
        let mut create_data = Vec::with_capacity(2 + P256_PUBLIC_KEY_LENGTH);
        create_data.extend_from_slice(&authkey_id.to_be_bytes());
        create_data.extend_from_slice(host_ephemeral_public);
        let response = send_plain_protocol(connector, COMMAND_CREATE_SESSION, &create_data)
            .map_err(map_authentication_error)?;
        if response.len() != 1 + P256_PUBLIC_KEY_LENGTH + ASYMMETRIC_RECEIPT_LENGTH {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut context = [0; P256_PUBLIC_KEY_LENGTH * 2];
        context[..P256_PUBLIC_KEY_LENGTH].copy_from_slice(host_ephemeral_public);
        context[P256_PUBLIC_KEY_LENGTH..].copy_from_slice(&response[1..1 + P256_PUBLIC_KEY_LENGTH]);
        Ok(AsymmetricHandshake {
            sid: response[0],
            context,
            receipt: response[1 + P256_PUBLIC_KEY_LENGTH..]
                .try_into()
                .map_err(|_| CKR_DEVICE_ERROR)?,
        })
    }

    pub(crate) fn complete_asymmetric_with_session_keys(
        handshake: AsymmetricHandshake,
        s_enc: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_mac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
        s_rmac: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    ) -> Self {
        let mut counter = [0; AES_BLOCK_SIZE];
        increment_counter(&mut counter);
        Self {
            sid: handshake.sid,
            s_enc,
            s_mac,
            s_rmac,
            counter,
            mac_chaining_value: handshake.receipt,
            valid: true,
        }
    }

    pub(crate) fn close_failed_asymmetric_handshake(
        connector: &dyn Connector,
        handshake: AsymmetricHandshake,
    ) {
        let mut counter = [0; AES_BLOCK_SIZE];
        increment_counter(&mut counter);
        Self::send_invalid_close(connector, handshake.sid, counter, handshake.receipt);
    }

    fn send_invalid_close(
        connector: &dyn Connector,
        sid: u8,
        counter: [u8; AES_BLOCK_SIZE],
        mac_chaining_value: [u8; AES_BLOCK_SIZE],
    ) {
        let zero_key = || Zeroizing::new([0; AES_BLOCK_SIZE]);
        let mut session = Self {
            sid,
            s_enc: zero_key(),
            s_mac: zero_key(),
            s_rmac: zero_key(),
            counter,
            mac_chaining_value,
            valid: true,
        };
        let _ = session.send_command(connector, &Command::close_session());
    }

    fn authenticate_asymmetric_detect_format(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        trust_prefix: Option<&std::ffi::OsStr>,
    ) -> Result<Option<(Self, DirectAuthenticationMaterial)>, Error> {
        let host_ephemeral_key = p256_secret_key()?;
        let host_ephemeral_public = p256_public_key(&host_ephemeral_key)?;

        let handshake = match Self::begin_asymmetric(connector, authkey_id, &host_ephemeral_public)
        {
            Ok(handshake) => handshake,
            Err(error) if is_wrong_length_error(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let static_secret = (|| {
            let host_static_key = crate::yubico_kdf::yubico_password_p256_key(password)?;
            let device_static_key = trusted_device_public_key(connector, trust_prefix)?;
            let static_secret = p256_ecdh(&host_static_key, &device_static_key)?;
            Ok(Zeroizing::new(
                static_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            ))
        })();
        match static_secret {
            Ok(static_secret) => {
                match Self::complete_asymmetric_with_static_secret(
                    connector,
                    handshake,
                    &host_ephemeral_key,
                    &host_ephemeral_public,
                    &static_secret,
                    CKR_PIN_INCORRECT as crate::CK_RV,
                ) {
                    Ok(session) => Ok(Some((
                        session,
                        DirectAuthenticationMaterial::Asymmetric(static_secret),
                    ))),
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                Self::close_failed_asymmetric_handshake(connector, handshake);
                Err(error)
            }
        }
    }

    fn authenticate_asymmetric_with_static_secret(
        connector: &dyn Connector,
        authkey_id: u16,
        static_secret: &[u8; P256_PRIVATE_KEY_LENGTH],
    ) -> Result<Self, Error> {
        let host_ephemeral_key = p256_secret_key()?;
        let host_ephemeral_public = p256_public_key(&host_ephemeral_key)?;
        let handshake = Self::begin_asymmetric(connector, authkey_id, &host_ephemeral_public)?;
        Self::complete_asymmetric_with_static_secret(
            connector,
            handshake,
            &host_ephemeral_key,
            &host_ephemeral_public,
            static_secret,
            CKR_ENCRYPTED_DATA_INVALID as crate::CK_RV,
        )
    }

    fn complete_asymmetric_with_static_secret(
        connector: &dyn Connector,
        handshake: AsymmetricHandshake,
        host_ephemeral_key: &SoftwareSigningKey,
        host_ephemeral_public: &[u8; P256_PUBLIC_KEY_LENGTH],
        static_secret: &[u8; P256_PRIVATE_KEY_LENGTH],
        receipt_error: crate::CK_RV,
    ) -> Result<Self, Error> {
        let keys = (|| {
            let device_ephemeral_public = &handshake.context[P256_PUBLIC_KEY_LENGTH..];
            parse_p256_public_key(device_ephemeral_public)?;
            let ephemeral_secret = p256_ecdh(host_ephemeral_key, device_ephemeral_public)?;
            let session_keys = x963_session_keys(&ephemeral_secret, static_secret)?;

            let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
            receipt_input.extend_from_slice(device_ephemeral_public);
            receipt_input.extend_from_slice(host_ephemeral_public);
            let expected_receipt = aes_cmac(&session_keys[..16], &receipt_input)?;
            if !bool::from(expected_receipt.ct_eq(&handshake.receipt)) {
                return Err(Error::from(receipt_error));
            }
            let s_enc = Zeroizing::new(
                session_keys[16..32]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            );
            let s_mac = Zeroizing::new(
                session_keys[32..48]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            );
            let s_rmac = Zeroizing::new(
                session_keys[48..64]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            );
            Ok((s_enc, s_mac, s_rmac))
        })();
        match keys {
            Ok((s_enc, s_mac, s_rmac)) => Ok(Self::complete_asymmetric_with_session_keys(
                handshake, s_enc, s_mac, s_rmac,
            )),
            Err(error) => {
                Self::close_failed_asymmetric_handshake(connector, handshake);
                Err(error)
            }
        }
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
        let ciphertext = aes_cbc(&self.s_enc[..], &iv, &pad(&inner), Direction::Encrypt)?;
        let mut outer_data = Vec::with_capacity(1 + ciphertext.len());
        outer_data.push(self.sid);
        outer_data.extend_from_slice(&ciphertext);
        self.valid = false;
        let outer =
            self.send_authenticated(connector, COMMAND_SESSION_MESSAGE, &outer_data, true)?;
        let encrypted = outer.require_response(COMMAND_SESSION_MESSAGE)?;
        if encrypted.len() < 1 + AES_BLOCK_SIZE
            || encrypted[0] != self.sid
            || !crate::is_multiple_of(encrypted.len() - 1, AES_BLOCK_SIZE)
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let clear = aes_cbc(&self.s_enc[..], &iv, &encrypted[1..], Direction::Decrypt)?;
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

        let encoded_response = connector.send(&request, Duration::ZERO)?;
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
        if !bool::from(expected[..MAC_LENGTH].ct_eq(&response.data[payload_length..])) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Frame::new(response.command, response.data[..payload_length].to_vec())
    }
}

fn p256_secret_key() -> Result<SoftwareSigningKey, Error> {
    SoftwareSigningKey::generate_for_kind(KeyKind::Ec(
        software_key_core::software_signing::EcCurve::P256,
    ))
    .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn p256_public_key(key: &SoftwareSigningKey) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], Error> {
    let SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    } = key.public_key()
    else {
        return Err(CKR_DEVICE_ERROR.into());
    };
    uncompressed.try_into().map_err(|_| CKR_DEVICE_ERROR.into())
}

fn parse_p256_public_key(encoded: &[u8]) -> Result<(), Error> {
    if encoded.len() != P256_PUBLIC_KEY_LENGTH || encoded[0] != 0x04 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: encoded.to_vec(),
    }
    .validate()
    .map_err(|_| Error::from(CKR_DEVICE_ERROR))
}

fn trusted_device_public_key(
    connector: &dyn Connector,
    trust_prefix: Option<&std::ffi::OsStr>,
) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], Error> {
    let encoded = device_public_key_bytes(connector)?;
    trust::validate_device_public_key(&encoded, trust_prefix)?;
    parse_p256_public_key(&encoded)?;
    Ok(encoded)
}

pub(crate) fn validate_device_public_key_with_prefix(
    encoded: &[u8],
    trust_prefix: Option<&std::ffi::OsStr>,
) -> Result<(), Error> {
    trust::validate_device_public_key(encoded, trust_prefix)
}

pub(crate) fn device_public_key_bytes(
    connector: &dyn Connector,
) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], Error> {
    let mut encoded = send_plain(connector, &Command::get_device_public_key())?;
    if encoded.len() != P256_PUBLIC_KEY_LENGTH || encoded[0] != EC_P256_AUTHENTICATION_ALGORITHM {
        return Err(CKR_DEVICE_ERROR.into());
    }
    encoded[0] = 0x04;
    encoded.try_into().map_err(|_| CKR_DEVICE_ERROR.into())
}

fn p256_ecdh(private: &SoftwareSigningKey, public: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let secret = derive_with_signing_key(private, public).map_err(|_| CKR_DEVICE_ERROR)?;
    if secret.len() != P256_PRIVATE_KEY_LENGTH {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(secret)
}

fn x963_session_keys(ephemeral: &[u8], static_secret: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut shared_secret =
        Zeroizing::new(Vec::with_capacity(ephemeral.len() + static_secret.len()));
    shared_secret.extend_from_slice(ephemeral);
    shared_secret.extend_from_slice(static_secret);
    x963_kdf_sha256(&shared_secret, &SCP11_SHARED_INFO, 64)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn secure_message_length(data_length: usize) -> usize {
    let inner_length = 3 + data_length;
    let encrypted_length = (inner_length + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    3 + 1 + encrypted_length + MAC_LENGTH
}

fn maximum_message_size(major: u8, minor: u8) -> usize {
    if major < 2 || (major == 2 && minor < 4) {
        PRE_2_4_MESSAGE_SIZE
    } else {
        MODERN_MESSAGE_SIZE
    }
}

fn derive_key(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; 16], Error> {
    scp03_kdf(key, constant, context, 128)?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn derive_cryptogram(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; 8], Error> {
    scp03_kdf(key, constant, context, 64)?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn increment_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn is_wrong_length_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Generic(rv) if *rv == CKR_DATA_LEN_RANGE as crate::CK_RV
    )
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

fn format_device_error(error: Option<u8>) -> String {
    match error {
        Some(0x03) => "0x03 (invalid session)".to_owned(),
        Some(0x05) => "0x05 (sessions full)".to_owned(),
        Some(0x07) => "0x07 (storage full)".to_owned(),
        Some(0x08) => "0x08 (wrong length)".to_owned(),
        Some(0x09) => "0x09 (invalid permissions)".to_owned(),
        Some(0x0a) => "0x0a (log full)".to_owned(),
        Some(0x0b) => "0x0b (object not found)".to_owned(),
        Some(0x0c) => "0x0c (invalid ID)".to_owned(),
        Some(0x0e) => "0x0e (SSH CA constraint violation)".to_owned(),
        Some(0x0f) => "0x0f (invalid OTP)".to_owned(),
        Some(0x10) => "0x10 (demo mode)".to_owned(),
        Some(0x11) => "0x11 (object exists)".to_owned(),
        Some(0x12) => "0x12 (algorithm disabled)".to_owned(),
        Some(0xff) => "0xff (command unexecuted)".to_owned(),
        Some(error) => format!("0x{error:02x}"),
        None => "missing status".to_owned(),
    }
}

fn map_authentication_error(error: Error) -> Error {
    match error {
        Error::Generic(rv) if rv == CKR_OBJECT_HANDLE_INVALID as crate::CK_RV => {
            CKR_PIN_INCORRECT.into()
        }
        other => other,
    }
}

#[cfg(test)]
pub(crate) mod tests;
