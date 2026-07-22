#[cfg(test)]
use crate::secure_channel_crypto::aes_ecb;
use crate::{
    error::Error,
    secure_channel_crypto::{
        aes_cbc, aes_cmac, aes_encrypt_block as aes_block, pad_iso7816 as pad, scp03_kdf,
        unpad_iso7816 as unpad, AES_BLOCK_SIZE,
    },
    Connector, CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY, CKR_ENCRYPTED_DATA_INVALID, CKR_FUNCTION_FAILED, CKR_FUNCTION_REJECTED,
    CKR_OBJECT_HANDLE_INVALID, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT,
};
#[cfg(test)]
use openssl::pkey::Id;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcKeyRef, EcPoint, PointConversionForm},
    hash::MessageDigest,
    memcmp,
    nid::Nid,
    pkey::{PKey, Private},
    rand::rand_bytes,
    sha::sha256,
    symm::Mode,
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
const MAC_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const P256_PRIVATE_KEY_LENGTH: usize = 32;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const ASYMMETRIC_RECEIPT_LENGTH: usize = 16;
const EC_P256_ALGORITHM: u8 = 12;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_SALT: &[u8] = b"Yubico";
const DEFAULT_ITERATIONS: usize = 10_000;
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
        Frame::parse(&connector.send(&request.encode(), DEFAULT_TIMEOUT)?)?
            .require_response(command)
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

        let handshake = Self::begin_symmetric(connector, authkey_id, host_challenge)?;

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
        if expected_card.is_some_and(|expected| !memcmp::eq(&expected, &handshake.card_cryptogram))
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

    pub(crate) fn authenticate_asymmetric(
        connector: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
    ) -> Result<Self, Error> {
        let host_static_key = derive_p256_key(password)?;
        let device_static_key = device_public_key(connector)?;
        let group = p256_group()?;
        let host_ephemeral_key = EcKey::generate(&group)?;
        let host_ephemeral_public = p256_public_key(&host_ephemeral_key)?;

        let mut create_data = Vec::with_capacity(2 + P256_PUBLIC_KEY_LENGTH);
        create_data.extend_from_slice(&authkey_id.to_be_bytes());
        create_data.extend_from_slice(&host_ephemeral_public);
        let response = send_plain_protocol(connector, COMMAND_CREATE_SESSION, &create_data)
            .map_err(map_authentication_error)?;
        if response.len() != 1 + P256_PUBLIC_KEY_LENGTH + ASYMMETRIC_RECEIPT_LENGTH {
            return Err(CKR_DEVICE_ERROR.into());
        }

        let sid = response[0];
        let device_ephemeral_public: [u8; P256_PUBLIC_KEY_LENGTH] = response
            [1..1 + P256_PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let receipt: [u8; ASYMMETRIC_RECEIPT_LENGTH] = response[1 + P256_PUBLIC_KEY_LENGTH..]
            .try_into()
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let device_ephemeral_key = parse_p256_public_key(&device_ephemeral_public)?;

        let ephemeral_secret = p256_ecdh(&host_ephemeral_key, &device_ephemeral_key)?;
        let static_secret = p256_ecdh(&host_static_key, &device_static_key)?;
        let session_keys = x963_session_keys(&ephemeral_secret, &static_secret);

        let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
        receipt_input.extend_from_slice(&device_ephemeral_public);
        receipt_input.extend_from_slice(&host_ephemeral_public);
        let expected_receipt = aes_cmac(&session_keys[..16], &receipt_input)?;
        if !memcmp::eq(&expected_receipt, &receipt) {
            return Err(CKR_PIN_INCORRECT.into());
        }

        let mut counter = [0; AES_BLOCK_SIZE];
        increment_counter(&mut counter);
        Ok(Self {
            sid,
            s_enc: Zeroizing::new(
                session_keys[16..32]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            ),
            s_mac: Zeroizing::new(
                session_keys[32..48]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            ),
            s_rmac: Zeroizing::new(
                session_keys[48..64]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
            ),
            counter,
            mac_chaining_value: receipt,
            valid: true,
        })
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

fn p256_group() -> Result<EcGroup, Error> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(Error::from)
}

fn derive_p256_key(password: &[u8]) -> Result<EcKey<Private>, Error> {
    let group = p256_group()?;
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    input.extend_from_slice(password);
    input.push(0);
    for perturbation in 0..=u8::MAX {
        *input.last_mut().unwrap() = perturbation;
        let mut private = Zeroizing::new([0; P256_PRIVATE_KEY_LENGTH]);
        openssl::pkcs5::pbkdf2_hmac(
            &input,
            DEFAULT_SALT,
            DEFAULT_ITERATIONS,
            MessageDigest::sha256(),
            private.as_mut(),
        )?;
        if let Ok(key) = p256_private_key(&group, &private[..]) {
            return Ok(key);
        }
    }
    Err(CKR_FUNCTION_FAILED.into())
}

fn p256_private_key(group: &EcGroup, private: &[u8]) -> Result<EcKey<Private>, Error> {
    let private = BigNum::from_slice(private)?;
    let mut context = BigNumContext::new()?;
    let mut public = EcPoint::new(group)?;
    public.mul_generator2(group, &private, &mut context)?;
    let key = EcKey::from_private_components(group, &private, &public)?;
    key.check_key()?;
    Ok(key)
}

fn p256_public_key(key: &EcKeyRef<Private>) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], Error> {
    let group = p256_group()?;
    let mut context = BigNumContext::new()?;
    key.public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn parse_p256_public_key(encoded: &[u8]) -> Result<EcKey<openssl::pkey::Public>, Error> {
    if encoded.len() != P256_PUBLIC_KEY_LENGTH || encoded[0] != 0x04 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let group = p256_group()?;
    let mut context = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, encoded, &mut context)?;
    let key = EcKey::from_public_key(&group, &point)?;
    key.check_key()?;
    Ok(key)
}

fn device_public_key(connector: &dyn Connector) -> Result<EcKey<openssl::pkey::Public>, Error> {
    parse_p256_public_key(&device_public_key_bytes(connector)?)
}

pub(crate) fn device_public_key_bytes(
    connector: &dyn Connector,
) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], Error> {
    let mut encoded = send_plain(connector, &Command::get_device_public_key())?;
    if encoded.len() != P256_PUBLIC_KEY_LENGTH || encoded[0] != EC_P256_ALGORITHM {
        return Err(CKR_DEVICE_ERROR.into());
    }
    encoded[0] = 0x04;
    encoded.try_into().map_err(|_| CKR_DEVICE_ERROR.into())
}

fn p256_ecdh(
    private: &EcKeyRef<Private>,
    public: &EcKeyRef<openssl::pkey::Public>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let private = PKey::from_ec_key(private.to_owned())?;
    let public = PKey::from_ec_key(public.to_owned())?;
    let mut deriver = Deriver::new(&private)?;
    deriver.set_peer(&public)?;
    let secret = Zeroizing::new(deriver.derive_to_vec()?);
    if secret.len() != P256_PRIVATE_KEY_LENGTH {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(secret)
}

fn x963_session_keys(ephemeral: &[u8], static_secret: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut output = Zeroizing::new([0; 64]);
    for (index, chunk) in output.chunks_mut(32).enumerate() {
        let mut input = Zeroizing::new(Vec::with_capacity(
            ephemeral.len() + static_secret.len() + 4 + SCP11_SHARED_INFO.len(),
        ));
        input.extend_from_slice(ephemeral);
        input.extend_from_slice(static_secret);
        input.extend_from_slice(&((index + 1) as u32).to_be_bytes());
        input.extend_from_slice(&SCP11_SHARED_INFO);
        chunk.copy_from_slice(&sha256(&input));
    }
    output
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
pub(crate) mod tests;
