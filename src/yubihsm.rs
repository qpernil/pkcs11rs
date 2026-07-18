use crate::{
    error::Error, Connector, CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_ENCRYPTED_DATA_INVALID, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_REJECTED, CKR_OBJECT_HANDLE_INVALID, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG,
    CKR_SESSION_CLOSED, CKR_SESSION_COUNT,
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
const P256_PRIVATE_KEY_LENGTH: usize = 32;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const ASYMMETRIC_RECEIPT_LENGTH: usize = 16;
const EC_P256_ALGORITHM: u8 = 12;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];
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

pub(crate) fn parse_asymmetric_pin(pin: &[u8]) -> Result<(u16, &[u8]), Error> {
    if pin.first() != Some(&b'@') {
        return Err(CKR_PIN_INCORRECT.into());
    }
    parse_pin(&pin[1..])
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
    let mut encoded = send_plain(connector, &Command::get_device_public_key())?;
    if encoded.len() != P256_PUBLIC_KEY_LENGTH || encoded[0] != EC_P256_ALGORITHM {
        return Err(CKR_DEVICE_ERROR.into());
    }
    encoded[0] = 0x04;
    parse_p256_public_key(&encoded)
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
    aes_ecb(key, block, Mode::Encrypt)?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn aes_ecb(key: &[u8], data: &[u8], mode: Mode) -> Result<Vec<u8>, Error> {
    if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), mode, key, None)?;
    crypter.pad(false);
    let mut output = vec![0; data.len() + AES_BLOCK_SIZE];
    let written = crypter.update(data, &mut output)?;
    let final_written = crypter.finalize(&mut output[written..])?;
    output.truncate(written + final_written);
    Ok(output)
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
    use std::collections::HashMap;

    const PASSWORD: &[u8] = b"password";
    const HOST_CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const CARD_CHALLENGE: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    const DEVICE_STATIC_PRIVATE_KEY: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    const DEVICE_EPHEMERAL_PRIVATE_KEY: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ];
    pub(crate) const TEST_AES_KEY: [u8; 16] = [0; 16];
    pub(crate) const NIST_AES_KEY_ID: u16 = 3;
    const NIST_AES_128_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const RFC7748_ALICE_PRIVATE_KEY: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const RFC7748_BOB_PRIVATE_KEY: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    pub(crate) const RFC7748_ALICE_PUBLIC_KEY: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    pub(crate) const RFC7748_BOB_PUBLIC_KEY: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    pub(crate) const RFC7748_SHARED_SECRET: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];
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
        x25519_private_keys: RefCell<HashMap<u16, [u8; 32]>>,
        corrupt_card_cryptogram: bool,
        corrupt_response_mac: std::rc::Rc<Cell<bool>>,
        authenticate_payload: Vec<u8>,
        closed_sessions: Cell<usize>,
    }

    impl ProtocolPeer {
        fn new() -> Self {
            let mut x25519_private_keys = HashMap::new();
            x25519_private_keys.insert(7, RFC7748_ALICE_PRIVATE_KEY);
            x25519_private_keys.insert(8, RFC7748_BOB_PRIVATE_KEY);
            Self {
                session: RefCell::new(None),
                commands: RefCell::new(Vec::new()),
                inner_commands: std::rc::Rc::new(RefCell::new(Vec::new())),
                objects: RefCell::new(vec![1]),
                x25519_private_keys: RefCell::new(x25519_private_keys),
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

        fn x25519_derive(&self, id: u16, public_key: &[u8]) -> Result<Vec<u8>, Error> {
            let private_key = self
                .x25519_private_keys
                .borrow()
                .get(&id)
                .copied()
                .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
            if public_key.len() != 32 {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            let private_key = PKey::private_key_from_raw_bytes(&private_key, Id::X25519)?;
            let public_key = PKey::public_key_from_raw_bytes(public_key, Id::X25519)?;
            let mut deriver = Deriver::new(&private_key)?;
            deriver.set_peer(&public_key)?;
            deriver.derive_to_vec().map_err(Error::from)
        }

        fn aes_key(id: u16) -> &'static [u8; 16] {
            if id == NIST_AES_KEY_ID {
                &NIST_AES_128_KEY
            } else {
                &TEST_AES_KEY
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
                Some(value) if value == CommandCode::GetDevicePublicKey as u8 => {
                    let group = p256_group()?;
                    let key = p256_private_key(&group, &DEVICE_STATIC_PRIVATE_KEY)?;
                    let mut public = p256_public_key(&key)?;
                    public[0] = EC_P256_ALGORITHM;
                    Frame::new(
                        CommandCode::GetDevicePublicKey as u8 | RESPONSE_BIT,
                        public.to_vec(),
                    )
                    .map(|frame| frame.encode())
                }
                _ => Err(CKR_DEVICE_ERROR.into()),
            }
        }

        fn create_session(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            let frame = Frame::parse(request)?;
            if frame.data.get(..2) != Some(&1u16.to_be_bytes()) {
                return Err(CKR_DEVICE_ERROR.into());
            }
            match frame.data.len() {
                10 => self.create_symmetric_session(&frame.data),
                length if length == 2 + P256_PUBLIC_KEY_LENGTH => {
                    self.create_asymmetric_session(&frame.data)
                }
                _ => Err(CKR_DEVICE_ERROR.into()),
            }
        }

        fn create_symmetric_session(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            let host_challenge: [u8; 8] = data[2..].try_into().unwrap();
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

        fn create_asymmetric_session(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            let host_ephemeral_public = parse_p256_public_key(&data[2..])?;
            let host_static_key = derive_p256_key(PASSWORD)?;
            let host_static_public = parse_p256_public_key(&p256_public_key(&host_static_key)?)?;
            let group = p256_group()?;
            let device_static_key = p256_private_key(&group, &DEVICE_STATIC_PRIVATE_KEY)?;
            let device_ephemeral_key = p256_private_key(&group, &DEVICE_EPHEMERAL_PRIVATE_KEY)?;
            let device_ephemeral_public = p256_public_key(&device_ephemeral_key)?;

            let ephemeral_secret = p256_ecdh(&device_ephemeral_key, &host_ephemeral_public)?;
            let static_secret = p256_ecdh(&device_static_key, &host_static_public)?;
            let session_keys = x963_session_keys(&ephemeral_secret, &static_secret);
            let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
            receipt_input.extend_from_slice(&device_ephemeral_public);
            receipt_input.extend_from_slice(&data[2..]);
            let receipt = aes_cmac(&session_keys[..16], &receipt_input)?;

            let mut counter = [0; AES_BLOCK_SIZE];
            increment_counter(&mut counter);
            *self.session.borrow_mut() = Some(PeerSession {
                sid: 7,
                s_enc: session_keys[16..32]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
                s_mac: session_keys[32..48]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
                s_rmac: session_keys[48..64]
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR)?,
                counter,
                mac_chaining_value: receipt,
                expected_host_cryptogram: [0; MAC_LENGTH],
            });

            let mut response = vec![7];
            response.extend_from_slice(&device_ephemeral_public);
            response.extend_from_slice(&receipt);
            Frame::new(COMMAND_CREATE_SESSION | RESPONSE_BIT, response).map(|frame| frame.encode())
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
                    if self.x25519_private_keys.borrow().contains_key(&id) {
                        let mut info = vec![0; 66];
                        info[7 - 0x0b / 8] |= 1 << (0x0b % 8);
                        info[8..10].copy_from_slice(&id.to_be_bytes());
                        info[10..12].copy_from_slice(&32u16.to_be_bytes());
                        info[12..14].copy_from_slice(&0xffffu16.to_be_bytes());
                        info[14..18].copy_from_slice(&[3, 56, 1, 1]);
                        info[18..26].copy_from_slice(b"test-x25");
                        (inner.command | RESPONSE_BIT, info)
                    } else {
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
                }
                value if value == CommandCode::GetPublicKey as u8 => {
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    if let Some(private_key) = self.x25519_private_keys.borrow().get(&id) {
                        let private_key =
                            PKey::private_key_from_raw_bytes(private_key, Id::X25519)?;
                        let mut key = vec![56];
                        key.extend_from_slice(&private_key.raw_public_key()?);
                        (inner.command | RESPONSE_BIT, key)
                    } else {
                        let mut key = vec![9, 0xc5];
                        key.resize(257, 0xa5);
                        key[256] |= 1;
                        (inner.command | RESPONSE_BIT, key)
                    }
                }
                value
                    if value == CommandCode::GenerateAsymmetricKey as u8
                        || value == CommandCode::PutAsymmetricKey as u8 =>
                {
                    let requested = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let id = if requested == 0 { 2 } else { requested };
                    if inner.command == CommandCode::GenerateAsymmetricKey as u8
                        && inner.data.get(52) == Some(&56)
                    {
                        let private_key = match id {
                            7 => RFC7748_ALICE_PRIVATE_KEY,
                            8 => RFC7748_BOB_PRIVATE_KEY,
                            _ => {
                                let mut private_key = [0; 32];
                                rand_bytes(&mut private_key)?;
                                private_key
                            }
                        };
                        self.x25519_private_keys
                            .borrow_mut()
                            .insert(id, private_key);
                    }
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
                value if value == CommandCode::DeriveEcdh as u8 => {
                    if inner.data.len() == 34 {
                        let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                        (
                            inner.command | RESPONSE_BIT,
                            self.x25519_derive(id, &inner.data[2..])?,
                        )
                    } else {
                        (inner.command | RESPONSE_BIT, vec![0x42; 32])
                    }
                }
                value
                    if value == CommandCode::EncryptEcb as u8
                        || value == CommandCode::DecryptEcb as u8 =>
                {
                    if inner.data.len() < 2 || !(inner.data.len() - 2).is_multiple_of(16) {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let mode = if value == CommandCode::EncryptEcb as u8 {
                        Mode::Encrypt
                    } else {
                        Mode::Decrypt
                    };
                    (
                        inner.command | RESPONSE_BIT,
                        aes_ecb(Self::aes_key(id), &inner.data[2..], mode)?,
                    )
                }
                value
                    if value == CommandCode::EncryptCbc as u8
                        || value == CommandCode::DecryptCbc as u8 =>
                {
                    if inner.data.len() < 18 || !(inner.data.len() - 18).is_multiple_of(16) {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let mode = if value == CommandCode::EncryptCbc as u8 {
                        Mode::Encrypt
                    } else {
                        Mode::Decrypt
                    };
                    (
                        inner.command | RESPONSE_BIT,
                        aes_cbc(
                            Self::aes_key(id),
                            &inner.data[2..18],
                            &inner.data[18..],
                            mode,
                        )?,
                    )
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
                algorithms: vec![
                    1, 5, 9, 12, 19, 20, 21, 22, 25, 46, 48, 50, 51, 52, 53, 54, 56,
                ],
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
    fn asymmetric_pin_uses_at_prefixed_authentication_key_id() {
        let (id, password) = parse_asymmetric_pin(b"@00fFpassword").unwrap();
        assert_eq!(id, 0xff);
        assert_eq!(password, PASSWORD);
        assert!(parse_asymmetric_pin(b"00ffpassword").is_err());
        assert!(parse_asymmetric_pin(b"@xyz1password").is_err());
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
    fn authenticates_asymmetrically_and_exchanges_encrypted_session_messages() {
        let peer = ProtocolPeer::new();
        let mut session = SecureSession::authenticate_asymmetric(&peer, 1, PASSWORD).unwrap();
        assert_eq!(
            session
                .send_command(&peer, &Command::get_storage_info())
                .unwrap(),
            [0xaa, 0xbb, 0xcc]
        );
        session
            .send_command(&peer, &Command::close_session())
            .unwrap();
        assert_eq!(peer.commands.borrow().len(), 4);
    }

    #[test]
    fn asymmetric_authentication_rejects_the_wrong_password() {
        let peer = ProtocolPeer::new();
        assert!(matches!(
            SecureSession::authenticate_asymmetric(&peer, 1, b"wrong-password"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
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
                        | CommandCode::DecryptEcb
                        | CommandCode::EncryptEcb
                        | CommandCode::DecryptCbc
                        | CommandCode::EncryptCbc
                )
        }) {
            let data = [code as u8, 0xa5];
            let command = Command::raw(code, &data).unwrap();
            let response = session.send_command(&peer, &command).unwrap();
            if code == CommandCode::DeriveEcdh {
                assert_eq!(response, vec![0x42; 32]);
            } else {
                assert_eq!(response, data);
            }
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
