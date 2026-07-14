use crate::{
    error::Error, Connector, CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG, CKR_USER_PIN_NOT_INITIALIZED,
};
use openssl::{
    memcmp,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const SECURITY_DOMAIN_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

const AES_BLOCK_SIZE: usize = 16;
const MAC_LENGTH: usize = 8;
const MAX_SHORT_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_EXTENDED_DATA_LENGTH: usize = u16::MAX as usize;
const MAX_SHORT_EXPECTED_LENGTH: u32 = 1 << 8;
const MAX_EXTENDED_EXPECTED_LENGTH: u32 = 1 << 16;
const DERIVATION_CARD_CRYPTOGRAM: u8 = 0x00;
const DERIVATION_HOST_CRYPTOGRAM: u8 = 0x01;
const DERIVATION_CARD_CHALLENGE: u8 = 0x02;
const DERIVATION_S_ENC: u8 = 0x04;
const DERIVATION_S_MAC: u8 = 0x06;
const DERIVATION_S_RMAC: u8 = 0x07;
const SECURITY_C_MAC: u8 = 0x01;
const SECURITY_C_ENCRYPTION: u8 = 0x02;
const SECURITY_R_MAC: u8 = 0x10;
const SECURITY_R_ENCRYPTION: u8 = 0x20;
const IMPLEMENTATION_S16: u8 = 0x01;
const IMPLEMENTATION_PSEUDO_RANDOM_CHALLENGE: u8 = 0x10;
const IMPLEMENTATION_R_MAC: u8 = 0x20;
const IMPLEMENTATION_R_ENCRYPTION: u8 = 0x40;
const RESPONSE_OK: u16 = 0x9000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandApdu {
    pub(crate) cla: u8,
    pub(crate) ins: u8,
    pub(crate) p1: u8,
    pub(crate) p2: u8,
    pub(crate) data: Vec<u8>,
    pub(crate) le: Option<u32>,
    pub(crate) extended: bool,
}

impl CommandApdu {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let extended = self.uses_extended_length(self.data.len())?;
        let mut encoded = self.encode_header_and_data(self.data.len())?;
        if let Some(le) = self.le {
            if extended {
                if self.data.is_empty() {
                    encoded.push(0);
                }
                let encoded_le = if le == MAX_EXTENDED_EXPECTED_LENGTH {
                    0
                } else {
                    le as u16
                };
                encoded.extend_from_slice(&encoded_le.to_be_bytes());
            } else {
                encoded.push(if le == MAX_SHORT_EXPECTED_LENGTH {
                    0
                } else {
                    le as u8
                });
            }
        }
        Ok(encoded)
    }

    fn encode_header_and_data(&self, encoded_data_len: usize) -> Result<Vec<u8>, Error> {
        if encoded_data_len < self.data.len() || encoded_data_len > MAX_EXTENDED_DATA_LENGTH {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let extended = self.uses_extended_length(encoded_data_len)?;
        let length_bytes = if encoded_data_len == 0 {
            0
        } else if extended {
            3
        } else {
            1
        };
        let mut encoded = Vec::with_capacity(4 + length_bytes + self.data.len());
        encoded.extend([self.cla, self.ins, self.p1, self.p2]);
        if encoded_data_len != 0 {
            if extended {
                encoded.push(0);
                encoded.extend_from_slice(&(encoded_data_len as u16).to_be_bytes());
            } else {
                encoded.push(encoded_data_len as u8);
            }
            encoded.extend_from_slice(&self.data);
        }
        Ok(encoded)
    }

    fn uses_extended_length(&self, data_len: usize) -> Result<bool, Error> {
        if data_len > MAX_EXTENDED_DATA_LENGTH
            || self
                .le
                .is_some_and(|le| le == 0 || le > MAX_EXTENDED_EXPECTED_LENGTH)
        {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        Ok(self.extended
            || data_len > MAX_SHORT_DATA_LENGTH
            || self.le.is_some_and(|le| le > MAX_SHORT_EXPECTED_LENGTH))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponseApdu {
    pub(crate) data: Vec<u8>,
    pub(crate) status: u16,
}

impl ResponseApdu {
    fn parse(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() < 2 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let data_len = encoded.len() - 2;
        Ok(Self {
            data: encoded[..data_len].to_vec(),
            status: u16::from_be_bytes([encoded[data_len], encoded[data_len + 1]]),
        })
    }

    fn require_success(self) -> Result<Self, Error> {
        if self.status != RESPONSE_OK {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(self)
    }
}

pub(crate) struct Scp03KeySet {
    key_version: u8,
    key_id: u8,
    enc: Zeroizing<Vec<u8>>,
    mac: Zeroizing<Vec<u8>>,
    dek: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Scp03KeySet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Scp03KeySet")
            .field("key_version", &self.key_version)
            .field("key_id", &self.key_id)
            .field("key_size", &self.enc.len())
            .finish_non_exhaustive()
    }
}

impl Scp03KeySet {
    #[cfg(test)]
    fn new(
        key_version: u8,
        key_id: u8,
        enc: Vec<u8>,
        mac: Vec<u8>,
        dek: Vec<u8>,
    ) -> Result<Self, Error> {
        let keys = Self {
            key_version,
            key_id,
            enc: Zeroizing::new(enc),
            mac: Zeroizing::new(mac),
            dek: Some(Zeroizing::new(dek)),
        };
        keys.validate()?;
        Ok(keys)
    }

    pub(crate) fn from_environment() -> Result<Self, Error> {
        let enc = environment_key("PKCS11RS_SCP03_ENC_KEY")?;
        let mac = environment_key("PKCS11RS_SCP03_MAC_KEY")?;
        let dek = environment_optional_key("PKCS11RS_SCP03_DEK_KEY")?;
        let key_version = environment_byte("PKCS11RS_SCP03_KEY_VERSION", 0)?;
        let key_id = environment_byte("PKCS11RS_SCP03_KEY_ID", 0)?;
        let keys = Self {
            key_version,
            key_id,
            enc,
            mac,
            dek,
        };
        keys.validate()?;
        Ok(keys)
    }

    fn validate(&self) -> Result<(), Error> {
        if !valid_aes_key(&self.enc)
            || !valid_aes_key(&self.mac)
            || self.dek.as_deref().is_some_and(|key| !valid_aes_key(key))
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(())
    }
}

fn valid_aes_key(key: &[u8]) -> bool {
    matches!(key.len(), 16 | 24 | 32)
}

fn environment_key(name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let value = Zeroizing::new(std::env::var(name).map_err(|error| match error {
        std::env::VarError::NotPresent => Error::from(CKR_USER_PIN_NOT_INITIALIZED),
        std::env::VarError::NotUnicode(_) => Error::from(CKR_ARGUMENTS_BAD),
    })?);
    parse_hex(&value).map(Zeroizing::new)
}

fn environment_optional_key(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    match std::env::var(name) {
        Ok(value) => {
            let value = Zeroizing::new(value);
            parse_hex(&value).map(Zeroizing::new).map(Some)
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn environment_byte(name: &str, default: u8) -> Result<u8, Error> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(default);
    };
    let value = value.to_str().ok_or(CKR_ARGUMENTS_BAD)?;
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).map_err(|_| CKR_ARGUMENTS_BAD.into())
    } else {
        value.parse().map_err(|_| CKR_ARGUMENTS_BAD.into())
    }
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Error> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .collect();
    if !compact.len().is_multiple_of(2) || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            u8::from_str_radix(pair, 16).map_err(|_| CKR_ARGUMENTS_BAD.into())
        })
        .collect()
}

#[derive(Debug)]
struct InitializeUpdate {
    key_version: u8,
    scp_id: u8,
    implementation: u8,
    card_challenge: [u8; 8],
    sequence_counter: Option<[u8; 3]>,
}

impl InitializeUpdate {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 13 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let implementation = data[12];
        validate_implementation(implementation)?;
        let pseudo_random = implementation & IMPLEMENTATION_PSEUDO_RANDOM_CHALLENGE != 0;
        if data.len() != if pseudo_random { 32 } else { 29 } {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(Self {
            key_version: data[10],
            scp_id: data[11],
            implementation,
            card_challenge: data[13..21]
                .try_into()
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
            sequence_counter: if pseudo_random {
                Some(
                    data[29..32]
                        .try_into()
                        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
                )
            } else {
                None
            },
        })
    }
}

pub(crate) struct Scp03Session {
    s_enc: Zeroizing<Vec<u8>>,
    s_mac: Zeroizing<Vec<u8>>,
    s_rmac: Zeroizing<Vec<u8>>,
    mac_chaining_value: [u8; AES_BLOCK_SIZE],
    encryption_counter: u128,
    security_level: u8,
}

impl std::fmt::Debug for Scp03Session {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Scp03Session")
            .field("key_size", &self.s_enc.len())
            .field("security_level", &self.security_level)
            .field("encryption_counter", &self.encryption_counter)
            .finish_non_exhaustive()
    }
}

impl Scp03Session {
    pub(crate) fn authenticate_selected(
        connector: &dyn Connector,
        keys: &Scp03KeySet,
        security_level: u8,
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        let mut host_challenge = [0u8; 8];
        openssl::rand::rand_bytes(&mut host_challenge)
            .map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        Self::establish_with_challenge(connector, keys, security_level, host_challenge)
    }

    fn establish_with_challenge(
        connector: &dyn Connector,
        keys: &Scp03KeySet,
        security_level: u8,
        host_challenge: [u8; 8],
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        let initialize = CommandApdu {
            cla: 0x80,
            ins: 0x50,
            p1: keys.key_version,
            p2: keys.key_id,
            data: host_challenge.to_vec(),
            le: Some(256),
            extended: false,
        };
        let initialize_response = transmit(connector, &initialize)?.require_success()?;
        let update = InitializeUpdate::parse(&initialize_response.data)?;
        if update.scp_id != 0x03
            || (keys.key_version != 0 && update.key_version != keys.key_version)
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        validate_card_capabilities(update.implementation, security_level)?;
        if let Some(sequence_counter) = update.sequence_counter {
            let mut challenge_context = Vec::with_capacity(3 + SECURITY_DOMAIN_AID.len());
            challenge_context.extend_from_slice(&sequence_counter);
            challenge_context.extend_from_slice(&SECURITY_DOMAIN_AID);
            let expected_challenge =
                derive(&keys.enc, DERIVATION_CARD_CHALLENGE, &challenge_context, 64)?;
            if !memcmp::eq(&expected_challenge, &update.card_challenge) {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }

        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&host_challenge);
        context[8..].copy_from_slice(&update.card_challenge);
        let enc_bits = (keys.enc.len() * 8) as u16;
        let mac_bits = (keys.mac.len() * 8) as u16;
        let s_enc = Zeroizing::new(derive(&keys.enc, DERIVATION_S_ENC, &context, enc_bits)?);
        let s_mac = Zeroizing::new(derive(&keys.mac, DERIVATION_S_MAC, &context, mac_bits)?);
        let s_rmac = Zeroizing::new(derive(&keys.mac, DERIVATION_S_RMAC, &context, mac_bits)?);
        let expected_card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &context, 64)?;
        if !memcmp::eq(&expected_card_cryptogram, &initialize_response.data[21..29]) {
            return Err(CKR_PIN_INCORRECT.into());
        }
        let host_cryptogram = derive(&s_mac, DERIVATION_HOST_CRYPTOGRAM, &context, 64)?;

        let mut session = Self {
            s_enc,
            s_mac,
            s_rmac,
            mac_chaining_value: [0; AES_BLOCK_SIZE],
            encryption_counter: 0,
            security_level,
        };
        let authenticate = session.external_authenticate(&host_cryptogram)?;
        transmit(connector, &authenticate)?.require_success()?;
        Ok(session)
    }

    fn external_authenticate(&mut self, host_cryptogram: &[u8]) -> Result<CommandApdu, Error> {
        if host_cryptogram.len() != MAC_LENGTH {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut mac_input = Vec::with_capacity(16 + 5 + MAC_LENGTH);
        mac_input.extend_from_slice(&self.mac_chaining_value);
        mac_input.extend([0x84, 0x82, self.security_level, 0x00, 0x10]);
        mac_input.extend_from_slice(host_cryptogram);
        let mac = aes_cmac(&self.s_mac, &mac_input)?;
        self.mac_chaining_value.copy_from_slice(&mac);

        let mut data = host_cryptogram.to_vec();
        data.extend_from_slice(&mac[..MAC_LENGTH]);
        Ok(CommandApdu {
            cla: 0x84,
            ins: 0x82,
            p1: self.security_level,
            p2: 0,
            data,
            le: None,
            extended: false,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn transmit(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        let protected = self.protect_command(command)?;
        let response = transmit(connector, &protected)?;
        self.unprotect_response(response)
    }

    fn protect_command(&mut self, command: &CommandApdu) -> Result<CommandApdu, Error> {
        self.encryption_counter = self
            .encryption_counter
            .checked_add(1)
            .ok_or(CKR_DEVICE_ERROR)?;

        if self.security_level == 0 {
            return Ok(command.clone());
        }
        if command.cla & 0x03 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        command.uses_extended_length(command.data.len())?;
        let mut data = command.data.clone();
        if self.security_level & SECURITY_C_ENCRYPTION != 0 && !data.is_empty() {
            let padded = pad(&data);
            let iv = self.command_iv(false)?;
            data = aes_cbc(&self.s_enc, &iv, &padded, Mode::Encrypt)?;
        }

        let cla = command.cla | 0x04;
        let mut protected = CommandApdu {
            cla,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data,
            le: command.le,
            extended: command.extended,
        };
        if self.security_level & SECURITY_C_MAC != 0 {
            let protected_len = protected
                .data
                .len()
                .checked_add(MAC_LENGTH)
                .filter(|length| *length <= MAX_EXTENDED_DATA_LENGTH)
                .ok_or(CKR_DATA_LEN_RANGE)?;
            let mut mac_input = Vec::with_capacity(16 + 7 + protected.data.len());
            mac_input.extend_from_slice(&self.mac_chaining_value);
            mac_input.extend_from_slice(&protected.encode_header_and_data(protected_len)?);
            let mac = aes_cmac(&self.s_mac, &mac_input)?;
            self.mac_chaining_value.copy_from_slice(&mac);
            protected.data.extend_from_slice(&mac[..MAC_LENGTH]);
        }
        Ok(protected)
    }

    fn unprotect_response(&self, response: ResponseApdu) -> Result<ResponseApdu, Error> {
        let mut data = response.data;
        if self.security_level & SECURITY_R_MAC != 0 {
            if data.len() < MAC_LENGTH {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
            let mac_offset = data.len() - MAC_LENGTH;
            let received_mac = data.split_off(mac_offset);
            let mut mac_input = Vec::with_capacity(16 + data.len() + 2);
            mac_input.extend_from_slice(&self.mac_chaining_value);
            mac_input.extend_from_slice(&data);
            mac_input.extend_from_slice(&response.status.to_be_bytes());
            let expected_mac = aes_cmac(&self.s_rmac, &mac_input)?;
            if !memcmp::eq(&expected_mac[..MAC_LENGTH], &received_mac) {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
        }
        if self.security_level & SECURITY_R_ENCRYPTION != 0 && !data.is_empty() {
            if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
            let iv = self.command_iv(true)?;
            data = unpad(aes_cbc(&self.s_enc, &iv, &data, Mode::Decrypt)?)?;
        }
        Ok(ResponseApdu {
            data,
            status: response.status,
        })
    }

    fn command_iv(&self, response: bool) -> Result<[u8; AES_BLOCK_SIZE], Error> {
        let mut counter = self.encryption_counter.to_be_bytes();
        if response {
            counter[0] |= 0x80;
        }
        aes_block(&self.s_enc, &counter)
    }
}

pub(crate) fn select_security_domain(connector: &dyn Connector) -> Result<(), Error> {
    let select = CommandApdu {
        cla: 0x00,
        ins: 0xa4,
        p1: 0x04,
        p2: 0x00,
        data: SECURITY_DOMAIN_AID.to_vec(),
        le: Some(256),
        extended: false,
    };
    transmit(connector, &select)?.require_success()?;
    Ok(())
}

fn transmit(connector: &dyn Connector, command: &CommandApdu) -> Result<ResponseApdu, Error> {
    ResponseApdu::parse(&connector.send(&command.encode()?, DEFAULT_TIMEOUT)?)
}

fn validate_security_level(security_level: u8) -> Result<(), Error> {
    if matches!(security_level, 0x00 | 0x01 | 0x03 | 0x11 | 0x13 | 0x33) {
        Ok(())
    } else {
        Err(CKR_ARGUMENTS_BAD.into())
    }
}

fn validate_implementation(implementation: u8) -> Result<(), Error> {
    let response_security = implementation & (IMPLEMENTATION_R_MAC | IMPLEMENTATION_R_ENCRYPTION);
    if implementation & IMPLEMENTATION_S16 != 0
        || implementation & 0x8e != 0
        || response_security == IMPLEMENTATION_R_ENCRYPTION
    {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(())
}

fn validate_card_capabilities(implementation: u8, security_level: u8) -> Result<(), Error> {
    if security_level & SECURITY_R_MAC != 0 && implementation & IMPLEMENTATION_R_MAC == 0 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    if security_level & SECURITY_R_ENCRYPTION != 0
        && implementation & (IMPLEMENTATION_R_MAC | IMPLEMENTATION_R_ENCRYPTION)
            != (IMPLEMENTATION_R_MAC | IMPLEMENTATION_R_ENCRYPTION)
    {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(())
}

pub(crate) fn configured_security_level() -> Result<u8, Error> {
    let security_level = environment_byte("PKCS11RS_SCP03_SECURITY_LEVEL", 0x03)?;
    validate_security_level(security_level)?;
    Ok(security_level)
}

fn derive(key: &[u8], constant: u8, context: &[u8], output_bits: u16) -> Result<Vec<u8>, Error> {
    if output_bits == 0 || !output_bits.is_multiple_of(8) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = output_bits as usize / 8;
    let iterations = output_len.div_ceil(AES_BLOCK_SIZE);
    if iterations > u8::MAX as usize {
        return Err(CKR_DATA_LEN_RANGE.into());
    }

    let mut output = Vec::with_capacity(iterations * AES_BLOCK_SIZE);
    for counter in 1..=iterations {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0; 11]);
        input.push(constant);
        input.push(0);
        input.extend_from_slice(&output_bits.to_be_bytes());
        input.push(counter as u8);
        input.extend_from_slice(context);
        output.extend_from_slice(&aes_cmac(key, &input)?);
    }
    output.truncate(output_len);
    Ok(output)
}

fn aes_cipher(key_len: usize, mode: AesMode) -> Result<Cipher, Error> {
    match (key_len, mode) {
        (16, AesMode::Cbc) => Ok(Cipher::aes_128_cbc()),
        (24, AesMode::Cbc) => Ok(Cipher::aes_192_cbc()),
        (32, AesMode::Cbc) => Ok(Cipher::aes_256_cbc()),
        (16, AesMode::Ecb) => Ok(Cipher::aes_128_ecb()),
        (24, AesMode::Ecb) => Ok(Cipher::aes_192_ecb()),
        (32, AesMode::Ecb) => Ok(Cipher::aes_256_ecb()),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

#[derive(Clone, Copy)]
enum AesMode {
    Cbc,
    Ecb,
}

fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    let cipher = aes_cipher(key.len(), AesMode::Cbc)?;
    let pkey = PKey::cmac(&cipher, key)?;
    let mut signer = Signer::new_without_digest(&pkey)?;
    signer.update(data)?;
    signer
        .sign_to_vec()?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn aes_block(key: &[u8], block: &[u8; AES_BLOCK_SIZE]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    let cipher = aes_cipher(key.len(), AesMode::Ecb)?;
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    crypter.pad(false);
    let mut encrypted = [0u8; AES_BLOCK_SIZE * 2];
    let written = crypter.update(block, &mut encrypted)?;
    let final_written = crypter.finalize(&mut encrypted[written..])?;
    if written + final_written != AES_BLOCK_SIZE {
        return Err(CKR_DEVICE_ERROR.into());
    }
    encrypted[..AES_BLOCK_SIZE]
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

fn aes_cbc(key: &[u8], iv: &[u8], data: &[u8], mode: Mode) -> Result<Vec<u8>, Error> {
    if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let cipher = aes_cipher(key.len(), AesMode::Cbc)?;
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
    crypter.pad(false);
    let mut output = vec![0u8; data.len() + AES_BLOCK_SIZE];
    let written = crypter.update(data, &mut output)?;
    let final_written = crypter.finalize(&mut output[written..])?;
    output.truncate(written + final_written);
    Ok(output)
}

fn pad(data: &[u8]) -> Vec<u8> {
    let padded_len = (data.len() + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(data);
    padded.push(0x80);
    padded.resize(padded_len, 0);
    padded
}

fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let Some(marker) = data.iter().rposition(|byte| *byte != 0) else {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    };
    if data[marker] != 0x80 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    data.truncate(marker);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

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
            "Test"
        }
        fn product(&self) -> &str {
            "SCP03"
        }
        fn serial(&self) -> &str {
            "1"
        }
        fn major(&self) -> u8 {
            1
        }
        fn minor(&self) -> u8 {
            0
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
            self.commands.borrow_mut().push(send_buffer.to_vec());
            let response = self
                .responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR)?;
            receive_buffer[..response.len()].copy_from_slice(&response);
            Ok(&receive_buffer[..response.len()])
        }
    }

    fn hex(value: &str) -> Vec<u8> {
        parse_hex(value).unwrap()
    }

    #[test]
    fn encodes_short_apdu_cases() {
        assert_eq!(
            CommandApdu {
                cla: 0,
                ins: 0x84,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(8),
                extended: false,
            }
            .encode()
            .unwrap(),
            hex("00 84 00 00 08")
        );
        assert_eq!(
            CommandApdu {
                cla: 0,
                ins: 0xa4,
                p1: 4,
                p2: 0,
                data: SECURITY_DOMAIN_AID.to_vec(),
                le: Some(256),
                extended: false,
            }
            .encode()
            .unwrap(),
            hex("00 A4 04 00 08 A0 00 00 01 51 00 00 00 00")
        );
    }

    #[test]
    fn encodes_extended_apdu_cases() {
        assert_eq!(
            CommandApdu {
                cla: 0,
                ins: 0xca,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(65_536),
                extended: false,
            }
            .encode()
            .unwrap(),
            hex("00 CA 00 00 00 00 00")
        );
        assert_eq!(
            CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1: 0,
                p2: 0,
                data: vec![1, 2, 3],
                le: None,
                extended: true,
            }
            .encode()
            .unwrap(),
            hex("80 E2 00 00 00 00 03 01 02 03")
        );

        let data = vec![0x5a; 256];
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: data.clone(),
            le: Some(65_536),
            extended: false,
        };
        let encoded = command.encode().unwrap();
        assert_eq!(&encoded[..7], &hex("80 E2 00 00 00 01 00"));
        assert_eq!(&encoded[7..263], data);
        assert_eq!(&encoded[263..], &[0, 0]);
    }

    #[test]
    fn rejects_unencodable_apdu_lengths() {
        let command = |data, le| CommandApdu {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            data,
            le,
            extended: false,
        };
        assert!(command(vec![0; 65_536], None).encode().is_err());
        assert!(command(vec![], Some(0)).encode().is_err());
        assert!(command(vec![], Some(65_537)).encode().is_err());
    }

    #[test]
    fn parses_response_status() {
        assert_eq!(
            ResponseApdu::parse(&hex("01 02 90 00")).unwrap(),
            ResponseApdu {
                data: vec![1, 2],
                status: 0x9000,
            }
        );
        assert!(ResponseApdu::parse(&[0x90]).is_err());
    }

    #[test]
    fn aes_cmac_matches_nist_vectors() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(
            aes_cmac(&key, &[]).unwrap().as_slice(),
            hex("bb1d6929e95937287fa37d129b756746")
        );
        assert_eq!(
            aes_cmac(&key, &hex("6bc1bee22e409f96e93d7e117393172a"))
                .unwrap()
                .as_slice(),
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
    }

    #[test]
    fn kdf_uses_gp_counter_layout_and_requested_length() {
        let key = hex("404142434445464748494a4b4c4d4e4f");
        let context = hex("0102030405060708 1112131415161718");
        assert_eq!(
            derive(&key, DERIVATION_S_ENC, &context, 128).unwrap(),
            hex("d99675d4a95c58de629225730cddb758")
        );
        assert_eq!(
            derive(&key, DERIVATION_S_ENC, &context, 192).unwrap().len(),
            24
        );
        assert_eq!(
            derive(&key, DERIVATION_S_ENC, &context, 256).unwrap().len(),
            32
        );
    }

    #[test]
    fn selects_configured_security_domain() {
        let connector = ScriptedConnector::new(vec![hex("6f 00 90 00")]);
        select_security_domain(&connector).unwrap();
        assert_eq!(
            connector.commands.into_inner(),
            vec![hex("00 A4 04 00 08 A0 00 00 01 51 00 00 00 00")]
        );
    }

    #[test]
    fn rejects_invalid_padding_and_response_mac() {
        assert!(unpad(vec![0; 16]).is_err());
        assert!(unpad(vec![0x80, 1]).is_err());
        let session = Scp03Session {
            s_enc: Zeroizing::new(vec![0; 16]),
            s_mac: Zeroizing::new(vec![0; 16]),
            s_rmac: Zeroizing::new(vec![0; 16]),
            mac_chaining_value: [0; 16],
            encryption_counter: 1,
            security_level: 0x11,
        };
        assert!(session
            .unprotect_response(ResponseApdu {
                data: vec![0; 8],
                status: 0x9000,
            })
            .is_err());
    }

    #[test]
    fn encrypts_and_macs_commands() {
        let key = hex("404142434445464748494a4b4c4d4e4f");
        let mut session = Scp03Session {
            s_enc: Zeroizing::new(key.clone()),
            s_mac: Zeroizing::new(key.clone()),
            s_rmac: Zeroizing::new(key),
            mac_chaining_value: [0; 16],
            encryption_counter: 0,
            security_level: 0x03,
        };
        let connector = ScriptedConnector::new(vec![hex("90 00")]);
        let response = session
            .transmit(
                &connector,
                &CommandApdu {
                    cla: 0x80,
                    ins: 0xe2,
                    p1: 0,
                    p2: 0,
                    data: vec![1, 2, 3],
                    le: Some(256),
                    extended: false,
                },
            )
            .unwrap();
        assert_eq!(response.status, 0x9000);
        assert_eq!(
            connector.commands.into_inner(),
            vec![hex(
                "84 E2 00 00 18 0F EF 8F BF 4E 4F 9A 76 8B 7A 07 C7 D0 89 88 \
                 BA E5 EF 16 EB C5 06 98 9B 00"
            )]
        );
    }

    #[test]
    fn macs_extended_commands_with_extended_lc() {
        let key = hex("404142434445464748494a4b4c4d4e4f");
        let mut session = Scp03Session {
            s_enc: Zeroizing::new(key.clone()),
            s_mac: Zeroizing::new(key.clone()),
            s_rmac: Zeroizing::new(key),
            mac_chaining_value: [0; 16],
            encryption_counter: 0,
            security_level: 0x01,
        };
        let protected = session
            .protect_command(&CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1: 0,
                p2: 0,
                data: vec![1, 2, 3],
                le: Some(256),
                extended: true,
            })
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            protected,
            hex("84 E2 00 00 00 00 0B 01 02 03 1D 53 BC 91 9D 15 44 FF 01 00")
        );
    }

    #[test]
    fn secure_messaging_promotes_short_commands_when_required() {
        let key = hex("404142434445464748494a4b4c4d4e4f");
        let mut session = Scp03Session {
            s_enc: Zeroizing::new(key.clone()),
            s_mac: Zeroizing::new(key.clone()),
            s_rmac: Zeroizing::new(key),
            mac_chaining_value: [0; 16],
            encryption_counter: 0,
            security_level: 0x03,
        };
        let protected = session
            .protect_command(&CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1: 0,
                p2: 0,
                data: vec![0x5a; 250],
                le: Some(256),
                extended: false,
            })
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(&protected[..7], &hex("84 E2 00 00 00 01 08"));
        assert_eq!(protected.len(), 273);
        assert_eq!(&protected[protected.len() - 2..], &[1, 0]);
    }

    #[test]
    fn authenticates_with_deterministic_challenges() {
        let keys = Scp03KeySet::new(
            0,
            0,
            hex("404142434445464748494a4b4c4d4e4f"),
            hex("404142434445464748494a4b4c4d4e4f"),
            hex("404142434445464748494a4b4c4d4e4f"),
        )
        .unwrap();
        let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
        let card = hex("1112131415161718");
        let mut context = host.to_vec();
        context.extend_from_slice(&card);
        let s_mac = derive(&keys.mac, DERIVATION_S_MAC, &context, 128).unwrap();
        let card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &context, 64).unwrap();
        let mut initialize_response = vec![0; 10];
        initialize_response.extend([0, 3, 0]);
        initialize_response.extend_from_slice(&card);
        initialize_response.extend_from_slice(&card_cryptogram);
        initialize_response.extend([0x90, 0x00]);
        let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

        Scp03Session::establish_with_challenge(&connector, &keys, 0x03, host).unwrap();
        let commands = connector.commands.into_inner();
        assert_eq!(
            commands[0],
            hex("80 50 00 00 08 01 02 03 04 05 06 07 08 00")
        );
        assert_eq!(
            commands[1],
            hex("84 82 03 00 10 00 B1 1D 00 F7 5C 45 6B 08 28 91 E5 45 EC 80 79")
        );
    }

    #[test]
    fn verifies_pseudo_random_card_challenge() {
        let keys = Scp03KeySet::new(
            0,
            0,
            hex("404142434445464748494a4b4c4d4e4f"),
            hex("404142434445464748494a4b4c4d4e4f"),
            hex("404142434445464748494a4b4c4d4e4f"),
        )
        .unwrap();
        let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
        let sequence = hex("000001");
        let mut challenge_context = sequence.clone();
        challenge_context.extend_from_slice(&SECURITY_DOMAIN_AID);
        let card = derive(&keys.enc, DERIVATION_CARD_CHALLENGE, &challenge_context, 64).unwrap();
        assert_eq!(card, hex("86 C8 BD 65 FA 10 44 EE"));
        let mut session_context = host.to_vec();
        session_context.extend_from_slice(&card);
        let s_mac = derive(&keys.mac, DERIVATION_S_MAC, &session_context, 128).unwrap();
        let card_cryptogram =
            derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &session_context, 64).unwrap();
        let mut initialize_response = vec![0; 10];
        initialize_response.extend([0, 3, 0x10]);
        initialize_response.extend_from_slice(&card);
        initialize_response.extend_from_slice(&card_cryptogram);
        initialize_response.extend_from_slice(&sequence);
        initialize_response.extend([0x90, 0x00]);
        let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

        Scp03Session::establish_with_challenge(&connector, &keys, 0x03, host).unwrap();
    }

    #[test]
    fn rejects_unsupported_response_security_and_s16() {
        assert!(validate_card_capabilities(0x00, 0x11).is_err());
        assert!(validate_card_capabilities(0x20, 0x33).is_err());
        assert!(validate_card_capabilities(0x60, 0x33).is_ok());
        assert!(validate_implementation(0x01).is_err());
        assert!(validate_implementation(0x40).is_err());
    }
}
