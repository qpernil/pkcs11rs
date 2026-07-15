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

pub(crate) const YUBIKEY_ISSUER_SECURITY_DOMAIN_AID: [u8; 8] =
    [0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
pub(crate) const YUBIKEY_FACTORY_KEY_VERSION: u8 = 0xff;
pub(crate) const YUBIKEY_FACTORY_KEY_ID: u8 = 0x00;
pub(crate) const YUBIKEY_FACTORY_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
pub(crate) const YUBIKEY_SECURITY_LEVEL: u8 = 0x33;

const AES_BLOCK_SIZE: usize = 16;
const MAC_LENGTH: usize = 8;
const MAX_SHORT_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_EXTENDED_DATA_LENGTH: usize = u16::MAX as usize;
const MAX_SHORT_EXPECTED_LENGTH: u32 = 1 << 8;
const MAX_EXTENDED_EXPECTED_LENGTH: u32 = 1 << 16;
const MAX_CHAINED_RESPONSE_LENGTH: usize =
    MAX_EXTENDED_EXPECTED_LENGTH as usize + AES_BLOCK_SIZE + MAC_LENGTH;
const MAX_RESPONSE_CHAIN_SEGMENTS: usize =
    MAX_EXTENDED_EXPECTED_LENGTH as usize / MAX_SHORT_EXPECTED_LENGTH as usize;
const MORE_COMMANDS: u8 = 0x80;
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
const YUBICO_DIVERSIFICATION_ENC_LABEL: [u8; 4] = [0, 0, 0, 1];
const YUBICO_DIVERSIFICATION_MAC_LABEL: [u8; 4] = [0, 0, 0, 2];
const YUBICO_DIVERSIFICATION_DEK_LABEL: [u8; 4] = [0, 0, 0, 3];
const YUBICO_DIVERSIFIED_KEY_BITS: u16 = 128;
const YUBICO_BMK_LENGTH: usize = 32;
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
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
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
    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() < 2 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let data_len = encoded.len() - 2;
        Ok(Self {
            data: encoded[..data_len].to_vec(),
            status: u16::from_be_bytes([encoded[data_len], encoded[data_len + 1]]),
        })
    }

    pub(crate) fn require_success(self) -> Result<Self, Error> {
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
    diversification_bmk: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Scp03KeySet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Scp03KeySet")
            .field("key_version", &self.key_version)
            .field("key_id", &self.key_id)
            .field(
                "key_size",
                &self
                    .diversification_bmk
                    .as_ref()
                    .map_or(self.enc.len(), |_| AES_BLOCK_SIZE),
            )
            .field("yubico_diversified", &self.diversification_bmk.is_some())
            .finish_non_exhaustive()
    }
}

impl Scp03KeySet {
    fn yubikey_factory() -> Self {
        let key = || Zeroizing::new(YUBIKEY_FACTORY_KEY.to_vec());
        Self {
            key_version: YUBIKEY_FACTORY_KEY_VERSION,
            key_id: YUBIKEY_FACTORY_KEY_ID,
            enc: key(),
            mac: key(),
            dek: Some(key()),
            diversification_bmk: None,
        }
    }

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
            diversification_bmk: None,
        };
        keys.validate()?;
        Ok(keys)
    }

    pub(crate) fn from_environment() -> Result<Self, Error> {
        let diversification_bmk = environment_optional_key("PKCS11RS_SCP03_BMK")?;
        let direct_keys_configured = [
            "PKCS11RS_SCP03_ENC_KEY",
            "PKCS11RS_SCP03_MAC_KEY",
            "PKCS11RS_SCP03_DEK_KEY",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some());
        if diversification_bmk.is_some() && direct_keys_configured {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        let (enc, mac, dek) = if diversification_bmk.is_some() {
            (Zeroizing::new(Vec::new()), Zeroizing::new(Vec::new()), None)
        } else if direct_keys_configured {
            (
                environment_key("PKCS11RS_SCP03_ENC_KEY")?,
                environment_key("PKCS11RS_SCP03_MAC_KEY")?,
                environment_optional_key("PKCS11RS_SCP03_DEK_KEY")?,
            )
        } else {
            let defaults = Self::yubikey_factory();
            (defaults.enc, defaults.mac, defaults.dek)
        };
        let key_version =
            environment_byte("PKCS11RS_SCP03_KEY_VERSION", YUBIKEY_FACTORY_KEY_VERSION)?;
        let key_id = environment_byte("PKCS11RS_SCP03_KEY_ID", YUBIKEY_FACTORY_KEY_ID)?;
        validate_factory_key_selector(
            key_version,
            key_id,
            diversification_bmk.is_some() || direct_keys_configured,
        )?;
        let keys = Self {
            key_version,
            key_id,
            enc,
            mac,
            dek,
            diversification_bmk,
        };
        keys.validate()?;
        Ok(keys)
    }

    fn validate(&self) -> Result<(), Error> {
        if let Some(bmk) = self.diversification_bmk.as_deref() {
            if bmk.len() == YUBICO_BMK_LENGTH
                && self.enc.is_empty()
                && self.mac.is_empty()
                && self.dek.is_none()
            {
                return Ok(());
            }
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if !valid_aes_key(&self.enc)
            || !valid_aes_key(&self.mac)
            || self.dek.as_deref().is_some_and(|key| !valid_aes_key(key))
            || self.enc.len() != self.mac.len()
            || self
                .dek
                .as_deref()
                .is_some_and(|key| key.len() != self.enc.len())
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(())
    }

    fn resolve(&self, issuer_context: &[u8; 10]) -> Result<ResolvedKeySet, Error> {
        if let Some(bmk) = self.diversification_bmk.as_deref() {
            return Ok(ResolvedKeySet {
                enc: Zeroizing::new(yubico_diversify_key(
                    bmk,
                    YUBICO_DIVERSIFICATION_ENC_LABEL,
                    issuer_context,
                )?),
                mac: Zeroizing::new(yubico_diversify_key(
                    bmk,
                    YUBICO_DIVERSIFICATION_MAC_LABEL,
                    issuer_context,
                )?),
                dek: Some(Zeroizing::new(yubico_diversify_key(
                    bmk,
                    YUBICO_DIVERSIFICATION_DEK_LABEL,
                    issuer_context,
                )?)),
            });
        }
        Ok(ResolvedKeySet {
            enc: Zeroizing::new(self.enc.to_vec()),
            mac: Zeroizing::new(self.mac.to_vec()),
            dek: self.dek.as_deref().map(|key| Zeroizing::new(key.to_vec())),
        })
    }
}

struct ResolvedKeySet {
    enc: Zeroizing<Vec<u8>>,
    mac: Zeroizing<Vec<u8>>,
    #[allow(dead_code)]
    dek: Option<Zeroizing<Vec<u8>>>,
}

fn valid_aes_key(key: &[u8]) -> bool {
    matches!(key.len(), 16 | 24 | 32)
}

fn validate_factory_key_selector(
    key_version: u8,
    key_id: u8,
    custom_key_material: bool,
) -> Result<(), Error> {
    if custom_key_material
        || (key_version == YUBIKEY_FACTORY_KEY_VERSION && key_id == YUBIKEY_FACTORY_KEY_ID)
    {
        Ok(())
    } else {
        Err(CKR_ARGUMENTS_BAD.into())
    }
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

pub(crate) fn environment_byte(name: &str, default: u8) -> Result<u8, Error> {
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

pub(crate) fn parse_hex(value: &str) -> Result<Vec<u8>, Error> {
    let compact = Zeroizing::new(
        value
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != ':')
            .collect::<String>(),
    );
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
    issuer_context: [u8; 10],
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
            issuer_context: data[..10]
                .try_into()
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
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
    pub(crate) fn from_session_keys(
        s_enc: Vec<u8>,
        s_mac: Vec<u8>,
        s_rmac: Vec<u8>,
        mac_chaining_value: [u8; AES_BLOCK_SIZE],
        security_level: u8,
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        if !valid_aes_key(&s_enc) || s_enc.len() != s_mac.len() || s_enc.len() != s_rmac.len() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Self {
            s_enc: Zeroizing::new(s_enc),
            s_mac: Zeroizing::new(s_mac),
            s_rmac: Zeroizing::new(s_rmac),
            mac_chaining_value,
            encryption_counter: 0,
            security_level,
        })
    }

    pub(crate) fn authenticate_selected(
        connector: &dyn Connector,
        keys: &Scp03KeySet,
        security_level: u8,
        selected_aid: &[u8],
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        let mut host_challenge = [0u8; 8];
        openssl::rand::rand_bytes(&mut host_challenge)
            .map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        Self::establish_with_challenge(
            connector,
            keys,
            security_level,
            host_challenge,
            selected_aid,
        )
    }

    fn establish_with_challenge(
        connector: &dyn Connector,
        keys: &Scp03KeySet,
        security_level: u8,
        host_challenge: [u8; 8],
        selected_aid: &[u8],
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
        let static_keys = keys.resolve(&update.issuer_context)?;
        if let Some(sequence_counter) = update.sequence_counter {
            let mut challenge_context = Vec::with_capacity(3 + selected_aid.len());
            challenge_context.extend_from_slice(&sequence_counter);
            challenge_context.extend_from_slice(selected_aid);
            let expected_challenge = derive(
                &static_keys.enc,
                DERIVATION_CARD_CHALLENGE,
                &challenge_context,
                64,
            )?;
            if !memcmp::eq(&expected_challenge, &update.card_challenge) {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }

        let (mut session, host_cryptogram) = Self::from_initialize_update(
            &static_keys,
            security_level,
            host_challenge,
            &update,
            &initialize_response.data[21..29],
        )?;
        let authenticate = session.external_authenticate(&host_cryptogram)?;
        transmit(connector, &authenticate)?.require_success()?;
        Ok(session)
    }

    fn from_initialize_update(
        static_keys: &ResolvedKeySet,
        security_level: u8,
        host_challenge: [u8; 8],
        update: &InitializeUpdate,
        card_cryptogram: &[u8],
    ) -> Result<(Self, Vec<u8>), Error> {
        validate_security_level(security_level)?;
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&host_challenge);
        context[8..].copy_from_slice(&update.card_challenge);
        let enc_bits = (static_keys.enc.len() * 8) as u16;
        let mac_bits = (static_keys.mac.len() * 8) as u16;
        let s_enc = Zeroizing::new(derive(
            &static_keys.enc,
            DERIVATION_S_ENC,
            &context,
            enc_bits,
        )?);
        let s_mac = Zeroizing::new(derive(
            &static_keys.mac,
            DERIVATION_S_MAC,
            &context,
            mac_bits,
        )?);
        let s_rmac = Zeroizing::new(derive(
            &static_keys.mac,
            DERIVATION_S_RMAC,
            &context,
            mac_bits,
        )?);
        let expected_card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &context, 64)?;
        if !memcmp::eq(&expected_card_cryptogram, card_cryptogram) {
            return Err(CKR_PIN_INCORRECT.into());
        }
        let host_cryptogram = derive(&s_mac, DERIVATION_HOST_CRYPTOGRAM, &context, 64)?;

        Ok((
            Self {
                s_enc,
                s_mac,
                s_rmac,
                mac_chaining_value: [0; AES_BLOCK_SIZE],
                encryption_counter: 0,
                security_level,
            },
            host_cryptogram,
        ))
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

    pub(crate) fn transmit(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        let protected = self.protect_command(command)?;
        let response = Self::collect_response_chain(connector, transmit(connector, &protected)?)?;
        self.unprotect_response(response)
    }

    pub(crate) fn transmit_chained(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        if command.p1 & MORE_COMMANDS != 0
            || command.le.is_some_and(|le| le > MAX_SHORT_EXPECTED_LENGTH)
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        let protected = self.protect_command(command)?;
        if protected.data.len() <= MAX_SHORT_DATA_LENGTH {
            let response =
                Self::collect_response_chain(connector, transmit(connector, &protected)?)?;
            return self.unprotect_response(response);
        }

        let segment_count = protected.data.len().div_ceil(MAX_SHORT_DATA_LENGTH);
        for (index, data) in protected.data.chunks(MAX_SHORT_DATA_LENGTH).enumerate() {
            let last = index + 1 == segment_count;
            let segment = CommandApdu {
                cla: protected.cla,
                ins: protected.ins,
                p1: if last {
                    protected.p1
                } else {
                    protected.p1 | MORE_COMMANDS
                },
                p2: protected.p2,
                data: data.to_vec(),
                le: if last { protected.le } else { None },
                extended: false,
            };
            let response = transmit(connector, &segment)?;
            if last {
                let response = Self::collect_response_chain(connector, response)?;
                return self.unprotect_response(response);
            }
            if response.status != RESPONSE_OK || !response.data.is_empty() {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }
        Err(CKR_DEVICE_ERROR.into())
    }

    fn collect_response_chain(
        connector: &dyn Connector,
        mut response: ResponseApdu,
    ) -> Result<ResponseApdu, Error> {
        if response.data.len() > MAX_CHAINED_RESPONSE_LENGTH {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut data = Vec::new();
        let mut segments = 0usize;
        while response.status & 0xff00 == 0x6100 {
            segments += 1;
            if segments > MAX_RESPONSE_CHAIN_SEGMENTS {
                return Err(CKR_DEVICE_ERROR.into());
            }
            if segments > 1 && response.data.is_empty() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let combined_len = data
                .len()
                .checked_add(response.data.len())
                .filter(|length| *length <= MAX_CHAINED_RESPONSE_LENGTH)
                .ok_or(CKR_DEVICE_ERROR)?;
            data.reserve(combined_len - data.len());
            data.extend_from_slice(&response.data);

            let available = (response.status & 0x00ff) as u32;
            let get_response = CommandApdu {
                cla: 0x00,
                ins: 0xc0,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(if available == 0 { 256 } else { available }),
                extended: false,
            };
            response = transmit(connector, &get_response)?;
        }

        let combined_len = data
            .len()
            .checked_add(response.data.len())
            .filter(|length| *length <= MAX_CHAINED_RESPONSE_LENGTH)
            .ok_or(CKR_DEVICE_ERROR)?;
        data.reserve(combined_len - data.len());
        data.extend_from_slice(&response.data);
        Ok(ResponseApdu {
            data,
            status: response.status,
        })
    }

    fn protect_command(&mut self, command: &CommandApdu) -> Result<CommandApdu, Error> {
        let cla = if self.security_level == 0 {
            command.cla
        } else {
            normalize_scp03_cla(command.cla)?
        };
        self.encryption_counter = self
            .encryption_counter
            .checked_add(1)
            .ok_or(CKR_DEVICE_ERROR)?;

        if self.security_level == 0 {
            return Ok(command.clone());
        }

        command.uses_extended_length(command.data.len())?;
        let mut data = command.data.clone();
        if self.security_level & SECURITY_C_ENCRYPTION != 0 && !data.is_empty() {
            let padded = pad(&data);
            let iv = self.command_iv(false)?;
            data = aes_cbc(&self.s_enc, &iv, &padded, Mode::Encrypt)?;
        }

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
        if response.status != RESPONSE_OK
            && response.status & 0xff00 != 0x6200
            && response.status & 0xff00 != 0x6300
        {
            if !response.data.is_empty() {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
            return Ok(response);
        }
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

fn normalize_scp03_cla(cla: u8) -> Result<u8, Error> {
    if cla & 0x40 != 0 || cla & 0x03 != 0 {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok((cla & !0x0c) | 0x04)
}

pub(crate) fn select_application(connector: &dyn Connector, aid: &[u8]) -> Result<(), Error> {
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let select = CommandApdu {
        cla: 0x00,
        ins: 0xa4,
        p1: 0x04,
        p2: 0x00,
        data: aid.to_vec(),
        le: Some(256),
        extended: false,
    };
    transmit(connector, &select)?.require_success()?;
    Ok(())
}

pub(crate) fn transmit(
    connector: &dyn Connector,
    command: &CommandApdu,
) -> Result<ResponseApdu, Error> {
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
    let security_level = environment_byte("PKCS11RS_SCP03_SECURITY_LEVEL", YUBIKEY_SECURITY_LEVEL)?;
    validate_security_level(security_level)?;
    Ok(security_level)
}

pub(crate) fn configured_application_aid() -> Result<Zeroizing<Vec<u8>>, Error> {
    let aid = match std::env::var("PKCS11RS_SCP03_AID") {
        Ok(value) => Zeroizing::new(parse_hex(&value)?),
        Err(std::env::VarError::NotPresent) => {
            Zeroizing::new(YUBIKEY_ISSUER_SECURITY_DOMAIN_AID.to_vec())
        }
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(aid)
}

fn yubico_diversify_key(
    bmk: &[u8],
    label: [u8; 4],
    issuer_context: &[u8; 10],
) -> Result<Vec<u8>, Error> {
    if bmk.len() != YUBICO_BMK_LENGTH {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mut input = Vec::with_capacity(18);
    input.push(1);
    input.extend_from_slice(&label);
    input.push(0);
    input.extend_from_slice(issuer_context);
    input.extend_from_slice(&YUBICO_DIVERSIFIED_KEY_BITS.to_be_bytes());
    Ok(aes_cmac(bmk, &input)?.to_vec())
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

pub(crate) fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
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

    fn test_session(security_level: u8) -> Scp03Session {
        let key = hex("404142434445464748494a4b4c4d4e4f");
        Scp03Session {
            s_enc: Zeroizing::new(key.clone()),
            s_mac: Zeroizing::new(key.clone()),
            s_rmac: Zeroizing::new(key),
            mac_chaining_value: [0; 16],
            encryption_counter: 0,
            security_level,
        }
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
                data: YUBIKEY_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
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
    fn yubikey_factory_key_set_uses_documented_defaults() {
        let keys = Scp03KeySet::yubikey_factory();
        assert_eq!(keys.key_version, YUBIKEY_FACTORY_KEY_VERSION);
        assert_eq!(keys.key_id, YUBIKEY_FACTORY_KEY_ID);
        assert_eq!(keys.enc.as_slice(), YUBIKEY_FACTORY_KEY);
        assert_eq!(keys.mac.as_slice(), YUBIKEY_FACTORY_KEY);
        assert_eq!(
            keys.dek.as_ref().map(|key| key.as_slice()),
            Some(YUBIKEY_FACTORY_KEY.as_slice())
        );
        assert_eq!(YUBIKEY_SECURITY_LEVEL, 0x33);
    }

    #[test]
    fn non_default_key_selectors_require_custom_key_material() {
        assert!(validate_factory_key_selector(
            YUBIKEY_FACTORY_KEY_VERSION,
            YUBIKEY_FACTORY_KEY_ID,
            false,
        )
        .is_ok());
        assert!(validate_factory_key_selector(1, YUBIKEY_FACTORY_KEY_ID, false).is_err());
        assert!(validate_factory_key_selector(YUBIKEY_FACTORY_KEY_VERSION, 1, false).is_err());
        assert!(validate_factory_key_selector(1, 1, true).is_ok());
    }

    #[test]
    fn accepts_explicit_generic_scp03_key_sizes_and_security_levels() {
        for key_size in [16, 24, 32] {
            assert!(Scp03KeySet::new(
                1,
                0,
                vec![1; key_size],
                vec![2; key_size],
                vec![3; key_size],
            )
            .is_ok());
        }
        assert!(Scp03KeySet::new(1, 0, vec![1; 16], vec![2; 24], vec![3; 16]).is_err());
        assert!(Scp03KeySet::new(1, 0, vec![1; 16], vec![2; 16], vec![3; 32]).is_err());
        for security_level in [0x00, 0x01, 0x03, 0x11, 0x13, 0x33] {
            assert!(validate_security_level(security_level).is_ok());
        }
    }

    #[test]
    fn yubico_diversification_matches_sp800_108_cmac_vectors() {
        let bmk = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let issuer_context: [u8; 10] = hex("00010203040506070809").try_into().unwrap();
        assert_eq!(
            yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_ENC_LABEL, &issuer_context).unwrap(),
            hex("6D8EF504CDFCA3D667DE72F24C4C82AF")
        );
        assert_eq!(
            yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_MAC_LABEL, &issuer_context).unwrap(),
            hex("90753AB6FD71D3BB9618DBEA179E0A56")
        );
        assert_eq!(
            yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_DEK_LABEL, &issuer_context).unwrap(),
            hex("53A68B700A229B4314315BFCB162A650")
        );
        assert!(yubico_diversify_key(
            &bmk[..AES_BLOCK_SIZE],
            YUBICO_DIVERSIFICATION_ENC_LABEL,
            &issuer_context,
        )
        .is_err());
    }

    #[test]
    fn resolves_all_three_keys_from_the_initialize_update_context() {
        let keys = Scp03KeySet {
            key_version: 7,
            key_id: 0,
            enc: Zeroizing::new(Vec::new()),
            mac: Zeroizing::new(Vec::new()),
            dek: None,
            diversification_bmk: Some(Zeroizing::new(hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ))),
        };
        keys.validate().unwrap();
        let resolved = keys
            .resolve(&hex("00010203040506070809").try_into().unwrap())
            .unwrap();
        assert_eq!(
            resolved.enc.as_slice(),
            hex("6D8EF504CDFCA3D667DE72F24C4C82AF")
        );
        assert_eq!(
            resolved.mac.as_slice(),
            hex("90753AB6FD71D3BB9618DBEA179E0A56")
        );
        assert_eq!(
            resolved.dek.as_ref().map(|key| key.as_slice()),
            Some(hex("53A68B700A229B4314315BFCB162A650").as_slice())
        );
    }

    #[test]
    fn selects_configured_security_domain() {
        let connector = ScriptedConnector::new(vec![hex("6f 00 90 00")]);
        select_application(&connector, &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID).unwrap();
        assert_eq!(
            connector.commands.into_inner(),
            vec![hex("00 A4 04 00 08 A0 00 00 01 51 00 00 00 00")]
        );
        assert!(select_application(&ScriptedConnector::new(Vec::new()), &[1, 2, 3, 4]).is_err());
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
    fn secure_messaging_normalizes_cla_and_rejects_other_logical_channels() {
        for (cla, expected) in [(0x08, 0x04), (0x88, 0x84)] {
            let protected = test_session(0x01)
                .protect_command(&CommandApdu {
                    cla,
                    ins: 0xca,
                    p1: 0,
                    p2: 0,
                    data: vec![],
                    le: Some(256),
                    extended: false,
                })
                .unwrap();
            assert_eq!(protected.cla, expected);
        }

        for cla in [0x01, 0x40, 0x81, 0xc0] {
            let mut session = test_session(0x01);
            assert!(session
                .protect_command(&CommandApdu {
                    cla,
                    ins: 0xca,
                    p1: 0,
                    p2: 0,
                    data: vec![],
                    le: Some(256),
                    extended: false,
                })
                .is_err());
            assert_eq!(session.encryption_counter, 0);
        }
    }

    #[test]
    fn chains_after_protecting_the_complete_command() {
        let data: Vec<u8> = (0..300).map(|value| value as u8).collect();
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0x02,
            p2: 0x03,
            data: data.clone(),
            le: Some(256),
            extended: false,
        };
        let connector = ScriptedConnector::new(vec![hex("90 00"), hex("90 00")]);
        let response = test_session(0x01)
            .transmit_chained(&connector, &command)
            .unwrap();
        assert_eq!(response.status, RESPONSE_OK);

        let commands = connector.commands.into_inner();
        assert_eq!(commands.len(), 2);
        assert_eq!(&commands[0][..5], &[0x84, 0xe2, 0x82, 0x03, 0xff]);
        assert_eq!(&commands[1][..5], &[0x84, 0xe2, 0x02, 0x03, 0x35]);
        assert_eq!(commands[1].last(), Some(&0));

        let mut protected_data = commands[0][5..].to_vec();
        protected_data.extend_from_slice(&commands[1][5..commands[1].len() - 1]);
        assert_eq!(&protected_data[..data.len()], data);
        assert_eq!(
            &protected_data[data.len()..],
            &hex("6F CD 3B 5E DE 1D 71 78")
        );
    }

    #[test]
    fn encrypts_the_complete_command_before_chaining() {
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![0x5a; 300],
            le: None,
            extended: false,
        };
        let connector = ScriptedConnector::new(vec![hex("90 00"), hex("90 00")]);
        test_session(0x03)
            .transmit_chained(&connector, &command)
            .unwrap();

        let commands = connector.commands.into_inner();
        let mut protected_data = commands[0][5..].to_vec();
        protected_data.extend_from_slice(&commands[1][5..]);
        assert_eq!(protected_data.len(), 312);
        assert_eq!(
            &protected_data[..16],
            &hex("1E C7 81 53 83 11 08 31 66 3C CC E3 A5 DE 45 06")
        );
        assert_eq!(
            &protected_data[protected_data.len() - MAC_LENGTH..],
            &hex("EE CC BD 4C 2A 82 50 C9")
        );
    }

    #[test]
    fn chained_intermediate_responses_omit_rmac() {
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![0x5a; 300],
            le: None,
            extended: false,
        };
        let mut preview = test_session(0x11);
        preview.protect_command(&command).unwrap();
        let mut rmac_input = preview.mac_chaining_value.to_vec();
        rmac_input.extend_from_slice(&RESPONSE_OK.to_be_bytes());
        let rmac = aes_cmac(&preview.s_rmac, &rmac_input).unwrap();
        let mut final_response = rmac[..MAC_LENGTH].to_vec();
        final_response.extend_from_slice(&RESPONSE_OK.to_be_bytes());
        let connector = ScriptedConnector::new(vec![hex("90 00"), final_response]);

        let response = test_session(0x11)
            .transmit_chained(&connector, &command)
            .unwrap();
        assert_eq!(
            response,
            ResponseApdu {
                data: vec![],
                status: RESPONSE_OK,
            }
        );
    }

    #[test]
    fn collects_iso_response_chains() {
        let connector = ScriptedConnector::new(vec![hex("AA 61 02"), hex("BB CC 90 00")]);
        let response = test_session(0x01)
            .transmit(
                &connector,
                &CommandApdu {
                    cla: 0x80,
                    ins: 0xca,
                    p1: 0,
                    p2: 0,
                    data: vec![],
                    le: Some(256),
                    extended: false,
                },
            )
            .unwrap();
        assert_eq!(
            response,
            ResponseApdu {
                data: hex("AA BB CC"),
                status: RESPONSE_OK,
            }
        );
        let commands = connector.commands.into_inner();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[1], hex("00 C0 00 00 02"));
    }

    #[test]
    fn response_chain_requires_progress_after_initial_continuation() {
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xca,
            p1: 0,
            p2: 0,
            data: vec![],
            le: Some(256),
            extended: false,
        };

        let connector = ScriptedConnector::new(vec![hex("61 01"), hex("61 01")]);
        assert!(test_session(0x01).transmit(&connector, &command).is_err());
        assert_eq!(connector.commands.into_inner().len(), 2);

        let connector = ScriptedConnector::new(vec![hex("61 01"), hex("AA 90 00")]);
        assert_eq!(
            test_session(0x01)
                .transmit(&connector, &command)
                .unwrap()
                .data,
            hex("AA")
        );

        let connector =
            ScriptedConnector::new(vec![hex("AA 61 01"); MAX_RESPONSE_CHAIN_SEGMENTS + 1]);
        assert!(test_session(0x01).transmit(&connector, &command).is_err());
        assert_eq!(
            connector.commands.into_inner().len(),
            MAX_RESPONSE_CHAIN_SEGMENTS + 1
        );
    }

    #[test]
    fn response_chain_is_verified_and_decrypted_as_one_response() {
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xca,
            p1: 0,
            p2: 0,
            data: vec![],
            le: Some(256),
            extended: false,
        };
        let mut preview = test_session(0x33);
        preview.protect_command(&command).unwrap();
        let plaintext: Vec<u8> = (0..300).map(|value| value as u8).collect();
        let iv = preview.command_iv(true).unwrap();
        let ciphertext = aes_cbc(&preview.s_enc, &iv, &pad(&plaintext), Mode::Encrypt).unwrap();
        let mut rmac_input = preview.mac_chaining_value.to_vec();
        rmac_input.extend_from_slice(&ciphertext);
        rmac_input.extend_from_slice(&RESPONSE_OK.to_be_bytes());
        let rmac = aes_cmac(&preview.s_rmac, &rmac_input).unwrap();
        let mut protected_response = ciphertext;
        protected_response.extend_from_slice(&rmac[..MAC_LENGTH]);

        let mut first_response = protected_response[..256].to_vec();
        first_response.extend([0x61, 0x00]);
        let mut final_response = protected_response[256..].to_vec();
        final_response.extend_from_slice(&RESPONSE_OK.to_be_bytes());
        let connector = ScriptedConnector::new(vec![first_response, final_response]);

        let response = test_session(0x33).transmit(&connector, &command).unwrap();
        assert_eq!(
            response,
            ResponseApdu {
                data: plaintext,
                status: RESPONSE_OK,
            }
        );
        assert_eq!(connector.commands.into_inner()[1], hex("00 C0 00 00 00"));
    }

    #[test]
    fn chained_transfer_stops_on_invalid_intermediate_response() {
        let command = CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![0x5a; 300],
            le: None,
            extended: false,
        };
        for response in [hex("6A 80"), hex("01 90 00")] {
            let connector = ScriptedConnector::new(vec![response]);
            assert!(test_session(0x01)
                .transmit_chained(&connector, &command)
                .is_err());
            assert_eq!(connector.commands.into_inner().len(), 1);
        }
    }

    #[test]
    fn chained_transfer_rejects_ambiguous_header_inputs() {
        let connector = ScriptedConnector::new(vec![]);
        for (p1, le) in [(MORE_COMMANDS, None), (0, Some(65_536))] {
            let mut session = test_session(0x01);
            let result = session.transmit_chained(
                &connector,
                &CommandApdu {
                    cla: 0x80,
                    ins: 0xe2,
                    p1,
                    p2: 0,
                    data: vec![0; 300],
                    le,
                    extended: false,
                },
            );
            assert!(result.is_err());
            assert_eq!(session.encryption_counter, 0);
        }
    }

    #[test]
    fn error_responses_do_not_require_rmac() {
        let connector = ScriptedConnector::new(vec![hex("6A 80")]);
        let response = test_session(0x11)
            .transmit(
                &connector,
                &CommandApdu {
                    cla: 0x80,
                    ins: 0xe2,
                    p1: 0,
                    p2: 0,
                    data: vec![1],
                    le: None,
                    extended: false,
                },
            )
            .unwrap();
        assert_eq!(response.status, 0x6a80);
        assert!(response.data.is_empty());
    }

    #[test]
    fn yubikey_sessions_share_and_require_the_authenticated_channel() {
        let connector = std::rc::Rc::new(ScriptedConnector::new(vec![hex("90 00")]));
        let shared = std::rc::Rc::new(RefCell::new(Some(test_session(0x01))));
        let session = crate::YubiKeySession {
            slotID: 1,
            flags: 0,
            connector: connector.clone(),
            session: shared.clone(),
        };
        let response = session
            .send_apdu(
                &CommandApdu {
                    cla: 0x80,
                    ins: 0xca,
                    p1: 0,
                    p2: 0,
                    data: Vec::new(),
                    le: Some(256),
                    extended: false,
                },
                false,
            )
            .unwrap();
        assert_eq!(response.status, RESPONSE_OK);
        assert_eq!(connector.commands.borrow().len(), 1);
        assert_eq!(connector.commands.borrow()[0][0], 0x84);
        assert_eq!(shared.borrow().as_ref().unwrap().encryption_counter, 1);

        *shared.borrow_mut() = None;
        assert!(session
            .send_apdu(
                &CommandApdu {
                    cla: 0,
                    ins: 0x84,
                    p1: 0,
                    p2: 0,
                    data: Vec::new(),
                    le: Some(8),
                    extended: false,
                },
                false,
            )
            .is_err());
        assert_eq!(connector.commands.borrow().len(), 1);
    }

    #[test]
    fn yubikey_sessions_discard_desynchronized_channels() {
        let connector = std::rc::Rc::new(ScriptedConnector::new(vec![]));
        let shared = std::rc::Rc::new(RefCell::new(Some(test_session(0x01))));
        let session = crate::YubiKeySession {
            slotID: 1,
            flags: 0,
            connector,
            session: shared.clone(),
        };
        assert!(session
            .send_apdu(
                &CommandApdu {
                    cla: 0,
                    ins: 0x84,
                    p1: 0,
                    p2: 0,
                    data: Vec::new(),
                    le: Some(8),
                    extended: false,
                },
                false,
            )
            .is_err());
        assert!(shared.borrow().is_none());
    }

    #[test]
    fn authenticates_with_yubico_diversified_transport_keys() {
        let keys = Scp03KeySet {
            key_version: 7,
            key_id: 0,
            enc: Zeroizing::new(Vec::new()),
            mac: Zeroizing::new(Vec::new()),
            dek: None,
            diversification_bmk: Some(Zeroizing::new(hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ))),
        };
        keys.validate().unwrap();
        let issuer_context: [u8; 10] = hex("00010203040506070809").try_into().unwrap();
        let resolved = keys.resolve(&issuer_context).unwrap();
        let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
        let card = hex("1112131415161718");
        let mut session_context = host.to_vec();
        session_context.extend_from_slice(&card);
        let s_mac = derive(&resolved.mac, DERIVATION_S_MAC, &session_context, 128).unwrap();
        let card_cryptogram =
            derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &session_context, 64).unwrap();
        let mut initialize_response = issuer_context.to_vec();
        initialize_response.extend([7, 3, 0x60]);
        initialize_response.extend_from_slice(&card);
        initialize_response.extend_from_slice(&card_cryptogram);
        initialize_response.extend([0x90, 0x00]);
        let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

        Scp03Session::establish_with_challenge(
            &connector,
            &keys,
            YUBIKEY_SECURITY_LEVEL,
            host,
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID,
        )
        .unwrap();
        let commands = connector.commands.into_inner();
        assert_eq!(&commands[0][..5], &hex("80 50 07 00 08"));
        assert_eq!(&commands[1][..5], &hex("84 82 33 00 10"));
    }

    #[test]
    fn matches_kaoh_globalplatform_scp03_authentication_vector() {
        // Published by the GlobalPlatform open-source implementation:
        // https://github.com/kaoh/globalplatform/blob/master/globalplatform/src/scp03Test.c
        let keys = Scp03KeySet::new(
            0,
            0,
            hex("F995D0A069335C7DF42E590317FFEA6D"),
            hex("58563362EC5A4541ABCD32B34B1EAE7D"),
            hex("0A02A6D687406DCFA09DC70B3EDB7E38"),
        )
        .unwrap();
        let host: [u8; 8] = hex("9BD6BF878FB8E991").try_into().unwrap();
        let connector = ScriptedConnector::new(vec![
            hex("00000000000000000000 300370 3C80C2CC87EB3A35 \
                 E4EDBA35E629C336 00001E 9000"),
            hex("9000"),
        ]);

        let session = Scp03Session::establish_with_challenge(
            &connector,
            &keys,
            0x03,
            host,
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID,
        )
        .unwrap();

        assert_eq!(
            session.s_enc.as_slice(),
            hex("D83EE38C9954C8078987A5E9EE6AB13C")
        );
        assert_eq!(
            session.s_mac.as_slice(),
            hex("6FF37716E0413065E8DFD08BF1E9EC5E")
        );
        assert_eq!(
            session.s_rmac.as_slice(),
            hex("0254C786E57ACA8982670C1C1A05FF12")
        );
        assert_eq!(
            connector.commands.into_inner(),
            vec![
                hex("8050000008 9BD6BF878FB8E991 00"),
                hex("8482030010 23EBFEDC579D22CD CDB6A25A5FF7891F"),
            ]
        );
    }

    #[test]
    fn matches_samsung_openscp_s8_exchange_vectors() {
        // Samsung OpenSCP publishes complete S8 exchanges for all AES key sizes:
        // https://github.com/Samsung/OpenSCP-Java/tree/main/src/test/java/com/samsung/openscp/testdata
        struct Vector<'a> {
            enc: &'a str,
            mac: &'a str,
            dek: &'a str,
            initialize_response: &'a str,
            external_authenticate: &'a str,
            protected_commands: [&'a str; 3],
            protected_responses: [&'a str; 3],
        }

        let vectors = [
            Vector {
                enc: "1D72CD9283FD55162722C6BEAA4DC187",
                mac: "F4932BA02FFC3098D172790099D28382",
                dek: "B4BDC610C3F6793708FF1132E2C5BF60",
                initialize_response: concat!(
                    "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                    "DC2DBE8974C8B0DE 00082A 9000"
                ),
                external_authenticate: "8482330010 B08D6CE26B6CB3CC B411CF0296EB7B1D",
                protected_commands: [
                    "84F2200018 5230BA64388B4A40E0B4DA5CC1DF51C2 85E4020D99D5AED1",
                    "84F2400018 1819D47B42BBE6B9449BBC2BD43A090D AC1F2F0A52D9F34B",
                    "84F2800018 09F07C3DF47956B1052951FA28211BA7 BABC05C321D9B3BF",
                ],
                protected_responses: [
                    concat!(
                        "BD3292BFB1A23C4478E37292BA1EDF43",
                        "8770CE472FB7611FBDBD1C981A27FA47",
                        "80A81A95D93C05F9C4C94839DED0363C",
                        "FEA57CE2ECFB572B26F3474DAEEBBABC",
                        "202942381F9755F5 9000"
                    ),
                    concat!(
                        "BB82442BB5CC8C839620615D1F163D3D",
                        "DBC9357D68EF4BAD997CFBB79A24C224",
                        "A89488C44B25C3B23D489E4E58A309D4",
                        "38FDD6E453D0E07216541FB142B977A3",
                        "A7D4C4048BBE2BA068F04A0A4A9C50B",
                        "AD232F8CA8EA1F40E 9000"
                    ),
                    concat!(
                        "31EB08363026463BAD10AF29F24301F1",
                        "D9B8532067F9313D97FDA39BBE6B6099",
                        "BEFD623E1F79FB5D 9000"
                    ),
                ],
            },
            Vector {
                enc: "1D72CD9283FD55162722C6BEAA4DC1877F4C0CD0ECC15E05",
                mac: "F4932BA02FFC3098D172790099D2838236F2E61068D56F44",
                dek: "B4BDC610C3F6793708FF1132E2C5BF60523AEAC06B32F204",
                initialize_response: concat!(
                    "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                    "6E7C64F962A822A4 00082A 9000"
                ),
                external_authenticate: "8482330010 63B6CEFAC0EC0983 33860788C65220BA",
                protected_commands: [
                    "84F2200018 D9EDCBCB7F69CB1EF0508E6EDE933A6D 80091E7D99CB3E51",
                    "84F2400018 CDC4B0480CF151C1132655133115A8CA 1A89964F2554551C",
                    "84F2800018 96800333FA638A32DBCCBF4C7E52FBD5 DA469A954E1D58F6",
                ],
                protected_responses: [
                    concat!(
                        "99077B167D43A4F313B59B63CC23EFD3",
                        "B5158BDEF8F24D85E250570A4AAB8186",
                        "9A92307350267F0FBC2278FA3D34D2FD",
                        "5D2B4E8C0362C01D082C76A17B80AEA4",
                        "BA5FB9D7DA3BB368 9000"
                    ),
                    concat!(
                        "AB7A97B6C673DF3D95378D06B7B42E25",
                        "D7C3B22D6D1A42299FFED17F5973950E",
                        "C68C77700FC01947067470178A1D0615",
                        "2ED648E95E8C3510B61CF0036DFD8C9F",
                        "6FA167D32FDEB3F81A0E6B2BB35BCD4C",
                        "D104692D131D7776 9000"
                    ),
                    concat!(
                        "E5E5761FEFF5C0C078ADBC4E77B72900",
                        "94C99183AC73CAB99A7412D0194DEFFD",
                        "D0895DCCE662D945 9000"
                    ),
                ],
            },
            Vector {
                enc: concat!(
                    "1D72CD9283FD55162722C6BEAA4DC187",
                    "7F4C0CD0ECC15E052AAC39A99AF9AD72"
                ),
                mac: concat!(
                    "F4932BA02FFC3098D172790099D28382",
                    "36F2E61068D56F4401CC0374C25AF8CB"
                ),
                dek: concat!(
                    "B4BDC610C3F6793708FF1132E2C5BF60",
                    "523AEAC06B32F204B851B6CC007C8D3C"
                ),
                initialize_response: concat!(
                    "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                    "8AFA7267CB63740E 00082A 9000"
                ),
                external_authenticate: "8482330010 50E003735F922282 69A094FFC07429FD",
                protected_commands: [
                    "84F2200018 BD57D1382AE8F66F7EB5F5991B92D139 9044157C7DFD2761",
                    "84F2400018 45D2B475C3EFF8BBB254D0B6A8E6CA97 CF5265D907A76070",
                    "84F2800018 7083CA3ADA0F76CF7B3FFAC60ABE1359 9D521EE7B9224C49",
                ],
                protected_responses: [
                    concat!(
                        "47D81041004B7E9208E3BEF1372E7CDE",
                        "8CD995AEF207F138C80D45156F2D36F2",
                        "B15BDC9C4D6FDB9774344495CCC83AE7",
                        "BA0B39C734BF9CEBD07204AA5A67DF2D",
                        "7E663D55FC4944C0 9000"
                    ),
                    concat!(
                        "59E8DCFDC22D436336552128F790E1B3",
                        "83D6942ED4025F30FE8D95541E634E23",
                        "8BFD963D88DF822D8EBCC1272A9D56C7",
                        "D1CBC306039647FC4977EFF562C0B8C0",
                        "1314B1C8B2D168A581A98C65B676B3EE",
                        "4032E91A9C0858EC 9000"
                    ),
                    concat!("E58CB33A46F76909ADDDFF0C2821F4F2", "5F22B5553C534DC6 9000"),
                ],
            },
        ];
        let host: [u8; 8] = hex("06F85B77251BF794").try_into().unwrap();
        let plain_responses = [
            concat!(
                "08A00000015141434C010010A00000022020030101010000000000060100",
                "10A0000002202003010101000000000011010005A0000002480100"
            ),
            concat!(
                "0AA9A8A7A6A5A4A3A2A1A00F800AA0A1A2A3A4A5A6A7A8A9070009",
                "A00000015141434C00070010A00000022020030103010000000000110700",
                "07A00000024804000700"
            ),
            "08A0000001510000000F9E",
        ];

        for vector in vectors {
            // These traces reuse one externally supplied card challenge for all key sizes even
            // though i=70 marks it as pseudo-random. The kaoh vector above covers verification
            // of a key-derived challenge; these vectors start at card-cryptogram verification.
            let mut responses = vec![hex("9000")];
            responses.extend(vector.protected_responses.map(hex));
            let connector = ScriptedConnector::new(responses);
            let keys = Scp03KeySet::new(0x30, 0, hex(vector.enc), hex(vector.mac), hex(vector.dek))
                .unwrap();
            let initialize_response =
                ResponseApdu::parse(&hex(vector.initialize_response)).unwrap();
            let update = InitializeUpdate::parse(&initialize_response.data).unwrap();
            let static_keys = keys.resolve(&update.issuer_context).unwrap();
            let (mut session, host_cryptogram) = Scp03Session::from_initialize_update(
                &static_keys,
                0x33,
                host,
                &update,
                &initialize_response.data[21..29],
            )
            .unwrap();
            assert_eq!(session.s_enc.len(), keys.enc.len());
            assert_eq!(session.s_mac.len(), keys.mac.len());
            assert_eq!(session.s_rmac.len(), keys.mac.len());
            let authenticate = session.external_authenticate(&host_cryptogram).unwrap();
            transmit(&connector, &authenticate)
                .unwrap()
                .require_success()
                .unwrap();

            for (p1, expected) in [0x20, 0x40, 0x80].into_iter().zip(plain_responses) {
                let response = session
                    .transmit(
                        &connector,
                        &CommandApdu {
                            cla: 0x80,
                            ins: 0xf2,
                            p1,
                            p2: 0,
                            data: hex("4F00"),
                            le: None,
                            extended: false,
                        },
                    )
                    .unwrap();
                assert_eq!(
                    response,
                    ResponseApdu {
                        data: hex(expected),
                        status: RESPONSE_OK
                    }
                );
            }

            let mut expected_commands = vec![hex(vector.external_authenticate)];
            expected_commands.extend(vector.protected_commands.map(hex));
            assert_eq!(connector.commands.into_inner(), expected_commands);
        }
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

        Scp03Session::establish_with_challenge(
            &connector,
            &keys,
            0x03,
            host,
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID,
        )
        .unwrap();
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
        challenge_context.extend_from_slice(&YUBIKEY_ISSUER_SECURITY_DOMAIN_AID);
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

        Scp03Session::establish_with_challenge(
            &connector,
            &keys,
            0x03,
            host,
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID,
        )
        .unwrap();
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
