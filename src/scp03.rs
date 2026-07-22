use crate::{
    error::Error,
    secure_channel_crypto::{
        aes_cbc, aes_cmac, aes_encrypt_block as aes_block, pad_iso7816 as pad, scp03_kdf as derive,
        unpad_iso7816 as unpad, AES_BLOCK_SIZE,
    },
    Connector, CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_ENCRYPTED_DATA_INVALID,
    CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG, CKR_USER_PIN_NOT_INITIALIZED,
};
use openssl::{memcmp, symm::Mode};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const DEFAULT_ISSUER_SECURITY_DOMAIN_AID: [u8; 8] =
    [0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
pub(crate) const YUBIKEY_FACTORY_KEY_VERSION: u8 = 0xff;
pub(crate) const YUBIKEY_FACTORY_KEY_ID: u8 = 0x00;
pub(crate) const YUBIKEY_FACTORY_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
pub(crate) const YUBIKEY_SECURITY_LEVEL: u8 = 0x33;

const MAC_LENGTH: usize = 8;
const MAX_SHORT_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_EXTENDED_DATA_LENGTH: usize = u16::MAX as usize;
const MAX_SHORT_EXPECTED_LENGTH: u32 = 1 << 8;
const MAX_EXTENDED_EXPECTED_LENGTH: u32 = 1 << 16;
#[cfg(test)]
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
    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() < 4 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let cla = encoded[0];
        let ins = encoded[1];
        let p1 = encoded[2];
        let p2 = encoded[3];
        let body = &encoded[4..];
        if body.is_empty() {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
                extended: false,
            });
        }
        if body.len() == 1 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(if body[0] == 0 { 256 } else { body[0] as u32 }),
                extended: false,
            });
        }
        if body[0] != 0 {
            let data_len = body[0] as usize;
            if body.len() == data_len + 1 {
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: body[1..].to_vec(),
                    le: None,
                    extended: false,
                });
            }
            if body.len() == data_len + 2 {
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: body[1..1 + data_len].to_vec(),
                    le: Some(if body[1 + data_len] == 0 {
                        256
                    } else {
                        body[1 + data_len] as u32
                    }),
                    extended: false,
                });
            }
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if body.len() == 3 {
            let le = u16::from_be_bytes([body[1], body[2]]) as u32;
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(if le == 0 { 65_536 } else { le }),
                extended: true,
            });
        }
        if body.len() < 3 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let data_len = u16::from_be_bytes([body[1], body[2]]) as usize;
        if body.len() == data_len + 3 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: body[3..].to_vec(),
                le: None,
                extended: true,
            });
        }
        if body.len() == data_len + 5 {
            let le_offset = 3 + data_len;
            let le = u16::from_be_bytes([body[le_offset], body[le_offset + 1]]) as u32;
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: body[3..le_offset].to_vec(),
                le: Some(if le == 0 { 65_536 } else { le }),
                extended: true,
            });
        }
        Err(CKR_ARGUMENTS_BAD.into())
    }

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
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut encoded = self.data.clone();
        encoded.extend_from_slice(&self.status.to_be_bytes());
        encoded
    }

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

    pub(crate) fn require_success(self, command: &CommandApdu) -> Result<Self, Error> {
        if self.status != RESPONSE_OK {
            log!(
                1,
                "APDU command {:02x}{:02x}{:02x}{:02x} failed with status {:04x} ({} data bytes, Le {:?}, extended {})",
                command.cla,
                command.ins,
                command.p1,
                command.p2,
                self.status,
                command.data.len(),
                command.le,
                command.extended
            );
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
        let initialize_response = transmit(connector, &initialize)?.require_success(&initialize)?;
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
        transmit(connector, &authenticate)?.require_success(&authenticate)?;
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
        let response = crate::iso7816::transmit(connector, &protected)?;
        self.unprotect_response(response)
    }

    pub(crate) fn transmit_short(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        let protected = self.protect_command(command)?;
        let response = crate::iso7816::transmit_short(connector, &protected)?;
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

    pub(crate) fn collect_response_chain(
        connector: &dyn Connector,
        response: ResponseApdu,
    ) -> Result<ResponseApdu, Error> {
        crate::iso7816::collect_response_chain(connector, response)
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
    transmit(connector, &select)?.require_success(&select)?;
    Ok(())
}

pub(crate) fn transmit<C: Connector + ?Sized>(
    connector: &C,
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

#[cfg(test)]
mod tests;
