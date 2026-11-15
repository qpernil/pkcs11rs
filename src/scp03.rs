use crate::{
    CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_ENCRYPTED_DATA_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_PIN_INCORRECT, CKR_RANDOM_NO_RNG, Connector,
    error::Error,
    scp_key_provider::{CardDek, Scp03Keys},
    secure_channel_crypto::{
        AES_BLOCK_SIZE, Direction, aes_cbc, aes_cmac, aes_encrypt_block as aes_block,
        pad_iso7816 as pad, scp03_kdf as derive, unpad_iso7816 as unpad,
    },
};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const DEFAULT_ISSUER_SECURITY_DOMAIN_AID: [u8; 8] =
    [0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
pub(crate) const YUBIKEY_FACTORY_KEY_VERSION: u8 = 0xff;
pub(crate) const YUBIKEY_FACTORY_KEY_ID: u8 = 0x00;
pub(crate) const YUBIKEY_FACTORY_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
#[cfg(test)]
pub(crate) const YUBIKEY_SECURITY_LEVEL: u8 = 0x33;

const MAC_LENGTH: usize = 8;
const MAX_EXTENDED_DATA_LENGTH: usize = u16::MAX as usize;
#[cfg(test)]
const MAX_SHORT_EXPECTED_LENGTH: u32 = 1 << 8;
#[cfg(test)]
const MAX_EXTENDED_EXPECTED_LENGTH: u32 = 1 << 16;
#[cfg(test)]
const MAX_RESPONSE_CHAIN_SEGMENTS: usize =
    MAX_EXTENDED_EXPECTED_LENGTH as usize / MAX_SHORT_EXPECTED_LENGTH as usize;
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
#[cfg(test)]
const YUBICO_DIVERSIFICATION_ENC_LABEL: [u8; 4] = [0, 0, 0, 1];
#[cfg(test)]
const YUBICO_DIVERSIFICATION_MAC_LABEL: [u8; 4] = [0, 0, 0, 2];
#[cfg(test)]
const YUBICO_DIVERSIFICATION_DEK_LABEL: [u8; 4] = [0, 0, 0, 3];
#[cfg(test)]
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
    pub(crate) fn as_shared(&self) -> yubikey_apdu::CommandApdu<'_> {
        yubikey_apdu::CommandApdu {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            data: &self.data,
            le: self.le,
            extended: self.extended,
        }
    }

    pub(crate) fn from_spec(
        spec: &yubikey_apdu::ApduSpec,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
        le: Option<u32>,
    ) -> Result<Self, Error> {
        spec.command(p1, p2, &data, le)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        Ok(Self {
            cla: spec.cla,
            ins: spec.ins,
            p1,
            p2,
            data,
            le,
            extended: false,
        })
    }

    pub(crate) fn spec<'a>(
        &self,
        specs: &'a [yubikey_apdu::ApduSpec],
    ) -> Result<&'a yubikey_apdu::ApduSpec, Error> {
        yubikey_apdu::find(specs, &self.as_shared()).map_err(|_| CKR_ARGUMENTS_BAD.into())
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, Error> {
        let command = yubikey_apdu::CommandApdu::decode(encoded)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        Ok(Self {
            cla: command.cla,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data: command.data.to_vec(),
            le: command.le,
            extended: command.extended,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        self.as_shared()
            .encode()
            .map_err(|_| CKR_DATA_LEN_RANGE.into())
    }

    fn encode_header_and_data(&self, encoded_data_len: usize) -> Result<Vec<u8>, Error> {
        self.as_shared()
            .encode_header_and_data(encoded_data_len)
            .map_err(|_| CKR_DATA_LEN_RANGE.into())
    }

    fn uses_extended_length(&self, data_len: usize) -> Result<bool, Error> {
        self.as_shared()
            .uses_extended_length(data_len)
            .map_err(|_| CKR_DATA_LEN_RANGE.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponseApdu {
    pub(crate) data: Vec<u8>,
    pub(crate) status: u16,
}

impl ResponseApdu {
    pub(crate) fn encode(&self) -> Vec<u8> {
        yubikey_apdu::ResponseApdu {
            data: &self.data,
            status: self.status,
        }
        .encode()
    }

    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, Error> {
        let response = yubikey_apdu::ResponseApdu::decode(encoded)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        Ok(Self {
            data: response.data.to_vec(),
            status: response.status,
        })
    }

    pub(crate) fn validate_spec(
        &self,
        spec: &yubikey_apdu::ApduSpec,
    ) -> Result<(), yubikey_apdu::SpecError> {
        spec.validate_response(&yubikey_apdu::ResponseApdu {
            data: &self.data,
            status: self.status,
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
    pub(crate) fn yubikey_factory() -> Self {
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

    pub(crate) fn from_configuration(
        configuration: &crate::configuration::Scp03Configuration,
    ) -> Result<Self, Error> {
        let (enc, mac, dek, diversification_bmk) = match &configuration.key_material {
            crate::Scp03KeyMaterialConfiguration::Factory => {
                let defaults = Self::yubikey_factory();
                (defaults.enc, defaults.mac, defaults.dek, None)
            }
            crate::Scp03KeyMaterialConfiguration::Direct { enc, mac, dek } => (
                Zeroizing::new(enc.to_vec()),
                Zeroizing::new(mac.to_vec()),
                dek.as_deref().map(|key| Zeroizing::new(key.to_vec())),
                None,
            ),
            crate::Scp03KeyMaterialConfiguration::YubicoBatchMasterKey(bmk) => (
                Zeroizing::new(Vec::new()),
                Zeroizing::new(Vec::new()),
                None,
                Some(Zeroizing::new(bmk.to_vec())),
            ),
        };
        let keys = Self {
            key_version: configuration.key_version,
            key_id: configuration.key_id,
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

    fn resolve(&self, issuer_context: &[u8; 10]) -> Result<Scp03Keys, Error> {
        if let Some(bmk) = self.diversification_bmk.as_deref() {
            Scp03Keys::diversify(bmk, issuer_context)
        } else {
            Scp03Keys::import(&self.enc, &self.mac, self.dek.as_deref().map(Vec::as_slice))
        }
    }
}

fn valid_aes_key(key: &[u8]) -> bool {
    matches!(key.len(), 16 | 24 | 32)
}

#[cfg(test)]
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

pub(crate) fn parse_hex(value: &str) -> Result<Vec<u8>, Error> {
    let compact = Zeroizing::new(
        value
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != ':')
            .collect::<String>(),
    );
    if !crate::is_multiple_of(compact.len(), 2)
        || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
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
    static_dek: Option<CardDek>,
    oce_authenticated: bool,
    mac_chaining_value: [u8; AES_BLOCK_SIZE],
    encryption_counter: u128,
    security_level: u8,
}

impl std::fmt::Debug for Scp03Session {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Scp03Session")
            .field("key_size", &self.s_enc.len())
            .field("has_static_dek", &self.static_dek.is_some())
            .field("oce_authenticated", &self.oce_authenticated)
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
        static_dek: Option<Vec<u8>>,
        oce_authenticated: bool,
        mac_chaining_value: [u8; AES_BLOCK_SIZE],
        security_level: u8,
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        if !valid_aes_key(&s_enc)
            || s_enc.len() != s_mac.len()
            || s_enc.len() != s_rmac.len()
            || static_dek.as_deref().is_some_and(|key| !valid_aes_key(key))
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Self {
            s_enc: Zeroizing::new(s_enc),
            s_mac: Zeroizing::new(s_mac),
            s_rmac: Zeroizing::new(s_rmac),
            static_dek: static_dek.map(|value| CardDek::Session(Zeroizing::new(value))),
            oce_authenticated,
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
        getrandom::fill(&mut host_challenge).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
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
        Self::establish_using(
            connector,
            keys.key_version,
            keys.key_id,
            security_level,
            host_challenge,
            selected_aid,
            |context| keys.resolve(context),
        )
    }

    pub(crate) fn authenticate_provider(
        connector: &dyn Connector,
        configuration: &crate::configuration::Scp03Configuration,
        credential: &crate::ccid_auth::CardCredential,
        selected_aid: &[u8],
    ) -> Result<Self, Error> {
        let mut challenge = [0; 8];
        getrandom::fill(&mut challenge).map_err(|_| CKR_RANDOM_NO_RNG)?;
        Self::establish_using(
            connector,
            configuration.key_version,
            configuration.key_id,
            configuration.security_level,
            challenge,
            selected_aid,
            |_| credential.scp03_keys(),
        )
    }

    fn establish_using(
        connector: &dyn Connector,
        key_version: u8,
        key_id: u8,
        security_level: u8,
        host_challenge: [u8; 8],
        selected_aid: &[u8],
        resolve: impl FnOnce(&[u8; 10]) -> Result<Scp03Keys, Error>,
    ) -> Result<Self, Error> {
        validate_security_level(security_level)?;
        let initialize = CommandApdu::from_spec(
            &yubikey_apdu::scp::INITIALIZE_UPDATE,
            key_version,
            key_id,
            host_challenge.to_vec(),
            Some(256),
        )?;
        let initialize_response = transmit(connector, &initialize)?.require_success(&initialize)?;
        let update = InitializeUpdate::parse(&initialize_response.data)?;
        if update.scp_id != 0x03 || (key_version != 0 && update.key_version != key_version) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        validate_card_capabilities(update.implementation, security_level)?;
        let mut static_keys = resolve(&update.issuer_context)?;
        if let Some(sequence_counter) = update.sequence_counter {
            let mut challenge_context = Vec::with_capacity(3 + selected_aid.len());
            challenge_context.extend_from_slice(&sequence_counter);
            challenge_context.extend_from_slice(selected_aid);
            let expected_challenge =
                static_keys.derive(true, DERIVATION_CARD_CHALLENGE, &challenge_context, 8)?;
            if !bool::from(expected_challenge.ct_eq(&update.card_challenge)) {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }

        let (mut session, host_cryptogram) = Self::from_initialize_update(
            &mut static_keys,
            security_level,
            host_challenge,
            &update,
            &initialize_response.data[21..29],
        )?;
        session.static_dek = static_keys.take_dek()?;
        session.oce_authenticated = true;
        let authenticate = session.external_authenticate(&host_cryptogram)?;
        transmit(connector, &authenticate)?.require_success(&authenticate)?;
        Ok(session)
    }

    pub(crate) fn static_dek(&self) -> Result<&CardDek, Error> {
        self.static_dek
            .as_ref()
            .ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED.into())
    }

    pub(crate) fn require_oce_authentication(&self) -> Result<(), Error> {
        if self.oce_authenticated {
            Ok(())
        } else {
            Err(crate::CKR_USER_NOT_LOGGED_IN.into())
        }
    }

    fn from_initialize_update(
        static_keys: &mut Scp03Keys,
        security_level: u8,
        host_challenge: [u8; 8],
        update: &InitializeUpdate,
        card_cryptogram: &[u8],
    ) -> Result<(Self, Vec<u8>), Error> {
        validate_security_level(security_level)?;
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&host_challenge);
        context[8..].copy_from_slice(&update.card_challenge);
        let enc_length = static_keys.scope.aes_length(&static_keys.enc)?;
        let mac_length = static_keys.scope.aes_length(&static_keys.mac)?;
        let s_enc = static_keys.derive(true, DERIVATION_S_ENC, &context, enc_length)?;
        let s_mac = static_keys.derive(false, DERIVATION_S_MAC, &context, mac_length)?;
        let s_rmac = static_keys.derive(false, DERIVATION_S_RMAC, &context, mac_length)?;
        let expected_card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &context, 64)?;
        if !bool::from(expected_card_cryptogram.ct_eq(card_cryptogram)) {
            return Err(CKR_PIN_INCORRECT.into());
        }
        let host_cryptogram = derive(&s_mac, DERIVATION_HOST_CRYPTOGRAM, &context, 64)?;

        Ok((
            Self {
                s_enc,
                s_mac,
                s_rmac,
                static_dek: None,
                oce_authenticated: true,
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
        CommandApdu::from_spec(
            &yubikey_apdu::scp::EXTERNAL_AUTHENTICATE,
            self.security_level,
            0,
            data,
            None,
        )
    }

    pub(crate) fn transmit(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        self.transmit_with_protected_status(connector, command, None)
    }

    pub(crate) fn transmit_with_protected_status(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
        protected_status: Option<u16>,
    ) -> Result<ResponseApdu, Error> {
        let protected = self.protect_command(command)?;
        let response = crate::iso7816::transmit(connector, &protected)?;
        self.unprotect_response_with_status(response, protected_status)
    }

    pub(crate) fn transmit_oath(
        &mut self,
        connector: &dyn Connector,
        command: &CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        let spec = command.spec(yubikey_apdu::oath::COMMANDS)?;
        let protected = self.protect_command(command)?;
        let response = crate::iso7816::transmit_with_continuation(
            connector,
            &protected,
            spec.response_continuation,
        )?;
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
            data = aes_cbc(&self.s_enc, &iv, &padded, Direction::Encrypt)?;
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
        self.unprotect_response_with_status(response, None)
    }

    fn unprotect_response_with_status(
        &self,
        response: ResponseApdu,
        protected_status: Option<u16>,
    ) -> Result<ResponseApdu, Error> {
        if response.status != RESPONSE_OK
            && Some(response.status) != protected_status
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
            if !bool::from(expected_mac[..MAC_LENGTH].ct_eq(&received_mac)) {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
        }
        if self.security_level & SECURITY_R_ENCRYPTION != 0 && !data.is_empty() {
            if !crate::is_multiple_of(data.len(), AES_BLOCK_SIZE) {
                return Err(CKR_ENCRYPTED_DATA_INVALID.into());
            }
            let iv = self.command_iv(true)?;
            data = unpad(aes_cbc(&self.s_enc, &iv, &data, Direction::Decrypt)?)?;
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
    connector.select_application(aid).map(|_| ())
}

pub(crate) fn select_application_response<C: Connector + ?Sized>(
    connector: &C,
    aid: &[u8],
) -> Result<ResponseApdu, Error> {
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let select = CommandApdu::from_spec(
        &yubikey_apdu::iso7816::SELECT,
        4,
        0,
        aid.to_vec(),
        Some(256),
    )?;
    connector.send_apdu(&select)?.require_success(&select)
}

pub(crate) fn transmit<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
) -> Result<ResponseApdu, Error> {
    let encoded = Zeroizing::new(command.encode()?);
    ResponseApdu::parse(&connector.send(&encoded, DEFAULT_TIMEOUT)?)
}

pub(crate) fn validate_security_level(security_level: u8) -> Result<(), Error> {
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

#[cfg(test)]
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
