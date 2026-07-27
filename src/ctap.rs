use crate::{
    is_multiple_of,
    secure_channel_crypto::{aes_cbc, Direction, AES_BLOCK_SIZE},
    Error, CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED, CKR_PIN_INCORRECT, CKR_PIN_INVALID,
    CKR_PIN_LOCKED, CKR_USER_PIN_NOT_INITIALIZED,
};
use hmac::{Hmac, Mac};
use minicbor::{data::Type, Decoder, Encoder};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::rc::Rc;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const AUTHENTICATOR_GET_INFO: u8 = 0x04;
pub(crate) const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
pub(crate) const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
pub(crate) const AUTHENTICATOR_CREDENTIAL_MANAGEMENT_PREVIEW: u8 = 0x41;
pub(crate) const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
#[cfg(test)]
pub(crate) const FIDO2_TEST_RP_ID: &str = "pkcs11rs.invalid";
#[cfg(test)]
pub(crate) const FIDO2_TEST_USER_DISPLAY_NAME: &str = "pkcs11rs synthetic user";

#[cfg(all(test, not(feature = "abi-tests")))]
const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const PIN_UV_AUTH_PROTOCOL_TWO: u8 = 2;
#[cfg(test)]
const PERMISSION_MAKE_CREDENTIAL: u8 = 0x01;
const PERMISSION_CREDENTIAL_MANAGEMENT: u8 = 0x04;
const PERMISSION_PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY: u8 = 0x40;
const MAX_CTAP_COLLECTION_LENGTH: usize = 4096;

#[derive(Debug)]
pub(crate) enum CtapError {
    Transport(Error),
    Status(u8),
    Malformed(&'static str),
}

impl CtapError {
    pub(crate) fn into_pkcs11(self) -> Error {
        match self {
            Self::Transport(error) => error,
            Self::Status(CTAP2_ERR_PIN_INVALID) => CKR_PIN_INCORRECT.into(),
            Self::Status(CTAP2_ERR_PIN_AUTH_INVALID | CTAP2_ERR_PIN_POLICY_VIOLATION) => {
                CKR_PIN_INVALID.into()
            }
            Self::Status(CTAP2_ERR_PIN_BLOCKED | CTAP2_ERR_PIN_AUTH_BLOCKED) => {
                CKR_PIN_LOCKED.into()
            }
            Self::Status(CTAP2_ERR_PIN_NOT_SET) => CKR_USER_PIN_NOT_INITIALIZED.into(),
            Self::Status(status) => {
                log!(1, "CTAP command failed with status {status:#04x}");
                CKR_DEVICE_ERROR.into()
            }
            Self::Malformed(reason) => {
                log!(1, "CTAP response is malformed: {reason}");
                CKR_DEVICE_ERROR.into()
            }
        }
    }
}

impl From<Error> for CtapError {
    fn from(error: Error) -> Self {
        Self::Transport(error)
    }
}

impl From<minicbor::decode::Error> for CtapError {
    fn from(_error: minicbor::decode::Error) -> Self {
        Self::Malformed("invalid CBOR")
    }
}

impl From<minicbor::encode::Error<std::convert::Infallible>> for CtapError {
    fn from(_error: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        Self::Malformed("CBOR encoding failed")
    }
}

pub(crate) trait CtapTransport {
    /// Exchange one CTAP message, including its command/status byte.
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatorInfo {
    pub(crate) versions: Vec<String>,
    pub(crate) extensions: Vec<String>,
    pub(crate) aaguid: [u8; 16],
    pub(crate) options: Vec<(String, bool)>,
    pub(crate) max_msg_size: Option<u64>,
    pub(crate) pin_uv_auth_protocols: Vec<u64>,
    pub(crate) transports: Vec<String>,
    pub(crate) min_pin_length: Option<u64>,
}

impl AuthenticatorInfo {
    pub(crate) fn option(&self, name: &str) -> bool {
        self.options
            .iter()
            .any(|(candidate, enabled)| candidate == name && *enabled)
    }

    fn credential_management_command(&self) -> Option<u8> {
        if self.option("credMgmt") {
            Some(AUTHENTICATOR_CREDENTIAL_MANAGEMENT)
        } else if self.option("credentialMgmtPreview") {
            Some(AUTHENTICATOR_CREDENTIAL_MANAGEMENT_PREVIEW)
        } else {
            None
        }
    }

    pub(crate) fn primary_version(&self) -> Option<&str> {
        let version_rank = |version: &String| {
            let suffix = version.strip_prefix("FIDO_2_")?;
            let (minor, qualifier) = suffix
                .split_once('_')
                .map_or((suffix, None), |(minor, qualifier)| {
                    (minor, Some(qualifier))
                });
            Some((minor.parse::<u16>().ok()?, qualifier.is_none()))
        };
        self.versions
            .iter()
            .filter(|version| version_rank(version).is_some_and(|(_, stable)| stable))
            .max_by_key(|version| version_rank(version).map(|(minor, _)| minor))
            .or_else(|| {
                self.versions
                    .iter()
                    .filter(|version| version_rank(version).is_some())
                    .max_by_key(|version| version_rank(version).map(|(minor, _)| minor))
            })
            .map(String::as_str)
            .or_else(|| self.versions.first().map(String::as_str))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelyingParty {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) id_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiscoverableCredential {
    pub(crate) relying_party: RelyingParty,
    pub(crate) user_id: Vec<u8>,
    pub(crate) user_name: Option<String>,
    pub(crate) user_display_name: Option<String>,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key_cose: Vec<u8>,
    pub(crate) cred_protect: Option<u64>,
    pub(crate) third_party_payment: Option<bool>,
}

#[derive(Debug)]
pub(crate) struct CredentialAuthorization {
    protocol: u8,
    token: Zeroizing<Vec<u8>>,
}

pub(crate) struct Client {
    transport: Rc<dyn CtapTransport>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("CtapClient").finish_non_exhaustive()
    }
}

fn normalize_pin(
    info: &AuthenticatorInfo,
    pin: &[u8],
    enforce_minimum: bool,
) -> Result<Zeroizing<Vec<u8>>, CtapError> {
    let pin_text =
        std::str::from_utf8(pin).map_err(|_| CtapError::Transport(CKR_PIN_INVALID.into()))?;
    let normalized = Zeroizing::new(pin_text.nfc().collect::<String>());
    let minimum = usize::try_from(info.min_pin_length.unwrap_or(4))
        .map_err(|_| CtapError::Transport(crate::CKR_PIN_LEN_RANGE.into()))?;
    if normalized.is_empty()
        || normalized.len() > 63
        || normalized.as_bytes().contains(&0)
        || (enforce_minimum && normalized.chars().count() < minimum)
    {
        return Err(CtapError::Transport(crate::CKR_PIN_LEN_RANGE.into()));
    }
    Ok(Zeroizing::new(normalized.as_bytes().to_vec()))
}

impl Client {
    pub(crate) fn new(transport: Rc<dyn CtapTransport>) -> Self {
        Self { transport }
    }

    fn exchange(&self, command: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        let mut request = Vec::with_capacity(1 + payload.len());
        request.push(command);
        request.extend_from_slice(payload);
        let response = self.transport.transact(&request)?;
        let (&status, data) = response
            .split_first()
            .ok_or(CtapError::Malformed("missing CTAP status"))?;
        if status != 0 {
            return Err(CtapError::Status(status));
        }
        Ok(data.to_vec())
    }

    pub(crate) fn get_info(&self) -> Result<AuthenticatorInfo, CtapError> {
        let response = self.exchange(AUTHENTICATOR_GET_INFO, &[])?;
        parse_authenticator_info(&response)
    }

    pub(crate) fn set_initial_pin(
        &self,
        info: &AuthenticatorInfo,
        new_pin: &[u8],
    ) -> Result<(), CtapError> {
        if info.option("clientPin") {
            return Err(CtapError::Transport(CKR_PIN_INVALID.into()));
        }
        if !info.pin_uv_auth_protocols.contains(&2) {
            return Err(CtapError::Transport(CKR_FUNCTION_NOT_SUPPORTED.into()));
        }
        let new_pin = normalize_pin(info, new_pin, true)?;

        let response = self.exchange(
            AUTHENTICATOR_CLIENT_PIN,
            &encode_get_key_agreement_request()?,
        )?;
        let authenticator_key = parse_key_agreement_response(&response)?;
        let (platform_key, mut shared_secret) = encapsulate(&authenticator_key)?;
        let mut padded_pin = Zeroizing::new(vec![0; 64]);
        padded_pin[..new_pin.len()].copy_from_slice(&new_pin);
        let mut new_pin_enc = protocol_two_encrypt(&shared_secret, &padded_pin)?;
        let pin_uv_auth_param = authenticate(&shared_secret[..32], &new_pin_enc)?;
        let request = encode_set_pin_request(&platform_key, &pin_uv_auth_param, &new_pin_enc)?;
        let response = self.exchange(AUTHENTICATOR_CLIENT_PIN, &request)?;
        shared_secret.zeroize();
        new_pin_enc.zeroize();
        if !response.is_empty() {
            return Err(CtapError::Malformed("unexpected setPIN response data"));
        }
        Ok(())
    }

    pub(crate) fn change_pin(
        &self,
        info: &AuthenticatorInfo,
        current_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), CtapError> {
        if !info.option("clientPin") {
            return Err(CtapError::Status(CTAP2_ERR_PIN_NOT_SET));
        }
        if !info.pin_uv_auth_protocols.contains(&2) {
            return Err(CtapError::Transport(CKR_FUNCTION_NOT_SUPPORTED.into()));
        }
        let current_pin = normalize_pin(info, current_pin, false)?;
        let new_pin = normalize_pin(info, new_pin, true)?;

        let response = self.exchange(
            AUTHENTICATOR_CLIENT_PIN,
            &encode_get_key_agreement_request()?,
        )?;
        let authenticator_key = parse_key_agreement_response(&response)?;
        let (platform_key, mut shared_secret) = encapsulate(&authenticator_key)?;
        let mut padded_pin = Zeroizing::new(vec![0; 64]);
        padded_pin[..new_pin.len()].copy_from_slice(&new_pin);
        let mut new_pin_enc = protocol_two_encrypt(&shared_secret, &padded_pin)?;
        let current_pin_hash = Zeroizing::new(Sha256::digest(&*current_pin).to_vec());
        let mut pin_hash_enc = protocol_two_encrypt(&shared_secret, &current_pin_hash[..16])?;
        let mut authenticated =
            Zeroizing::new(Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len()));
        authenticated.extend_from_slice(&new_pin_enc);
        authenticated.extend_from_slice(&pin_hash_enc);
        let pin_uv_auth_param = authenticate(&shared_secret[..32], &authenticated)?;
        let request = encode_change_pin_request(
            &platform_key,
            &pin_uv_auth_param,
            &new_pin_enc,
            &pin_hash_enc,
        )?;
        let response = self.exchange(AUTHENTICATOR_CLIENT_PIN, &request)?;
        shared_secret.zeroize();
        new_pin_enc.zeroize();
        pin_hash_enc.zeroize();
        if !response.is_empty() {
            return Err(CtapError::Malformed("unexpected changePIN response data"));
        }
        Ok(())
    }

    pub(crate) fn authorize_credential_enumeration(
        &self,
        info: &AuthenticatorInfo,
        pin: &[u8],
    ) -> Result<CredentialAuthorization, CtapError> {
        let permission = if info.option("perCredMgmtRO") {
            PERMISSION_PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY
        } else {
            PERMISSION_CREDENTIAL_MANAGEMENT
        };
        self.authorize_with_pin(info, pin, permission, None)
    }

    fn authorize_with_pin(
        &self,
        info: &AuthenticatorInfo,
        pin: &[u8],
        permission: u8,
        rp_id: Option<&str>,
    ) -> Result<CredentialAuthorization, CtapError> {
        if !info.option("clientPin") {
            return Err(CtapError::Status(CTAP2_ERR_PIN_NOT_SET));
        }
        if !info.pin_uv_auth_protocols.contains(&2) || !info.option("pinUvAuthToken") {
            return Err(CtapError::Transport(CKR_FUNCTION_NOT_SUPPORTED.into()));
        }
        let pin = normalize_pin(info, pin, true)?;

        let response = self.exchange(
            AUTHENTICATOR_CLIENT_PIN,
            &encode_get_key_agreement_request()?,
        )?;
        let authenticator_key = parse_key_agreement_response(&response)?;
        let (platform_key, mut shared_secret) = encapsulate(&authenticator_key)?;
        let pin_hash = Zeroizing::new(Sha256::digest(&*pin).to_vec());
        let pin_hash_enc = protocol_two_encrypt(&shared_secret, &pin_hash[..16])?;
        let request = encode_get_token_request(&platform_key, &pin_hash_enc, permission, rp_id)?;
        let mut response = self.exchange(AUTHENTICATOR_CLIENT_PIN, &request)?;
        let encrypted_token = parse_pin_token_response(&response)?;
        let token = Zeroizing::new(protocol_two_decrypt(&shared_secret, &encrypted_token)?);
        shared_secret.zeroize();
        response.zeroize();
        if token.len() != 32 {
            return Err(CtapError::Malformed("invalid PIN/UV auth token length"));
        }
        Ok(CredentialAuthorization {
            protocol: PIN_UV_AUTH_PROTOCOL_TWO,
            token,
        })
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    pub(crate) fn create_discoverable_test_credential(
        &self,
        info: &AuthenticatorInfo,
        pin: &[u8],
    ) -> Result<Vec<u8>, CtapError> {
        if info.option("noMcGaPermissionsWithClientPin") {
            return Err(CtapError::Transport(CKR_FUNCTION_NOT_SUPPORTED.into()));
        }
        let authorization = self.authorize_with_pin(
            info,
            pin,
            PERMISSION_MAKE_CREDENTIAL,
            Some(FIDO2_TEST_RP_ID),
        )?;
        let client_data_hash: [u8; 32] =
            Sha256::digest(b"pkcs11rs synthetic FIDO2 hardware credential").into();
        let pin_uv_auth_param = authenticate(&authorization.token, &client_data_hash)?;
        let request = encode_test_make_credential_request(
            &client_data_hash,
            &pin_uv_auth_param,
            authorization.protocol,
        )?;
        let response = self.exchange(AUTHENTICATOR_MAKE_CREDENTIAL, &request)?;
        parse_make_credential_response(&response)
    }

    pub(crate) fn enumerate_credentials(
        &self,
        info: &AuthenticatorInfo,
        authorization: &CredentialAuthorization,
    ) -> Result<Vec<DiscoverableCredential>, CtapError> {
        let command = info
            .credential_management_command()
            .ok_or(CtapError::Transport(CKR_FUNCTION_NOT_SUPPORTED.into()))?;
        let relying_parties = self.enumerate_relying_parties(command, authorization)?;
        let mut credentials = Vec::new();
        for relying_party in relying_parties {
            credentials.extend(self.enumerate_credentials_for_rp(
                command,
                authorization,
                &relying_party,
            )?);
            if credentials.len() > MAX_CTAP_COLLECTION_LENGTH {
                return Err(CtapError::Malformed("credential count exceeds limit"));
            }
        }
        Ok(credentials)
    }

    fn enumerate_relying_parties(
        &self,
        command: u8,
        authorization: &CredentialAuthorization,
    ) -> Result<Vec<RelyingParty>, CtapError> {
        let first = match self.exchange(command, &encode_enumerate_rps_begin(authorization)?) {
            Ok(response) => response,
            Err(CtapError::Status(CTAP2_ERR_NO_CREDENTIALS)) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let (first, total) = parse_relying_party_response(&first, true)?;
        let total = bounded_count(total, "RP count exceeds limit")?;
        let mut relying_parties = Vec::with_capacity(total);
        relying_parties.push(first);
        for _ in 1..total {
            let response = self.exchange(command, &encode_management_next(0x03)?)?;
            let (relying_party, _) = parse_relying_party_response(&response, false)?;
            relying_parties.push(relying_party);
        }
        Ok(relying_parties)
    }

    fn enumerate_credentials_for_rp(
        &self,
        command: u8,
        authorization: &CredentialAuthorization,
        relying_party: &RelyingParty,
    ) -> Result<Vec<DiscoverableCredential>, CtapError> {
        let request = encode_enumerate_credentials_begin(authorization, &relying_party.id_hash)?;
        let first = match self.exchange(command, &request) {
            Ok(response) => response,
            Err(CtapError::Status(CTAP2_ERR_NO_CREDENTIALS)) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let (first, total) = parse_credential_response(&first, relying_party, true)?;
        let total = bounded_count(total, "credential count exceeds limit")?;
        let mut credentials = Vec::with_capacity(total);
        credentials.push(first);
        for _ in 1..total {
            let response = self.exchange(command, &encode_management_next(0x05)?)?;
            let (credential, _) = parse_credential_response(&response, relying_party, false)?;
            credentials.push(credential);
        }
        Ok(credentials)
    }
}

fn bounded_count(value: u64, message: &'static str) -> Result<usize, CtapError> {
    let value = usize::try_from(value).map_err(|_| CtapError::Malformed(message))?;
    if !(1..=MAX_CTAP_COLLECTION_LENGTH).contains(&value) {
        return Err(CtapError::Malformed(message));
    }
    Ok(value)
}

fn definite_map(decoder: &mut Decoder<'_>) -> Result<u64, CtapError> {
    let count = decoder
        .map()?
        .ok_or(CtapError::Malformed("indefinite CBOR map"))?;
    if count > MAX_CTAP_COLLECTION_LENGTH as u64 {
        return Err(CtapError::Malformed("CBOR map exceeds limit"));
    }
    Ok(count)
}

fn definite_array(decoder: &mut Decoder<'_>) -> Result<u64, CtapError> {
    let count = decoder
        .array()?
        .ok_or(CtapError::Malformed("indefinite CBOR array"))?;
    if count > MAX_CTAP_COLLECTION_LENGTH as u64 {
        return Err(CtapError::Malformed("CBOR array exceeds limit"));
    }
    Ok(count)
}

fn decode_string_array(decoder: &mut Decoder<'_>) -> Result<Vec<String>, CtapError> {
    let count = definite_array(decoder)?;
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= 4096)
        .ok_or(CtapError::Malformed("string array exceeds limit"))?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decoder.str()?.to_owned());
    }
    Ok(values)
}

fn parse_authenticator_info(data: &[u8]) -> Result<AuthenticatorInfo, CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut versions = None;
    let mut extensions = Vec::new();
    let mut aaguid = None;
    let mut options = Vec::new();
    let mut max_msg_size = None;
    let mut pin_uv_auth_protocols = Vec::new();
    let mut transports = Vec::new();
    let mut min_pin_length = None;
    let mut seen = [false; 14];

    for _ in 0..count {
        let key = decoder.u64()?;
        if key < seen.len() as u64 {
            if seen[key as usize] {
                return Err(CtapError::Malformed("duplicate authenticator info field"));
            }
            seen[key as usize] = true;
        }
        match key {
            0x01 => versions = Some(decode_string_array(&mut decoder)?),
            0x02 => extensions = decode_string_array(&mut decoder)?,
            0x03 => {
                let bytes = decoder.bytes()?;
                aaguid = Some(
                    bytes
                        .try_into()
                        .map_err(|_| CtapError::Malformed("invalid AAGUID length"))?,
                );
            }
            0x04 => {
                let option_count = definite_map(&mut decoder)?;
                for _ in 0..option_count {
                    let name = decoder.str()?.to_owned();
                    let value = decoder.bool()?;
                    if options.iter().any(|(candidate, _)| candidate == &name) {
                        return Err(CtapError::Malformed("duplicate authenticator option"));
                    }
                    options.push((name, value));
                }
            }
            0x05 => max_msg_size = Some(decoder.u64()?),
            0x06 => {
                let protocol_count = definite_array(&mut decoder)?;
                for _ in 0..protocol_count {
                    pin_uv_auth_protocols.push(decoder.u64()?);
                }
            }
            0x09 => transports = decode_string_array(&mut decoder)?,
            0x0d => {
                let value = decoder.u64()?;
                if value == 0 || value > 63 {
                    return Err(CtapError::Malformed("invalid minimum PIN length"));
                }
                min_pin_length = Some(value);
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing authenticator info data"));
    }
    let versions = versions.ok_or(CtapError::Malformed("missing versions"))?;
    if versions.is_empty() {
        return Err(CtapError::Malformed("empty versions"));
    }
    let aaguid = aaguid.ok_or(CtapError::Malformed("missing AAGUID"))?;
    Ok(AuthenticatorInfo {
        versions,
        extensions,
        aaguid,
        options,
        max_msg_size,
        pin_uv_auth_protocols,
        transports,
        min_pin_length,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoseKey {
    x: [u8; 32],
    y: [u8; 32],
}

fn parse_key_agreement_response(data: &[u8]) -> Result<CoseKey, CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut key = None;
    for _ in 0..count {
        match decoder.u64()? {
            0x01 if key.is_none() => key = Some(parse_cose_key(&mut decoder)?),
            0x01 => return Err(CtapError::Malformed("duplicate key agreement")),
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing key agreement data"));
    }
    key.ok_or(CtapError::Malformed("missing key agreement"))
}

fn parse_cose_key(decoder: &mut Decoder<'_>) -> Result<CoseKey, CtapError> {
    let count = definite_map(decoder)?;
    let mut kty = None;
    let mut alg = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..count {
        let key = decoder.i64()?;
        match key {
            1 if kty.is_none() => kty = Some(decoder.u64()?),
            3 if alg.is_none() => alg = Some(decoder.i64()?),
            -1 if curve.is_none() => curve = Some(decoder.u64()?),
            -2 if x.is_none() => {
                x = Some(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| CtapError::Malformed("invalid COSE x coordinate"))?,
                )
            }
            -3 if y.is_none() => {
                y = Some(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| CtapError::Malformed("invalid COSE y coordinate"))?,
                )
            }
            1 | 3 | -1 | -2 | -3 => return Err(CtapError::Malformed("duplicate COSE key field")),
            _ => decoder.skip()?,
        }
    }
    if kty != Some(2) || alg != Some(-25) || curve != Some(1) {
        return Err(CtapError::Malformed("unsupported key agreement COSE key"));
    }
    Ok(CoseKey {
        x: x.ok_or(CtapError::Malformed("missing COSE x coordinate"))?,
        y: y.ok_or(CtapError::Malformed("missing COSE y coordinate"))?,
    })
}

fn random_p256_secret() -> Result<SecretKey, CtapError> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| CtapError::Transport(CKR_DEVICE_ERROR.into()))?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn encapsulate(authenticator_key: &CoseKey) -> Result<(CoseKey, Zeroizing<Vec<u8>>), CtapError> {
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&authenticator_key.x);
    encoded[33..].copy_from_slice(&authenticator_key.y);
    let peer = PublicKey::from_sec1_bytes(&encoded)
        .map_err(|_| CtapError::Malformed("invalid authenticator key agreement point"))?;
    let secret = random_p256_secret()?;
    let public = secret.public_key().to_sec1_point(false);
    let public = public.as_bytes();
    let platform_key = CoseKey {
        x: public[1..33]
            .try_into()
            .map_err(|_| CtapError::Malformed("invalid platform x coordinate"))?,
        y: public[33..65]
            .try_into()
            .map_err(|_| CtapError::Malformed("invalid platform y coordinate"))?,
    };
    let z = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), z.raw_secret_bytes().as_ref());
    let mut shared = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(b"CTAP2 HMAC key", &mut shared[..32])
        .map_err(|_| CtapError::Malformed("HMAC key derivation failed"))?;
    hkdf.expand(b"CTAP2 AES key", &mut shared[32..])
        .map_err(|_| CtapError::Malformed("AES key derivation failed"))?;
    Ok((platform_key, shared))
}

fn protocol_two_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CtapError> {
    if key.len() != 64 || !is_multiple_of(plaintext.len(), AES_BLOCK_SIZE) {
        return Err(CtapError::Malformed(
            "invalid protocol two encryption input",
        ));
    }
    let mut iv = [0u8; AES_BLOCK_SIZE];
    getrandom::fill(&mut iv).map_err(|_| CtapError::Transport(CKR_DEVICE_ERROR.into()))?;
    let ciphertext = aes_cbc(&key[32..], &iv, plaintext, Direction::Encrypt)?;
    let mut output = Vec::with_capacity(iv.len() + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn protocol_two_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CtapError> {
    if key.len() != 64
        || ciphertext.len() < AES_BLOCK_SIZE * 2
        || !is_multiple_of(ciphertext.len(), AES_BLOCK_SIZE)
    {
        return Err(CtapError::Malformed("invalid protocol two ciphertext"));
    }
    aes_cbc(
        &key[32..],
        &ciphertext[..AES_BLOCK_SIZE],
        &ciphertext[AES_BLOCK_SIZE..],
        Direction::Decrypt,
    )
    .map_err(Into::into)
}

fn authenticate(token: &[u8], message: &[u8]) -> Result<[u8; 32], CtapError> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(token)
        .map_err(|_| CtapError::Malformed("invalid PIN/UV auth token"))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    Ok(output)
}

fn encode_get_key_agreement_request() -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    Encoder::new(&mut output)
        .map(2)?
        .u8(0x01)?
        .u8(PIN_UV_AUTH_PROTOCOL_TWO)?
        .u8(0x02)?
        .u8(0x02)?;
    Ok(output)
}

fn encode_set_pin_request(
    platform_key: &CoseKey,
    pin_uv_auth_param: &[u8; 32],
    new_pin_enc: &[u8],
) -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(5)?
        .u8(0x01)?
        .u8(PIN_UV_AUTH_PROTOCOL_TWO)?
        .u8(0x02)?
        .u8(0x03)?
        .u8(0x03)?;
    encode_cose_key(&mut encoder, platform_key)?;
    encoder
        .u8(0x04)?
        .bytes(pin_uv_auth_param)?
        .u8(0x05)?
        .bytes(new_pin_enc)?;
    Ok(output)
}

fn encode_change_pin_request(
    platform_key: &CoseKey,
    pin_uv_auth_param: &[u8; 32],
    new_pin_enc: &[u8],
    pin_hash_enc: &[u8],
) -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(6)?
        .u8(0x01)?
        .u8(PIN_UV_AUTH_PROTOCOL_TWO)?
        .u8(0x02)?
        .u8(0x04)?
        .u8(0x03)?;
    encode_cose_key(&mut encoder, platform_key)?;
    encoder
        .u8(0x04)?
        .bytes(pin_uv_auth_param)?
        .u8(0x05)?
        .bytes(new_pin_enc)?
        .u8(0x06)?
        .bytes(pin_hash_enc)?;
    Ok(output)
}

fn encode_cose_key(encoder: &mut Encoder<&mut Vec<u8>>, key: &CoseKey) -> Result<(), CtapError> {
    encoder
        .map(5)?
        .u8(1)?
        .u8(2)?
        .u8(3)?
        .i8(-25)?
        .i8(-1)?
        .u8(1)?
        .i8(-2)?
        .bytes(&key.x)?
        .i8(-3)?
        .bytes(&key.y)?;
    Ok(())
}

fn encode_get_token_request(
    platform_key: &CoseKey,
    pin_hash_enc: &[u8],
    permission: u8,
    rp_id: Option<&str>,
) -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(if rp_id.is_some() { 6 } else { 5 })?
        .u8(0x01)?
        .u8(PIN_UV_AUTH_PROTOCOL_TWO)?
        .u8(0x02)?
        .u8(0x09)?
        .u8(0x03)?;
    encode_cose_key(&mut encoder, platform_key)?;
    encoder
        .u8(0x06)?
        .bytes(pin_hash_enc)?
        .u8(0x09)?
        .u8(permission)?;
    if let Some(rp_id) = rp_id {
        encoder.u8(0x0a)?.str(rp_id)?;
    }
    Ok(output)
}

#[cfg(test)]
fn encode_test_make_credential_request(
    client_data_hash: &[u8; 32],
    pin_uv_auth_param: &[u8; 32],
    protocol: u8,
) -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    Encoder::new(&mut output)
        .map(7)?
        .u8(0x01)?
        .bytes(client_data_hash)?
        .u8(0x02)?
        .map(2)?
        .str("id")?
        .str(FIDO2_TEST_RP_ID)?
        .str("name")?
        .str("pkcs11rs synthetic relying party")?
        .u8(0x03)?
        .map(3)?
        .str("id")?
        .bytes(b"pkcs11rs-fido2-hardware-user-v1")?
        .str("name")?
        .str("pkcs11rs-test")?
        .str("displayName")?
        .str(FIDO2_TEST_USER_DISPLAY_NAME)?
        .u8(0x04)?
        .array(1)?
        .map(2)?
        .str("alg")?
        .i8(-7)?
        .str("type")?
        .str("public-key")?
        .u8(0x07)?
        .map(1)?
        .str("rk")?
        .bool(true)?
        .u8(0x08)?
        .bytes(pin_uv_auth_param)?
        .u8(0x09)?
        .u8(protocol)?;
    Ok(output)
}

#[cfg(test)]
fn parse_make_credential_response(data: &[u8]) -> Result<Vec<u8>, CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut format = None;
    let mut authenticator_data = None;
    let mut attestation_statement = false;
    for _ in 0..count {
        match decoder.u64()? {
            0x01 if format.is_none() => format = Some(decoder.str()?.to_owned()),
            0x01 => return Err(CtapError::Malformed("duplicate attestation format")),
            0x02 if authenticator_data.is_none() => {
                authenticator_data = Some(decoder.bytes()?.to_vec())
            }
            0x02 => return Err(CtapError::Malformed("duplicate authenticator data")),
            0x03 if !attestation_statement => {
                let entries = definite_map(&mut decoder)?;
                for _ in 0..entries {
                    decoder.skip()?;
                    decoder.skip()?;
                }
                attestation_statement = true;
            }
            0x03 => return Err(CtapError::Malformed("duplicate attestation statement")),
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed(
            "trailing makeCredential response data",
        ));
    }
    let _format = format.ok_or(CtapError::Malformed("missing attestation format"))?;
    if !attestation_statement {
        return Err(CtapError::Malformed("missing attestation statement"));
    }
    let authenticator_data =
        authenticator_data.ok_or(CtapError::Malformed("missing authenticator data"))?;
    if authenticator_data.len() < 55 || authenticator_data[32] & 0x40 == 0 {
        return Err(CtapError::Malformed("missing attested credential data"));
    }
    let expected_rp_id_hash = Sha256::digest(FIDO2_TEST_RP_ID.as_bytes());
    if authenticator_data[..32] != expected_rp_id_hash[..] {
        return Err(CtapError::Malformed("unexpected relying-party ID hash"));
    }
    let credential_id_length = usize::from(u16::from_be_bytes([
        authenticator_data[53],
        authenticator_data[54],
    ]));
    let credential_id_end = 55_usize
        .checked_add(credential_id_length)
        .ok_or(CtapError::Malformed("credential ID length overflow"))?;
    if credential_id_length == 0 || credential_id_end >= authenticator_data.len() {
        return Err(CtapError::Malformed("invalid credential ID length"));
    }
    Ok(authenticator_data[55..credential_id_end].to_vec())
}

fn parse_pin_token_response(data: &[u8]) -> Result<Vec<u8>, CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut token = None;
    for _ in 0..count {
        match decoder.u64()? {
            0x02 if token.is_none() => token = Some(decoder.bytes()?.to_vec()),
            0x02 => return Err(CtapError::Malformed("duplicate PIN/UV auth token")),
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing PIN token response"));
    }
    token.ok_or(CtapError::Malformed("missing PIN/UV auth token"))
}

fn encode_enumerate_rps_begin(
    authorization: &CredentialAuthorization,
) -> Result<Vec<u8>, CtapError> {
    let subcommand = 0x02;
    let auth = authenticate(&authorization.token, &[subcommand])?;
    let mut output = Vec::new();
    Encoder::new(&mut output)
        .map(3)?
        .u8(0x01)?
        .u8(subcommand)?
        .u8(0x03)?
        .u8(authorization.protocol)?
        .u8(0x04)?
        .bytes(&auth)?;
    Ok(output)
}

fn encode_enumerate_credentials_begin(
    authorization: &CredentialAuthorization,
    rp_id_hash: &[u8; 32],
) -> Result<Vec<u8>, CtapError> {
    let subcommand = 0x04;
    let mut params = Vec::new();
    Encoder::new(&mut params)
        .map(1)?
        .u8(0x01)?
        .bytes(rp_id_hash)?;
    let mut message = Vec::with_capacity(1 + params.len());
    message.push(subcommand);
    message.extend_from_slice(&params);
    let auth = authenticate(&authorization.token, &message)?;

    let mut output = Vec::new();
    Encoder::new(&mut output)
        .map(4)?
        .u8(0x01)?
        .u8(subcommand)?
        .u8(0x02)?
        .map(1)?
        .u8(0x01)?
        .bytes(rp_id_hash)?
        .u8(0x03)?
        .u8(authorization.protocol)?
        .u8(0x04)?
        .bytes(&auth)?;
    Ok(output)
}

fn encode_management_next(subcommand: u8) -> Result<Vec<u8>, CtapError> {
    let mut output = Vec::new();
    Encoder::new(&mut output).map(1)?.u8(0x01)?.u8(subcommand)?;
    Ok(output)
}

fn parse_relying_party_response(
    data: &[u8],
    begin: bool,
) -> Result<(RelyingParty, u64), CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut entity = None;
    let mut id_hash = None;
    let mut total = None;
    for _ in 0..count {
        match decoder.u64()? {
            0x03 if entity.is_none() => entity = Some(parse_rp_entity(&mut decoder)?),
            0x04 if id_hash.is_none() => {
                id_hash = Some(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| CtapError::Malformed("invalid RP ID hash"))?,
                )
            }
            0x05 if total.is_none() => total = Some(decoder.u64()?),
            0x03..=0x05 => return Err(CtapError::Malformed("duplicate RP response field")),
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing RP response data"));
    }
    let (id, name) = entity.ok_or(CtapError::Malformed("missing RP entity"))?;
    let relying_party = RelyingParty {
        id,
        name,
        id_hash: id_hash.ok_or(CtapError::Malformed("missing RP ID hash"))?,
    };
    let total = match (begin, total) {
        (true, Some(total)) => total,
        (true, None) => return Err(CtapError::Malformed("missing total RP count")),
        (false, Some(_)) => return Err(CtapError::Malformed("unexpected total RP count")),
        (false, None) => 0,
    };
    Ok((relying_party, total))
}

fn parse_rp_entity(
    decoder: &mut Decoder<'_>,
) -> Result<(Option<String>, Option<String>), CtapError> {
    let count = definite_map(decoder)?;
    let mut id = None;
    let mut name = None;
    for _ in 0..count {
        match decoder.str()? {
            "id" if id.is_none() => id = Some(decoder.str()?.to_owned()),
            "name" if name.is_none() => name = Some(decoder.str()?.to_owned()),
            "id" | "name" => return Err(CtapError::Malformed("duplicate RP entity field")),
            _ => decoder.skip()?,
        }
    }
    Ok((id, name))
}

fn parse_credential_response(
    data: &[u8],
    relying_party: &RelyingParty,
    begin: bool,
) -> Result<(DiscoverableCredential, u64), CtapError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(&mut decoder)?;
    let mut user = None;
    let mut credential_id = None;
    let mut public_key_cose = None;
    let mut total = None;
    let mut cred_protect = None;
    let mut third_party_payment = None;
    for _ in 0..count {
        match decoder.u64()? {
            0x06 if user.is_none() => user = Some(parse_user_entity(&mut decoder)?),
            0x07 if credential_id.is_none() => {
                credential_id = Some(parse_credential_descriptor(&mut decoder)?)
            }
            0x08 if public_key_cose.is_none() => {
                if decoder.datatype()? != Type::Map {
                    return Err(CtapError::Malformed("credential public key is not a map"));
                }
                let start = decoder.position();
                let count = definite_map(&mut decoder)?;
                for _ in 0..count {
                    decoder.skip()?;
                    decoder.skip()?;
                }
                public_key_cose = Some(data[start..decoder.position()].to_vec());
            }
            0x09 if total.is_none() => total = Some(decoder.u64()?),
            0x0a if cred_protect.is_none() => cred_protect = Some(decoder.u64()?),
            0x0c if third_party_payment.is_none() => third_party_payment = Some(decoder.bool()?),
            0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0c => {
                return Err(CtapError::Malformed("duplicate credential response field"))
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(CtapError::Malformed("trailing credential response data"));
    }
    let (user_id, user_name, user_display_name) =
        user.ok_or(CtapError::Malformed("missing credential user"))?;
    let total = match (begin, total) {
        (true, Some(total)) => total,
        (true, None) => return Err(CtapError::Malformed("missing total credential count")),
        (false, Some(_)) => return Err(CtapError::Malformed("unexpected total credential count")),
        (false, None) => 0,
    };
    Ok((
        DiscoverableCredential {
            relying_party: relying_party.clone(),
            user_id,
            user_name,
            user_display_name,
            credential_id: credential_id.ok_or(CtapError::Malformed("missing credential ID"))?,
            public_key_cose: public_key_cose
                .ok_or(CtapError::Malformed("missing credential public key"))?,
            cred_protect,
            third_party_payment,
        },
        total,
    ))
}

type UserEntity = (Vec<u8>, Option<String>, Option<String>);

fn parse_user_entity(decoder: &mut Decoder<'_>) -> Result<UserEntity, CtapError> {
    let count = definite_map(decoder)?;
    let mut id = None;
    let mut name = None;
    let mut display_name = None;
    for _ in 0..count {
        match decoder.str()? {
            "id" if id.is_none() => id = Some(decoder.bytes()?.to_vec()),
            "name" if name.is_none() => name = Some(decoder.str()?.to_owned()),
            "displayName" if display_name.is_none() => {
                display_name = Some(decoder.str()?.to_owned())
            }
            "id" | "name" | "displayName" => {
                return Err(CtapError::Malformed("duplicate user entity field"))
            }
            _ => decoder.skip()?,
        }
    }
    Ok((
        id.ok_or(CtapError::Malformed("missing user ID"))?,
        name,
        display_name,
    ))
}

fn parse_credential_descriptor(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, CtapError> {
    let count = definite_map(decoder)?;
    let mut type_ = None;
    let mut id = None;
    for _ in 0..count {
        match decoder.str()? {
            "type" if type_.is_none() => type_ = Some(decoder.str()?.to_owned()),
            "id" if id.is_none() => id = Some(decoder.bytes()?.to_vec()),
            "type" | "id" => {
                return Err(CtapError::Malformed(
                    "duplicate credential descriptor field",
                ))
            }
            _ => decoder.skip()?,
        }
    }
    if type_.as_deref() != Some("public-key") {
        return Err(CtapError::Malformed(
            "unsupported credential descriptor type",
        ));
    }
    id.ok_or(CtapError::Malformed("missing descriptor credential ID"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Debug)]
    struct MockTransport {
        responses: RefCell<VecDeque<Vec<u8>>>,
        requests: RefCell<Vec<Vec<u8>>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl CtapTransport for MockTransport {
        fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.requests.borrow_mut().push(request.to_vec());
            Ok(self.responses.borrow_mut().pop_front().unwrap())
        }
    }

    fn get_info_vector() -> Vec<u8> {
        vec![
            0xa7, 0x01, 0x82, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x66, b'U',
            b'2', b'F', b'_', b'V', b'2', 0x02, 0x81, 0x6b, b'c', b'r', b'e', b'd', b'P', b'r',
            b'o', b't', b'e', b'c', b't', 0x03, 0x50, 0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d,
            0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d, 0x04, 0xa5, 0x62, b'r', b'k',
            0xf5, 0x68, b'c', b'r', b'e', b'd', b'M', b'g', b'm', b't', 0xf5, 0x69, b'c', b'l',
            b'i', b'e', b'n', b't', b'P', b'i', b'n', 0xf5, 0x6e, b'p', b'i', b'n', b'U', b'v',
            b'A', b'u', b't', b'h', b'T', b'o', b'k', b'e', b'n', 0xf5, 0x64, b'p', b'c', b'm',
            b'r', 0xf5, 0x05, 0x19, 0x04, 0xb0, 0x06, 0x82, 0x02, 0x01, 0x09, 0x82, 0x63, b'u',
            b's', b'b', 0x63, b'n', b'f', b'c',
        ]
    }

    #[test]
    fn get_info_request_and_response_match_protocol_vector() {
        let mut response = get_info_vector();
        response.insert(0, 0);
        let transport = Rc::new(MockTransport::new(vec![response]));
        let client = Client::new(transport.clone());
        let info = client.get_info().unwrap();
        assert_eq!(
            &*transport.requests.borrow(),
            &[vec![AUTHENTICATOR_GET_INFO]]
        );
        assert_eq!(info.versions, ["FIDO_2_1", "U2F_V2"]);
        assert_eq!(
            info.aaguid,
            [
                0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e,
                0xdc, 0x7d
            ]
        );
        assert_eq!(info.pin_uv_auth_protocols, [2, 1]);
        assert_eq!(info.transports, ["usb", "nfc"]);
    }

    #[test]
    fn get_info_reports_and_validates_minimum_pin_length() {
        let encoded = |minimum: u8| {
            let mut output = Vec::new();
            Encoder::new(&mut output)
                .map(3)
                .unwrap()
                .u8(1)
                .unwrap()
                .array(1)
                .unwrap()
                .str("FIDO_2_1")
                .unwrap()
                .u8(3)
                .unwrap()
                .bytes(&[0; 16])
                .unwrap()
                .u8(0x0d)
                .unwrap()
                .u8(minimum)
                .unwrap();
            output
        };
        assert_eq!(
            parse_authenticator_info(&encoded(8))
                .unwrap()
                .min_pin_length,
            Some(8)
        );
        assert!(parse_authenticator_info(&encoded(0)).is_err());
        assert!(parse_authenticator_info(&encoded(64)).is_err());
    }

    #[test]
    fn malformed_get_info_responses_are_rejected() {
        let mut missing_aaguid = get_info_vector();
        missing_aaguid[0] = 0xa6;
        missing_aaguid.drain(24..42);
        assert!(parse_authenticator_info(&missing_aaguid).is_err());

        let mut trailing = get_info_vector();
        trailing.push(0);
        assert!(parse_authenticator_info(&trailing).is_err());

        let indefinite = [
            0xbf, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x03, 0x50, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
        ];
        assert!(parse_authenticator_info(&indefinite).is_err());
    }

    #[test]
    fn ctap_status_and_missing_status_are_not_parsed_as_cbor() {
        let transport = Rc::new(MockTransport::new(vec![vec![0x01], Vec::new()]));
        let client = Client::new(transport);
        assert!(matches!(client.get_info(), Err(CtapError::Status(0x01))));
        assert!(matches!(
            client.get_info(),
            Err(CtapError::Malformed("missing CTAP status"))
        ));
    }

    fn credential_management_info() -> AuthenticatorInfo {
        AuthenticatorInfo {
            versions: vec!["FIDO_2_1".to_owned()],
            extensions: Vec::new(),
            aaguid: [0; 16],
            options: vec![
                ("credMgmt".to_owned(), true),
                ("clientPin".to_owned(), true),
                ("pinUvAuthToken".to_owned(), true),
                ("perCredMgmtRO".to_owned(), true),
            ],
            max_msg_size: Some(1200),
            pin_uv_auth_protocols: vec![2],
            transports: vec!["usb".to_owned()],
            min_pin_length: Some(4),
        }
    }

    fn key_agreement_response() -> Vec<u8> {
        let key = CoseKey {
            x: [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            y: [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        };
        let mut response = vec![0];
        let mut encoder = Encoder::new(&mut response);
        encoder.map(1).unwrap().u8(1).unwrap();
        encode_cose_key(&mut encoder, &key).unwrap();
        response
    }

    fn make_credential_response(credential_id: &[u8]) -> Vec<u8> {
        let mut authenticator_data = Sha256::digest(FIDO2_TEST_RP_ID.as_bytes()).to_vec();
        authenticator_data.push(0x41);
        authenticator_data.extend_from_slice(&[0; 4]);
        authenticator_data.extend_from_slice(&[0x33; 16]);
        authenticator_data
            .extend_from_slice(&(u16::try_from(credential_id.len()).unwrap()).to_be_bytes());
        authenticator_data.extend_from_slice(credential_id);
        authenticator_data.push(0xa0);

        let mut response = Vec::new();
        Encoder::new(&mut response)
            .map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .str("none")
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&authenticator_data)
            .unwrap()
            .u8(3)
            .unwrap()
            .map(0)
            .unwrap();
        response
    }

    fn rp_response() -> Vec<u8> {
        let mut output = vec![0];
        let mut encoder = Encoder::new(&mut output);
        encoder
            .map(3)
            .unwrap()
            .u8(3)
            .unwrap()
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap()
            .str("name")
            .unwrap()
            .str("Example")
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(&[0x11; 32])
            .unwrap()
            .u8(5)
            .unwrap()
            .u8(1)
            .unwrap();
        output
    }

    fn credential_response() -> Vec<u8> {
        let mut output = vec![0];
        let mut encoder = Encoder::new(&mut output);
        encoder
            .map(6)
            .unwrap()
            .u8(6)
            .unwrap()
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(b"user-id")
            .unwrap()
            .str("name")
            .unwrap()
            .str("alice")
            .unwrap()
            .str("displayName")
            .unwrap()
            .str("Alice")
            .unwrap()
            .u8(7)
            .unwrap()
            .map(2)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[0x22; 32])
            .unwrap()
            .u8(8)
            .unwrap()
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i8(-7)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[0x33; 32])
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&[0x44; 32])
            .unwrap()
            .u8(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(10)
            .unwrap()
            .u8(3)
            .unwrap()
            .u8(12)
            .unwrap()
            .bool(true)
            .unwrap();
        output
    }

    #[test]
    fn credential_management_requests_match_protocol_vectors() {
        assert_eq!(
            encode_get_key_agreement_request().unwrap(),
            [0xa2, 0x01, 0x02, 0x02, 0x02]
        );
        let authorization = CredentialAuthorization {
            protocol: 2,
            token: Zeroizing::new(vec![0; 32]),
        };
        let mut expected = vec![0xa3, 0x01, 0x02, 0x03, 0x02, 0x04, 0x58, 0x20];
        expected.extend([
            0x4e, 0xe7, 0xbe, 0x0c, 0x78, 0x72, 0x36, 0x0c, 0xa6, 0x74, 0x14, 0x60, 0x80, 0x81,
            0xe9, 0xbd, 0x60, 0xfd, 0x58, 0x0a, 0x7b, 0xbd, 0x20, 0x97, 0x01, 0xd2, 0xa5, 0xa0,
            0xb4, 0x31, 0x6d, 0x0d,
        ]);
        assert_eq!(
            encode_enumerate_rps_begin(&authorization).unwrap(),
            expected
        );
        assert_eq!(encode_management_next(3).unwrap(), [0xa1, 0x01, 0x03]);
        assert_eq!(encode_management_next(5).unwrap(), [0xa1, 0x01, 0x05]);
    }

    #[test]
    fn synthetic_make_credential_request_matches_ctap_shape() {
        let request = encode_test_make_credential_request(&[0x11; 32], &[0x22; 32], 2).unwrap();
        let mut decoder = Decoder::new(&request);
        assert_eq!(decoder.map().unwrap(), Some(7));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.bytes().unwrap(), &[0x11; 32]);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), FIDO2_TEST_RP_ID);
        assert_eq!(decoder.str().unwrap(), "name");
        assert_eq!(decoder.str().unwrap(), "pkcs11rs synthetic relying party");
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.map().unwrap(), Some(3));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.bytes().unwrap(), b"pkcs11rs-fido2-hardware-user-v1");
        assert_eq!(decoder.str().unwrap(), "name");
        assert_eq!(decoder.str().unwrap(), "pkcs11rs-test");
        assert_eq!(decoder.str().unwrap(), "displayName");
        assert_eq!(decoder.str().unwrap(), FIDO2_TEST_USER_DISPLAY_NAME);
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(decoder.array().unwrap(), Some(1));
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "alg");
        assert_eq!(decoder.i8().unwrap(), -7);
        assert_eq!(decoder.str().unwrap(), "type");
        assert_eq!(decoder.str().unwrap(), "public-key");
        assert_eq!(decoder.u8().unwrap(), 7);
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "rk");
        assert!(decoder.bool().unwrap());
        assert_eq!(decoder.u8().unwrap(), 8);
        assert_eq!(decoder.bytes().unwrap(), &[0x22; 32]);
        assert_eq!(decoder.u8().unwrap(), 9);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.position(), request.len());
    }

    #[test]
    fn make_credential_pin_token_request_is_bound_to_the_test_rp() {
        let key = CoseKey {
            x: [0x33; 32],
            y: [0x44; 32],
        };
        let request = encode_get_token_request(
            &key,
            &[0x55; 32],
            PERMISSION_MAKE_CREDENTIAL,
            Some(FIDO2_TEST_RP_ID),
        )
        .unwrap();
        let mut decoder = Decoder::new(&request);
        assert_eq!(decoder.map().unwrap(), Some(6));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 9);
        assert_eq!(decoder.u8().unwrap(), 3);
        parse_cose_key(&mut decoder).unwrap();
        assert_eq!(decoder.u8().unwrap(), 6);
        assert_eq!(decoder.bytes().unwrap(), &[0x55; 32]);
        assert_eq!(decoder.u8().unwrap(), 9);
        assert_eq!(decoder.u8().unwrap(), PERMISSION_MAKE_CREDENTIAL);
        assert_eq!(decoder.u8().unwrap(), 0x0a);
        assert_eq!(decoder.str().unwrap(), FIDO2_TEST_RP_ID);
        assert_eq!(decoder.position(), request.len());
    }

    #[test]
    fn make_credential_response_extracts_and_validates_credential_id() {
        let response = make_credential_response(&[0x44; 32]);
        assert_eq!(
            parse_make_credential_response(&response).unwrap(),
            [0x44; 32]
        );

        let mut wrong_rp = response.clone();
        let hash_offset = wrong_rp
            .windows(32)
            .position(|window| window == Sha256::digest(FIDO2_TEST_RP_ID.as_bytes()).as_slice())
            .unwrap();
        wrong_rp[hash_offset] ^= 1;
        assert!(matches!(
            parse_make_credential_response(&wrong_rp),
            Err(CtapError::Malformed("unexpected relying-party ID hash"))
        ));

        let mut trailing = response;
        trailing.push(0);
        assert!(matches!(
            parse_make_credential_response(&trailing),
            Err(CtapError::Malformed(
                "trailing makeCredential response data"
            ))
        ));
    }

    #[test]
    fn set_pin_uses_protocol_two_request_shape() {
        let transport = Rc::new(MockTransport::new(vec![key_agreement_response(), vec![0]]));
        let client = Client::new(transport.clone());
        let mut info = credential_management_info();
        info.options
            .retain(|(name, _)| name.as_str() != "clientPin");
        client.set_initial_pin(&info, b"test-PIN").unwrap();

        let requests = transport.requests.borrow();
        assert_eq!(
            requests[0],
            [
                AUTHENTICATOR_CLIENT_PIN,
                0xa2,
                0x01,
                PIN_UV_AUTH_PROTOCOL_TWO,
                0x02,
                0x02
            ]
        );
        assert_eq!(requests[1][0], AUTHENTICATOR_CLIENT_PIN);
        let mut decoder = Decoder::new(&requests[1][1..]);
        assert_eq!(decoder.map().unwrap(), Some(5));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), PIN_UV_AUTH_PROTOCOL_TWO);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.u8().unwrap(), 3);
        parse_cose_key(&mut decoder).unwrap();
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(decoder.bytes().unwrap().len(), 32);
        assert_eq!(decoder.u8().unwrap(), 5);
        assert_eq!(decoder.bytes().unwrap().len(), 80);
        assert_eq!(decoder.position(), requests[1].len() - 1);
    }

    #[test]
    fn set_pin_rejects_unsafe_inputs_and_malformed_success_data() {
        let transport = Rc::new(MockTransport::new(Vec::new()));
        let client = Client::new(transport.clone());
        let info = credential_management_info();
        assert!(client.set_initial_pin(&info, b"test-PIN").is_err());
        assert!(transport.requests.borrow().is_empty());

        let mut unset = info;
        unset
            .options
            .retain(|(name, _)| name.as_str() != "clientPin");
        unset.min_pin_length = Some(8);
        assert!(client.set_initial_pin(&unset, b"short").is_err());
        assert!(client.set_initial_pin(&unset, b"has\0zero").is_err());
        assert!(transport.requests.borrow().is_empty());

        let malformed = Rc::new(MockTransport::new(vec![
            key_agreement_response(),
            vec![0, 0xa0],
        ]));
        assert!(matches!(
            Client::new(malformed).set_initial_pin(&unset, b"long-enough"),
            Err(CtapError::Malformed("unexpected setPIN response data"))
        ));
    }

    #[test]
    fn change_pin_uses_protocol_two_request_shape() {
        let transport = Rc::new(MockTransport::new(vec![key_agreement_response(), vec![0]]));
        let client = Client::new(transport.clone());
        let mut info = credential_management_info();
        info.min_pin_length = Some(8);
        client.change_pin(&info, b"old!", b"new-PIN!").unwrap();

        let requests = transport.requests.borrow();
        assert_eq!(
            requests[0],
            [
                AUTHENTICATOR_CLIENT_PIN,
                0xa2,
                0x01,
                PIN_UV_AUTH_PROTOCOL_TWO,
                0x02,
                0x02
            ]
        );
        assert_eq!(requests[1][0], AUTHENTICATOR_CLIENT_PIN);
        let mut decoder = Decoder::new(&requests[1][1..]);
        assert_eq!(decoder.map().unwrap(), Some(6));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), PIN_UV_AUTH_PROTOCOL_TWO);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(decoder.u8().unwrap(), 3);
        parse_cose_key(&mut decoder).unwrap();
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(decoder.bytes().unwrap().len(), 32);
        assert_eq!(decoder.u8().unwrap(), 5);
        assert_eq!(decoder.bytes().unwrap().len(), 80);
        assert_eq!(decoder.u8().unwrap(), 6);
        assert_eq!(decoder.bytes().unwrap().len(), 32);
        assert_eq!(decoder.position(), requests[1].len() - 1);
    }

    #[test]
    fn change_pin_rejects_unsafe_inputs_and_malformed_success_data() {
        let transport = Rc::new(MockTransport::new(Vec::new()));
        let client = Client::new(transport.clone());
        let mut info = credential_management_info();
        info.min_pin_length = Some(8);
        assert!(client.change_pin(&info, b"old-PIN", b"short").is_err());
        assert!(client.change_pin(&info, b"old-PIN", b"has\0zero").is_err());
        assert!(transport.requests.borrow().is_empty());

        let malformed = Rc::new(MockTransport::new(vec![
            key_agreement_response(),
            vec![0, 0xa0],
        ]));
        assert!(matches!(
            Client::new(malformed).change_pin(&info, b"old!", b"long-enough"),
            Err(CtapError::Malformed("unexpected changePIN response data"))
        ));

        let wrong_pin = Rc::new(MockTransport::new(vec![
            key_agreement_response(),
            vec![CTAP2_ERR_PIN_INVALID],
        ]));
        assert!(matches!(
            Client::new(wrong_pin)
                .change_pin(&info, b"old!", b"long-enough")
                .map_err(CtapError::into_pkcs11),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));
    }

    #[test]
    fn fido_pins_are_normalized_to_nfc_before_use() {
        let mut info = credential_management_info();
        info.min_pin_length = Some(4);
        assert_eq!(
            normalize_pin(&info, "ra\u{0308}ka".as_bytes(), true)
                .unwrap()
                .as_slice(),
            "räka".as_bytes()
        );
        info.min_pin_length = Some(5);
        assert!(matches!(
            normalize_pin(&info, "ra\u{0308}ka".as_bytes(), true),
            Err(CtapError::Transport(_))
        ));
        assert_eq!(
            normalize_pin(&info, "räka".as_bytes(), false)
                .unwrap()
                .as_slice(),
            "räka".as_bytes()
        );
    }

    #[test]
    fn primary_version_prefers_latest_stable_ctap_over_u2f_and_preview() {
        let mut info = credential_management_info();
        info.versions = [
            "U2F_V2",
            "FIDO_2_0",
            "FIDO_2_1_PRE",
            "FIDO_2_1",
            "FIDO_2_3",
            "FIDO_2_4_PRE",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(info.primary_version(), Some("FIDO_2_3"));
    }

    #[test]
    fn mock_transport_enumerates_read_only_credentials() {
        let transport = Rc::new(MockTransport::new(vec![
            rp_response(),
            credential_response(),
        ]));
        let client = Client::new(transport.clone());
        let authorization = CredentialAuthorization {
            protocol: 2,
            token: Zeroizing::new(vec![0x55; 32]),
        };
        let credentials = client
            .enumerate_credentials(&credential_management_info(), &authorization)
            .unwrap();
        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];
        assert_eq!(credential.relying_party.id.as_deref(), Some("example.com"));
        assert_eq!(credential.relying_party.id_hash, [0x11; 32]);
        assert_eq!(credential.user_id, b"user-id");
        assert_eq!(credential.user_name.as_deref(), Some("alice"));
        assert_eq!(credential.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(credential.credential_id, [0x22; 32]);
        assert_eq!(credential.cred_protect, Some(3));
        assert_eq!(credential.third_party_payment, Some(true));

        let requests = transport.requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0][0], AUTHENTICATOR_CREDENTIAL_MANAGEMENT);
        assert_eq!(requests[1][0], AUTHENTICATOR_CREDENTIAL_MANAGEMENT);
        let mut decoder = Decoder::new(&requests[1][1..]);
        assert_eq!(decoder.map().unwrap(), Some(4));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 4);
    }

    #[test]
    fn no_credentials_is_a_successful_empty_enumeration() {
        let transport = Rc::new(MockTransport::new(vec![vec![CTAP2_ERR_NO_CREDENTIALS]]));
        let client = Client::new(transport);
        let authorization = CredentialAuthorization {
            protocol: 2,
            token: Zeroizing::new(vec![0x55; 32]),
        };
        assert!(client
            .enumerate_credentials(&credential_management_info(), &authorization)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_credential_management_responses_are_rejected() {
        let rp = RelyingParty {
            id: Some("example.com".to_owned()),
            name: None,
            id_hash: [0x11; 32],
        };
        assert!(parse_relying_party_response(&[0xa1, 0x05, 0x01], true).is_err());
        let mut trailing_rp = rp_response();
        trailing_rp.remove(0);
        trailing_rp.push(0);
        assert!(parse_relying_party_response(&trailing_rp, true).is_err());

        let missing_user_id = [
            0xa4, 0x06, 0xa0, 0x07, 0xa2, 0x64, b't', b'y', b'p', b'e', 0x6a, b'p', b'u', b'b',
            b'l', b'i', b'c', b'-', b'k', b'e', b'y', 0x62, b'i', b'd', 0x41, 1, 0x08, 0xa0, 0x09,
            0x01,
        ];
        assert!(parse_credential_response(&missing_user_id, &rp, true).is_err());

        let public_key_not_map = [
            0xa4, 0x06, 0xa1, 0x62, b'i', b'd', 0x41, 1, 0x07, 0xa2, 0x64, b't', b'y', b'p', b'e',
            0x6a, b'p', b'u', b'b', b'l', b'i', b'c', b'-', b'k', b'e', b'y', 0x62, b'i', b'd',
            0x41, 2, 0x08, 0x40, 0x09, 0x01,
        ];
        assert!(parse_credential_response(&public_key_not_map, &rp, true).is_err());
    }
}
