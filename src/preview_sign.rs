//! Canonical persistence records for the experimental FIDO `previewSign`
//! extension.
//!
//! This module models protocol material and performs offline ARKG-P256 public
//! key derivation. The FIDO backend maps those records to experimental
//! PKCS #11 mechanisms; private-key reconstruction remains authenticator-side.

use crate::storage::{ContentReference, StorageError};
use minicbor::{Decoder, Encoder, data::Type};
use std::fmt;

mod arkg;

pub use arkg::{
    ARKG_P256_ALGORITHM, ARKG_P256_ESP256_ALGORITHM, ARKG_PUBLIC_KEY_TYPE, ArkgP256DerivedKey,
    ArkgP256PublicSeed, ESP256_ALGORITHM,
};
const REGISTRATION_SCHEMA: &str = "pkcs11rs.preview-sign.registration";
const DERIVED_KEY_SCHEMA: &str = "pkcs11rs.preview-sign.derived-key";
const SCHEMA_VERSION: u64 = 1;
const PREVIEW_SIGN_EXTENSION: &str = "previewSign";
const CLIENT_DATA_HASH_LENGTH: usize = 32;
const AAGUID_LENGTH: usize = 16;
const AUTHENTICATOR_DATA_PREFIX_LENGTH: usize = 37;
const ATTESTED_CREDENTIAL_PREFIX_LENGTH: usize = 18;
const AUTHENTICATOR_FLAG_AT: u8 = 0x40;
const AUTHENTICATOR_FLAG_ED: u8 = 0x80;

/// A failure while constructing or decoding a `previewSign` persistence
/// record.
#[derive(Debug)]
pub enum PreviewSignError {
    /// A record or embedded protocol value was malformed.
    Malformed(&'static str),
    /// The operating system could not provide random derivation input.
    RandomnessUnavailable,
    /// The record uses a schema version this implementation does not support.
    UnsupportedSchemaVersion(u64),
    /// An embedded content reference was invalid.
    Storage(StorageError),
}

impl fmt::Display for PreviewSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(formatter, "malformed previewSign data: {reason}"),
            Self::RandomnessUnavailable => {
                formatter.write_str("randomness unavailable for previewSign derivation")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported previewSign schema version {version}"
                )
            }
            Self::Storage(error) => {
                write!(formatter, "invalid previewSign content reference: {error}")
            }
        }
    }
}

impl std::error::Error for PreviewSignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for PreviewSignError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<minicbor::decode::Error> for PreviewSignError {
    fn from(_error: minicbor::decode::Error) -> Self {
        Self::Malformed("invalid CBOR")
    }
}

impl From<minicbor::encode::Error<std::convert::Infallible>> for PreviewSignError {
    fn from(_error: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        Self::Malformed("CBOR encoding failed")
    }
}

/// The user-presence and user-verification policy fixed when a `previewSign`
/// signing seed is registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewSignPolicy {
    /// Signing requires neither user presence nor user verification.
    Unattended,
    /// Signing requires user presence.
    RequireUserPresence,
    /// Signing requires both user presence and user verification.
    RequireUserVerification,
}

impl PreviewSignPolicy {
    fn from_wire(value: u64) -> Result<Self, PreviewSignError> {
        match value {
            0b000 => Ok(Self::Unattended),
            0b001 => Ok(Self::RequireUserPresence),
            0b101 => Ok(Self::RequireUserVerification),
            _ => Err(PreviewSignError::Malformed(
                "invalid previewSign user-interaction policy",
            )),
        }
    }

    /// Return the integer value used by the extension wire format.
    pub fn wire_value(self) -> u8 {
        match self {
            Self::Unattended => 0b000,
            Self::RequireUserPresence => 0b001,
            Self::RequireUserVerification => 0b101,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttestedKey {
    rp_id_hash: [u8; 32],
    flags: u8,
    signature_counter: u32,
    aaguid: [u8; AAGUID_LENGTH],
    credential_id: Vec<u8>,
    public_key_cose: Vec<u8>,
    preview_sign_output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationMaterial {
    credential: AttestedKey,
    signing_key: AttestedKey,
    algorithm: i64,
    policy: PreviewSignPolicy,
    signed_extension_output: Vec<u8>,
    unsigned_extension_output: Vec<u8>,
    signing_key_attestation_object: Vec<u8>,
}

/// A canonical wrapper around the exact CTAP `authenticatorMakeCredential`
/// response that registered a `previewSign` signing seed.
///
/// The wrapper adds the RP ID, client-data hash, and an optional YubiKey serial
/// hint that are not recoverable from the response. All credential and signing
/// key fields are parsed from the preserved response bytes and validated for
/// internal consistency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewSignRegistration {
    rp_id: String,
    client_data_hash: [u8; CLIENT_DATA_HASH_LENGTH],
    make_credential_response: Vec<u8>,
    token_serial_hint: Option<String>,
    material: RegistrationMaterial,
}

impl PreviewSignRegistration {
    /// Construct and validate a registration from a CTAP
    /// `authenticatorMakeCredential` success payload.
    ///
    /// `make_credential_response` is the CBOR response map after removal of the
    /// CTAP status byte. `token_serial_hint` is routing metadata only and is not
    /// treated as cryptographic token identity.
    pub fn new(
        rp_id: impl Into<String>,
        client_data_hash: [u8; CLIENT_DATA_HASH_LENGTH],
        make_credential_response: impl Into<Vec<u8>>,
        token_serial_hint: Option<String>,
    ) -> Result<Self, PreviewSignError> {
        let rp_id = rp_id.into();
        if rp_id.is_empty() {
            return Err(PreviewSignError::Malformed("empty relying-party ID"));
        }
        if token_serial_hint.as_ref().is_some_and(String::is_empty) {
            return Err(PreviewSignError::Malformed("empty token serial hint"));
        }
        let make_credential_response = make_credential_response.into();
        let material = parse_make_credential_response(&make_credential_response)?;
        let expected_rp_id_hash: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
            .digest(rp_id.as_bytes())
            .try_into()
            .map_err(|_| PreviewSignError::Malformed("invalid RP ID hash"))?;
        if material.credential.rp_id_hash != expected_rp_id_hash
            || material.signing_key.rp_id_hash != expected_rp_id_hash
        {
            return Err(PreviewSignError::Malformed(
                "registration is not bound to the supplied relying-party ID",
            ));
        }
        if material.credential.aaguid != material.signing_key.aaguid {
            return Err(PreviewSignError::Malformed(
                "parent credential and signing key use different AAGUIDs",
            ));
        }
        if material.signing_key.signature_counter != 0 {
            return Err(PreviewSignError::Malformed(
                "signing-key attestation counter is not zero",
            ));
        }
        Ok(Self {
            rp_id,
            client_data_hash,
            make_credential_response,
            token_serial_hint,
            material,
        })
    }

    /// Decode and validate the canonical wrapper.
    pub fn from_cbor(encoded: &[u8]) -> Result<Self, PreviewSignError> {
        let mut decoder = Decoder::new(encoded);
        let count = definite_map(&mut decoder, "registration wrapper is not a definite map")?;
        let mut schema = None;
        let mut version = None;
        let mut rp_id = None;
        let mut client_data_hash = None;
        let mut response = None;
        let mut serial = None;
        for _ in 0..count {
            match decoder.u64()? {
                1 if schema.is_none() => schema = Some(decoder.str()?.to_owned()),
                1 => return Err(PreviewSignError::Malformed("duplicate registration schema")),
                2 if version.is_none() => version = Some(decoder.u64()?),
                2 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate registration schema version",
                    ));
                }
                3 if rp_id.is_none() => rp_id = Some(decoder.str()?.to_owned()),
                3 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate registration relying-party ID",
                    ));
                }
                4 if client_data_hash.is_none() => {
                    client_data_hash = Some(copy_array::<CLIENT_DATA_HASH_LENGTH>(
                        decoder.bytes()?,
                        "invalid client-data hash length",
                    )?)
                }
                4 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate registration client-data hash",
                    ));
                }
                5 if response.is_none() => response = Some(decoder.bytes()?.to_vec()),
                5 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate makeCredential response",
                    ));
                }
                6 if serial.is_none() => serial = Some(decoder.str()?.to_owned()),
                6 => return Err(PreviewSignError::Malformed("duplicate token serial hint")),
                _ => decoder.skip()?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err(PreviewSignError::Malformed(
                "trailing registration wrapper data",
            ));
        }
        if schema.as_deref() != Some(REGISTRATION_SCHEMA) {
            return Err(PreviewSignError::Malformed(
                "invalid registration schema identifier",
            ));
        }
        let version = version.ok_or(PreviewSignError::Malformed(
            "missing registration schema version",
        ))?;
        if version != SCHEMA_VERSION {
            return Err(PreviewSignError::UnsupportedSchemaVersion(version));
        }
        let registration = Self::new(
            rp_id.ok_or(PreviewSignError::Malformed(
                "missing registration relying-party ID",
            ))?,
            client_data_hash.ok_or(PreviewSignError::Malformed(
                "missing registration client-data hash",
            ))?,
            response.ok_or(PreviewSignError::Malformed(
                "missing makeCredential response",
            ))?,
            serial,
        )?;
        if registration.to_cbor()? != encoded {
            return Err(PreviewSignError::Malformed(
                "registration wrapper is not canonical",
            ));
        }
        Ok(registration)
    }

    /// Encode the wrapper in its canonical, versioned CBOR form.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PreviewSignError> {
        let mut encoded = Vec::new();
        let count = if self.token_serial_hint.is_some() {
            6
        } else {
            5
        };
        let mut encoder = Encoder::new(&mut encoded);
        encoder
            .map(count)?
            .u8(1)?
            .str(REGISTRATION_SCHEMA)?
            .u8(2)?
            .u8(SCHEMA_VERSION as u8)?
            .u8(3)?
            .str(&self.rp_id)?
            .u8(4)?
            .bytes(&self.client_data_hash)?
            .u8(5)?
            .bytes(&self.make_credential_response)?;
        if let Some(serial) = &self.token_serial_hint {
            encoder.u8(6)?.str(serial)?;
        }
        Ok(encoded)
    }

    /// Return the RP ID required by later `authenticatorGetAssertion` calls.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Return the client-data hash needed to verify the original attestation.
    pub fn client_data_hash(&self) -> &[u8; CLIENT_DATA_HASH_LENGTH] {
        &self.client_data_hash
    }

    /// Return the exact CTAP `authenticatorMakeCredential` response map.
    pub fn make_credential_response(&self) -> &[u8] {
        &self.make_credential_response
    }

    /// Return the ordinary FIDO credential ID used in a later assertion
    /// allow-list.
    pub fn credential_id(&self) -> &[u8] {
        &self.material.credential.credential_id
    }

    /// Return the ordinary parent credential public key in its original
    /// COSE_Key encoding.
    pub fn credential_public_key_cose(&self) -> &[u8] {
        &self.material.credential.public_key_cose
    }

    /// Return the generated signing key handle supplied inside the
    /// `previewSign` assertion input.
    pub fn signing_key_handle(&self) -> &[u8] {
        &self.material.signing_key.credential_id
    }

    /// Return the generated signing seed public key in its original COSE_Key
    /// encoding.
    ///
    /// For the current Yubico ARKG preview algorithm this is an ARKG seed key,
    /// not the final P-256 verification key produced by offline derivation.
    pub fn signing_seed_public_key_cose(&self) -> &[u8] {
        &self.material.signing_key.public_key_cose
    }

    /// Return the signing algorithm selected from the registration request.
    pub fn algorithm(&self) -> i64 {
        self.material.algorithm
    }

    /// Return the fixed user-interaction policy for this signing seed.
    pub fn policy(&self) -> PreviewSignPolicy {
        self.material.policy
    }

    /// Return the authenticator AAGUID shared by the parent credential and
    /// nested signing-key attestation.
    pub fn aaguid(&self) -> &[u8; AAGUID_LENGTH] {
        &self.material.credential.aaguid
    }

    /// Return an optional YubiKey serial routing hint.
    pub fn token_serial_hint(&self) -> Option<&str> {
        self.token_serial_hint.as_deref()
    }

    /// Return the exact signed `previewSign` registration extension output.
    pub fn signed_extension_output(&self) -> &[u8] {
        &self.material.signed_extension_output
    }

    /// Return the exact unsigned `previewSign` registration extension output.
    pub fn unsigned_extension_output(&self) -> &[u8] {
        &self.material.unsigned_extension_output
    }

    /// Return the exact nested attestation object for the generated signing
    /// seed.
    pub fn signing_key_attestation_object(&self) -> &[u8] {
        &self.material.signing_key_attestation_object
    }
}

/// A canonical wrapper for one public key derived offline from a persisted
/// `previewSign` registration.
///
/// The record retains the exact algorithm-specific COSE_Sign_Args bytes needed
/// for a later signing request. In the current ARKG preview those bytes contain
/// the per-derived-key ticket and derivation context. Their interpretation
/// remains algorithm-specific.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewSignDerivedKeyRecord {
    registration: ContentReference,
    algorithm: i64,
    verification_key_cose: Vec<u8>,
    additional_args_cbor: Option<Vec<u8>>,
    label: Option<String>,
}

impl PreviewSignDerivedKeyRecord {
    /// Construct a derived-key record.
    pub fn new(
        registration: ContentReference,
        algorithm: i64,
        verification_key_cose: impl Into<Vec<u8>>,
        additional_args_cbor: Option<Vec<u8>>,
        label: Option<String>,
    ) -> Result<Self, PreviewSignError> {
        let verification_key_cose = verification_key_cose.into();
        validate_single_definite_map(
            &verification_key_cose,
            "derived verification key is not one definite COSE_Key map",
        )?;
        if let Some(arguments) = &additional_args_cbor {
            validate_single_definite_map(
                arguments,
                "derived signing arguments are not one definite CBOR map",
            )?;
        }
        Ok(Self {
            registration,
            algorithm,
            verification_key_cose,
            additional_args_cbor,
            label,
        })
    }

    /// Decode and validate the canonical wrapper.
    pub fn from_cbor(encoded: &[u8]) -> Result<Self, PreviewSignError> {
        let mut decoder = Decoder::new(encoded);
        let count = definite_map(&mut decoder, "derived-key wrapper is not a definite map")?;
        let mut schema = None;
        let mut version = None;
        let mut registration = None;
        let mut algorithm = None;
        let mut public_key = None;
        let mut arguments = None;
        let mut label = None;
        for _ in 0..count {
            match decoder.u64()? {
                1 if schema.is_none() => schema = Some(decoder.str()?.to_owned()),
                1 => return Err(PreviewSignError::Malformed("duplicate derived-key schema")),
                2 if version.is_none() => version = Some(decoder.u64()?),
                2 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate derived-key schema version",
                    ));
                }
                3 if registration.is_none() => {
                    registration = Some(decode_content_reference(&mut decoder, encoded)?)
                }
                3 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate registration reference",
                    ));
                }
                4 if algorithm.is_none() => algorithm = Some(decoder.i64()?),
                4 => return Err(PreviewSignError::Malformed("duplicate signing algorithm")),
                5 if public_key.is_none() => public_key = Some(decoder.bytes()?.to_vec()),
                5 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate derived verification key",
                    ));
                }
                6 if arguments.is_none() => arguments = Some(decoder.bytes()?.to_vec()),
                6 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate derived signing arguments",
                    ));
                }
                7 if label.is_none() => label = Some(decoder.str()?.to_owned()),
                7 => return Err(PreviewSignError::Malformed("duplicate derived-key label")),
                _ => decoder.skip()?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err(PreviewSignError::Malformed(
                "trailing derived-key wrapper data",
            ));
        }
        if schema.as_deref() != Some(DERIVED_KEY_SCHEMA) {
            return Err(PreviewSignError::Malformed(
                "invalid derived-key schema identifier",
            ));
        }
        let version = version.ok_or(PreviewSignError::Malformed(
            "missing derived-key schema version",
        ))?;
        if version != SCHEMA_VERSION {
            return Err(PreviewSignError::UnsupportedSchemaVersion(version));
        }
        let record = Self::new(
            registration.ok_or(PreviewSignError::Malformed(
                "missing registration reference",
            ))?,
            algorithm.ok_or(PreviewSignError::Malformed(
                "missing derived signing algorithm",
            ))?,
            public_key.ok_or(PreviewSignError::Malformed(
                "missing derived verification key",
            ))?,
            arguments,
            label,
        )?;
        if record.to_cbor()? != encoded {
            return Err(PreviewSignError::Malformed(
                "derived-key wrapper is not canonical",
            ));
        }
        Ok(record)
    }

    /// Encode the wrapper in its canonical, versioned CBOR form.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PreviewSignError> {
        let count = 5
            + usize::from(self.additional_args_cbor.is_some())
            + usize::from(self.label.is_some());
        let reference = self.registration.to_cbor()?;
        let mut encoded = Vec::new();
        let mut encoder = Encoder::new(&mut encoded);
        encoder
            .map(u64::try_from(count).map_err(|_| {
                PreviewSignError::Malformed("derived-key wrapper field count overflow")
            })?)?
            .u8(1)?
            .str(DERIVED_KEY_SCHEMA)?
            .u8(2)?
            .u8(SCHEMA_VERSION as u8)?
            .u8(3)?;
        encoder.writer_mut().extend_from_slice(&reference);
        encoder
            .u8(4)?
            .i64(self.algorithm)?
            .u8(5)?
            .bytes(&self.verification_key_cose)?;
        if let Some(arguments) = &self.additional_args_cbor {
            encoder.u8(6)?.bytes(arguments)?;
        }
        if let Some(label) = &self.label {
            encoder.u8(7)?.str(label)?;
        }
        Ok(encoded)
    }

    /// Return the content reference of the registration that owns this key.
    pub fn registration(&self) -> &ContentReference {
        &self.registration
    }

    /// Return the algorithm identifier used for later signing.
    pub fn algorithm(&self) -> i64 {
        self.algorithm
    }

    /// Return the derived verification key in COSE_Key format.
    pub fn verification_key_cose(&self) -> &[u8] {
        &self.verification_key_cose
    }

    /// Return the exact algorithm-specific COSE_Sign_Args map, when required.
    pub fn additional_args_cbor(&self) -> Option<&[u8]> {
        self.additional_args_cbor.as_deref()
    }

    /// Return the caller-supplied bookkeeping label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Validate that this derived key can be restored with an exact
    /// registration record.
    ///
    /// This checks the content reference, the current ARKG-P256 algorithm,
    /// the canonical ESP256 verification key, and the canonical signing
    /// ticket and context consumed by the authenticator.
    pub fn validate_for_registration(
        &self,
        registration: &PreviewSignRegistration,
    ) -> Result<(), PreviewSignError> {
        arkg::validate_derived_key_record(registration, self)
    }
}

fn parse_make_credential_response(data: &[u8]) -> Result<RegistrationMaterial, PreviewSignError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(
        &mut decoder,
        "makeCredential response is not a definite map",
    )?;
    let mut format = None;
    let mut authenticator_data = None;
    let mut attestation_statement = false;
    let mut unsigned_extension_output = None;
    for _ in 0..count {
        match decoder.u64()? {
            1 if format.is_none() => format = Some(decoder.str()?.to_owned()),
            1 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate makeCredential attestation format",
                ));
            }
            2 if authenticator_data.is_none() => {
                authenticator_data = Some(decoder.bytes()?.to_vec())
            }
            2 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate makeCredential authenticator data",
                ));
            }
            3 if !attestation_statement => {
                require_map_value(
                    &mut decoder,
                    "makeCredential attestation statement is not a map",
                )?;
                attestation_statement = true;
            }
            3 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate makeCredential attestation statement",
                ));
            }
            6 if unsigned_extension_output.is_none() => {
                unsigned_extension_output = Some(parse_named_extension(
                    &mut decoder,
                    data,
                    PREVIEW_SIGN_EXTENSION,
                )?)
            }
            6 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate makeCredential unsigned extension output",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(PreviewSignError::Malformed(
            "trailing makeCredential response data",
        ));
    }
    if format.as_ref().is_none_or(String::is_empty) {
        return Err(PreviewSignError::Malformed(
            "missing makeCredential attestation format",
        ));
    }
    if !attestation_statement {
        return Err(PreviewSignError::Malformed(
            "missing makeCredential attestation statement",
        ));
    }
    let credential = parse_attested_key(
        &authenticator_data.ok_or(PreviewSignError::Malformed(
            "missing makeCredential authenticator data",
        ))?,
        true,
    )?;
    let signed_extension_output = credential.preview_sign_output.clone();
    let algorithm = parse_registration_algorithm(&signed_extension_output)?;
    let unsigned_extension_output = unsigned_extension_output.ok_or(
        PreviewSignError::Malformed("missing previewSign unsigned extension output"),
    )?;
    let signing_key_attestation_object =
        parse_unsigned_registration_output(&unsigned_extension_output)?;
    let signing_key = parse_signing_key_attestation_object(&signing_key_attestation_object)?;
    let policy = parse_registration_policy(&signing_key.preview_sign_output)?;
    Ok(RegistrationMaterial {
        credential,
        signing_key,
        algorithm,
        policy,
        signed_extension_output,
        unsigned_extension_output,
        signing_key_attestation_object,
    })
}

fn parse_attested_key(
    authenticator_data: &[u8],
    require_nonempty_credential_id: bool,
) -> Result<AttestedKey, PreviewSignError> {
    let minimum = AUTHENTICATOR_DATA_PREFIX_LENGTH
        .checked_add(ATTESTED_CREDENTIAL_PREFIX_LENGTH)
        .ok_or(PreviewSignError::Malformed(
            "authenticator-data length overflow",
        ))?;
    if authenticator_data.len() < minimum {
        return Err(PreviewSignError::Malformed(
            "truncated attested authenticator data",
        ));
    }
    let flags = authenticator_data[32];
    if flags & AUTHENTICATOR_FLAG_AT == 0 {
        return Err(PreviewSignError::Malformed(
            "authenticator data has no attested credential",
        ));
    }
    if flags & AUTHENTICATOR_FLAG_ED == 0 {
        return Err(PreviewSignError::Malformed(
            "authenticator data has no signed extension output",
        ));
    }
    let rp_id_hash = copy_array::<32>(
        &authenticator_data[..32],
        "invalid authenticator RP ID hash",
    )?;
    let signature_counter = u32::from_be_bytes(copy_array::<4>(
        &authenticator_data[33..37],
        "invalid authenticator signature counter",
    )?);
    let aaguid =
        copy_array::<AAGUID_LENGTH>(&authenticator_data[37..53], "invalid authenticator AAGUID")?;
    let credential_id_length = usize::from(u16::from_be_bytes(copy_array::<2>(
        &authenticator_data[53..55],
        "invalid credential ID length",
    )?));
    let credential_id_end = 55_usize
        .checked_add(credential_id_length)
        .ok_or(PreviewSignError::Malformed("credential ID length overflow"))?;
    if credential_id_end > authenticator_data.len()
        || (require_nonempty_credential_id && credential_id_length == 0)
    {
        return Err(PreviewSignError::Malformed("invalid credential ID length"));
    }
    let credential_id = authenticator_data[55..credential_id_end].to_vec();
    let tail = &authenticator_data[credential_id_end..];
    let mut decoder = Decoder::new(tail);
    if decoder.datatype()? != Type::Map {
        return Err(PreviewSignError::Malformed(
            "attested credential public key is not a definite COSE_Key map",
        ));
    }
    let public_key_start = decoder.position();
    decoder.skip()?;
    let public_key_end = decoder.position();
    let public_key_cose = tail[public_key_start..public_key_end].to_vec();
    let preview_sign_output = parse_named_extension(&mut decoder, tail, PREVIEW_SIGN_EXTENSION)?;
    if decoder.position() != tail.len() {
        return Err(PreviewSignError::Malformed(
            "trailing authenticator extension data",
        ));
    }
    Ok(AttestedKey {
        rp_id_hash,
        flags,
        signature_counter,
        aaguid,
        credential_id,
        public_key_cose,
        preview_sign_output,
    })
}

fn parse_signing_key_attestation_object(data: &[u8]) -> Result<AttestedKey, PreviewSignError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(
        &mut decoder,
        "signing-key attestation object is not a definite map",
    )?;
    let mut format = None;
    let mut authenticator_data = None;
    let mut attestation_statement = false;
    for _ in 0..count {
        match decoder.u64()? {
            1 if format.is_none() => format = Some(decoder.str()?.to_owned()),
            1 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate signing-key attestation format",
                ));
            }
            2 if authenticator_data.is_none() => {
                authenticator_data = Some(decoder.bytes()?.to_vec())
            }
            2 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate signing-key authenticator data",
                ));
            }
            3 if !attestation_statement => {
                require_map_value(
                    &mut decoder,
                    "signing-key attestation statement is not a map",
                )?;
                attestation_statement = true;
            }
            3 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate signing-key attestation statement",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(PreviewSignError::Malformed(
            "trailing signing-key attestation object data",
        ));
    }
    if format.as_ref().is_none_or(String::is_empty) || !attestation_statement {
        return Err(PreviewSignError::Malformed(
            "incomplete signing-key attestation object",
        ));
    }
    parse_attested_key(
        &authenticator_data.ok_or(PreviewSignError::Malformed(
            "missing signing-key authenticator data",
        ))?,
        false,
    )
}

fn parse_registration_algorithm(data: &[u8]) -> Result<i64, PreviewSignError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(
        &mut decoder,
        "previewSign signed output is not a definite map",
    )?;
    let mut algorithm = None;
    for _ in 0..count {
        match decoder.u64()? {
            3 if algorithm.is_none() => algorithm = Some(decoder.i64()?),
            3 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate previewSign signing algorithm",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(PreviewSignError::Malformed(
            "trailing previewSign signed output",
        ));
    }
    algorithm.ok_or(PreviewSignError::Malformed(
        "missing previewSign signing algorithm",
    ))
}

fn parse_registration_policy(data: &[u8]) -> Result<PreviewSignPolicy, PreviewSignError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(
        &mut decoder,
        "previewSign attested output is not a definite map",
    )?;
    let mut policy = None;
    for _ in 0..count {
        match decoder.u64()? {
            4 if policy.is_none() => policy = Some(PreviewSignPolicy::from_wire(decoder.u64()?)?),
            4 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate previewSign signing policy",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(PreviewSignError::Malformed(
            "trailing previewSign attested output",
        ));
    }
    policy.ok_or(PreviewSignError::Malformed(
        "missing previewSign signing policy",
    ))
}

fn parse_unsigned_registration_output(data: &[u8]) -> Result<Vec<u8>, PreviewSignError> {
    let mut decoder = Decoder::new(data);
    let count = definite_map(
        &mut decoder,
        "previewSign unsigned output is not a definite map",
    )?;
    let mut attestation = None;
    for _ in 0..count {
        match decoder.u64()? {
            7 if attestation.is_none() => attestation = Some(decoder.bytes()?.to_vec()),
            7 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate previewSign signing-key attestation",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != data.len() {
        return Err(PreviewSignError::Malformed(
            "trailing previewSign unsigned output",
        ));
    }
    attestation.ok_or(PreviewSignError::Malformed(
        "missing previewSign signing-key attestation",
    ))
}

fn parse_named_extension(
    decoder: &mut Decoder<'_>,
    input: &[u8],
    name: &str,
) -> Result<Vec<u8>, PreviewSignError> {
    let count = definite_map(decoder, "extension output is not a definite map")?;
    let mut value = None;
    for _ in 0..count {
        let key = decoder.str()?;
        let start = decoder.position();
        decoder.skip()?;
        let end = decoder.position();
        if key == name {
            if value.is_some() {
                return Err(PreviewSignError::Malformed(
                    "duplicate previewSign extension output",
                ));
            }
            value = Some(input[start..end].to_vec());
        }
    }
    value.ok_or(PreviewSignError::Malformed(
        "missing previewSign extension output",
    ))
}

fn decode_content_reference(
    decoder: &mut Decoder<'_>,
    input: &[u8],
) -> Result<ContentReference, PreviewSignError> {
    let start = decoder.position();
    decoder.skip()?;
    let end = decoder.position();
    Ok(ContentReference::from_cbor(&input[start..end])?)
}

fn require_map_value(
    decoder: &mut Decoder<'_>,
    reason: &'static str,
) -> Result<(), PreviewSignError> {
    if decoder.datatype()? != Type::Map {
        return Err(PreviewSignError::Malformed(reason));
    }
    decoder.skip()?;
    Ok(())
}

fn validate_single_definite_map(
    encoded: &[u8],
    reason: &'static str,
) -> Result<(), PreviewSignError> {
    let mut decoder = Decoder::new(encoded);
    if decoder.datatype()? != Type::Map {
        return Err(PreviewSignError::Malformed(reason));
    }
    decoder.skip()?;
    if decoder.position() != encoded.len() {
        return Err(PreviewSignError::Malformed(reason));
    }
    Ok(())
}

fn definite_map(
    decoder: &mut Decoder<'_>,
    reason: &'static str,
) -> Result<usize, PreviewSignError> {
    let count = decoder.map()?.ok_or(PreviewSignError::Malformed(reason))?;
    usize::try_from(count).map_err(|_| PreviewSignError::Malformed("CBOR map is too large"))
}

fn copy_array<const N: usize>(
    input: &[u8],
    reason: &'static str,
) -> Result<[u8; N], PreviewSignError> {
    if input.len() != N {
        return Err(PreviewSignError::Malformed(reason));
    }
    let mut output = [0; N];
    output.copy_from_slice(input);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RP_ID: &str = "preview-sign.pkcs11rs.invalid";
    const ARKG_P256_ESP256: i64 = -65_539;
    const ARKG_PUBLIC_KEY_TYPE: i64 = -65_537;
    const ARKG_P256_ALGORITHM: i64 = -65_700;
    const ARKG_VECTOR_IKM: &str =
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const ARKG_VECTOR_CONTEXT: &[u8] = b"ARKG-P256.test vectors";
    const ARKG_VECTOR_PUBLIC_KEY: &str = "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107\
         dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd";

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: String = input
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        compact
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    fn ec2_key(seed: u8, algorithm: i64) -> Vec<u8> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(algorithm)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[seed; 32])
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&[seed.wrapping_add(1); 32])
            .unwrap();
        encoded
    }

    fn arkg_seed_key() -> Vec<u8> {
        let blinding_point = decode_hex(
            "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df\
             65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        );
        let kem_point = decode_hex(
            "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5\
             dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        );
        let blinding_key = ec2_key_from_point(&blinding_point, -9);
        let kem_key = ec2_key_from_point(&kem_point, -25);
        let mut encoded = Vec::new();
        let mut encoder = Encoder::new(&mut encoded);
        encoder
            .map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .i64(ARKG_PUBLIC_KEY_TYPE)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(ARKG_P256_ALGORITHM)
            .unwrap()
            .i8(-1)
            .unwrap();
        encoder.writer_mut().extend_from_slice(&blinding_key);
        encoder.i8(-2).unwrap();
        encoder.writer_mut().extend_from_slice(&kem_key);
        encoded
    }

    fn ec2_key_from_point(point: &[u8], algorithm: i64) -> Vec<u8> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(algorithm)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&point[1..33])
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&point[33..])
            .unwrap();
        encoded
    }

    fn preview_sign_algorithm_output() -> Vec<u8> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(1)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(ARKG_P256_ESP256)
            .unwrap();
        encoded
    }

    fn preview_sign_policy_output(policy: u8) -> Vec<u8> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(1)
            .unwrap()
            .u8(4)
            .unwrap()
            .u8(policy)
            .unwrap();
        encoded
    }

    fn authenticator_data(
        credential_id: &[u8],
        public_key: &[u8],
        extension_output: &[u8],
        aaguid: [u8; 16],
        signature_counter: u32,
    ) -> Vec<u8> {
        let mut data =
            software_key_core::digest::HashAlgorithm::Sha256.digest(TEST_RP_ID.as_bytes());
        data.push(0xc1);
        data.extend_from_slice(&signature_counter.to_be_bytes());
        data.extend_from_slice(&aaguid);
        data.extend_from_slice(&u16::try_from(credential_id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(public_key);
        let mut extensions = Vec::new();
        let mut encoder = Encoder::new(&mut extensions);
        encoder.map(1).unwrap().str(PREVIEW_SIGN_EXTENSION).unwrap();
        encoder.writer_mut().extend_from_slice(extension_output);
        data.extend_from_slice(&extensions);
        data
    }

    fn signing_attestation(
        key_handle: &[u8],
        policy: u8,
        aaguid: [u8; 16],
        signature_counter: u32,
    ) -> Vec<u8> {
        let auth_data = authenticator_data(
            key_handle,
            &arkg_seed_key(),
            &preview_sign_policy_output(policy),
            aaguid,
            signature_counter,
        );
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .str("none")
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&auth_data)
            .unwrap()
            .u8(3)
            .unwrap()
            .map(0)
            .unwrap();
        encoded
    }

    fn unsigned_output(
        key_handle: &[u8],
        policy: u8,
        aaguid: [u8; 16],
        signature_counter: u32,
    ) -> Vec<u8> {
        let attestation = signing_attestation(key_handle, policy, aaguid, signature_counter);
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(1)
            .unwrap()
            .u8(7)
            .unwrap()
            .bytes(&attestation)
            .unwrap();
        encoded
    }

    fn make_credential_response_with(
        policy: u8,
        outer_aaguid: [u8; 16],
        inner_aaguid: [u8; 16],
        inner_counter: u32,
        include_unsigned_output: bool,
    ) -> Vec<u8> {
        let parent_credential_id = [0xa5; 32];
        let signing_key_handle = [0x5a; 48];
        let signed_output = preview_sign_algorithm_output();
        let outer_auth_data = authenticator_data(
            &parent_credential_id,
            &ec2_key(0x21, -7),
            &signed_output,
            outer_aaguid,
            7,
        );
        let unsigned_output =
            unsigned_output(&signing_key_handle, policy, inner_aaguid, inner_counter);

        let mut response = Vec::new();
        let mut encoder = Encoder::new(&mut response);
        encoder
            .map(if include_unsigned_output { 4 } else { 3 })
            .unwrap()
            .u8(1)
            .unwrap()
            .str("none")
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&outer_auth_data)
            .unwrap()
            .u8(3)
            .unwrap()
            .map(0)
            .unwrap();
        if include_unsigned_output {
            encoder
                .u8(6)
                .unwrap()
                .map(1)
                .unwrap()
                .str(PREVIEW_SIGN_EXTENSION)
                .unwrap();
            encoder.writer_mut().extend_from_slice(&unsigned_output);
        }
        response
    }

    fn make_credential_response() -> Vec<u8> {
        make_credential_response_with(1, [0x33; 16], [0x33; 16], 0, true)
    }

    #[test]
    fn registration_wrapper_preserves_and_projects_protocol_material() {
        let response = make_credential_response();
        let registration = PreviewSignRegistration::new(
            TEST_RP_ID,
            [0x11; 32],
            response.clone(),
            Some("1656992924".to_owned()),
        )
        .unwrap();

        assert_eq!(registration.make_credential_response(), response);
        assert_eq!(registration.credential_id(), &[0xa5; 32]);
        assert_eq!(registration.signing_key_handle(), &[0x5a; 48]);
        assert_eq!(registration.signing_seed_public_key_cose(), arkg_seed_key());
        assert_eq!(registration.algorithm(), ARKG_P256_ESP256);
        assert_eq!(
            registration.policy(),
            PreviewSignPolicy::RequireUserPresence
        );
        assert_eq!(registration.aaguid(), &[0x33; 16]);
        assert_eq!(registration.token_serial_hint(), Some("1656992924"));
        let derived = registration
            .derive_arkg_p256_with_ikm(&decode_hex(ARKG_VECTOR_IKM), ARKG_VECTOR_CONTEXT)
            .unwrap();
        assert_eq!(
            derived.public_key_sec1().as_slice(),
            decode_hex(ARKG_VECTOR_PUBLIC_KEY)
        );
        assert_eq!(
            PreviewSignRegistration::from_cbor(&registration.to_cbor().unwrap()).unwrap(),
            registration
        );
    }

    #[test]
    fn registration_wrapper_has_stable_canonical_encoding() {
        let registration =
            PreviewSignRegistration::new(TEST_RP_ID, [0x11; 32], make_credential_response(), None)
                .unwrap();
        let encoded = registration.to_cbor().unwrap();
        assert_eq!(
            crate::storage::ContentReference::for_object(&encoded).digest(),
            [
                0x9d, 0x77, 0x49, 0x3f, 0x69, 0xf1, 0xd7, 0xbe, 0x32, 0x8d, 0xc6, 0x0f, 0xc4, 0x5a,
                0x1f, 0x99, 0x34, 0xa5, 0x4a, 0xdb, 0x9b, 0x96, 0x1e, 0x2e, 0xa9, 0x0a, 0x39, 0x32,
                0x9b, 0x1c, 0x11, 0xee,
            ]
        );
        assert_eq!(encoded[0], 0xa5);
        assert_eq!(
            PreviewSignRegistration::from_cbor(&encoded).unwrap(),
            registration
        );
    }

    #[test]
    fn malformed_registration_material_is_rejected() {
        assert!(matches!(
            PreviewSignRegistration::new(
                "wrong.example",
                [0x11; 32],
                make_credential_response(),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "registration is not bound to the supplied relying-party ID"
            ))
        ));
        assert!(matches!(
            PreviewSignRegistration::new(
                TEST_RP_ID,
                [0x11; 32],
                make_credential_response_with(2, [0x33; 16], [0x33; 16], 0, true),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "invalid previewSign user-interaction policy"
            ))
        ));
        assert!(matches!(
            PreviewSignRegistration::new(
                TEST_RP_ID,
                [0x11; 32],
                make_credential_response_with(1, [0x33; 16], [0x44; 16], 0, true),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "parent credential and signing key use different AAGUIDs"
            ))
        ));
        assert!(matches!(
            PreviewSignRegistration::new(
                TEST_RP_ID,
                [0x11; 32],
                make_credential_response_with(1, [0x33; 16], [0x33; 16], 1, true),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "signing-key attestation counter is not zero"
            ))
        ));
        assert!(matches!(
            PreviewSignRegistration::new(
                TEST_RP_ID,
                [0x11; 32],
                make_credential_response_with(1, [0x33; 16], [0x33; 16], 0, false),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "missing previewSign unsigned extension output"
            ))
        ));
    }

    #[test]
    fn noncanonical_or_trailing_registration_wrappers_are_rejected() {
        let registration =
            PreviewSignRegistration::new(TEST_RP_ID, [0x11; 32], make_credential_response(), None)
                .unwrap();
        let encoded = registration.to_cbor().unwrap();
        let mut noncanonical = vec![encoded[0], 0x18, 0x01];
        noncanonical.extend_from_slice(&encoded[2..]);
        assert!(matches!(
            PreviewSignRegistration::from_cbor(&noncanonical),
            Err(PreviewSignError::Malformed(
                "registration wrapper is not canonical"
            ))
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            PreviewSignRegistration::from_cbor(&trailing),
            Err(PreviewSignError::Malformed(
                "trailing registration wrapper data"
            ))
        ));
    }

    #[test]
    fn derived_key_record_round_trips_ticket_and_reference() {
        let registration =
            PreviewSignRegistration::new(TEST_RP_ID, [0x11; 32], make_credential_response(), None)
                .unwrap();
        let registration_cbor = registration.to_cbor().unwrap();
        let reference = ContentReference::for_object(&registration_cbor);
        let additional_args = [
            0xa3, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x20, 0x42, 0xaa, 0xbb, 0x21, 0x43, 0x63,
            0x74, 0x78,
        ];
        let record = PreviewSignDerivedKeyRecord::new(
            reference.clone(),
            ARKG_P256_ESP256,
            ec2_key(0x81, -7),
            Some(additional_args.to_vec()),
            Some("demo signing key".to_owned()),
        )
        .unwrap();
        let encoded = record.to_cbor().unwrap();
        let decoded = PreviewSignDerivedKeyRecord::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.registration(), &reference);
        assert_eq!(
            decoded.additional_args_cbor(),
            Some(additional_args.as_slice())
        );
        assert_eq!(decoded.label(), Some("demo signing key"));
    }

    #[test]
    fn derived_key_record_rejects_non_map_material() {
        let reference = ContentReference::for_object(&[0xa0]);
        assert!(matches!(
            PreviewSignDerivedKeyRecord::new(
                reference.clone(),
                ARKG_P256_ESP256,
                [0x40],
                None,
                None,
            ),
            Err(PreviewSignError::Malformed(
                "derived verification key is not one definite COSE_Key map"
            ))
        ));
        assert!(matches!(
            PreviewSignDerivedKeyRecord::new(
                reference,
                ARKG_P256_ESP256,
                ec2_key(0x81, -7),
                Some(vec![0x80]),
                None,
            ),
            Err(PreviewSignError::Malformed(
                "derived signing arguments are not one definite CBOR map"
            ))
        ));
    }
}
