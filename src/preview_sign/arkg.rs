//! ARKG-P256 public-key derivation for the Yubico `previewSign` protocol.

use super::{PreviewSignDerivedKeyRecord, PreviewSignError, PreviewSignRegistration};
use crate::storage::ContentReference;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::{Decoder, Encoder};
use p256::{
    FieldBytes, ProjectivePoint, PublicKey, Scalar,
    elliptic_curve::{
        Group,
        group::ff::{Field, PrimeField},
        sec1::ToSec1Point,
    },
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[cfg(feature = "mock-yubikey")]
use {p256::ecdsa::SigningKey, signature::hazmat::PrehashSigner, subtle::ConstantTimeEq};

/// Experimental COSE algorithm identifier for ESP256-split with ARKG-P256.
pub const ARKG_P256_ESP256_ALGORITHM: i64 = -65_539;
/// Experimental COSE key type for an ARKG public seed.
pub const ARKG_PUBLIC_KEY_TYPE: i64 = -65_537;
/// Experimental COSE algorithm identifier for ARKG-P256.
pub const ARKG_P256_ALGORITHM: i64 = -65_700;
/// COSE algorithm identifier for ESP256 verification.
pub const ESP256_ALGORITHM: i64 = -9;

const COSE_EC2_KEY_TYPE: i64 = 2;
const COSE_P256_CURVE: i64 = 1;
const MAX_CONTEXT_LENGTH: usize = 64;
const MIN_IKM_LENGTH: usize = 32;
const P256_POINT_LENGTH: usize = 65;
const ARKG_TICKET_LENGTH: usize = 16 + P256_POINT_LENGTH;
const HASH_TO_SCALAR_LENGTH: usize = 48;

const DERIVE_KEY_KEM_LABEL: &[u8] = b"ARKG-Derive-Key-KEM.";
const DERIVE_KEY_BL_LABEL: &[u8] = b"ARKG-Derive-Key-BL.";
const KEM_KEY_GENERATION_LABEL: &[u8] = b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256";
const ECDH_AUGMENTED_DST: &[u8] = b"ARKG-ECDH.ARKG-P256";
const KEM_MAC_LABEL: &[u8] = b"ARKG-KEM-HMAC-mac.";
const KEM_SHARED_LABEL: &[u8] = b"ARKG-KEM-HMAC-shared.";
const BLINDING_PRF_LABEL: &[u8] = b"ARKG-BL-EC.ARKG-P256";

/// A validated ARKG-P256 public seed returned by `previewSign` registration.
///
/// The seed contains two public P-256 points: a key-blinding point and a KEM
/// point. It contains no private key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArkgP256PublicSeed {
    blinding_public_key: PublicKey,
    kem_public_key: PublicKey,
}

impl ArkgP256PublicSeed {
    /// Parse and validate an ARKG-P256 public seed encoded as a COSE_Key.
    pub fn from_cose(encoded: &[u8]) -> Result<Self, PreviewSignError> {
        let mut decoder = Decoder::new(encoded);
        let count = decoder
            .map()?
            .ok_or(PreviewSignError::Malformed(
                "ARKG public seed is not a definite COSE_Key map",
            ))
            .and_then(|count| {
                usize::try_from(count)
                    .map_err(|_| PreviewSignError::Malformed("ARKG public seed is too large"))
            })?;
        let mut key_type = None;
        let mut algorithm = None;
        let mut derived_algorithm = None;
        let mut blinding_public_key = None;
        let mut kem_public_key = None;

        for _ in 0..count {
            match decoder.i64()? {
                1 if key_type.is_none() => key_type = Some(decoder.i64()?),
                1 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate ARKG public-seed key type",
                    ));
                }
                3 if algorithm.is_none() => algorithm = Some(decoder.i64()?),
                3 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate ARKG public-seed algorithm",
                    ));
                }
                -1 if blinding_public_key.is_none() => {
                    blinding_public_key = Some(parse_ec2_public_key(&mut decoder)?)
                }
                -1 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate ARKG blinding public key",
                    ));
                }
                -2 if kem_public_key.is_none() => {
                    kem_public_key = Some(parse_ec2_public_key(&mut decoder)?)
                }
                -2 => return Err(PreviewSignError::Malformed("duplicate ARKG KEM public key")),
                -3 if derived_algorithm.is_none() => derived_algorithm = Some(decoder.i64()?),
                -3 => {
                    return Err(PreviewSignError::Malformed(
                        "duplicate ARKG derived-key algorithm",
                    ));
                }
                _ => decoder.skip()?,
            }
        }

        if decoder.position() != encoded.len() {
            return Err(PreviewSignError::Malformed(
                "trailing ARKG public-seed data",
            ));
        }
        if key_type != Some(ARKG_PUBLIC_KEY_TYPE) {
            return Err(PreviewSignError::Malformed(
                "previewSign seed is not an ARKG public key",
            ));
        }
        if algorithm != Some(ARKG_P256_ALGORITHM) {
            return Err(PreviewSignError::Malformed(
                "previewSign seed does not use ARKG-P256",
            ));
        }
        if derived_algorithm.is_some_and(|value| value != ESP256_ALGORITHM) {
            return Err(PreviewSignError::Malformed(
                "ARKG seed derived-key algorithm is not ESP256",
            ));
        }

        Ok(Self {
            blinding_public_key: blinding_public_key.ok_or(PreviewSignError::Malformed(
                "missing ARKG blinding public key",
            ))?,
            kem_public_key: kem_public_key
                .ok_or(PreviewSignError::Malformed("missing ARKG KEM public key"))?,
        })
    }

    /// Derive a public key and ticket from caller-supplied input keying
    /// material.
    ///
    /// `input_keying_material` must contain at least 256 bits of entropy and
    /// should remain confidential to preserve public-key unlinkability. This
    /// deterministic entry point exists for protocol vectors and callers that
    /// already have a suitable random source; [`Self::derive`] generates it
    /// internally.
    pub fn derive_with_ikm(
        &self,
        input_keying_material: &[u8],
        context: &[u8],
    ) -> Result<ArkgP256DerivedKey, PreviewSignError> {
        if input_keying_material.len() < MIN_IKM_LENGTH {
            return Err(PreviewSignError::Malformed(
                "ARKG-P256 input keying material is shorter than 32 bytes",
            ));
        }
        if context.len() > MAX_CONTEXT_LENGTH {
            return Err(PreviewSignError::Malformed(
                "ARKG derivation context is longer than 64 bytes",
            ));
        }

        derive_public_key(self, input_keying_material, context)
    }

    /// Derive a public key and ticket using fresh operating-system randomness.
    pub fn derive(&self, context: &[u8]) -> Result<ArkgP256DerivedKey, PreviewSignError> {
        let mut input_keying_material = Zeroizing::new([0u8; MIN_IKM_LENGTH]);
        getrandom::fill(&mut *input_keying_material)
            .map_err(|_| PreviewSignError::RandomnessUnavailable)?;
        self.derive_with_ikm(&input_keying_material[..], context)
    }

    /// Return the SEC1-uncompressed key-blinding public point.
    pub fn blinding_public_key_sec1(&self) -> Box<[u8]> {
        self.blinding_public_key.to_sec1_bytes()
    }

    /// Return the SEC1-uncompressed KEM public point.
    pub fn kem_public_key_sec1(&self) -> Box<[u8]> {
        self.kem_public_key.to_sec1_bytes()
    }
}

/// The public output of one ARKG-P256 derivation.
///
/// The ticket and context are encoded into `signing_arguments_cbor` for a
/// later YubiKey assertion. The input keying material is deliberately not
/// retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArkgP256DerivedKey {
    public_key_sec1: [u8; P256_POINT_LENGTH],
    verification_key_cose: Vec<u8>,
    ticket: [u8; ARKG_TICKET_LENGTH],
    context: Vec<u8>,
    signing_arguments_cbor: Vec<u8>,
}

impl ArkgP256DerivedKey {
    /// Return the derived verification key as an uncompressed SEC1 point.
    pub fn public_key_sec1(&self) -> &[u8; P256_POINT_LENGTH] {
        &self.public_key_sec1
    }

    /// Return the derived verification key as an EC2 ESP256 COSE_Key.
    pub fn verification_key_cose(&self) -> &[u8] {
        &self.verification_key_cose
    }

    /// Return the ARKG key handle consumed by the YubiKey.
    pub fn ticket(&self) -> &[u8; ARKG_TICKET_LENGTH] {
        &self.ticket
    }

    /// Return the public domain-separation context.
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    /// Return the canonical COSE_Sign_Args map containing algorithm, ticket,
    /// and context.
    pub fn signing_arguments_cbor(&self) -> &[u8] {
        &self.signing_arguments_cbor
    }

    /// Consume this derivation and create its canonical persistence record.
    pub fn into_record(
        self,
        registration: ContentReference,
        label: Option<String>,
    ) -> Result<PreviewSignDerivedKeyRecord, PreviewSignError> {
        PreviewSignDerivedKeyRecord::new(
            registration,
            ARKG_P256_ESP256_ALGORITHM,
            self.verification_key_cose,
            Some(self.signing_arguments_cbor),
            label,
        )
    }
}

impl PreviewSignRegistration {
    /// Parse the generated signing seed as an ARKG-P256 public seed.
    pub fn arkg_p256_public_seed(&self) -> Result<ArkgP256PublicSeed, PreviewSignError> {
        if self.algorithm() != ARKG_P256_ESP256_ALGORITHM {
            return Err(PreviewSignError::Malformed(
                "previewSign registration does not use ESP256-split ARKG-P256",
            ));
        }
        ArkgP256PublicSeed::from_cose(self.signing_seed_public_key_cose())
    }

    /// Derive a public signing key using fresh operating-system randomness.
    pub fn derive_arkg_p256(&self, context: &[u8]) -> Result<ArkgP256DerivedKey, PreviewSignError> {
        self.arkg_p256_public_seed()?.derive(context)
    }

    /// Deterministically derive a public signing key from explicit input
    /// keying material.
    ///
    /// This entry point is intended for test vectors and callers that already
    /// manage at least 256 bits of confidential random input.
    pub fn derive_arkg_p256_with_ikm(
        &self,
        input_keying_material: &[u8],
        context: &[u8],
    ) -> Result<ArkgP256DerivedKey, PreviewSignError> {
        self.arkg_p256_public_seed()?
            .derive_with_ikm(input_keying_material, context)
    }
}

fn parse_ec2_public_key(decoder: &mut Decoder<'_>) -> Result<PublicKey, PreviewSignError> {
    let count = decoder
        .map()?
        .ok_or(PreviewSignError::Malformed(
            "ARKG component is not a definite EC2 COSE_Key map",
        ))
        .and_then(|count| {
            usize::try_from(count)
                .map_err(|_| PreviewSignError::Malformed("ARKG EC2 key is too large"))
        })?;
    let mut key_type = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;

    for _ in 0..count {
        match decoder.i64()? {
            1 if key_type.is_none() => key_type = Some(decoder.i64()?),
            1 => return Err(PreviewSignError::Malformed("duplicate ARKG EC2 key type")),
            -1 if curve.is_none() => curve = Some(decoder.i64()?),
            -1 => return Err(PreviewSignError::Malformed("duplicate ARKG EC2 curve")),
            -2 if x.is_none() => x = Some(copy_coordinate(decoder.bytes()?)?),
            -2 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate ARKG EC2 x-coordinate",
                ));
            }
            -3 if y.is_none() => y = Some(copy_coordinate(decoder.bytes()?)?),
            -3 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate ARKG EC2 y-coordinate",
                ));
            }
            _ => decoder.skip()?,
        }
    }

    if key_type != Some(COSE_EC2_KEY_TYPE) || curve != Some(COSE_P256_CURVE) {
        return Err(PreviewSignError::Malformed(
            "ARKG component is not an EC2 P-256 key",
        ));
    }
    let x = x.ok_or(PreviewSignError::Malformed("missing ARKG EC2 x-coordinate"))?;
    let y = y.ok_or(PreviewSignError::Malformed("missing ARKG EC2 y-coordinate"))?;
    let mut point = [0u8; P256_POINT_LENGTH];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| PreviewSignError::Malformed("ARKG component is not on the P-256 curve"))
}

fn copy_coordinate(input: &[u8]) -> Result<[u8; 32], PreviewSignError> {
    if input.len() != 32 {
        return Err(PreviewSignError::Malformed(
            "ARKG EC2 coordinate is not 32 bytes",
        ));
    }
    let mut coordinate = [0u8; 32];
    coordinate.copy_from_slice(input);
    Ok(coordinate)
}

fn derive_public_key(
    seed: &ArkgP256PublicSeed,
    input_keying_material: &[u8],
    context: &[u8],
) -> Result<ArkgP256DerivedKey, PreviewSignError> {
    let context_length = u8::try_from(context.len())
        .map_err(|_| PreviewSignError::Malformed("ARKG context length overflow"))?;
    let mut context_prime = Vec::with_capacity(1 + context.len());
    context_prime.push(context_length);
    context_prime.extend_from_slice(context);
    let context_kem = concatenate(&[DERIVE_KEY_KEM_LABEL, &context_prime]);
    let context_bl = concatenate(&[DERIVE_KEY_BL_LABEL, &context_prime]);

    let ephemeral_scalar = hash_to_scalar(input_keying_material, KEM_KEY_GENERATION_LABEL)?;
    if bool::from(ephemeral_scalar.is_zero()) {
        return Err(PreviewSignError::Malformed(
            "ARKG KEM derived the zero scalar",
        ));
    }
    let ephemeral_public_key =
        projective_to_uncompressed(ProjectivePoint::GENERATOR * ephemeral_scalar)?;
    let shared_point = seed.kem_public_key.to_projective() * ephemeral_scalar;
    let shared_point = projective_to_uncompressed(shared_point)?;
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&shared_point[1..33]);

    let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let mac_key = hkdf_sha256(&shared_secret[..], &mac_info)?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
        .map_err(|_| PreviewSignError::Malformed("ARKG HMAC key is invalid"))?;
    mac.update(&ephemeral_public_key);
    let tag = mac.finalize().into_bytes();

    let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let blinding_input = hkdf_sha256(&shared_secret[..], &shared_info)?;
    let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
    let tau = hash_to_scalar(&blinding_input[..], &blinding_dst)?;

    let derived_point = seed.blinding_public_key.to_projective() + ProjectivePoint::GENERATOR * tau;
    let public_key_sec1 = projective_to_uncompressed(derived_point)?;

    let mut ticket = [0u8; ARKG_TICKET_LENGTH];
    ticket[..16].copy_from_slice(&tag[..16]);
    ticket[16..].copy_from_slice(&ephemeral_public_key);

    let verification_key_cose = encode_verification_key(&public_key_sec1)?;
    let signing_arguments_cbor = encode_signing_arguments(&ticket, context)?;
    Ok(ArkgP256DerivedKey {
        public_key_sec1,
        verification_key_cose,
        ticket,
        context: context.to_vec(),
        signing_arguments_cbor,
    })
}

fn hkdf_sha256(
    input_keying_material: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PreviewSignError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, &mut *output)
        .map_err(|_| PreviewSignError::Malformed("ARKG HKDF output length is invalid"))?;
    Ok(output)
}

fn hash_to_scalar(message: &[u8], domain: &[u8]) -> Result<Scalar, PreviewSignError> {
    if domain.len() > u8::MAX as usize {
        return Err(PreviewSignError::Malformed(
            "ARKG hash-to-scalar domain is too long",
        ));
    }

    let mut domain_prime = Vec::with_capacity(domain.len() + 1);
    domain_prime.extend_from_slice(domain);
    domain_prime.push(
        u8::try_from(domain.len())
            .map_err(|_| PreviewSignError::Malformed("ARKG domain length overflow"))?,
    );

    let mut b0_hasher = Sha256::new();
    b0_hasher.update([0u8; 64]);
    b0_hasher.update(message);
    b0_hasher.update([0, HASH_TO_SCALAR_LENGTH as u8]);
    b0_hasher.update([0]);
    b0_hasher.update(&domain_prime);
    let b0 = b0_hasher.finalize();

    let mut b1_hasher = Sha256::new();
    b1_hasher.update(b0);
    b1_hasher.update([1]);
    b1_hasher.update(&domain_prime);
    let b1 = b1_hasher.finalize();

    let mut xored = [0u8; 32];
    for (output, (left, right)) in xored.iter_mut().zip(b0.iter().zip(b1.iter())) {
        *output = left ^ right;
    }
    let mut b2_hasher = Sha256::new();
    b2_hasher.update(xored);
    b2_hasher.update([2]);
    b2_hasher.update(&domain_prime);
    let b2 = b2_hasher.finalize();

    let mut uniform = [0u8; HASH_TO_SCALAR_LENGTH];
    uniform[..32].copy_from_slice(&b1);
    uniform[32..].copy_from_slice(&b2[..16]);
    reduce_48_bytes(&uniform)
}

fn reduce_48_bytes(uniform: &[u8; HASH_TO_SCALAR_LENGTH]) -> Result<Scalar, PreviewSignError> {
    let high = scalar_from_24_bytes(&uniform[..24])?;
    let low = scalar_from_24_bytes(&uniform[24..])?;
    let mut two_to_192_bytes = FieldBytes::default();
    two_to_192_bytes[7] = 1;
    let two_to_192 = Option::<Scalar>::from(Scalar::from_repr(two_to_192_bytes)).ok_or(
        PreviewSignError::Malformed("ARKG scalar reduction constant is invalid"),
    )?;
    Ok(high * two_to_192 + low)
}

fn scalar_from_24_bytes(input: &[u8]) -> Result<Scalar, PreviewSignError> {
    if input.len() != 24 {
        return Err(PreviewSignError::Malformed(
            "ARKG scalar reduction input has invalid length",
        ));
    }
    let mut bytes = FieldBytes::default();
    bytes[8..].copy_from_slice(input);
    Option::<Scalar>::from(Scalar::from_repr(bytes)).ok_or(PreviewSignError::Malformed(
        "ARKG scalar reduction input is out of range",
    ))
}

fn projective_to_uncompressed(
    point: ProjectivePoint,
) -> Result<[u8; P256_POINT_LENGTH], PreviewSignError> {
    if bool::from(point.is_identity()) {
        return Err(PreviewSignError::Malformed(
            "ARKG derivation produced the identity point",
        ));
    }
    let encoded = point.to_affine().to_sec1_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != P256_POINT_LENGTH {
        return Err(PreviewSignError::Malformed(
            "ARKG P-256 point has invalid length",
        ));
    }
    let mut output = [0u8; P256_POINT_LENGTH];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn encode_verification_key(
    public_key: &[u8; P256_POINT_LENGTH],
) -> Result<Vec<u8>, PreviewSignError> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(5)?
        .u8(1)?
        .i64(COSE_EC2_KEY_TYPE)?
        .u8(3)?
        .i64(ESP256_ALGORITHM)?
        .i8(-1)?
        .i64(COSE_P256_CURVE)?
        .i8(-2)?
        .bytes(&public_key[1..33])?
        .i8(-3)?
        .bytes(&public_key[33..])?;
    Ok(encoded)
}

fn encode_signing_arguments(
    ticket: &[u8; ARKG_TICKET_LENGTH],
    context: &[u8],
) -> Result<Vec<u8>, PreviewSignError> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(3)?
        .u8(3)?
        .i64(ARKG_P256_ESP256_ALGORITHM)?
        .i8(-1)?
        .bytes(ticket)?
        .i8(-2)?
        .bytes(context)?;
    Ok(encoded)
}

fn validate_verification_key(encoded: &[u8]) -> Result<(), PreviewSignError> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder.map()?.ok_or(PreviewSignError::Malformed(
        "derived verification key is not a definite map",
    ))?;
    let mut key_type = None;
    let mut algorithm = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..count {
        match decoder.i64()? {
            1 if key_type.is_none() => key_type = Some(decoder.i64()?),
            3 if algorithm.is_none() => algorithm = Some(decoder.i64()?),
            -1 if curve.is_none() => curve = Some(decoder.i64()?),
            -2 if x.is_none() => x = Some(decoder.bytes()?.to_vec()),
            -3 if y.is_none() => y = Some(decoder.bytes()?.to_vec()),
            1 | 3 | -1 | -2 | -3 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate derived verification-key field",
                ));
            }
            _ => {
                return Err(PreviewSignError::Malformed(
                    "unknown derived verification-key field",
                ));
            }
        }
    }
    if decoder.position() != encoded.len()
        || key_type != Some(COSE_EC2_KEY_TYPE)
        || algorithm != Some(ESP256_ALGORITHM)
        || curve != Some(COSE_P256_CURVE)
    {
        return Err(PreviewSignError::Malformed(
            "derived verification key is not ESP256",
        ));
    }
    let x = x.ok_or(PreviewSignError::Malformed(
        "missing derived verification-key x-coordinate",
    ))?;
    let y = y.ok_or(PreviewSignError::Malformed(
        "missing derived verification-key y-coordinate",
    ))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(PreviewSignError::Malformed(
            "derived verification-key coordinate is not 32 bytes",
        ));
    }
    let mut public_key = [0u8; P256_POINT_LENGTH];
    public_key[0] = 4;
    public_key[1..33].copy_from_slice(&x);
    public_key[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&public_key).map_err(|_| {
        PreviewSignError::Malformed("derived verification key is not on the P-256 curve")
    })?;
    if encode_verification_key(&public_key)? != encoded {
        return Err(PreviewSignError::Malformed(
            "derived verification key is not canonical",
        ));
    }
    Ok(())
}

fn validate_signing_arguments(encoded: &[u8]) -> Result<(), PreviewSignError> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder.map()?.ok_or(PreviewSignError::Malformed(
        "derived signing arguments are not a definite map",
    ))?;
    let mut algorithm = None;
    let mut ticket = None;
    let mut context = None;
    for _ in 0..count {
        match decoder.i64()? {
            3 if algorithm.is_none() => algorithm = Some(decoder.i64()?),
            -1 if ticket.is_none() => ticket = Some(decoder.bytes()?.to_vec()),
            -2 if context.is_none() => context = Some(decoder.bytes()?.to_vec()),
            3 | -1 | -2 => {
                return Err(PreviewSignError::Malformed(
                    "duplicate derived signing-argument field",
                ));
            }
            _ => {
                return Err(PreviewSignError::Malformed(
                    "unknown derived signing-argument field",
                ));
            }
        }
    }
    if decoder.position() != encoded.len() || algorithm != Some(ARKG_P256_ESP256_ALGORITHM) {
        return Err(PreviewSignError::Malformed(
            "derived signing arguments use the wrong algorithm",
        ));
    }
    let ticket: [u8; ARKG_TICKET_LENGTH] = ticket
        .ok_or(PreviewSignError::Malformed(
            "missing derived signing ticket",
        ))?
        .try_into()
        .map_err(|_| PreviewSignError::Malformed("invalid derived signing ticket length"))?;
    let context = context.ok_or(PreviewSignError::Malformed(
        "missing derived signing context",
    ))?;
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(PreviewSignError::Malformed(
            "derived signing context is too long",
        ));
    }
    PublicKey::from_sec1_bytes(&ticket[16..])
        .map_err(|_| PreviewSignError::Malformed("invalid derived signing ticket point"))?;
    if encode_signing_arguments(&ticket, &context)? != encoded {
        return Err(PreviewSignError::Malformed(
            "derived signing arguments are not canonical",
        ));
    }
    Ok(())
}

pub(super) fn validate_derived_key_record(
    registration: &PreviewSignRegistration,
    derived: &PreviewSignDerivedKeyRecord,
) -> Result<(), PreviewSignError> {
    registration.arkg_p256_public_seed()?;
    let registration_cbor = registration.to_cbor()?;
    if derived.registration() != &ContentReference::for_object(&registration_cbor) {
        return Err(PreviewSignError::Malformed(
            "derived key references a different registration",
        ));
    }
    if derived.algorithm() != ARKG_P256_ESP256_ALGORITHM
        || derived.algorithm() != registration.algorithm()
    {
        return Err(PreviewSignError::Malformed(
            "derived key uses a different signing algorithm",
        ));
    }
    validate_verification_key(derived.verification_key_cose())?;
    validate_signing_arguments(derived.additional_args_cbor().ok_or(
        PreviewSignError::Malformed("derived key is missing signing arguments"),
    )?)
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let length = parts.iter().map(|part| part.len()).sum();
    let mut output = Vec::with_capacity(length);
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

#[cfg(feature = "mock-yubikey")]
fn mock_private_scalar(bytes: [u8; 32]) -> Result<Scalar, &'static str> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or("invalid mock private scalar")
}

#[cfg(feature = "mock-yubikey")]
pub(crate) fn mock_preview_sign_seed_cose() -> Result<Vec<u8>, &'static str> {
    let blinding = mock_private_scalar([
        0xd9, 0x59, 0x50, 0x0a, 0x78, 0xcc, 0xf8, 0x50, 0xce, 0x46, 0xc8, 0x0a, 0x8c, 0x50, 0x43,
        0xc9, 0xa2, 0xe3, 0x38, 0x44, 0x23, 0x2b, 0x38, 0x29, 0xdf, 0x37, 0xd0, 0x5b, 0x30, 0x69,
        0xf4, 0x55,
    ])?;
    let kem = mock_private_scalar([
        0x74, 0xe0, 0xa4, 0xcd, 0x81, 0xca, 0x2d, 0x24, 0x24, 0x6f, 0xf7, 0x5b, 0xfd, 0x6d, 0x4f,
        0xb7, 0xf9, 0xdf, 0xc9, 0x38, 0x37, 0x26, 0x27, 0xfe, 0xb2, 0xc2, 0x34, 0x8f, 0x8b, 0x14,
        0x93, 0xb5,
    ])?;
    let blinding = projective_to_uncompressed(ProjectivePoint::GENERATOR * blinding)
        .map_err(|_| "invalid mock blinding public key")?;
    let kem = projective_to_uncompressed(ProjectivePoint::GENERATOR * kem)
        .map_err(|_| "invalid mock KEM public key")?;
    let encode_ec2 = |point: &[u8; P256_POINT_LENGTH]| -> Result<Vec<u8>, &'static str> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(5)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.u8(COSE_EC2_KEY_TYPE as u8))
            .and_then(|encoder| encoder.u8(3))
            .and_then(|encoder| encoder.i64(ESP256_ALGORITHM))
            .and_then(|encoder| encoder.i8(-1))
            .and_then(|encoder| encoder.u8(COSE_P256_CURVE as u8))
            .and_then(|encoder| encoder.i8(-2))
            .and_then(|encoder| encoder.bytes(&point[1..33]))
            .and_then(|encoder| encoder.i8(-3))
            .and_then(|encoder| encoder.bytes(&point[33..]))
            .map_err(|_| "failed to encode mock EC2 key")?;
        Ok(encoded)
    };
    let blinding = encode_ec2(&blinding)?;
    let kem = encode_ec2(&kem)?;
    let mut encoded = Vec::new();
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .map(5)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(ARKG_PUBLIC_KEY_TYPE))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.i64(ARKG_P256_ALGORITHM))
        .and_then(|encoder| encoder.i8(-1))
        .map_err(|_| "failed to encode mock ARKG seed")?;
    encoder.writer_mut().extend_from_slice(&blinding);
    encoder
        .i8(-2)
        .map_err(|_| "failed to encode mock ARKG seed")?;
    encoder.writer_mut().extend_from_slice(&kem);
    encoder
        .i8(-3)
        .and_then(|encoder| encoder.i64(ESP256_ALGORITHM))
        .map_err(|_| "failed to encode mock ARKG seed")?;
    Ok(encoded)
}

#[cfg(feature = "mock-yubikey")]
pub(crate) fn mock_preview_sign(
    signing_arguments_cbor: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let digest: &[u8; 32] = digest
        .try_into()
        .map_err(|_| "mock previewSign requires 32 bytes")?;
    let mut decoder = Decoder::new(signing_arguments_cbor);
    let count = decoder
        .map()
        .map_err(|_| "invalid signing arguments")?
        .ok_or("indefinite signing arguments")?;
    let mut algorithm = None;
    let mut ticket = None;
    let mut context = None;
    for _ in 0..count {
        match decoder.i64().map_err(|_| "invalid signing argument key")? {
            3 if algorithm.is_none() => {
                algorithm = Some(decoder.i64().map_err(|_| "invalid signing algorithm")?)
            }
            -1 if ticket.is_none() => {
                ticket = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "invalid signing ticket")?
                        .try_into()
                        .map_err(|_| "invalid signing ticket length")?,
                )
            }
            -2 if context.is_none() => {
                context = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "invalid signing context")?
                        .to_vec(),
                )
            }
            3 | -1 | -2 => return Err("duplicate signing argument"),
            _ => decoder.skip().map_err(|_| "invalid signing argument")?,
        }
    }
    if decoder.position() != signing_arguments_cbor.len()
        || algorithm != Some(ARKG_P256_ESP256_ALGORITHM)
    {
        return Err("invalid signing arguments");
    }
    let ticket: [u8; ARKG_TICKET_LENGTH] = ticket.ok_or("missing signing ticket")?;
    let context = context.ok_or("missing signing context")?;
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err("context is too long");
    }
    let kem_private = mock_private_scalar([
        0x74, 0xe0, 0xa4, 0xcd, 0x81, 0xca, 0x2d, 0x24, 0x24, 0x6f, 0xf7, 0x5b, 0xfd, 0x6d, 0x4f,
        0xb7, 0xf9, 0xdf, 0xc9, 0x38, 0x37, 0x26, 0x27, 0xfe, 0xb2, 0xc2, 0x34, 0x8f, 0x8b, 0x14,
        0x93, 0xb5,
    ])?;
    let ephemeral =
        PublicKey::from_sec1_bytes(&ticket[16..]).map_err(|_| "invalid ticket point")?;
    let shared = projective_to_uncompressed(ephemeral.to_projective() * kem_private)
        .map_err(|_| "invalid shared point")?;
    let shared_secret = Zeroizing::new(<[u8; 32]>::try_from(&shared[1..33]).map_err(|_| "shared")?);
    let mut context_prime = Vec::with_capacity(context.len() + 1);
    context_prime.push(u8::try_from(context.len()).map_err(|_| "context length")?);
    context_prime.extend_from_slice(&context);
    let context_kem = concatenate(&[DERIVE_KEY_KEM_LABEL, &context_prime]);
    let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let mac_key = hkdf_sha256(&shared_secret[..], &mac_info).map_err(|_| "HKDF failed")?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
        .map_err(|_| "invalid HMAC key")?;
    mac.update(&ticket[16..]);
    if !bool::from(ticket[..16].ct_eq(&mac.finalize().into_bytes()[..16])) {
        return Err("ticket authentication failed");
    }
    let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let blinding_input =
        hkdf_sha256(&shared_secret[..], &shared_info).map_err(|_| "HKDF failed")?;
    let context_bl = concatenate(&[DERIVE_KEY_BL_LABEL, &context_prime]);
    let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
    let tau = hash_to_scalar(&blinding_input[..], &blinding_dst).map_err(|_| "PRF failed")?;
    let blinding_private = mock_private_scalar([
        0xd9, 0x59, 0x50, 0x0a, 0x78, 0xcc, 0xf8, 0x50, 0xce, 0x46, 0xc8, 0x0a, 0x8c, 0x50, 0x43,
        0xc9, 0xa2, 0xe3, 0x38, 0x44, 0x23, 0x2b, 0x38, 0x29, 0xdf, 0x37, 0xd0, 0x5b, 0x30, 0x69,
        0xf4, 0x55,
    ])?;
    let private = blinding_private + tau;
    if bool::from(private.is_zero()) {
        return Err("derived private key is zero");
    }
    let signing_key =
        SigningKey::from_bytes(&private.to_bytes()).map_err(|_| "invalid signing key")?;
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| "signing failed")?;
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use signature::hazmat::{PrehashSigner, PrehashVerifier};
    use subtle::ConstantTimeEq;

    const BLINDING_PUBLIC_KEY: &str = "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df\
         65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7";
    const KEM_PUBLIC_KEY: &str = "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5\
         dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35";
    const IKM_A: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const EXPECTED_PUBLIC_KEY_A: &str = "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107\
         dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd";
    const EXPECTED_TICKET_A: &str = "27987995f184a44cfa548d104b0a461d\
         0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec\
         2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361";
    const BLINDING_PRIVATE_KEY: &str =
        "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455";
    const KEM_PRIVATE_KEY: &str =
        "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5";
    const EXPECTED_PRIVATE_KEY_A: &str =
        "775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7";
    const CONTEXT_A: &[u8] = b"ARKG-P256.test vectors";
    const IKM_B: &str = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    const EXPECTED_PUBLIC_KEY_B: &str = "04aed80c70cc9e2fa6b2d22db62285e6e3af7dc7426ce9846a500723d82aa60cd0\
         98168e98c4f437fc5d45986afaed5d5ce6e39de46fe4f61ae88541cb37687f8d";
    const IKM_ADDITIONAL_B: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const EXPECTED_PUBLIC_KEY_ADDITIONAL_B: &str = "04ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f\
         577f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86";
    const CONTEXT_C: &[u8] = b"ARKG-P256.alt context";
    const EXPECTED_PUBLIC_KEY_C: &str = "04ccfc29c2d0f438642dae5153ccb4eda6be6ec8a0e654a009f2953ab4b52dc1eb\
         3ffbbf91b3e46e8e68a3c38c7268b2ca42f6d19c44dd5ee15fa0d30e0c9eb326";
    const CONTEXT_ADDITIONAL_C: &[u8] = b"ARKG-P256.test vectors.0";
    const EXPECTED_PUBLIC_KEY_ADDITIONAL_C: &str = "04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61\
         dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e";

    /// Test-only model of the ARKG private side implemented by the
    /// authenticator. Keeping this beside the protocol vectors prevents
    /// private-seed operations from becoming part of the production API.
    struct MockPreviewSignAuthenticator {
        blinding_private_key: Scalar,
        kem_private_key: Scalar,
    }

    impl MockPreviewSignAuthenticator {
        fn from_vector() -> Self {
            Self {
                blinding_private_key: scalar_from_hex(BLINDING_PRIVATE_KEY),
                kem_private_key: scalar_from_hex(KEM_PRIVATE_KEY),
            }
        }

        fn derive_signing_key(
            &self,
            signing_arguments_cbor: &[u8],
        ) -> Result<SigningKey, &'static str> {
            let (ticket, context) = decode_mock_signing_arguments(signing_arguments_cbor)?;
            let ephemeral_public_key =
                PublicKey::from_sec1_bytes(&ticket[16..]).map_err(|_| "invalid ticket point")?;
            let shared_point = ephemeral_public_key.to_projective() * self.kem_private_key;
            let shared_point =
                projective_to_uncompressed(shared_point).map_err(|_| "invalid shared point")?;
            let mut shared_secret = Zeroizing::new([0u8; 32]);
            shared_secret.copy_from_slice(&shared_point[1..33]);

            let context_length =
                u8::try_from(context.len()).map_err(|_| "context length overflow")?;
            if context.len() > MAX_CONTEXT_LENGTH {
                return Err("context is too long");
            }
            let mut context_prime = Vec::with_capacity(1 + context.len());
            context_prime.push(context_length);
            context_prime.extend_from_slice(&context);
            let context_kem = concatenate(&[DERIVE_KEY_KEM_LABEL, &context_prime]);
            let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
            let mac_key = hkdf_sha256(&shared_secret[..], &mac_info).map_err(|_| "HKDF failed")?;
            let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
                .map_err(|_| "invalid HMAC key")?;
            mac.update(&ticket[16..]);
            let expected_tag = mac.finalize().into_bytes();
            if !bool::from(ticket[..16].ct_eq(&expected_tag[..16])) {
                return Err("ticket authentication failed");
            }

            let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
            let blinding_input =
                hkdf_sha256(&shared_secret[..], &shared_info).map_err(|_| "HKDF failed")?;
            let context_bl = concatenate(&[DERIVE_KEY_BL_LABEL, &context_prime]);
            let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
            let tau =
                hash_to_scalar(&blinding_input[..], &blinding_dst).map_err(|_| "PRF failed")?;
            let private_key = self.blinding_private_key + tau;
            if bool::from(private_key.is_zero()) {
                return Err("derived private key is zero");
            }

            SigningKey::from_bytes(&private_key.to_bytes()).map_err(|_| "invalid signing key")
        }

        fn sign_digest(
            &self,
            signing_arguments_cbor: &[u8],
            digest: &[u8; 32],
        ) -> Result<Signature, &'static str> {
            self.derive_signing_key(signing_arguments_cbor)?
                .sign_prehash(digest)
                .map_err(|_| "signing failed")
        }
    }

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

    fn scalar_from_hex(input: &str) -> Scalar {
        let bytes: [u8; 32] = decode_hex(input).try_into().unwrap();
        Option::<Scalar>::from(Scalar::from_repr(bytes.into())).unwrap()
    }

    fn decode_mock_signing_arguments(
        encoded: &[u8],
    ) -> Result<([u8; ARKG_TICKET_LENGTH], Vec<u8>), &'static str> {
        let mut decoder = Decoder::new(encoded);
        let count = decoder
            .map()
            .map_err(|_| "invalid signing arguments")?
            .ok_or("indefinite signing arguments")?;
        let mut algorithm = None;
        let mut ticket = None;
        let mut context = None;
        for _ in 0..count {
            match decoder.i64().map_err(|_| "invalid signing argument key")? {
                3 if algorithm.is_none() => {
                    algorithm = Some(
                        decoder
                            .i64()
                            .map_err(|_| "invalid signing argument algorithm")?,
                    )
                }
                -1 if ticket.is_none() => {
                    ticket = Some(
                        decoder
                            .bytes()
                            .map_err(|_| "invalid signing ticket")?
                            .try_into()
                            .map_err(|_| "invalid signing ticket length")?,
                    )
                }
                -2 if context.is_none() => {
                    context = Some(
                        decoder
                            .bytes()
                            .map_err(|_| "invalid signing context")?
                            .to_vec(),
                    )
                }
                3 | -1 | -2 => return Err("duplicate signing argument"),
                _ => decoder
                    .skip()
                    .map_err(|_| "invalid unknown signing argument")?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err("trailing signing argument data");
        }
        if algorithm != Some(ARKG_P256_ESP256_ALGORITHM) {
            return Err("wrong signing algorithm");
        }
        Ok((
            ticket.ok_or("missing signing ticket")?,
            context.ok_or("missing signing context")?,
        ))
    }

    fn encode_ec2(point: &[u8], coordinate_length: usize) -> Vec<u8> {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(COSE_EC2_KEY_TYPE as u8)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(ESP256_ALGORITHM)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(COSE_P256_CURVE as u8)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&point[1..1 + coordinate_length])
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&point[33..])
            .unwrap();
        encoded
    }

    fn encode_seed(key_type: i64, algorithm: i64, blinding: &[u8], kem: &[u8]) -> Vec<u8> {
        let blinding = encode_ec2(blinding, 32);
        let kem = encode_ec2(kem, 32);
        let mut encoded = Vec::new();
        let mut encoder = Encoder::new(&mut encoded);
        encoder
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .i64(key_type)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(algorithm)
            .unwrap()
            .i8(-1)
            .unwrap();
        encoder.writer_mut().extend_from_slice(&blinding);
        encoder.i8(-2).unwrap();
        encoder.writer_mut().extend_from_slice(&kem);
        encoder.i8(-3).unwrap().i64(ESP256_ALGORITHM).unwrap();
        encoded
    }

    fn vector_seed_cose() -> Vec<u8> {
        encode_seed(
            ARKG_PUBLIC_KEY_TYPE,
            ARKG_P256_ALGORITHM,
            &decode_hex(BLINDING_PUBLIC_KEY),
            &decode_hex(KEM_PUBLIC_KEY),
        )
    }

    #[test]
    fn yubico_regression_vector_matches_public_key_ticket_and_cose_arguments() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let derived = seed.derive_with_ikm(&decode_hex(IKM_A), CONTEXT_A).unwrap();

        assert_eq!(
            derived.public_key_sec1().as_slice(),
            decode_hex(EXPECTED_PUBLIC_KEY_A)
        );
        assert_eq!(derived.ticket().as_slice(), decode_hex(EXPECTED_TICKET_A));
        assert_eq!(
            derived.signing_arguments_cbor(),
            decode_hex(
                "a3033a0001000220585127987995f184a44cfa548d104b0a461d0487fc739dbc\
                 dabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea906\
                 0fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361215641524b\
                 472d503235362e7465737420766563746f7273"
            )
        );
        assert_eq!(
            derived.verification_key_cose(),
            decode_hex(
                "a5010203282001215820572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9\
                 c5b579df749647d107225820dac2a1b197cc10d2376559ad6df6bc107318d5cfb\
                 90def9f4a1f5347e086c2cd"
            )
        );
    }

    #[test]
    fn yubico_regression_vectors_separate_ikm_and_context() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let vectors = [
            (IKM_B, CONTEXT_A, EXPECTED_PUBLIC_KEY_B),
            (
                IKM_ADDITIONAL_B,
                CONTEXT_A,
                EXPECTED_PUBLIC_KEY_ADDITIONAL_B,
            ),
            (IKM_A, CONTEXT_C, EXPECTED_PUBLIC_KEY_C),
            (
                IKM_A,
                CONTEXT_ADDITIONAL_C,
                EXPECTED_PUBLIC_KEY_ADDITIONAL_C,
            ),
        ];

        for (ikm, context, expected) in vectors {
            let derived = seed.derive_with_ikm(&decode_hex(ikm), context).unwrap();
            assert_eq!(derived.public_key_sec1().as_slice(), decode_hex(expected));
        }
    }

    #[test]
    fn mock_private_side_matches_draft_private_key_and_signs() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let derived = seed.derive_with_ikm(&decode_hex(IKM_A), CONTEXT_A).unwrap();
        let authenticator = MockPreviewSignAuthenticator::from_vector();
        let signing_key = authenticator
            .derive_signing_key(derived.signing_arguments_cbor())
            .unwrap();

        assert_eq!(
            signing_key.to_bytes().as_slice(),
            decode_hex(EXPECTED_PRIVATE_KEY_A)
        );
        assert_eq!(
            signing_key.verifying_key().to_sec1_point(false).as_bytes(),
            derived.public_key_sec1()
        );

        let digest: [u8; 32] = Sha256::digest(b"pkcs11rs previewSign mock").into();
        let signature = authenticator
            .sign_digest(derived.signing_arguments_cbor(), &digest)
            .unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(derived.public_key_sec1()).unwrap();
        assert!(verifying_key.verify_prehash(&digest, &signature).is_ok());
    }

    #[test]
    fn mock_private_side_opens_random_tickets_for_context_boundaries() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let authenticator = MockPreviewSignAuthenticator::from_vector();
        let maximum_context = [0x55; MAX_CONTEXT_LENGTH];
        let contexts: [&[u8]; 3] = [b"", b"pkcs11rs", &maximum_context];

        for context in contexts {
            let derived = seed.derive(context).unwrap();
            let digest: [u8; 32] = Sha256::digest(context).into();
            let signature = authenticator
                .sign_digest(derived.signing_arguments_cbor(), &digest)
                .unwrap();
            let verifying_key = VerifyingKey::from_sec1_bytes(derived.public_key_sec1()).unwrap();
            assert!(verifying_key.verify_prehash(&digest, &signature).is_ok());
        }
    }

    #[test]
    fn mock_private_side_rejects_tampered_ticket_and_context() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let derived = seed.derive_with_ikm(&decode_hex(IKM_A), CONTEXT_A).unwrap();
        let authenticator = MockPreviewSignAuthenticator::from_vector();

        let mut tampered_ticket = *derived.ticket();
        tampered_ticket[0] ^= 0x80;
        let tampered_ticket_arguments =
            encode_signing_arguments(&tampered_ticket, derived.context()).unwrap();
        assert_eq!(
            authenticator.derive_signing_key(&tampered_ticket_arguments),
            Err("ticket authentication failed")
        );

        let wrong_context_arguments =
            encode_signing_arguments(derived.ticket(), b"wrong context").unwrap();
        assert_eq!(
            authenticator.derive_signing_key(&wrong_context_arguments),
            Err("ticket authentication failed")
        );

        let mut malformed_point_ticket = *derived.ticket();
        malformed_point_ticket[16..].fill(0);
        let malformed_point_arguments =
            encode_signing_arguments(&malformed_point_ticket, derived.context()).unwrap();
        assert_eq!(
            authenticator.derive_signing_key(&malformed_point_arguments),
            Err("invalid ticket point")
        );
    }

    #[test]
    fn random_derivations_are_valid_and_do_not_retain_ikm() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let first = seed.derive(b"pkcs11rs-demo").unwrap();
        let second = seed.derive(b"pkcs11rs-demo").unwrap();

        assert_ne!(first.public_key_sec1(), second.public_key_sec1());
        assert_ne!(first.ticket(), second.ticket());
        assert_eq!(first.context(), b"pkcs11rs-demo");
        assert!(PublicKey::from_sec1_bytes(first.public_key_sec1()).is_ok());
        assert!(PublicKey::from_sec1_bytes(second.public_key_sec1()).is_ok());
    }

    #[test]
    fn malformed_seed_metadata_and_points_are_rejected() {
        let blinding = decode_hex(BLINDING_PUBLIC_KEY);
        let kem = decode_hex(KEM_PUBLIC_KEY);
        assert!(matches!(
            ArkgP256PublicSeed::from_cose(&encode_seed(
                COSE_EC2_KEY_TYPE,
                ARKG_P256_ALGORITHM,
                &blinding,
                &kem,
            )),
            Err(PreviewSignError::Malformed(
                "previewSign seed is not an ARKG public key"
            ))
        ));
        assert!(matches!(
            ArkgP256PublicSeed::from_cose(&encode_seed(
                ARKG_PUBLIC_KEY_TYPE,
                ARKG_P256_ALGORITHM - 1,
                &blinding,
                &kem,
            )),
            Err(PreviewSignError::Malformed(
                "previewSign seed does not use ARKG-P256"
            ))
        ));

        let mut off_curve = blinding;
        off_curve[1..].fill(0);
        assert!(matches!(
            ArkgP256PublicSeed::from_cose(&encode_seed(
                ARKG_PUBLIC_KEY_TYPE,
                ARKG_P256_ALGORITHM,
                &off_curve,
                &kem,
            )),
            Err(PreviewSignError::Malformed(
                "ARKG component is not on the P-256 curve"
            ))
        ));
    }

    #[test]
    fn malformed_coordinate_context_and_ikm_are_rejected() {
        let blinding = decode_hex(BLINDING_PUBLIC_KEY);
        let kem = decode_hex(KEM_PUBLIC_KEY);
        let short_point = encode_ec2(&blinding, 31);
        let valid_kem = encode_ec2(&kem, 32);
        let mut malformed_seed = Vec::new();
        let mut encoder = Encoder::new(&mut malformed_seed);
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
        encoder.writer_mut().extend_from_slice(&short_point);
        encoder.i8(-2).unwrap();
        encoder.writer_mut().extend_from_slice(&valid_kem);
        assert!(matches!(
            ArkgP256PublicSeed::from_cose(&malformed_seed),
            Err(PreviewSignError::Malformed(
                "ARKG EC2 coordinate is not 32 bytes"
            ))
        ));

        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        assert!(matches!(
            seed.derive_with_ikm(&[0u8; 31], b""),
            Err(PreviewSignError::Malformed(
                "ARKG-P256 input keying material is shorter than 32 bytes"
            ))
        ));
        assert!(matches!(
            seed.derive_with_ikm(&[0u8; 32], &[0u8; 65]),
            Err(PreviewSignError::Malformed(
                "ARKG derivation context is longer than 64 bytes"
            ))
        ));
    }

    #[test]
    fn derived_output_becomes_a_canonical_persistence_record() {
        let seed = ArkgP256PublicSeed::from_cose(&vector_seed_cose()).unwrap();
        let derived = seed.derive_with_ikm(&decode_hex(IKM_A), CONTEXT_A).unwrap();
        let reference = ContentReference::for_object(b"registration");
        let record = derived
            .into_record(reference.clone(), Some("vector A".to_owned()))
            .unwrap();
        let round_trip =
            PreviewSignDerivedKeyRecord::from_cbor(&record.to_cbor().unwrap()).unwrap();

        assert_eq!(round_trip, record);
        assert_eq!(record.registration(), &reference);
        assert_eq!(record.algorithm(), ARKG_P256_ESP256_ALGORITHM);
        assert_eq!(record.label(), Some("vector A"));
    }
}
