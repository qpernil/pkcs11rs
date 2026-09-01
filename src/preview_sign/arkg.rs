//! ARKG-P256 public-key derivation for the Yubico `previewSign` protocol.

use super::{PreviewSignDerivedKeyRecord, PreviewSignError, PreviewSignRegistration};
use crate::storage::ContentReference;
use minicbor::{Decoder, Encoder};
use software_key_core::arkg::{
    ARKG_P256_MAX_CONTEXT_LENGTH as MAX_CONTEXT_LENGTH, ARKG_P256_MIN_IKM_LENGTH as MIN_IKM_LENGTH,
    ARKG_P256_POINT_LENGTH as P256_POINT_LENGTH, ARKG_P256_TICKET_LENGTH as ARKG_TICKET_LENGTH,
    arkg_p256_derive_public,
};
use software_key_core::software_signing::{EcCurve, SoftwarePublicKey};
use zeroize::Zeroizing;
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

/// A validated ARKG-P256 public seed returned by `previewSign` registration.
///
/// The seed contains two public P-256 points: a key-blinding point and a KEM
/// point. It contains no private key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArkgP256PublicSeed {
    blinding_public_key: [u8; P256_POINT_LENGTH],
    kem_public_key: [u8; P256_POINT_LENGTH],
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
        self.blinding_public_key.as_slice().into()
    }

    /// Return the SEC1-uncompressed KEM public point.
    pub fn kem_public_key_sec1(&self) -> Box<[u8]> {
        self.kem_public_key.as_slice().into()
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

fn parse_ec2_public_key(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; P256_POINT_LENGTH], PreviewSignError> {
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
    validate_p256_point(&point)
        .map_err(|_| PreviewSignError::Malformed("ARKG component is not on the P-256 curve"))?;
    Ok(point)
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
    let derived = arkg_p256_derive_public(
        &seed.blinding_public_key,
        &seed.kem_public_key,
        input_keying_material,
        context,
    )
    .map_err(|error| {
        PreviewSignError::Malformed(match error {
            software_key_core::arkg::ArkgP256Error::ContextTooLong => {
                "ARKG derivation context is longer than 64 bytes"
            }
            software_key_core::arkg::ArkgP256Error::InputKeyingMaterialTooShort => {
                "ARKG-P256 input keying material is shorter than 32 bytes"
            }
            _ => "ARKG-P256 public derivation failed",
        })
    })?;
    let public_key_sec1 = derived.public_key;
    let ticket = derived.ticket;

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
    validate_p256_point(&public_key).map_err(|_| {
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
    validate_p256_point(&ticket[16..])
        .map_err(|_| PreviewSignError::Malformed("invalid derived signing ticket point"))?;
    if encode_signing_arguments(&ticket, &context)? != encoded {
        return Err(PreviewSignError::Malformed(
            "derived signing arguments are not canonical",
        ));
    }
    Ok(())
}

fn validate_p256_point(point: &[u8]) -> Result<(), ()> {
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: point.to_vec(),
    }
    .validate()
    .map_err(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        PublicKey,
        ecdsa::{Signature, SigningKey, VerifyingKey},
    };
    use signature::hazmat::{PrehashSigner, PrehashVerifier};
    use software_key_core::arkg::{ArkgP256Error, arkg_p256_derive_private};

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
        blinding_private_key: [u8; 32],
        kem_private_key: [u8; 32],
    }

    impl MockPreviewSignAuthenticator {
        fn from_vector() -> Self {
            Self {
                blinding_private_key: decode_hex(BLINDING_PRIVATE_KEY).try_into().unwrap(),
                kem_private_key: decode_hex(KEM_PRIVATE_KEY).try_into().unwrap(),
            }
        }

        fn derive_signing_key(
            &self,
            signing_arguments_cbor: &[u8],
        ) -> Result<SigningKey, &'static str> {
            let (ticket, context) = decode_mock_signing_arguments(signing_arguments_cbor)?;
            let private_key = arkg_p256_derive_private(
                &self.blinding_private_key,
                &self.kem_private_key,
                &ticket,
                &context,
            )
            .map_err(|error| match error {
                ArkgP256Error::TicketAuthenticationFailed => "ticket authentication failed",
                ArkgP256Error::InvalidTicketPoint => "invalid ticket point",
                _ => "private derivation failed",
            })?;
            SigningKey::from_slice(&private_key[..]).map_err(|_| "invalid signing key")
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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
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

        let digest: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
            .digest(b"pkcs11rs previewSign mock")
            .try_into()
            .unwrap();
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
            let digest: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
                .digest(context)
                .try_into()
                .unwrap();
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
