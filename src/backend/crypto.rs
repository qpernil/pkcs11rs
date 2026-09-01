use crate::*;
use software_key_core::rsa_signing::{
    RsaHashAlgorithm as SharedRsaHashAlgorithm, RsaPssParameters as SharedRsaPssParameters,
};
use software_key_core::software_signing::{
    EcCurve as SharedEcCurve, SignatureScheme as SharedSigningAlgorithm,
    SoftwarePublicKey as SharedPublicKey, SoftwareSigningError,
};

pub(crate) fn openpgp_sign_mechanism_supported(
    algorithm: OpenPgpAlgorithm,
    mechanism: CK_MECHANISM_TYPE,
) -> bool {
    match algorithm {
        OpenPgpAlgorithm::Rsa { .. } => matches!(
            mechanism,
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
        ),
        OpenPgpAlgorithm::Ecdsa(_) => {
            matches!(
                mechanism,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
            )
        }
        OpenPgpAlgorithm::Ed25519 => mechanism == CKM_EDDSA as CK_MECHANISM_TYPE,
        OpenPgpAlgorithm::Ecdh(_) => false,
    }
}

pub(crate) fn openpgp_ec_coordinate_length(algorithm: OpenPgpAlgorithm) -> Option<usize> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => curve.coordinate_length(),
        OpenPgpAlgorithm::Ed25519 => Some(32),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

pub(crate) fn openpgp_ec_params(algorithm: OpenPgpAlgorithm) -> Option<Vec<u8>> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => {
            Some(curve.oid().to_vec())
        }
        OpenPgpAlgorithm::Ed25519 => Some(openpgp::Curve::Ed25519.oid().to_vec()),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

pub(crate) fn openpgp_signature(
    signature: &[u8],
    coordinate_length: usize,
) -> Result<Vec<u8>, Error> {
    if signature.len() == coordinate_length * 2 {
        return Ok(signature.to_vec());
    }
    piv_ecdsa_signature(signature, coordinate_length)
}

pub(crate) fn piv_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<MessageDigest> {
    match mechanism {
        x if x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha1())
        }
        x if x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha224())
        }
        x if x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha256())
        }
        x if x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha384())
        }
        x if x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha512())
        }
        x if x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_224())
        }
        x if x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_256())
        }
        x if x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_384())
        }
        x if x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_512())
        }
        _ => None,
    }
}

pub(crate) fn piv_is_pss_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
}

pub(crate) fn piv_is_hashed_rsa_pkcs(mechanism: CK_MECHANISM_TYPE) -> bool {
    piv_hash_mechanism(mechanism).is_some()
        && !piv_is_pss_mechanism(mechanism)
        && mechanism != CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
        && mechanism < CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
}

pub(crate) fn piv_is_hashed_ecdsa(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
}

pub(crate) fn piv_digest_info(mechanism: CK_MECHANISM_TYPE, digest: &[u8]) -> Option<Vec<u8>> {
    if !HASHED_RSA_PKCS_MECHANISMS.contains(&mechanism) {
        return None;
    }
    software_key_core::rsa_signing::digest_info(piv_hash_mechanism(mechanism)?, digest).ok()
}

pub(crate) fn digest_for_hash_mechanism(
    mechanism: CK_MECHANISM_TYPE,
) -> Result<MessageDigest, Error> {
    match mechanism {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha1()),
        x if x == CKM_SHA224 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha224()),
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha256()),
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha384()),
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha512()),
        x if x == CKM_SHA3_224 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_224()),
        x if x == CKM_SHA3_256 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_256()),
        x if x == CKM_SHA3_384 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_384()),
        x if x == CKM_SHA3_512 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_512()),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

pub(crate) fn pss_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Result<CK_MECHANISM_TYPE, Error> {
    match mechanism {
        x if x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE => Ok(CKM_SHA_1 as CK_MECHANISM_TYPE),
        x if x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA224 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA256 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA384 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA512 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_224 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_256 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_384 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_512 as CK_MECHANISM_TYPE)
        }
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

pub(crate) fn mgf_digest(mgf: u8, hash: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
    match mgf {
        0 => digest_for_hash_mechanism(hash),
        32 => Ok(MessageDigest::sha1()),
        33 => Ok(MessageDigest::sha256()),
        34 => Ok(MessageDigest::sha384()),
        35 => Ok(MessageDigest::sha512()),
        36 => Ok(MessageDigest::sha224()),
        37 => Ok(MessageDigest::sha3_224()),
        38 => Ok(MessageDigest::sha3_256()),
        39 => Ok(MessageDigest::sha3_384()),
        40 => Ok(MessageDigest::sha3_512()),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

pub(crate) fn shared_rsa_hash_algorithm(
    mechanism: CK_MECHANISM_TYPE,
) -> Result<SharedRsaHashAlgorithm, Error> {
    match mechanism {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE
            || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha1)
        }
        x if x == CKM_SHA224 as CK_MECHANISM_TYPE
            || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha224)
        }
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE
            || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha256)
        }
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE
            || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha384)
        }
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE
            || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha512)
        }
        x if x == CKM_SHA3_224 as CK_MECHANISM_TYPE
            || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha3_224)
        }
        x if x == CKM_SHA3_256 as CK_MECHANISM_TYPE
            || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha3_256)
        }
        x if x == CKM_SHA3_384 as CK_MECHANISM_TYPE
            || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha3_384)
        }
        x if x == CKM_SHA3_512 as CK_MECHANISM_TYPE
            || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE =>
        {
            Ok(SharedRsaHashAlgorithm::Sha3_512)
        }
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

pub(crate) fn shared_rsa_pss_parameters(
    pss: (u8, u16, CK_MECHANISM_TYPE),
) -> Result<SharedRsaPssParameters, Error> {
    let (mgf, salt_length, hash_mechanism) = pss;
    let hash = shared_rsa_hash_algorithm(hash_mechanism)?;
    let mgf_hash = match mgf {
        0 => hash,
        32 => SharedRsaHashAlgorithm::Sha1,
        33 => SharedRsaHashAlgorithm::Sha256,
        34 => SharedRsaHashAlgorithm::Sha384,
        35 => SharedRsaHashAlgorithm::Sha512,
        36 => SharedRsaHashAlgorithm::Sha224,
        37 => SharedRsaHashAlgorithm::Sha3_224,
        38 => SharedRsaHashAlgorithm::Sha3_256,
        39 => SharedRsaHashAlgorithm::Sha3_384,
        40 => SharedRsaHashAlgorithm::Sha3_512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    Ok(SharedRsaPssParameters {
        hash,
        mgf_hash,
        salt_length: usize::from(salt_length),
    })
}

pub(crate) fn encode_rsa_pss(
    digest: &[u8],
    modulus_size: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<Vec<u8>, Error> {
    let parameters = software_key_core::rsa_signing::RsaPssParameters {
        hash: digest_for_hash_mechanism(hash_mechanism)?,
        mgf_hash: mgf_digest(mgf_code, hash_mechanism)?,
        salt_length,
    };
    software_key_core::rsa_signing::pss_encoded_digest(modulus_size * 8, parameters, digest)
        .map_err(|error| match error {
            software_key_core::rsa_signing::RsaConstructionError::RandomnessUnavailable => {
                CKR_RANDOM_NO_RNG.into()
            }
            software_key_core::rsa_signing::RsaConstructionError::InvalidKey => {
                CKR_KEY_SIZE_RANGE.into()
            }
            _ => CKR_DATA_LEN_RANGE.into(),
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EcCurve {
    P224,
    P256,
    P384,
    P521,
    K256,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
}

pub(crate) fn ec_curve_parameters(curve: EcCurve) -> &'static [u8] {
    match curve {
        EcCurve::P224 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21],
        EcCurve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        EcCurve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        EcCurve::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        EcCurve::K256 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
        EcCurve::BrainpoolP256 => &[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
        ],
        EcCurve::BrainpoolP384 => &[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
        ],
        EcCurve::BrainpoolP512 => &[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
        ],
    }
}

pub(crate) struct EcParameters {
    #[cfg(test)]
    pub(crate) p: BigUint,
    #[cfg(test)]
    a: BigUint,
    #[cfg(test)]
    pub(crate) gx: BigUint,
    #[cfg(test)]
    pub(crate) gy: BigUint,
    pub(crate) n: BigUint,
    pub(crate) coordinate_length: usize,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct EcPointValue {
    pub(crate) x: BigUint,
    pub(crate) y: BigUint,
    pub(crate) z: BigUint,
}

pub(crate) fn biguint_hex(value: &str) -> Result<BigUint, Error> {
    BigUint::parse_bytes(value.as_bytes(), 16).ok_or_else(|| CKR_FUNCTION_FAILED.into())
}

pub(crate) fn ec_parameters(curve: EcCurve) -> Result<EcParameters, Error> {
    let values = match curve {
        EcCurve::P224 => (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
            28,
        ),
        EcCurve::P256 => (
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            32,
        ),
        EcCurve::P384 => (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            48,
        ),
        EcCurve::P521 => (
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            66,
        ),
        EcCurve::K256 => (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            "0",
            "7",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            32,
        ),
        EcCurve::BrainpoolP256 => (
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
            32,
        ),
        EcCurve::BrainpoolP384 => (
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
            48,
        ),
        EcCurve::BrainpoolP512 => (
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
            64,
        ),
    };
    Ok(EcParameters {
        #[cfg(test)]
        p: biguint_hex(values.0)?,
        #[cfg(test)]
        a: biguint_hex(values.1)?,
        #[cfg(test)]
        gx: biguint_hex(values.3)?,
        #[cfg(test)]
        gy: biguint_hex(values.4)?,
        n: biguint_hex(values.5)?,
        coordinate_length: values.6,
    })
}

#[cfg(test)]
pub(crate) fn mod_sub(left: &BigUint, right: &BigUint, modulus: &BigUint) -> BigUint {
    if left >= right {
        (left - right) % modulus
    } else {
        modulus - ((right - left) % modulus)
    }
}

#[cfg(test)]
pub(crate) fn ec_infinity() -> EcPointValue {
    EcPointValue {
        x: BigUint::from(0u8),
        y: BigUint::from(1u8),
        z: BigUint::from(0u8),
    }
}

#[cfg(test)]
pub(crate) fn ec_double(point: &EcPointValue, parameters: &EcParameters) -> EcPointValue {
    let zero = BigUint::from(0u8);
    if point.z == zero || point.y == zero {
        return ec_infinity();
    }
    let p = &parameters.p;
    let xx = (&point.x * &point.x) % p;
    let yy = (&point.y * &point.y) % p;
    let yyyy = (&yy * &yy) % p;
    let zz = (&point.z * &point.z) % p;
    let x_plus_yy = (&point.x + &yy) % p;
    let mut s = mod_sub(&((&x_plus_yy * &x_plus_yy) % p), &xx, p);
    s = mod_sub(&s, &yyyy, p);
    s = (&s * BigUint::from(2u8)) % p;
    let zz_squared = (&zz * &zz) % p;
    let m = ((&xx * BigUint::from(3u8)) + (&parameters.a * zz_squared)) % p;
    let t = (&m * &m) % p;
    let x = mod_sub(&t, &((&s * BigUint::from(2u8)) % p), p);
    let mut y = (&m * mod_sub(&s, &x, p)) % p;
    y = mod_sub(&y, &((&yyyy * BigUint::from(8u8)) % p), p);
    let z = ((&point.y * &point.z) * BigUint::from(2u8)) % p;
    EcPointValue { x, y, z }
}

#[cfg(test)]
pub(crate) fn ec_add(
    left: &EcPointValue,
    right: &EcPointValue,
    parameters: &EcParameters,
) -> EcPointValue {
    let zero = BigUint::from(0u8);
    if left.z == zero {
        return right.clone();
    }
    if right.z == zero {
        return left.clone();
    }
    let p = &parameters.p;
    let z1z1 = (&left.z * &left.z) % p;
    let z2z2 = (&right.z * &right.z) % p;
    let u1 = (&left.x * &z2z2) % p;
    let u2 = (&right.x * &z1z1) % p;
    let s1 = ((&left.y * &right.z) * &z2z2) % p;
    let s2 = ((&right.y * &left.z) * &z1z1) % p;
    if u1 == u2 {
        return if s1 == s2 {
            ec_double(left, parameters)
        } else {
            ec_infinity()
        };
    }
    let h = mod_sub(&u2, &u1, p);
    let two_h = (&h * BigUint::from(2u8)) % p;
    let i = (&two_h * &two_h) % p;
    let j = (&h * &i) % p;
    let r = (mod_sub(&s2, &s1, p) * BigUint::from(2u8)) % p;
    let v = (&u1 * &i) % p;
    let mut x = mod_sub(&((&r * &r) % p), &j, p);
    x = mod_sub(&x, &((&v * BigUint::from(2u8)) % p), p);
    let mut y = (&r * mod_sub(&v, &x, p)) % p;
    y = mod_sub(&y, &(((&s1 * &j) * BigUint::from(2u8)) % p), p);
    let z_sum = (&left.z + &right.z) % p;
    let mut z = mod_sub(&((&z_sum * &z_sum) % p), &z1z1, p);
    z = mod_sub(&z, &z2z2, p);
    z = (&z * &h) % p;
    EcPointValue { x, y, z }
}

#[cfg(test)]
pub(crate) fn ec_multiply(
    scalar: &BigUint,
    point: &EcPointValue,
    parameters: &EcParameters,
) -> EcPointValue {
    let mut result = ec_infinity();
    for byte in scalar.to_bytes_be() {
        for bit in (0..8).rev() {
            result = ec_double(&result, parameters);
            if byte & (1 << bit) != 0 {
                result = ec_add(&result, point, parameters);
            }
        }
    }
    result
}

fn shared_ec_profile(curve: EcCurve) -> (SharedEcCurve, SharedSigningAlgorithm) {
    match curve {
        EcCurve::P224 => (SharedEcCurve::P224, SharedSigningAlgorithm::EcdsaP224Sha224),
        EcCurve::P256 => (SharedEcCurve::P256, SharedSigningAlgorithm::EcdsaP256Sha256),
        EcCurve::P384 => (SharedEcCurve::P384, SharedSigningAlgorithm::EcdsaP384Sha384),
        EcCurve::P521 => (SharedEcCurve::P521, SharedSigningAlgorithm::EcdsaP521Sha512),
        EcCurve::K256 => (
            SharedEcCurve::Secp256k1,
            SharedSigningAlgorithm::EcdsaSecp256k1Sha256,
        ),
        EcCurve::BrainpoolP256 => (
            SharedEcCurve::BrainpoolP256,
            SharedSigningAlgorithm::EcdsaBrainpoolP256Sha256,
        ),
        EcCurve::BrainpoolP384 => (
            SharedEcCurve::BrainpoolP384,
            SharedSigningAlgorithm::EcdsaBrainpoolP384Sha384,
        ),
        EcCurve::BrainpoolP512 => (
            SharedEcCurve::BrainpoolP512,
            SharedSigningAlgorithm::EcdsaBrainpoolP512Sha512,
        ),
    }
}

pub(crate) fn verify_ecdsa(
    curve: EcCurve,
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let parameters = ec_parameters(curve)?;
    if public_key.len() != parameters.coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    if signature.len() != parameters.coordinate_length * 2 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let (curve, algorithm) = shared_ec_profile(curve);
    let mut uncompressed = Vec::with_capacity(1 + public_key.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public_key);
    SharedPublicKey::Ec {
        curve,
        uncompressed,
    }
    .verify_prehash(algorithm, digest, signature)
    .map_err(shared_verification_error)
}

pub(crate) fn validate_ec_public_point(curve: EcCurve, point: &[u8]) -> Result<(), Error> {
    let parameters = ec_parameters(curve)?;
    if point.len() != 1 + parameters.coordinate_length * 2 || point[0] != 0x04 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let (curve, _) = shared_ec_profile(curve);
    SharedPublicKey::Ec {
        curve,
        uncompressed: point.to_vec(),
    }
    .validate()
    .map_err(shared_verification_error)
}

pub(crate) fn ec_curve_from_parameters(parameters: &[u8]) -> Result<EcCurve, Error> {
    [
        EcCurve::P224,
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::K256,
        EcCurve::BrainpoolP256,
        EcCurve::BrainpoolP384,
        EcCurve::BrainpoolP512,
    ]
    .into_iter()
    .find(|curve| parameters == ec_curve_parameters(*curve))
    .ok_or(CKR_KEY_TYPE_INCONSISTENT.into())
}

pub(crate) fn verify_ed25519(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
    SharedPublicKey::Ed25519(key_bytes)
        .verify_message(SharedSigningAlgorithm::Ed25519, data, signature)
        .map_err(shared_verification_error)
}

fn shared_verification_error(error: SoftwareSigningError) -> Error {
    match error {
        SoftwareSigningError::InvalidSignature => CKR_SIGNATURE_INVALID.into(),
        SoftwareSigningError::AlgorithmMismatch
        | SoftwareSigningError::InvalidPublicKey
        | SoftwareSigningError::InvalidPrivateKey => CKR_KEY_TYPE_INCONSISTENT.into(),
        SoftwareSigningError::RandomnessUnavailable => CKR_RANDOM_NO_RNG.into(),
        SoftwareSigningError::SigningFailed => CKR_FUNCTION_FAILED.into(),
    }
}

pub(crate) fn ecdsa_der_to_raw(
    signature: &[u8],
    coordinate_length: usize,
) -> Result<Vec<u8>, Error> {
    software_key_core::software_signing::ecdsa_signature_from_der(signature, coordinate_length)
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

pub(crate) fn rsa_operation(
    input: &[u8],
    exponent: &BigUint,
    modulus: &BigUint,
    size: usize,
) -> Result<Vec<u8>, Error> {
    if input.len() > size {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let value = BigUint::from_bytes_be(input);
    if &value >= modulus {
        return Err(CKR_DATA_INVALID.into());
    }
    let encoded = value.modpow(exponent, modulus).to_bytes_be();
    let mut output = vec![0; size];
    output[size - encoded.len()..].copy_from_slice(&encoded);
    Ok(output)
}

pub(crate) fn rsa_public_operation(key: &RsaPublicKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    rsa_operation(input, key.e(), key.n(), key.size())
}

pub(crate) fn rsa_private_operation(key: &RsaPrivateKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    rsa_operation(input, key.d(), key.n(), key.size())
}

pub(crate) fn rsa_pkcs1_encrypt(key: &RsaPublicKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let encoded =
        software_key_core::rsa_signing::rsa_pkcs1v15_pad(input, key.size()).map_err(|error| {
            match error {
                software_key_core::rsa_signing::RsaConstructionError::RandomnessUnavailable => {
                    Error::from(CKR_RANDOM_NO_RNG)
                }
                _ => Error::from(CKR_DATA_LEN_RANGE),
            }
        })?;
    rsa_public_operation(key, &encoded)
}

#[cfg(test)]
pub(crate) fn rsa_pkcs1_sign(key: &RsaPrivateKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let encoded = software_key_core::rsa_signing::pkcs1v15_encoded_payload(key.size(), input)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    rsa_private_operation(key, &encoded)
}

#[cfg(test)]
pub(crate) fn verify_rsa_pss(
    encoded: &[u8],
    digest: &[u8],
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<bool, Error> {
    let parameters = software_key_core::rsa_signing::RsaPssParameters {
        hash: digest_for_hash_mechanism(hash_mechanism)?,
        mgf_hash: mgf_digest(mgf_code, hash_mechanism)?,
        salt_length,
    };
    Ok(software_key_core::rsa_signing::verify_pss_encoded_digest(
        encoded,
        encoded.len() * 8,
        parameters,
        digest,
    )
    .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_and_openpgp_composite_sign_admission_is_exact() {
        for mechanism in HASHED_RSA_PKCS_MECHANISMS
            .into_iter()
            .chain(HASHED_RSA_PSS_MECHANISMS)
            .chain(HASHED_ECDSA_MECHANISMS)
        {
            let rsa = HASHED_RSA_PKCS_MECHANISMS.contains(&mechanism)
                || HASHED_RSA_PSS_MECHANISMS.contains(&mechanism);
            let ecdsa = HASHED_ECDSA_MECHANISMS.contains(&mechanism);
            assert_eq!(
                piv_sign_mechanism_supported(piv::Algorithm::Rsa2048, mechanism),
                rsa
            );
            assert_eq!(
                piv_sign_mechanism_supported(piv::Algorithm::EccP256, mechanism),
                ecdsa
            );

            let openpgp_rsa = [
                CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE,
                CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE,
                CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE,
            ]
            .contains(&mechanism);
            let openpgp_ecdsa = [
                CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
                CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
                CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
            ]
            .contains(&mechanism);
            assert_eq!(
                openpgp_sign_mechanism_supported(OpenPgpAlgorithm::Rsa { bits: 2048 }, mechanism,),
                openpgp_rsa
            );
            assert_eq!(
                openpgp_sign_mechanism_supported(
                    OpenPgpAlgorithm::Ecdsa(openpgp::Curve::P256),
                    mechanism,
                ),
                openpgp_ecdsa
            );
        }
    }
}
