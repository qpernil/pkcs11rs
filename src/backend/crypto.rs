fn openpgp_sign_mechanism_supported(
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

fn openpgp_ec_coordinate_length(algorithm: OpenPgpAlgorithm) -> Option<usize> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => curve.coordinate_length(),
        OpenPgpAlgorithm::Ed25519 => Some(32),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

fn openpgp_ec_params(algorithm: OpenPgpAlgorithm) -> Option<Vec<u8>> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => {
            Some(curve.oid().to_vec())
        }
        OpenPgpAlgorithm::Ed25519 => Some(openpgp::Curve::Ed25519.oid().to_vec()),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

fn openpgp_signature(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    if signature.len() == coordinate_length * 2 {
        return Ok(signature.to_vec());
    }
    piv_ecdsa_signature(signature, coordinate_length)
}

fn piv_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<MessageDigest> {
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

fn piv_is_pss_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
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

fn piv_is_hashed_rsa_pkcs(mechanism: CK_MECHANISM_TYPE) -> bool {
    piv_hash_mechanism(mechanism).is_some()
        && !piv_is_pss_mechanism(mechanism)
        && mechanism != CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
        && mechanism < CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
}

fn piv_is_hashed_ecdsa(mechanism: CK_MECHANISM_TYPE) -> bool {
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

fn piv_digest_info(mechanism: CK_MECHANISM_TYPE, digest: &[u8]) -> Option<Vec<u8>> {
    let prefix: &[u8] = match mechanism {
        x if x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
        ],
        x if x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00,
        ],
        x if x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00,
        ],
        x if x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00,
        ],
        x if x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x07, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00,
        ],
        _ => return None,
    };
    let mut result = prefix.to_vec();
    result.extend_from_slice(digest);
    Some(result)
}

fn digest_for_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
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

fn pss_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Result<CK_MECHANISM_TYPE, Error> {
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

fn mgf_digest(mgf: u8, hash: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
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

fn mgf1(seed: &[u8], length: usize, digest: MessageDigest) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(length);
    let mut counter = 0u32;
    while output.len() < length {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        output.extend_from_slice(hash(digest, &input)?.as_ref());
        counter = counter.checked_add(1).ok_or(CKR_DATA_LEN_RANGE)?;
    }
    output.truncate(length);
    Ok(output)
}

fn encode_rsa_pss(
    digest: &[u8],
    modulus_size: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<Vec<u8>, Error> {
    let hash_digest = digest_for_hash_mechanism(hash_mechanism)?;
    if digest.len() != hash_digest.size() || salt_length > modulus_size {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let em_bits = modulus_size
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(1))
        .ok_or(CKR_KEY_SIZE_RANGE)?;
    let em_len = em_bits.div_ceil(8);
    if em_len < hash_digest.size() + salt_length + 2 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut salt = vec![0; salt_length];
    getrandom::fill(&mut salt).map_err(|_| CKR_RANDOM_NO_RNG)?;
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    let h = hash(hash_digest, &m_prime)?;
    let mut db = vec![0; em_len - salt_length - h.len() - 2];
    db.push(1);
    db.extend_from_slice(&salt);
    let mask = mgf1(
        h.as_ref(),
        em_len - h.len() - 1,
        mgf_digest(mgf_code, hash_mechanism)?,
    )?;
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    let mut encoded = db;
    encoded.extend_from_slice(h.as_ref());
    encoded.push(0xbc);
    if encoded.len() < modulus_size {
        let mut padded = vec![0; modulus_size - encoded.len()];
        padded.extend_from_slice(&encoded);
        encoded = padded;
    }
    Ok(encoded)
}

#[derive(Clone, Copy)]
enum EcCurve {
    P224,
    P256,
    P384,
    P521,
    K256,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
}

struct EcParameters {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    gx: BigUint,
    gy: BigUint,
    n: BigUint,
    coordinate_length: usize,
}

#[derive(Clone)]
struct EcPointValue {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

fn biguint_hex(value: &str) -> BigUint {
    BigUint::parse_bytes(value.as_bytes(), 16).expect("valid embedded EC parameter")
}

fn ec_parameters(curve: EcCurve) -> EcParameters {
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
    EcParameters {
        p: biguint_hex(values.0),
        a: biguint_hex(values.1),
        b: biguint_hex(values.2),
        gx: biguint_hex(values.3),
        gy: biguint_hex(values.4),
        n: biguint_hex(values.5),
        coordinate_length: values.6,
    }
}

fn mod_sub(left: &BigUint, right: &BigUint, modulus: &BigUint) -> BigUint {
    if left >= right {
        (left - right) % modulus
    } else {
        modulus - ((right - left) % modulus)
    }
}

fn ec_infinity() -> EcPointValue {
    EcPointValue {
        x: BigUint::from(0u8),
        y: BigUint::from(1u8),
        z: BigUint::from(0u8),
    }
}

fn ec_double(point: &EcPointValue, parameters: &EcParameters) -> EcPointValue {
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

fn ec_add(left: &EcPointValue, right: &EcPointValue, parameters: &EcParameters) -> EcPointValue {
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

fn ec_multiply(
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

fn verify_ecdsa(
    curve: EcCurve,
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let parameters = ec_parameters(curve);
    let coordinate_length = parameters.coordinate_length;
    if public_key.len() != coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    if signature.len() != coordinate_length * 2 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let q = EcPointValue {
        x: BigUint::from_bytes_be(&public_key[..coordinate_length]),
        y: BigUint::from_bytes_be(&public_key[coordinate_length..]),
        z: BigUint::from(1u8),
    };
    if q.x >= parameters.p || q.y >= parameters.p {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let lhs = (&q.y * &q.y) % &parameters.p;
    let rhs = (((&q.x * &q.x * &q.x) + (&parameters.a * &q.x)) + &parameters.b)
        % &parameters.p;
    if lhs != rhs {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let r = BigUint::from_bytes_be(&signature[..coordinate_length]);
    let s = BigUint::from_bytes_be(&signature[coordinate_length..]);
    let zero = BigUint::from(0u8);
    if r == zero || r >= parameters.n || s == zero || s >= parameters.n {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    let mut z = BigUint::from_bytes_be(digest);
    let n_bits = parameters.n.bits() as usize;
    if digest.len() * 8 > n_bits {
        z >>= digest.len() * 8 - n_bits;
    }
    let w = s.modpow(&(&parameters.n - BigUint::from(2u8)), &parameters.n);
    let u1 = (z * &w) % &parameters.n;
    let u2 = (&r * &w) % &parameters.n;
    let generator = EcPointValue {
        x: parameters.gx.clone(),
        y: parameters.gy.clone(),
        z: BigUint::from(1u8),
    };
    let point = ec_add(
        &ec_multiply(&u1, &generator, &parameters),
        &ec_multiply(&u2, &q, &parameters),
        &parameters,
    );
    if point.z == zero {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    let inverse = point
        .z
        .modpow(&(&parameters.p - BigUint::from(2u8)), &parameters.p);
    let x = (&point.x * &inverse * &inverse) % &parameters.p;
    if x % &parameters.n == r {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

fn validate_ec_public_point(curve: EcCurve, point: &[u8]) -> Result<(), Error> {
    let parameters = ec_parameters(curve);
    if point.len() != 1 + parameters.coordinate_length * 2 || point[0] != 0x04 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let x = BigUint::from_bytes_be(&point[1..1 + parameters.coordinate_length]);
    let y = BigUint::from_bytes_be(&point[1 + parameters.coordinate_length..]);
    if x >= parameters.p || y >= parameters.p {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let lhs = (&y * &y) % &parameters.p;
    let rhs =
        (((&x * &x * &x) + (&parameters.a * &x)) + &parameters.b) % &parameters.p;
    if lhs == rhs {
        Ok(())
    } else {
        Err(CKR_KEY_TYPE_INCONSISTENT.into())
    }
}

fn piv_ec_curve(algorithm: piv::Algorithm) -> Result<EcCurve, Error> {
    match algorithm {
        piv::Algorithm::EccP256 => Ok(EcCurve::P256),
        piv::Algorithm::EccP384 => Ok(EcCurve::P384),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn openpgp_ec_curve(curve: openpgp::Curve) -> Result<EcCurve, Error> {
    match curve {
        openpgp::Curve::P256 => Ok(EcCurve::P256),
        openpgp::Curve::P384 => Ok(EcCurve::P384),
        openpgp::Curve::P521 => Ok(EcCurve::P521),
        openpgp::Curve::BrainpoolP256 => Ok(EcCurve::BrainpoolP256),
        openpgp::Curve::BrainpoolP384 => Ok(EcCurve::BrainpoolP384),
        openpgp::Curve::BrainpoolP512 => Ok(EcCurve::BrainpoolP512),
        openpgp::Curve::Secp256k1 => Ok(EcCurve::K256),
        openpgp::Curve::Ed25519 | openpgp::Curve::X25519 => {
            Err(CKR_KEY_TYPE_INCONSISTENT.into())
        }
    }
}

fn yubihsm_ec_curve(algorithm: u8) -> Result<EcCurve, Error> {
    match algorithm {
        YUBIHSM_ALGO_EC_P224 => Ok(EcCurve::P224),
        YUBIHSM_ALGO_EC_P256 => Ok(EcCurve::P256),
        YUBIHSM_ALGO_EC_P384 => Ok(EcCurve::P384),
        YUBIHSM_ALGO_EC_P521 => Ok(EcCurve::P521),
        YUBIHSM_ALGO_EC_K256 => Ok(EcCurve::K256),
        YUBIHSM_ALGO_EC_BP256 => Ok(EcCurve::BrainpoolP256),
        YUBIHSM_ALGO_EC_BP384 => Ok(EcCurve::BrainpoolP384),
        YUBIHSM_ALGO_EC_BP512 => Ok(EcCurve::BrainpoolP512),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn verify_ed25519(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let key_bytes: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
        .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| Error::from(CKR_SIGNATURE_INVALID))?;
    signature::Verifier::verify(&key, data, &signature)
        .map_err(|_| Error::from(CKR_SIGNATURE_INVALID))
}

fn der_length(encoded: &[u8], offset: &mut usize) -> Option<usize> {
    let first = *encoded.get(*offset)?;
    *offset += 1;
    match first {
        0..=0x7f => Some(first as usize),
        0x81 => {
            let length = *encoded.get(*offset)? as usize;
            *offset += 1;
            (length >= 0x80).then_some(length)
        }
        _ => None,
    }
}

fn der_positive_integer<'a>(encoded: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    if *encoded.get(*offset)? != 0x02 {
        return None;
    }
    *offset += 1;
    let length = der_length(encoded, offset)?;
    let value = encoded.get(*offset..offset.checked_add(length)?)?;
    *offset += length;
    if value.is_empty() || value[0] & 0x80 != 0 {
        return None;
    }
    if value.len() > 1 && value[0] == 0 {
        if value[1] & 0x80 == 0 {
            return None;
        }
        Some(&value[1..])
    } else {
        Some(value)
    }
}

fn ecdsa_der_to_raw(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    let mut offset = 0;
    if signature.get(offset) != Some(&0x30) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    offset += 1;
    let sequence_length = der_length(signature, &mut offset).ok_or(CKR_DEVICE_ERROR)?;
    if offset.checked_add(sequence_length) != Some(signature.len()) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let r = der_positive_integer(signature, &mut offset).ok_or(CKR_DEVICE_ERROR)?;
    let s = der_positive_integer(signature, &mut offset).ok_or(CKR_DEVICE_ERROR)?;
    if offset != signature.len() || r.len() > coordinate_length || s.len() > coordinate_length {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut output = vec![0; coordinate_length * 2];
    output[coordinate_length - r.len()..coordinate_length].copy_from_slice(r);
    output[2 * coordinate_length - s.len()..].copy_from_slice(s);
    Ok(output)
}

fn rsa_operation(
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

pub(crate) fn rsa_public_operation(
    key: &RsaPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    rsa_operation(input, key.e(), key.n(), key.size())
}

pub(crate) fn rsa_private_operation(
    key: &RsaPrivateKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    rsa_operation(input, key.d(), key.n(), key.size())
}

pub(crate) fn rsa_pkcs1_encrypt(
    key: &RsaPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let size = key.size();
    if input.len() > size.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let padding_length = size - input.len() - 3;
    let mut encoded = vec![0, 2];
    while encoded.len() < padding_length + 2 {
        let mut byte = [0];
        getrandom::fill(&mut byte).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
        if byte[0] != 0 {
            encoded.push(byte[0]);
        }
    }
    encoded.push(0);
    encoded.extend_from_slice(input);
    rsa_public_operation(key, &encoded)
}

pub(crate) fn rsa_pkcs1_sign(
    key: &RsaPrivateKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let size = key.size();
    if input.len() > size.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = vec![0, 1];
    encoded.resize(size - input.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend_from_slice(input);
    rsa_private_operation(key, &encoded)
}

pub(crate) fn rsa_pkcs1_recover(
    key: &RsaPublicKey,
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    let encoded = rsa_public_operation(key, signature)?;
    if encoded.len() < 11 || encoded[..2] != [0, 1] {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    let separator = encoded[2..]
        .iter()
        .position(|byte| *byte != 0xff)
        .map(|position| position + 2)
        .ok_or(CKR_SIGNATURE_INVALID)?;
    if separator < 10 || encoded[separator] != 0 {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    Ok(encoded[separator + 1..].to_vec())
}

fn verify_rsa_pss(
    encoded: &[u8],
    digest: &[u8],
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<bool, Error> {
    let hash_digest = digest_for_hash_mechanism(hash_mechanism)?;
    if digest.len() != hash_digest.size() || encoded.len() < hash_digest.size() + salt_length + 2 {
        return Ok(false);
    }
    let em_bits = encoded.len() * 8 - 1;
    let em_len = em_bits.div_ceil(8);
    let encoded = if encoded.len() > em_len {
        &encoded[encoded.len() - em_len..]
    } else {
        encoded
    };
    if encoded.last() != Some(&0xbc) {
        return Ok(false);
    }
    let h_offset = encoded.len() - hash_digest.size() - 1;
    let masked_db = &encoded[..h_offset];
    let h = &encoded[h_offset..h_offset + hash_digest.size()];
    if masked_db.first().is_some_and(|value| *value & 0x80 != 0) {
        return Ok(false);
    }
    let mask = mgf1(h, masked_db.len(), mgf_digest(mgf_code, hash_mechanism)?)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0x7f;
    let separator = db.len() - salt_length - 1;
    if db.get(separator) != Some(&1) || db[..separator].iter().any(|value| *value != 0) {
        return Ok(false);
    }
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&db[separator + 1..]);
    Ok(hash(hash_digest, &m_prime)?.as_slice() == h)
}
