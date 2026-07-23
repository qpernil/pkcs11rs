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

fn piv_ec_public_key(algorithm: piv::Algorithm, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match algorithm {
        piv::Algorithm::EccP256 => Nid::X9_62_PRIME256V1,
        piv::Algorithm::EccP384 => Nid::SECP384R1,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn openpgp_ec_public_key(curve: openpgp::Curve, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match curve {
        openpgp::Curve::P256 => Nid::X9_62_PRIME256V1,
        openpgp::Curve::P384 => Nid::SECP384R1,
        openpgp::Curve::P521 => Nid::SECP521R1,
        openpgp::Curve::BrainpoolP256 => Nid::BRAINPOOL_P256R1,
        openpgp::Curve::BrainpoolP384 => Nid::BRAINPOOL_P384R1,
        openpgp::Curve::BrainpoolP512 => Nid::BRAINPOOL_P512R1,
        openpgp::Curve::Secp256k1 => Nid::SECP256K1,
        openpgp::Curve::Ed25519 | openpgp::Curve::X25519 => {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into())
        }
    };
    let coordinate_length = curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    if point.len() != coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn yubihsm_ec_public_key(algorithm: u8, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match algorithm {
        YUBIHSM_ALGO_EC_P224 => Nid::SECP224R1,
        YUBIHSM_ALGO_EC_P256 => Nid::X9_62_PRIME256V1,
        YUBIHSM_ALGO_EC_P384 => Nid::SECP384R1,
        YUBIHSM_ALGO_EC_P521 => Nid::SECP521R1,
        YUBIHSM_ALGO_EC_K256 => Nid::SECP256K1,
        YUBIHSM_ALGO_EC_BP256 => Nid::BRAINPOOL_P256R1,
        YUBIHSM_ALGO_EC_BP384 => Nid::BRAINPOOL_P384R1,
        YUBIHSM_ALGO_EC_BP512 => Nid::BRAINPOOL_P512R1,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    let coordinate_length = yubihsm_ec_coordinate_length(algorithm)?;
    if point.len() != coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn verify_ed25519(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let key = PKey::public_key_from_raw_bytes(public_key, Id::ED25519).map_err(Error::from)?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(Error::from)?;
    if verifier
        .verify_oneshot(signature, data)
        .map_err(Error::from)?
    {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

fn point_with_prefix(point: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(point.len() + 1);
    encoded.push(0x04);
    encoded.extend_from_slice(point);
    encoded
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
    Ok(hash(hash_digest, &m_prime)?.as_ref() == h)
}
