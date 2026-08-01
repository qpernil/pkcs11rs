use crate::*;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

pub(crate) type RsaOaepParameters = (u8, CK_MECHANISM_TYPE, Vec<u8>);

pub(crate) fn parse_rsa_oaep_parameters(
    mechanism: &CK_MECHANISM,
) -> Result<RsaOaepParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_RSA_PKCS_OAEP_PARAMS_PTR) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if parameters.source != CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let digest = digest_for_hash_mechanism(parameters.hashAlg)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let mgf = match parameters.mgf {
        x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => 32,
        x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => 33,
        x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => 34,
        x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => 35,
        x if x == CKG_MGF1_SHA224 as CK_RSA_PKCS_MGF_TYPE => 36,
        x if x == CKG_MGF1_SHA3_224 as CK_RSA_PKCS_MGF_TYPE => 37,
        x if x == CKG_MGF1_SHA3_256 as CK_RSA_PKCS_MGF_TYPE => 38,
        x if x == CKG_MGF1_SHA3_384 as CK_RSA_PKCS_MGF_TYPE => 39,
        x if x == CKG_MGF1_SHA3_512 as CK_RSA_PKCS_MGF_TYPE => 40,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    let label = unsafe {
        from_raw_parts(
            parameters.pSourceData as *const u8,
            parameters.ulSourceDataLen as usize,
        )
    }
    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    Ok((mgf, parameters.hashAlg, hash(digest, label)?.to_vec()))
}

pub(crate) fn yubihsm_ec_coordinate_length(algorithm: u8) -> Result<usize, Error> {
    match algorithm {
        YUBIHSM_ALGO_EC_P224 => Ok(28),
        YUBIHSM_ALGO_EC_P256 | YUBIHSM_ALGO_EC_K256 | YUBIHSM_ALGO_EC_BP256 => Ok(32),
        YUBIHSM_ALGO_EC_P384 | YUBIHSM_ALGO_EC_BP384 => Ok(48),
        YUBIHSM_ALGO_EC_BP512 => Ok(64),
        YUBIHSM_ALGO_EC_P521 => Ok(66),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

pub(super) fn yubihsm_ecdsa_signature(
    signature: &[u8],
    coordinate_length: usize,
) -> Result<Vec<u8>, Error> {
    ecdsa_der_to_raw(signature, coordinate_length)
}

pub(crate) fn encode_pkcs1_v1_5_signature_input(
    data: &[u8],
    modulus_size: usize,
) -> Result<Vec<u8>, Error> {
    if data.len() > modulus_size.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = Vec::with_capacity(modulus_size);
    encoded.extend([0, 1]);
    encoded.resize(modulus_size - data.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend_from_slice(data);
    Ok(encoded)
}

pub(crate) fn rsa_pkcs1_v1_5_unpad(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded.len() < 11 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }

    let mut valid = encoded[0].ct_eq(&0) & encoded[1].ct_eq(&2);
    let mut found = subtle::Choice::from(0);
    let mut separator = 0u32;
    for (index, value) in encoded[2..].iter().enumerate() {
        let is_separator = value.ct_eq(&0);
        let use_index = !found & is_separator;
        separator = u32::conditional_select(&separator, &((index + 2) as u32), use_index);
        found |= is_separator;
    }
    valid &= found & separator.ct_gt(&9);

    if !bool::from(valid) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(encoded[separator as usize + 1..].to_vec())
}

pub(crate) fn rsa_oaep_unpad(
    encoded: &[u8],
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let digest = digest_for_hash_mechanism(hash_mechanism)?;
    let mgf_digest = mgf_digest(mgf_code, hash_mechanism)?;
    let hash_len = digest.size();
    if encoded.len() < 2 * hash_len + 2 || label_digest.len() != hash_len {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let mut valid = encoded[0].ct_eq(&0);
    let masked_seed = &encoded[1..hash_len + 1];
    let masked_db = &encoded[hash_len + 1..];
    let seed_mask = mgf1(masked_db, hash_len, mgf_digest)?;
    let mut seed = masked_seed.to_vec();
    for (value, mask) in seed.iter_mut().zip(seed_mask) {
        *value ^= mask;
    }
    let db_mask = mgf1(&seed, masked_db.len(), mgf_digest)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(db_mask) {
        *value ^= mask;
    }

    valid &= db[..hash_len].ct_eq(label_digest);
    let mut looking_for_separator = subtle::Choice::from(1);
    let mut separator_is_one = subtle::Choice::from(0);
    let mut separator = 0u32;
    for (index, value) in db[hash_len..].iter().enumerate() {
        let is_zero = value.ct_eq(&0);
        let first_nonzero = looking_for_separator & !is_zero;
        separator =
            u32::conditional_select(&separator, &((index + hash_len) as u32), first_nonzero);
        separator_is_one |= first_nonzero & value.ct_eq(&1);
        looking_for_separator &= is_zero;
    }
    valid &= !looking_for_separator & separator_is_one;

    if !bool::from(valid) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(db[separator as usize + 1..].to_vec())
}

pub(crate) fn rsa_oaep_pad(
    input: &[u8],
    modulus_size: usize,
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let digest = digest_for_hash_mechanism(hash_mechanism)?;
    let mgf_digest = mgf_digest(mgf_code, hash_mechanism)?;
    let hash_len = digest.size();
    if input.len() > modulus_size.saturating_sub(2 * hash_len + 2) || label_digest.len() != hash_len
    {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut seed = vec![0; hash_len];
    getrandom::fill(&mut seed).map_err(|_| CKR_RANDOM_NO_RNG)?;
    let mut db = label_digest.to_vec();
    db.extend(std::iter::repeat_n(
        0,
        modulus_size - input.len() - 2 * hash_len - 2,
    ));
    db.push(1);
    db.extend_from_slice(input);
    let db_mask = mgf1(&seed, db.len(), mgf_digest)?;
    for (value, mask) in db.iter_mut().zip(db_mask) {
        *value ^= mask;
    }
    let seed_mask = mgf1(&db, hash_len, mgf_digest)?;
    let mut encoded = vec![0];
    encoded.extend(seed.iter().zip(seed_mask).map(|(value, mask)| value ^ mask));
    encoded.extend_from_slice(&db);
    Ok(encoded)
}

session_unsupported_stub!(C_DigestEncryptUpdate(
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
));

session_unsupported_stub!(C_DecryptDigestUpdate(
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
));

session_unsupported_stub!(C_SignEncryptUpdate(
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
));

session_unsupported_stub!(C_DecryptVerifyUpdate(
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
));
