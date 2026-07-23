fn yubihsm_ec_coordinate_length(algorithm: u8) -> Result<usize, Error> {
    match algorithm {
        YUBIHSM_ALGO_EC_P224 => Ok(28),
        YUBIHSM_ALGO_EC_P256 | YUBIHSM_ALGO_EC_K256 | YUBIHSM_ALGO_EC_BP256 => Ok(32),
        YUBIHSM_ALGO_EC_P384 | YUBIHSM_ALGO_EC_BP384 => Ok(48),
        YUBIHSM_ALGO_EC_BP512 => Ok(64),
        YUBIHSM_ALGO_EC_P521 => Ok(66),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn yubihsm_ecdsa_signature(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    ecdsa_der_to_raw(signature, coordinate_length)
}

fn encode_pkcs1_v1_5_signature_input(data: &[u8], modulus_size: usize) -> Result<Vec<u8>, Error> {
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

fn rsa_pkcs1_v1_5_unpad(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded.len() < 11 || encoded.get(0..2) != Some(&[0, 2]) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let separator = encoded[2..]
        .iter()
        .position(|value| *value == 0)
        .map(|position| position + 2)
        .ok_or(CKR_ENCRYPTED_DATA_INVALID)?;
    if separator < 10 || encoded[2..separator].contains(&0) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(encoded[separator + 1..].to_vec())
}

fn rsa_oaep_unpad(
    encoded: &[u8],
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let digest = digest_for_hash_mechanism(hash_mechanism)?;
    let mgf_digest = mgf_digest(mgf_code, hash_mechanism)?;
    let hash_len = digest.size();
    if encoded.len() < 2 * hash_len + 2 || encoded[0] != 0 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
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
    if db.get(..hash_len) != Some(label_digest) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let separator = db[hash_len..]
        .iter()
        .position(|value| *value == 1)
        .map(|position| position + hash_len)
        .ok_or(CKR_ENCRYPTED_DATA_INVALID)?;
    if db[hash_len..separator].iter().any(|value| *value != 0) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(db[separator + 1..].to_vec())
}

fn rsa_oaep_pad(
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


#[no_mangle]
pub extern "C" fn C_DigestEncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptDigestUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptVerifyUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}
