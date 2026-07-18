#[no_mangle]
pub extern "C" fn C_EncryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    map(crypt_init(session_handle, mechanism, key, true))
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    encrypted_data: *mut ::std::os::raw::c_uchar,
    encrypted_data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        data,
        data_len,
        encrypted_data,
        encrypted_data_len,
        true,
    ))
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    session_handle: CK_SESSION_HANDLE,
    _last_encrypted_part: *mut ::std::os::raw::c_uchar,
    _last_encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    map(crypt_init(session_handle, mechanism, key, false))
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    session_handle: CK_SESSION_HANDLE,
    encrypted_data: *mut ::std::os::raw::c_uchar,
    encrypted_data_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        encrypted_data,
        encrypted_data_len,
        data,
        data_len,
        false,
    ))
}

fn parse_gcm_parameters(mechanism: &CK_MECHANISM) -> Result<GcmParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_GCM_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = _as_ref(mechanism.pParameter as CK_GCM_PARAMS_PTR)?;
    let iv_len = usize::try_from(parameters.ulIvLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let aad_len = usize::try_from(parameters.ulAADLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let tag_bits = usize::try_from(parameters.ulTagBits)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if iv_len == 0
        || iv_len > u32::MAX as usize
        || aad_len > u32::MAX as usize
        || tag_bits > 128
        || parameters.pIv.is_null()
        || (aad_len != 0 && parameters.pAAD.is_null())
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(GcmParameters {
        iv: from_raw_parts(parameters.pIv as *const u8, iv_len)?.to_vec(),
        aad: from_raw_parts(parameters.pAAD as *const u8, aad_len)?.to_vec(),
        tag_bits,
    })
}

fn crypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
    encrypting: bool,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let operations = if encrypting {
            &ctx.encrypt_operations
        } else {
            &ctx.decrypt_operations
        };
        if operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        let mechanism = _as_ref(mechanism)?;
        let (iv, gcm, oaep) = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_AES_ECB as CK_MECHANISM_TYPE =>
            {
                if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                (None, None, None)
            }
            x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => {
                if mechanism.ulParameterLen != 16 || mechanism.pParameter.is_null() {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let bytes = from_raw_parts(mechanism.pParameter as *const u8, 16)?;
                (
                    Some(bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?),
                    None,
                    None,
                )
            }
            x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                (None, Some(parse_gcm_parameters(mechanism)?), None)
            }
            x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                if mechanism.ulParameterLen as usize
                    != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_OAEP_PARAMS_PTR)?;
                if parameters.source != CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let digest = digest_for_hash_mechanism(parameters.hashAlg)?;
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
                let label = from_raw_parts(
                    parameters.pSourceData as *const u8,
                    parameters.ulSourceDataLen as usize,
                )?;
                (
                    None,
                    None,
                    Some((mgf, parameters.hashAlg, hash(digest, label)?.to_vec())),
                )
            }
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        let object = ctx
            .objects
            .get(&key)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if (encrypting && !object.encrypt) || (!encrypting && !object.decrypt) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let required_capability = match (mechanism.mechanism, encrypting) {
            (mechanism, false) if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE => 0x09,
            (mechanism, false) if mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => 0x0a,
            (mechanism, false) if mechanism == CKM_AES_ECB as CK_MECHANISM_TYPE => 0x32,
            (mechanism, true) if mechanism == CKM_AES_ECB as CK_MECHANISM_TYPE => 0x33,
            (mechanism, false) if mechanism == CKM_AES_CBC as CK_MECHANISM_TYPE => 0x34,
            (mechanism, true) if mechanism == CKM_AES_CBC as CK_MECHANISM_TYPE => 0x35,
            (mechanism, _) if mechanism == CKM_AES_GCM as CK_MECHANISM_TYPE => 0x33,
            _ => 0,
        };
        if required_capability != 0
            && !yubihsm_material_has_capability(&object.material, required_capability)
        {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let valid_key = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
            {
                object.key_type == CKK_RSA as CK_KEY_TYPE
                    && if encrypting {
                        matches!(object.material, KeyMaterial::RsaPublic(_))
                    } else {
                        matches!(
                            object.material,
                            KeyMaterial::YubiHsm { .. }
                                | KeyMaterial::PivPrivate { .. }
                                | KeyMaterial::OpenPgpPrivate { .. }
                        )
                    }
            }
            _ => {
                object.key_type == CKK_AES as CK_KEY_TYPE
                    && matches!(object.material, KeyMaterial::YubiHsm { .. })
            }
        };
        if !valid_key {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let operation = CryptOperation {
            key: object.material.clone(),
            slot_id,
            requires_login: object.private,
            context_specific_extended: matches!(
                &object.material,
                KeyMaterial::OpenPgpPrivate { .. }
            ),
            mechanism: mechanism.mechanism,
            iv,
            gcm,
            oaep,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
        };
        if encrypting {
            ctx.encrypt_operations.insert(session_handle, operation);
        } else {
            ctx.decrypt_operations.insert(session_handle, operation);
        }
        Ok(())
    })
}

fn yubihsm_rsa_length(algorithm: u8) -> Result<usize, Error> {
    match algorithm {
        YUBIHSM_ALGO_RSA_2048 => Ok(256),
        YUBIHSM_ALGO_RSA_3072 => Ok(384),
        YUBIHSM_ALGO_RSA_4096 => Ok(512),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

const AES_BLOCK_LENGTH: usize = 16;
const YUBIHSM_ECB_CHUNK_LENGTH: usize = 2016;

fn ghash_multiply(left: u128, right: u128) -> u128 {
    const REDUCTION: u128 = 0xe1000000000000000000000000000000;
    let mut product = 0;
    let mut factor = right;
    for bit in 0..128 {
        if left & (1u128 << (127 - bit)) != 0 {
            product ^= factor;
        }
        factor = if factor & 1 == 0 {
            factor >> 1
        } else {
            (factor >> 1) ^ REDUCTION
        };
    }
    product
}

fn ghash_update(mut hash: u128, key: u128, data: &[u8]) -> u128 {
    for chunk in data.chunks(AES_BLOCK_LENGTH) {
        let mut block = [0; AES_BLOCK_LENGTH];
        block[..chunk.len()].copy_from_slice(chunk);
        hash = ghash_multiply(hash ^ u128::from_be_bytes(block), key);
    }
    hash
}

fn ghash(key: [u8; AES_BLOCK_LENGTH], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], Error> {
    let aad_bits = u64::try_from(aad.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let ciphertext_bits = u64::try_from(ciphertext.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let key = u128::from_be_bytes(key);
    let mut hash = ghash_update(0, key, aad);
    hash = ghash_update(hash, key, ciphertext);
    let mut lengths = [0; AES_BLOCK_LENGTH];
    lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    Ok(ghash_multiply(hash ^ u128::from_be_bytes(lengths), key).to_be_bytes())
}

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_LENGTH]) {
    let value = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&value.to_be_bytes());
}

fn gcm_tag(full_tag: [u8; AES_BLOCK_LENGTH], tag_bits: usize) -> Vec<u8> {
    let tag_length = tag_bits.div_ceil(8);
    let mut tag = full_tag[..tag_length].to_vec();
    if !tag_bits.is_multiple_of(8) {
        let mask = 0xff << (8 - tag_bits % 8);
        if let Some(last) = tag.last_mut() {
            *last &= mask;
        }
    }
    tag
}

fn aes_gcm<F>(
    parameters: &GcmParameters,
    input: &[u8],
    encrypting: bool,
    mut encrypt_blocks: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, Error>,
{
    if parameters.iv.is_empty() || parameters.tag_bits > 128 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let tag_length = parameters.tag_bits.div_ceil(8);
    let (payload, supplied_tag) = if encrypting {
        (input, None)
    } else {
        if input.len() < tag_length {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
        }
        let split = input.len() - tag_length;
        (&input[..split], Some(&input[split..]))
    };
    let block_count = payload.len().div_ceil(AES_BLOCK_LENGTH);
    if block_count > u32::MAX as usize - 2 {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }

    let hash_subkey = encrypt_blocks(&[0; AES_BLOCK_LENGTH])?;
    let hash_subkey: [u8; AES_BLOCK_LENGTH] = hash_subkey
        .as_slice()
        .try_into()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut initial_counter = if parameters.iv.len() == 12 {
        let mut counter = [0; AES_BLOCK_LENGTH];
        counter[..12].copy_from_slice(&parameters.iv);
        counter[15] = 1;
        counter
    } else {
        ghash(hash_subkey, &[], &parameters.iv)?
    };

    let counter_capacity = (block_count + 1)
        .checked_mul(AES_BLOCK_LENGTH)
        .ok_or_else(|| {
            if encrypting {
                Error::from(CKR_DATA_LEN_RANGE)
            } else {
                Error::from(CKR_ENCRYPTED_DATA_LEN_RANGE)
            }
        })?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    counter_blocks.extend_from_slice(&initial_counter);
    for _ in 0..block_count {
        increment_gcm_counter(&mut initial_counter);
        counter_blocks.extend_from_slice(&initial_counter);
    }
    let encrypted_counters = encrypt_blocks(&counter_blocks)?;
    if encrypted_counters.len() != counter_blocks.len() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut transformed = Vec::with_capacity(payload.len());
    for (block, key_stream) in payload
        .chunks(AES_BLOCK_LENGTH)
        .zip(encrypted_counters[AES_BLOCK_LENGTH..].chunks(AES_BLOCK_LENGTH))
    {
        transformed.extend(
            block
                .iter()
                .zip(key_stream)
                .map(|(left, right)| left ^ right),
        );
    }
    let ciphertext = if encrypting { &transformed } else { payload };
    let hash = ghash(hash_subkey, &parameters.aad, ciphertext)?;
    let mut full_tag = [0; AES_BLOCK_LENGTH];
    for ((output, mask), value) in full_tag
        .iter_mut()
        .zip(&encrypted_counters[..AES_BLOCK_LENGTH])
        .zip(hash)
    {
        *output = mask ^ value;
    }
    let expected_tag = gcm_tag(full_tag, parameters.tag_bits);
    if let Some(supplied_tag) = supplied_tag {
        if !openssl::memcmp::eq(&expected_tag, supplied_tag) {
            transformed.fill(0);
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&expected_tag);
        Ok(transformed)
    }
}

fn yubihsm_encrypt_ecb_blocks(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
) -> Result<Vec<u8>, Error> {
    if !blocks.len().is_multiple_of(AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encrypted = Vec::with_capacity(blocks.len());
    for chunk in blocks.chunks(YUBIHSM_ECB_CHUNK_LENGTH) {
        let command = YubiHsmCommand::key_data(YubiHsmCommandCode::EncryptEcb, key_id, chunk)?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        if response.len() != chunk.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        encrypted.extend_from_slice(&response);
    }
    Ok(encrypted)
}

fn crypt(
    session_handle: CK_SESSION_HANDLE,
    input: *const u8,
    input_len: CK_ULONG,
    output: *mut u8,
    output_len: CK_ULONG_PTR,
    encrypting: bool,
) -> Result<(), Error> {
    if output_len.is_null() {
        let _ = with_context_mut(|ctx| {
            ctx.encrypt_operations.remove(&session_handle);
            ctx.decrypt_operations.remove(&session_handle);
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = as_mut(output_len)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = if encrypting {
            ctx.encrypt_operations.get(&session_handle)
        } else {
            ctx.decrypt_operations.get(&session_handle)
        }
        .cloned()
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.encrypt_operations.remove(&session_handle);
            ctx.decrypt_operations.remove(&session_handle);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let input = match from_raw_parts(input, input_len as usize) {
            Ok(input) => input,
            Err(error) => {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(error);
            }
        };
        let required = if operation.mechanism == CKM_AES_GCM as CK_MECHANISM_TYPE {
            let Some(parameters) = operation.gcm.as_ref() else {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let tag_length = parameters.tag_bits.div_ceil(8);
            let required = if encrypting {
                input.len().checked_add(tag_length)
            } else {
                input.len().checked_sub(tag_length)
            };
            let Some(required) = required else {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(if encrypting {
                    CKR_DATA_LEN_RANGE.into()
                } else {
                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                });
            };
            required
        } else {
            match &operation.key {
                KeyMaterial::RsaPublic(key) => key.size() as usize,
                KeyMaterial::PivPrivate { modulus, .. } if !encrypting => modulus.len(),
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !encrypting => modulus.len(),
                KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                    match yubihsm_rsa_length(*algorithm) {
                        Ok(length) => length,
                        Err(error) => {
                            ctx.encrypt_operations.remove(&session_handle);
                            ctx.decrypt_operations.remove(&session_handle);
                            return Err(error);
                        }
                    }
                }
                KeyMaterial::YubiHsm { .. } => input.len(),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        };
        if output.is_null() {
            *output_len = required as CK_ULONG;
            return Ok(());
        }
        let result = (|| -> Result<Vec<u8>, Error> {
            match &operation.key {
                KeyMaterial::RsaPublic(key)
                    if encrypting && operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE =>
                {
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(input, &mut encrypted, Padding::PKCS1)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::RsaPublic(key)
                    if encrypting && operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE =>
                {
                    if input.len() != key.size() as usize {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(input, &mut encrypted, Padding::NONE)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::RsaPublic(key)
                    if encrypting
                        && operation.mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
                {
                    let (mgf, hash_mechanism, label_digest) =
                        operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    let encoded = rsa_oaep_pad(
                        input,
                        key.size() as usize,
                        *mgf,
                        *hash_mechanism,
                        label_digest,
                    )?;
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(&encoded, &mut encrypted, Padding::NONE)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } if !encrypting => {
                    let raw = ctx._get_session(session_handle)?.1.piv_decipher(
                        *slot,
                        *algorithm,
                        input,
                        operation.piv_pin_policy.unwrap_or_default(),
                    )?;
                    let raw = if let Some(expected) = algorithm.rsa_input_length() {
                        if raw.len() > expected {
                            return Err(CKR_DEVICE_ERROR.into());
                        }
                        if raw.len() < expected {
                            let mut padded = vec![0; expected - raw.len()];
                            padded.extend_from_slice(&raw);
                            padded
                        } else {
                            raw
                        }
                    } else {
                        raw
                    };
                    match operation.mechanism {
                        x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE => Ok(raw),
                        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => rsa_pkcs1_v1_5_unpad(&raw),
                        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                            let (mgf, hash_mechanism, label_digest) =
                                operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                            rsa_oaep_unpad(&raw, *mgf, *hash_mechanism, label_digest)
                        }
                        _ => Err(CKR_MECHANISM_INVALID.into()),
                    }
                }
                KeyMaterial::OpenPgpPrivate { algorithm, .. } if !encrypting => {
                    if !matches!(algorithm, OpenPgpAlgorithm::Rsa { .. }) {
                        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
                    }
                    ctx._get_session(session_handle)?.1.openpgp_decipher(
                        input,
                        operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE,
                    )
                }
                KeyMaterial::YubiHsm { id, .. } => {
                    let command = match operation.mechanism {
                        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE && !encrypting => {
                            YubiHsmCommand::key_data(YubiHsmCommandCode::DecryptPkcs1, *id, input)?
                        }
                        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE && !encrypting => {
                            let (mgf, _hash_mechanism, label_digest) =
                                operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                            YubiHsmCommand::decrypt_oaep(*id, *mgf, input, label_digest)?
                        }
                        x if x == CKM_AES_ECB as CK_MECHANISM_TYPE => YubiHsmCommand::key_data(
                            if encrypting {
                                YubiHsmCommandCode::EncryptEcb
                            } else {
                                YubiHsmCommandCode::DecryptEcb
                            },
                            *id,
                            input,
                        )?,
                        x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => YubiHsmCommand::crypt_cbc(
                            if encrypting {
                                YubiHsmCommandCode::EncryptCbc
                            } else {
                                YubiHsmCommandCode::DecryptCbc
                            },
                            *id,
                            operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                        )?,
                        x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                            return aes_gcm(
                                operation.gcm.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                input,
                                encrypting,
                                |blocks| {
                                    yubihsm_encrypt_ecb_blocks(ctx, session_handle, *id, blocks)
                                },
                            );
                        }
                        _ => return Err(CKR_MECHANISM_INVALID.into()),
                    };
                    ctx._get_session(session_handle)?
                        .1
                        .yubihsm_command(&command)
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(error);
            }
        };
        if *output_len < result.len() as CK_ULONG {
            *output_len = result.len() as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        unsafe { ptr::copy_nonoverlapping(result.as_ptr(), output, result.len()) };
        *output_len = result.len() as CK_ULONG;
        ctx.encrypt_operations.remove(&session_handle);
        ctx.decrypt_operations.remove(&session_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    session_handle: CK_SESSION_HANDLE,
    _last_part: *mut ::std::os::raw::c_uchar,
    _last_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_Digest(
    session_handle: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestKey(session_handle: CK_SESSION_HANDLE, _key: CK_OBJECT_HANDLE) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    session_handle: CK_SESSION_HANDLE,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_SignInit called with {:?}",
        (session_handle, mechanism, key)
    );
    map(sign_init(session_handle, mechanism, key))
}

fn sign_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx.sign_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = _as_ref(mechanism)?;
        let pss = if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR)?;
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
            let salt_length = u16::try_from(parameters.sLen)
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
            Some((mgf, salt_length, parameters.hashAlg))
        } else if piv_is_pss_mechanism(mechanism.mechanism) {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let digest =
                piv_hash_mechanism(mechanism.mechanism).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let hash = pss_hash_mechanism(mechanism.mechanism)?;
            Some((0, digest.size() as u16, hash))
        } else {
            if !matches!(
                mechanism.mechanism,
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                    || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
                    || x == CKM_EDDSA as CK_MECHANISM_TYPE
                    || x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
            ) {
                return Err(CKR_MECHANISM_INVALID.into());
            }
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };

        let object = ctx.objects.get(&key).ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !object.is_visible_to(session_handle, slot_id, logged_in) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        if !object.sign {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let required_capability = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || piv_is_hashed_rsa_pkcs(x) =>
            {
                0x05
            }
            x if piv_is_pss_mechanism(x) => 0x06,
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE => 0x07,
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => 0x08,
            _ => 0x16,
        };
        if !yubihsm_material_has_capability(&object.material, required_capability) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let expected_key_type = match mechanism.mechanism {
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE || piv_is_hashed_ecdsa(x) => {
                CKK_EC as CK_KEY_TYPE
            }
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => CKK_EC_EDWARDS as CK_KEY_TYPE,
            x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => CKK_SHA_1_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => CKK_SHA256_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => CKK_SHA384_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => CKK_SHA512_HMAC as CK_KEY_TYPE,
            _ => CKK_RSA as CK_KEY_TYPE,
        };
        let hmac_yubihsm = is_hmac_key_type(expected_key_type)
            && matches!(object.material, KeyMaterial::YubiHsm { .. });
        if ((!hmac_yubihsm && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            || (hmac_yubihsm && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS))
            || object.key_type != expected_key_type
            || !matches!(
                object.material,
                KeyMaterial::RsaPrivate(_)
                    | KeyMaterial::PivPrivate { .. }
                    | KeyMaterial::OpenPgpPrivate { .. }
                    | KeyMaterial::YubiHsm { .. }
            )
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let piv_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::PivPrivate { algorithm, .. }
                if piv_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        let openpgp_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::OpenPgpPrivate { algorithm, .. }
                if openpgp_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        if !matches!(object.material, KeyMaterial::YubiHsm { .. })
            && !piv_mechanism_supported
            && !openpgp_mechanism_supported
            && !matches!(
                &object.material,
                KeyMaterial::RsaPrivate(_) if mechanism.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            )
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if matches!(object.material, KeyMaterial::YubiHsm { .. })
            && (piv_is_hashed_rsa_pkcs(mechanism.mechanism)
                || piv_is_hashed_ecdsa(mechanism.mechanism)
                || (piv_is_pss_mechanism(mechanism.mechanism)
                    && mechanism.mechanism != CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE))
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        ctx.sign_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: object.private,
                context_specific_extended: false,
                mechanism: mechanism.mechanism,
                pss,
                piv_pin_policy: match &object.material {
                    KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                    _ => None,
                },
                buffer: Vec::new(),
            },
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_Sign(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Sign called with {:?}",
        (session_handle, data, data_len, signature, signature_len)
    );
    map(sign(
        session_handle,
        data,
        data_len,
        signature,
        signature_len,
    ))
}

fn sign(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    if signature_len.is_null() {
        let _ = with_context_mut(|ctx| {
            if ctx._get_session(session_handle).is_ok() {
                ctx.sign_operations.remove(&session_handle);
            }
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_len = as_mut(signature_len)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .sign_operations
            .get(&session_handle)
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.sign_operations.remove(&session_handle);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let data = match from_raw_parts(data, data_len as usize) {
            Ok(data) => data,
            Err(error) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(error);
            }
        };
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let required = match &operation.key {
            KeyMaterial::RsaPrivate(key) => key.size() as usize,
            KeyMaterial::PivPrivate {
                algorithm, modulus, ..
            } => match algorithm {
                piv::Algorithm::Rsa1024
                | piv::Algorithm::Rsa2048
                | piv::Algorithm::Rsa3072
                | piv::Algorithm::Rsa4096 => modulus.len(),
                piv::Algorithm::EccP256 => 64,
                piv::Algorithm::EccP384 => 96,
                piv::Algorithm::Ed25519 => 64,
                piv::Algorithm::X25519 => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::OpenPgpPrivate {
                algorithm, modulus, ..
            } => match algorithm {
                OpenPgpAlgorithm::Rsa { .. } => modulus.len(),
                OpenPgpAlgorithm::Ecdsa(_) => openpgp_ec_coordinate_length(*algorithm).unwrap() * 2,
                OpenPgpAlgorithm::Ed25519 => 64,
                OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                match *algorithm {
                    YUBIHSM_ALGO_RSA_2048 => 256,
                    YUBIHSM_ALGO_RSA_3072 => 384,
                    YUBIHSM_ALGO_RSA_4096 => 512,
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                }
            }
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm) => {
                yubihsm_ec_coordinate_length(*algorithm)? * 2
            }
            KeyMaterial::YubiHsm {
                algorithm: YUBIHSM_ALGO_ED25519,
                ..
            } => 64,
            KeyMaterial::YubiHsm { algorithm, .. } => match *algorithm {
                YUBIHSM_ALGO_HMAC_SHA1 => 20,
                YUBIHSM_ALGO_HMAC_SHA256 => 32,
                YUBIHSM_ALGO_HMAC_SHA384 => 48,
                YUBIHSM_ALGO_HMAC_SHA512 => 64,
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if (operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            || operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
            || piv_is_hashed_rsa_pkcs(operation.mechanism))
            && data.len() > required.saturating_sub(11)
        {
            ctx.sign_operations.remove(&session_handle);
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            let Some((_mgf, _salt, hash)) = operation.pss else {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let expected = digest_for_hash_mechanism(hash)?.size();
            if data.len() != expected {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        }

        if signature.is_null() {
            *signature_len = required as CK_ULONG;
            return Ok(());
        }
        if *signature_len < required as CK_ULONG {
            *signature_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let signature_result = (|| -> Result<Vec<u8>, Error> {
            match &operation.key {
                KeyMaterial::RsaPrivate(private_key) => {
                    let mut signature = vec![0; required];
                    private_key
                        .private_encrypt(data, &mut signature, Padding::PKCS1)
                        .map(|written| {
                            signature.truncate(written);
                            signature
                        })
                        .map_err(Error::from)
                }
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()
                        .map_err(Error::from)?;
                    let input = if piv_is_pss_mechanism(operation.mechanism) {
                        let (mgf, salt_length, hash_mechanism) =
                            operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        let digest = digest.as_deref().unwrap_or(data);
                        encode_rsa_pss(digest, required, hash_mechanism, mgf, salt_length as usize)?
                    } else if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                        let digest = digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        encode_pkcs1_v1_5_signature_input(
                            &piv_digest_info(operation.mechanism, digest)
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            required,
                        )?
                    } else if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                        encode_pkcs1_v1_5_signature_input(data, required)?
                    } else if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                        if data.len() != required {
                            return Err(CKR_DATA_LEN_RANGE.into());
                        }
                        data.to_vec()
                    } else if piv_is_hashed_ecdsa(operation.mechanism) {
                        digest.ok_or(CKR_MECHANISM_PARAM_INVALID)?
                    } else {
                        data.to_vec()
                    };
                    let response = ctx._get_session(session_handle)?.1.piv_sign(
                        *slot,
                        *algorithm,
                        &input,
                        operation.piv_pin_policy.unwrap_or(0),
                    )?;
                    match algorithm {
                        piv::Algorithm::EccP256 => piv_ecdsa_signature(&response, 32),
                        piv::Algorithm::EccP384 => piv_ecdsa_signature(&response, 48),
                        _ => Ok(response),
                    }
                }
                KeyMaterial::OpenPgpPrivate {
                    key_ref,
                    algorithm,
                    pin_policy,
                    ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()
                        .map_err(Error::from)?;
                    let input = match algorithm {
                        OpenPgpAlgorithm::Rsa { .. } => {
                            if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                                piv_digest_info(
                                    operation.mechanism,
                                    digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                )
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?
                            } else {
                                data.to_vec()
                            }
                        }
                        OpenPgpAlgorithm::Ecdsa(_) => digest.unwrap_or_else(|| data.to_vec()),
                        OpenPgpAlgorithm::Ed25519 => data.to_vec(),
                        OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                    };
                    let response = ctx._get_session(session_handle)?.1.openpgp_sign(
                        *key_ref,
                        &input,
                        *pin_policy,
                    )?;
                    match algorithm {
                        OpenPgpAlgorithm::Ecdsa(curve) => {
                            openpgp_signature(&response, curve.coordinate_length().unwrap())
                        }
                        _ => Ok(response),
                    }
                }
                KeyMaterial::YubiHsm { id, algorithm, .. } => {
                    let command = if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignPkcs1, *id, data)?
                    } else if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
                        let (mgf, salt_length, _) =
                            operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        YubiHsmCommand::sign_pss(*id, mgf, salt_length, data)?
                    } else if matches!(
                        operation.mechanism,
                        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
                    ) {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignHmac, *id, data)?
                    } else if operation.mechanism == CKM_EDDSA as CK_MECHANISM_TYPE {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignEddsa, *id, data)?
                    } else {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignEcdsa, *id, data)?
                    };
                    let response = ctx
                        ._get_session(session_handle)?
                        .1
                        .yubihsm_command(&command)?;
                    if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                        yubihsm_ecdsa_signature(
                            &response,
                            yubihsm_ec_coordinate_length(*algorithm)?,
                        )
                    } else {
                        Ok(response)
                    }
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let signature_bytes = match signature_result {
            Ok(signature) if signature.len() == required => signature,
            Ok(_) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_DEVICE_ERROR.into());
            }
            Err(error) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(error);
            }
        };

        unsafe {
            ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
        }
        *signature_len = required as CK_ULONG;
        ctx.sign_operations.remove(&session_handle);
        Ok(())
    })
}

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
    let signature = EcdsaSig::from_der(signature).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut output = Vec::with_capacity(coordinate_length * 2);
    for coordinate in [signature.r(), signature.s()] {
        let encoded = coordinate.to_vec();
        if encoded.len() > coordinate_length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        output.resize(output.len() + coordinate_length - encoded.len(), 0);
        output.extend_from_slice(&encoded);
    }
    Ok(output)
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
    openssl::rand::rand_bytes(&mut seed).map_err(|_| CKR_RANDOM_NO_RNG)?;
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
pub extern "C" fn C_SignUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let part = from_raw_parts(part, part_len as usize)?.to_vec();
        let operation = ctx
            .sign_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        operation.buffer.extend_from_slice(&part);
        Ok(())
    }))
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    session_handle: CK_SESSION_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(sign(
        session_handle,
        ptr::null(),
        0,
        signature,
        signature_len,
    ))
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    session_handle: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_VerifyInit called with {:?}",
        (session_handle, mechanism, key)
    );
    map(verify_init(session_handle, mechanism, key))
}

fn verify_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx.verify_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = _as_ref(mechanism)?;
        let pss = if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR)?;
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
            Some((
                mgf,
                u16::try_from(parameters.sLen)
                    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?,
                parameters.hashAlg,
            ))
        } else if piv_is_pss_mechanism(mechanism.mechanism) {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let digest =
                piv_hash_mechanism(mechanism.mechanism).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let hash = pss_hash_mechanism(mechanism.mechanism)?;
            Some((0, digest.size() as u16, hash))
        } else {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };
        let rsa_mechanism = mechanism.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            || mechanism.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
            || piv_is_hashed_rsa_pkcs(mechanism.mechanism)
            || piv_is_pss_mechanism(mechanism.mechanism);
        let ecdsa_mechanism = mechanism.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE
            || piv_is_hashed_ecdsa(mechanism.mechanism);
        let eddsa_mechanism = mechanism.mechanism == CKM_EDDSA as CK_MECHANISM_TYPE;
        if !rsa_mechanism && !ecdsa_mechanism && !eddsa_mechanism {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        let object = ctx
            .objects
            .get(&key)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if !object.verify {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        if object.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || (rsa_mechanism
                && (object.key_type != CKK_RSA as CK_KEY_TYPE
                    || !matches!(object.material, KeyMaterial::RsaPublic(_))))
            || (ecdsa_mechanism
                && (object.key_type != CKK_EC as CK_KEY_TYPE
                    || (!matches!(
                        &object.material,
                        KeyMaterial::PivPublic { .. } | KeyMaterial::OpenPgpPublic { .. }
                    ) && !matches!(
                        &object.material,
                        KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm)
                    ))))
            || (eddsa_mechanism
                && (object.key_type != CKK_EC_EDWARDS as CK_KEY_TYPE
                    || (!matches!(
                        &object.material,
                        KeyMaterial::PivPublic { .. } | KeyMaterial::OpenPgpPublic { .. }
                    ) && !matches!(
                        &object.material,
                        KeyMaterial::YubiHsm { algorithm, .. }
                            if *algorithm == YUBIHSM_ALGO_ED25519
                    ))))
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }

        ctx.verify_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: false,
                context_specific_extended: false,
                mechanism: mechanism.mechanism,
                pss,
                piv_pin_policy: None,
                buffer: Vec::new(),
            },
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_Verify(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Verify called with {:?}",
        (session_handle, data, data_len, signature, signature_len)
    );
    map(verify(
        session_handle,
        data,
        data_len,
        signature,
        signature_len,
    ))
}

fn verify(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *const ::std::os::raw::c_uchar,
    signature_len: CK_ULONG,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .verify_operations
            .remove(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let data = from_raw_parts(data, data_len as usize)?;
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let signature = from_raw_parts(signature, signature_len as usize)?;
        match &operation.key {
            KeyMaterial::RsaPublic(public_key) => {
                if signature.len() != public_key.size() as usize {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let mut recovered = vec![0; public_key.size() as usize];
                let padding = if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                    Padding::NONE
                } else {
                    Padding::PKCS1
                };
                let recovered_len = public_key
                    .public_decrypt(signature, &mut recovered, padding)
                    .map_err(|_| Error::from(CKR_SIGNATURE_INVALID))?;
                recovered.truncate(recovered_len);
                let expected = if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                    let digest = hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?;
                    piv_digest_info(operation.mechanism, digest.as_ref())
                        .ok_or(CKR_MECHANISM_INVALID)?
                } else if piv_is_pss_mechanism(operation.mechanism) {
                    let (mgf, salt_length, hash_mechanism) =
                        operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    let digest = if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
                        data.to_vec()
                    } else {
                        hash(
                            piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                            data,
                        )?
                        .to_vec()
                    };
                    if !verify_rsa_pss(
                        &recovered,
                        &digest,
                        hash_mechanism,
                        mgf,
                        salt_length as usize,
                    )? {
                        return Err(CKR_SIGNATURE_INVALID.into());
                    }
                    return Ok(());
                } else {
                    return Err(CKR_MECHANISM_INVALID.into());
                };
                if recovered != expected {
                    return Err(CKR_SIGNATURE_INVALID.into());
                }
                Ok(())
            }
            KeyMaterial::PivPublic {
                algorithm,
                public_key,
            } => {
                if *algorithm == piv::Algorithm::Ed25519 {
                    if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                        return Err(CKR_MECHANISM_INVALID.into());
                    }
                    return verify_ed25519(public_key, data, signature);
                }
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length =
                    piv_ec_coordinate_length(*algorithm).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = piv_ec_public_key(*algorithm, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::OpenPgpPublic {
                algorithm: OpenPgpAlgorithm::Ed25519,
                public_key,
            } => {
                if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                    return Err(CKR_MECHANISM_INVALID.into());
                }
                verify_ed25519(public_key, data, signature)
            }
            KeyMaterial::OpenPgpPublic {
                algorithm: OpenPgpAlgorithm::Ecdsa(curve),
                public_key,
            } => {
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length =
                    curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = openpgp_ec_public_key(*curve, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::YubiHsm {
                algorithm,
                public_key,
                ..
            } if is_yubihsm_ec(*algorithm) => {
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length = yubihsm_ec_coordinate_length(*algorithm)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = yubihsm_ec_public_key(*algorithm, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::YubiHsm {
                algorithm: YUBIHSM_ALGO_ED25519,
                public_key,
                ..
            } => {
                if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                    return Err(CKR_MECHANISM_INVALID.into());
                }
                verify_ed25519(public_key, data, signature)
            }
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        }
    })
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let part = from_raw_parts(part, part_len as usize)?.to_vec();
        let operation = ctx
            .verify_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        operation.buffer.extend_from_slice(&part);
        Ok(())
    }))
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    session_handle: CK_SESSION_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(verify(
        session_handle,
        ptr::null(),
        0,
        signature,
        signature_len,
    ))
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_VerifyRecover(
    session_handle: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
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

