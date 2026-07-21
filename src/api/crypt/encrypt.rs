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
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
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
