use super::shared::{rsa_oaep_pad, rsa_oaep_unpad, rsa_pkcs1_v1_5_unpad};
use crate::*;
use ghash::{universal_hash::UniversalHash, GHash};
use subtle::{ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

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
        false,
    ))
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
    encrypted_part: *mut ::std::os::raw::c_uchar,
    encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt_update(
        session_handle,
        part,
        part_len,
        encrypted_part,
        encrypted_part_len,
        true,
    ))
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    session_handle: CK_SESSION_HANDLE,
    last_encrypted_part: *mut ::std::os::raw::c_uchar,
    last_encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        ptr::null(),
        0,
        last_encrypted_part,
        last_encrypted_part_len,
        true,
        true,
    ))
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
        false,
    ))
}

#[cfg_attr(test, allow(private_interfaces))]
pub(crate) fn parse_gcm_parameters(mechanism: &CK_MECHANISM) -> Result<GcmParameters, Error> {
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

fn parse_ctr_parameters(mechanism: &CK_MECHANISM) -> Result<CtrParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_AES_CTR_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = _as_ref(mechanism.pParameter as CK_AES_CTR_PARAMS_PTR)?;
    let counter_bits = usize::try_from(parameters.ulCounterBits)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if !(1..=128).contains(&counter_bits) {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(CtrParameters {
        counter_bits,
        counter_block: parameters.cb,
    })
}

fn crypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
    encrypting: bool,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let operation_active = if encrypting {
            ctx.encrypt_operations.contains_key(&session_handle)
        } else {
            ctx.decrypt_operations.contains_key(&session_handle)
        };
        if mechanism.is_null() {
            let removed = if encrypting {
                ctx.encrypt_operations.remove(&session_handle)
            } else {
                ctx.decrypt_operations.remove(&session_handle)
            };
            return if removed.is_some() {
                Ok(())
            } else {
                Err(CKR_OPERATION_NOT_INITIALIZED.into())
            };
        }
        if operation_active {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        let mechanism = _as_ref(mechanism)?;
        require_slot_mechanism(
            ctx,
            slot_id,
            mechanism.mechanism,
            if encrypting {
                CKF_ENCRYPT as CK_FLAGS
            } else {
                CKF_DECRYPT as CK_FLAGS
            },
        )?;
        let (iv, ctr, gcm, oaep) = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_AES_ECB as CK_MECHANISM_TYPE
                || x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE =>
            {
                if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                (None, None, None, None)
            }
            x if x == CKM_AES_CBC as CK_MECHANISM_TYPE
                || x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE =>
            {
                if mechanism.ulParameterLen != 16 || mechanism.pParameter.is_null() {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let bytes = from_raw_parts(mechanism.pParameter as *const u8, 16)?;
                (
                    Some(bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?),
                    None,
                    None,
                    None,
                )
            }
            x if x == CKM_AES_CTR as CK_MECHANISM_TYPE => {
                (None, Some(parse_ctr_parameters(mechanism)?), None, None)
            }
            x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                (None, None, Some(parse_gcm_parameters(mechanism)?), None)
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
                    None,
                    Some((mgf, parameters.hashAlg, hash(digest, label)?.to_vec())),
                )
            }
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        let object = ctx
            .resolve_object(key)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if (encrypting && !object.encrypt) || (!encrypting && !object.decrypt) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let valid_key = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
            {
                object.key_type == CKK_RSA as CK_KEY_TYPE
                    && if encrypting {
                        rsa_public_key_material(&object.material)?.is_some()
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
            ctr,
            gcm,
            oaep,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
            buffer: Zeroizing::new(Vec::new()),
            multipart: false,
            result: None,
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

pub(crate) const AES_BLOCK_LENGTH: usize = 16;
const YUBIHSM_ECB_CHUNK_LENGTH: usize = 2016;

fn ghash(key: [u8; AES_BLOCK_LENGTH], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], Error> {
    let aad_bits = u64::try_from(aad.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let ciphertext_bits = u64::try_from(ciphertext.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let mut hash = GHash::new(&key.into());
    hash.update_padded(aad);
    hash.update_padded(ciphertext);
    let mut lengths = [0; AES_BLOCK_LENGTH];
    lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    hash.update(&[lengths.into()]);
    Ok(hash.finalize().into())
}

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_LENGTH]) {
    let value = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&value.to_be_bytes());
}

fn gcm_tag(full_tag: [u8; AES_BLOCK_LENGTH], tag_bits: usize) -> Vec<u8> {
    let tag_length = tag_bits.div_ceil(8);
    let mut tag = full_tag[..tag_length].to_vec();
    if !crate::is_multiple_of(tag_bits, 8) {
        let mask = 0xff << (8 - tag_bits % 8);
        if let Some(last) = tag.last_mut() {
            *last &= mask;
        }
    }
    tag
}

pub(crate) fn aes_gcm<F>(
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
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            expected_tag.as_slice(),
            supplied_tag,
        )) {
            transformed.fill(0);
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&expected_tag);
        Ok(transformed)
    }
}

fn yubihsm_crypt_ecb_blocks(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if !crate::is_multiple_of(blocks.len(), AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut output = Vec::with_capacity(blocks.len());
    for chunk in blocks.chunks(YUBIHSM_ECB_CHUNK_LENGTH) {
        let command = YubiHsmCommand::key_data(
            if encrypting {
                YubiHsmCommandCode::EncryptEcb
            } else {
                YubiHsmCommandCode::DecryptEcb
            },
            key_id,
            chunk,
        )?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        if response.len() != chunk.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        output.extend_from_slice(&response);
    }
    Ok(output)
}

pub(super) fn yubihsm_encrypt_ecb_blocks(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
) -> Result<Vec<u8>, Error> {
    yubihsm_crypt_ecb_blocks(ctx, session_handle, key_id, blocks, true)
}

fn aes_ctr<F>(
    parameters: &CtrParameters,
    input: &[u8],
    mut encrypt_blocks: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, Error>,
{
    let block_count = input.len().div_ceil(AES_BLOCK_LENGTH);
    let counter_capacity = block_count
        .checked_mul(AES_BLOCK_LENGTH)
        .ok_or(CKR_DATA_LEN_RANGE)?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    let initial = u128::from_be_bytes(parameters.counter_block);
    let mask = if parameters.counter_bits == 128 {
        u128::MAX
    } else {
        (1u128 << parameters.counter_bits) - 1
    };
    let fixed = initial & !mask;
    let initial_counter = initial & mask;
    for offset in 0..block_count {
        let offset = offset as u128;
        let counter = fixed | initial_counter.wrapping_add(offset) & mask;
        counter_blocks.extend_from_slice(&counter.to_be_bytes());
    }
    let key_stream = encrypt_blocks(&counter_blocks)?;
    if key_stream.len() != counter_blocks.len() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(input
        .iter()
        .zip(key_stream)
        .map(|(input, key_stream)| input ^ key_stream)
        .collect())
}

fn aes_kwp_transform<F>(
    input: &[u8],
    encrypting: bool,
    mut crypt_block: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8], bool) -> Result<Vec<u8>, Error>,
{
    const AIV_PREFIX: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];
    const SEMIBLOCK_LENGTH: usize = 8;

    if encrypting {
        if input.is_empty() || input.len() > u32::MAX as usize {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let semiblocks = input.len().div_ceil(SEMIBLOCK_LENGTH);
        let mut a = [0; SEMIBLOCK_LENGTH];
        a[..4].copy_from_slice(&AIV_PREFIX);
        a[4..].copy_from_slice(&(input.len() as u32).to_be_bytes());
        let mut r = input.to_vec();
        r.resize(semiblocks * SEMIBLOCK_LENGTH, 0);
        if semiblocks == 1 {
            let mut block = a.to_vec();
            block.extend_from_slice(&r);
            return crypt_block(&block, true);
        }
        for round in 0..6 {
            for index in 0..semiblocks {
                let mut block = a.to_vec();
                block.extend_from_slice(
                    &r[index * SEMIBLOCK_LENGTH..(index + 1) * SEMIBLOCK_LENGTH],
                );
                let transformed = crypt_block(&block, true)?;
                let transformed: [u8; AES_BLOCK_LENGTH] = transformed
                    .try_into()
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                let counter = semiblocks as u64 * round as u64 + index as u64 + 1;
                a.copy_from_slice(&transformed[..SEMIBLOCK_LENGTH]);
                for (byte, counter) in a.iter_mut().zip(counter.to_be_bytes()) {
                    *byte ^= counter;
                }
                r[index * SEMIBLOCK_LENGTH..(index + 1) * SEMIBLOCK_LENGTH]
                    .copy_from_slice(&transformed[SEMIBLOCK_LENGTH..]);
            }
        }
        let mut output = a.to_vec();
        output.extend_from_slice(&r);
        return Ok(output);
    }

    if input.len() < AES_BLOCK_LENGTH || !crate::is_multiple_of(input.len(), SEMIBLOCK_LENGTH) {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
    }
    let semiblocks = input.len() / SEMIBLOCK_LENGTH - 1;
    let mut a: [u8; SEMIBLOCK_LENGTH] = input[..SEMIBLOCK_LENGTH]
        .try_into()
        .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_INVALID))?;
    let mut r = input[SEMIBLOCK_LENGTH..].to_vec();
    if semiblocks == 1 {
        let transformed = crypt_block(input, false)?;
        let transformed: [u8; AES_BLOCK_LENGTH] = transformed
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        a.copy_from_slice(&transformed[..SEMIBLOCK_LENGTH]);
        r.copy_from_slice(&transformed[SEMIBLOCK_LENGTH..]);
    } else {
        for round in (0..6).rev() {
            for index in (0..semiblocks).rev() {
                let counter = semiblocks as u64 * round as u64 + index as u64 + 1;
                let mut block = a;
                for (byte, counter) in block.iter_mut().zip(counter.to_be_bytes()) {
                    *byte ^= counter;
                }
                let mut block = block.to_vec();
                block.extend_from_slice(
                    &r[index * SEMIBLOCK_LENGTH..(index + 1) * SEMIBLOCK_LENGTH],
                );
                let transformed = crypt_block(&block, false)?;
                let transformed: [u8; AES_BLOCK_LENGTH] = transformed
                    .try_into()
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                a.copy_from_slice(&transformed[..SEMIBLOCK_LENGTH]);
                r[index * SEMIBLOCK_LENGTH..(index + 1) * SEMIBLOCK_LENGTH]
                    .copy_from_slice(&transformed[SEMIBLOCK_LENGTH..]);
            }
        }
    }

    let message_length = u32::from_be_bytes(
        a[4..]
            .try_into()
            .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_INVALID))?,
    ) as usize;
    let minimum_length = (semiblocks - 1) * SEMIBLOCK_LENGTH;
    let maximum_length = semiblocks * SEMIBLOCK_LENGTH;
    let mut invalid = !a[..4].ct_eq(&AIV_PREFIX);
    invalid |= !(message_length as u64).ct_gt(&(minimum_length as u64));
    invalid |= (message_length as u64).ct_gt(&(maximum_length as u64));
    for (index, byte) in r.iter().enumerate() {
        invalid |= !(index as u64).ct_lt(&(message_length as u64)) & !byte.ct_eq(&0);
    }
    if bool::from(invalid) {
        r.fill(0);
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    r.truncate(message_length);
    Ok(r)
}

fn remove_pkcs7_padding(mut plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
    let padding = plaintext.last().copied().unwrap_or_default();
    let mut invalid = padding.ct_eq(&0) | padding.ct_gt(&(AES_BLOCK_LENGTH as u8));
    for (index, byte) in plaintext.iter().rev().take(AES_BLOCK_LENGTH).enumerate() {
        invalid |= (index as u8).ct_lt(&padding) & !byte.ct_eq(&padding);
    }
    if bool::from(invalid) {
        plaintext.fill(0);
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    plaintext.truncate(plaintext.len() - padding as usize);
    Ok(plaintext)
}

pub(crate) fn yubihsm_aes_cbc_pad(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    iv: &[u8; AES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    let prepared = if encrypting {
        let padding_length = AES_BLOCK_LENGTH - input.len() % AES_BLOCK_LENGTH;
        let padded_length = input
            .len()
            .checked_add(padding_length)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        let mut padded = Vec::with_capacity(padded_length);
        padded.extend_from_slice(input);
        padded.resize(padded_length, padding_length as u8);
        padded
    } else {
        if input.is_empty() || !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
        }
        input.to_vec()
    };
    let command = YubiHsmCommand::crypt_cbc(
        if encrypting {
            YubiHsmCommandCode::EncryptCbc
        } else {
            YubiHsmCommandCode::DecryptCbc
        },
        key_id,
        iv,
        &prepared,
    )?;
    let output = ctx
        ._get_session(session_handle)?
        .1
        .yubihsm_command(&command)?;
    if output.len() != prepared.len() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    if encrypting {
        Ok(output)
    } else {
        remove_pkcs7_padding(output)
    }
}

fn crypt(
    session_handle: CK_SESSION_HANDLE,
    input: *const u8,
    input_len: CK_ULONG,
    output: *mut u8,
    output_len: CK_ULONG_PTR,
    encrypting: bool,
    finalizing: bool,
) -> Result<(), Error> {
    if output_len.is_null() {
        let _ = with_session_context_mut(session_handle, |ctx| {
            ctx.encrypt_operations.remove(&session_handle);
            ctx.decrypt_operations.remove(&session_handle);
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = as_mut(output_len)?;
    with_session_context_mut(session_handle, |ctx| {
        ctx._get_session(session_handle)?;
        let operation = if encrypting {
            ctx.encrypt_operations.get(&session_handle)
        } else {
            ctx.decrypt_operations.get(&session_handle)
        }
        .cloned()
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.multipart && !finalizing {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
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
        let mut buffered_input = operation.buffer.clone();
        buffered_input.extend_from_slice(input);
        let input = buffered_input.as_slice();
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
        } else if operation.mechanism == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE {
            if encrypting {
                let Some(required) = input
                    .len()
                    .checked_add(AES_BLOCK_LENGTH - input.len() % AES_BLOCK_LENGTH)
                else {
                    ctx.encrypt_operations.remove(&session_handle);
                    ctx.decrypt_operations.remove(&session_handle);
                    return Err(CKR_DATA_LEN_RANGE.into());
                };
                required
            } else {
                if input.is_empty() || !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
                    ctx.encrypt_operations.remove(&session_handle);
                    ctx.decrypt_operations.remove(&session_handle);
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len()
            }
        } else if operation.mechanism == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE {
            if encrypting {
                if input.is_empty() || input.len() > u32::MAX as usize {
                    ctx.encrypt_operations.remove(&session_handle);
                    return Err(CKR_DATA_LEN_RANGE.into());
                }
                input
                    .len()
                    .div_ceil(8)
                    .checked_add(1)
                    .and_then(|semiblocks| semiblocks.checked_mul(8))
                    .ok_or(CKR_DATA_LEN_RANGE)?
            } else {
                if input.len() < AES_BLOCK_LENGTH || !crate::is_multiple_of(input.len(), 8) {
                    ctx.decrypt_operations.remove(&session_handle);
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len() - 8
            }
        } else {
            match &operation.key {
                KeyMaterial::RsaPublic(key) => key.size(),
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
        let result = if let Some(result) = operation.result {
            result.to_vec()
        } else {
            let result = (|| -> Result<Vec<u8>, Error> {
                if encrypting {
                    if let Some(public_key) = rsa_public_key_material(&operation.key)? {
                        return rsa_public_encrypt(
                            &public_key,
                            operation.mechanism,
                            operation.oaep.as_ref(),
                            input,
                        );
                    }
                }
                match &operation.key {
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
                            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
                                rsa_pkcs1_v1_5_unpad(&raw)
                            }
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
                                YubiHsmCommand::key_data(
                                    YubiHsmCommandCode::DecryptPkcs1,
                                    *id,
                                    input,
                                )?
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
                            x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => {
                                YubiHsmCommand::crypt_cbc(
                                    if encrypting {
                                        YubiHsmCommandCode::EncryptCbc
                                    } else {
                                        YubiHsmCommandCode::DecryptCbc
                                    },
                                    *id,
                                    operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                    input,
                                )?
                            }
                            x if x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE => {
                                return yubihsm_aes_cbc_pad(
                                    ctx,
                                    session_handle,
                                    *id,
                                    operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                    input,
                                    encrypting,
                                );
                            }
                            x if x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE => {
                                return aes_kwp_transform(
                                    input,
                                    encrypting,
                                    |block, encrypting| {
                                        yubihsm_crypt_ecb_blocks(
                                            ctx,
                                            session_handle,
                                            *id,
                                            block,
                                            encrypting,
                                        )
                                    },
                                );
                            }
                            x if x == CKM_AES_CTR as CK_MECHANISM_TYPE => {
                                return aes_ctr(
                                    operation.ctr.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                    input,
                                    |blocks| {
                                        yubihsm_encrypt_ecb_blocks(ctx, session_handle, *id, blocks)
                                    },
                                );
                            }
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
            match result {
                Ok(result) => result,
                Err(error) => {
                    ctx.encrypt_operations.remove(&session_handle);
                    ctx.decrypt_operations.remove(&session_handle);
                    return Err(error);
                }
            }
        };
        if *output_len < result.len() as CK_ULONG {
            *output_len = result.len() as CK_ULONG;
            let operations = if encrypting {
                &mut ctx.encrypt_operations
            } else {
                &mut ctx.decrypt_operations
            };
            if let Some(operation) = operations.get_mut(&session_handle) {
                operation.result = Some(Zeroizing::new(result));
            }
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        unsafe { ptr::copy_nonoverlapping(result.as_ptr(), output, result.len()) };
        *output_len = result.len() as CK_ULONG;
        ctx.encrypt_operations.remove(&session_handle);
        ctx.decrypt_operations.remove(&session_handle);
        Ok(())
    })
}

fn rsa_public_encrypt(
    key: &RsaPublicKey,
    mechanism: CK_MECHANISM_TYPE,
    oaep: Option<&(u8, CK_MECHANISM_TYPE, Vec<u8>)>,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
        rsa_pkcs1_encrypt(key, input)
    } else if mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
        if input.len() != key.size() {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        rsa_public_operation(key, input)
    } else if mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE {
        let (mgf, hash_mechanism, label_digest) = oaep.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        let encoded = rsa_oaep_pad(input, key.size(), *mgf, *hash_mechanism, label_digest)?;
        rsa_public_operation(key, &encoded)
    } else {
        Err(CKR_MECHANISM_INVALID.into())
    }
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    encrypted_part: *mut ::std::os::raw::c_uchar,
    encrypted_part_len: ::std::os::raw::c_ulong,
    part: *mut ::std::os::raw::c_uchar,
    part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt_update(
        session_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        part_len,
        false,
    ))
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    session_handle: CK_SESSION_HANDLE,
    last_part: *mut ::std::os::raw::c_uchar,
    last_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        ptr::null(),
        0,
        last_part,
        last_part_len,
        false,
        true,
    ))
}

fn crypt_update(
    session_handle: CK_SESSION_HANDLE,
    input: *const u8,
    input_len: CK_ULONG,
    output: *mut u8,
    output_len: CK_ULONG_PTR,
    encrypting: bool,
) -> Result<(), Error> {
    if output_len.is_null() {
        return with_session_context_mut(session_handle, |ctx| {
            ctx._get_session(session_handle)?;
            if encrypting {
                ctx.encrypt_operations.remove(&session_handle);
            } else {
                ctx.decrypt_operations.remove(&session_handle);
            }
            Err(CKR_ARGUMENTS_BAD.into())
        });
    }
    let output_len = as_mut(output_len)?;
    with_session_context_mut(session_handle, |ctx| {
        ctx._get_session(session_handle)?;
        let operation = if encrypting {
            ctx.encrypt_operations.get(&session_handle)
        } else {
            ctx.decrypt_operations.get(&session_handle)
        }
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            let slot_id = operation.slot_id;
            ctx.reconcile_login_state(slot_id);
            if encrypting {
                ctx.encrypt_operations.remove(&session_handle);
            } else {
                ctx.decrypt_operations.remove(&session_handle);
            }
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if operation.result.is_some() {
            if encrypting {
                ctx.encrypt_operations.remove(&session_handle);
            } else {
                ctx.decrypt_operations.remove(&session_handle);
            }
            return Err(CKR_OPERATION_NOT_INITIALIZED.into());
        }
        let input = match from_raw_parts(input, input_len as usize) {
            Ok(input) => input,
            Err(error) => {
                if encrypting {
                    ctx.encrypt_operations.remove(&session_handle);
                } else {
                    ctx.decrypt_operations.remove(&session_handle);
                }
                return Err(error);
            }
        };
        *output_len = 0;
        if output.is_null() {
            return Ok(());
        }
        let operation = if encrypting {
            ctx.encrypt_operations.get_mut(&session_handle)
        } else {
            ctx.decrypt_operations.get_mut(&session_handle)
        }
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.buffer.try_reserve(input.len()).is_err() {
            if encrypting {
                ctx.encrypt_operations.remove(&session_handle);
            } else {
                ctx.decrypt_operations.remove(&session_handle);
            }
            return Err(CKR_HOST_MEMORY.into());
        }
        operation.buffer.extend_from_slice(input);
        operation.multipart = true;
        Ok(())
    })
}
