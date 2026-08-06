use super::shared::{
    parse_rsa_oaep_parameters, rsa_oaep_pad, rsa_oaep_unpad, rsa_pkcs1_v1_5_unpad,
};
use crate::backed_object::projected_public_key_material;
use crate::*;
use ghash::{universal_hash::UniversalHash, GHash};
use subtle::{ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

ffi_entry_point! {
    pub fn C_EncryptInit(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        map(crypt_init(session_handle, mechanism, key, true))
    }
}

ffi_entry_point! {
    pub fn C_Encrypt(
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
}

ffi_entry_point! {
    pub fn C_EncryptUpdate(
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
}

ffi_entry_point! {
    pub fn C_EncryptFinal(
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
}

ffi_entry_point! {
    pub fn C_DecryptInit(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        map(crypt_init(session_handle, mechanism, key, false))
    }
}

ffi_entry_point! {
    pub fn C_Decrypt(
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
}

#[cfg_attr(test, allow(private_interfaces))]
pub(crate) fn parse_gcm_parameters(mechanism: &CK_MECHANISM) -> Result<GcmParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_GCM_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_GCM_PARAMS_PTR) }?;
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
        iv: unsafe { from_raw_parts(parameters.pIv as *const u8, iv_len) }?.to_vec(),
        aad: unsafe { from_raw_parts(parameters.pAAD as *const u8, aad_len) }?.to_vec(),
        tag_bits,
    })
}

fn parse_ctr_parameters(mechanism: &CK_MECHANISM) -> Result<CtrParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_AES_CTR_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_AES_CTR_PARAMS_PTR) }?;
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

fn parse_ccm_parameters(mechanism: &CK_MECHANISM) -> Result<CcmParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_CCM_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_CCM_PARAMS_PTR) }?;
    let data_len = usize::try_from(parameters.ulDataLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let nonce_len = usize::try_from(parameters.ulNonceLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let aad_len = usize::try_from(parameters.ulAADLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let mac_len = usize::try_from(parameters.ulMACLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if !(7..=13).contains(&nonce_len)
        || !matches!(mac_len, 4 | 6 | 8 | 10 | 12 | 14 | 16)
        || aad_len > u32::MAX as usize
        || parameters.pNonce.is_null()
        || (aad_len != 0 && parameters.pAAD.is_null())
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let length_bytes = 15 - nonce_len;
    if length_bytes < 8 && data_len as u128 >= 1u128 << (length_bytes * 8) {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(CcmParameters {
        data_len,
        nonce: unsafe { from_raw_parts(parameters.pNonce as *const u8, nonce_len) }?.to_vec(),
        aad: unsafe { from_raw_parts(parameters.pAAD as *const u8, aad_len) }?.to_vec(),
        mac_len,
    })
}

pub(crate) fn parse_key_wrap_iv(
    mechanism: &CK_MECHANISM,
    default: &[u8],
) -> Result<Vec<u8>, Error> {
    if mechanism.pParameter.is_null() && mechanism.ulParameterLen == 0 {
        return Ok(default.to_vec());
    }
    if mechanism.pParameter.is_null() || mechanism.ulParameterLen as usize != default.len() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(unsafe { from_raw_parts(mechanism.pParameter.cast::<u8>(), default.len()) }?.to_vec())
}

fn crypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
    encrypting: bool,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let operation_active = ctx
            .get_session_context(session_handle)?
            .crypt_operation(encrypting)
            .is_some();
        if mechanism.is_null() {
            let removed = ctx
                .get_session_context_mut(session_handle)?
                .take_crypt_operation(encrypting);
            return if removed.is_some() {
                Ok(())
            } else {
                Err(CKR_OPERATION_NOT_INITIALIZED.into())
            };
        }
        if operation_active {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        let mechanism = unsafe { _as_ref(mechanism) }?;
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
        let des3_iv = if matches!(
            mechanism.mechanism,
            x if x == CKM_DES3_CBC as CK_MECHANISM_TYPE
                || x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE
        ) {
            if mechanism.ulParameterLen != 8 || mechanism.pParameter.is_null() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let bytes = unsafe { from_raw_parts(mechanism.pParameter.cast::<u8>(), 8) }?;
            Some(bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?)
        } else {
            None
        };
        let (iv, ctr, ccm, gcm, key_wrap_iv, oaep) = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_AES_ECB as CK_MECHANISM_TYPE
                || x == CKM_DES3_ECB as CK_MECHANISM_TYPE
                || x == CKM_YUBICO_AES_CCM_WRAP =>
            {
                if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                (None, None, None, None, None, None)
            }
            x if x == CKM_DES3_CBC as CK_MECHANISM_TYPE
                || x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE =>
            {
                (None, None, None, None, None, None)
            }
            x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE => (
                None,
                None,
                None,
                None,
                Some(parse_key_wrap_iv(mechanism, &[0xa6; 8])?),
                None,
            ),
            x if x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE => (
                None,
                None,
                None,
                None,
                Some(parse_key_wrap_iv(mechanism, &[0xa6, 0x59, 0x59, 0xa6])?),
                None,
            ),
            x if x == CKM_AES_CBC as CK_MECHANISM_TYPE
                || x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE =>
            {
                if mechanism.ulParameterLen != 16 || mechanism.pParameter.is_null() {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let bytes = unsafe { from_raw_parts(mechanism.pParameter as *const u8, 16) }?;
                (
                    Some(bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }
            x if x == CKM_AES_CTR as CK_MECHANISM_TYPE => (
                None,
                Some(parse_ctr_parameters(mechanism)?),
                None,
                None,
                None,
                None,
            ),
            x if x == CKM_AES_CCM as CK_MECHANISM_TYPE => (
                None,
                None,
                Some(parse_ccm_parameters(mechanism)?),
                None,
                None,
                None,
            ),
            x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => (
                None,
                None,
                None,
                Some(parse_gcm_parameters(mechanism)?),
                None,
                None,
            ),
            x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => (
                None,
                None,
                None,
                None,
                None,
                Some(parse_rsa_oaep_parameters(mechanism)?),
            ),
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        let object = ctx
            .resolve_object(key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        require_key_mechanism(&object, mechanism.mechanism)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if (encrypting && !object.encrypt) || (!encrypting && !object.decrypt) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let rsa_mechanism = matches!(
            mechanism.mechanism,
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE
        );
        let operation_key = if encrypting && rsa_mechanism {
            projected_public_key_material(&object)?
        } else {
            object.material.clone()
        };
        let valid_key = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
            {
                object.key_type == CKK_RSA as CK_KEY_TYPE
                    && if encrypting {
                        rsa_public_key_material(&operation_key)?.is_some()
                    } else {
                        matches!(
                            object.material,
                            KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(_))
                                | KeyMaterial::YubiHsm { .. }
                                | KeyMaterial::PivPrivate { .. }
                                | KeyMaterial::OpenPgpPrivate { .. }
                        )
                    }
            }
            x if x == CKM_YUBICO_AES_CCM_WRAP => {
                matches!(
                    object.key_type,
                    CKK_YUBICO_AES128_CCM_WRAP
                        | CKK_YUBICO_AES192_CCM_WRAP
                        | CKK_YUBICO_AES256_CCM_WRAP
                ) && matches!(
                    &object.material,
                    KeyMaterial::YubiHsm {
                        object_type: YUBIHSM_WRAP_KEY,
                        algorithm,
                        ..
                    } if is_yubihsm_ccm_wrap(*algorithm)
                )
            }
            x if x == CKM_DES3_ECB as CK_MECHANISM_TYPE
                || x == CKM_DES3_CBC as CK_MECHANISM_TYPE
                || x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE =>
            {
                object.key_type == CKK_DES3 as CK_KEY_TYPE
                    && matches!(object.material, KeyMaterial::SoftwareSecret(_))
            }
            _ => {
                object.key_type == CKK_AES as CK_KEY_TYPE
                    && matches!(
                        object.material,
                        KeyMaterial::YubiHsm { .. } | KeyMaterial::SoftwareSecret(_)
                    )
            }
        };
        if !valid_key {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let operation = CryptOperation {
            key: operation_key,
            public_key: object.public_key.clone(),
            slot_id,
            requires_login: object.private
                && ctx.get_slot(slot_id)?.private_objects_require_login(),
            context_specific_extended: matches!(
                &object.material,
                KeyMaterial::OpenPgpPrivate { .. }
            ),
            mechanism: mechanism.mechanism,
            iv,
            des3_iv,
            ctr,
            ccm,
            gcm,
            key_wrap_iv,
            oaep,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
            buffer: Zeroizing::new(Vec::new()),
            multipart: false,
            result: None,
        };
        ctx.get_session_context_mut(session_handle)?
            .set_crypt_operation(encrypting, operation);
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
const TDES_BLOCK_LENGTH: usize = 8;
const YUBIHSM_ECB_CHUNK_LENGTH: usize = 2016;
const YUBIHSM_CBC_CHUNK_LENGTH: usize = 2000;
const YUBIHSM_CCM_WRAP_OVERHEAD: usize = 1 + 13 + 16;

pub(crate) fn software_crypt_ecb_blocks(
    key: &[u8],
    blocks: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    if !crate::is_multiple_of(blocks.len(), AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut output = blocks.to_vec();
    macro_rules! transform {
        ($cipher:ty) => {{
            let cipher = <$cipher as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::from(CKR_KEY_SIZE_RANGE))?;
            for block in output.chunks_exact_mut(AES_BLOCK_LENGTH) {
                let block = aes::cipher::Block::<$cipher>::from_mut_slice(block);
                if encrypting {
                    cipher.encrypt_block(block);
                } else {
                    cipher.decrypt_block(block);
                }
            }
        }};
    }
    match key.len() {
        16 => transform!(aes::Aes128),
        24 => transform!(aes::Aes192),
        32 => transform!(aes::Aes256),
        _ => return Err(CKR_KEY_SIZE_RANGE.into()),
    }
    Ok(output)
}

fn software_tdes_ecb_blocks(key: &[u8], blocks: &[u8], encrypting: bool) -> Result<Vec<u8>, Error> {
    use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    if key.len() != 24 {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    if !crate::is_multiple_of(blocks.len(), TDES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let cipher = des::TdesEde3::new_from_slice(key).map_err(|_| CKR_KEY_SIZE_RANGE)?;
    let mut output = blocks.to_vec();
    for chunk in output.chunks_exact_mut(TDES_BLOCK_LENGTH) {
        let block = des::cipher::Block::<des::TdesEde3>::from_mut_slice(chunk);
        if encrypting {
            cipher.encrypt_block(block);
        } else {
            cipher.decrypt_block(block);
        }
    }
    Ok(output)
}

fn software_tdes_cbc(
    key: &[u8],
    iv: &[u8; TDES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if !crate::is_multiple_of(input.len(), TDES_BLOCK_LENGTH) {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }
    let mut previous = *iv;
    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks_exact(TDES_BLOCK_LENGTH) {
        let block: [u8; TDES_BLOCK_LENGTH] = chunk.try_into().map_err(|_| CKR_DATA_LEN_RANGE)?;
        if encrypting {
            let mixed: [u8; TDES_BLOCK_LENGTH] =
                std::array::from_fn(|index| block[index] ^ previous[index]);
            let encrypted = software_tdes_ecb_blocks(key, &mixed, true)?;
            previous.copy_from_slice(&encrypted);
            output.extend_from_slice(&encrypted);
        } else {
            let decrypted = software_tdes_ecb_blocks(key, &block, false)?;
            output.extend(
                decrypted
                    .iter()
                    .zip(previous)
                    .map(|(value, previous)| value ^ previous),
            );
            previous = block;
        }
    }
    Ok(output)
}

fn software_tdes_cbc_pad(
    key: &[u8],
    iv: &[u8; TDES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if encrypting {
        let padding_length = TDES_BLOCK_LENGTH - input.len() % TDES_BLOCK_LENGTH;
        let padded_length = input
            .len()
            .checked_add(padding_length)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        let mut padded = Vec::with_capacity(padded_length);
        padded.extend_from_slice(input);
        padded.resize(padded_length, padding_length as u8);
        software_tdes_cbc(key, iv, &padded, true)
    } else {
        if input.is_empty() || !crate::is_multiple_of(input.len(), TDES_BLOCK_LENGTH) {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
        }
        remove_pkcs7_padding(software_tdes_cbc(key, iv, input, false)?, TDES_BLOCK_LENGTH)
    }
}

fn software_aes_cbc(
    key: &[u8],
    iv: &[u8; AES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }
    let mut output = Vec::with_capacity(input.len());
    let mut previous = *iv;
    for input_block in input.chunks_exact(AES_BLOCK_LENGTH) {
        if encrypting {
            let block = Zeroizing::new(
                input_block
                    .iter()
                    .zip(previous)
                    .map(|(value, previous)| value ^ previous)
                    .collect::<Vec<_>>(),
            );
            let encrypted = software_crypt_ecb_blocks(key, &block, true)?;
            previous.copy_from_slice(&encrypted);
            output.extend_from_slice(&encrypted);
        } else {
            let decrypted = Zeroizing::new(software_crypt_ecb_blocks(key, input_block, false)?);
            output.extend(
                decrypted
                    .iter()
                    .zip(previous)
                    .map(|(value, previous)| value ^ previous),
            );
            previous.copy_from_slice(input_block);
        }
    }
    Ok(output)
}

fn software_aes_cbc_pad(
    key: &[u8],
    iv: &[u8; AES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if encrypting {
        let padding_length = AES_BLOCK_LENGTH - input.len() % AES_BLOCK_LENGTH;
        let padded_length = input
            .len()
            .checked_add(padding_length)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_length));
        padded.extend_from_slice(input);
        padded.resize(padded_length, padding_length as u8);
        software_aes_cbc(key, iv, &padded, true)
    } else {
        if input.is_empty() || !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
        }
        remove_pkcs7_padding(software_aes_cbc(key, iv, input, false)?, AES_BLOCK_LENGTH)
    }
}

fn software_cbc_mac(key: &[u8], blocks: &[u8]) -> Result<Vec<u8>, Error> {
    if blocks.is_empty() || !crate::is_multiple_of(blocks.len(), AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let output = software_aes_cbc(key, &[0; AES_BLOCK_LENGTH], blocks, true)?;
    Ok(output[output.len() - AES_BLOCK_LENGTH..].to_vec())
}

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

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_LENGTH]) -> Result<(), Error> {
    let value = u32::from_be_bytes(
        counter
            .get(12..)
            .and_then(|value| <[u8; 4]>::try_from(value).ok())
            .ok_or(CKR_FUNCTION_FAILED)?,
    )
    .wrapping_add(1);
    counter[12..].copy_from_slice(&value.to_be_bytes());
    Ok(())
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
        increment_gcm_counter(&mut initial_counter)?;
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
    ctx: &mut SlotContext,
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
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
) -> Result<Vec<u8>, Error> {
    yubihsm_crypt_ecb_blocks(ctx, session_handle, key_id, blocks, true)
}

fn yubihsm_cbc_mac(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
) -> Result<[u8; AES_BLOCK_LENGTH], Error> {
    if blocks.is_empty() || !crate::is_multiple_of(blocks.len(), AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut iv = [0; AES_BLOCK_LENGTH];
    for chunk in blocks.chunks(YUBIHSM_CBC_CHUNK_LENGTH) {
        let command =
            YubiHsmCommand::crypt_cbc(YubiHsmCommandCode::EncryptCbc, key_id, &iv, chunk)?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        if response.len() != chunk.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        iv.copy_from_slice(&response[response.len() - AES_BLOCK_LENGTH..]);
    }
    Ok(iv)
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

#[derive(Clone, Copy)]
enum CcmOperation {
    EncryptBlocks,
    CbcMac,
}

fn aes_ccm<F>(
    parameters: &CcmParameters,
    input: &[u8],
    encrypting: bool,
    mut crypt: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(CcmOperation, &[u8]) -> Result<Vec<u8>, Error>,
{
    let expected_input = if encrypting {
        parameters.data_len
    } else {
        parameters
            .data_len
            .checked_add(parameters.mac_len)
            .ok_or(CKR_ENCRYPTED_DATA_LEN_RANGE)?
    };
    if input.len() != expected_input {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }
    let (payload, supplied_tag) = if encrypting {
        (input, None)
    } else {
        (
            &input[..parameters.data_len],
            Some(&input[parameters.data_len..]),
        )
    };

    let length_bytes = 15 - parameters.nonce.len();
    let block_count = parameters.data_len.div_ceil(AES_BLOCK_LENGTH);
    let counter_capacity = block_count
        .checked_add(1)
        .and_then(|blocks| blocks.checked_mul(AES_BLOCK_LENGTH))
        .ok_or(CKR_DATA_LEN_RANGE)?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    for counter in 0..=block_count {
        let mut block = [0; AES_BLOCK_LENGTH];
        block[0] = (length_bytes - 1) as u8;
        block[1..1 + parameters.nonce.len()].copy_from_slice(&parameters.nonce);
        let encoded = (counter as u64).to_be_bytes();
        block[AES_BLOCK_LENGTH - length_bytes..]
            .copy_from_slice(&encoded[encoded.len() - length_bytes..]);
        counter_blocks.extend_from_slice(&block);
    }
    let key_stream = crypt(CcmOperation::EncryptBlocks, &counter_blocks)?;
    if key_stream.len() != counter_blocks.len() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut transformed = Vec::with_capacity(payload.len());
    for (block, key_stream) in payload
        .chunks(AES_BLOCK_LENGTH)
        .zip(key_stream[AES_BLOCK_LENGTH..].chunks(AES_BLOCK_LENGTH))
    {
        transformed.extend(
            block
                .iter()
                .zip(key_stream)
                .map(|(input, key_stream)| input ^ key_stream),
        );
    }
    let plaintext = if encrypting {
        payload
    } else {
        transformed.as_slice()
    };

    let mut mac_input = Zeroizing::new(Vec::new());
    let mut b0 = [0; AES_BLOCK_LENGTH];
    b0[0] = u8::from(!parameters.aad.is_empty()) << 6
        | (((parameters.mac_len - 2) / 2) as u8) << 3
        | (length_bytes - 1) as u8;
    b0[1..1 + parameters.nonce.len()].copy_from_slice(&parameters.nonce);
    let encoded_length = (parameters.data_len as u64).to_be_bytes();
    b0[AES_BLOCK_LENGTH - length_bytes..]
        .copy_from_slice(&encoded_length[encoded_length.len() - length_bytes..]);
    mac_input.extend_from_slice(&b0);
    if !parameters.aad.is_empty() {
        if parameters.aad.len() < 0xff00 {
            mac_input.extend_from_slice(&(parameters.aad.len() as u16).to_be_bytes());
        } else {
            mac_input.extend_from_slice(&[0xff, 0xfe]);
            mac_input.extend_from_slice(&(parameters.aad.len() as u32).to_be_bytes());
        }
        mac_input.extend_from_slice(&parameters.aad);
        let padded_length = mac_input.len().next_multiple_of(AES_BLOCK_LENGTH);
        mac_input.resize(padded_length, 0);
    }
    mac_input.extend_from_slice(plaintext);
    let padded_length = mac_input.len().next_multiple_of(AES_BLOCK_LENGTH);
    mac_input.resize(padded_length, 0);
    let mac = crypt(CcmOperation::CbcMac, &mac_input)?;
    let mac: [u8; AES_BLOCK_LENGTH] = mac.try_into().map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let tag = mac[..parameters.mac_len]
        .iter()
        .zip(&key_stream[..parameters.mac_len])
        .map(|(mac, mask)| mac ^ mask)
        .collect::<Vec<_>>();

    if let Some(supplied_tag) = supplied_tag {
        if !bool::from(tag.ct_eq(supplied_tag)) {
            transformed.fill(0);
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&tag);
        Ok(transformed)
    }
}

const AES_KEY_WRAP_SEMIBLOCK_LENGTH: usize = 8;

fn aes_key_wrap_rounds<F>(
    mut a: [u8; AES_KEY_WRAP_SEMIBLOCK_LENGTH],
    mut r: Vec<u8>,
    encrypting: bool,
    crypt_block: &mut F,
) -> Result<([u8; AES_KEY_WRAP_SEMIBLOCK_LENGTH], Vec<u8>), Error>
where
    F: FnMut(&[u8], bool) -> Result<Vec<u8>, Error>,
{
    let semiblocks = r.len() / AES_KEY_WRAP_SEMIBLOCK_LENGTH;
    if encrypting {
        for round in 0..6 {
            for index in 0..semiblocks {
                let mut block = a.to_vec();
                block.extend_from_slice(
                    &r[index * AES_KEY_WRAP_SEMIBLOCK_LENGTH
                        ..(index + 1) * AES_KEY_WRAP_SEMIBLOCK_LENGTH],
                );
                let transformed: [u8; AES_BLOCK_LENGTH] = crypt_block(&block, true)?
                    .try_into()
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                let counter = semiblocks as u64 * round as u64 + index as u64 + 1;
                a.copy_from_slice(&transformed[..AES_KEY_WRAP_SEMIBLOCK_LENGTH]);
                for (byte, counter) in a.iter_mut().zip(counter.to_be_bytes()) {
                    *byte ^= counter;
                }
                r[index * AES_KEY_WRAP_SEMIBLOCK_LENGTH
                    ..(index + 1) * AES_KEY_WRAP_SEMIBLOCK_LENGTH]
                    .copy_from_slice(&transformed[AES_KEY_WRAP_SEMIBLOCK_LENGTH..]);
            }
        }
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
                    &r[index * AES_KEY_WRAP_SEMIBLOCK_LENGTH
                        ..(index + 1) * AES_KEY_WRAP_SEMIBLOCK_LENGTH],
                );
                let transformed: [u8; AES_BLOCK_LENGTH] = crypt_block(&block, false)?
                    .try_into()
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                a.copy_from_slice(&transformed[..AES_KEY_WRAP_SEMIBLOCK_LENGTH]);
                r[index * AES_KEY_WRAP_SEMIBLOCK_LENGTH
                    ..(index + 1) * AES_KEY_WRAP_SEMIBLOCK_LENGTH]
                    .copy_from_slice(&transformed[AES_KEY_WRAP_SEMIBLOCK_LENGTH..]);
            }
        }
    }
    Ok((a, r))
}

pub(crate) fn aes_key_wrap_transform<F>(
    input: &[u8],
    encrypting: bool,
    initial_value: &[u8],
    mut crypt_block: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8], bool) -> Result<Vec<u8>, Error>,
{
    if initial_value.len() != AES_KEY_WRAP_SEMIBLOCK_LENGTH {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if encrypting {
        if input.len() < AES_BLOCK_LENGTH
            || !crate::is_multiple_of(input.len(), AES_KEY_WRAP_SEMIBLOCK_LENGTH)
        {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let a = initial_value
            .try_into()
            .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
        let (a, r) = aes_key_wrap_rounds(a, input.to_vec(), true, &mut crypt_block)?;
        let mut output = a.to_vec();
        output.extend_from_slice(&r);
        return Ok(output);
    }

    if input.len() < AES_BLOCK_LENGTH + AES_KEY_WRAP_SEMIBLOCK_LENGTH
        || !crate::is_multiple_of(input.len(), AES_KEY_WRAP_SEMIBLOCK_LENGTH)
    {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
    }
    let a = input[..AES_KEY_WRAP_SEMIBLOCK_LENGTH]
        .try_into()
        .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_INVALID))?;
    let (a, mut r) = aes_key_wrap_rounds(
        a,
        input[AES_KEY_WRAP_SEMIBLOCK_LENGTH..].to_vec(),
        false,
        &mut crypt_block,
    )?;
    if !bool::from(a.ct_eq(initial_value)) {
        r.fill(0);
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(r)
}

pub(crate) fn aes_kwp_transform<F>(
    input: &[u8],
    encrypting: bool,
    alternative_initial_value: &[u8],
    mut crypt_block: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8], bool) -> Result<Vec<u8>, Error>,
{
    if alternative_initial_value.len() != 4 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if encrypting {
        if input.is_empty() || input.len() > u32::MAX as usize {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let semiblocks = input.len().div_ceil(AES_KEY_WRAP_SEMIBLOCK_LENGTH);
        let mut a = [0; AES_KEY_WRAP_SEMIBLOCK_LENGTH];
        a[..4].copy_from_slice(alternative_initial_value);
        a[4..].copy_from_slice(&(input.len() as u32).to_be_bytes());
        let mut r = input.to_vec();
        r.resize(semiblocks * AES_KEY_WRAP_SEMIBLOCK_LENGTH, 0);
        if semiblocks == 1 {
            let mut block = a.to_vec();
            block.extend_from_slice(&r);
            return crypt_block(&block, true);
        }
        let (a, r) = aes_key_wrap_rounds(a, r, true, &mut crypt_block)?;
        let mut output = a.to_vec();
        output.extend_from_slice(&r);
        return Ok(output);
    }

    if input.len() < AES_BLOCK_LENGTH
        || !crate::is_multiple_of(input.len(), AES_KEY_WRAP_SEMIBLOCK_LENGTH)
    {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
    }
    let semiblocks = input.len() / AES_KEY_WRAP_SEMIBLOCK_LENGTH - 1;
    let mut a: [u8; AES_KEY_WRAP_SEMIBLOCK_LENGTH] = input[..AES_KEY_WRAP_SEMIBLOCK_LENGTH]
        .try_into()
        .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_INVALID))?;
    let mut r = input[AES_KEY_WRAP_SEMIBLOCK_LENGTH..].to_vec();
    if semiblocks == 1 {
        let transformed: [u8; AES_BLOCK_LENGTH] = crypt_block(input, false)?
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        a.copy_from_slice(&transformed[..AES_KEY_WRAP_SEMIBLOCK_LENGTH]);
        r.copy_from_slice(&transformed[AES_KEY_WRAP_SEMIBLOCK_LENGTH..]);
    } else {
        (a, r) = aes_key_wrap_rounds(a, r, false, &mut crypt_block)?;
    }

    let message_length = u32::from_be_bytes(
        a[4..]
            .try_into()
            .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_INVALID))?,
    ) as usize;
    let minimum_length = (semiblocks - 1) * AES_KEY_WRAP_SEMIBLOCK_LENGTH;
    let maximum_length = semiblocks * AES_KEY_WRAP_SEMIBLOCK_LENGTH;
    let mut invalid = !a[..4].ct_eq(alternative_initial_value);
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

fn remove_pkcs7_padding(mut plaintext: Vec<u8>, block_length: usize) -> Result<Vec<u8>, Error> {
    let padding = plaintext.last().copied().unwrap_or_default();
    let mut invalid = padding.ct_eq(&0) | padding.ct_gt(&(block_length as u8));
    for (index, byte) in plaintext.iter().rev().take(block_length).enumerate() {
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
    ctx: &mut SlotContext,
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
        remove_pkcs7_padding(output, AES_BLOCK_LENGTH)
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
            ctx.get_session_context_mut(session_handle)?
                .clear_crypt_operations();
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = unsafe { as_mut(output_len) }?;
    with_session_context_mut(session_handle, |ctx| {
        let operation = ctx
            .get_session_context(session_handle)?
            .crypt_operation(encrypting)
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.multipart && !finalizing {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.get_session_context_mut(session_handle)?
                .clear_crypt_operations();
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let input = match unsafe { from_raw_parts(input, input_len as usize) } {
            Ok(input) => input,
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?
                    .clear_crypt_operations();
                return Err(error);
            }
        };
        let mut buffered_input = operation.buffer.clone();
        buffered_input.extend_from_slice(input);
        let input = buffered_input.as_slice();
        let required = if operation.mechanism == CKM_YUBICO_AES_CCM_WRAP {
            if encrypting {
                if input.is_empty() {
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(true);
                    return Err(CKR_DATA_LEN_RANGE.into());
                }
                input
                    .len()
                    .checked_add(YUBIHSM_CCM_WRAP_OVERHEAD)
                    .ok_or(CKR_DATA_LEN_RANGE)?
            } else {
                if input.len() <= YUBIHSM_CCM_WRAP_OVERHEAD {
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(false);
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len() - YUBIHSM_CCM_WRAP_OVERHEAD
            }
        } else if operation.mechanism == CKM_AES_CCM as CK_MECHANISM_TYPE {
            let Some(parameters) = operation.ccm.as_ref() else {
                ctx.get_session_context_mut(session_handle)?
                    .clear_crypt_operations();
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let expected_input = if encrypting {
                parameters.data_len
            } else {
                parameters
                    .data_len
                    .checked_add(parameters.mac_len)
                    .ok_or(CKR_ENCRYPTED_DATA_LEN_RANGE)?
            };
            if input.len() != expected_input {
                ctx.get_session_context_mut(session_handle)?
                    .clear_crypt_operations();
                return Err(if encrypting {
                    CKR_DATA_LEN_RANGE.into()
                } else {
                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                });
            }
            if encrypting {
                expected_input
                    .checked_add(parameters.mac_len)
                    .ok_or(CKR_DATA_LEN_RANGE)?
            } else {
                parameters.data_len
            }
        } else if operation.mechanism == CKM_AES_GCM as CK_MECHANISM_TYPE {
            let Some(parameters) = operation.gcm.as_ref() else {
                ctx.get_session_context_mut(session_handle)?
                    .clear_crypt_operations();
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let tag_length = parameters.tag_bits.div_ceil(8);
            let required = if encrypting {
                input.len().checked_add(tag_length)
            } else {
                input.len().checked_sub(tag_length)
            };
            let Some(required) = required else {
                ctx.get_session_context_mut(session_handle)?
                    .clear_crypt_operations();
                return Err(if encrypting {
                    CKR_DATA_LEN_RANGE.into()
                } else {
                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                });
            };
            required
        } else if matches!(
            operation.mechanism,
            x if x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE
                || x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE
        ) {
            let block_length = if operation.mechanism == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE {
                TDES_BLOCK_LENGTH
            } else {
                AES_BLOCK_LENGTH
            };
            if encrypting {
                let Some(required) = input
                    .len()
                    .checked_add(block_length - input.len() % block_length)
                else {
                    ctx.get_session_context_mut(session_handle)?
                        .clear_crypt_operations();
                    return Err(CKR_DATA_LEN_RANGE.into());
                };
                required
            } else {
                if input.is_empty() || !crate::is_multiple_of(input.len(), block_length) {
                    ctx.get_session_context_mut(session_handle)?
                        .clear_crypt_operations();
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len()
            }
        } else if operation.mechanism == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE {
            if encrypting {
                if input.len() < AES_BLOCK_LENGTH
                    || !crate::is_multiple_of(input.len(), AES_KEY_WRAP_SEMIBLOCK_LENGTH)
                {
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(true);
                    return Err(CKR_DATA_LEN_RANGE.into());
                }
                input
                    .len()
                    .checked_add(AES_KEY_WRAP_SEMIBLOCK_LENGTH)
                    .ok_or(CKR_DATA_LEN_RANGE)?
            } else {
                if input.len() < AES_BLOCK_LENGTH + AES_KEY_WRAP_SEMIBLOCK_LENGTH
                    || !crate::is_multiple_of(input.len(), AES_KEY_WRAP_SEMIBLOCK_LENGTH)
                {
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(false);
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len() - AES_KEY_WRAP_SEMIBLOCK_LENGTH
            }
        } else if operation.mechanism == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE {
            if encrypting {
                if input.is_empty() || input.len() > u32::MAX as usize {
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(true);
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
                    ctx.get_session_context_mut(session_handle)?
                        .take_crypt_operation(false);
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                }
                input.len() - 8
            }
        } else {
            match &operation.key {
                KeyMaterial::Public(PublicKeyMaterial::Rsa(key)) => key.size(),
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key))
                    if !encrypting =>
                {
                    key.size()
                }
                KeyMaterial::PivPrivate { .. } | KeyMaterial::OpenPgpPrivate { .. }
                    if !encrypting =>
                {
                    match &operation.public_key {
                        Some(PublicKeyMaterial::Rsa(key)) => key.size(),
                        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                    }
                }
                KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                    match yubihsm_rsa_length(*algorithm) {
                        Ok(length) => length,
                        Err(error) => {
                            ctx.get_session_context_mut(session_handle)?
                                .clear_crypt_operations();
                            return Err(error);
                        }
                    }
                }
                KeyMaterial::YubiHsm { .. } | KeyMaterial::SoftwareSecret(_) => input.len(),
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
                    KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key))
                        if !encrypting =>
                    {
                        if input.len() != key.size() {
                            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
                        }
                        let raw = rsa_private_operation(key, input)?;
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
                            x if x == CKM_YUBICO_AES_CCM_WRAP => YubiHsmCommand::key_data(
                                if encrypting {
                                    YubiHsmCommandCode::WrapData
                                } else {
                                    YubiHsmCommandCode::UnwrapData
                                },
                                *id,
                                input,
                            )?,
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
                            x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE => {
                                return aes_key_wrap_transform(
                                    input,
                                    encrypting,
                                    operation
                                        .key_wrap_iv
                                        .as_deref()
                                        .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
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
                            x if x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE => {
                                return aes_kwp_transform(
                                    input,
                                    encrypting,
                                    operation
                                        .key_wrap_iv
                                        .as_deref()
                                        .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
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
                            x if x == CKM_AES_CCM as CK_MECHANISM_TYPE => {
                                return aes_ccm(
                                    operation.ccm.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                    input,
                                    encrypting,
                                    |operation, blocks| match operation {
                                        CcmOperation::EncryptBlocks => yubihsm_encrypt_ecb_blocks(
                                            ctx,
                                            session_handle,
                                            *id,
                                            blocks,
                                        ),
                                        CcmOperation::CbcMac => {
                                            yubihsm_cbc_mac(ctx, session_handle, *id, blocks)
                                                .map(|mac| mac.to_vec())
                                        }
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
                        let response = ctx
                            ._get_session(session_handle)?
                            .1
                            .yubihsm_command(&command)?;
                        if operation.mechanism == CKM_YUBICO_AES_CCM_WRAP
                            && response.len() != required
                        {
                            return Err(CKR_DEVICE_ERROR.into());
                        }
                        Ok(response)
                    }
                    KeyMaterial::SoftwareSecret(key) => match operation.mechanism {
                        x if x == CKM_DES3_ECB as CK_MECHANISM_TYPE => {
                            if !crate::is_multiple_of(input.len(), TDES_BLOCK_LENGTH) {
                                return Err(if encrypting {
                                    CKR_DATA_LEN_RANGE.into()
                                } else {
                                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                                });
                            }
                            software_tdes_ecb_blocks(key, input, encrypting)
                        }
                        x if x == CKM_DES3_CBC as CK_MECHANISM_TYPE => software_tdes_cbc(
                            key,
                            operation
                                .des3_iv
                                .as_ref()
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                        ),
                        x if x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE => software_tdes_cbc_pad(
                            key,
                            operation
                                .des3_iv
                                .as_ref()
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                        ),
                        x if x == CKM_AES_ECB as CK_MECHANISM_TYPE => {
                            if !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
                                return Err(if encrypting {
                                    CKR_DATA_LEN_RANGE.into()
                                } else {
                                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                                });
                            }
                            software_crypt_ecb_blocks(key, input, encrypting)
                        }
                        x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => software_aes_cbc(
                            key,
                            operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                        ),
                        x if x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE => software_aes_cbc_pad(
                            key,
                            operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                        ),
                        x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE => aes_key_wrap_transform(
                            input,
                            encrypting,
                            operation
                                .key_wrap_iv
                                .as_deref()
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            |block, encrypting| software_crypt_ecb_blocks(key, block, encrypting),
                        ),
                        x if x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE => aes_kwp_transform(
                            input,
                            encrypting,
                            operation
                                .key_wrap_iv
                                .as_deref()
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            |block, encrypting| software_crypt_ecb_blocks(key, block, encrypting),
                        ),
                        x if x == CKM_AES_CTR as CK_MECHANISM_TYPE => aes_ctr(
                            operation.ctr.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            |blocks| software_crypt_ecb_blocks(key, blocks, true),
                        ),
                        x if x == CKM_AES_CCM as CK_MECHANISM_TYPE => aes_ccm(
                            operation.ccm.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                            |operation, blocks| match operation {
                                CcmOperation::EncryptBlocks => {
                                    software_crypt_ecb_blocks(key, blocks, true)
                                }
                                CcmOperation::CbcMac => software_cbc_mac(key, blocks),
                            },
                        ),
                        x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => aes_gcm(
                            operation.gcm.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                            encrypting,
                            |blocks| software_crypt_ecb_blocks(key, blocks, true),
                        ),
                        _ => Err(CKR_MECHANISM_INVALID.into()),
                    },
                    _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                }
            })();
            match result {
                Ok(result) => result,
                Err(error) => {
                    ctx.get_session_context_mut(session_handle)?
                        .clear_crypt_operations();
                    return Err(error);
                }
            }
        };
        if *output_len < result.len() as CK_ULONG {
            *output_len = result.len() as CK_ULONG;
            if let Some(operation) = ctx
                .get_session_context_mut(session_handle)?
                .crypt_operation_mut(encrypting)
            {
                operation.result = Some(Zeroizing::new(result));
            }
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        unsafe { ptr::copy_nonoverlapping(result.as_ptr(), output, result.len()) };
        *output_len = result.len() as CK_ULONG;
        ctx.get_session_context_mut(session_handle)?
            .clear_crypt_operations();
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

ffi_entry_point! {
    pub fn C_DecryptUpdate(
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
}

ffi_entry_point! {
    pub fn C_DecryptFinal(
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
            ctx.get_session_context_mut(session_handle)?
                .take_crypt_operation(encrypting);
            Err(CKR_ARGUMENTS_BAD.into())
        });
    }
    let output_len = unsafe { as_mut(output_len) }?;
    with_session_context_mut(session_handle, |ctx| {
        let operation = ctx
            .get_session_context(session_handle)?
            .crypt_operation(encrypting)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            let slot_id = operation.slot_id;
            ctx.reconcile_login_state(slot_id);
            ctx.get_session_context_mut(session_handle)?
                .take_crypt_operation(encrypting);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if operation.result.is_some() {
            ctx.get_session_context_mut(session_handle)?
                .take_crypt_operation(encrypting);
            return Err(CKR_OPERATION_NOT_INITIALIZED.into());
        }
        let input = match unsafe { from_raw_parts(input, input_len as usize) } {
            Ok(input) => input,
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?
                    .take_crypt_operation(encrypting);
                return Err(error);
            }
        };
        *output_len = 0;
        if output.is_null() {
            return Ok(());
        }
        let operation = ctx
            .get_session_context_mut(session_handle)?
            .crypt_operation_mut(encrypting)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.buffer.try_reserve(input.len()).is_err() {
            ctx.get_session_context_mut(session_handle)?
                .take_crypt_operation(encrypting);
            return Err(CKR_HOST_MEMORY.into());
        }
        operation.buffer.extend_from_slice(input);
        operation.multipart = true;
        Ok(())
    })
}
