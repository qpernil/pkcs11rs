use super::{
    encrypt::{aes_gcm, parse_gcm_parameters, yubihsm_encrypt_ecb_blocks},
    shared::{
        encode_pkcs1_v1_5_signature_input, yubihsm_ec_coordinate_length, yubihsm_ecdsa_signature,
    },
};
use crate::api::general::session_function_not_supported;
use crate::*;

const AES_CMAC_LENGTH: usize = 16;

pub(crate) fn aes_cmac_length(mechanism: &CK_MECHANISM) -> Result<Option<usize>, Error> {
    match mechanism.mechanism {
        x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Ok(Some(AES_CMAC_LENGTH))
        }
        x if x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE => {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_ULONG>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let length = *_as_ref(mechanism.pParameter.cast::<CK_ULONG>())
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?
                as usize;
            if length > AES_CMAC_LENGTH {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Ok(Some(length))
        }
        _ => Ok(None),
    }
}

pub(crate) fn aes_gmac_parameters(
    mechanism: &CK_MECHANISM,
) -> Result<Option<GcmParameters>, Error> {
    if mechanism.mechanism != CKM_AES_GMAC as CK_MECHANISM_TYPE {
        return Ok(None);
    }
    let mut parameters = parse_gcm_parameters(mechanism)?;
    parameters.aad.clear();
    Ok(Some(parameters))
}

fn aes_cmac_double(mut block: [u8; AES_CMAC_LENGTH]) -> [u8; AES_CMAC_LENGTH] {
    let carry = block[0] >> 7;
    for index in 0..AES_CMAC_LENGTH - 1 {
        block[index] = (block[index] << 1) | (block[index + 1] >> 7);
    }
    block[AES_CMAC_LENGTH - 1] <<= 1;
    block[AES_CMAC_LENGTH - 1] ^= 0x87 & 0u8.wrapping_sub(carry);
    block
}

fn aes_cmac_with_encryptor(
    data: &[u8],
    mut encrypt: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let encrypted_zero = encrypt(&[0; AES_CMAC_LENGTH])?;
    let subkey = encrypted_zero
        .as_slice()
        .try_into()
        .map(aes_cmac_double)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let complete = !data.is_empty() && crate::is_multiple_of(data.len(), AES_CMAC_LENGTH);
    let last_subkey = if complete {
        subkey
    } else {
        aes_cmac_double(subkey)
    };
    let block_count = std::cmp::max(1, data.len().div_ceil(AES_CMAC_LENGTH));
    let mut state = [0; AES_CMAC_LENGTH];

    for block_index in 0..block_count {
        let start = block_index * AES_CMAC_LENGTH;
        let available = data.len().saturating_sub(start).min(AES_CMAC_LENGTH);
        let mut block = [0; AES_CMAC_LENGTH];
        block[..available].copy_from_slice(&data[start..start + available]);
        if block_index + 1 == block_count {
            if !complete {
                block[available] = 0x80;
            }
            for (value, subkey) in block.iter_mut().zip(last_subkey) {
                *value ^= subkey;
            }
        }
        for (value, previous) in block.iter_mut().zip(state) {
            *value ^= previous;
        }
        let encrypted = encrypt(&block)?;
        state = encrypted
            .as_slice()
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    Ok(state.to_vec())
}

pub(crate) fn yubihsm_aes_cmac(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    aes_cmac_with_encryptor(data, |block| {
        yubihsm_encrypt_ecb_blocks(ctx, session_handle, key_id, block)
    })
}

pub(crate) fn yubihsm_aes_gmac(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    parameters: &GcmParameters,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut parameters = parameters.clone();
    parameters.aad = data.to_vec();
    aes_gcm(&parameters, &[], true, |blocks| {
        yubihsm_encrypt_ecb_blocks(ctx, session_handle, key_id, blocks)
    })
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
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx
            .get_session_context(session_handle)?
            .sign_operation
            .is_some()
        {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = _as_ref(mechanism)?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_SIGN as CK_FLAGS)?;
        let gmac = aes_gmac_parameters(mechanism)?;
        let mac_length = match &gmac {
            Some(parameters) => Some(parameters.tag_bits.div_ceil(8)),
            None => aes_cmac_length(mechanism)?,
        };
        let pss = if mac_length.is_some() {
            None
        } else if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
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
                    || x == CKM_AES_CMAC as CK_MECHANISM_TYPE
                    || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
                    || x == CKM_AES_GMAC as CK_MECHANISM_TYPE
                    || x == CKM_PKCS11RS_PREVIEW_SIGN
            ) {
                return Err(CKR_MECHANISM_INVALID.into());
            }
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };

        let object = ctx.resolve_object(key)?.ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !object.is_visible_to(logged_in) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        if !object.sign {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let expected_key_type = match mechanism.mechanism {
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE || piv_is_hashed_ecdsa(x) => {
                CKK_EC as CK_KEY_TYPE
            }
            x if x == CKM_PKCS11RS_PREVIEW_SIGN => CKK_EC as CK_KEY_TYPE,
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => CKK_EC_EDWARDS as CK_KEY_TYPE,
            x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => CKK_SHA_1_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => CKK_SHA256_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => CKK_SHA384_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => CKK_SHA512_HMAC as CK_KEY_TYPE,
            x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE
                || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
                || x == CKM_AES_GMAC as CK_MECHANISM_TYPE =>
            {
                CKK_AES as CK_KEY_TYPE
            }
            _ => CKK_RSA as CK_KEY_TYPE,
        };
        let secret_yubihsm = (is_hmac_key_type(expected_key_type)
            || expected_key_type == CKK_AES as CK_KEY_TYPE)
            && matches!(object.material, KeyMaterial::YubiHsm { .. });
        if ((!secret_yubihsm && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            || (secret_yubihsm && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS))
            || object.key_type != expected_key_type
            || !matches!(
                object.material,
                KeyMaterial::RsaPrivate(_)
                    | KeyMaterial::PivPrivate { .. }
                    | KeyMaterial::OpenPgpPrivate { .. }
                    | KeyMaterial::YubiHsm { .. }
                    | KeyMaterial::PreviewSignDerived { .. }
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
        let preview_sign_mechanism_supported = matches!(
            object.material,
            KeyMaterial::PreviewSignDerived { .. }
                if mechanism.mechanism == CKM_PKCS11RS_PREVIEW_SIGN
        );
        if !matches!(object.material, KeyMaterial::YubiHsm { .. })
            && !piv_mechanism_supported
            && !openpgp_mechanism_supported
            && !preview_sign_mechanism_supported
            && !matches!(
                &object.material,
                KeyMaterial::RsaPrivate(_) if mechanism.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            )
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if matches!(object.material, KeyMaterial::YubiHsm { .. })
            && mechanism.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if matches!(object.material, KeyMaterial::YubiHsm { .. })
            && (piv_is_hashed_ecdsa(mechanism.mechanism)
                || (piv_is_pss_mechanism(mechanism.mechanism)
                    && mechanism.mechanism != CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE))
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        ctx.get_session_context_mut(session_handle)?.sign_operation = Some(SignatureOperation {
            key: object.material.clone(),
            slot_id,
            requires_login: object.private,
            context_specific_extended: false,
            mechanism: mechanism.mechanism,
            mac_length,
            gmac,
            pss,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
            buffer: Vec::new(),
        });
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
        let _ = with_session_context_mut(session_handle, |ctx| {
            if let Ok(session) = ctx.get_session_context_mut(session_handle) {
                session.sign_operation = None;
            }
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_len = as_mut(signature_len)?;
    with_session_context_mut(session_handle, |ctx| {
        let operation = ctx
            .get_session_context(session_handle)?
            .sign_operation
            .as_ref()
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let data = match from_raw_parts(data, data_len as usize) {
            Ok(data) => data,
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(error);
            }
        };
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let required = match &operation.key {
            KeyMaterial::RsaPrivate(key) => key.size(),
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
                OpenPgpAlgorithm::Ecdsa(_) => {
                    openpgp_ec_coordinate_length(*algorithm).ok_or(CKR_KEY_TYPE_INCONSISTENT)? * 2
                }
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
            KeyMaterial::YubiHsm { .. } if operation.mac_length.is_some() => {
                operation.mac_length.ok_or(CKR_KEY_TYPE_INCONSISTENT)?
            }
            KeyMaterial::YubiHsm { algorithm, .. } => match *algorithm {
                YUBIHSM_ALGO_HMAC_SHA1 => 20,
                YUBIHSM_ALGO_HMAC_SHA256 => 32,
                YUBIHSM_ALGO_HMAC_SHA384 => 48,
                YUBIHSM_ALGO_HMAC_SHA512 => 64,
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::PreviewSignDerived { .. } => 64,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if matches!(operation.key, KeyMaterial::PreviewSignDerived { .. }) && data.len() != 32 {
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            && data.len() > required.saturating_sub(11)
        {
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            let Some((_mgf, _salt, hash)) = operation.pss else {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let expected = digest_for_hash_mechanism(hash)?.size();
            if data.len() != expected {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
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
                KeyMaterial::RsaPrivate(private_key) => rsa_pkcs1_sign(private_key, data),
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()?;
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
                        if data.len() > required {
                            return Err(CKR_DATA_LEN_RANGE.into());
                        }
                        let mut input = vec![0; required - data.len()];
                        input.extend_from_slice(data);
                        input
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
                        .transpose()?;
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
                        OpenPgpAlgorithm::Ecdsa(curve) => openpgp_signature(
                            &response,
                            curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?,
                        ),
                        _ => Ok(response),
                    }
                }
                KeyMaterial::YubiHsm { id, algorithm, .. } => {
                    if let Some(parameters) = &operation.gmac {
                        return yubihsm_aes_gmac(ctx, session_handle, *id, parameters, data);
                    }
                    if operation.mac_length.is_some() {
                        let mut mac = yubihsm_aes_cmac(ctx, session_handle, *id, data)?;
                        mac.truncate(required);
                        return Ok(mac);
                    }
                    let digest_info = if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                        let digest = piv_hash_mechanism(operation.mechanism)
                            .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        let digest = hash(digest, data)?;
                        Some(
                            piv_digest_info(operation.mechanism, &digest)
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                        )
                    } else {
                        None
                    };
                    let command = if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                        || piv_is_hashed_rsa_pkcs(operation.mechanism)
                    {
                        let input = digest_info.as_deref().unwrap_or(data);
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignPkcs1, *id, input)?
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
                KeyMaterial::PreviewSignDerived {
                    registration,
                    derived,
                    ..
                } => {
                    let arguments = derived
                        .additional_args_cbor()
                        .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    ctx._get_slot_mut(operation.slot_id)?.fido_preview_sign(
                        registration,
                        data,
                        arguments,
                    )
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let signature_bytes = match signature_result {
            Ok(signature) if signature.len() == required => signature,
            Ok(_) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_DEVICE_ERROR.into());
            }
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(error);
            }
        };

        unsafe {
            ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
        }
        *signature_len = required as CK_ULONG;
        ctx.get_session_context_mut(session_handle)?.sign_operation = None;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(with_session_context_mut(session_handle, |ctx| {
        let part = from_raw_parts(part, part_len as usize)?.to_vec();
        let operation = ctx
            .get_session_context_mut(session_handle)?
            .sign_operation
            .as_mut()
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
