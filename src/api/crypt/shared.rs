use crate::*;

/// Validate a caller-owned output length before execution. Any invalid pointer
/// is a terminal argument error, regardless of whether it is null or misaligned.
pub(super) fn output_length<'a>(
    session_handle: CK_SESSION_HANDLE,
    length: CK_ULONG_PTR,
    operation: CK_FLAGS,
) -> Result<&'a mut CK_ULONG, Error> {
    match unsafe { as_mut(length) } {
        Ok(length) => Ok(length),
        Err(error) => {
            let _ = with_session_context_mut(session_handle, |ctx| {
                ctx.get_session_context_mut(session_handle)?
                    .cancel_operations(operation);
                Ok(())
            });
            Err(error)
        }
    }
}

/// An update error terminates its operation, including malformed input and
/// allocation failures. Signing and verification share the same input handling.
pub(super) fn signature_update(
    session_handle: CK_SESSION_HANDLE,
    part: *const u8,
    part_len: CK_ULONG,
    signing: bool,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let session = ctx.get_session_context_mut(session_handle)?;
        let state = if signing {
            &mut session.sign_operation
        } else {
            &mut session.verify_operation
        };
        let result = (|| {
            let operation = state.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            let part = unsafe { from_raw_parts(part, part_len as usize) }?;
            if operation.mechanism == CKM_HASH_ML_DSA as CK_MECHANISM_TYPE
                || (signing
                    && (crate::oath::is_mechanism(operation.mechanism)
                        || operation.mechanism == CKM_PKCS11RS_FIDO_ASSERTION))
            {
                return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
            }
            if let Some(hash) = &mut operation.prehash_state {
                hash.update(part);
            } else {
                operation
                    .buffer
                    .try_reserve(part.len())
                    .map_err(|_| CKR_HOST_MEMORY)?;
                operation.buffer.extend_from_slice(part);
            }
            operation.multipart = true;
            Ok(())
        })();
        if result.is_err() {
            *state = None;
        }
        result
    })
}

fn parse_mgf(mgf: CK_RSA_PKCS_MGF_TYPE) -> Result<u8, Error> {
    Ok(match mgf {
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
    })
}

/// Decode both raw and composite RSA-PSS mechanisms. Composite mechanisms fix
/// the message hash, but the caller still supplies the MGF and salt length.
pub(super) fn parse_rsa_pss_parameters(
    mechanism: &CK_MECHANISM,
) -> Result<(u8, u16, CK_MECHANISM_TYPE), Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter.cast::<CK_RSA_PKCS_PSS_PARAMS>()) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if mechanism.mechanism != CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        && parameters.hashAlg != pss_hash_mechanism(mechanism.mechanism)?
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let mgf = parse_mgf(parameters.mgf)?;
    let salt_length =
        u16::try_from(parameters.sLen).map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let parsed = (mgf, salt_length, parameters.hashAlg);
    shared_rsa_pss_parameters(parsed).map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    Ok(parsed)
}

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
    let mgf = parse_mgf(parameters.mgf)?;
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
    software_key_core::rsa_signing::pkcs1v15_encoded_payload(modulus_size, data)
        .map_err(|_| CKR_DATA_LEN_RANGE.into())
}

pub(crate) fn rsa_pkcs1_v1_5_unpad(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    software_key_core::rsa_signing::rsa_pkcs1v15_unpad(encoded)
        .map_err(|_| CKR_ENCRYPTED_DATA_INVALID.into())
}

pub(crate) fn rsa_oaep_unpad(
    encoded: &[u8],
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let parameters = shared_rsa_pss_parameters((mgf_code, 0, hash_mechanism))?;
    if label_digest.len() != parameters.hash.output_length() {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    software_key_core::rsa_signing::rsa_oaep_unpad_digest(
        encoded,
        label_digest,
        parameters.mgf_hash,
    )
    .map_err(|_| CKR_ENCRYPTED_DATA_INVALID.into())
}

pub(crate) fn rsa_oaep_pad(
    input: &[u8],
    modulus_size: usize,
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let parameters = shared_rsa_pss_parameters((mgf_code, 0, hash_mechanism))?;
    if label_digest.len() != parameters.hash.output_length() {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    software_key_core::rsa_signing::rsa_oaep_pad_digest(
        input,
        modulus_size,
        label_digest,
        parameters.mgf_hash,
    )
    .map_err(|error| match error {
        software_key_core::rsa_signing::RsaConstructionError::RandomnessUnavailable => {
            CKR_RANDOM_NO_RNG.into()
        }
        _ => CKR_DATA_LEN_RANGE.into(),
    })
}

session_unsupported_stub!(
    C_DigestEncryptUpdate(
        _part: *mut ::std::os::raw::c_uchar,
        _part_len: ::std::os::raw::c_ulong,
        _encrypted_part: *mut ::std::os::raw::c_uchar,
        _encrypted_part_len: *mut ::std::os::raw::c_ulong,
    )
);

session_unsupported_stub!(
    C_DecryptDigestUpdate(
        _encrypted_part: *mut ::std::os::raw::c_uchar,
        _encrypted_part_len: ::std::os::raw::c_ulong,
        _part: *mut ::std::os::raw::c_uchar,
        _part_len: *mut ::std::os::raw::c_ulong,
    )
);

session_unsupported_stub!(
    C_SignEncryptUpdate(
        _part: *mut ::std::os::raw::c_uchar,
        _part_len: ::std::os::raw::c_ulong,
        _encrypted_part: *mut ::std::os::raw::c_uchar,
        _encrypted_part_len: *mut ::std::os::raw::c_ulong,
    )
);

session_unsupported_stub!(
    C_DecryptVerifyUpdate(
        _encrypted_part: *mut ::std::os::raw::c_uchar,
        _encrypted_part_len: ::std::os::raw::c_ulong,
        _part: *mut ::std::os::raw::c_uchar,
        _part_len: *mut ::std::os::raw::c_ulong,
    )
);
