use super::sign::{
    aes_cmac_length, aes_gmac_parameters, hmac_key_type_and_length, hmac_output_length,
    ml_dsa_parameters, software_aes_cmac, software_aes_gmac, software_hmac, yubihsm_aes_cmac,
    yubihsm_aes_gmac,
};
use crate::backed_object::projected_public_key_material;
use crate::*;
use software_key_core::post_quantum::{MlDsaError, MlDsaParameterSet, verify_ml_dsa};
use software_key_core::rsa_signing::{
    RsaConstructionError, rsa_verify_pkcs1v15_digest, rsa_verify_pkcs1v15_payload,
    rsa_verify_pss_digest, rsa_verify_raw,
};

ffi_entry_point! {
    pub fn C_VerifyInit(
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
}

fn verify_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx
            .get_session_context(session_handle)?
            .verify_operation
            .is_some()
        {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = unsafe { _as_ref(mechanism) }?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_VERIFY as CK_FLAGS)?;
        let gmac = aes_gmac_parameters(mechanism)?;
        let aes_mac_length = match &gmac {
            Some(parameters) => Some(parameters.tag_bits.div_ceil(8)),
            None => aes_cmac_length(mechanism)?,
        };
        let hmac_length = hmac_output_length(mechanism)?;
        let mac_length = hmac_length.or(aes_mac_length);
        let ml_dsa = ml_dsa_parameters(mechanism)?;
        let pss = if mac_length.is_some() || ml_dsa.is_some() {
            None
        } else if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters =
                unsafe { _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR) }?;
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
        let ml_dsa_mechanism = mechanism.mechanism == CKM_ML_DSA as CK_MECHANISM_TYPE;
        let aes_mac_mechanism = aes_mac_length.is_some();
        let hmac_mechanism = hmac_key_type_and_length(mechanism.mechanism);
        if !rsa_mechanism
            && !ecdsa_mechanism
            && !eddsa_mechanism
            && !ml_dsa_mechanism
            && !aes_mac_mechanism
            && hmac_mechanism.is_none()
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        let object = ctx.resolve_object(key)?.ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !object.is_visible_to(logged_in) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        require_key_mechanism(&object, mechanism.mechanism)?;
        if !object.verify {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let asymmetric_key = if !aes_mac_mechanism && hmac_mechanism.is_none() {
            Some(projected_public_key_material(&object)?)
        } else {
            None
        };
        let hmac_key_is_invalid = hmac_mechanism.is_some_and(|(key_type, _)| {
            let material_is_valid = match &object.material {
                KeyMaterial::SoftwareSecret(_) => {
                    object.key_type == key_type
                        || object.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE
                }
                KeyMaterial::YubiHsm { algorithm, .. } => {
                    yubihsm_hmac_mechanism(mechanism.mechanism)
                        .is_some_and(|(_, expected_algorithm, _)| *algorithm == expected_algorithm)
                }
                _ => false,
            };
            object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || !material_is_valid
        });
        if (aes_mac_mechanism
            && (object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
                || object.key_type != CKK_AES as CK_KEY_TYPE
                || !matches!(
                    object.material,
                    KeyMaterial::YubiHsm {
                        algorithm: YUBIHSM_ALGO_AES128 | YUBIHSM_ALGO_AES192 | YUBIHSM_ALGO_AES256,
                        ..
                    } | KeyMaterial::SoftwareSecret(_)
                )))
            || hmac_key_is_invalid
            || (!aes_mac_mechanism
                && hmac_mechanism.is_none()
                && object.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
            || (rsa_mechanism
                && (object.key_type != CKK_RSA as CK_KEY_TYPE
                    || rsa_public_key_material(
                        asymmetric_key.as_ref().ok_or(CKR_KEY_TYPE_INCONSISTENT)?,
                    )?
                    .is_none()))
            || (ecdsa_mechanism
                && (object.key_type != CKK_EC as CK_KEY_TYPE
                    || !matches!(
                        asymmetric_key,
                        Some(KeyMaterial::Public(PublicKeyMaterial::Ec { .. }))
                    )))
            || (eddsa_mechanism
                && (object.key_type != CKK_EC_EDWARDS as CK_KEY_TYPE
                    || !matches!(
                        asymmetric_key,
                        Some(KeyMaterial::Public(PublicKeyMaterial::Ec { .. }))
                    )))
            || (ml_dsa_mechanism
                && (object.key_type != CKK_ML_DSA as CK_KEY_TYPE
                    || !matches!(
                        asymmetric_key,
                        Some(KeyMaterial::Public(PublicKeyMaterial::MlDsa { .. }))
                    )))
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }

        ctx.get_session_context_mut(session_handle)?
            .verify_operation = Some(SignatureOperation {
            key: asymmetric_key.unwrap_or_else(|| object.material.clone()),
            public_key: object.public_key.clone(),
            slot_id,
            requires_login: object.private
                && ctx.get_slot(slot_id)?.private_objects_require_login(),
            context_specific_extended: false,
            context_specific_rp_id: None,
            fido_authorization: None,
            mechanism: mechanism.mechanism,
            mac_length,
            gmac,
            pss,
            ml_dsa,
            piv_pin_policy: None,
            buffer: Vec::new(),
            result: None,
        });
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_Verify(
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
}

fn verify(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *const ::std::os::raw::c_uchar,
    signature_len: CK_ULONG,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let operation = ctx
            .get_session_context_mut(session_handle)?
            .verify_operation
            .take()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let data = unsafe { from_raw_parts(data, data_len as usize) }?;
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let signature = unsafe { from_raw_parts(signature, signature_len as usize) }?;
        if let Some((_, full_length)) = hmac_key_type_and_length(operation.mechanism) {
            let expected_length = operation.mac_length.unwrap_or(full_length);
            if signature.len() != expected_length {
                return Err(CKR_SIGNATURE_LEN_RANGE.into());
            }
            if let KeyMaterial::SoftwareSecret(key) = &operation.key {
                let mut expected = software_hmac(key, operation.mechanism, data)?;
                expected.truncate(expected_length);
                if bool::from(subtle::ConstantTimeEq::ct_eq(
                    expected.as_slice(),
                    signature,
                )) {
                    return Ok(());
                }
                return Err(CKR_SIGNATURE_INVALID.into());
            }
            let KeyMaterial::YubiHsm { id, algorithm, .. } = &operation.key else {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            };
            let (_, expected_algorithm, _) =
                yubihsm_hmac_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?;
            if *algorithm != expected_algorithm || expected_length != full_length {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            }
            let command = YubiHsmCommand::verify_hmac(*id, signature, data)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            return match response.as_slice() {
                [1] => Ok(()),
                [0] => Err(CKR_SIGNATURE_INVALID.into()),
                _ => Err(CKR_DEVICE_ERROR.into()),
            };
        }
        if let Some(mac_length) = operation.mac_length {
            if signature.len() != mac_length {
                return Err(CKR_SIGNATURE_LEN_RANGE.into());
            }
            let mut expected = match &operation.key {
                KeyMaterial::YubiHsm { id, .. } => match &operation.gmac {
                    Some(parameters) => {
                        yubihsm_aes_gmac(ctx, session_handle, *id, parameters, data)?
                    }
                    None => yubihsm_aes_cmac(ctx, session_handle, *id, data)?,
                },
                KeyMaterial::SoftwareSecret(key) => match &operation.gmac {
                    Some(parameters) => software_aes_gmac(key, parameters, data)?,
                    None => software_aes_cmac(key, data)?,
                },
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            };
            expected.truncate(mac_length);
            if !bool::from(subtle::ConstantTimeEq::ct_eq(
                expected.as_slice(),
                signature,
            )) {
                return Err(CKR_SIGNATURE_INVALID.into());
            }
            return Ok(());
        }
        if let Some(public_key) = rsa_public_key_material(&operation.key)? {
            return verify_rsa_signature(
                &public_key,
                operation.mechanism,
                operation.pss,
                data,
                signature,
            );
        }
        match &operation.key {
            KeyMaterial::Public(PublicKeyMaterial::MlDsa {
                parameter_set,
                public_key,
            }) if operation.mechanism == CKM_ML_DSA as CK_MECHANISM_TYPE => ml_dsa_verify(
                *parameter_set,
                public_key,
                operation
                    .ml_dsa
                    .as_ref()
                    .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                data,
                signature,
            ),
            KeyMaterial::Public(PublicKeyMaterial::Ec { public_key, .. })
                if operation.mechanism == CKM_EDDSA as CK_MECHANISM_TYPE =>
            {
                verify_ed25519(public_key, data, signature)
            }
            KeyMaterial::Public(PublicKeyMaterial::Ec {
                parameters,
                public_key,
            }) => {
                let curve = ec_curve_from_parameters(parameters)?;
                let coordinate_length = ec_parameters(curve)?.coordinate_length;
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                };
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                verify_ecdsa(curve, public_key, &digest, signature)
            }
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        }
    })
}

fn ml_dsa_verify(
    parameter_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    public_key: &[u8],
    parameters: &MlDsaSignatureParameters,
    data: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let parameter_set = match parameter_set {
        x if x == CKP_ML_DSA_44 as CK_ML_DSA_PARAMETER_SET_TYPE => MlDsaParameterSet::MlDsa44,
        x if x == CKP_ML_DSA_65 as CK_ML_DSA_PARAMETER_SET_TYPE => MlDsaParameterSet::MlDsa65,
        x if x == CKP_ML_DSA_87 as CK_ML_DSA_PARAMETER_SET_TYPE => MlDsaParameterSet::MlDsa87,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    if signature.len() != parameter_set.signature_length() {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    if public_key.len() != parameter_set.public_key_length() {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    verify_ml_dsa(
        parameter_set,
        public_key,
        data,
        &parameters.context,
        signature,
    )
    .map_err(|error| match error {
        MlDsaError::InvalidPublicKey | MlDsaError::InvalidSeedLength => {
            Error::from(CKR_KEY_TYPE_INCONSISTENT)
        }
        MlDsaError::InvalidContext => Error::from(CKR_MECHANISM_PARAM_INVALID),
        MlDsaError::InvalidSignature => Error::from(CKR_SIGNATURE_INVALID),
        MlDsaError::RandomnessUnavailable | MlDsaError::SigningFailed => {
            Error::from(CKR_FUNCTION_FAILED)
        }
    })
}

fn yubihsm_hmac_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<(CK_KEY_TYPE, u8, usize)> {
    match mechanism {
        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => {
            Some((CKK_SHA_1_HMAC as CK_KEY_TYPE, YUBIHSM_ALGO_HMAC_SHA1, 20))
        }
        x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => {
            Some((CKK_SHA256_HMAC as CK_KEY_TYPE, YUBIHSM_ALGO_HMAC_SHA256, 32))
        }
        x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => {
            Some((CKK_SHA384_HMAC as CK_KEY_TYPE, YUBIHSM_ALGO_HMAC_SHA384, 48))
        }
        x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => {
            Some((CKK_SHA512_HMAC as CK_KEY_TYPE, YUBIHSM_ALGO_HMAC_SHA512, 64))
        }
        _ => None,
    }
}

fn verify_rsa_signature(
    public_key: &RsaPublicKey,
    mechanism: CK_MECHANISM_TYPE,
    pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    data: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.len() != public_key.size() {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let result = if mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
        rsa_verify_raw(public_key, data, signature)
    } else if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
        rsa_verify_pkcs1v15_payload(public_key, data, signature)
    } else if piv_is_hashed_rsa_pkcs(mechanism) {
        let digest = hash(
            piv_hash_mechanism(mechanism).ok_or(CKR_MECHANISM_INVALID)?,
            data,
        )?;
        rsa_verify_pkcs1v15_digest(
            public_key,
            shared_rsa_hash_algorithm(mechanism)?,
            &digest,
            signature,
        )
    } else if piv_is_pss_mechanism(mechanism) {
        let parameters = shared_rsa_pss_parameters(pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?)?;
        let digest = if mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            let expected_length = parameters.hash.output_length();
            if data.len() != expected_length {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            data.to_vec()
        } else {
            hash(
                piv_hash_mechanism(mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                data,
            )?
            .to_vec()
        };
        rsa_verify_pss_digest(public_key, parameters, &digest, signature)
    } else {
        return Err(CKR_MECHANISM_INVALID.into());
    };
    result.map_err(shared_rsa_verification_error)
}

fn shared_rsa_verification_error(error: RsaConstructionError) -> Error {
    match error {
        RsaConstructionError::InputTooLong | RsaConstructionError::InvalidDigestLength => {
            CKR_DATA_LEN_RANGE.into()
        }
        RsaConstructionError::InvalidKey => CKR_KEY_TYPE_INCONSISTENT.into(),
        RsaConstructionError::InvalidSignature | RsaConstructionError::InputOutOfRange => {
            CKR_SIGNATURE_INVALID.into()
        }
        RsaConstructionError::RandomnessUnavailable | RsaConstructionError::OperationFailed => {
            CKR_FUNCTION_FAILED.into()
        }
    }
}

ffi_entry_point! {
    pub fn C_VerifyUpdate(
        session_handle: CK_SESSION_HANDLE,
        part: *mut ::std::os::raw::c_uchar,
        part_len: ::std::os::raw::c_ulong,
    ) -> CK_RV {
        map(with_session_context_mut(session_handle, |ctx| {
            let part = unsafe { from_raw_parts(part, part_len as usize) }?.to_vec();
            let operation = ctx
                .get_session_context_mut(session_handle)?
                .verify_operation
                .as_mut()
                .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            operation.buffer.extend_from_slice(&part);
            Ok(())
        }))
    }
}

ffi_entry_point! {
    pub fn C_VerifyFinal(
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
}

session_unsupported_stub!(C_VerifyRecoverInit(
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
));

session_unsupported_stub!(C_VerifyRecover(
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
));
