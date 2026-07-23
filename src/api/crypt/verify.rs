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
            .resolve_object(key)?
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
                let recovered = if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                    || piv_is_pss_mechanism(operation.mechanism)
                {
                    rsa_public_operation(public_key, signature)
                } else {
                    rsa_pkcs1_recover(public_key, signature)
                }
                .map_err(|_| Error::from(CKR_SIGNATURE_INVALID))?;
                let expected = if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                    if data.len() > public_key.size() as usize {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let mut expected = vec![0; public_key.size() as usize - data.len()];
                    expected.extend_from_slice(data);
                    expected
                } else if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
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
                        let expected_length = digest_for_hash_mechanism(hash_mechanism)?.size();
                        if data.len() != expected_length {
                            return Err(CKR_DATA_LEN_RANGE.into());
                        }
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
                verify_ecdsa(
                    piv_ec_curve(*algorithm)?,
                    public_key,
                    &digest,
                    signature,
                )
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
                verify_ecdsa(
                    openpgp_ec_curve(*curve)?,
                    public_key,
                    &digest,
                    signature,
                )
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
                verify_ecdsa(
                    yubihsm_ec_curve(*algorithm)?,
                    public_key,
                    &digest,
                    signature,
                )
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
