use crate::*;

#[derive(Clone, Debug)]
pub(crate) struct DigestOperation {
    algorithm: MessageDigest,
    buffer: Vec<u8>,
}

fn software_digest(mechanism: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
    if !SOFTWARE_DIGEST_MECHANISMS
        .iter()
        .any(|details| details.type_ == mechanism)
    {
        return Err(Error::from(CKR_MECHANISM_INVALID as CK_RV));
    }
    digest_for_hash_mechanism(mechanism)
}

fn digest_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, _logged_in) = ctx.session_details(session_handle)?;
        if ctx
            .get_session_context(session_handle)?
            .digest_operation
            .is_some()
        {
            return Err(Error::from(CKR_OPERATION_ACTIVE as CK_RV));
        }
        let mechanism = unsafe { _as_ref(mechanism) }?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_DIGEST as CK_FLAGS)?;
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return Err(Error::from(CKR_MECHANISM_PARAM_INVALID as CK_RV));
        }
        ctx.get_session_context_mut(session_handle)?
            .digest_operation = Some(DigestOperation {
            algorithm: software_digest(mechanism.mechanism)?,
            buffer: Vec::new(),
        });
        Ok(())
    })
}

fn copy_digest(
    session: &mut SessionContext,
    operation: &DigestOperation,
    data: &[u8],
    digest: *mut u8,
    digest_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    let digest_len = unsafe { as_mut(digest_len) }?;
    let mut input = operation.buffer.clone();
    input.extend_from_slice(data);
    let value = hash(operation.algorithm, &input)?;
    let required = value.len() as CK_ULONG;
    if digest.is_null() {
        *digest_len = required;
        return Ok(());
    }
    if *digest_len < required {
        *digest_len = required;
        return Err(Error::from(CKR_BUFFER_TOO_SMALL as CK_RV));
    }
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), digest, value.len());
    }
    *digest_len = required;
    session.digest_operation = None;
    Ok(())
}

#[no_mangle]
pub extern "C" fn C_DigestInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
) -> CK_RV {
    crate::ffi_boundary(|| {
        log!(
            2,
            "C_DigestInit called with {:?}",
            (session_handle, mechanism)
        );
        map(digest_init(session_handle, mechanism))
    })
}

#[no_mangle]
pub extern "C" fn C_Digest(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    digest: *mut ::std::os::raw::c_uchar,
    digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    crate::ffi_boundary(|| {
        log!(
            2,
            "C_Digest called with {:?}",
            (session_handle, data, data_len, digest, digest_len)
        );
        map((|| {
            if digest_len.is_null() {
                let _ = with_session_context_mut(session_handle, |ctx| {
                    if let Ok(session) = ctx.get_session_context_mut(session_handle) {
                        session.digest_operation = None;
                    }
                    Ok(())
                });
                return Err(Error::from(CKR_ARGUMENTS_BAD as CK_RV));
            }
            with_session_context_mut(session_handle, |ctx| {
                let operation = ctx
                    .get_session_context(session_handle)?
                    .digest_operation
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| Error::from(CKR_OPERATION_NOT_INITIALIZED as CK_RV))?;
                let data = match unsafe { from_raw_parts(data, data_len as usize) } {
                    Ok(data) => data,
                    Err(error) => {
                        ctx.get_session_context_mut(session_handle)?
                            .digest_operation = None;
                        return Err(error);
                    }
                };
                copy_digest(
                    ctx.get_session_context_mut(session_handle)?,
                    &operation,
                    data,
                    digest,
                    digest_len,
                )
            })
        })())
    })
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    crate::ffi_boundary(|| {
        log!(
            2,
            "C_DigestUpdate called with {:?}",
            (session_handle, part, part_len)
        );
        map(with_session_context_mut(session_handle, |ctx| {
            let part = match unsafe { from_raw_parts(part, part_len as usize) } {
                Ok(part) => part,
                Err(error) => {
                    ctx.get_session_context_mut(session_handle)?
                        .digest_operation = None;
                    return Err(error);
                }
            };
            ctx.get_session_context_mut(session_handle)?
                .digest_operation
                .as_mut()
                .ok_or_else(|| Error::from(CKR_OPERATION_NOT_INITIALIZED as CK_RV))?
                .buffer
                .extend_from_slice(part);
            Ok(())
        }))
    })
}

#[no_mangle]
pub extern "C" fn C_DigestKey(session_handle: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
    crate::ffi_boundary(|| {
        log!(2, "C_DigestKey called with {:?}", (session_handle, key));
        map(with_session_context_mut(session_handle, |ctx| {
            let (_slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
            if ctx
                .get_session_context(session_handle)?
                .digest_operation
                .is_none()
            {
                return Err(Error::from(CKR_OPERATION_NOT_INITIALIZED as CK_RV));
            }
            let object = ctx
                .resolve_object(key)?
                .ok_or_else(|| Error::from(CKR_KEY_HANDLE_INVALID as CK_RV))?;
            if !object.is_visible_to(logged_in) {
                return Err(Error::from(CKR_KEY_HANDLE_INVALID as CK_RV));
            }
            if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS {
                return Err(Error::from(CKR_KEY_INDIGESTIBLE as CK_RV));
            }
            let value = match &object.material {
                KeyMaterial::Secret(value) | KeyMaterial::DerivedSecret(value) => value.to_vec(),
                _ => return Err(Error::from(CKR_KEY_INDIGESTIBLE as CK_RV)),
            };
            ctx.get_session_context_mut(session_handle)?
                .digest_operation
                .as_mut()
                .ok_or_else(|| Error::from(CKR_OPERATION_NOT_INITIALIZED as CK_RV))?
                .buffer
                .extend_from_slice(&value);
            Ok(())
        }))
    })
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    session_handle: CK_SESSION_HANDLE,
    digest: *mut ::std::os::raw::c_uchar,
    digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    crate::ffi_boundary(|| {
        log!(
            2,
            "C_DigestFinal called with {:?}",
            (session_handle, digest, digest_len)
        );
        map((|| {
            if digest_len.is_null() {
                let _ = with_session_context_mut(session_handle, |ctx| {
                    if let Ok(session) = ctx.get_session_context_mut(session_handle) {
                        session.digest_operation = None;
                    }
                    Ok(())
                });
                return Err(Error::from(CKR_ARGUMENTS_BAD as CK_RV));
            }
            with_session_context_mut(session_handle, |ctx| {
                let operation = ctx
                    .get_session_context(session_handle)?
                    .digest_operation
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| Error::from(CKR_OPERATION_NOT_INITIALIZED as CK_RV))?;
                copy_digest(
                    ctx.get_session_context_mut(session_handle)?,
                    &operation,
                    &[],
                    digest,
                    digest_len,
                )
            })
        })())
    })
}
