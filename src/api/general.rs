fn session_function_not_supported(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let result: Result<(), Error> = with_context(|ctx| {
        ctx._get_session(session_handle)?;
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    });
    map(result)
}

#[no_mangle]
pub extern "C" fn C_Initialize(init_args: CK_VOID_PTR) -> CK_RV {
    if let Err(rv) = initialize_debug_logging() {
        return rv;
    }
    log!(2, "C_Initialize called with {:?}", init_args);
    if let Err(rv) = validate_initialize_args(init_args) {
        return rv;
    }
    match lock_context() {
        Ok(mut guard) => match guard.as_mut() {
            Some(_) => CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV,
            None => match Context::new() {
                Ok(context) => {
                    *guard = Some(context);
                    CKR_OK as CK_RV
                }
                Err(error) => error.into(),
            },
        },
        Err(e) => e.into(),
    }
}

fn validate_initialize_args(init_args: CK_VOID_PTR) -> Result<(), CK_RV> {
    if init_args.is_null() {
        return Ok(());
    }

    let args = unsafe { &*(init_args as CK_C_INITIALIZE_ARGS_PTR) };
    if !args.pReserved.is_null() {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    let callbacks = [
        args.CreateMutex.is_some(),
        args.DestroyMutex.is_some(),
        args.LockMutex.is_some(),
        args.UnlockMutex.is_some(),
    ];
    let any_callbacks = callbacks.iter().any(|present| *present);
    let all_callbacks = callbacks.iter().all(|present| *present);
    if any_callbacks != all_callbacks {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    let known_flags = (CKF_LIBRARY_CANT_CREATE_OS_THREADS | CKF_OS_LOCKING_OK) as CK_FLAGS;
    if args.flags & !known_flags != 0 {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    if all_callbacks && args.flags & CKF_OS_LOCKING_OK as CK_FLAGS == 0 {
        return Err(CKR_CANT_LOCK as CK_RV);
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: *mut ::std::os::raw::c_void) -> CK_RV {
    log!(2, "C_Finalize called with {:?}", pReserved);
    if !pReserved.is_null() {
        return CKR_ARGUMENTS_BAD.into();
    }
    match lock_context() {
        Ok(mut guard) => match guard.as_mut() {
            Some(ctx) => {
                let logged_in_slots: Vec<CK_SLOT_ID> =
                    ctx.logged_in_slots.iter().copied().collect();
                let mut logout_failed = false;
                for slot_id in logged_in_slots {
                    if ctx.logout_slot(slot_id).is_err() {
                        ctx.clear_login_state(slot_id);
                        logout_failed = true;
                    }
                }
                *guard = None;
                if logout_failed {
                    CKR_FUNCTION_FAILED as CK_RV
                } else {
                    CKR_OK as CK_RV
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
        },
        Err(e) => e.into(),
    }
}

// Cryptoki declares these as callable C function pointers. They validate each
// caller-owned pointer before dereferencing it, but cannot be exposed as unsafe
// Rust functions without changing the generated PKCS #11 function-list types.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetFunctionList(function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    unsafe {
        log!(2, "C_GetFunctionList called with {:?}", function_list);
        match function_list.as_mut() {
            Some(function_list) => {
                *function_list =
                    &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
                log!(2, "C_GetFunctionList returning {:?}", *function_list);
                CKR_OK
            }
            None => CKR_ARGUMENTS_BAD,
        }
    }
    .into()
}

fn get_info(info_ptr: CK_INFO_PTR) -> Result<(), Error> {
    with_context(|ctx| ctx.get_info(as_mut(info_ptr)?))
}

#[no_mangle]
pub extern "C" fn C_GetInfo(info_ptr: *mut CK_INFO) -> CK_RV {
    log!(2, "C_GetInfo called with {:?}", info_ptr);
    map(get_info(info_ptr))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetSlotList(
    token_present: ::std::os::raw::c_uchar,
    slot_list: *mut CK_SLOT_ID,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    unsafe {
        log!(
            2,
            "C_GetSlotList called with {:?}",
            (token_present, slot_list, count)
        );
        let count = match count.as_mut() {
            Some(count) => count,
            None => return CKR_ARGUMENTS_BAD.into(),
        };
        match with_context_mut(|ctx| {
            ctx.init();
            let mut keys: Vec<CK_SLOT_ID> = if token_present == 0 {
                ctx.slots.keys().cloned().collect()
            } else {
                ctx.slots
                    .iter()
                    .filter(|s| s.1.flags() & (CKF_TOKEN_PRESENT as CK_FLAGS) != 0)
                    .map(|s| *s.0)
                    .collect()
            };
            match slot_list.as_mut() {
                Some(_) => {
                    if *count >= keys.len() as ::std::os::raw::c_ulong {
                        keys.sort();
                        ptr::copy(keys.as_ptr(), slot_list, keys.len());
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        log!(2, "C_GetSlotList returning {:?}", (keys, *count));
                        Ok(CKR_OK as CK_RV)
                    } else {
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        log!(2, "C_GetSlotList returning {:?}", *count);
                        Ok(CKR_BUFFER_TOO_SMALL as CK_RV)
                    }
                }
                None => {
                    *count = keys.len() as ::std::os::raw::c_ulong;
                    log!(2, "C_GetSlotList returning {:?}", *count);
                    Ok(CKR_OK as CK_RV)
                }
            }
        }) {
            Ok(rv) => rv,
            Err(e) => e.into(),
        }
    }
}

fn get_slot_info(slotID: CK_SLOT_ID, info_ptr: CK_SLOT_INFO_PTR) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context(|ctx| ctx.get_slot(slotID)?.get_slot_info(info))
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_SLOT_INFO) -> CK_RV {
    log!(2, "C_GetSlotInfo called with {:?}", (slotID, info_ptr));
    map(get_slot_info(slotID, info_ptr))
}

fn get_token_info(slotID: CK_SLOT_ID, info_ptr: CK_TOKEN_INFO_PTR) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        ctx.get_present_slot(slotID)?.get_token_info(info)?;
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulSessionCount = ctx
            .sessions
            .values()
            .filter(|session| session.slotID() == slotID)
            .count() as CK_ULONG;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulRwSessionCount = ctx
            .sessions
            .values()
            .filter(|session| {
                session.slotID() == slotID && session.flags() & CKF_RW_SESSION as CK_FLAGS != 0
            })
            .count() as CK_ULONG;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_TOKEN_INFO) -> CK_RV {
    log!(2, "C_GetTokenInfo called with {:?}", (slotID, info_ptr));
    map(get_token_info(slotID, info_ptr))
}

#[no_mangle]
pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: *mut CK_SLOT_ID,
    _pReserved: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}
