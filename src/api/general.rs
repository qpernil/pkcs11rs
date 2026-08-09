use crate::*;

pub(super) fn session_function_not_supported(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let result: Result<(), Error> = with_session_context(session_handle, |ctx| {
        ctx._get_session(session_handle)?;
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    });
    map(result)
}

ffi_entry_point! {
    pub fn C_Initialize(
        init_args: CK_VOID_PTR,
    ) -> CK_RV {
        log!(2, "C_Initialize called with {:?}", init_args);
        let initialization = match validate_initialize_args(init_args) {
            Ok(initialization) => initialization,
            Err(rv) => return rv,
        };
        let configuration = match ModuleConfiguration::resolve(initialization.configuration) {
            Ok(configuration) => configuration,
            Err(error) => return error.into(),
        };
        match lock_context_write() {
            Ok(mut guard) => match guard.as_mut() {
                Some(_) => CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV,
                None => match ModuleContext::new_with_configuration_and_log(
                    configuration,
                    initialization.host_log_provider,
                ) {
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
}

fn validate_initialize_args(
    init_args: CK_VOID_PTR,
) -> Result<super::initialize::InitializeReserved, CK_RV> {
    if init_args.is_null() {
        return Ok(super::initialize::InitializeReserved {
            configuration: None,
            host_log_provider: None,
        });
    }

    let args = unsafe { _as_ref(init_args.cast::<CK_C_INITIALIZE_ARGS>()) }?;
    let initialization = unsafe { super::initialize::parse_initialize_reserved(args.pReserved) }
        .map_err(CK_RV::from)?;

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

    Ok(initialization)
}

ffi_entry_point! {
    pub fn C_Finalize(
        pReserved: *mut ::std::os::raw::c_void,
    ) -> CK_RV {
        log!(2, "C_Finalize called with {:?}", pReserved);
        if !pReserved.is_null() {
            return CKR_ARGUMENTS_BAD.into();
        }
        match lock_context_write() {
            Ok(mut guard) => match guard.as_mut() {
                Some(ctx) => {
                    let mut logout_failed = false;
                    match ctx.slot_contexts.read() {
                        Ok(slot_contexts) => {
                            for child in slot_contexts.values() {
                                let Ok(mut child) = child.lock() else {
                                    logout_failed = true;
                                    continue;
                                };
                                if child.login_role.is_some() {
                                    let slot_id = child.slot_id;
                                    if child.logout_slot(slot_id).is_err() {
                                        child.clear_login_state(slot_id);
                                        logout_failed = true;
                                    }
                                }
                            }
                        }
                        Err(_) => {
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
}

// The public generated declarations and function-list entries are unsafe. The
// handwritten implementations stay in this private module and validate each
// caller-owned pointer before dereferencing it.
ffi_entry_point! {
    pub fn C_GetFunctionList(
        function_list: *mut *mut CK_FUNCTION_LIST,
    ) -> CK_RV {
        unsafe {
            log!(2, "C_GetFunctionList called with {:?}", function_list);
            match as_mut(function_list) {
                Ok(function_list) => {
                    *function_list = &super::interfaces::G_FUNCTION_LIST as *const CK_FUNCTION_LIST
                        as CK_FUNCTION_LIST_PTR;
                    log!(2, "C_GetFunctionList returning {:?}", *function_list);
                    CKR_OK as CK_RV
                }
                Err(error) => error.into(),
            }
        }
    }
}

fn get_info(info_ptr: CK_INFO_PTR) -> Result<(), Error> {
    with_context(|ctx| ctx.get_info(unsafe { as_mut(info_ptr) }?))
}

ffi_entry_point! {
    pub fn C_GetInfo(
        info_ptr: *mut CK_INFO,
    ) -> CK_RV {
        log!(2, "C_GetInfo called with {:?}", info_ptr);
        map(get_info(info_ptr))
    }
}

ffi_entry_point! {
    pub fn C_GetSlotList(
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
            let count = match as_mut(count) {
                Ok(count) => count,
                Err(error) => return error.into(),
            };
            match with_context(|ctx| {
                let initialized = ctx.init()?;
                ctx.refresh_discovery_after_init(initialized)?;
                let slot_contexts = ctx
                    .slot_contexts
                    .read()
                    .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
                let mut keys: Vec<CK_SLOT_ID> = if token_present == 0 {
                    slot_contexts.keys().copied().collect()
                } else {
                    let mut keys = Vec::new();
                    for (slot_id, child) in slot_contexts.iter() {
                        let child = child.lock().map_err(|_| CKR_MUTEX_BAD)?;
                        if child.slot.flags() & (CKF_TOKEN_PRESENT as CK_FLAGS) != 0 {
                            keys.push(*slot_id);
                        }
                    }
                    keys
                };
                if slot_list.is_null() {
                    *count = keys.len() as CK_ULONG;
                    log!(2, "C_GetSlotList returning {:?}", *count);
                    return Ok(CKR_OK as CK_RV);
                }

                if *count < keys.len() as CK_ULONG {
                    *count = keys.len() as CK_ULONG;
                    log!(2, "C_GetSlotList returning {:?}", *count);
                    return Ok(CKR_BUFFER_TOO_SMALL as CK_RV);
                }

                keys.sort();
                let output = _from_raw_parts_mut(slot_list, keys.len())?;
                output.copy_from_slice(&keys);
                *count = keys.len() as CK_ULONG;
                log!(2, "C_GetSlotList returning {:?}", (keys, *count));
                Ok(CKR_OK as CK_RV)
            }) {
                Ok(rv) => rv,
                Err(e) => e.into(),
            }
        }
    }
}

fn get_slot_info(slotID: CK_SLOT_ID, info_ptr: CK_SLOT_INFO_PTR) -> Result<(), Error> {
    let info = unsafe { as_mut(info_ptr) }?;
    with_slot_context(slotID, |ctx| ctx.get_slot(slotID)?.get_slot_info(info))
}

ffi_entry_point! {
    pub fn C_GetSlotInfo(
        slotID: CK_SLOT_ID,
        info_ptr: *mut CK_SLOT_INFO,
    ) -> CK_RV {
        log!(2, "C_GetSlotInfo called with {:?}", (slotID, info_ptr));
        map(get_slot_info(slotID, info_ptr))
    }
}

fn get_token_info(slotID: CK_SLOT_ID, info_ptr: CK_TOKEN_INFO_PTR) -> Result<(), Error> {
    let info = unsafe { as_mut(info_ptr) }?;
    with_slot_context_mut(slotID, |ctx| {
        let slot = ctx.get_present_slot(slotID)?;
        slot.get_token_info(info)?;
        if ctx.pinentry.is_configured() && slot.supports_protected_authentication_path() {
            info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH as CK_FLAGS;
        }
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulSessionCount = ctx
            .sessions
            .values()
            .filter(|session| session.backend().slotID() == slotID)
            .count() as CK_ULONG;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulRwSessionCount = ctx
            .sessions
            .values()
            .filter(|session| {
                session.backend().slotID() == slotID
                    && session.backend().flags() & CKF_RW_SESSION as CK_FLAGS != 0
            })
            .count() as CK_ULONG;
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_GetTokenInfo(
        slotID: CK_SLOT_ID,
        info_ptr: *mut CK_TOKEN_INFO,
    ) -> CK_RV {
        log!(2, "C_GetTokenInfo called with {:?}", (slotID, info_ptr));
        map(get_token_info(slotID, info_ptr))
    }
}

non_session_unsupported_stub!(C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: *mut CK_SLOT_ID,
    _pReserved: *mut ::std::os::raw::c_void,
));
