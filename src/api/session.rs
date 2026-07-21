#[no_mangle]
pub extern "C" fn C_InitToken(
    _slotID: CK_SLOT_ID,
    _pin: *mut ::std::os::raw::c_uchar,
    _pin_len: ::std::os::raw::c_ulong,
    _label: *mut ::std::os::raw::c_uchar,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_InitPIN(
    session_handle: CK_SESSION_HANDLE,
    pin: *mut ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(2, "C_InitPIN called with {:?}", (session_handle, pin, pin_len));
    map(init_pin(session_handle, pin, pin_len))
}

fn init_pin(
    session_handle: CK_SESSION_HANDLE,
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, flags, _) = ctx.session_details(session_handle)?;
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        ctx.reconcile_login_state(slot_id);
        if ctx.login_role(slot_id) != Some(LoginRole::So) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        with_pin(pin, pin_len, |pin| {
            ctx._get_slot_mut(slot_id)?.init_user_pin(pin)
        })
    })
}

#[no_mangle]
pub extern "C" fn C_SetPIN(
    session_handle: CK_SESSION_HANDLE,
    old_pin: *mut ::std::os::raw::c_uchar,
    old_len: ::std::os::raw::c_ulong,
    new_pin: *mut ::std::os::raw::c_uchar,
    new_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_SetPIN called with {:?}",
        (session_handle, old_pin, old_len, new_pin, new_len)
    );
    map(set_pin(
        session_handle,
        old_pin,
        old_len,
        new_pin,
        new_len,
    ))
}

fn set_pin(
    session_handle: CK_SESSION_HANDLE,
    old_pin: *const CK_UTF8CHAR,
    old_len: CK_ULONG,
    new_pin: *const CK_UTF8CHAR,
    new_len: CK_ULONG,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, flags, _) = ctx.session_details(session_handle)?;
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        with_pin(old_pin, old_len, |old_pin| {
            with_pin(new_pin, new_len, |new_pin| {
                ctx.reconcile_login_state(slot_id);
                let role = ctx.login_role(slot_id);
                let result = match role {
                    Some(LoginRole::So) => {
                        ctx._get_slot_mut(slot_id)?.set_so_pin(old_pin, new_pin)
                    }
                    _ => ctx._get_slot_mut(slot_id)?.set_pin(old_pin, new_pin),
                };
                if !matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_FUNCTION_NOT_SUPPORTED as CK_RV)
                {
                    ctx.clear_login_state(slot_id);
                }
                result
            })
        })
    })
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: *mut ::std::os::raw::c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    log!(2, "C_OpenSession called with {:?}", (slotID, flags));
    unsafe {
        let session = match session.as_mut() {
            Some(session) => session,
            None => return CKR_ARGUMENTS_BAD.into(),
        };
        match with_context_mut(|ctx| {
            if flags & CKF_SERIAL_SESSION as CK_FLAGS == 0 {
                return Ok(CKR_SESSION_PARALLEL_NOT_SUPPORTED as CK_RV);
            }
            if flags & CKF_ASYNC_SESSION as CK_FLAGS != 0 {
                return Ok(CKR_SESSION_ASYNC_NOT_SUPPORTED as CK_RV);
            }
            ctx.reconcile_login_state(slotID);
            if flags & CKF_RW_SESSION as CK_FLAGS == 0
                && ctx.login_role(slotID) == Some(LoginRole::So)
            {
                return Ok(CKR_SESSION_READ_WRITE_SO_EXISTS as CK_RV);
            }

            match ctx.slots.get_mut(&slotID) {
                Some(slot) => {
                    let _ = slot.refresh();
                    log!(2, "{:?}", slot);
                    if slot.flags() & CKF_TOKEN_PRESENT as CK_FLAGS != 0 {
                        let k = next_key(&ctx.sessions, 1);
                        log!(2, "C_OpenSession sessions before {:?}", ctx.sessions);
                        ctx.sessions.insert(k, slot.open_session(slotID, flags));
                        log!(2, "C_OpenSession sessions after {:?}", ctx.sessions);
                        log!(2, "C_OpenSession returning {:?}", k);
                        *session = k;
                        Ok(CKR_OK as CK_RV)
                    } else {
                        Ok(CKR_TOKEN_NOT_PRESENT as CK_RV)
                    }
                }
                None => Ok(CKR_SLOT_ID_INVALID as CK_RV),
            }
        }) {
            Ok(rv) => rv,
            Err(e) => e.into(),
        }
    }
}

#[no_mangle]
pub extern "C" fn C_CloseSession(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_CloseSession called with {:?}", session_handle);
    match with_context_mut(|ctx| {
        log!(2, "C_CloseSession sessions before {:?}", ctx.sessions);
        let slot_id = match ctx.sessions.get(&session_handle) {
            Some(session) => session.slotID(),
            None => return Ok(CKR_SESSION_HANDLE_INVALID as CK_RV),
        };
        let is_last_session = !ctx
            .sessions
            .iter()
            .any(|(handle, session)| *handle != session_handle && session.slotID() == slot_id);
        ctx.reconcile_login_state(slot_id);
        let logout_error = if is_last_session && ctx.is_slot_logged_in(slot_id) {
            match ctx.logout_slot(slot_id) {
                Ok(()) => None,
                Err(error) => {
                    ctx.clear_login_state(slot_id);
                    if let Some(slot) = ctx.slots.get_mut(&slot_id) {
                        slot.clear_session();
                    }
                    Some(error)
                }
            }
        } else {
            None
        };
        let session = ctx.sessions.remove(&session_handle).unwrap();
        ctx.find_operations.remove(&session_handle);
        ctx.encrypt_operations.remove(&session_handle);
        ctx.decrypt_operations.remove(&session_handle);
        ctx.sign_operations.remove(&session_handle);
        ctx.verify_operations.remove(&session_handle);
        ctx.objects
            .retain(|_, object| object.owner_session != Some(session_handle));
        log!(2, "C_CloseSession removed {:?}", (session_handle, session));
        log!(2, "C_CloseSession sessions after {:?}", ctx.sessions);
        match logout_error {
            Some(error) => Err(error),
            None => Ok(CKR_OK as CK_RV),
        }
    }) {
        Ok(rv) => rv,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    log!(2, "C_CloseAllSessions called with {:?}", slotID);
    match with_context_mut(|ctx| {
        if !ctx.slots.contains_key(&slotID) {
            return Ok(CKR_SLOT_ID_INVALID as CK_RV);
        }
        log!(2, "C_CloseAllSessions sessions before {:?}", ctx.sessions);
        let closed_sessions: HashSet<CK_SESSION_HANDLE> = ctx
            .sessions
            .iter()
            .filter(|(_k, v)| v.slotID() == slotID)
            .map(|(k, _v)| *k)
            .collect();
        ctx.reconcile_login_state(slotID);
        let logout_error = if ctx.is_slot_logged_in(slotID) {
            match ctx.logout_slot(slotID) {
                Ok(()) => None,
                Err(error) => {
                    ctx.clear_login_state(slotID);
                    if let Some(slot) = ctx.slots.get_mut(&slotID) {
                        slot.clear_session();
                    }
                    Some(error)
                }
            }
        } else {
            None
        };
        ctx.sessions.retain(|_k, v| v.slotID() != slotID);
        ctx.find_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.encrypt_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.decrypt_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.sign_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.verify_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.objects.retain(|_, object| {
            object
                .owner_session
                .map(|owner| !closed_sessions.contains(&owner))
                .unwrap_or(true)
        });
        log!(2, "C_CloseAllSessions sessions after {:?}", ctx.sessions);
        match logout_error {
            Some(error) => Err(error),
            None => Ok(CKR_OK as CK_RV),
        }
    }) {
        Ok(rv) => rv,
        Err(e) => e.into(),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetSessionInfo(
    session_handle: CK_SESSION_HANDLE,
    info_ptr: *mut CK_SESSION_INFO,
) -> CK_RV {
    log!(2, "C_GetSessionInfo called with {:?}", session_handle);
    map(get_session_info(session_handle, info_ptr))
}

fn get_session_info(
    session_handle: CK_SESSION_HANDLE,
    info_ptr: *mut CK_SESSION_INFO,
) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        let (slot_id, flags) = {
            let session = ctx._get_session(session_handle)?.1;
            (session.slotID(), session.flags())
        };
        if ctx.is_slot_logged_in(slot_id) {
            if let Err(error) = ctx._get_session(session_handle)?.1.get_session_info() {
                ctx.reconcile_login_state(slot_id);
                return Err(error);
            }
        }
        ctx.reconcile_login_state(slot_id);
        info.slotID = slot_id;
        info.state = session_state(flags, ctx.login_role(slot_id));
        info.flags = flags;
        info.ulDeviceError = 0;
        log!(2, "C_GetSessionInfo returning {:?}", info);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetOperationState(
    session_handle: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SetOperationState(
    session_handle: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: ::std::os::raw::c_ulong,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentiation_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

fn login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *const ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            return with_pin(pin, pin_len, |pin| {
                let mut context_operation = None;
                if let Some(operation) = ctx.sign_operations.get(&session_handle) {
                    context_operation =
                        Some((operation.slot_id, operation.context_specific_extended));
                }
                if let Some(operation) = ctx.decrypt_operations.get(&session_handle) {
                    if context_operation.is_some() {
                        return Err(CKR_OPERATION_ACTIVE.into());
                    }
                    context_operation =
                        Some((operation.slot_id, operation.context_specific_extended));
                }
                let (slot_id, extended) = context_operation.ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
                ctx.reconcile_login_state(slot_id);
                if !ctx.is_slot_user_logged_in(slot_id) {
                    return Err(CKR_USER_NOT_LOGGED_IN.into());
                }
                ctx._get_slot_mut(slot_id)?
                    .login_context_specific(pin, extended)
            });
        }
        let role = match user_type {
            value if value == CKU_USER as CK_USER_TYPE => LoginRole::User,
            value if value == CKU_SO as CK_USER_TYPE => LoginRole::So,
            _ => return Err(CKR_USER_TYPE_INVALID.into()),
        };
        ctx.reconcile_login_state(slot_id);
        if let Some(active_role) = ctx.login_role(slot_id) {
            return Err(if active_role == role {
                CKR_USER_ALREADY_LOGGED_IN.into()
            } else {
                CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into()
            });
        }
        if role == LoginRole::So {
            let flags = ctx._get_session(session_handle)?.1.flags();
            if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
                return Err(CKR_SESSION_READ_ONLY.into());
            }
            if ctx.sessions.values().any(|session| {
                session.slotID() == slot_id
                    && session.flags() & CKF_RW_SESSION as CK_FLAGS == 0
            }) {
                return Err(CKR_SESSION_READ_ONLY_EXISTS.into());
            }
        }
        with_pin(pin, pin_len, |pin| match role {
            LoginRole::User => ctx._get_slot_mut(slot_id)?.login(pin),
            LoginRole::So => ctx._get_slot_mut(slot_id)?.login_so(pin),
        })?;
        ctx.logged_in_slots.insert(slot_id, role);
        if role == LoginRole::User && ctx.get_slot(slot_id)?.is_yubihsm() {
            if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
                let _ = ctx._get_slot_mut(slot_id)?.logout();
                ctx.clear_login_state(slot_id);
                return Err(error);
            }
        }
        Ok(())
    })
}

fn with_pin<R>(
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
    use_pin: impl for<'a> FnOnce(&'a [u8]) -> Result<R, Error>,
) -> Result<R, Error> {
    let pin = from_raw_parts(pin, pin_len as usize)?;
    if std::str::from_utf8(pin).is_err() {
        return Err(CKR_PIN_INVALID.into());
    }
    use_pin(pin)
}

#[no_mangle]
pub extern "C" fn C_Login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *mut ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Login called with {:?}",
        (session_handle, user_type, pin, pin_len)
    );
    map(login(session_handle, user_type, pin, pin_len))
}

fn logout(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        ctx.reconcile_login_state(slot_id);
        if !ctx.is_slot_logged_in(slot_id) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        ctx.logout_slot(slot_id)
    })
}

#[no_mangle]
pub extern "C" fn C_Logout(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_Logout called with {:?}", session_handle);
    map(logout(session_handle))
}
