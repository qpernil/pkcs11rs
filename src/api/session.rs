use crate::*;

ffi_entry_point! {
    pub fn C_SessionCancel(
        session_handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> CK_RV {
        map(session_cancel(session_handle, flags))
    }
}

fn session_cancel(session_handle: CK_SESSION_HANDLE, flags: CK_FLAGS) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        ctx.get_session_context_mut(session_handle)?
            .cancel_operations(flags);
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_InitToken(
        slot_id: CK_SLOT_ID,
        pin: *mut ::std::os::raw::c_uchar,
        pin_len: ::std::os::raw::c_ulong,
        label: *mut ::std::os::raw::c_uchar,
    ) -> CK_RV {
        log!(2, "C_InitToken called with {:?}", (slot_id, pin, pin_len, label));
        map(init_token(slot_id, pin, pin_len, label))
    }
}

fn init_token(
    slot_id: CK_SLOT_ID,
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
    label: *const CK_UTF8CHAR,
) -> Result<(), Error> {
    let label = unsafe { from_raw_parts(label, 32) }?;
    std::str::from_utf8(label).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let label: [CK_UTF8CHAR; 32] = label.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
    with_pin(pin, pin_len, |pin| {
        with_slot_context_mut(slot_id, |ctx| ctx.init_token(pin, label))
    })
}

ffi_entry_point! {
    pub fn C_InitPIN(
        session_handle: CK_SESSION_HANDLE,
        pin: *mut ::std::os::raw::c_uchar,
        pin_len: ::std::os::raw::c_ulong,
    ) -> CK_RV {
        log!(
            2,
            "C_InitPIN called with {:?}",
            (session_handle, pin, pin_len)
        );
        map(init_pin(session_handle, pin, pin_len))
    }
}

fn init_pin(
    session_handle: CK_SESSION_HANDLE,
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
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

ffi_entry_point! {
    pub fn C_SetPIN(
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
        map(set_pin(session_handle, old_pin, old_len, new_pin, new_len))
    }
}

fn set_pin(
    session_handle: CK_SESSION_HANDLE,
    old_pin: *const CK_UTF8CHAR,
    old_len: CK_ULONG,
    new_pin: *const CK_UTF8CHAR,
    new_len: CK_ULONG,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, _) = ctx.session_details(session_handle)?;
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        with_pin(old_pin, old_len, |old_pin| {
            with_pin(new_pin, new_len, |new_pin| {
                ctx.reconcile_login_state(slot_id);
                let role = ctx.login_role(slot_id);
                match role {
                    Some(LoginRole::So) => ctx._get_slot_mut(slot_id)?.set_so_pin(old_pin, new_pin),
                    _ => ctx._get_slot_mut(slot_id)?.set_pin(old_pin, new_pin),
                }
            })
        })
    })
}

ffi_entry_point! {
    pub fn C_OpenSession(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        _application: *mut ::std::os::raw::c_void,
        _notify: CK_NOTIFY,
        session: *mut CK_SESSION_HANDLE,
    ) -> CK_RV {
        log!(2, "C_OpenSession called with {:?}", (slotID, flags));
        unsafe {
            let session = match as_mut(session) {
                Ok(session) => session,
                Err(error) => return error.into(),
            };
            let module = match lock_context_read() {
                Ok(guard) => guard,
                Err(error) => return error.into(),
            };
            let context = match module.as_ref() {
                Some(context) => context,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let mut opened_handle = None;
            let result = with_slot_context_mut_in_context(context, slotID, |ctx| {
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

                let _ = ctx.slot.refresh();
                log!(2, "{:?}", ctx.slot);
                if ctx.slot.flags() & CKF_TOKEN_PRESENT as CK_FLAGS != 0 {
                    let k = context.handles.allocate_session()?;
                    log!(2, "C_OpenSession sessions before {:?}", ctx.sessions);
                    ctx.sessions
                        .insert(k, SessionContext::new(ctx.slot.open_session(slotID, flags)));
                    log!(2, "C_OpenSession sessions after {:?}", ctx.sessions);
                    log!(2, "C_OpenSession returning {:?}", k);
                    opened_handle = Some(k);
                    Ok(CKR_OK as CK_RV)
                } else {
                    Ok(CKR_TOKEN_NOT_PRESENT as CK_RV)
                }
            });
            match (result, opened_handle) {
                (Ok(rv), None) => rv,
                (Ok(_), Some(handle)) => {
                    match register_session_slot_in_context(context, handle, slotID) {
                        Ok(()) => {
                            *session = handle;
                            CKR_OK as CK_RV
                        }
                        Err(error) => {
                            let _ = with_slot_context_mut_in_context(context, slotID, |ctx| {
                                ctx.sessions.remove(&handle);
                                Ok(())
                            });
                            error.into()
                        }
                    }
                }
                (Err(error), _) => error.into(),
            }
        }
    }
}

ffi_entry_point! {
    pub fn C_CloseSession(
        session_handle: CK_SESSION_HANDLE,
    ) -> CK_RV {
        log!(2, "C_CloseSession called with {:?}", session_handle);
        let module = match lock_context_read() {
            Ok(guard) => guard,
            Err(error) => return error.into(),
        };
        let context = match module.as_ref() {
            Some(context) => context,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let mut removed = false;
        let result = with_session_context_mut_in_context(context, session_handle, |ctx| {
            log!(2, "C_CloseSession sessions before {:?}", ctx.sessions);
            let slot_id = match ctx.sessions.get(&session_handle) {
                Some(session) => session.backend().slotID(),
                None => return Ok(CKR_SESSION_HANDLE_INVALID as CK_RV),
            };
            let is_last_session = !ctx.sessions.iter().any(|(handle, session)| {
                *handle != session_handle && session.backend().slotID() == slot_id
            });
            ctx.reconcile_login_state(slot_id);
            let logout_error = if is_last_session && ctx.is_slot_logged_in(slot_id) {
                match ctx.logout_slot(slot_id) {
                    Ok(()) => None,
                    Err(error) => {
                        ctx.clear_login_state(slot_id);
                        ctx.slot.clear_session();
                        Some(error)
                    }
                }
            } else {
                None
            };
            let session = ctx
                .sessions
                .remove(&session_handle)
                .ok_or(CKR_SESSION_HANDLE_INVALID)?;
            removed = true;
            let creator_objects = ctx
                .memory_objects
                .iter()
                .filter_map(|(handle, object)| {
                    (object.creator_session == Some(session_handle)).then_some(*handle)
                })
                .collect::<Vec<_>>();
            for handle in creator_objects {
                ctx.remove_object_handle(handle);
            }
            log!(2, "C_CloseSession removed {:?}", (session_handle, session));
            log!(2, "C_CloseSession sessions after {:?}", ctx.sessions);
            match logout_error {
                Some(error) => Err(error),
                None => Ok(CKR_OK as CK_RV),
            }
        });
        if removed {
            if let Err(error) = unregister_session_slot_in_context(context, session_handle) {
                return error.into();
            }
        }
        match result {
            Ok(rv) => rv,
            Err(error) => error.into(),
        }
    }
}

ffi_entry_point! {
    pub fn C_CloseAllSessions(
        slotID: CK_SLOT_ID,
    ) -> CK_RV {
        log!(2, "C_CloseAllSessions called with {:?}", slotID);
        let module = match lock_context_read() {
            Ok(guard) => guard,
            Err(error) => return error.into(),
        };
        let context = match module.as_ref() {
            Some(context) => context,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let mut closed_sessions = HashSet::new();
        let result = with_slot_context_mut_in_context(context, slotID, |ctx| {
            log!(2, "C_CloseAllSessions sessions before {:?}", ctx.sessions);
            closed_sessions.extend(
                ctx.sessions
                    .iter()
                    .filter(|(_k, v)| v.backend().slotID() == slotID)
                    .map(|(k, _v)| *k),
            );
            ctx.reconcile_login_state(slotID);
            let logout_error = if ctx.is_slot_logged_in(slotID) {
                match ctx.logout_slot(slotID) {
                    Ok(()) => None,
                    Err(error) => {
                        ctx.clear_login_state(slotID);
                        ctx.slot.clear_session();
                        Some(error)
                    }
                }
            } else {
                None
            };
            ctx.sessions.retain(|_k, v| v.backend().slotID() != slotID);
            ctx.memory_objects.retain(|_, object| {
                object
                    .creator_session
                    .map(|owner| !closed_sessions.contains(&owner))
                    .unwrap_or(true)
            });
            log!(2, "C_CloseAllSessions sessions after {:?}", ctx.sessions);
            match logout_error {
                Some(error) => Err(error),
                None => Ok(CKR_OK as CK_RV),
            }
        });
        if let Err(error) = unregister_session_slots_in_context(context, &closed_sessions) {
            return error.into();
        }
        match result {
            Ok(rv) => rv,
            Err(error) => error.into(),
        }
    }
}

ffi_entry_point! {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn C_GetSessionInfo(
        session_handle: CK_SESSION_HANDLE,
        info_ptr: *mut CK_SESSION_INFO,
    ) -> CK_RV {
        log!(2, "C_GetSessionInfo called with {:?}", session_handle);
        map(get_session_info(session_handle, info_ptr))
    }
}

fn get_session_info(
    session_handle: CK_SESSION_HANDLE,
    info_ptr: *mut CK_SESSION_INFO,
) -> Result<(), Error> {
    let info = unsafe { as_mut(info_ptr) }?;
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags) = {
            let session = ctx._get_session(session_handle)?.1;
            (session.slotID(), session.flags())
        };
        ctx.reconcile_login_state(slot_id);
        if ctx.is_slot_logged_in(slot_id) || ctx.get_slot(slot_id)?.backend_session_is_active() {
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

session_unsupported_stub!(C_GetOperationState(
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: *mut ::std::os::raw::c_ulong,
));

session_unsupported_stub!(C_SetOperationState(
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: ::std::os::raw::c_ulong,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentiation_key: CK_OBJECT_HANDLE,
));

fn login_role(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    role: LoginRole,
    authenticate: impl FnOnce(&mut dyn Slot) -> Result<(), Error>,
) -> Result<(), Error> {
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
            session.backend().slotID() == slot_id
                && session.backend().flags() & CKF_RW_SESSION as CK_FLAGS == 0
        }) {
            return Err(CKR_SESSION_READ_ONLY_EXISTS.into());
        }
    }
    authenticate(ctx._get_slot_mut(slot_id)?)?;
    ctx.login_role = Some(role);
    if ctx.get_slot(slot_id)?.refresh_token_objects_after_login() {
        if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
            let _ = ctx._get_slot_mut(slot_id)?.logout();
            ctx.clear_login_state(slot_id);
            return Err(error);
        }
    }
    Ok(())
}

fn login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *const ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        let pinentry = ctx.pinentry.clone();
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            return with_pin(pin, pin_len, |pin| {
                let mut context_operation = None;
                let mut sign_operation = false;
                let session = ctx.get_session_context_mut(session_handle)?;
                if let Some(operation) = &session.sign_operation {
                    context_operation = Some((
                        operation.slot_id,
                        operation.context_specific_extended,
                        operation.context_specific_rp_id.clone(),
                    ));
                    sign_operation = true;
                }
                if let Some(operation) = &session.decrypt_operation {
                    if context_operation.is_some() {
                        return Err(CKR_OPERATION_ACTIVE.into());
                    }
                    context_operation =
                        Some((operation.slot_id, operation.context_specific_extended, None));
                }
                let (slot_id, extended, rp_id) =
                    context_operation.ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
                ctx.reconcile_login_state(slot_id);
                if !ctx.is_slot_user_logged_in(slot_id) {
                    return Err(CKR_USER_NOT_LOGGED_IN.into());
                }
                let authorization = ctx._get_slot_mut(slot_id)?.login_context_specific(
                    pin,
                    extended,
                    rp_id.as_deref(),
                )?;
                if let Some(authorization) = authorization {
                    if !sign_operation {
                        return Err(CKR_FUNCTION_FAILED.into());
                    }
                    let operation = ctx
                        .get_session_context_mut(session_handle)?
                        .sign_operation
                        .as_mut()
                        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
                    if operation.context_specific_rp_id != rp_id {
                        return Err(CKR_OPERATION_NOT_INITIALIZED.into());
                    }
                    operation.fido_authorization = Some(authorization);
                }
                Ok(())
            });
        }
        let role = match user_type {
            value if value == CKU_USER as CK_USER_TYPE => LoginRole::User,
            value if value == CKU_SO as CK_USER_TYPE => LoginRole::So,
            _ => return Err(CKR_USER_TYPE_INVALID.into()),
        };
        with_optional_pin(pin, pin_len, |pin| {
            login_role(ctx, session_handle, slot_id, role, |slot| match role {
                LoginRole::User => match pin {
                    Some(pin) => slot.login_with_pinentry(pin, pinentry.as_ref()),
                    None => slot.login_without_pin(pinentry.as_ref()),
                },
                LoginRole::So => match pin {
                    Some(pin) => slot.login_so(pin),
                    None => slot.login_so_without_pin(pinentry.as_ref()),
                },
            })
        })
    })
}

fn with_optional_pin<R>(
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
    use_pin: impl for<'a> FnOnce(Option<&'a [u8]>) -> Result<R, Error>,
) -> Result<R, Error> {
    if pin.is_null() {
        if pin_len != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        return use_pin(None);
    }
    with_pin(pin, pin_len, |pin| use_pin(Some(pin)))
}

fn with_pin<R>(
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
    use_pin: impl for<'a> FnOnce(&'a [u8]) -> Result<R, Error>,
) -> Result<R, Error> {
    let pin = unsafe { from_raw_parts(pin, pin_len as usize) }?;
    if std::str::from_utf8(pin).is_err() {
        return Err(CKR_PIN_INVALID.into());
    }
    use_pin(pin)
}

ffi_entry_point! {
    pub fn C_Login(
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
}

fn login_user(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *const CK_UTF8CHAR,
    pin_len: CK_ULONG,
    username: *const CK_UTF8CHAR,
    username_len: CK_ULONG,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        let pinentry = ctx.pinentry.clone();
        if user_type != CKU_USER as CK_USER_TYPE {
            return Err(CKR_USER_TYPE_INVALID.into());
        }
        if !ctx.get_slot(slot_id)?.supports_login_user() {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        let username = unsafe { from_raw_parts(username, username_len as usize) }?;
        let username = std::str::from_utf8(username).map_err(|_| CKR_ARGUMENTS_BAD)?;
        with_optional_pin(pin, pin_len, |pin| {
            login_role(ctx, session_handle, slot_id, LoginRole::User, |slot| {
                if let Some(pin) = pin {
                    return slot.login_user(username.as_bytes(), pin);
                }
                slot.login_user_without_pin(username.as_bytes(), pinentry.as_ref())
            })
        })
    })
}

ffi_entry_point! {
    pub fn C_LoginUser(
        session_handle: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: *mut CK_UTF8CHAR,
        pin_len: CK_ULONG,
        username: *mut CK_UTF8CHAR,
        username_len: CK_ULONG,
    ) -> CK_RV {
        log!(
            2,
            "C_LoginUser called with {:?}",
            (
                session_handle,
                user_type,
                pin,
                pin_len,
                username,
                username_len
            )
        );
        map(login_user(
            session_handle,
            user_type,
            pin,
            pin_len,
            username,
            username_len,
        ))
    }
}

fn logout(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        ctx.reconcile_login_state(slot_id);
        if !ctx.is_slot_logged_in(slot_id) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        ctx.logout_slot(slot_id)
    })
}

ffi_entry_point! {
    pub fn C_Logout(
        session_handle: CK_SESSION_HANDLE,
    ) -> CK_RV {
        log!(2, "C_Logout called with {:?}", session_handle);
        map(logout(session_handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_null_zero_length_pin_is_an_empty_pin() {
        let empty_string = [0_u8];
        with_pin(empty_string.as_ptr(), 0, |pin| {
            assert!(pin.is_empty());
            Ok(())
        })
        .unwrap();
    }
}
