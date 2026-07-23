const HSMAUTH_P256_PUBLIC_KEY_LENGTH: usize = 65;

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthPutSymmetricCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    enc_key: *const CK_BYTE,
    enc_key_len: CK_ULONG,
    mac_key: *const CK_BYTE,
    mac_key_len: CK_ULONG,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
) -> CK_RV {
    map(hsmauth_put_symmetric(
        session_handle,
        label,
        label_len,
        from_raw_parts(enc_key, enc_key_len as usize),
        from_raw_parts(mac_key, mac_key_len as usize),
        credential_password,
        credential_password_len,
        touch_required,
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthPutDerivedSymmetricCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    derivation_password: *const CK_UTF8CHAR,
    derivation_password_len: CK_ULONG,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
) -> CK_RV {
    map((|| {
        let derivation_password =
            hsmauth_utf8(derivation_password, derivation_password_len)?;
        let keys = crate::yubico_password_kdf(derivation_password.as_bytes())?;
        hsmauth_put_symmetric(
            session_handle,
            label,
            label_len,
            Ok(&keys[..16]),
            Ok(&keys[16..]),
            credential_password,
            credential_password_len,
            touch_required,
        )
    })())
}

#[allow(clippy::too_many_arguments)]
fn hsmauth_put_symmetric(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    enc_key: Result<&[u8], Error>,
    mac_key: Result<&[u8], Error>,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
) -> Result<(), Error> {
    let label = hsmauth_utf8(label, label_len)?;
    let enc_key = enc_key?;
    let mac_key = mac_key?;
    if enc_key.len() != 16 || mac_key.len() != 16 {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let credential_password =
        hsmauth_password(credential_password, credential_password_len)?;
    let touch_required = hsmauth_bool(touch_required)?;
    hsmauth_mutation(
        session_handle,
        HsmAuthAdministration::PutSymmetric {
            label,
            keys: hsmauth::SymmetricCredentialKeys {
                enc: enc_key,
                mac: mac_key,
            },
            credential_password: credential_password.as_slice(),
            touch_required,
        },
    )
    .map(|_| ())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthPutAsymmetricCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    private_key: *const CK_BYTE,
    private_key_len: CK_ULONG,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> CK_RV {
    map((|| {
        let private_key = from_raw_parts(private_key, private_key_len as usize)?;
        if private_key.len() != 32 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        hsmauth_put_asymmetric(
            session_handle,
            label,
            label_len,
            Some(private_key),
            credential_password,
            credential_password_len,
            touch_required,
            public_key,
            public_key_len,
        )
    })())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthPutDerivedAsymmetricCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    derivation_password: *const CK_UTF8CHAR,
    derivation_password_len: CK_ULONG,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> CK_RV {
    map((|| {
        let derivation_password =
            hsmauth_utf8(derivation_password, derivation_password_len)?;
        let key =
            crate::yubico_kdf::yubico_password_p256_key(derivation_password.as_bytes())?;
        let private_key = Zeroizing::new(key.private_key().to_vec_padded(32)?);
        hsmauth_put_asymmetric(
            session_handle,
            label,
            label_len,
            Some(private_key.as_slice()),
            credential_password,
            credential_password_len,
            touch_required,
            public_key,
            public_key_len,
        )
    })())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthGenerateAsymmetricCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> CK_RV {
    map(hsmauth_put_asymmetric(
        session_handle,
        label,
        label_len,
        None,
        credential_password,
        credential_password_len,
        touch_required,
        public_key,
        public_key_len,
    ))
}

#[allow(clippy::too_many_arguments)]
fn hsmauth_put_asymmetric(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    private_key: Option<&[u8]>,
    credential_password: *const CK_UTF8CHAR,
    credential_password_len: CK_ULONG,
    touch_required: CK_BBOOL,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    let public_key_len = as_mut(public_key_len)?;
    hsmauth_validate_session_handle(session_handle)?;
    if public_key.is_null() {
        *public_key_len = HSMAUTH_P256_PUBLIC_KEY_LENGTH as CK_ULONG;
        return Ok(());
    }
    if *public_key_len < HSMAUTH_P256_PUBLIC_KEY_LENGTH as CK_ULONG {
        *public_key_len = HSMAUTH_P256_PUBLIC_KEY_LENGTH as CK_ULONG;
        return Err(CKR_BUFFER_TOO_SMALL.into());
    }

    let label = hsmauth_utf8(label, label_len)?;
    let credential_password =
        hsmauth_password(credential_password, credential_password_len)?;
    let touch_required = hsmauth_bool(touch_required)?;
    let value = hsmauth_mutation(
        session_handle,
        HsmAuthAdministration::PutAsymmetric {
            label,
            private_key,
            credential_password: credential_password.as_slice(),
            touch_required,
        },
    )?;
    if value.len() != HSMAUTH_P256_PUBLIC_KEY_LENGTH {
        return Err(CKR_DEVICE_ERROR.into());
    }
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), public_key, value.len());
    }
    *public_key_len = value.len() as CK_ULONG;
    Ok(())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthDeleteCredential(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
) -> CK_RV {
    map((|| {
        let label = hsmauth_utf8(label, label_len)?;
        hsmauth_mutation(
            session_handle,
            HsmAuthAdministration::Delete { label },
        )
        .map(|_| ())
    })())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthChangeCredentialPassword(
    session_handle: CK_SESSION_HANDLE,
    label: *const CK_UTF8CHAR,
    label_len: CK_ULONG,
    new_credential_password: *const CK_UTF8CHAR,
    new_credential_password_len: CK_ULONG,
) -> CK_RV {
    map((|| {
        let label = hsmauth_utf8(label, label_len)?;
        let password =
            hsmauth_password(new_credential_password, new_credential_password_len)?;
        hsmauth_mutation(
            session_handle,
            HsmAuthAdministration::ChangeCredentialPassword {
                label,
                new_credential_password: password.as_slice(),
            },
        )
        .map(|_| ())
    })())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthChangeManagementPassword(
    session_handle: CK_SESSION_HANDLE,
    new_management_password: *const CK_UTF8CHAR,
    new_management_password_len: CK_ULONG,
) -> CK_RV {
    map((|| {
        let password =
            hsmauth_password(new_management_password, new_management_password_len)?;
        hsmauth_mutation(
            session_handle,
            HsmAuthAdministration::ChangeManagementKey {
                new_management_key: password.as_slice(),
            },
        )
        .map(|_| ())
    })())
}

#[no_mangle]
pub extern "C" fn PKCS11RS_HsmAuthReset(
    session_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    map(hsmauth_mutation(
        session_handle,
        HsmAuthAdministration::Reset,
    )
    .map(|_| ()))
}

fn hsmauth_mutation(
    session_handle: CK_SESSION_HANDLE,
    operation: HsmAuthAdministration<'_>,
) -> Result<Vec<u8>, Error> {
    with_context_mut(|ctx| {
        let slot_id = validate_hsmauth_session(ctx, session_handle)?;

        let result = ctx
            ._get_slot_mut(slot_id)?
            .hsmauth_administration(operation);
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                ctx.reconcile_login_state(slot_id);
                return Err(error);
            }
        };
        ctx.reconcile_login_state(slot_id);
        if ctx.login_role(slot_id).is_some() {
            if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
                log!(
                    2,
                    "YubiHSM Auth object refresh after administration failed: {:?}",
                    error
                );
            }
        }
        Ok(value)
    })
}

fn hsmauth_validate_session_handle(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| validate_hsmauth_session(ctx, session_handle).map(|_| ()))
}

fn validate_hsmauth_session(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
) -> Result<CK_SLOT_ID, Error> {
    let (slot_id, flags, _) = ctx.session_details(session_handle)?;
    if !ctx.get_slot(slot_id)?.is_hsmauth() {
        return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
    }
    if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
        return Err(CKR_SESSION_READ_ONLY.into());
    }
    ctx.reconcile_login_state(slot_id);
    if ctx.login_role(slot_id) != Some(LoginRole::So) {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }
    Ok(slot_id)
}

fn hsmauth_utf8<'a>(
    value: *const CK_UTF8CHAR,
    value_len: CK_ULONG,
) -> Result<&'a str, Error> {
    std::str::from_utf8(from_raw_parts(value, value_len as usize)?)
        .map_err(|_| CKR_ARGUMENTS_BAD.into())
}

fn hsmauth_password(
    value: *const CK_UTF8CHAR,
    value_len: CK_ULONG,
) -> Result<Zeroizing<[u8; 16]>, Error> {
    let value = hsmauth_utf8(value, value_len)?;
    hsmauth::password_to_key(value.as_bytes())
}

fn hsmauth_bool(value: CK_BBOOL) -> Result<bool, Error> {
    match value {
        value if value == CK_FALSE as CK_BBOOL => Ok(false),
        value if value == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}
