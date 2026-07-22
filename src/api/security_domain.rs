#[repr(C)]
pub struct PKCS11RS_SCP03_KEY_SET {
    pub pEncKey: *const CK_BYTE,
    pub ulEncKeyLen: CK_ULONG,
    pub pMacKey: *const CK_BYTE,
    pub ulMacKeyLen: CK_ULONG,
    pub pDekKey: *const CK_BYTE,
    pub ulDekKeyLen: CK_ULONG,
}

#[repr(C)]
pub struct PKCS11RS_BYTE_BUFFER {
    pub pValue: *const CK_BYTE,
    pub ulValueLen: CK_ULONG,
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainPutScp03KeySet(
    session_handle: CK_SESSION_HANDLE,
    new_kvn: CK_BYTE,
    replace_kvn: CK_BYTE,
    keys: *const PKCS11RS_SCP03_KEY_SET,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainPutScp03KeySet called for session {session_handle}, new KVN {new_kvn}, replacement KVN {replace_kvn}"
    );
    map(security_domain_put_scp03_key_set(
        session_handle,
        new_kvn,
        replace_kvn,
        keys,
    ))
}

fn security_domain_put_scp03_key_set(
    session_handle: CK_SESSION_HANDLE,
    new_kvn: u8,
    replace_kvn: u8,
    keys: *const PKCS11RS_SCP03_KEY_SET,
) -> Result<(), Error> {
    let keys = _as_ref(keys)?;
    let enc = from_raw_parts(keys.pEncKey, keys.ulEncKeyLen as usize)?;
    let mac = from_raw_parts(keys.pMacKey, keys.ulMacKeyLen as usize)?;
    let dek = from_raw_parts(keys.pDekKey, keys.ulDekKeyLen as usize)?;
    if [enc, mac, dek].iter().any(|key| key.len() != 16) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let keys = Scp03ProvisioningKeys { enc, mac, dek };

    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        validate_security_domain_administration(ctx, slot_id, flags, logged_in)?;
        let result = ctx
            ._get_session(session_handle)?
            .1
            .security_domain_put_scp03_key_set(new_kvn, replace_kvn, &keys);
        finish_security_domain_mutation(ctx, slot_id, result)
    })
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainDeleteScp03KeySet(
    session_handle: CK_SESSION_HANDLE,
    kvn: CK_BYTE,
    delete_last: CK_BBOOL,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainDeleteScp03KeySet called for session {session_handle}, KVN {kvn}, delete last {delete_last}"
    );
    map(security_domain_delete_scp03_key_set(
        session_handle,
        kvn,
        delete_last,
    ))
}

fn security_domain_delete_scp03_key_set(
    session_handle: CK_SESSION_HANDLE,
    kvn: u8,
    delete_last: CK_BBOOL,
) -> Result<(), Error> {
    let delete_last = match delete_last {
        x if x == CK_FALSE as CK_BBOOL => false,
        x if x == CK_TRUE as CK_BBOOL => true,
        _ => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        validate_security_domain_administration(ctx, slot_id, flags, logged_in)?;
        let result = ctx
            ._get_session(session_handle)?
            .1
            .security_domain_delete_scp03_key_set(kvn, delete_last);
        finish_security_domain_mutation(ctx, slot_id, result)
    })
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainGenerateScp11Key(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    new_kvn: CK_BYTE,
    replace_kvn: CK_BYTE,
    curve: CK_BYTE,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainGenerateScp11Key called for session {session_handle}, KID {kid}, new KVN {new_kvn}, replacement KVN {replace_kvn}, curve {curve}"
    );
    map(security_domain_generate_scp11_key(
        session_handle,
        kid,
        new_kvn,
        replace_kvn,
        curve,
        public_key,
        public_key_len,
    ))
}

fn security_domain_generate_scp11_key(
    session_handle: CK_SESSION_HANDLE,
    kid: u8,
    new_kvn: u8,
    replace_kvn: u8,
    curve: u8,
    public_key: CK_BYTE_PTR,
    public_key_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    let required = security_domain::scp11_public_point_length(curve)?;
    let public_key_len = as_mut(public_key_len)?;
    with_context_mut(|ctx| {
        let slot_id = validate_security_domain_session(ctx, session_handle)?;
        if public_key.is_null() {
            *public_key_len = required as CK_ULONG;
            return Ok(());
        }
        if *public_key_len < required as CK_ULONG {
            *public_key_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        let result = ctx
            ._get_session(session_handle)?
            .1
            .security_domain_scp11_administration(&Scp11Administration::GenerateKey {
                key_ref: security_domain::KeyRef {
                    kid,
                    kvn: new_kvn,
                },
                replace_kvn,
                curve,
            });
        let generated = finish_security_domain_mutation(ctx, slot_id, result)?;
        if generated.len() != required {
            return Err(CKR_DEVICE_ERROR.into());
        }
        unsafe { ptr::copy_nonoverlapping(generated.as_ptr(), public_key, generated.len()) };
        *public_key_len = generated.len() as CK_ULONG;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainPutScp11PrivateKey(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    new_kvn: CK_BYTE,
    replace_kvn: CK_BYTE,
    key: *const CK_BYTE,
    key_len: CK_ULONG,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainPutScp11PrivateKey called for session {session_handle}, KID {kid}, new KVN {new_kvn}, replacement KVN {replace_kvn}"
    );
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::PutPrivateKey {
            key_ref: security_domain::KeyRef {
                kid,
                kvn: new_kvn,
            },
            replace_kvn,
            encoded: Zeroizing::new(match from_raw_parts(key, key_len as usize) {
                Ok(key) => key.to_vec(),
                Err(error) => return error.into(),
            }),
        },
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainPutScp11PublicKey(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    new_kvn: CK_BYTE,
    replace_kvn: CK_BYTE,
    key: *const CK_BYTE,
    key_len: CK_ULONG,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainPutScp11PublicKey called for session {session_handle}, KID {kid}, new KVN {new_kvn}, replacement KVN {replace_kvn}"
    );
    let key = match from_raw_parts(key, key_len as usize) {
        Ok(key) => key.to_vec(),
        Err(error) => return error.into(),
    };
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::PutPublicKey {
            key_ref: security_domain::KeyRef {
                kid,
                kvn: new_kvn,
            },
            replace_kvn,
            encoded: key,
        },
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainStoreScp11CertificateChain(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    kvn: CK_BYTE,
    certificates: *const PKCS11RS_BYTE_BUFFER,
    certificate_count: CK_ULONG,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainStoreScp11CertificateChain called for session {session_handle}, KID {kid}, KVN {kvn}, certificate count {certificate_count}"
    );
    let certificates = match copy_buffers(certificates, certificate_count) {
        Ok(certificates) => certificates,
        Err(error) => return error.into(),
    };
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::StoreCertificateChain {
            key_ref: security_domain::KeyRef { kid, kvn },
            certificates,
        },
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainStoreScp11CaIssuer(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    kvn: CK_BYTE,
    subject_key_identifier: *const CK_BYTE,
    subject_key_identifier_len: CK_ULONG,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainStoreScp11CaIssuer called for session {session_handle}, KID {kid}, KVN {kvn}"
    );
    let subject_key_identifier =
        match from_raw_parts(subject_key_identifier, subject_key_identifier_len as usize) {
            Ok(value) => value.to_vec(),
            Err(error) => return error.into(),
        };
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::StoreCaIssuer {
            key_ref: security_domain::KeyRef { kid, kvn },
            subject_key_identifier,
        },
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainSetScp11Allowlist(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    kvn: CK_BYTE,
    serials: *const PKCS11RS_BYTE_BUFFER,
    serial_count: CK_ULONG,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainSetScp11Allowlist called for session {session_handle}, KID {kid}, KVN {kvn}, serial count {serial_count}"
    );
    let serials = match copy_buffers(serials, serial_count) {
        Ok(serials) => serials,
        Err(error) => return error.into(),
    };
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::SetAllowlist {
            key_ref: security_domain::KeyRef { kid, kvn },
            serials,
        },
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_SecurityDomainDeleteScp11Key(
    session_handle: CK_SESSION_HANDLE,
    kid: CK_BYTE,
    kvn: CK_BYTE,
    delete_last: CK_BBOOL,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_SecurityDomainDeleteScp11Key called for session {session_handle}, KID {kid}, KVN {kvn}, delete last {delete_last}"
    );
    let delete_last = match parse_bool(delete_last) {
        Ok(value) => value,
        Err(error) => return error.into(),
    };
    map(security_domain_mutation(
        session_handle,
        Scp11Administration::DeleteKey {
            key_ref: security_domain::KeyRef { kid, kvn },
            delete_last,
        },
    ))
}

fn copy_buffers(
    buffers: *const PKCS11RS_BYTE_BUFFER,
    count: CK_ULONG,
) -> Result<Vec<Vec<u8>>, Error> {
    from_raw_parts(buffers, count as usize)?
        .iter()
        .map(|buffer| {
            from_raw_parts(buffer.pValue, buffer.ulValueLen as usize).map(|value| value.to_vec())
        })
        .collect()
}

fn parse_bool(value: CK_BBOOL) -> Result<bool, Error> {
    match value {
        x if x == CK_FALSE as CK_BBOOL => Ok(false),
        x if x == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn security_domain_mutation(
    session_handle: CK_SESSION_HANDLE,
    operation: Scp11Administration,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let slot_id = validate_security_domain_session(ctx, session_handle)?;
        let result = ctx
            ._get_session(session_handle)?
            .1
            .security_domain_scp11_administration(&operation);
        finish_security_domain_mutation(ctx, slot_id, result).map(|_| ())
    })
}

fn validate_security_domain_session(
    ctx: &Context,
    session_handle: CK_SESSION_HANDLE,
) -> Result<CK_SLOT_ID, Error> {
    let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
    validate_security_domain_administration(ctx, slot_id, flags, logged_in)?;
    Ok(slot_id)
}

fn validate_security_domain_administration(
    ctx: &Context,
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    logged_in: bool,
) -> Result<(), Error> {
    if !ctx.get_slot(slot_id)?.is_issuer_security_domain() {
        return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
    }
    if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
        return Err(CKR_SESSION_READ_ONLY.into());
    }
    if !logged_in {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }
    Ok(())
}

fn finish_security_domain_mutation<T>(
    ctx: &mut Context,
    slot_id: CK_SLOT_ID,
    result: Result<T, Error>,
) -> Result<T, Error> {
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            ctx.reconcile_login_state(slot_id);
            return Err(error);
        }
    };
    ctx._get_slot_mut(slot_id)?.invalidate_token_objects();
    if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
        log!(
            2,
            "Issuer SD object refresh after provisioning failed: {:?}",
            error
        );
        ctx.reconcile_login_state(slot_id);
    }
    Ok(value)
}
