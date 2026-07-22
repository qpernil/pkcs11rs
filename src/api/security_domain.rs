#[repr(C)]
pub struct PKCS11RS_SCP03_KEY_SET {
    pub pEncKey: *const CK_BYTE,
    pub ulEncKeyLen: CK_ULONG,
    pub pMacKey: *const CK_BYTE,
    pub ulMacKeyLen: CK_ULONG,
    pub pDekKey: *const CK_BYTE,
    pub ulDekKeyLen: CK_ULONG,
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

fn finish_security_domain_mutation(
    ctx: &mut Context,
    slot_id: CK_SLOT_ID,
    result: Result<(), Error>,
) -> Result<(), Error> {
    if let Err(error) = result {
        ctx.reconcile_login_state(slot_id);
        return Err(error);
    }
    ctx._get_slot_mut(slot_id)?.invalidate_token_objects();
    if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
        log!(
            2,
            "Issuer SD object refresh after provisioning failed: {:?}",
            error
        );
        ctx.reconcile_login_state(slot_id);
    }
    Ok(())
}
