use crate::*;

const MIN_EXPORT_PASSWORD_LENGTH: usize = 8;
const MAX_EXPORT_PASSWORD_LENGTH: usize = 1024;

/// Export an extractable private key from a named software slot as a DER
/// PKCS #8 `EncryptedPrivateKeyInfo`.
///
/// The PKCS #11 user login authorizes access to the private key. `password`
/// independently protects the exported document so it can be opened by
/// interoperable tools such as OpenSSL.
#[no_mangle]
pub extern "C" fn PKCS11RS_SoftwareExportPrivateKey(
    session_handle: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    password: *const CK_UTF8CHAR,
    password_len: CK_ULONG,
    encrypted_key: CK_BYTE_PTR,
    encrypted_key_len: CK_ULONG_PTR,
) -> CK_RV {
    map(software_export_private_key(
        session_handle,
        key,
        password,
        password_len,
        encrypted_key,
        encrypted_key_len,
    ))
}

fn software_export_private_key(
    session_handle: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    password: *const CK_UTF8CHAR,
    password_len: CK_ULONG,
    encrypted_key: CK_BYTE_PTR,
    encrypted_key_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    let password_len = usize::try_from(password_len).map_err(|_| CKR_PIN_LEN_RANGE)?;
    if !(MIN_EXPORT_PASSWORD_LENGTH..=MAX_EXPORT_PASSWORD_LENGTH).contains(&password_len) {
        return Err(CKR_PIN_LEN_RANGE.into());
    }
    let password = Zeroizing::new(from_raw_parts(password, password_len)?.to_vec());
    let output_len = as_mut(encrypted_key_len)?;

    with_session_context(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.kind() != SlotKind::Software {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if !ctx.is_slot_user_logged_in(slot_id) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let object = ctx
            .resolve_object(key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if !matches!(object.material, KeyMaterial::SoftwarePrivate(_)) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        if !object.extractable {
            return Err(CKR_KEY_UNEXTRACTABLE.into());
        }

        let required_len = crate::software_storage::encrypted_private_key_info_len(&object)?;
        let required_len =
            CK_ULONG::try_from(required_len).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        if encrypted_key.is_null() {
            *output_len = required_len;
            return Ok(());
        }
        if *output_len < required_len {
            *output_len = required_len;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        let encrypted =
            crate::software_storage::export_encrypted_private_key_info(&object, password.as_ref())?;
        if encrypted.len() != required_len as usize {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let output = _from_raw_parts_mut(encrypted_key, encrypted.len())?;
        output.copy_from_slice(encrypted.as_ref());
        *output_len = required_len;
        Ok(())
    })
}
