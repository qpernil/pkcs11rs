const YUBIHSM_DEVICE_FINGERPRINT_LENGTH: usize = 32;

#[derive(Clone, Copy)]
enum YubiHsmEnrollment {
    Attestation {
        key_id: u16,
        validation: crate::yubihsm::trust::AttestationValidation,
    },
    PublicKey,
}

#[no_mangle]
pub extern "C" fn PKCS11RS_YubiHsmEnrollDeviceAttestation(
    session_handle: CK_SESSION_HANDLE,
    attestation_key_id: CK_ULONG,
    fingerprint: CK_BYTE_PTR,
    fingerprint_len: CK_ULONG_PTR,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_YubiHsmEnrollDeviceAttestation called for session {session_handle}, attestation key {attestation_key_id}"
    );
    let key_id = match u16::try_from(attestation_key_id) {
        Ok(key_id) => key_id,
        Err(_) => return CKR_ARGUMENTS_BAD as CK_RV,
    };
    map(yubihsm_enroll_device(
        session_handle,
        fingerprint,
        fingerprint_len,
        YubiHsmEnrollment::Attestation {
            key_id,
            validation: crate::yubihsm::trust::AttestationValidation::ExplicitSigner,
        },
        None,
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation(
    session_handle: CK_SESSION_HANDLE,
    fingerprint: CK_BYTE_PTR,
    fingerprint_len: CK_ULONG_PTR,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation called for session {session_handle}"
    );
    map(yubihsm_enroll_device(
        session_handle,
        fingerprint,
        fingerprint_len,
        YubiHsmEnrollment::Attestation {
            key_id: 0,
            validation: crate::yubihsm::trust::AttestationValidation::Yubico,
        },
        None,
    ))
}

#[no_mangle]
pub extern "C" fn PKCS11RS_YubiHsmEnrollDevicePublicKey(
    session_handle: CK_SESSION_HANDLE,
    fingerprint: CK_BYTE_PTR,
    fingerprint_len: CK_ULONG_PTR,
) -> CK_RV {
    log!(
        2,
        "PKCS11RS_YubiHsmEnrollDevicePublicKey called for session {session_handle}"
    );
    map(yubihsm_enroll_device(
        session_handle,
        fingerprint,
        fingerprint_len,
        YubiHsmEnrollment::PublicKey,
        None,
    ))
}

fn yubihsm_enroll_device(
    session_handle: CK_SESSION_HANDLE,
    fingerprint: CK_BYTE_PTR,
    fingerprint_len: CK_ULONG_PTR,
    enrollment: YubiHsmEnrollment,
    trust_prefix: Option<&std::ffi::OsStr>,
) -> Result<(), Error> {
    let fingerprint_len = as_mut(fingerprint_len)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        validate_yubihsm_enrollment(ctx, slot_id, flags, logged_in)?;
        let session = ctx._get_session(session_handle)?.1;
        let device_public_key = session.yubihsm_device_public_key()?;
        let digest = crate::yubihsm::trust::fingerprint_bytes(&device_public_key)?;
        if fingerprint.is_null() {
            *fingerprint_len = YUBIHSM_DEVICE_FINGERPRINT_LENGTH as CK_ULONG;
            return Ok(());
        }
        if *fingerprint_len < YUBIHSM_DEVICE_FINGERPRINT_LENGTH as CK_ULONG {
            *fingerprint_len = YUBIHSM_DEVICE_FINGERPRINT_LENGTH as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let installed = match enrollment {
            YubiHsmEnrollment::PublicKey => crate::yubihsm::trust::install_public_key(
                &device_public_key,
                trust_prefix,
            )?,
            YubiHsmEnrollment::Attestation { key_id, validation } => {
                let attestation = session.yubihsm_command(
                    &YubiHsmCommand::sign_attestation_certificate(0, key_id),
                )?;
                let device_certificate = session.yubihsm_command(
                    &YubiHsmCommand::get_object(YubiHsmCommandCode::GetOpaque, key_id)?,
                )?;
                crate::yubihsm::trust::install_attestation(
                    &device_public_key,
                    &attestation,
                    &device_certificate,
                    validation,
                    trust_prefix,
                )?
            }
        };
        if installed != digest {
            return Err(CKR_DEVICE_ERROR.into());
        }
        unsafe {
            ptr::copy_nonoverlapping(installed.as_ptr(), fingerprint, installed.len());
        }
        *fingerprint_len = installed.len() as CK_ULONG;
        Ok(())
    })
}

fn validate_yubihsm_enrollment(
    ctx: &Context,
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    logged_in: bool,
) -> Result<(), Error> {
    if !ctx.get_slot(slot_id)?.is_yubihsm() {
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
