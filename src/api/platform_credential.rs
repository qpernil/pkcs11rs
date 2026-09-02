use crate::*;

const P256_PUBLIC_KEY_LENGTH: usize = 65;
const YUBIHSM_CAPABILITIES_LENGTH: usize = 8;

pub const PKCS11RS_PLATFORM_CREDENTIAL_ALGORITHM_P256: CK_ULONG = 1;
pub const PKCS11RS_PLATFORM_PROVISIONED: CK_ULONG = 1;
pub const PKCS11RS_PLATFORM_ALREADY_PROVISIONED: CK_ULONG = 2;
pub const PKCS11RS_PLATFORM_REPAIRED: CK_ULONG = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PKCS11RS_PLATFORM_CREDENTIAL_INFO {
    pub ulAlgorithm: CK_ULONG,
    pub ulNameLen: CK_ULONG,
    pub name: [CK_UTF8CHAR; crate::platform_crypto::PLATFORM_CREDENTIAL_NAME_CAPACITY],
}

impl Default for PKCS11RS_PLATFORM_CREDENTIAL_INFO {
    fn default() -> Self {
        Self {
            ulAlgorithm: 0,
            ulNameLen: 0,
            name: [0; crate::platform_crypto::PLATFORM_CREDENTIAL_NAME_CAPACITY],
        }
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_PlatformCredentialGenerate(
        name: *const CK_UTF8CHAR,
        name_len: CK_ULONG,
        public_key: CK_BYTE_PTR,
        public_key_len: CK_ULONG_PTR,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let name = platform_name(name, name_len)?;
            let public_key_len = unsafe { as_mut(public_key_len) }?;
            if public_key.is_null() {
                *public_key_len = P256_PUBLIC_KEY_LENGTH as CK_ULONG;
                return Ok(());
            }
            require_public_key_buffer(public_key_len)?;
            let key = crate::platform_crypto::generate_platform_credential(name)
                .map_err(platform_crypto_error)?;
            copy_platform_public_key(&key, public_key, public_key_len)
        })())
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_PlatformCredentialGetPublicKey(
        name: *const CK_UTF8CHAR,
        name_len: CK_ULONG,
        public_key: CK_BYTE_PTR,
        public_key_len: CK_ULONG_PTR,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let name = platform_name(name, name_len)?;
            let public_key_len = unsafe { as_mut(public_key_len) }?;
            if public_key.is_null() {
                *public_key_len = P256_PUBLIC_KEY_LENGTH as CK_ULONG;
                return Ok(());
            }
            require_public_key_buffer(public_key_len)?;
            let key = crate::platform_crypto::platform_credential_public_key(name)
                .map_err(platform_crypto_error)?;
            copy_platform_public_key(&key, public_key, public_key_len)
        })())
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_PlatformCredentialList(
        credentials: *mut PKCS11RS_PLATFORM_CREDENTIAL_INFO,
        credential_count: CK_ULONG_PTR,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let credential_count = unsafe { as_mut(credential_count) }?;
            let listed = crate::platform_crypto::list_platform_credentials()
                .map_err(platform_crypto_error)?;
            if credentials.is_null() {
                *credential_count = listed.len() as CK_ULONG;
                return Ok(());
            }
            if *credential_count < listed.len() as CK_ULONG {
                *credential_count = listed.len() as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL.into());
            }
            for (index, credential) in listed.iter().enumerate() {
                let mut info = PKCS11RS_PLATFORM_CREDENTIAL_INFO {
                    ulAlgorithm: platform_algorithm(credential.algorithm),
                    ulNameLen: credential.name.len() as CK_ULONG,
                    ..Default::default()
                };
                info.name[..credential.name.len()].copy_from_slice(credential.name.as_bytes());
                unsafe { credentials.add(index).write(info) };
            }
            *credential_count = listed.len() as CK_ULONG;
            Ok(())
        })())
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_PlatformCredentialDelete(
        name: *const CK_UTF8CHAR,
        name_len: CK_ULONG,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let name = platform_name(name, name_len)?;
            crate::platform_crypto::delete_platform_credential(name)
                .map_err(platform_crypto_error)
        })())
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_YubiHsmProvisionPlatformCredential(
        session_handle: CK_SESSION_HANDLE,
        credential_name: *const CK_UTF8CHAR,
        credential_name_len: CK_ULONG,
        authentication_key_id: CK_ULONG,
        label: *const CK_UTF8CHAR,
        label_len: CK_ULONG,
        domains: CK_ULONG,
        capabilities: *const CK_BYTE,
        capabilities_len: CK_ULONG,
        delegated_capabilities: *const CK_BYTE,
        delegated_capabilities_len: CK_ULONG,
        provisioning_result: CK_ULONG_PTR,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let provisioning_result = unsafe { as_mut(provisioning_result) }?;
            *provisioning_result = 0;
            let credential_name = platform_name(credential_name, credential_name_len)?.to_owned();
            let label = platform_label(label, label_len)?.to_owned();
            let authentication_key_id = u16::try_from(authentication_key_id)
                .ok()
                .filter(|id| *id != 0)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let domains = u16::try_from(domains)
                .ok()
                .filter(|domains| *domains != 0)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let capabilities = capability_bytes(capabilities, capabilities_len)?;
            let delegated_capabilities = capability_bytes(
                delegated_capabilities,
                delegated_capabilities_len,
            )?;

            validate_provisioning_session(session_handle)?;
            let public_key = get_or_generate_platform_credential(&credential_name)?;
            *provisioning_result = provision_platform_credential(
                session_handle,
                &credential_name,
                authentication_key_id,
                &label,
                domains,
                capabilities,
                delegated_capabilities,
                &public_key,
            )?;
            Ok(())
        })())
    }
}

ffi_entry_point! {
    pub fn PKCS11RS_YubiHsmUnprovisionPlatformCredential(
        session_handle: CK_SESSION_HANDLE,
        credential_name: *const CK_UTF8CHAR,
        credential_name_len: CK_ULONG,
        authentication_key_id: CK_ULONG,
    ) -> CK_RV {
        map((|| -> Result<(), Error> {
            let credential_name = platform_name(credential_name, credential_name_len)?;
            let authentication_key_id = u16::try_from(authentication_key_id)
                .ok()
                .filter(|id| *id != 0)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            validate_provisioning_session(session_handle)?;
            let public_key = crate::platform_crypto::platform_credential_public_key(credential_name)
                .map_err(platform_crypto_error)?;
            unprovision_platform_credential(
                session_handle,
                authentication_key_id,
                &public_key,
            )
        })())
    }
}

fn platform_name<'a>(name: *const CK_UTF8CHAR, name_len: CK_ULONG) -> Result<&'a str, Error> {
    let value = unsafe { from_raw_parts(name, name_len as usize) }?;
    let value = std::str::from_utf8(value).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    crate::platform_crypto::validate_platform_credential_name(value)
        .map_err(platform_crypto_error)?;
    Ok(value)
}

fn platform_label<'a>(label: *const CK_UTF8CHAR, label_len: CK_ULONG) -> Result<&'a str, Error> {
    let value = unsafe { from_raw_parts(label, label_len as usize) }?;
    let value = std::str::from_utf8(value).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    if value.is_empty() || value.len() > 40 || value.as_bytes().contains(&0) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(value)
}

fn capability_bytes(value: *const CK_BYTE, length: CK_ULONG) -> Result<[u8; 8], Error> {
    let value = unsafe { from_raw_parts(value, length as usize) }?;
    value.try_into().map_err(|_| CKR_ARGUMENTS_BAD.into())
}

fn require_public_key_buffer(public_key_len: &mut CK_ULONG) -> Result<(), Error> {
    if *public_key_len < P256_PUBLIC_KEY_LENGTH as CK_ULONG {
        *public_key_len = P256_PUBLIC_KEY_LENGTH as CK_ULONG;
        return Err(CKR_BUFFER_TOO_SMALL.into());
    }
    Ok(())
}

fn platform_public_key_bytes(key: &SoftwarePublicKey) -> Result<&[u8], Error> {
    let SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    } = key
    else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    if uncompressed.len() != P256_PUBLIC_KEY_LENGTH || uncompressed.first() != Some(&0x04) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(uncompressed)
}

fn copy_platform_public_key(
    key: &SoftwarePublicKey,
    output: CK_BYTE_PTR,
    output_len: &mut CK_ULONG,
) -> Result<(), Error> {
    let bytes = platform_public_key_bytes(key)?;
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    *output_len = bytes.len() as CK_ULONG;
    Ok(())
}

fn platform_algorithm(algorithm: crate::platform_crypto::PlatformCredentialAlgorithm) -> CK_ULONG {
    match algorithm {
        crate::platform_crypto::PlatformCredentialAlgorithm::P256 => {
            PKCS11RS_PLATFORM_CREDENTIAL_ALGORITHM_P256
        }
        _ => 0,
    }
}

fn platform_crypto_error(error: crate::platform_crypto::PlatformCryptoError) -> Error {
    use crate::platform_crypto::PlatformCryptoError;
    match error {
        PlatformCryptoError::InvalidName => CKR_ARGUMENTS_BAD.into(),
        PlatformCryptoError::AlreadyExists => CKR_TEMPLATE_INCONSISTENT.into(),
        PlatformCryptoError::NotFound => CKR_OBJECT_HANDLE_INVALID.into(),
        PlatformCryptoError::Ambiguous => CKR_DEVICE_ERROR.into(),
        PlatformCryptoError::Unsupported => CKR_FUNCTION_NOT_SUPPORTED.into(),
        PlatformCryptoError::InvalidPublicKey => CKR_DATA_INVALID.into(),
        PlatformCryptoError::OutputTooLong => CKR_DATA_LEN_RANGE.into(),
        PlatformCryptoError::Backend(_) => CKR_DEVICE_ERROR.into(),
    }
}

fn validate_provisioning_session(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        Ok(())
    })
}

fn get_or_generate_platform_credential(name: &str) -> Result<SoftwarePublicKey, Error> {
    match crate::platform_crypto::platform_credential_public_key(name) {
        Ok(key) => Ok(key),
        Err(crate::platform_crypto::PlatformCryptoError::NotFound) => {
            match crate::platform_crypto::generate_platform_credential(name) {
                Ok(key) => Ok(key),
                Err(crate::platform_crypto::PlatformCryptoError::AlreadyExists) => {
                    crate::platform_crypto::platform_credential_public_key(name)
                        .map_err(platform_crypto_error)
                }
                Err(error) => Err(platform_crypto_error(error)),
            }
        }
        Err(error) => Err(platform_crypto_error(error)),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn provision_platform_credential(
    session_handle: CK_SESSION_HANDLE,
    _credential_name: &str,
    authentication_key_id: u16,
    label: &str,
    domains: u16,
    capabilities: [u8; YUBIHSM_CAPABILITIES_LENGTH],
    delegated_capabilities: [u8; YUBIHSM_CAPABILITIES_LENGTH],
    platform_public_key: &SoftwarePublicKey,
) -> Result<CK_ULONG, Error> {
    let uncompressed = platform_public_key_bytes(platform_public_key)?;
    let raw_public_key = uncompressed.get(1..).ok_or(CKR_DEVICE_ERROR)?;
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }

        ctx.refresh_slot_token_objects(slot_id)?;
        let objects = ctx.resolved_objects()?;
        let mut authentication_keys = objects.iter().filter(|(_, object)| {
            matches!(
                object.material,
                KeyMaterial::YubiHsm {
                    id,
                    object_type: YUBIHSM_AUTHENTICATION_KEY,
                    ..
                } if id == authentication_key_id
            )
        });
        let existing_authentication_key = authentication_keys.next().map(|(_, object)| object);
        if authentication_keys.next().is_some() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        if let Some(object) = existing_authentication_key {
            match &object.material {
                KeyMaterial::YubiHsm {
                    algorithm,
                    domains: existing_domains,
                    capabilities: existing_capabilities,
                    delegated_capabilities: existing_delegated_capabilities,
                    ..
                } if *algorithm == YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION
                    && *existing_domains == domains
                    && *existing_capabilities == capabilities
                    && *existing_delegated_capabilities == delegated_capabilities
                    && object.label == label => {}
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            }
        }

        let matching_id = authentication_key_id.to_be_bytes();
        let public_candidates = objects
            .iter()
            .filter(|(_, object)| {
                object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                    && object.token
                    && object.id == matching_id
            })
            .map(|(_, object)| object)
            .collect::<Vec<_>>();
        let matching_projection = public_candidates.iter().find(|object| {
            object.label == label
                && matches!(
                    &object.material,
                    KeyMaterial::Public(PublicKeyMaterial::Ec { parameters, public_key })
                        if parameters.as_slice() == [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                            && public_key.as_slice() == raw_public_key
                )
        });
        if !public_candidates.is_empty()
            && (public_candidates.len() != 1 || matching_projection.is_none())
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }

        if existing_authentication_key.is_some() {
            if matching_projection.is_some() {
                return Ok(PKCS11RS_PLATFORM_ALREADY_PROVISIONED);
            }
            // The Authentication Key public half cannot be read portably. A
            // missing projection therefore cannot be repaired safely.
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }

        let mut created_projection = None;
        if matching_projection.is_none() {
            let projection =
                platform_projection_object(slot_id, authentication_key_id, label, raw_public_key);
            created_projection = Some(ctx.store_backed_object(session_handle, projection)?);
        }

        let parameters = YubiHsmDelegatedObjectParameters {
            object: YubiHsmObjectParameters {
                id: authentication_key_id,
                label,
                domains,
                capabilities,
                algorithm: YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities,
        };
        let command = YubiHsmCommand::put_delegated_object(
            YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            raw_public_key,
        )?;
        let creation = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)
            .and_then(|response| parse_yubihsm_object_id(&response));
        let installed_id = match creation {
            Ok(installed_id) if installed_id == authentication_key_id => installed_id,
            Ok(_) => {
                rollback_projection(ctx, created_projection)?;
                return Err(CKR_DEVICE_ERROR.into());
            }
            Err(error) => {
                rollback_projection(ctx, created_projection)?;
                return Err(error);
            }
        };
        let _ = installed_id;
        ctx.refresh_slot_token_objects(slot_id)?;
        Ok(if matching_projection.is_some() {
            PKCS11RS_PLATFORM_REPAIRED
        } else {
            PKCS11RS_PLATFORM_PROVISIONED
        })
    })
}

pub(crate) fn unprovision_platform_credential(
    session_handle: CK_SESSION_HANDLE,
    authentication_key_id: u16,
    platform_public_key: &SoftwarePublicKey,
) -> Result<(), Error> {
    let uncompressed = platform_public_key_bytes(platform_public_key)?;
    let raw_public_key = uncompressed.get(1..).ok_or(CKR_DEVICE_ERROR)?;
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }

        ctx.refresh_slot_token_objects(slot_id)?;
        let objects = ctx.resolved_objects()?;
        let authentication_keys = objects
            .iter()
            .filter(|(_, object)| {
                matches!(
                    object.material,
                    KeyMaterial::YubiHsm {
                        id,
                        object_type: YUBIHSM_AUTHENTICATION_KEY,
                        ..
                    } if id == authentication_key_id
                )
            })
            .map(|(_, object)| object)
            .collect::<Vec<_>>();
        if authentication_keys.len() > 1 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        if authentication_keys.first().is_some_and(|object| {
            !matches!(
                object.material,
                KeyMaterial::YubiHsm {
                    algorithm: YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
                    ..
                }
            )
        }) {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }

        let matching_id = authentication_key_id.to_be_bytes();
        let public_candidates = objects
            .iter()
            .filter(|(_, object)| {
                object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                    && object.token
                    && object.id == matching_id
            })
            .map(|(_, object)| object)
            .collect::<Vec<_>>();
        let matching_projection = public_candidates.iter().find(|object| {
            matches!(
                &object.material,
                KeyMaterial::Public(PublicKeyMaterial::Ec { parameters, public_key })
                    if parameters.as_slice() == [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                        && public_key.as_slice() == raw_public_key
            )
        });
        if !public_candidates.is_empty()
            && (public_candidates.len() != 1 || matching_projection.is_none())
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        if !authentication_keys.is_empty() && matching_projection.is_none() {
            // The Authentication Key public half cannot be read portably. Do
            // not delete an object unless its persisted projection binds it to
            // the requested platform credential.
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }

        if let Some(authentication_key) = authentication_keys.first() {
            ctx.get_slot(slot_id)?
                .yubihsm_destroy_native_object(slot_id, &authentication_key.unique_id)?;
            ctx.refresh_slot_token_objects(slot_id)?;
        }

        let projection = ctx
            .resolved_objects()?
            .into_iter()
            .find(|(_, object)| {
                object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                    && object.token
                    && object.id == matching_id
                    && matches!(
                        &object.material,
                        KeyMaterial::Public(PublicKeyMaterial::Ec { parameters, public_key })
                            if parameters.as_slice() == [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                                && public_key.as_slice() == raw_public_key
                    )
            });
        if let Some((handle, projection)) = projection
            && !ctx.destroy_backed_object(handle, &projection)?
        {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        Ok(())
    })
}

fn rollback_projection(
    ctx: &mut SlotContext,
    created_projection: Option<CK_OBJECT_HANDLE>,
) -> Result<(), Error> {
    let Some(handle) = created_projection else {
        return Ok(());
    };
    let object = ctx.resolve_object(handle)?.ok_or(CKR_DEVICE_ERROR)?;
    if !ctx.destroy_backed_object(handle, &object)? {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(())
}

fn platform_projection_object(
    slot_id: CK_SLOT_ID,
    authentication_key_id: u16,
    label: &str,
    raw_public_key: &[u8],
) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: String::new(),
        class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: label.to_owned(),
        id: authentication_key_id.to_be_bytes().to_vec(),
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        wrap: false,
        unwrap: false,
        encapsulate: false,
        decapsulate: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: true,
        key_gen_mechanism: None,
        allowed_mechanisms: None,
        wrap_with_trusted: false,
        policy_templates: crate::KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: KeyMaterial::Public(PublicKeyMaterial::Ec {
            parameters: vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            public_key: raw_public_key.to_vec(),
        }),
    }
}
