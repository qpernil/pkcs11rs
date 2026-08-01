use super::crypt::yubihsm_ec_coordinate_length;
use super::object::{
    piv_key_object_handles, publish_software_secret_object, required_template_value,
    validate_software_secret_length, validate_unique_template, yubihsm_hardware_import_object,
    yubihsm_id, yubihsm_object_parameters,
};
use crate::*;
use p256::elliptic_curve::Generate;
use zeroize::Zeroize;

ffi_entry_point! {
    pub fn C_GenerateKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        templ: *mut CK_ATTRIBUTE,
        count: ::std::os::raw::c_ulong,
        key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV {
        log!(
            2,
            "C_GenerateKey called with {:?}",
            (session_handle, mechanism, templ, count, key)
        );
        match generate_key(session_handle, mechanism, templ, count, key) {
            Ok(()) => CKR_OK as CK_RV,
            Err(e) => e.into(),
        }
    }
}

fn generate_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let key_handle = unsafe { as_mut(key) }?;
    let mechanism = unsafe { _as_ref(mechanism) }?;
    let templ = unsafe { from_raw_parts(templ, count as usize) }?;

    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_GENERATE as CK_FLAGS)?;
        if ctx.get_slot(slot_id)?.kind() == SlotKind::YubiHsm {
            let (object, command) = yubihsm_generate_key_command(mechanism, templ)?;
            validate_new_object_access(&object, flags, logged_in)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            let id = parse_yubihsm_object_id(&response)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            let (handle, imported) = ctx
                .resolved_objects()?
                .into_iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                        && matches!(&object.material, KeyMaterial::YubiHsm { id: object_id, .. } if *object_id == id)
                })
                .ok_or(CKR_DEVICE_ERROR)?;
            let metadata_result = ctx.get_slot(slot_id)?.yubihsm_set_attributes(
                slot_id,
                &imported.unique_id,
                (!object.id.is_empty()).then_some(object.id.as_slice()),
                (!object.label.is_empty()).then_some(object.label.as_str()),
            );
            let refresh = ctx.refresh_slot_token_objects(slot_id);
            if let Err(error) = metadata_result {
                let _ = refresh;
                return Err(error);
            }
            refresh?;
            *key_handle = handle;
            return Ok(());
        }
        let software_secret = ctx.get_slot(slot_id)?.supports_software_secret_operations();
        let mut key = generate_key_object(mechanism, templ, software_secret)?;
        validate_new_object_access(&key, flags, logged_in)?;
        if software_secret {
            *key_handle = publish_software_secret_object(ctx, session_handle, slot_id, key)?;
            return Ok(());
        }
        key.set_creator(session_handle, slot_id);
        let handle = ctx.insert_object(key)?;
        *key_handle = handle;
        Ok(())
    })
}

fn yubihsm_generate_key_command(
    mechanism: &CK_MECHANISM,
    templ: &[CK_ATTRIBUTE],
) -> Result<(TokenObject, YubiHsmCommand), Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if !matches!(
        mechanism.mechanism,
        x if x == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE
            || x == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE
    ) {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    validate_unique_template(templ)?;
    let default_key_type = if mechanism.mechanism == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE {
        CKK_AES as CK_KEY_TYPE
    } else {
        CKK_GENERIC_SECRET as CK_KEY_TYPE
    };
    let mut key_template = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        key_type: Some(default_key_type),
        token: true,
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        ..TokenObjectTemplate::default()
    };
    let mut value_len = None;
    for attribute in templ {
        if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
            value_len = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
        } else {
            key_template
                .apply_attribute(attribute)
                .map_err(Error::from)?;
        }
    }
    let mut object = key_template.into_object().map_err(Error::from)?;
    if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let supplied_value_len = value_len.map(|length| length as usize);
    let (code, algorithm, expected_len) =
        if mechanism.mechanism == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE {
            let value_len = supplied_value_len.ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            let algorithm = match value_len {
                16 => YUBIHSM_ALGO_AES128,
                24 => YUBIHSM_ALGO_AES192,
                32 => YUBIHSM_ALGO_AES256,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            (
                YubiHsmCommandCode::GenerateSymmetricKey,
                algorithm,
                value_len,
            )
        } else {
            let (algorithm, expected_len) = match object.key_type {
                x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA1, 20),
                x if x == CKK_SHA384_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA384, 48),
                x if x == CKK_SHA512_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA512, 64),
                x if x == CKK_SHA256_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA256, 32),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            };
            (YubiHsmCommandCode::GenerateHmacKey, algorithm, expected_len)
        };
    if supplied_value_len.is_some_and(|value_len| value_len != expected_len) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let hardware = yubihsm_hardware_import_object(&object)?;
    let object_type = if code == YubiHsmCommandCode::GenerateSymmetricKey {
        YUBIHSM_SYMMETRIC_KEY
    } else {
        YUBIHSM_HMAC_KEY
    };
    let command = YubiHsmCommand::generate_object(
        code,
        &yubihsm_object_parameters(&hardware, object_type, algorithm)?,
    )?;
    object.local = true;
    Ok((object, command))
}

fn generate_key_object(
    mechanism: &CK_MECHANISM,
    templ: &[CK_ATTRIBUTE],
    software_secret: bool,
) -> Result<TokenObject, Error> {
    let aes_generation =
        software_secret && mechanism.mechanism == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE;
    if mechanism.mechanism != CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE && !aes_generation {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    validate_unique_template(templ)?;

    let mut key_template = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        key_type: Some(if aes_generation {
            CKK_AES as CK_KEY_TYPE
        } else {
            CKK_GENERIC_SECRET as CK_KEY_TYPE
        }),
        sensitive: Some(true),
        extractable: Some(false),
        ..TokenObjectTemplate::default()
    };
    let mut value_len = None;
    for attribute in templ {
        if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
            if value_len.is_some() {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            value_len = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
            continue;
        }
        key_template
            .apply_attribute(attribute)
            .map_err(Error::from)?;
    }
    let mut key = if software_secret {
        key_template.into_software_secret_object()
    } else {
        key_template.into_object()
    }
    .map_err(Error::from)?;
    if key.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
        || (!software_secret && key.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE)
        || (aes_generation && key.key_type != CKK_AES as CK_KEY_TYPE)
        || (software_secret
            && !aes_generation
            && key.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
            && !is_hmac_key_type(key.key_type))
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let value_len = value_len.ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if software_secret {
        validate_software_secret_length(key.key_type, value_len as usize)?;
    } else {
        let key_size_bits = value_len
            .checked_mul(8)
            .ok_or(CKR_KEY_SIZE_RANGE as CK_RV)?;
        let details = mechanism_details(&MECHANISMS, mechanism.mechanism)?;
        if key_size_bits < details.min_key_size || key_size_bits > details.max_key_size {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
    }
    let mut value = vec![0; value_len as usize];
    getrandom::fill(&mut value).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
    key.material = if software_secret {
        KeyMaterial::SoftwareSecret(Zeroizing::new(value))
    } else {
        KeyMaterial::Secret(Zeroizing::new(value))
    };
    key.local = true;
    key.key_gen_mechanism = Some(mechanism.mechanism);
    Ok(key)
}

ffi_entry_point! {
    pub fn C_GenerateKeyPair(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        public_key_template: *mut CK_ATTRIBUTE,
        public_key_attribute_count: ::std::os::raw::c_ulong,
        private_key_template: *mut CK_ATTRIBUTE,
        private_key_attribute_count: ::std::os::raw::c_ulong,
        public_key: *mut CK_OBJECT_HANDLE,
        private_key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV {
        map(generate_key_pair(
            session_handle,
            mechanism,
            public_key_template,
            public_key_attribute_count,
            private_key_template,
            private_key_attribute_count,
            public_key,
            private_key,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_key_pair(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    public_template: CK_ATTRIBUTE_PTR,
    public_count: CK_ULONG,
    private_template: CK_ATTRIBUTE_PTR,
    private_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    with_session_context(session_handle, |ctx| {
        ctx._get_session(session_handle).map(|_| ())
    })?;
    let mechanism = unsafe { _as_ref(mechanism) }?;
    let public_template = unsafe { from_raw_parts(public_template, public_count as usize) }?;
    let private_template = unsafe { from_raw_parts(private_template, private_count as usize) }?;
    let public_handle = unsafe { as_mut(public_key) }?;
    let private_handle = unsafe { as_mut(private_key) }?;
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        require_slot_mechanism(
            ctx,
            slot_id,
            mechanism.mechanism,
            CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        )?;
        let private_token =
            optional_bool_template_attribute(private_template, CKA_TOKEN as CK_ATTRIBUTE_TYPE)?
                .unwrap_or(false);
        if ctx
            .get_slot(slot_id)?
            .supports_software_private_operations()
            && matches!(
                mechanism.mechanism,
                x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE
            )
        {
            let (public_object, mut private_object) =
                software_generate_key_pair(mechanism, public_template, private_template)?;
            validate_new_object_access(&public_object, flags, logged_in)?;
            validate_new_object_access(&private_object, flags, logged_in)?;
            if private_token {
                let stored_private = ctx
                    ._get_slot_mut(slot_id)?
                    .store_software_private_object(slot_id, &private_object)?;
                let private_unique_id = stored_private.unique_id.clone();
                if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
                    let _ = ctx
                        ._get_slot_mut(slot_id)?
                        .destroy_software_private_object(&private_unique_id);
                    return Err(error);
                }
                let private =
                    match ctx
                        .resolved_objects()?
                        .into_iter()
                        .find_map(|(handle, object)| {
                            (object.unique_id == private_unique_id).then_some(handle)
                        }) {
                        Some(handle) => handle,
                        None => {
                            let _ = ctx
                                ._get_slot_mut(slot_id)?
                                .destroy_software_private_object(&private_unique_id);
                            let _ = ctx.refresh_slot_token_objects(slot_id);
                            return Err(CKR_DEVICE_ERROR.into());
                        }
                    };
                let public = match ctx.store_backed_object(session_handle, public_object) {
                    Ok(public) => public,
                    Err(error) => {
                        let _ = ctx
                            ._get_slot_mut(slot_id)?
                            .destroy_software_private_object(&private_unique_id);
                        let _ = ctx.refresh_slot_token_objects(slot_id);
                        return Err(error);
                    }
                };
                *public_handle = public;
                *private_handle = private;
                return Ok(());
            }
            private_object.set_creator(session_handle, slot_id);
            let private = ctx.insert_object(private_object)?;
            let public = match ctx.store_backed_object(session_handle, public_object) {
                Ok(public) => public,
                Err(error) => {
                    ctx.remove_object_handle(private);
                    return Err(error);
                }
            };
            *public_handle = public;
            *private_handle = private;
            return Ok(());
        }
        if ctx.get_slot(slot_id)?.kind() == SlotKind::Fido2 {
            if mechanism.mechanism != CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN
                || !mechanism.pParameter.is_null()
                || mechanism.ulParameterLen != 0
            {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let mut public_object = key_pair_object(
                public_template,
                CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                CKK_EC as CK_KEY_TYPE,
            )?;
            let mut private_object = key_pair_object(
                private_template,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                CKK_EC as CK_KEY_TYPE,
            )?;
            if !public_object.token || !private_object.token {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            public_object.verify = false;
            private_object.sign = false;
            private_object.derive = false;
            validate_new_object_access(&public_object, flags, logged_in)?;
            validate_new_object_access(&private_object, flags, logged_in)?;
            let registration = ctx
                ._get_slot_mut(slot_id)?
                .fido_preview_sign_registration()?;
            let projected = project_cose_public_key(registration.credential_public_key_cose())
                .filter(|projected| projected.key_type == CKK_EC as CK_KEY_TYPE)
                .ok_or(CKR_DEVICE_ERROR)?;
            public_object.material = KeyMaterial::Public(projected.public_key.clone());
            private_object.public_key = Some(projected.public_key);
            private_object.material = KeyMaterial::FidoPreviewCredential { registration };
            public_object.local = true;
            private_object.local = true;
            public_object.key_gen_mechanism = Some(mechanism.mechanism);
            private_object.key_gen_mechanism = Some(mechanism.mechanism);
            public_object.set_creator(session_handle, slot_id);
            private_object.set_creator(session_handle, slot_id);
            *public_handle = ctx.insert_object(public_object)?;
            *private_handle = ctx.insert_object(private_object)?;
            return Ok(());
        }
        if ctx.get_slot(slot_id)?.kind() == SlotKind::Ccid(CcidApplication::Piv) {
            let generation =
                piv_generate_key_pair_parameters(mechanism, public_template, private_template)?;
            validate_new_object_access(&generation.public_object, flags, logged_in)?;
            validate_new_object_access(&generation.private_object, flags, logged_in)?;
            let replaced = piv_key_object_handles(ctx, slot_id, generation.slot)?;
            ctx._get_slot_mut(slot_id)?.piv_generate_key_pair(
                generation.slot,
                generation.algorithm,
                generation.pin_policy,
                generation.touch_policy,
            )?;
            for (handle, _, _) in replaced {
                ctx.remove_object_handle(handle);
            }
            ctx.refresh_slot_token_objects(slot_id)?;
            *private_handle = find_piv_key_handle(
                ctx,
                slot_id,
                generation.slot,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            )?;
            *public_handle = find_piv_key_handle(
                ctx,
                slot_id,
                generation.slot,
                CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            )?;
            return Ok(());
        }
        if ctx.get_slot(slot_id)?.kind() == SlotKind::Ccid(CcidApplication::OpenPgp) {
            let generation =
                openpgp_generate_key_pair_parameters(mechanism, public_template, private_template)?;
            validate_new_object_access(&generation.public_object, flags, logged_in)?;
            validate_new_object_access(&generation.private_object, flags, logged_in)?;
            ctx._get_slot_mut(slot_id)?
                .openpgp_generate_key_pair(generation.key_ref, generation.algorithm)?;
            if generation.touch_policy != 0 {
                ctx._get_slot_mut(slot_id)?
                    .openpgp_set_touch_policy(generation.key_ref, generation.touch_policy)?;
            }
            ctx.refresh_slot_token_objects(slot_id)?;
            *private_handle = find_openpgp_key_handle(
                ctx,
                slot_id,
                generation.key_ref,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            )?;
            *public_handle = find_openpgp_key_handle(
                ctx,
                slot_id,
                generation.key_ref,
                CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            )?;
            return Ok(());
        }
        if ctx.get_slot(slot_id)?.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        let (private_object, public_object, command) =
            yubihsm_generate_key_pair_command(mechanism, public_template, private_template)?;
        let wrap_key = command.code() == YubiHsmCommandCode::GenerateWrapKey;
        let private_object_type = if wrap_key {
            YUBIHSM_WRAP_KEY
        } else {
            YUBIHSM_ASYMMETRIC_KEY
        };
        validate_new_object_access(&private_object, flags, logged_in)?;
        validate_new_object_access(&public_object, flags, logged_in)?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        let id = parse_yubihsm_object_id(&response)?;
        ctx.refresh_slot_token_objects(slot_id)?;
        let (private, imported_private) = ctx
            .resolved_objects()?
            .into_iter()
            .find(|(_, object)| {
                object.slot_id == Some(slot_id)
                    && object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                    && matches!(
                        &object.material,
                        KeyMaterial::YubiHsm {
                            id: object_id,
                            object_type,
                            ..
                        } if *object_id == id && *object_type == private_object_type
                    )
            })
            .ok_or(CKR_DEVICE_ERROR)?;
        let private_result = ctx.get_slot(slot_id)?.yubihsm_set_attributes(
            slot_id,
            &imported_private.unique_id,
            (!private_object.id.is_empty()).then_some(private_object.id.as_slice()),
            (!private_object.label.is_empty()).then_some(private_object.label.as_str()),
        );
        let refresh = ctx.refresh_slot_token_objects(slot_id);
        if let Err(error) = private_result {
            let _ = refresh;
            return Err(error);
        }
        refresh?;
        let imported_private = ctx.resolve_object(private)?.ok_or(CKR_DEVICE_ERROR)?;
        let mut projected = project_public_key_object(&imported_private, public_template)?;
        projected.local = true;
        projected.key_gen_mechanism = Some(mechanism.mechanism);
        let public = if projected.token {
            ctx.get_slot(slot_id)?.yubihsm_persist_public_projection(
                slot_id,
                &imported_private.unique_id,
                &projected,
            )?;
            ctx.refresh_slot_token_objects(slot_id)?;
            ctx.resolved_objects()?
                .into_iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                        && matches!(
                            object.material,
                            KeyMaterial::YubiHsm {
                                id: object_id,
                                object_type: YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC,
                                ..
                            } if object_id == id
                        )
                })
                .map(|(handle, _)| handle)
                .ok_or(CKR_DEVICE_ERROR)?
        } else {
            ctx.store_backed_object(session_handle, projected)?
        };
        *private_handle = private;
        *public_handle = public;
        Ok(())
    })
}

pub(crate) struct OpenPgpGeneration {
    pub(crate) key_ref: OpenPgpKeyRef,
    pub(crate) algorithm: OpenPgpAlgorithm,
    public_object: TokenObject,
    private_object: TokenObject,
    pub(crate) touch_policy: u8,
}

pub(super) fn openpgp_key_ref(id: &[u8]) -> Result<OpenPgpKeyRef, Error> {
    match id {
        [1] => Ok(OpenPgpKeyRef::Signature),
        [2] => Ok(OpenPgpKeyRef::Decipher),
        [3] => Ok(OpenPgpKeyRef::Authentication),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

pub(crate) fn openpgp_generate_key_pair_parameters(
    mechanism: &CK_MECHANISM,
    public_template: &[CK_ATTRIBUTE],
    private_template: &[CK_ATTRIBUTE],
) -> Result<OpenPgpGeneration, Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let key_type = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => CKK_RSA as CK_KEY_TYPE,
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => CKK_EC as CK_KEY_TYPE,
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => CKK_EC_EDWARDS as CK_KEY_TYPE,
        x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            CKK_EC_MONTGOMERY as CK_KEY_TYPE
        }
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    };
    let public_object =
        key_pair_object(public_template, CKO_PUBLIC_KEY as CK_OBJECT_CLASS, key_type)?;
    let filtered_private_template = private_template
        .iter()
        .filter(|attribute| attribute.type_ != CKA_YUBICO_TOUCH_POLICY)
        .copied()
        .collect::<Vec<_>>();
    let private_object = key_pair_object(
        &filtered_private_template,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    if !public_object.token || !private_object.token || public_object.id != private_object.id {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let key_ref = openpgp_key_ref(&private_object.id)?;
    let algorithm = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let bits_attribute =
                template_attribute(public_template, CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE)
                    .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            let bits = read_ulong_template_attribute(bits_attribute).map_err(Error::from)?;
            if let Some(exponent) =
                template_attribute(public_template, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)
            {
                if read_attribute_value(exponent).map_err(Error::from)? != [1, 0, 1] {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            match bits {
                2048 | 3072 | 4096 => OpenPgpAlgorithm::Rsa {
                    bits: bits as usize,
                },
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            }
        }
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let params =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            let curve = openpgp_curve(&params)?;
            if key_ref == OpenPgpKeyRef::Decipher {
                OpenPgpAlgorithm::Ecdh(curve)
            } else {
                OpenPgpAlgorithm::Ecdsa(curve)
            }
        }
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let params =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            if params.as_slice() != openpgp::Curve::Ed25519.oid()
                || key_ref == OpenPgpKeyRef::Decipher
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            OpenPgpAlgorithm::Ed25519
        }
        _ => {
            let params =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            if params.as_slice() != openpgp::Curve::X25519.oid()
                || key_ref != OpenPgpKeyRef::Decipher
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            OpenPgpAlgorithm::Ecdh(openpgp::Curve::X25519)
        }
    };
    let touch_policy = match template_attribute(private_template, CKA_YUBICO_TOUCH_POLICY) {
        Some(attribute) => {
            let value = read_ulong_template_attribute(attribute).map_err(Error::from)?;
            match value {
                1..=5 => value as u8,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            }
        }
        None => 0,
    };
    Ok(OpenPgpGeneration {
        key_ref,
        algorithm,
        public_object,
        private_object,
        touch_policy,
    })
}

pub(super) fn openpgp_curve(parameters: &[u8]) -> Result<openpgp::Curve, Error> {
    [
        openpgp::Curve::P256,
        openpgp::Curve::P384,
        openpgp::Curve::P521,
        openpgp::Curve::BrainpoolP256,
        openpgp::Curve::BrainpoolP384,
        openpgp::Curve::BrainpoolP512,
        openpgp::Curve::Secp256k1,
    ]
    .into_iter()
    .find(|curve| curve.oid() == parameters)
    .ok_or_else(|| CKR_CURVE_NOT_SUPPORTED.into())
}

pub(super) fn find_openpgp_key_handle(
    ctx: &SlotContext,
    slot_id: CK_SLOT_ID,
    key_ref: OpenPgpKeyRef,
    class: CK_OBJECT_CLASS,
) -> Result<CK_OBJECT_HANDLE, Error> {
    ctx.resolved_objects()?
        .into_iter()
        .find(|(_, object)| {
            object.slot_id == Some(slot_id) && object.class == class && object.id == [key_ref as u8]
        })
        .map(|(handle, _)| handle)
        .ok_or_else(|| CKR_DEVICE_ERROR.into())
}

struct PivGeneration {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    pin_policy: u8,
    touch_policy: u8,
    public_object: TokenObject,
    private_object: TokenObject,
}

pub(super) fn piv_policy_attribute(
    templ: &[CK_ATTRIBUTE],
    attribute_type: CK_ATTRIBUTE_TYPE,
    maximum: CK_ULONG,
) -> Result<u8, Error> {
    let Some(attribute) = template_attribute(templ, attribute_type) else {
        return Ok(0);
    };
    let value = read_ulong_template_attribute(attribute).map_err(Error::from)?;
    if value > maximum {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    Ok(value as u8)
}

pub(super) fn piv_key_pair_object(
    templ: &[CK_ATTRIBUTE],
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
) -> Result<TokenObject, Error> {
    let filtered = templ
        .iter()
        .filter(|attribute| {
            !matches!(
                attribute.type_,
                CKA_YUBICO_TOUCH_POLICY | CKA_YUBICO_PIN_POLICY
            )
        })
        .copied()
        .collect::<Vec<_>>();
    key_pair_object(&filtered, class, key_type)
}

fn piv_generate_key_pair_parameters(
    mechanism: &CK_MECHANISM,
    public_template: &[CK_ATTRIBUTE],
    private_template: &[CK_ATTRIBUTE],
) -> Result<PivGeneration, Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    validate_unique_template(public_template)?;
    validate_unique_template(private_template)?;
    let (key_type, algorithm) = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let bits_attribute =
                template_attribute(public_template, CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE)
                    .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            let bits = read_ulong_template_attribute(bits_attribute).map_err(Error::from)?;
            if let Some(exponent) =
                template_attribute(public_template, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)
            {
                if read_attribute_value(exponent).map_err(Error::from)? != [1, 0, 1] {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            let algorithm = match bits {
                1024 => piv::Algorithm::Rsa1024,
                2048 => piv::Algorithm::Rsa2048,
                3072 => piv::Algorithm::Rsa3072,
                4096 => piv::Algorithm::Rsa4096,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            (CKK_RSA as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let params_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            let params = read_attribute_value(params_attribute).map_err(Error::from)?;
            let algorithm = match params.as_slice() {
                [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => {
                    piv::Algorithm::EccP256
                }
                [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => piv::Algorithm::EccP384,
                _ => return Err(CKR_CURVE_NOT_SUPPORTED.into()),
            };
            (CKK_EC as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => (
            CKK_EC_EDWARDS as CK_KEY_TYPE,
            piv_generation_25519_algorithm(public_template, piv::Algorithm::Ed25519)?,
        ),
        x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => (
            CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            piv_generation_25519_algorithm(public_template, piv::Algorithm::X25519)?,
        ),
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    };
    let public_object =
        piv_key_pair_object(public_template, CKO_PUBLIC_KEY as CK_OBJECT_CLASS, key_type)?;
    let private_object = piv_key_pair_object(
        private_template,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    if !public_object.token || !private_object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let id = if private_object.id.is_empty() {
        &public_object.id
    } else {
        &private_object.id
    };
    if id.len() != 1 || (!public_object.id.is_empty() && public_object.id != *id) {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let slot = piv::Slot::from_cka_id(id[0]).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
    if slot == piv::Slot::Attestation {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    let pin_policy = piv_policy_attribute(private_template, CKA_YUBICO_PIN_POLICY, 5)?;
    let touch_policy = piv_policy_attribute(private_template, CKA_YUBICO_TOUCH_POLICY, 3)?;
    Ok(PivGeneration {
        slot,
        algorithm,
        pin_policy,
        touch_policy,
        public_object,
        private_object,
    })
}

fn piv_generation_25519_algorithm(
    public_template: &[CK_ATTRIBUTE],
    algorithm: piv::Algorithm,
) -> Result<piv::Algorithm, Error> {
    let attribute = template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
        .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let parameters = read_attribute_value(attribute).map_err(Error::from)?;
    if piv_ec_parameters(algorithm) != Some(parameters.as_slice()) {
        return Err(CKR_CURVE_NOT_SUPPORTED.into());
    }
    Ok(algorithm)
}

pub(super) fn find_piv_key_handle(
    ctx: &SlotContext,
    slot_id: CK_SLOT_ID,
    piv_slot: piv::Slot,
    class: CK_OBJECT_CLASS,
) -> Result<CK_OBJECT_HANDLE, Error> {
    ctx.resolved_objects()?
        .into_iter()
        .find(|(_, object)| {
            object.slot_id == Some(slot_id)
                && object.class == class
                && object.id == [piv_slot.cka_id()]
        })
        .map(|(handle, _)| handle)
        .ok_or_else(|| CKR_DEVICE_ERROR.into())
}

pub(super) fn key_pair_object(
    templ: &[CK_ATTRIBUTE],
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let mut parsed = TokenObjectTemplate {
        class: Some(class),
        key_type: Some(key_type),
        token: true,
        private: class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        sensitive: (class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS).then_some(true),
        extractable: (class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS).then_some(false),
        ..TokenObjectTemplate::default()
    };
    for attribute in templ {
        if matches!(
            attribute.type_,
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
        ) {
            continue;
        }
        parsed.apply_attribute(attribute).map_err(Error::from)?;
    }
    let object = parsed.into_object().map_err(Error::from)?;
    if object.class != class || object.key_type != key_type {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    Ok(object)
}

fn software_key_pair_object(
    templ: &[CK_ATTRIBUTE],
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let private = class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut parsed = TokenObjectTemplate {
        class: Some(class),
        key_type: Some(key_type),
        token: false,
        private,
        sensitive: private.then_some(true),
        extractable: private.then_some(false),
        ..TokenObjectTemplate::default()
    };
    for attribute in templ {
        if matches!(
            attribute.type_,
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
        ) {
            continue;
        }
        parsed.apply_attribute(attribute).map_err(Error::from)?;
    }
    let object = parsed.into_object().map_err(Error::from)?;
    if object.class != class || object.key_type != key_type {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    Ok(object)
}

fn software_generate_key_pair(
    mechanism: &CK_MECHANISM,
    public_template: &[CK_ATTRIBUTE],
    private_template: &[CK_ATTRIBUTE],
) -> Result<(TokenObject, TokenObject), Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let (key_type, private_material) = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let bits = read_ulong_template_attribute(
                template_attribute(public_template, CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE)
                    .ok_or(CKR_TEMPLATE_INCOMPLETE)?,
            )
            .map_err(Error::from)?;
            if !(1024..=4096).contains(&bits) || bits % 256 != 0 {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            if let Some(exponent) =
                template_attribute(public_template, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)
            {
                if read_attribute_value(exponent).map_err(Error::from)? != [0x01, 0x00, 0x01] {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            let mut key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits as usize)
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
            key.precompute()
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
            (
                CKK_RSA as CK_KEY_TYPE,
                SoftwarePrivateKeyMaterial::Rsa(Box::new(key)),
            )
        }
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            let curve = ec_curve_from_parameters(&parameters)
                .map_err(|_| Error::from(CKR_CURVE_NOT_SUPPORTED))?;
            let material = match curve {
                EcCurve::P224 => SoftwarePrivateKeyMaterial::P224(p224::SecretKey::generate()),
                EcCurve::P256 => SoftwarePrivateKeyMaterial::P256(p256::SecretKey::generate()),
                EcCurve::P384 => SoftwarePrivateKeyMaterial::P384(p384::SecretKey::generate()),
                EcCurve::P521 => SoftwarePrivateKeyMaterial::P521(p521::SecretKey::generate()),
                EcCurve::K256 => SoftwarePrivateKeyMaterial::K256(k256::SecretKey::generate()),
                EcCurve::BrainpoolP256 => {
                    SoftwarePrivateKeyMaterial::BrainpoolP256(bp256::r1::SecretKey::generate())
                }
                EcCurve::BrainpoolP384 => {
                    SoftwarePrivateKeyMaterial::BrainpoolP384(bp384::r1::SecretKey::generate())
                }
                EcCurve::BrainpoolP512 => SoftwarePrivateKeyMaterial::BrainpoolP512(
                    crate::brainpool512::SecretKey::generate(),
                ),
            };
            (CKK_EC as CK_KEY_TYPE, material)
        }
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            if parameters.as_slice()
                != piv_ec_parameters(piv::Algorithm::Ed25519).ok_or(CKR_CURVE_NOT_SUPPORTED)?
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
            (
                CKK_EC_EDWARDS as CK_KEY_TYPE,
                SoftwarePrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
            )
        }
        x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters =
                required_template_value(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            if parameters.as_slice()
                != piv_ec_parameters(piv::Algorithm::X25519).ok_or(CKR_CURVE_NOT_SUPPORTED)?
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            let mut scalar = Zeroizing::new([0u8; 32]);
            getrandom::fill(scalar.as_mut()).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
            (
                CKK_EC_MONTGOMERY as CK_KEY_TYPE,
                SoftwarePrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from(*scalar)),
            )
        }
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    };
    let public_material = private_material.public_key()?;
    let mut public_object =
        software_key_pair_object(public_template, CKO_PUBLIC_KEY as CK_OBJECT_CLASS, key_type)?;
    let mut private_object = software_key_pair_object(
        private_template,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    public_object.material = KeyMaterial::Public(public_material);
    private_object.material = KeyMaterial::SoftwarePrivate(private_material);
    public_object.local = true;
    private_object.local = true;
    public_object.key_gen_mechanism = Some(mechanism.mechanism);
    private_object.key_gen_mechanism = Some(mechanism.mechanism);
    Ok((public_object, private_object))
}

pub(super) fn template_attribute(
    templ: &[CK_ATTRIBUTE],
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Option<&CK_ATTRIBUTE> {
    templ
        .iter()
        .find(|attribute| attribute.type_ == attribute_type)
}

fn optional_bool_template_attribute(
    templ: &[CK_ATTRIBUTE],
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<bool>, Error> {
    template_attribute(templ, attribute_type)
        .map(|attribute| read_bool_template_attribute(attribute).map_err(Error::from))
        .transpose()
}

pub(crate) fn yubihsm_ec_algorithm(parameters: &[u8]) -> Result<u8, Error> {
    match parameters {
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21] => Ok(YUBIHSM_ALGO_EC_P224),
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Ok(YUBIHSM_ALGO_EC_P256),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => Ok(YUBIHSM_ALGO_EC_P384),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] => Ok(YUBIHSM_ALGO_EC_P521),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a] => Ok(YUBIHSM_ALGO_EC_K256),
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => {
            Ok(YUBIHSM_ALGO_EC_BP256)
        }
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b] => {
            Ok(YUBIHSM_ALGO_EC_BP384)
        }
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d] => {
            Ok(YUBIHSM_ALGO_EC_BP512)
        }
        [0x06, 0x03, 0x2b, 0x65, 0x70] => Ok(YUBIHSM_ALGO_ED25519),
        [0x13, 0x07, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39] => Ok(YUBIHSM_ALGO_ED25519),
        [0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39] => {
            Ok(YUBIHSM_ALGO_X25519)
        }
        [0x06, 0x03, 0x2b, 0x65, 0x6e] => Ok(YUBIHSM_ALGO_X25519),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

pub(crate) fn yubihsm_generate_key_pair_command(
    mechanism: &CK_MECHANISM,
    public_template: &[CK_ATTRIBUTE],
    private_template: &[CK_ATTRIBUTE],
) -> Result<(TokenObject, TokenObject, YubiHsmCommand), Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let (key_type, algorithm) = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let bits_attribute =
                template_attribute(public_template, CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let bits = read_ulong_template_attribute(bits_attribute).map_err(Error::from)?;
            if let Some(exponent) =
                template_attribute(public_template, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)
            {
                if read_attribute_value(exponent).map_err(Error::from)? != [0x01, 0x00, 0x01] {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            let algorithm = match bits {
                2048 => YUBIHSM_ALGO_RSA_2048,
                3072 => YUBIHSM_ALGO_RSA_3072,
                4096 => YUBIHSM_ALGO_RSA_4096,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            (CKK_RSA as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if is_yubihsm_x25519(algorithm) || algorithm == YUBIHSM_ALGO_ED25519 {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if !is_yubihsm_x25519(algorithm) {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC_MONTGOMERY as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if algorithm != YUBIHSM_ALGO_ED25519 {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC_EDWARDS as CK_KEY_TYPE, algorithm)
        }
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    };
    validate_unique_template(public_template)?;
    validate_unique_template(private_template)?;
    let public_wrap =
        optional_bool_template_attribute(public_template, CKA_WRAP as CK_ATTRIBUTE_TYPE)?
            .unwrap_or(false);
    let public_unwrap =
        optional_bool_template_attribute(public_template, CKA_UNWRAP as CK_ATTRIBUTE_TYPE)?
            .unwrap_or(false);
    let private_wrap =
        optional_bool_template_attribute(private_template, CKA_WRAP as CK_ATTRIBUTE_TYPE)?
            .unwrap_or(false);
    let private_unwrap =
        optional_bool_template_attribute(private_template, CKA_UNWRAP as CK_ATTRIBUTE_TYPE)?
            .unwrap_or(false);
    let private_extractable =
        optional_bool_template_attribute(private_template, CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)?
            .unwrap_or(false);
    let public_filtered = public_template
        .iter()
        .copied()
        .filter(|attribute| {
            attribute.type_ != CKA_WRAP as CK_ATTRIBUTE_TYPE
                && attribute.type_ != CKA_UNWRAP as CK_ATTRIBUTE_TYPE
        })
        .collect::<Vec<_>>();
    let private_filtered = private_template
        .iter()
        .copied()
        .filter(|attribute| {
            attribute.type_ != CKA_WRAP as CK_ATTRIBUTE_TYPE
                && attribute.type_ != CKA_UNWRAP as CK_ATTRIBUTE_TYPE
                && attribute.type_ != CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE
        })
        .collect::<Vec<_>>();
    let mut public_object = key_pair_object(
        &public_filtered,
        CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    if template_attribute(public_template, CKA_TOKEN as CK_ATTRIBUTE_TYPE).is_none() {
        public_object.token = false;
    }
    let mut private_object = key_pair_object(
        &private_filtered,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    private_object.extractable = private_extractable;
    private_object.never_extractable = !private_extractable;
    if !private_object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if public_object.token && public_object.id != private_object.id {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if is_montgomery_key_type(key_type)
        && (public_object.encrypt
            || public_object.decrypt
            || public_object.sign
            || public_object.verify
            || public_object.derive
            || private_object.encrypt
            || private_object.decrypt
            || private_object.sign
            || private_object.verify)
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if private_object.label.is_empty() {
        private_object.label = public_object.label.clone();
    }
    let hardware = yubihsm_hardware_import_object(&private_object)?;
    let wrap_key = private_unwrap;
    if public_unwrap
        || public_wrap
        || private_wrap
        || (wrap_key && key_type != CKK_RSA as CK_KEY_TYPE)
        || (wrap_key
            && (public_object.encrypt
                || public_object.decrypt
                || public_object.sign
                || public_object.verify
                || public_object.derive
                || private_object.encrypt
                || private_object.decrypt
                || private_object.sign
                || private_object.verify
                || private_object.derive))
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let command = if wrap_key {
        let attributes = YubiHsmPkcs11Attributes {
            wrap: false,
            unwrap: true,
            extractable: private_extractable,
            ..YubiHsmPkcs11Attributes::default()
        };
        let parameters = YubiHsmDelegatedObjectParameters {
            object: YubiHsmObjectParameters {
                id: yubihsm_id(&hardware.id)?,
                label: &hardware.label,
                domains: 0xffff,
                capabilities: yubihsm_attributes_to_capabilities(
                    YUBIHSM_WRAP_KEY,
                    algorithm,
                    attributes,
                ),
                algorithm,
            },
            delegated_capabilities: [0xff; 8],
        };
        YubiHsmCommand::generate_wrap_key(&parameters)?
    } else {
        YubiHsmCommand::generate_object(
            YubiHsmCommandCode::GenerateAsymmetricKey,
            &yubihsm_object_parameters(&hardware, YUBIHSM_ASYMMETRIC_KEY, algorithm)?,
        )?
    };
    Ok((private_object, public_object, command))
}

ffi_entry_point! {
    pub fn C_DeriveKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        base_key: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        attribute_count: ::std::os::raw::c_ulong,
        key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV {
        map(derive_key(
            session_handle,
            mechanism,
            base_key,
            templ,
            attribute_count,
            key,
        ))
    }
}

fn project_public_key_object(
    base: &TokenObject,
    templ: &[CK_ATTRIBUTE],
) -> Result<TokenObject, Error> {
    let material = KeyMaterial::Public(base.projected_public_key()?);
    let mut parsed = TokenObjectTemplate {
        class: Some(CKO_PUBLIC_KEY as CK_OBJECT_CLASS),
        key_type: Some(base.key_type),
        token: false,
        private: false,
        ..TokenObjectTemplate::default()
    };
    for attribute in templ {
        if !matches!(
            attribute.type_,
            x if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
                || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
                || x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
                || x == CKA_WRAP as CK_ATTRIBUTE_TYPE
                || x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE
        ) {
            parsed.apply_attribute(attribute).map_err(Error::from)?;
        }
    }
    let mut projected = parsed.into_object().map_err(Error::from)?;
    if projected.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
        || projected.key_type != base.key_type
        || projected.sensitive
        || !projected.extractable
        || projected.sign
        || projected.decrypt
        || projected.derive
        || projected.encrypt && projected.key_type != CKK_RSA as CK_KEY_TYPE
        || projected.verify
            && !matches!(
                projected.key_type,
                x if x == CKK_RSA as CK_KEY_TYPE
                    || x == CKK_EC as CK_KEY_TYPE
                    || x == CKK_EC_EDWARDS as CK_KEY_TYPE
            )
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    projected.material = material;
    projected.rp_id = base.rp_id.clone();
    projected.local = false;
    projected.key_gen_mechanism = None;
    for attribute in templ {
        if matches!(
            attribute.type_,
            x if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
                || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
                || x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
                || x == CKA_WRAP as CK_ATTRIBUTE_TYPE
                || x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE
        ) {
            let supplied = read_attribute_value(attribute).map_err(Error::from)?;
            if projected.attribute_value(attribute.type_).as_deref() != Some(supplied.as_slice()) {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
        }
    }
    Ok(projected)
}

fn software_ecdh(key: &SoftwarePrivateKeyMaterial, public_data: &[u8]) -> Result<Vec<u8>, Error> {
    macro_rules! derive {
        ($key:expr, $curve:ty) => {{
            let peer = elliptic_curve::PublicKey::<$curve>::from_sec1_bytes(public_data)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            Ok(
                elliptic_curve::ecdh::diffie_hellman($key.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .to_vec(),
            )
        }};
    }
    match key {
        SoftwarePrivateKeyMaterial::P224(key) => derive!(key, p224::NistP224),
        SoftwarePrivateKeyMaterial::P256(key) => derive!(key, p256::NistP256),
        SoftwarePrivateKeyMaterial::P384(key) => derive!(key, p384::NistP384),
        SoftwarePrivateKeyMaterial::P521(key) => derive!(key, p521::NistP521),
        SoftwarePrivateKeyMaterial::K256(key) => derive!(key, k256::Secp256k1),
        SoftwarePrivateKeyMaterial::BrainpoolP256(key) => {
            derive!(key, bp256::BrainpoolP256r1)
        }
        SoftwarePrivateKeyMaterial::BrainpoolP384(key) => {
            derive!(key, bp384::BrainpoolP384r1)
        }
        SoftwarePrivateKeyMaterial::BrainpoolP512(key) => {
            derive!(key, crate::brainpool512::BrainpoolP512r1)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn derive_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    base_key: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let key_handle = unsafe { as_mut(key) }?;
    let mechanism = unsafe { _as_ref(mechanism) }?;
    if mechanism.mechanism == CKM_HKDF_DERIVE as CK_MECHANISM_TYPE {
        return derive_hkdf_key(
            session_handle,
            mechanism,
            base_key,
            templ,
            attribute_count,
            key_handle,
        );
    }
    if mechanism.mechanism == CKM_PKCS11RS_PROJECT_PUBLIC_KEY {
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
        validate_unique_template(templ)?;
        return with_session_context_mut(session_handle, |ctx| {
            let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
            let base = ctx
                .resolve_object(base_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_KEY_HANDLE_INVALID)?;
            let mut merged = merge_policy_template(templ, base.policy_templates.derive.as_ref())?;
            let templ = merged.as_slice();
            require_key_mechanism(&base, mechanism.mechanism)?;
            if base.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            }
            if !base.allows_derive() {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let projected = project_public_key_object(&base, templ)?;
            validate_new_object_access(&projected, flags, logged_in)?;
            if projected.token
                && matches!(
                    &base.material,
                    KeyMaterial::YubiHsm {
                        object_type: YUBIHSM_ASYMMETRIC_KEY | YUBIHSM_WRAP_KEY,
                        ..
                    }
                )
            {
                let (base_id, public_object_type) = match &base.material {
                    KeyMaterial::YubiHsm {
                        id,
                        object_type: YUBIHSM_ASYMMETRIC_KEY,
                        ..
                    } => (*id, YUBIHSM_PUBLIC_KEY),
                    KeyMaterial::YubiHsm {
                        id,
                        object_type: YUBIHSM_WRAP_KEY,
                        ..
                    } => (*id, YUBIHSM_WRAP_KEY_PUBLIC),
                    _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
                };
                if ctx.get_slot(slot_id)?.kind() != SlotKind::YubiHsm {
                    return Err(CKR_TEMPLATE_INCONSISTENT.into());
                }
                ctx.get_slot(slot_id)?.yubihsm_persist_public_projection(
                    slot_id,
                    &base.unique_id,
                    &projected,
                )?;
                ctx.refresh_slot_token_objects(slot_id)?;
                *key_handle = ctx
                    .resolved_objects()?
                    .into_iter()
                    .find(|(_, object)| {
                        object.slot_id == Some(slot_id)
                            && object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                            && object.token
                            && matches!(
                                object.material,
                                KeyMaterial::YubiHsm {
                                    id,
                                    object_type,
                                    ..
                                } if id == base_id && object_type == public_object_type
                            )
                            && object.id == projected.id
                            && object.label == projected.label
                            && object.attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
                                == projected
                                    .attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
                    })
                    .map(|(handle, _)| handle)
                    .ok_or(CKR_DEVICE_ERROR)?;
            } else {
                *key_handle = ctx.store_backed_object(session_handle, projected)?;
            }
            Ok(())
        });
    }
    if mechanism.mechanism == CKM_PKCS11RS_PREVIEW_SIGN_DERIVE {
        let context = unsafe {
            from_raw_parts(
                mechanism.pParameter as *const u8,
                mechanism.ulParameterLen as usize,
            )
        }?
        .to_vec();
        let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
        validate_unique_template(templ)?;
        return with_session_context_mut(session_handle, |ctx| {
            let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
            let base = ctx
                .resolve_object(base_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_KEY_HANDLE_INVALID)?;
            let mut merged = merge_policy_template(templ, base.policy_templates.derive.as_ref())?;
            let templ = merged.as_slice();
            require_key_mechanism(&base, mechanism.mechanism)?;
            if !base.derive {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let registration = match base.material {
                KeyMaterial::PreviewSignRegistration { registration } => registration,
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            };
            let mut parsed = TokenObjectTemplate {
                class: Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS),
                key_type: Some(CKK_EC as CK_KEY_TYPE),
                token: false,
                private: true,
                sensitive: Some(true),
                extractable: Some(false),
                ..TokenObjectTemplate::default()
            };
            for attribute in templ {
                parsed.apply_attribute(attribute).map_err(Error::from)?;
            }
            let mut object = parsed.into_object().map_err(Error::from)?;
            if object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                || object.key_type != CKK_EC as CK_KEY_TYPE
            {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            object.sign = true;
            object.derive = false;
            validate_new_object_access(&object, flags, logged_in)?;
            let derived = registration
                .derive_arkg_p256(&context)
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
            let projected = project_cose_public_key(derived.verification_key_cose())
                .filter(|projected| projected.key_type == CKK_EC as CK_KEY_TYPE)
                .ok_or(CKR_DEVICE_ERROR)?;
            let registration_cbor = registration
                .to_cbor()
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
            let record = derived
                .into_record(
                    crate::storage::ContentReference::for_object(&registration_cbor),
                    (!object.label.is_empty()).then(|| object.label.clone()),
                )
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
            object.material = KeyMaterial::PreviewSignDerived {
                registration,
                derived: record,
            };
            object.public_key = Some(projected.public_key);
            object.local = true;
            object.key_gen_mechanism = Some(mechanism.mechanism);
            *key_handle = ctx.store_backed_object(session_handle, object)?;
            Ok(())
        });
    }
    if mechanism.mechanism != CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE
        && mechanism.mechanism != CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE
    {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_ECDH1_DERIVE_PARAMS_PTR) }?;
    let kdf = ecdh_kdf(parameters.kdf)?;
    let shared_data = unsafe {
        from_raw_parts(
            parameters.pSharedData as *const u8,
            parameters.ulSharedDataLen as usize,
        )
    }
    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if matches!(kdf, EcdhKdf::Null)
        && (!parameters.pSharedData.is_null() || !shared_data.is_empty())
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let public_data = unsafe {
        from_raw_parts(
            parameters.pPublicData as *const u8,
            parameters.ulPublicDataLen as usize,
        )
    }?;
    let public_data = der_octet_string_value(public_data).unwrap_or(public_data);
    let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
    validate_unique_template(templ)?;

    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
        let object = ctx
            .resolve_object(base_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        let mut merged = merge_policy_template(templ, object.policy_templates.derive.as_ref())?;
        let templ = merged.as_slice();
        require_key_mechanism(&object, mechanism.mechanism)?;
        if object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if !object.derive {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        #[derive(Clone)]
        enum DeriveSource {
            Software(Box<SoftwarePrivateKeyMaterial>),
            Piv {
                slot: piv::Slot,
                algorithm: piv::Algorithm,
                pin_policy: u8,
            },
            OpenPgp {
                key_ref: OpenPgpKeyRef,
                algorithm: OpenPgpAlgorithm,
                pin_policy: u8,
            },
            YubiHsm {
                id: u16,
                algorithm: u8,
            },
        }
        let source = match &object.material {
            KeyMaterial::SoftwarePrivate(key)
                if key.weierstrass_curve().is_some()
                    || matches!(key, SoftwarePrivateKeyMaterial::X25519(_)) =>
            {
                DeriveSource::Software(Box::new(key.clone()))
            }
            KeyMaterial::PivPrivate {
                slot,
                algorithm,
                pin_policy,
                ..
            } => DeriveSource::Piv {
                slot: *slot,
                algorithm: *algorithm,
                pin_policy: *pin_policy,
            },
            KeyMaterial::OpenPgpPrivate {
                key_ref,
                algorithm: algorithm @ OpenPgpAlgorithm::Ecdh(_),
                pin_policy,
                ..
            } => DeriveSource::OpenPgp {
                key_ref: *key_ref,
                algorithm: *algorithm,
                pin_policy: *pin_policy,
            },
            KeyMaterial::YubiHsm { id, algorithm, .. }
                if is_yubihsm_ec(*algorithm) || is_yubihsm_x25519(*algorithm) =>
            {
                DeriveSource::YubiHsm {
                    id: *id,
                    algorithm: *algorithm,
                }
            }
            _ => return Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
        };
        let source_is_x25519 = match &source {
            DeriveSource::Software(key) => {
                matches!(key.as_ref(), SoftwarePrivateKeyMaterial::X25519(_))
            }
            DeriveSource::Piv { algorithm, .. } => *algorithm == piv::Algorithm::X25519,
            DeriveSource::OpenPgp { algorithm, .. } => {
                *algorithm == OpenPgpAlgorithm::Ecdh(openpgp::Curve::X25519)
            }
            DeriveSource::YubiHsm { algorithm, .. } => is_yubihsm_x25519(*algorithm),
        };
        if mechanism.mechanism == CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE && source_is_x25519
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        match &source {
            DeriveSource::Piv {
                slot, pin_policy, ..
            } if piv_policy_requires_login(*slot, *pin_policy) && !logged_in => {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            DeriveSource::OpenPgp { .. } if !logged_in => {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            _ => {}
        }
        let (expected_length, expected_public_length, requires_uncompressed) = match &source {
            DeriveSource::Software(key) => match key.as_ref() {
                SoftwarePrivateKeyMaterial::X25519(_) => (32, 32, false),
                key => {
                    let coordinate_length =
                        ec_parameters(key.weierstrass_curve().ok_or(CKR_KEY_TYPE_INCONSISTENT)?)?
                            .coordinate_length;
                    (coordinate_length, coordinate_length * 2 + 1, true)
                }
            },
            DeriveSource::Piv { algorithm, .. } => match *algorithm {
                piv::Algorithm::EccP256 => (32, 65, true),
                piv::Algorithm::EccP384 => (48, 97, true),
                piv::Algorithm::X25519 => (32, 32, false),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            DeriveSource::OpenPgp { algorithm, .. } => match *algorithm {
                OpenPgpAlgorithm::Ecdh(curve) => {
                    let coordinate_length = curve.coordinate_length();
                    (
                        coordinate_length.unwrap_or(32),
                        coordinate_length.map(|length| length * 2 + 1).unwrap_or(32),
                        coordinate_length.is_some(),
                    )
                }
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            DeriveSource::YubiHsm { algorithm, .. } if is_yubihsm_x25519(*algorithm) => {
                (32, 32, false)
            }
            DeriveSource::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm) => {
                let coordinate_length = yubihsm_ec_coordinate_length(*algorithm)?;
                (coordinate_length, coordinate_length * 2 + 1, true)
            }
            DeriveSource::YubiHsm { .. } => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if public_data.len() != expected_public_length
            || (requires_uncompressed && public_data.first() != Some(&0x04))
        {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let software_secret = ctx.get_slot(slot_id)?.supports_software_secret_operations();
        let maximum_length = if matches!(kdf, EcdhKdf::Null) {
            expected_length
        } else {
            1024
        };
        let (mut derived_object, requested_length) =
            derived_secret_object(templ, expected_length, maximum_length, software_secret)?;
        validate_new_object_access(&derived_object, flags, logged_in)?;

        let mut derived =
            Zeroizing::new(match source {
                DeriveSource::Software(key) => match key.as_ref() {
                    SoftwarePrivateKeyMaterial::X25519(key) => {
                        let peer: [u8; 32] = public_data
                            .try_into()
                            .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
                        key.diffie_hellman(&x25519_dalek::PublicKey::from(peer))
                            .as_bytes()
                            .to_vec()
                    }
                    key => software_ecdh(key, public_data)?,
                },
                DeriveSource::Piv {
                    slot,
                    algorithm,
                    pin_policy,
                } => ctx._get_session(session_handle)?.1.piv_decipher(
                    slot,
                    algorithm,
                    public_data,
                    pin_policy,
                )?,
                DeriveSource::OpenPgp {
                    key_ref,
                    algorithm,
                    pin_policy,
                } => ctx._get_session(session_handle)?.1.openpgp_derive(
                    key_ref,
                    algorithm,
                    public_data,
                    pin_policy,
                )?,
                DeriveSource::YubiHsm { id, .. } => {
                    ctx._get_session(session_handle)?.1.yubihsm_command(
                        &YubiHsmCommand::key_data(YubiHsmCommandCode::DeriveEcdh, id, public_data)?,
                    )?
                }
            });
        if derived.len() != expected_length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        match kdf {
            EcdhKdf::Null => {
                let removed = derived.len() - requested_length;
                derived.rotate_left(removed);
                derived[requested_length..].zeroize();
                derived.truncate(requested_length);
            }
            EcdhKdf::X963(digest) => {
                derived = x963_kdf(digest, &derived, shared_data, requested_length)?;
            }
        }
        derived_object.material = if software_secret {
            KeyMaterial::SoftwareSecret(derived)
        } else {
            KeyMaterial::DerivedSecret(derived)
        };
        derived_object.always_sensitive = object.always_sensitive && derived_object.sensitive;
        derived_object.never_extractable = object.never_extractable && !derived_object.extractable;
        derived_object.local = false;
        derived_object.key_gen_mechanism = Some(mechanism.mechanism);
        if software_secret {
            *key_handle =
                publish_software_secret_object(ctx, session_handle, slot_id, derived_object)?;
            return Ok(());
        }
        derived_object.set_creator(session_handle, slot_id);
        *key_handle = ctx.insert_object(derived_object)?;
        Ok(())
    })
}

fn derive_hkdf_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: &CK_MECHANISM,
    base_key: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: &mut CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_HKDF_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_HKDF_PARAMS_PTR) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let extract = parameters.bExtract != CK_FALSE as CK_BBOOL;
    let expand = parameters.bExpand != CK_FALSE as CK_BBOOL;
    if !extract && !expand {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let digest = match parameters.prfHashMechanism {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE => MessageDigest::Sha1,
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => MessageDigest::Sha256,
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => MessageDigest::Sha384,
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => MessageDigest::Sha512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    let salt_data = if extract && parameters.ulSaltType == CKF_HKDF_SALT_DATA as CK_ULONG {
        if parameters.pSalt.is_null() || parameters.ulSaltLen == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        Some(
            unsafe { from_raw_parts(parameters.pSalt.cast_const(), parameters.ulSaltLen as usize) }
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?,
        )
    } else {
        None
    };
    if extract
        && !matches!(
            parameters.ulSaltType,
            x if x == CKF_HKDF_SALT_NULL as CK_ULONG
                || x == CKF_HKDF_SALT_DATA as CK_ULONG
                || x == CKF_HKDF_SALT_KEY as CK_ULONG
        )
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let info = if expand {
        unsafe { from_raw_parts(parameters.pInfo.cast_const(), parameters.ulInfoLen as usize) }
            .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?
    } else {
        &[]
    };
    let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
    validate_unique_template(templ)?;

    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if !ctx.get_slot(slot_id)?.supports_software_secret_operations() {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
        let base = ctx
            .resolve_object(base_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        let mut merged = merge_policy_template(templ, base.policy_templates.derive.as_ref())?;
        let templ = merged.as_slice();
        let requested_length = templ
            .iter()
            .find(|attribute| attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE)
            .map(|attribute| read_ulong_template_attribute(attribute).map(|value| value as usize))
            .transpose()
            .map_err(Error::from)?;
        let output_length = if expand {
            requested_length.ok_or(CKR_TEMPLATE_INCOMPLETE)?
        } else {
            if requested_length.is_some_and(|length| length != digest.size()) {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            digest.size()
        };
        if output_length == 0 || output_length > 1024 || output_length > digest.size() * 255 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        let (mut object, material_length) =
            derived_secret_object(templ, output_length, output_length, true)?;
        if material_length != output_length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        validate_new_object_access(&object, flags, logged_in)?;
        require_key_mechanism(&base, mechanism.mechanism)?;
        if base.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
            || base.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if !base.derive {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let KeyMaterial::SoftwareSecret(base_value) = &base.material else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        if base_value.len() != digest.size() {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        let salt_key = if extract && parameters.ulSaltType == CKF_HKDF_SALT_KEY as CK_ULONG {
            let salt = ctx
                .resolve_object(parameters.hSaltKey)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_KEY_HANDLE_INVALID)?;
            let KeyMaterial::SoftwareSecret(value) = salt.material else {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            };
            Some(value)
        } else {
            None
        };
        let salt = salt_key
            .as_ref()
            .map(|value| value.as_slice())
            .or(salt_data);
        let value = hkdf_key_material(
            digest,
            extract,
            expand,
            base_value,
            salt,
            info,
            output_length,
        )?;
        if material_length != value.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        object.material = KeyMaterial::SoftwareSecret(value);
        object.always_sensitive = base.always_sensitive && object.sensitive;
        object.never_extractable = base.never_extractable && !object.extractable;
        object.local = false;
        object.key_gen_mechanism = Some(mechanism.mechanism);
        *key_handle = publish_software_secret_object(ctx, session_handle, slot_id, object)?;
        Ok(())
    })
}

pub(crate) fn hkdf_key_material(
    digest: MessageDigest,
    extract: bool,
    expand: bool,
    base_key: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    macro_rules! derive {
        ($hash:ty) => {{
            if extract {
                let (mut prk, hkdf) = hkdf::Hkdf::<$hash>::extract(salt, base_key);
                if expand {
                    prk.zeroize();
                    let mut output = Zeroizing::new(vec![0; output_length]);
                    hkdf.expand(info, &mut output)
                        .map_err(|_| Error::from(CKR_KEY_SIZE_RANGE))?;
                    Ok(output)
                } else {
                    let output = Zeroizing::new(prk.to_vec());
                    prk.zeroize();
                    Ok(output)
                }
            } else {
                let hkdf = hkdf::Hkdf::<$hash>::from_prk(base_key)
                    .map_err(|_| Error::from(CKR_KEY_SIZE_RANGE))?;
                let mut output = Zeroizing::new(vec![0; output_length]);
                hkdf.expand(info, &mut output)
                    .map_err(|_| Error::from(CKR_KEY_SIZE_RANGE))?;
                Ok(output)
            }
        }};
    }
    match digest {
        MessageDigest::Sha1 => derive!(sha1::Sha1),
        MessageDigest::Sha256 => derive!(sha2::Sha256),
        MessageDigest::Sha384 => derive!(sha2::Sha384),
        MessageDigest::Sha512 => derive!(sha2::Sha512),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

#[derive(Clone, Copy)]
enum EcdhKdf {
    Null,
    X963(MessageDigest),
}

fn ecdh_kdf(kdf: CK_EC_KDF_TYPE) -> Result<EcdhKdf, Error> {
    let digest = match kdf {
        x if x == CKD_NULL as CK_EC_KDF_TYPE => return Ok(EcdhKdf::Null),
        x if x == CKD_SHA1_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha1,
        x if x == CKD_SHA224_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha224,
        x if x == CKD_SHA256_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha256,
        x if x == CKD_SHA384_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha384,
        x if x == CKD_SHA512_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha512,
        x if x == CKD_SHA3_224_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha3_224,
        x if x == CKD_SHA3_256_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha3_256,
        x if x == CKD_SHA3_384_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha3_384,
        x if x == CKD_SHA3_512_KDF as CK_EC_KDF_TYPE => MessageDigest::Sha3_512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    Ok(EcdhKdf::X963(digest))
}

pub(crate) fn x963_kdf(
    digest: MessageDigest,
    secret: &[u8],
    shared_data: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let blocks = output_length.div_ceil(digest.size());
    if output_length == 0 || blocks > u32::MAX as usize {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let input_length = secret
        .len()
        .checked_add(std::mem::size_of::<u32>())
        .and_then(|length| length.checked_add(shared_data.len()))
        .ok_or(CKR_KEY_SIZE_RANGE)?;
    let mut output = Zeroizing::new(Vec::with_capacity(output_length));
    for counter in 1..=blocks {
        let mut input = Zeroizing::new(Vec::with_capacity(input_length));
        input.extend_from_slice(secret);
        input.extend_from_slice(&(counter as u32).to_be_bytes());
        input.extend_from_slice(shared_data);
        let block = Zeroizing::new(hash(digest, &input)?);
        let remaining = output_length - output.len();
        output.extend_from_slice(&block[..remaining.min(block.len())]);
    }
    Ok(output)
}

fn derived_secret_object(
    templ: &[CK_ATTRIBUTE],
    default_length: usize,
    maximum_length: usize,
    software_secret: bool,
) -> Result<(TokenObject, usize), Error> {
    let mut object_template = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        key_type: Some(CKK_GENERIC_SECRET as CK_KEY_TYPE),
        private: !software_secret,
        sensitive: Some(!software_secret),
        extractable: Some(software_secret),
        ..TokenObjectTemplate::default()
    };
    let mut requested_length = None;
    for attribute in templ {
        if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
            requested_length =
                Some(read_ulong_template_attribute(attribute).map_err(Error::from)? as usize);
        } else {
            object_template
                .apply_attribute(attribute)
                .map_err(Error::from)?;
        }
    }
    let requested_length = requested_length.unwrap_or(default_length);
    if requested_length == 0 || requested_length > maximum_length {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let mut object = if software_secret {
        object_template.into_software_secret_object()
    } else {
        object_template.into_object()
    }
    .map_err(Error::from)?;
    if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if software_secret {
        if object.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
            && object.key_type != CKK_AES as CK_KEY_TYPE
            && !is_hmac_key_type(object.key_type)
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        validate_software_secret_length(object.key_type, requested_length)?;
        if object.token && !object.private {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
    } else {
        if object.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE || object.token {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        object.private = false;
        object.sensitive = false;
        object.extractable = true;
        object.always_sensitive = false;
        object.never_extractable = false;
        object.encrypt = false;
        object.decrypt = false;
        object.sign = false;
        object.verify = false;
        object.derive = false;
    }
    Ok((object, requested_length))
}

ffi_entry_point! {
    pub fn C_SeedRandom(
        session: CK_SESSION_HANDLE,
        _seed: *mut ::std::os::raw::c_uchar,
        _seed_len: ::std::os::raw::c_ulong,
    ) -> CK_RV {
        log!(2, "C_SeedRandom called");
        let result: Result<(), Error> = with_session_context(session, |ctx| {
            ctx._get_session(session)?;
            Err(CKR_RANDOM_SEED_NOT_SUPPORTED.into())
        });
        map(result)
    }
}

ffi_entry_point! {
    pub fn C_GenerateRandom(
        session: CK_SESSION_HANDLE,
        random_data: *mut ::std::os::raw::c_uchar,
        random_len: ::std::os::raw::c_ulong,
    ) -> CK_RV {
        log!(2, "C_GenerateRandom called");
        let result: Result<(), Error> = with_session_context_mut(session, |ctx| {
            let random_data = unsafe { _from_raw_parts_mut(random_data, random_len as usize) }?;
            let slot_id = ctx._get_session(session)?.1.slotID();
            ctx.reconcile_login_state(slot_id);
            ctx.get_slot(slot_id)?.ensure_backend_read_session()?;
            ctx._get_session(session)?.1.generate_random(random_data)
        });
        map(result)
    }
}
