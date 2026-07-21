#[no_mangle]
pub extern "C" fn C_CreateObject(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CreateObject called with {:?}",
        (session_handle, templ, count, object)
    );
    match create_object(session_handle, templ, count, object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn create_object(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let object_handle = as_mut(object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mut object = parse_create_object_template(templ)?;
        validate_new_object_access(&object, flags, logged_in)?;
        if ctx.get_slot(slot_id)?.is_yubihsm() {
            let (command, expected_class) = yubihsm_import_command(&object)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            let id = parse_yubihsm_object_id(&response)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            *object_handle = ctx
                .objects
                .iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == expected_class
                        && matches!(object.material, KeyMaterial::YubiHsm { id: object_id, .. } if object_id == id)
                })
                .map(|(handle, _)| *handle)
                .ok_or(CKR_DEVICE_ERROR)?;
            return Ok(());
        }
        object.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(object);
        *object_handle = handle;
        Ok(())
    })
}

fn yubihsm_id(id: &[u8]) -> Result<u16, Error> {
    match id {
        [] => Ok(0),
        [high, low] => Ok(u16::from_be_bytes([*high, *low])),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

fn padded_big_num(value: &openssl::bn::BigNumRef, length: usize) -> Result<Vec<u8>, Error> {
    let encoded = value.to_vec();
    if encoded.len() > length {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let mut padded = vec![0; length];
    padded[length - encoded.len()..].copy_from_slice(&encoded);
    Ok(padded)
}

fn yubihsm_object_parameters(
    object: &TokenObject,
    algorithm: u8,
) -> Result<YubiHsmObjectParameters<'_>, Error> {
    if !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let mut bits = Vec::new();
    if object.sign
        && (object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || is_hmac_key_type(object.key_type))
    {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x05, 0x06]);
        } else if object.key_type == CKK_EC as CK_KEY_TYPE {
            bits.push(0x07);
        } else if object.key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
            bits.push(0x08);
        } else {
            bits.push(0x16);
        }
    }
    if object.verify {
        bits.push(0x17);
    }
    if object.derive {
        bits.push(0x0b);
    }
    if object.decrypt {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x09, 0x0a]);
        } else {
            bits.extend([0x32, 0x34]);
        }
    }
    if object.encrypt {
        bits.extend([0x33, 0x35]);
    }
    if object.extractable
        && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
        && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
    {
        bits.push(0x10);
    }
    Ok(YubiHsmObjectParameters {
        id: yubihsm_id(&object.id)?,
        label: &object.label,
        domains: 0xffff,
        capabilities: yubihsm_capabilities(&bits),
        algorithm,
    })
}

fn yubihsm_import_command(
    object: &TokenObject,
) -> Result<(YubiHsmCommand, CK_OBJECT_CLASS), Error> {
    match &object.material {
        KeyMaterial::RsaPrivate(key) if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
            let (algorithm, component_length) = match key.size() {
                256 => (YUBIHSM_ALGO_RSA_2048, 128),
                384 => (YUBIHSM_ALGO_RSA_3072, 192),
                512 => (YUBIHSM_ALGO_RSA_4096, 256),
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            let mut value =
                padded_big_num(key.p().ok_or(CKR_TEMPLATE_INCOMPLETE)?, component_length)?;
            value.extend_from_slice(&padded_big_num(
                key.q().ok_or(CKR_TEMPLATE_INCOMPLETE)?,
                component_length,
            )?);
            Ok((
                YubiHsmCommand::put_object(
                    YubiHsmCommandCode::PutAsymmetricKey,
                    &yubihsm_object_parameters(object, algorithm)?,
                    &value,
                )?,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            ))
        }
        KeyMaterial::Secret(value) if object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS => {
            let (code, algorithm) = if object.key_type == CKK_AES as CK_KEY_TYPE {
                let algorithm = match value.len() {
                    16 => YUBIHSM_ALGO_AES128,
                    24 => YUBIHSM_ALGO_AES192,
                    32 => YUBIHSM_ALGO_AES256,
                    _ => return Err(CKR_KEY_SIZE_RANGE.into()),
                };
                (YubiHsmCommandCode::PutSymmetricKey, algorithm)
            } else {
                let algorithm = match object.key_type {
                    x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA1,
                    x if x == CKK_SHA384_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA384,
                    x if x == CKK_SHA512_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA512,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE =>
                    {
                        YUBIHSM_ALGO_HMAC_SHA256
                    }
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                };
                (YubiHsmCommandCode::PutHmacKey, algorithm)
            };
            Ok((
                YubiHsmCommand::put_object(
                    code,
                    &yubihsm_object_parameters(object, algorithm)?,
                    value,
                )?,
                CKO_SECRET_KEY as CK_OBJECT_CLASS,
            ))
        }
        _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
    }
}

fn parse_create_object_template(templ: &[CK_ATTRIBUTE]) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let mut object_template = TokenObjectTemplate::default();
    let mut key_components = HashMap::new();
    for attribute in templ {
        if is_key_component_attribute(attribute.type_) {
            key_components.insert(
                attribute.type_,
                Zeroizing::new(read_attribute_value(attribute).map_err(Error::from)?),
            );
            continue;
        }
        object_template
            .apply_attribute(attribute)
            .map_err(Error::from)?;
    }
    let mut object = object_template.into_object().map_err(Error::from)?;
    object.material = build_imported_key_material(&object, key_components)?;
    Ok(object)
}

fn is_key_component_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
    )
}

fn required_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<BigNum, Error> {
    let value = components
        .remove(&attribute_type)
        .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if value.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    BigNum::from_slice(&value).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
}

fn optional_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<BigNum>, Error> {
    components
        .remove(&attribute_type)
        .map(|value| {
            if value.is_empty() {
                Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
            } else {
                BigNum::from_slice(&value)
                    .map(Some)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
            }
        })
        .unwrap_or(Ok(None))
}

fn build_imported_key_material(
    object: &TokenObject,
    mut components: HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
) -> Result<KeyMaterial, Error> {
    let material = match (object.class, object.key_type) {
        (class, key_type)
            if class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                && matches!(
                    key_type,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_AES as CK_KEY_TYPE
                        || x == CKK_SHA_1_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA384_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA512_HMAC as CK_KEY_TYPE
                ) =>
        {
            let value = components
                .remove(&(CKA_VALUE as CK_ATTRIBUTE_TYPE))
                .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            if value.is_empty() {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            KeyMaterial::Secret(value)
        }
        (class, key_type)
            if class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let key = Rsa::from_public_components(modulus, exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            KeyMaterial::RsaPublic(key)
        }
        (class, key_type)
            if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let public_exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let private_exponent =
                required_big_num(&mut components, CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let mut builder = RsaPrivateKeyBuilder::new(modulus, public_exponent, private_exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

            let prime_1 = optional_big_num(&mut components, CKA_PRIME_1 as CK_ATTRIBUTE_TYPE)?;
            let prime_2 = optional_big_num(&mut components, CKA_PRIME_2 as CK_ATTRIBUTE_TYPE)?;
            let has_factors = prime_1.is_some() || prime_2.is_some();
            builder = match (prime_1, prime_2) {
                (Some(prime_1), Some(prime_2)) => builder
                    .set_factors(prime_1, prime_2)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };

            let exponent_1 =
                optional_big_num(&mut components, CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE)?;
            let exponent_2 =
                optional_big_num(&mut components, CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE)?;
            let coefficient =
                optional_big_num(&mut components, CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE)?;
            builder = match (exponent_1, exponent_2, coefficient) {
                (Some(exponent_1), Some(exponent_2), Some(coefficient)) if has_factors => builder
                    .set_crt_params(exponent_1, exponent_2, coefficient)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };
            KeyMaterial::RsaPrivate(builder.build())
        }
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };
    if components.is_empty() {
        Ok(material)
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

fn validate_unique_template(templ: &[CK_ATTRIBUTE]) -> Result<(), Error> {
    let mut types = HashSet::new();
    if templ.iter().all(|attribute| types.insert(attribute.type_)) {
        Ok(())
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

#[no_mangle]
pub extern "C" fn C_CopyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    new_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CopyObject called with {:?}",
        (session_handle, object, templ, count, new_object)
    );
    match copy_object(session_handle, object, templ, count, new_object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn copy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    new_object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let new_object_handle = as_mut(new_object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mut copied_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?
            .clone();
        if matches!(
            copied_object.material,
            KeyMaterial::SecurityDomainData { .. }
                | KeyMaterial::SecurityDomainCertificate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::HsmAuthPublic { .. }
        ) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        if matches!(copied_object.material, KeyMaterial::YubiHsm { .. }) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = copied_object.set_copy_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }
        if rv != CKR_OK as CK_RV {
            return Err(rv.into());
        }
        validate_new_object_access(&copied_object, flags, logged_in)?;
        copied_object.set_owner(session_handle, slot_id);
        copied_object.unique_id.clear();

        let handle = ctx.insert_object(copied_object);
        *new_object_handle = handle;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_DestroyObject called with {:?}",
        (session_handle, object)
    );
    map(destroy_object(session_handle, object))
}

fn destroy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?
            .clone();
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if matches!(
            stored_object.material,
            KeyMaterial::SecurityDomainData { .. }
                | KeyMaterial::SecurityDomainCertificate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::HsmAuthPublic { .. }
        ) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        if let KeyMaterial::YubiHsm {
            id, object_type, ..
        } = stored_object.material
        {
            if matches!(object_type, YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC) {
                return Ok(());
            }
            ctx._get_session(session_handle)?
                .1
                .yubihsm_command(&YubiHsmCommand::delete_object(id, object_type & !0x80))?;
            let removed: Vec<_> = ctx
                .objects
                .iter()
                .filter_map(|(handle, candidate)| match candidate.material {
                    KeyMaterial::YubiHsm {
                        id: candidate_id,
                        object_type: candidate_type,
                        ..
                    } if candidate.slot_id == Some(slot_id)
                        && candidate_id == id
                        && candidate_type & !0x80 == object_type & !0x80 =>
                    {
                        Some(*handle)
                    }
                    _ => None,
                })
                .collect();
            for handle in removed {
                ctx.objects.remove(&handle);
                remove_object_from_find_operations(&mut ctx.find_operations, handle);
            }
            return Ok(());
        }
        ctx.objects.remove(&object);
        remove_object_from_find_operations(&mut ctx.find_operations, object);
        Ok(())
    })
}

fn remove_object_from_find_operations(
    find_operations: &mut HashMap<CK_SESSION_HANDLE, FindOperation>,
    object: CK_OBJECT_HANDLE,
) {
    for operation in find_operations.values_mut() {
        let already_returned = operation.next.min(operation.objects.len());
        let removed_before_cursor = operation.objects[..already_returned]
            .iter()
            .filter(|&&handle| handle == object)
            .count();
        operation.objects.retain(|&handle| handle != object);
        operation.next -= removed_before_cursor;
    }
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetObjectSize called with {:?}",
        (session_handle, object, size)
    );
    map(get_object_size(session_handle, object, size))
}

fn get_object_size(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> Result<(), Error> {
    let size = as_mut(size)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        *size = object.size();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match get_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn get_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = _from_raw_parts_mut(templ, count as usize)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if attribute.type_ == CKA_VALUE as CK_ATTRIBUTE_TYPE {
                match &object.material {
                    KeyMaterial::DerivedSecret(value) => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(value) if !object.sensitive && object.extractable => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(_) => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
                    }
                    KeyMaterial::HsmAuthCredential { .. } => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
                    }
                    KeyMaterial::PivCertificate { .. }
                    | KeyMaterial::PivAttestation { .. }
                    | KeyMaterial::OpenPgpCertificate { .. }
                    | KeyMaterial::SecurityDomainData { .. }
                    | KeyMaterial::SecurityDomainCertificate { .. } => {
                        match object.attribute_value(attribute.type_) {
                            Some(value) => {
                                if let Err(e) = write_attribute_value(attribute, &value) {
                                    rv = combine_attribute_rv(rv, e);
                                }
                            }
                            None => {
                                attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                                rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                            }
                        }
                    }
                    KeyMaterial::YubiHsm {
                        id,
                        object_type,
                        value,
                        ..
                    } if *object_type == YUBIHSM_OPAQUE => {
                        if value.borrow().is_none() {
                            let payload = ctx._get_session(session_handle)?.1.yubihsm_command(
                                &YubiHsmCommand::get_object(YubiHsmCommandCode::GetOpaque, *id)?,
                            )?;
                            *value.borrow_mut() = Some(payload);
                        }
                        let payload = value.borrow();
                        if let Err(e) = write_attribute_value(
                            attribute,
                            payload.as_deref().ok_or(CKR_DEVICE_ERROR)?,
                        ) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    _ => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                    }
                }
                continue;
            }
            match object.attribute_value(attribute.type_) {
                Some(value) => {
                    if let Err(e) = write_attribute_value(attribute, &value) {
                        rv = combine_attribute_rv(rv, e);
                    }
                }
                None => {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                    rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
            }
        }

        if rv == CKR_OK as CK_RV {
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

fn write_attribute_value(attribute: &mut CK_ATTRIBUTE, value: &[u8]) -> Result<(), CK_RV> {
    let required_len = value.len() as CK_ULONG;
    if attribute.pValue.is_null() {
        attribute.ulValueLen = required_len;
        return Ok(());
    }
    if attribute.ulValueLen < required_len {
        attribute.ulValueLen = required_len;
        return Err(CKR_BUFFER_TOO_SMALL as CK_RV);
    }

    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), attribute.pValue as *mut u8, value.len());
    }
    attribute.ulValueLen = required_len;
    Ok(())
}

fn read_attribute_value(attribute: &CK_ATTRIBUTE) -> Result<Vec<u8>, CK_RV> {
    if attribute.ulValueLen > 0 && attribute.pValue.is_null() {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }
    let value = if attribute.ulValueLen == 0 {
        &[]
    } else {
        unsafe {
            slice::from_raw_parts(attribute.pValue as *const u8, attribute.ulValueLen as usize)
        }
    };
    Ok(value.to_vec())
}

fn read_ulong_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<CK_ULONG, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?;
    let mut bytes = [0u8; ::std::mem::size_of::<CK_ULONG>()];
    bytes.copy_from_slice(&value);
    Ok(CK_ULONG::from_ne_bytes(bytes))
}

fn read_bool_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<bool, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?[0];
    match value {
        x if x == CK_FALSE as CK_BBOOL => Ok(false),
        x if x == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV),
    }
}

fn combine_attribute_rv(current: CK_RV, next: CK_RV) -> CK_RV {
    if current == CKR_ARGUMENTS_BAD as CK_RV {
        current
    } else if next == CKR_ARGUMENTS_BAD as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        next
    } else if current == CKR_BUFFER_TOO_SMALL as CK_RV {
        current
    } else {
        next
    }
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_SetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match set_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn set_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if matches!(stored_object.material, KeyMaterial::YubiHsm { .. }) {
            return Err(CKR_ATTRIBUTE_READ_ONLY.into());
        }
        let mut updated_object = stored_object.clone();

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = updated_object.set_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }

        if rv == CKR_OK as CK_RV {
            ctx.objects.insert(object, updated_object);
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjectsInit called with {:?}",
        (session_handle, templ, count)
    );
    if count > 0 && templ.is_null() {
        return CKR_ARGUMENTS_BAD.into();
    }
    map(find_objects_init(session_handle, templ, count))
}

fn find_objects_init(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    let templ: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = templ
        .iter()
        .map(|attribute| {
            Ok((
                attribute.type_,
                read_attribute_value(attribute).map_err(Error::from)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.find_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        ctx.insert_session_objects(slot_id, session_handle)?;
        log!(2, "C_FindObjectsInit template {:?}", templ);
        let mut objects: Vec<CK_OBJECT_HANDLE> = ctx
            .objects
            .iter()
            .filter(|(_handle, object)| {
                object.is_visible_to(session_handle, slot_id, logged_in)
                    && object.matches_template(&templ)
            })
            .map(|(handle, _object)| *handle)
            .collect();
        objects.sort();
        ctx.find_operations
            .insert(session_handle, FindOperation { objects, next: 0 });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    session_handle: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: ::std::os::raw::c_ulong,
    object_count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjects called with {:?}",
        (session_handle, object, max_object_count, object_count)
    );
    map(find_objects(
        session_handle,
        object,
        max_object_count,
        object_count,
    ))
}

fn find_objects(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    object_count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let object_count = as_mut(object_count)?;
    let output = _from_raw_parts_mut(object, max_object_count as usize)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .find_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;

        let remaining = &operation.objects[operation.next..];
        let returned = remaining.len().min(max_object_count as usize);
        output[..returned].copy_from_slice(&remaining[..returned]);
        operation.next += returned;
        *object_count = returned as CK_ULONG;
        log!(2, "C_FindObjects returning {:?}", &output[..returned]);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_FindObjectsFinal called with {:?}", session_handle);
    map(find_objects_final(session_handle))
}

fn find_objects_final(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        ctx.find_operations
            .remove(&session_handle)
            .map(|_| ())
            .ok_or(CKR_OPERATION_NOT_INITIALIZED.into())
    })
}
