use super::{
    crypt::{
        aes_key_wrap_transform, aes_kwp_transform, parse_key_wrap_iv, software_crypt_ecb_blocks,
    },
    key::yubihsm_ec_algorithm,
    object::{
        publish_software_secret_object, validate_software_secret_length, validate_unique_template,
        yubihsm_hardware_import_object, yubihsm_id,
    },
};
use crate::*;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub(crate) struct RsaAesWrapParameters {
    aes_algorithm: u8,
    hash_algorithm: u8,
    mgf1_algorithm: u8,
    label_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) enum YubiHsmWrapMechanism {
    AesCcm {
        format: u8,
    },
    Rsa {
        full_object: bool,
        parameters: RsaAesWrapParameters,
    },
}

struct YubiHsmUnwrapTemplate {
    object: TokenObject,
    hardware_id: u16,
    hardware_label: String,
    capabilities: [u8; 8],
    algorithm: u8,
}

impl YubiHsmUnwrapTemplate {
    fn parameters(&self) -> YubiHsmObjectParameters<'_> {
        YubiHsmObjectParameters {
            id: self.hardware_id,
            label: &self.hardware_label,
            domains: 0xffff,
            capabilities: self.capabilities,
            algorithm: self.algorithm,
        }
    }
}

fn rsa_wrap_hash_algorithm(mechanism: CK_MECHANISM_TYPE) -> Result<(u8, MessageDigest), Error> {
    match mechanism {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE => {
            Ok((YUBIHSM_ALGO_RSA_OAEP_SHA1, MessageDigest::Sha1))
        }
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => {
            Ok((YUBIHSM_ALGO_RSA_OAEP_SHA256, MessageDigest::Sha256))
        }
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => {
            Ok((YUBIHSM_ALGO_RSA_OAEP_SHA384, MessageDigest::Sha384))
        }
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => {
            Ok((YUBIHSM_ALGO_RSA_OAEP_SHA512, MessageDigest::Sha512))
        }
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

fn rsa_wrap_mgf_algorithm(mgf: CK_RSA_PKCS_MGF_TYPE) -> Result<u8, Error> {
    match mgf {
        x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA1),
        x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA256),
        x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA384),
        x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA512),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

fn parse_rsa_wrap_parameters(mechanism: &CK_MECHANISM) -> Result<RsaAesWrapParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_RSA_AES_KEY_WRAP_PARAMS_PTR) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let aes_algorithm = match parameters.ulAESKeyBits {
        128 => YUBIHSM_ALGO_AES128,
        192 => YUBIHSM_ALGO_AES192,
        256 => YUBIHSM_ALGO_AES256,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    let oaep = unsafe { _as_ref(parameters.pOAEPParams) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if oaep.source != CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let (hash_algorithm, digest) = rsa_wrap_hash_algorithm(oaep.hashAlg)?;
    let mgf1_algorithm = rsa_wrap_mgf_algorithm(oaep.mgf)?;
    let label =
        unsafe { from_raw_parts(oaep.pSourceData as *const u8, oaep.ulSourceDataLen as usize) }
            .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    Ok(RsaAesWrapParameters {
        aes_algorithm,
        hash_algorithm,
        mgf1_algorithm,
        label_digest: hash(digest, label)?,
    })
}

pub(crate) fn parse_yubihsm_wrap_mechanism(
    mechanism: &CK_MECHANISM,
) -> Result<YubiHsmWrapMechanism, Error> {
    match mechanism.mechanism {
        x if x == CKM_YUBICO_AES_CCM_WRAP => {
            let format = if mechanism.pParameter.is_null() {
                if mechanism.ulParameterLen != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                0
            } else {
                if mechanism.ulParameterLen as usize
                    != std::mem::size_of::<CKM_YUBICO_AES_CCM_WRAP_PARAMS>()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let parameters = unsafe {
                    _as_ref(
                        mechanism
                            .pParameter
                            .cast::<CKM_YUBICO_AES_CCM_WRAP_PARAMS>(),
                    )
                }
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
                u8::try_from(parameters.format)
                    .ok()
                    .filter(|format| *format <= 1)
                    .ok_or(CKR_MECHANISM_PARAM_INVALID)?
            };
            Ok(YubiHsmWrapMechanism::AesCcm { format })
        }
        x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE || x == CKM_YUBICO_RSA_WRAP => {
            Ok(YubiHsmWrapMechanism::Rsa {
                full_object: x == CKM_YUBICO_RSA_WRAP,
                parameters: parse_rsa_wrap_parameters(mechanism)?,
            })
        }
        _ => Err(CKR_MECHANISM_INVALID.into()),
    }
}

fn yubihsm_material(object: &TokenObject) -> Result<(u16, u8, u8), Error> {
    match &object.material {
        KeyMaterial::YubiHsm {
            id,
            object_type,
            algorithm,
            ..
        } => Ok((*id, *object_type, *algorithm)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn validate_yubihsm_wrapping_key(
    object: &TokenObject,
    mechanism: &YubiHsmWrapMechanism,
    unwrapping: bool,
) -> Result<(u16, u8), Error> {
    let (id, object_type, algorithm) = yubihsm_material(object)?;
    let compatible = match mechanism {
        YubiHsmWrapMechanism::AesCcm { .. } => {
            object_type == YUBIHSM_WRAP_KEY && is_yubihsm_ccm_wrap(algorithm)
        }
        YubiHsmWrapMechanism::Rsa { .. } if unwrapping => {
            object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(algorithm)
        }
        YubiHsmWrapMechanism::Rsa { .. } => {
            matches!(
                object_type,
                YUBIHSM_WRAP_KEY | YUBIHSM_WRAP_KEY_PUBLIC | YUBIHSM_PUBLIC_WRAP_KEY
            ) && is_yubihsm_rsa(algorithm)
        }
    };
    if !compatible {
        return Err(if unwrapping {
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into()
        } else {
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into()
        });
    }
    Ok((id, object_type))
}

fn parse_yubihsm_import_response(response: &[u8]) -> Result<(u8, u16), Error> {
    let [object_type, high, low] = response else {
        return Err(CKR_DEVICE_ERROR.into());
    };
    Ok((*object_type, u16::from_be_bytes([*high, *low])))
}

enum SoftwareAesWrapMechanism {
    Kw(Vec<u8>),
    Kwp(Vec<u8>),
}

fn parse_software_aes_wrap_mechanism(
    mechanism: &CK_MECHANISM,
) -> Result<SoftwareAesWrapMechanism, Error> {
    match mechanism.mechanism {
        x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE => Ok(SoftwareAesWrapMechanism::Kw(
            parse_key_wrap_iv(mechanism, &[0xa6; 8])?,
        )),
        x if x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE => Ok(SoftwareAesWrapMechanism::Kwp(
            parse_key_wrap_iv(mechanism, &[0xa6, 0x59, 0x59, 0xa6])?,
        )),
        _ => Err(CKR_MECHANISM_INVALID.into()),
    }
}

fn transform_software_wrapped_key(
    mechanism: &SoftwareAesWrapMechanism,
    wrapping_key: &[u8],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    match mechanism {
        SoftwareAesWrapMechanism::Kw(iv) => {
            aes_key_wrap_transform(input, encrypting, iv, |block, encrypting| {
                software_crypt_ecb_blocks(wrapping_key, block, encrypting)
            })
        }
        SoftwareAesWrapMechanism::Kwp(iv) => {
            aes_kwp_transform(input, encrypting, iv, |block, encrypting| {
                software_crypt_ecb_blocks(wrapping_key, block, encrypting)
            })
        }
    }
}

fn software_unwrap_template(template: &[CK_ATTRIBUTE]) -> Result<TokenObject, Error> {
    validate_unique_template(template)?;
    let mut parsed = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        ..TokenObjectTemplate::default()
    };
    for attribute in template {
        parsed.apply_attribute(attribute).map_err(Error::from)?;
    }
    let mut object = parsed.into_software_secret_object().map_err(Error::from)?;
    if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
        || (object.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
            && object.key_type != CKK_AES as CK_KEY_TYPE
            && !is_hmac_key_type(object.key_type))
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if object.token && !object.private {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    object.always_sensitive = false;
    object.never_extractable = false;
    object.local = false;
    object.key_gen_mechanism = None;
    Ok(object)
}

fn software_unwrap_error(error: Error) -> Error {
    match error {
        Error::Generic(rv)
            if rv == CKR_ENCRYPTED_DATA_INVALID as CK_RV || rv == CKR_DATA_INVALID as CK_RV =>
        {
            CKR_WRAPPED_KEY_INVALID.into()
        }
        Error::Generic(rv)
            if rv == CKR_ENCRYPTED_DATA_LEN_RANGE as CK_RV || rv == CKR_DATA_LEN_RANGE as CK_RV =>
        {
            CKR_WRAPPED_KEY_LEN_RANGE.into()
        }
        error => error,
    }
}

ffi_entry_point! {
    pub fn C_WrapKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_PTR,
        wrapping_key: CK_OBJECT_HANDLE,
        key: CK_OBJECT_HANDLE,
        wrapped_key: CK_BYTE_PTR,
        wrapped_key_len: CK_ULONG_PTR,
    ) -> CK_RV {
        map(wrap_key(
            session_handle,
            mechanism,
            wrapping_key,
            key,
            wrapped_key,
            wrapped_key_len,
        ))
    }
}

fn wrap_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let mechanism = unsafe { _as_ref(mechanism) }?;
        let output_len = unsafe { as_mut(wrapped_key_len) }?;
        if ctx.get_slot(slot_id)?.supports_software_secret_operations() {
            let parsed_mechanism = parse_software_aes_wrap_mechanism(mechanism)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_WRAP as CK_FLAGS)?;
            let target = ctx
                .resolve_object(key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_KEY_HANDLE_INVALID)?;
            if !target.extractable || target.never_extractable {
                return Err(CKR_KEY_UNEXTRACTABLE.into());
            }
            let KeyMaterial::SoftwareSecret(target_value) = &target.material else {
                return Err(CKR_KEY_NOT_WRAPPABLE.into());
            };
            let wrapper = ctx
                .resolve_object(wrapping_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
            if !wrapper.can_wrap() {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let KeyMaterial::SoftwareSecret(wrapping_value) = &wrapper.material else {
                return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
            };
            if wrapper.key_type != CKK_AES as CK_KEY_TYPE {
                return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
            }
            let response = transform_software_wrapped_key(
                &parsed_mechanism,
                wrapping_value,
                target_value,
                true,
            )?;
            if wrapped_key.is_null() {
                *output_len = response.len() as CK_ULONG;
                return Ok(());
            }
            if *output_len < response.len() as CK_ULONG {
                *output_len = response.len() as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL.into());
            }
            let output = unsafe { _from_raw_parts_mut(wrapped_key, response.len()) }?;
            output.copy_from_slice(&response);
            *output_len = response.len() as CK_ULONG;
            return Ok(());
        }
        let parsed_mechanism = parse_yubihsm_wrap_mechanism(mechanism)?;
        let slot = ctx.get_slot(slot_id)?;
        if slot.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_WRAP as CK_FLAGS)?;
        let target = ctx
            .resolve_object(key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        let (target_id, target_type, _algorithm) =
            yubihsm_material(&target).map_err(|_| Error::from(CKR_KEY_HANDLE_INVALID))?;
        if target_type & 0x80 != 0 {
            return Err(CKR_KEY_NOT_WRAPPABLE.into());
        }
        let wrapper = ctx
            .resolve_object(wrapping_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
        let (wrapping_key_id, _wrapping_key_type) =
            validate_yubihsm_wrapping_key(&wrapper, &parsed_mechanism, false)?;

        let command = match &parsed_mechanism {
            YubiHsmWrapMechanism::AesCcm { format } => YubiHsmCommand::export_wrapped(
                wrapping_key_id,
                target_type,
                target_id,
                Some(*format),
            ),
            YubiHsmWrapMechanism::Rsa {
                full_object,
                parameters,
            } => YubiHsmCommand::rsa_wrap(
                if *full_object {
                    YubiHsmCommandCode::ExportRsaWrapped
                } else {
                    YubiHsmCommandCode::GetRsaWrappedKey
                },
                &YubiHsmRsaWrapParameters {
                    wrapping_key_id,
                    object_type: target_type,
                    object_id: target_id,
                    aes_algorithm: parameters.aes_algorithm,
                    hash_algorithm: parameters.hash_algorithm,
                    mgf1_algorithm: parameters.mgf1_algorithm,
                    label_digest: &parameters.label_digest,
                },
            )?,
        };
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        if wrapped_key.is_null() {
            *output_len = response.len() as CK_ULONG;
            return Ok(());
        }
        if *output_len < response.len() as CK_ULONG {
            *output_len = response.len() as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        let output = unsafe { _from_raw_parts_mut(wrapped_key, response.len()) }?;
        output.copy_from_slice(&response);
        *output_len = response.len() as CK_ULONG;
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_UnwrapKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_PTR,
        unwrapping_key: CK_OBJECT_HANDLE,
        wrapped_key: CK_BYTE_PTR,
        wrapped_key_len: CK_ULONG,
        templ: CK_ATTRIBUTE_PTR,
        attribute_count: CK_ULONG,
        key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        map(unwrap_key(
            session_handle,
            mechanism,
            unwrapping_key,
            wrapped_key,
            wrapped_key_len,
            templ,
            attribute_count,
            key,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn unwrap_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    unwrapping_key: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mechanism = unsafe { _as_ref(mechanism) }?;
        let output_handle = unsafe { as_mut(key) }?;
        if wrapped_key.is_null() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let wrapped =
            unsafe { from_raw_parts(wrapped_key as *const u8, wrapped_key_len as usize) }?;
        let template = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
        if ctx.get_slot(slot_id)?.supports_software_secret_operations() {
            let parsed_mechanism = parse_software_aes_wrap_mechanism(mechanism)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_UNWRAP as CK_FLAGS)?;
            let mut object = software_unwrap_template(template)?;
            validate_new_object_access(&object, flags, logged_in)?;
            let wrapper = ctx
                .resolve_object(unwrapping_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_UNWRAPPING_KEY_HANDLE_INVALID)?;
            if !wrapper.can_unwrap() {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let KeyMaterial::SoftwareSecret(unwrapping_value) = &wrapper.material else {
                return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
            };
            if wrapper.key_type != CKK_AES as CK_KEY_TYPE {
                return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
            }
            let value = Zeroizing::new(
                transform_software_wrapped_key(&parsed_mechanism, unwrapping_value, wrapped, false)
                    .map_err(software_unwrap_error)?,
            );
            validate_software_secret_length(object.key_type, value.len())?;
            object.material = KeyMaterial::SoftwareSecret(value);
            *output_handle = publish_software_secret_object(ctx, session_handle, slot_id, object)?;
            return Ok(());
        }
        let parsed_mechanism = parse_yubihsm_wrap_mechanism(mechanism)?;
        let slot = ctx.get_slot(slot_id)?;
        if slot.kind() != SlotKind::YubiHsm {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        if !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_UNWRAP as CK_FLAGS)?;
        let wrapper = ctx
            .resolve_object(unwrapping_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_UNWRAPPING_KEY_HANDLE_INVALID)?;
        let (unwrapping_key_id, _unwrapping_key_type) =
            validate_yubihsm_wrapping_key(&wrapper, &parsed_mechanism, true)?;

        let mut requested_attributes = None;
        let mut expected_target_type = None;
        let command = match &parsed_mechanism {
            YubiHsmWrapMechanism::AesCcm { .. } => {
                YubiHsmCommand::import_wrapped(unwrapping_key_id, wrapped)?
            }
            YubiHsmWrapMechanism::Rsa {
                full_object: true,
                parameters,
            } => YubiHsmCommand::import_rsa_wrapped(
                unwrapping_key_id,
                parameters.hash_algorithm,
                parameters.mgf1_algorithm,
                wrapped,
                &parameters.label_digest,
            )?,
            YubiHsmWrapMechanism::Rsa {
                full_object: false,
                parameters,
            } => {
                let parsed = parse_yubihsm_unwrap_template(template)?;
                validate_new_object_access(&parsed.object, flags, logged_in)?;
                let target_type = match parsed.object.class {
                    x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => YUBIHSM_ASYMMETRIC_KEY,
                    x if x == CKO_SECRET_KEY as CK_OBJECT_CLASS => YUBIHSM_SYMMETRIC_KEY,
                    _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
                };
                let command = YubiHsmCommand::put_rsa_wrapped_key(
                    unwrapping_key_id,
                    target_type,
                    &parsed.parameters(),
                    parameters.hash_algorithm,
                    parameters.mgf1_algorithm,
                    wrapped,
                    &parameters.label_digest,
                )?;
                requested_attributes = Some(parsed.object);
                expected_target_type = Some(target_type);
                command
            }
        };
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        let (target_type, target_id) = parse_yubihsm_import_response(&response)?;
        if expected_target_type.is_some_and(|expected| expected != target_type) {
            let _ = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&YubiHsmCommand::delete_object(target_id, target_type));
            let _ = ctx.refresh_slot_token_objects(slot_id);
            return Err(CKR_DEVICE_ERROR.into());
        }
        ctx.refresh_slot_token_objects(slot_id)?;
        let (handle, imported) = ctx
            .resolved_objects()?
            .into_iter()
            .find(|(_, object)| {
                object.slot_id == Some(slot_id)
                    && matches!(
                        object.material,
                        KeyMaterial::YubiHsm {
                            id,
                            object_type,
                            ..
                        } if id == target_id && object_type == target_type
                    )
            })
            .ok_or(CKR_DEVICE_ERROR)?;

        if let Some(requested) = requested_attributes {
            let metadata_result = ctx.get_slot(slot_id)?.yubihsm_set_attributes(
                slot_id,
                &imported.unique_id,
                (!requested.id.is_empty()).then_some(requested.id.as_slice()),
                (!requested.label.is_empty()).then_some(requested.label.as_str()),
            );
            let refresh = ctx.refresh_slot_token_objects(slot_id);
            if let Err(error) = metadata_result {
                let _ = refresh;
                return Err(error);
            }
            refresh?;
        }
        *output_handle = handle;
        Ok(())
    })
}

fn parse_yubihsm_unwrap_template(
    template: &[CK_ATTRIBUTE],
) -> Result<YubiHsmUnwrapTemplate, Error> {
    validate_unique_template(template)?;
    let mut object_template = TokenObjectTemplate {
        token: true,
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        ..TokenObjectTemplate::default()
    };
    let mut modulus_bits = None;
    let mut ec_parameters = None;
    let mut value_len = None;
    let mut exportable_under_wrap = false;
    for attribute in template {
        match attribute.type_ {
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE => {
                modulus_bits = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
            }
            x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE => {
                ec_parameters = Some(read_attribute_value(attribute).map_err(Error::from)?);
            }
            x if x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE => {
                value_len = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE => {
                exportable_under_wrap =
                    read_bool_template_attribute(attribute).map_err(Error::from)?;
            }
            _ => object_template
                .apply_attribute(attribute)
                .map_err(Error::from)?,
        }
    }
    let object = object_template.into_object().map_err(Error::from)?;
    if !object.token || !object.private || !object.sensitive {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let algorithm = match (object.class, object.key_type) {
        (class, key_type)
            if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            match modulus_bits.ok_or(CKR_TEMPLATE_INCOMPLETE)? {
                2048 => YUBIHSM_ALGO_RSA_2048,
                3072 => YUBIHSM_ALGO_RSA_3072,
                4096 => YUBIHSM_ALGO_RSA_4096,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            }
        }
        (class, key_type)
            if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && matches!(
                    key_type,
                    x if x == CKK_EC as CK_KEY_TYPE
                        || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                        || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE
                ) =>
        {
            let algorithm = yubihsm_ec_algorithm(&ec_parameters.ok_or(CKR_TEMPLATE_INCOMPLETE)?)?;
            let compatible = match key_type {
                x if x == CKK_EC as CK_KEY_TYPE => is_yubihsm_ec(algorithm),
                x if x == CKK_EC_EDWARDS as CK_KEY_TYPE => algorithm == YUBIHSM_ALGO_ED25519,
                _ => is_yubihsm_x25519(algorithm),
            };
            if !compatible {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            algorithm
        }
        (class, key_type)
            if class == CKO_SECRET_KEY as CK_OBJECT_CLASS && key_type == CKK_AES as CK_KEY_TYPE =>
        {
            match value_len.ok_or(CKR_TEMPLATE_INCOMPLETE)? {
                16 => YUBIHSM_ALGO_AES128,
                24 => YUBIHSM_ALGO_AES192,
                32 => YUBIHSM_ALGO_AES256,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            }
        }
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };

    if object.sign {
        match object.key_type {
            x if x == CKK_RSA as CK_KEY_TYPE
                || x == CKK_EC as CK_KEY_TYPE
                || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                || x == CKK_AES as CK_KEY_TYPE => {}
            _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        }
    }
    if object.derive
        && !matches!(
            object.key_type,
            x if x == CKK_EC as CK_KEY_TYPE || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE
        )
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if object.decrypt
        && !matches!(
            object.key_type,
            x if x == CKK_RSA as CK_KEY_TYPE || x == CKK_AES as CK_KEY_TYPE
        )
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if object.encrypt && object.key_type != CKK_AES as CK_KEY_TYPE {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if object.verify && object.key_type != CKK_AES as CK_KEY_TYPE {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let object_type = if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS {
        YUBIHSM_ASYMMETRIC_KEY
    } else {
        YUBIHSM_SYMMETRIC_KEY
    };
    let attributes = YubiHsmPkcs11Attributes {
        encrypt: object.encrypt,
        decrypt: object.decrypt,
        sign: object.sign,
        verify: object.verify,
        derive: object.derive,
        extractable: exportable_under_wrap,
        ..YubiHsmPkcs11Attributes::default()
    };

    let hardware = yubihsm_hardware_import_object(&object)?;
    Ok(YubiHsmUnwrapTemplate {
        object,
        hardware_id: yubihsm_id(&hardware.id)?,
        hardware_label: hardware.label,
        capabilities: yubihsm_attributes_to_capabilities(object_type, algorithm, attributes),
        algorithm,
    })
}
