use super::{
    crypt::{
        aes_key_wrap_transform, aes_kwp_transform, parse_key_wrap_iv, parse_rsa_oaep_parameters,
        rsa_oaep_pad, rsa_oaep_unpad, rsa_pkcs1_v1_5_unpad, software_crypt_ecb_blocks,
        RsaOaepParameters,
    },
    key::yubihsm_ec_algorithm,
    object::{
        persist_software_private_object, publish_software_secret_object,
        validate_software_secret_length, validate_unique_template, yubihsm_hardware_import_object,
        yubihsm_id,
    },
};
use crate::*;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub(crate) struct RsaAesWrapParameters {
    aes_key_length: usize,
    oaep: RsaOaepParameters,
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

fn parse_rsa_aes_wrap_parameters(mechanism: &CK_MECHANISM) -> Result<RsaAesWrapParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe { _as_ref(mechanism.pParameter as CK_RSA_AES_KEY_WRAP_PARAMS_PTR) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let aes_key_length = match parameters.ulAESKeyBits {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    let oaep_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        pParameter: parameters.pOAEPParams.cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    Ok(RsaAesWrapParameters {
        aes_key_length,
        oaep: parse_rsa_oaep_parameters(&oaep_mechanism)?,
    })
}

fn yubihsm_rsa_aes_parameters(
    parameters: &RsaAesWrapParameters,
) -> Result<(u8, u8, u8, &[u8]), Error> {
    let aes_algorithm = match parameters.aes_key_length {
        16 => YUBIHSM_ALGO_AES128,
        24 => YUBIHSM_ALGO_AES192,
        32 => YUBIHSM_ALGO_AES256,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    let (mgf, hash_mechanism, label_digest) = &parameters.oaep;
    let (hash_algorithm, _) = rsa_wrap_hash_algorithm(*hash_mechanism)?;
    let mgf1_algorithm = match *mgf {
        32 => YUBIHSM_ALGO_MGF1_SHA1,
        33 => YUBIHSM_ALGO_MGF1_SHA256,
        34 => YUBIHSM_ALGO_MGF1_SHA384,
        35 => YUBIHSM_ALGO_MGF1_SHA512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    Ok((aes_algorithm, hash_algorithm, mgf1_algorithm, label_digest))
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
            let parameters = parse_rsa_aes_wrap_parameters(mechanism)?;
            yubihsm_rsa_aes_parameters(&parameters)?;
            Ok(YubiHsmWrapMechanism::Rsa {
                full_object: x == CKM_YUBICO_RSA_WRAP,
                parameters,
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

enum SoftwareWrapMechanism {
    Aes(SoftwareAesWrapMechanism),
    RsaPkcs,
    RsaOaep(RsaOaepParameters),
    RsaAes(RsaAesWrapParameters),
}

enum SoftwareWrappingKey<'a> {
    Aes(&'a [u8]),
    Rsa(RsaPublicKey),
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

fn parse_software_wrap_mechanism(mechanism: &CK_MECHANISM) -> Result<SoftwareWrapMechanism, Error> {
    match mechanism.mechanism {
        x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
            || x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE =>
        {
            Ok(SoftwareWrapMechanism::Aes(
                parse_software_aes_wrap_mechanism(mechanism)?,
            ))
        }
        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Ok(SoftwareWrapMechanism::RsaPkcs)
        }
        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => Ok(SoftwareWrapMechanism::RsaOaep(
            parse_rsa_oaep_parameters(mechanism)?,
        )),
        x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE => Ok(SoftwareWrapMechanism::RsaAes(
            parse_rsa_aes_wrap_parameters(mechanism)?,
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

fn software_rsa_wrap(
    mechanism: &SoftwareWrapMechanism,
    wrapping_key: &RsaPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    match mechanism {
        SoftwareWrapMechanism::RsaPkcs => rsa_pkcs1_encrypt(wrapping_key, input),
        SoftwareWrapMechanism::RsaOaep((mgf, hash_mechanism, label_digest)) => {
            let encoded = Zeroizing::new(rsa_oaep_pad(
                input,
                wrapping_key.size(),
                *mgf,
                *hash_mechanism,
                label_digest,
            )?);
            rsa_public_operation(wrapping_key, &encoded)
        }
        SoftwareWrapMechanism::Aes(_) | SoftwareWrapMechanism::RsaAes(_) => {
            Err(CKR_MECHANISM_INVALID.into())
        }
    }
}

fn software_wrapped_key_length(
    mechanism: &SoftwareWrapMechanism,
    wrapping_key: &SoftwareWrappingKey<'_>,
    input_length: usize,
) -> Result<usize, Error> {
    match (mechanism, wrapping_key) {
        (
            SoftwareWrapMechanism::Aes(SoftwareAesWrapMechanism::Kw(_)),
            SoftwareWrappingKey::Aes(_),
        ) => {
            if input_length < 16 || !crate::is_multiple_of(input_length, 8) {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            input_length.checked_add(8).ok_or(CKR_KEY_SIZE_RANGE.into())
        }
        (
            SoftwareWrapMechanism::Aes(SoftwareAesWrapMechanism::Kwp(_)),
            SoftwareWrappingKey::Aes(_),
        ) => {
            if input_length == 0 || input_length > u32::MAX as usize {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            input_length
                .div_ceil(8)
                .checked_add(1)
                .and_then(|semiblocks| semiblocks.checked_mul(8))
                .ok_or(CKR_KEY_SIZE_RANGE.into())
        }
        (SoftwareWrapMechanism::RsaPkcs, SoftwareWrappingKey::Rsa(key)) => {
            if input_length > key.size().saturating_sub(11) {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            Ok(key.size())
        }
        (SoftwareWrapMechanism::RsaOaep((_, _, label_digest)), SoftwareWrappingKey::Rsa(key)) => {
            if input_length > key.size().saturating_sub(2 * label_digest.len() + 2) {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            Ok(key.size())
        }
        (SoftwareWrapMechanism::RsaAes(parameters), SoftwareWrappingKey::Rsa(key)) => {
            if input_length == 0 || input_length > u32::MAX as usize {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let (_, hash_mechanism, label_digest) = &parameters.oaep;
            let digest = digest_for_hash_mechanism(*hash_mechanism)?;
            if parameters.aes_key_length > key.size().saturating_sub(2 * digest.size() + 2)
                || label_digest.len() != digest.size()
            {
                return Err(CKR_WRAPPING_KEY_SIZE_RANGE.into());
            }
            let wrapped_target_length = input_length
                .div_ceil(8)
                .checked_add(1)
                .and_then(|semiblocks| semiblocks.checked_mul(8))
                .ok_or(CKR_KEY_SIZE_RANGE)?;
            key.size()
                .checked_add(wrapped_target_length)
                .ok_or(CKR_KEY_SIZE_RANGE.into())
        }
        _ => Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn software_rsa_unwrap(
    mechanism: &SoftwareWrapMechanism,
    unwrapping_key: &RsaPrivateKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    if input.len() != unwrapping_key.size() {
        return Err(CKR_WRAPPED_KEY_LEN_RANGE.into());
    }
    let decoded = Zeroizing::new(
        rsa_private_operation(unwrapping_key, input).map_err(software_unwrap_error)?,
    );
    match mechanism {
        SoftwareWrapMechanism::RsaPkcs => {
            rsa_pkcs1_v1_5_unpad(&decoded).map_err(software_unwrap_error)
        }
        SoftwareWrapMechanism::RsaOaep((mgf, hash_mechanism, label_digest)) => {
            rsa_oaep_unpad(&decoded, *mgf, *hash_mechanism, label_digest)
                .map_err(software_unwrap_error)
        }
        SoftwareWrapMechanism::Aes(_) | SoftwareWrapMechanism::RsaAes(_) => {
            Err(CKR_MECHANISM_INVALID.into())
        }
    }
}

fn software_rsa_aes_wrap(
    parameters: &RsaAesWrapParameters,
    wrapping_key: &RsaPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut temporary_key = Zeroizing::new(vec![0; parameters.aes_key_length]);
    getrandom::fill(&mut temporary_key).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
    let rsa_mechanism = SoftwareWrapMechanism::RsaOaep(parameters.oaep.clone());
    let wrapped_temporary_key = software_rsa_wrap(&rsa_mechanism, wrapping_key, &temporary_key)?;
    let kwp = SoftwareAesWrapMechanism::Kwp(vec![0xa6, 0x59, 0x59, 0xa6]);
    let wrapped_target = transform_software_wrapped_key(&kwp, &temporary_key, input, true)?;
    let mut output = Vec::with_capacity(wrapped_temporary_key.len() + wrapped_target.len());
    output.extend_from_slice(&wrapped_temporary_key);
    output.extend_from_slice(&wrapped_target);
    Ok(output)
}

fn software_rsa_aes_unwrap(
    parameters: &RsaAesWrapParameters,
    unwrapping_key: &RsaPrivateKey,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let rsa_length = unwrapping_key.size();
    if input.len() < rsa_length.saturating_add(16) {
        return Err(CKR_WRAPPED_KEY_LEN_RANGE.into());
    }
    let (wrapped_temporary_key, wrapped_target) = input.split_at(rsa_length);
    let rsa_mechanism = SoftwareWrapMechanism::RsaOaep(parameters.oaep.clone());
    let temporary_key = Zeroizing::new(software_rsa_unwrap(
        &rsa_mechanism,
        unwrapping_key,
        wrapped_temporary_key,
    )?);
    if temporary_key.len() != parameters.aes_key_length {
        return Err(CKR_WRAPPED_KEY_INVALID.into());
    }
    let kwp = SoftwareAesWrapMechanism::Kwp(vec![0xa6, 0x59, 0x59, 0xa6]);
    transform_software_wrapped_key(&kwp, &temporary_key, wrapped_target, false)
        .map_err(software_unwrap_error)
}

fn software_unwrap_template(template: &[CK_ATTRIBUTE]) -> Result<TokenObject, Error> {
    validate_unique_template(template)?;
    let requested_class = template
        .iter()
        .find(|attribute| attribute.type_ == CKA_CLASS as CK_ATTRIBUTE_TYPE)
        .map(read_ulong_template_attribute)
        .transpose()
        .map_err(Error::from)?;
    let requested_key_type = template
        .iter()
        .find(|attribute| attribute.type_ == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
        .map(read_ulong_template_attribute)
        .transpose()
        .map_err(Error::from)?;
    let class = requested_class.unwrap_or_else(|| {
        if requested_key_type.is_some_and(|key_type| {
            matches!(
                key_type,
                x if x == CKK_RSA as CK_KEY_TYPE
                    || x == CKK_EC as CK_KEY_TYPE
                    || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                    || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE
            )
        }) {
            CKO_PRIVATE_KEY as CK_OBJECT_CLASS
        } else {
            CKO_SECRET_KEY as CK_OBJECT_CLASS
        }
    });
    let mut parsed = match class {
        x if x == CKO_SECRET_KEY as CK_OBJECT_CLASS => TokenObjectTemplate {
            class: Some(class),
            ..TokenObjectTemplate::default()
        },
        x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => TokenObjectTemplate {
            class: Some(class),
            private: true,
            extractable: Some(true),
            ..TokenObjectTemplate::default()
        },
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };
    for attribute in template {
        parsed.apply_attribute(attribute).map_err(Error::from)?;
    }
    let mut object = if class == CKO_SECRET_KEY as CK_OBJECT_CLASS {
        parsed.into_software_secret_object()
    } else {
        parsed.into_object()
    }
    .map_err(Error::from)?;
    let supported = if object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS {
        object.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE
            || object.key_type == CKK_AES as CK_KEY_TYPE
            || is_hmac_key_type(object.key_type)
    } else {
        object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            && matches!(
                object.key_type,
                x if x == CKK_RSA as CK_KEY_TYPE
                    || x == CKK_EC as CK_KEY_TYPE
                    || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                    || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE
            )
    };
    if !supported
        || (object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS && object.token && !object.private)
    {
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

fn software_wrap_error(error: Error) -> Error {
    match error {
        Error::Generic(rv)
            if rv == CKR_DATA_LEN_RANGE as CK_RV || rv == CKR_ENCRYPTED_DATA_LEN_RANGE as CK_RV =>
        {
            CKR_KEY_SIZE_RANGE.into()
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
            let parsed_mechanism = parse_software_wrap_mechanism(mechanism)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_WRAP as CK_FLAGS)?;
            let target = ctx
                .resolve_object(key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_KEY_HANDLE_INVALID)?;
            if !target.extractable || target.never_extractable {
                return Err(CKR_KEY_UNEXTRACTABLE.into());
            }
            let (target_value, private_target) = match &target.material {
                KeyMaterial::SoftwareSecret(value) => (Zeroizing::new(value.to_vec()), false),
                KeyMaterial::SoftwarePrivate(material) => {
                    (crate::software_storage::material_to_pkcs8(material)?, true)
                }
                _ => return Err(CKR_KEY_NOT_WRAPPABLE.into()),
            };
            if private_target
                && !matches!(
                    parsed_mechanism,
                    SoftwareWrapMechanism::Aes(SoftwareAesWrapMechanism::Kwp(_))
                        | SoftwareWrapMechanism::RsaAes(_)
                )
            {
                return Err(CKR_KEY_NOT_WRAPPABLE.into());
            }
            if private_target
                && !ctx
                    .get_slot(slot_id)?
                    .supports_software_private_operations()
            {
                return Err(CKR_KEY_NOT_WRAPPABLE.into());
            }
            let wrapper = ctx
                .resolve_object(wrapping_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
            if !wrapper.can_wrap() {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let wrapping_material = match &parsed_mechanism {
                SoftwareWrapMechanism::Aes(_) => {
                    let KeyMaterial::SoftwareSecret(wrapping_value) = &wrapper.material else {
                        return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
                    };
                    if wrapper.key_type != CKK_AES as CK_KEY_TYPE {
                        return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
                    }
                    SoftwareWrappingKey::Aes(wrapping_value)
                }
                SoftwareWrapMechanism::RsaPkcs
                | SoftwareWrapMechanism::RsaOaep(_)
                | SoftwareWrapMechanism::RsaAes(_) => {
                    if wrapper.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                        || wrapper.key_type != CKK_RSA as CK_KEY_TYPE
                    {
                        return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
                    }
                    let PublicKeyMaterial::Rsa(public_key) = wrapper
                        .projected_public_key()
                        .map_err(|_| Error::from(CKR_WRAPPING_KEY_TYPE_INCONSISTENT))?
                    else {
                        return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into());
                    };
                    SoftwareWrappingKey::Rsa(public_key)
                }
            };
            let required = software_wrapped_key_length(
                &parsed_mechanism,
                &wrapping_material,
                target_value.len(),
            )?;
            if wrapped_key.is_null() {
                *output_len = required as CK_ULONG;
                return Ok(());
            }
            if *output_len < required as CK_ULONG {
                *output_len = required as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL.into());
            }
            let response = match (&parsed_mechanism, &wrapping_material) {
                (SoftwareWrapMechanism::Aes(aes), SoftwareWrappingKey::Aes(key)) => {
                    transform_software_wrapped_key(aes, key, &target_value, true)
                        .map_err(software_wrap_error)?
                }
                (
                    SoftwareWrapMechanism::RsaPkcs | SoftwareWrapMechanism::RsaOaep(_),
                    SoftwareWrappingKey::Rsa(key),
                ) => software_rsa_wrap(&parsed_mechanism, key, &target_value)
                    .map_err(software_wrap_error)?,
                (SoftwareWrapMechanism::RsaAes(parameters), SoftwareWrappingKey::Rsa(key)) => {
                    software_rsa_aes_wrap(parameters, key, &target_value)
                        .map_err(software_wrap_error)?
                }
                _ => return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT.into()),
            };
            if response.len() != required {
                return Err(CKR_DEVICE_ERROR.into());
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
            } => {
                let (aes_algorithm, hash_algorithm, mgf1_algorithm, label_digest) =
                    yubihsm_rsa_aes_parameters(parameters)?;
                YubiHsmCommand::rsa_wrap(
                    if *full_object {
                        YubiHsmCommandCode::ExportRsaWrapped
                    } else {
                        YubiHsmCommandCode::GetRsaWrappedKey
                    },
                    &YubiHsmRsaWrapParameters {
                        wrapping_key_id,
                        object_type: target_type,
                        object_id: target_id,
                        aes_algorithm,
                        hash_algorithm,
                        mgf1_algorithm,
                        label_digest,
                    },
                )?
            }
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
            let parsed_mechanism = parse_software_wrap_mechanism(mechanism)?;
            require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_UNWRAP as CK_FLAGS)?;
            let mut object = software_unwrap_template(template)?;
            let private_target = object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
            if private_target
                && !matches!(
                    parsed_mechanism,
                    SoftwareWrapMechanism::Aes(SoftwareAesWrapMechanism::Kwp(_))
                        | SoftwareWrapMechanism::RsaAes(_)
                )
            {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            if private_target
                && !ctx
                    .get_slot(slot_id)?
                    .supports_software_private_operations()
            {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            validate_new_object_access(&object, flags, logged_in)?;
            let wrapper = ctx
                .resolve_object(unwrapping_key)?
                .filter(|object| object.is_visible_to(logged_in))
                .ok_or(CKR_UNWRAPPING_KEY_HANDLE_INVALID)?;
            if !wrapper.can_unwrap() {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            let value = Zeroizing::new(match &parsed_mechanism {
                SoftwareWrapMechanism::Aes(aes) => {
                    let KeyMaterial::SoftwareSecret(unwrapping_value) = &wrapper.material else {
                        return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
                    };
                    if wrapper.key_type != CKK_AES as CK_KEY_TYPE {
                        return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
                    }
                    transform_software_wrapped_key(aes, unwrapping_value, wrapped, false)
                        .map_err(software_unwrap_error)?
                }
                SoftwareWrapMechanism::RsaPkcs
                | SoftwareWrapMechanism::RsaOaep(_)
                | SoftwareWrapMechanism::RsaAes(_) => {
                    if wrapper.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                        || wrapper.key_type != CKK_RSA as CK_KEY_TYPE
                    {
                        return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
                    }
                    let KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(private_key)) =
                        &wrapper.material
                    else {
                        return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT.into());
                    };
                    match &parsed_mechanism {
                        SoftwareWrapMechanism::RsaAes(parameters) => {
                            software_rsa_aes_unwrap(parameters, private_key, wrapped)?
                        }
                        _ => software_rsa_unwrap(&parsed_mechanism, private_key, wrapped)?,
                    }
                }
            });
            if private_target {
                let material = crate::software_storage::material_from_bare_pkcs8(value.as_ref())
                    .map_err(software_unwrap_error)?;
                if material.key_type() != object.key_type {
                    return Err(CKR_WRAPPED_KEY_INVALID.into());
                }
                object.public_key = Some(material.public_key()?);
                object.material = KeyMaterial::SoftwarePrivate(material);
                *output_handle = if object.token {
                    persist_software_private_object(ctx, slot_id, &object)?
                } else {
                    object.set_creator(session_handle, slot_id);
                    ctx.insert_object(object)?
                };
            } else {
                validate_software_secret_length(object.key_type, value.len())?;
                object.material = KeyMaterial::SoftwareSecret(value);
                *output_handle =
                    publish_software_secret_object(ctx, session_handle, slot_id, object)?;
            }
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
            } => {
                let (_, hash_algorithm, mgf1_algorithm, label_digest) =
                    yubihsm_rsa_aes_parameters(parameters)?;
                YubiHsmCommand::import_rsa_wrapped(
                    unwrapping_key_id,
                    hash_algorithm,
                    mgf1_algorithm,
                    wrapped,
                    label_digest,
                )?
            }
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
                let (_, hash_algorithm, mgf1_algorithm, label_digest) =
                    yubihsm_rsa_aes_parameters(parameters)?;
                let command = YubiHsmCommand::put_rsa_wrapped_key(
                    unwrapping_key_id,
                    target_type,
                    &parsed.parameters(),
                    hash_algorithm,
                    mgf1_algorithm,
                    wrapped,
                    label_digest,
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
