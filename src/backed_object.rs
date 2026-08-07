use crate::key_metadata::{
    cryptoki_ulong_to_u64, BackedKeyMetadata, KeyAttributeValue, KeyAttributes, KeyBacking,
};
use crate::storage::{ContentReference, StorageError, StorageProvider};
use crate::*;
use minicbor::{Decoder, Encoder};
use rsa::{traits::PublicKeyParts, BigUint, RsaPublicKey};

pub(crate) const PUBLIC_KEY_PROVIDER: &str = "pkcs11rs.public-key";
const PREVIEW_SIGN_REGISTRATION_PROVIDER: &str = "pkcs11rs.preview-sign-registration";
const PREVIEW_SIGN_DERIVED_PROVIDER: &str = "pkcs11rs.preview-sign-derived";
const PUBLIC_KEY_SCHEMA: &str = "pkcs11rs.public-key-material";
const PUBLIC_KEY_SCHEMA_VERSION: u64 = 1;
const PUBLIC_KEY_KIND_RSA: u64 = 1;
const PUBLIC_KEY_KIND_EC: u64 = 2;
const BACKED_KEY_SCHEMA: &str = "pkcs11rs.backed-key";

pub(crate) struct EncodedBackedObject {
    pub(crate) object: Vec<u8>,
    pub(crate) dependencies: Vec<Vec<u8>>,
}

fn metadata_error(_: crate::key_metadata::KeyMetadataError) -> Error {
    CKR_DATA_INVALID.into()
}

pub(crate) fn storage_error(error: StorageError) -> Error {
    match error {
        StorageError::Unavailable => CKR_TOKEN_WRITE_PROTECTED.into(),
        StorageError::InvalidReference
        | StorageError::InvalidCbor
        | StorageError::UnsupportedHashAlgorithm(_) => CKR_DATA_INVALID.into(),
        StorageError::Io(_)
        | StorageError::Integrity
        | StorageError::Conflict
        | StorageError::Provider(_) => CKR_DEVICE_ERROR.into(),
    }
}

fn insert(
    attributes: &mut KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
    value: KeyAttributeValue,
) -> Result<(), Error> {
    attributes
        .insert(cryptoki_ulong_to_u64(attribute), value)
        .map(|_| ())
        .map_err(metadata_error)
}

fn object_attributes(object: &TokenObject) -> Result<KeyAttributes, Error> {
    let mut attributes = KeyAttributes::new();
    for (attribute, value) in [
        (
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(object.key_type)),
        ),
        (
            CKA_LABEL as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Text(object.label.clone()),
        ),
        (
            CKA_ID as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Bytes(object.id.clone()),
        ),
        (
            CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.private),
        ),
        (
            CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.encrypt),
        ),
        (
            CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.decrypt),
        ),
        (
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.sign),
        ),
        (
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.verify),
        ),
        (
            CKA_DERIVE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.derive),
        ),
        (
            CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.sensitive),
        ),
        (
            CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.extractable),
        ),
        (
            CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.always_sensitive),
        ),
        (
            CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.never_extractable),
        ),
        (
            CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.local),
        ),
    ] {
        insert(&mut attributes, attribute, value)?;
    }
    if let Some(mechanism) = object.key_gen_mechanism {
        insert(
            &mut attributes,
            CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(mechanism)),
        )?;
    }
    if let Some(mechanisms) = &object.allowed_mechanisms {
        insert(
            &mut attributes,
            CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Mechanisms(
                mechanisms
                    .iter()
                    .copied()
                    .map(cryptoki_ulong_to_u64)
                    .collect(),
            ),
        )?;
    }
    if matches!(
        object.class,
        x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS || x == CKO_SECRET_KEY as CK_OBJECT_CLASS
    ) {
        insert(
            &mut attributes,
            CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Boolean(object.wrap_with_trusted),
        )?;
    }
    for (attribute, template) in [
        (
            CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
            object.policy_templates.wrap.as_ref(),
        ),
        (
            CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
            object.policy_templates.unwrap.as_ref(),
        ),
        (
            CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE,
            object.policy_templates.derive.as_ref(),
        ),
    ] {
        if let Some(template) = template {
            insert(
                &mut attributes,
                attribute,
                KeyAttributeValue::Template(template.clone()),
            )?;
        }
    }
    if let Some(public_key_info) = object.public_key_info() {
        insert(
            &mut attributes,
            CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE,
            KeyAttributeValue::Bytes(public_key_info),
        )?;
    }
    Ok(attributes)
}

fn encode_public_key_material(object: &TokenObject) -> Result<Vec<u8>, Error> {
    let public_key = object.projected_public_key()?;
    let (kind, first, second, requires_uncompressed_prefix) = match &public_key {
        PublicKeyMaterial::Rsa(public) => (
            PUBLIC_KEY_KIND_RSA,
            public.n().to_bytes_be(),
            public.e().to_bytes_be(),
            false,
        ),
        PublicKeyMaterial::Ec {
            parameters,
            public_key,
        } => (
            PUBLIC_KEY_KIND_EC,
            parameters.clone(),
            public_key.clone(),
            object.key_type == CKK_EC as CK_KEY_TYPE,
        ),
    };
    let rp_id = object.rp_id.clone();
    let count = 7 + usize::from(rp_id.is_some());
    let mut encoded = Vec::new();
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .map(u64::try_from(count).map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(PUBLIC_KEY_SCHEMA))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.u8(PUBLIC_KEY_SCHEMA_VERSION as u8))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.u64(kind))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.u64(cryptoki_ulong_to_u64(object.key_type)))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.bytes(&first))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.bytes(&second))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.bool(requires_uncompressed_prefix))
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    if let Some(rp_id) = rp_id {
        encoder
            .u8(8)
            .and_then(|encoder| encoder.str(&rp_id))
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    }
    Ok(encoded)
}

fn encode_record(object: &TokenObject, provider: &str, backing: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut record =
        BackedKeyMetadata::new(KeyBacking::new(provider, backing).map_err(metadata_error)?);
    record
        .insert_aspect(
            cryptoki_ulong_to_u64(object.class),
            object_attributes(object)?,
        )
        .map_err(metadata_error)?;
    record.to_cbor().map_err(metadata_error)
}

pub(crate) fn encode_backed_object(object: &TokenObject) -> Result<EncodedBackedObject, Error> {
    match &object.material {
        KeyMaterial::Public(_) if object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS => {
            Ok(EncodedBackedObject {
                object: encode_record(
                    object,
                    PUBLIC_KEY_PROVIDER,
                    encode_public_key_material(object)?,
                )?,
                dependencies: Vec::new(),
            })
        }
        KeyMaterial::PreviewSignRegistration { registration }
            if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS =>
        {
            let registration = registration
                .to_cbor()
                .map_err(|_| Error::from(CKR_DATA_INVALID))?;
            Ok(EncodedBackedObject {
                object: encode_record(
                    object,
                    PREVIEW_SIGN_REGISTRATION_PROVIDER,
                    registration.clone(),
                )?,
                dependencies: vec![registration],
            })
        }
        KeyMaterial::PreviewSignDerived {
            registration,
            derived,
            ..
        } if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
            let registration = registration
                .to_cbor()
                .map_err(|_| Error::from(CKR_DATA_INVALID))?;
            if derived.registration() != &ContentReference::for_object(&registration) {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(EncodedBackedObject {
                object: encode_record(
                    object,
                    PREVIEW_SIGN_DERIVED_PROVIDER,
                    derived
                        .to_cbor()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?,
                )?,
                dependencies: vec![registration],
            })
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

pub(crate) fn supports_backed_object(object: &TokenObject) -> bool {
    matches!(
        (&object.material, object.class),
        (
            KeyMaterial::Public(_),
            class
        ) if class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
    ) || matches!(
        (&object.material, object.class),
        (
            KeyMaterial::PreviewSignRegistration { .. }
                | KeyMaterial::PreviewSignDerived { .. },
            class
        ) if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
    )
}

pub(crate) fn put_backed_object(
    provider: &dyn StorageProvider,
    object: &TokenObject,
) -> Result<ContentReference, Error> {
    if !provider.supports_mutation() {
        return Err(CKR_TOKEN_WRITE_PROTECTED.into());
    }
    let encoded = encode_backed_object(object)?;
    for dependency in encoded.dependencies {
        provider.put(&dependency).map_err(storage_error)?;
    }
    provider.put(&encoded.object).map_err(storage_error)
}

fn required_unsigned(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<u64, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Unsigned(value)) => Ok(*value),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn required_bool(attributes: &KeyAttributes, attribute: CK_ATTRIBUTE_TYPE) -> Result<bool, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Boolean(value)) => Ok(*value),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn required_bytes(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Bytes(value)) => Ok(value.clone()),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn required_text(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<String, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Text(value)) => Ok(value.clone()),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn optional_unsigned(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Option<u64>, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Unsigned(value)) => Ok(Some(*value)),
        None => Ok(None),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn optional_bool(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Option<bool>, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Boolean(value)) => Ok(Some(*value)),
        None => Ok(None),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn optional_mechanisms(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Option<Vec<CK_MECHANISM_TYPE>>, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Mechanisms(values)) => {
            let mechanisms = values
                .iter()
                .copied()
                .map(CK_MECHANISM_TYPE::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::from(CKR_DATA_INVALID))?;
            if mechanisms.len() > 256 || mechanisms.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(Some(mechanisms))
        }
        None => Ok(None),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn optional_template(
    attributes: &KeyAttributes,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Option<KeyAttributes>, Error> {
    match attributes.get(cryptoki_ulong_to_u64(attribute)) {
        Some(KeyAttributeValue::Template(value)) => Ok(Some(value.clone())),
        None => Ok(None),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn decode_public_key_material(
    encoded: &[u8],
) -> Result<(CK_KEY_TYPE, KeyMaterial, Option<String>), Error> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder
        .map()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?
        .ok_or(CKR_DATA_INVALID)?;
    let mut schema = None;
    let mut version = None;
    let mut kind = None;
    let mut key_type = None;
    let mut first = None;
    let mut second = None;
    let mut prefix = None;
    let mut rp_id = None;
    for _ in 0..count {
        match decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))? {
            1 if schema.is_none() => {
                schema = Some(
                    decoder
                        .str()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_owned(),
                )
            }
            2 if version.is_none() => {
                version = Some(decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            3 if kind.is_none() => {
                kind = Some(decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            4 if key_type.is_none() => {
                key_type = Some(decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            5 if first.is_none() => {
                first = Some(
                    decoder
                        .bytes()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_vec(),
                )
            }
            6 if second.is_none() => {
                second = Some(
                    decoder
                        .bytes()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_vec(),
                )
            }
            7 if prefix.is_none() => {
                prefix = Some(decoder.bool().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            8 if rp_id.is_none() => {
                rp_id = Some(
                    decoder
                        .str()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_owned(),
                )
            }
            _ => return Err(CKR_DATA_INVALID.into()),
        }
    }
    if decoder.position() != encoded.len()
        || schema.as_deref() != Some(PUBLIC_KEY_SCHEMA)
        || version != Some(PUBLIC_KEY_SCHEMA_VERSION)
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let key_type = CK_KEY_TYPE::try_from(key_type.ok_or(CKR_DATA_INVALID)?)
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let first = first.ok_or(CKR_DATA_INVALID)?;
    let second = second.ok_or(CKR_DATA_INVALID)?;
    let prefix = prefix.ok_or(CKR_DATA_INVALID)?;
    let material = match kind.ok_or(CKR_DATA_INVALID)? {
        PUBLIC_KEY_KIND_RSA if key_type == CKK_RSA as CK_KEY_TYPE && !prefix => {
            KeyMaterial::Public(PublicKeyMaterial::Rsa(
                RsaPublicKey::new(
                    BigUint::from_bytes_be(&first),
                    BigUint::from_bytes_be(&second),
                )
                .map_err(|_| Error::from(CKR_DATA_INVALID))?,
            ))
        }
        PUBLIC_KEY_KIND_EC
            if matches!(
                key_type,
                x if x == CKK_EC as CK_KEY_TYPE
                    || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                    || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE
            ) =>
        {
            if prefix != (key_type == CKK_EC as CK_KEY_TYPE) {
                return Err(CKR_DATA_INVALID.into());
            }
            KeyMaterial::Public(PublicKeyMaterial::Ec {
                parameters: first,
                public_key: second,
            })
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    };
    Ok((key_type, material, rp_id))
}

/// Convert any operational public-key object to the canonical software-backed
/// material used by projected and provider-restored public keys.
pub(crate) fn projected_public_key_material(object: &TokenObject) -> Result<KeyMaterial, Error> {
    if object.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let (key_type, material, _) = decode_public_key_material(&encode_public_key_material(object)?)?;
    if key_type != object.key_type {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    Ok(material)
}

fn materialize_object(
    slot_id: CK_SLOT_ID,
    token: bool,
    reference: &ContentReference,
    class: CK_OBJECT_CLASS,
    attributes: &KeyAttributes,
    material: KeyMaterial,
    rp_id: Option<String>,
) -> Result<TokenObject, Error> {
    let key_type = CK_KEY_TYPE::try_from(required_unsigned(
        attributes,
        CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
    )?)
    .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let key_gen_mechanism =
        optional_unsigned(attributes, CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE)?
            .map(CK_MECHANISM_TYPE::try_from)
            .transpose()
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let allowed_mechanisms =
        optional_mechanisms(attributes, CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE)?;
    let wrap_with_trusted =
        optional_bool(attributes, CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE)?.unwrap_or(false);
    let policy_templates = crate::KeyPolicyTemplates {
        wrap: optional_template(attributes, CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE)?,
        unwrap: optional_template(attributes, CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE)?,
        derive: optional_template(attributes, CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE)?,
    };
    let object = TokenObject {
        slot_id: token.then_some(slot_id),
        unique_id: backed_object_unique_id(reference),
        class,
        key_type,
        label: required_text(attributes, CKA_LABEL as CK_ATTRIBUTE_TYPE)?,
        id: required_bytes(attributes, CKA_ID as CK_ATTRIBUTE_TYPE)?,
        token,
        private: required_bool(attributes, CKA_PRIVATE as CK_ATTRIBUTE_TYPE)?,
        encrypt: required_bool(attributes, CKA_ENCRYPT as CK_ATTRIBUTE_TYPE)?,
        decrypt: required_bool(attributes, CKA_DECRYPT as CK_ATTRIBUTE_TYPE)?,
        sign: required_bool(attributes, CKA_SIGN as CK_ATTRIBUTE_TYPE)?,
        verify: required_bool(attributes, CKA_VERIFY as CK_ATTRIBUTE_TYPE)?,
        derive: required_bool(attributes, CKA_DERIVE as CK_ATTRIBUTE_TYPE)?,
        wrap: false,
        unwrap: false,
        sensitive: required_bool(attributes, CKA_SENSITIVE as CK_ATTRIBUTE_TYPE)?,
        extractable: required_bool(attributes, CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)?,
        always_sensitive: required_bool(attributes, CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE)?,
        never_extractable: required_bool(attributes, CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE)?,
        local: required_bool(attributes, CKA_LOCAL as CK_ATTRIBUTE_TYPE)?,
        key_gen_mechanism,
        allowed_mechanisms,
        wrap_with_trusted,
        policy_templates,
        creator_session: None,
        public_key: None,
        rp_id,
        material,
    };
    if object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS {
        let expected = required_bytes(attributes, CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)?;
        if object.public_key_info().as_deref() != Some(expected.as_slice()) {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    Ok(object)
}

pub(crate) fn decode_backed_object(
    provider: &dyn StorageProvider,
    slot_id: CK_SLOT_ID,
    token: bool,
    reference: &ContentReference,
    encoded: &[u8],
) -> Result<Option<TokenObject>, Error> {
    let record = match BackedKeyMetadata::from_cbor(encoded) {
        Ok(record) => record,
        Err(_) if declares_backed_key_schema(encoded) => return Err(CKR_DATA_INVALID.into()),
        Err(_) => return Ok(None),
    };
    match record.backing().provider() {
        PUBLIC_KEY_PROVIDER => {
            let attributes = record
                .aspect(u64::from(CKO_PUBLIC_KEY))
                .ok_or(CKR_DATA_INVALID)?;
            if record.aspects().count() != 1 {
                return Err(CKR_DATA_INVALID.into());
            }
            let (key_type, material, rp_id) =
                decode_public_key_material(record.backing().data_cbor())?;
            if required_unsigned(attributes, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
                != cryptoki_ulong_to_u64(key_type)
            {
                return Err(CKR_DATA_INVALID.into());
            }
            materialize_object(
                slot_id,
                token,
                reference,
                CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                attributes,
                material,
                rp_id,
            )
            .map(Some)
        }
        PREVIEW_SIGN_REGISTRATION_PROVIDER => {
            let attributes = record
                .aspect(u64::from(CKO_PRIVATE_KEY))
                .ok_or(CKR_DATA_INVALID)?;
            if record.aspects().count() != 1
                || required_unsigned(attributes, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
                    != cryptoki_ulong_to_u64(CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION)
            {
                return Err(CKR_DATA_INVALID.into());
            }
            let registration = crate::preview_sign::PreviewSignRegistration::from_cbor(
                record.backing().data_cbor(),
            )
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
            materialize_object(
                slot_id,
                token,
                reference,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                attributes,
                KeyMaterial::PreviewSignRegistration { registration },
                None,
            )
            .map(Some)
        }
        PREVIEW_SIGN_DERIVED_PROVIDER => {
            let attributes = record
                .aspect(u64::from(CKO_PRIVATE_KEY))
                .ok_or(CKR_DATA_INVALID)?;
            if record.aspects().count() != 1
                || required_unsigned(attributes, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
                    != cryptoki_ulong_to_u64(CKK_EC as CK_KEY_TYPE)
            {
                return Err(CKR_DATA_INVALID.into());
            }
            let derived = crate::preview_sign::PreviewSignDerivedKeyRecord::from_cbor(
                record.backing().data_cbor(),
            )
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
            let registration = provider
                .get(derived.registration())
                .map_err(storage_error)?
                .ok_or(CKR_DATA_INVALID)
                .and_then(|encoded| {
                    crate::preview_sign::PreviewSignRegistration::from_cbor(&encoded)
                        .map_err(|_| CKR_DATA_INVALID)
                })
                .map_err(Error::from)?;
            let projected = project_cose_public_key(derived.verification_key_cose())
                .filter(|projected| projected.key_type == CKK_EC as CK_KEY_TYPE)
                .ok_or(CKR_DATA_INVALID)?;
            materialize_object(
                slot_id,
                token,
                reference,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                attributes,
                KeyMaterial::PreviewSignDerived {
                    registration,
                    derived,
                },
                None,
            )
            .map(|mut object| {
                object.public_key = Some(projected.public_key);
                Some(object)
            })
        }
        _ => Ok(None),
    }
}

fn declares_backed_key_schema(encoded: &[u8]) -> bool {
    let mut decoder = Decoder::new(encoded);
    let Some(count) = decoder.map().ok().flatten() else {
        return false;
    };
    for _ in 0..count {
        let Ok(key) = decoder.u64() else {
            return false;
        };
        if key == 1 {
            return decoder.str().ok() == Some(BACKED_KEY_SCHEMA);
        }
        if decoder.skip().is_err() {
            return false;
        }
    }
    false
}

pub(crate) fn stored_objects(
    provider: &dyn StorageProvider,
    slot_id: CK_SLOT_ID,
    token: bool,
) -> Result<Vec<(ContentReference, TokenObject)>, Error> {
    let references = match provider.list() {
        Ok(references) => references,
        Err(StorageError::Unavailable) => return Ok(Vec::new()),
        Err(error) => return Err(storage_error(error)),
    };
    let mut objects = Vec::new();
    for reference in references {
        let encoded = provider
            .get(&reference)
            .map_err(storage_error)?
            .ok_or(CKR_DEVICE_ERROR)?;
        if let Some(object) = decode_backed_object(provider, slot_id, token, &reference, &encoded)?
        {
            objects.push((reference, object));
        }
    }
    Ok(objects)
}

pub(crate) fn backed_object_unique_id(reference: &ContentReference) -> String {
    let mut unique_id = String::from("pkcs11rs stored ");
    for byte in reference.digest() {
        use std::fmt::Write;
        let _ = write!(unique_id, "{byte:02x}");
    }
    unique_id
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProvider {
        reference: ContentReference,
        object: Vec<u8>,
    }

    impl StorageProvider for FixedProvider {
        fn list(&self) -> Result<Vec<ContentReference>, StorageError> {
            Ok(vec![self.reference.clone()])
        }

        fn get(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError> {
            Ok((reference == &self.reference).then(|| self.object.clone()))
        }

        fn put(&self, _object: &[u8]) -> Result<ContentReference, StorageError> {
            Err(StorageError::Unavailable)
        }

        fn delete(&self, _reference: &ContentReference) -> Result<bool, StorageError> {
            Err(StorageError::Unavailable)
        }
    }

    #[test]
    fn malformed_declared_backed_key_is_not_silently_ignored() {
        let mut object = Vec::new();
        Encoder::new(&mut object)
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .str(BACKED_KEY_SCHEMA)
            .unwrap();
        let provider = FixedProvider {
            reference: ContentReference::for_object(&object),
            object,
        };
        let error = stored_objects(&provider, 7, true).unwrap_err();
        assert_eq!(CK_RV::from(error), CKR_DATA_INVALID as CK_RV);
    }

    #[test]
    fn unrelated_cbor_objects_do_not_become_pkcs11_objects() {
        let object = [0xa1, 0x01, 0x61, 0x78].to_vec();
        let provider = FixedProvider {
            reference: ContentReference::for_object(&object),
            object,
        };
        assert!(stored_objects(&provider, 7, true).unwrap().is_empty());
    }

    #[test]
    fn backed_public_key_preserves_allowed_mechanisms() {
        let mut object = TokenObject {
            slot_id: Some(7),
            unique_id: "public-key".to_owned(),
            class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            key_type: CKK_RSA as CK_KEY_TYPE,
            label: "restricted RSA key".to_owned(),
            id: vec![1],
            token: true,
            private: false,
            encrypt: true,
            decrypt: false,
            sign: false,
            verify: true,
            derive: false,
            wrap: false,
            unwrap: false,
            sensitive: false,
            extractable: true,
            always_sensitive: false,
            never_extractable: false,
            local: true,
            key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            allowed_mechanisms: Some(vec![
                CKM_RSA_PKCS as CK_MECHANISM_TYPE,
                CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE,
            ]),
            wrap_with_trusted: false,
            policy_templates: crate::KeyPolicyTemplates::default(),
            creator_session: None,
            public_key: None,
            rp_id: None,
            material: KeyMaterial::Public(PublicKeyMaterial::Rsa(
                RsaPublicKey::new(
                    BigUint::from_bytes_be(&vec![0x11; 256]),
                    BigUint::from(65537u32),
                )
                .unwrap(),
            )),
        };
        let mut wrap_policy = KeyAttributes::new();
        wrap_policy
            .insert_template(u64::from(CKA_PRIVATE), KeyAttributeValue::Boolean(true))
            .unwrap();
        object.policy_templates.wrap = Some(wrap_policy);
        let encoded = encode_backed_object(&object).unwrap().object;
        let provider = FixedProvider {
            reference: ContentReference::for_object(&encoded),
            object: encoded,
        };

        let restored = stored_objects(&provider, 7, true).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].1.allowed_mechanisms, object.allowed_mechanisms);
        assert_eq!(restored[0].1.policy_templates, object.policy_templates);
    }
}
