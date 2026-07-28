//! Canonical metadata for a key backed by hardware or provider-specific state.
//!
//! A record describes the relationship between one backing key and its
//! potential PKCS #11 public, private, or secret-key aspects. Storage location
//! is deliberately outside the record: the same bytes can be held by any
//! [`crate::storage::StorageProvider`].

use crate::pkcs11::*;
use minicbor::{data::Type, Decoder, Encoder};
use std::{collections::BTreeMap, fmt};

const BACKED_KEY_SCHEMA: &str = "pkcs11rs.backed-key";
const BACKED_KEY_SCHEMA_VERSION: u64 = 1;
const MAX_PROVIDER_LENGTH: usize = 128;
const MAX_PROVIDER_DATA_LENGTH: usize = 16 * 1024 * 1024;
const MAX_ASPECTS: usize = 3;
const MAX_ATTRIBUTES: usize = 256;
const MAX_TEMPLATE_DEPTH: usize = 4;

/// A failure while constructing or decoding canonical backed-key metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyMetadataError {
    /// The record or one of its values is malformed.
    Malformed(&'static str),
    /// The record uses an unsupported schema version.
    UnsupportedSchemaVersion(u64),
    /// A PKCS #11 object class cannot be represented as a key aspect.
    UnsupportedClass(u64),
    /// A PKCS #11 attribute is not part of the supported key-attribute model.
    UnsupportedAttribute(u64),
    /// An attribute has the wrong semantic CBOR value type.
    InvalidAttributeType(u64),
}

impl fmt::Display for KeyMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(formatter, "malformed key metadata: {reason}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported key metadata schema version {version}"
                )
            }
            Self::UnsupportedClass(class) => {
                write!(
                    formatter,
                    "unsupported key metadata object class {class:#x}"
                )
            }
            Self::UnsupportedAttribute(attribute) => {
                write!(
                    formatter,
                    "unsupported key metadata attribute {attribute:#x}"
                )
            }
            Self::InvalidAttributeType(attribute) => {
                write!(
                    formatter,
                    "invalid value type for key metadata attribute {attribute:#x}"
                )
            }
        }
    }
}

impl std::error::Error for KeyMetadataError {}

impl From<minicbor::decode::Error> for KeyMetadataError {
    fn from(_error: minicbor::decode::Error) -> Self {
        Self::Malformed("invalid CBOR")
    }
}

impl From<minicbor::encode::Error<std::convert::Infallible>> for KeyMetadataError {
    fn from(_error: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        Self::Malformed("CBOR encoding failed")
    }
}

/// Provider-specific identity and operational state for one backing key.
///
/// `data_cbor` is retained byte-for-byte as an embedded CBOR item. The named
/// provider owns its schema and performs its semantic validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBacking {
    provider: String,
    data_cbor: Vec<u8>,
}

impl KeyBacking {
    /// Construct a provider backing from one exact CBOR data item.
    pub fn new(
        provider: impl Into<String>,
        data_cbor: impl Into<Vec<u8>>,
    ) -> Result<Self, KeyMetadataError> {
        let provider = provider.into();
        if provider.is_empty()
            || provider.len() > MAX_PROVIDER_LENGTH
            || !provider.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
        {
            return Err(KeyMetadataError::Malformed(
                "invalid backing provider identifier",
            ));
        }
        let data_cbor = data_cbor.into();
        if data_cbor.len() > MAX_PROVIDER_DATA_LENGTH {
            return Err(KeyMetadataError::Malformed(
                "backing provider data is too large",
            ));
        }
        validate_single_cbor_item(&data_cbor)?;
        Ok(Self {
            provider,
            data_cbor,
        })
    }

    /// Return the provider identifier.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Return the exact provider-owned CBOR item.
    pub fn data_cbor(&self) -> &[u8] {
        &self.data_cbor
    }
}

/// A semantic, architecture-independent value for a PKCS #11 key attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAttributeValue {
    /// A `CK_BBOOL` attribute.
    Boolean(bool),
    /// A `CK_ULONG`, flags, enum, class, type, or mechanism attribute.
    Unsigned(u64),
    /// A byte-array, big-integer, date, or encoded structure attribute.
    Bytes(Vec<u8>),
    /// An RFC 2279 or local-string attribute.
    Text(String),
    /// A `CK_MECHANISM_TYPE` array.
    Mechanisms(Vec<u64>),
    /// A nested `CK_ATTRIBUTE` template.
    Template(KeyAttributes),
}

/// A canonical map of PKCS #11 attributes for one key aspect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyAttributes {
    attributes: BTreeMap<u64, KeyAttributeValue>,
}

impl KeyAttributes {
    /// Construct an empty attribute map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one semantically typed attribute.
    ///
    /// `CKA_CLASS` and `CKA_TOKEN` are structural properties of a persisted
    /// aspect and cannot appear in this map.
    pub fn insert(
        &mut self,
        attribute: u64,
        value: KeyAttributeValue,
    ) -> Result<Option<KeyAttributeValue>, KeyMetadataError> {
        if self.attributes.len() >= MAX_ATTRIBUTES && !self.attributes.contains_key(&attribute) {
            return Err(KeyMetadataError::Malformed("too many key attributes"));
        }
        validate_attribute(attribute, &value)?;
        Ok(self.attributes.insert(attribute, value))
    }

    /// Return an attribute value.
    pub fn get(&self, attribute: u64) -> Option<&KeyAttributeValue> {
        self.attributes.get(&attribute)
    }

    /// Return whether this aspect uses entirely provider-derived defaults.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Iterate over attributes in canonical numeric order.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &KeyAttributeValue)> {
        self.attributes.iter()
    }
}

/// Canonical metadata for one backing key and its PKCS #11 key aspects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackedKeyMetadata {
    backing: KeyBacking,
    aspects: BTreeMap<u64, KeyAttributes>,
}

impl BackedKeyMetadata {
    /// Construct metadata without any projected aspects.
    pub fn new(backing: KeyBacking) -> Self {
        Self {
            backing,
            aspects: BTreeMap::new(),
        }
    }

    /// Return the backing identity and provider-owned state.
    pub fn backing(&self) -> &KeyBacking {
        &self.backing
    }

    /// Add or replace a public, private, or secret-key aspect.
    pub fn insert_aspect(
        &mut self,
        class: u64,
        attributes: KeyAttributes,
    ) -> Result<Option<KeyAttributes>, KeyMetadataError> {
        validate_key_class(class)?;
        if self.aspects.len() >= MAX_ASPECTS && !self.aspects.contains_key(&class) {
            return Err(KeyMetadataError::Malformed("too many key aspects"));
        }
        validate_attributes(&attributes)?;
        Ok(self.aspects.insert(class, attributes))
    }

    /// Return one projected key aspect.
    pub fn aspect(&self, class: u64) -> Option<&KeyAttributes> {
        self.aspects.get(&class)
    }

    /// Iterate over aspects in canonical object-class order.
    pub fn aspects(&self) -> impl Iterator<Item = (&u64, &KeyAttributes)> {
        self.aspects.iter()
    }

    /// Encode the record as canonical CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, KeyMetadataError> {
        if self.aspects.is_empty() {
            return Err(KeyMetadataError::Malformed(
                "backed key has no PKCS #11 aspects",
            ));
        }
        let mut encoded = Vec::new();
        let mut encoder = Encoder::new(&mut encoded);
        encoder
            .map(5)?
            .u8(1)?
            .str(BACKED_KEY_SCHEMA)?
            .u8(2)?
            .u8(BACKED_KEY_SCHEMA_VERSION as u8)?
            .u8(3)?
            .str(self.backing.provider())?
            .u8(4)?
            .bytes(self.backing.data_cbor())?
            .u8(5)?
            .map(
                u64::try_from(self.aspects.len())
                    .map_err(|_| KeyMetadataError::Malformed("aspect count overflow"))?,
            )?;
        for (class, attributes) in &self.aspects {
            encoder.u64(*class)?;
            encode_attributes(&mut encoder, attributes)?;
        }
        Ok(encoded)
    }

    /// Decode, validate, and require the canonical encoding of a record.
    pub fn from_cbor(encoded: &[u8]) -> Result<Self, KeyMetadataError> {
        let mut decoder = Decoder::new(encoded);
        let count = definite_map(&mut decoder, "backed key is not a definite map")?;
        let mut schema = None;
        let mut version = None;
        let mut provider = None;
        let mut provider_data = None;
        let mut aspects = None;
        for _ in 0..count {
            match decoder.u64()? {
                1 if schema.is_none() => schema = Some(decoder.str()?.to_owned()),
                1 => return Err(KeyMetadataError::Malformed("duplicate schema identifier")),
                2 if version.is_none() => version = Some(decoder.u64()?),
                2 => return Err(KeyMetadataError::Malformed("duplicate schema version")),
                3 if provider.is_none() => provider = Some(decoder.str()?.to_owned()),
                3 => return Err(KeyMetadataError::Malformed("duplicate backing provider")),
                4 if provider_data.is_none() => {
                    let data = decoder.bytes()?;
                    if data.len() > MAX_PROVIDER_DATA_LENGTH {
                        return Err(KeyMetadataError::Malformed(
                            "backing provider data is too large",
                        ));
                    }
                    provider_data = Some(data.to_vec());
                }
                4 => return Err(KeyMetadataError::Malformed("duplicate backing data")),
                5 if aspects.is_none() => aspects = Some(decode_aspects(&mut decoder)?),
                5 => return Err(KeyMetadataError::Malformed("duplicate key aspects")),
                _ => return Err(KeyMetadataError::Malformed("unknown backed-key field")),
            }
        }
        if decoder.position() != encoded.len() {
            return Err(KeyMetadataError::Malformed("trailing backed-key data"));
        }
        if schema.as_deref() != Some(BACKED_KEY_SCHEMA) {
            return Err(KeyMetadataError::Malformed("invalid schema identifier"));
        }
        let version = version.ok_or(KeyMetadataError::Malformed("missing schema version"))?;
        if version != BACKED_KEY_SCHEMA_VERSION {
            return Err(KeyMetadataError::UnsupportedSchemaVersion(version));
        }
        let backing = KeyBacking::new(
            provider.ok_or(KeyMetadataError::Malformed("missing backing provider"))?,
            provider_data.ok_or(KeyMetadataError::Malformed("missing backing data"))?,
        )?;
        let record = Self {
            backing,
            aspects: aspects.ok_or(KeyMetadataError::Malformed("missing key aspects"))?,
        };
        if record.aspects.is_empty() {
            return Err(KeyMetadataError::Malformed(
                "backed key has no PKCS #11 aspects",
            ));
        }
        if record.to_cbor()? != encoded {
            return Err(KeyMetadataError::Malformed(
                "backed key is not canonically encoded",
            ));
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttributeKind {
    Boolean,
    Unsigned,
    Bytes,
    Text,
    Mechanisms,
    Template,
}

fn validate_key_class(class: u64) -> Result<(), KeyMetadataError> {
    if matches!(
        class,
        x if x == u64::from(CKO_PUBLIC_KEY)
            || x == u64::from(CKO_PRIVATE_KEY)
            || x == u64::from(CKO_SECRET_KEY)
    ) {
        Ok(())
    } else {
        Err(KeyMetadataError::UnsupportedClass(class))
    }
}

fn validate_attributes(attributes: &KeyAttributes) -> Result<(), KeyMetadataError> {
    if attributes.attributes.len() > MAX_ATTRIBUTES {
        return Err(KeyMetadataError::Malformed("too many key attributes"));
    }
    for (attribute, value) in &attributes.attributes {
        validate_attribute(*attribute, value)?;
    }
    Ok(())
}

fn validate_attribute(attribute: u64, value: &KeyAttributeValue) -> Result<(), KeyMetadataError> {
    if attribute == u64::from(CKA_CLASS) || attribute == u64::from(CKA_TOKEN) {
        return Err(KeyMetadataError::Malformed(
            "structural attribute present in key aspect",
        ));
    }
    let expected = attribute_kind(attribute)?;
    let actual = match value {
        KeyAttributeValue::Boolean(_) => AttributeKind::Boolean,
        KeyAttributeValue::Unsigned(_) => AttributeKind::Unsigned,
        KeyAttributeValue::Bytes(_) => AttributeKind::Bytes,
        KeyAttributeValue::Text(_) => AttributeKind::Text,
        KeyAttributeValue::Mechanisms(_) => AttributeKind::Mechanisms,
        KeyAttributeValue::Template(_) => AttributeKind::Template,
    };
    if expected != actual {
        return Err(KeyMetadataError::InvalidAttributeType(attribute));
    }
    if let KeyAttributeValue::Template(attributes) = value {
        validate_attributes(attributes)?;
    }
    Ok(())
}

fn attribute_kind(attribute: u64) -> Result<AttributeKind, KeyMetadataError> {
    let kind = match attribute {
        x if x == u64::from(CKA_PRIVATE)
            || x == u64::from(CKA_MODIFIABLE)
            || x == u64::from(CKA_COPYABLE)
            || x == u64::from(CKA_DESTROYABLE)
            || x == u64::from(CKA_DERIVE)
            || x == u64::from(CKA_LOCAL)
            || x == u64::from(CKA_ENCRYPT)
            || x == u64::from(CKA_VERIFY)
            || x == u64::from(CKA_VERIFY_RECOVER)
            || x == u64::from(CKA_WRAP)
            || x == u64::from(CKA_ENCAPSULATE)
            || x == u64::from(CKA_TRUSTED)
            || x == u64::from(CKA_SENSITIVE)
            || x == u64::from(CKA_DECRYPT)
            || x == u64::from(CKA_SIGN)
            || x == u64::from(CKA_SIGN_RECOVER)
            || x == u64::from(CKA_UNWRAP)
            || x == u64::from(CKA_DECAPSULATE)
            || x == u64::from(CKA_EXTRACTABLE)
            || x == u64::from(CKA_ALWAYS_SENSITIVE)
            || x == u64::from(CKA_NEVER_EXTRACTABLE)
            || x == u64::from(CKA_WRAP_WITH_TRUSTED)
            || x == u64::from(CKA_ALWAYS_AUTHENTICATE) =>
        {
            AttributeKind::Boolean
        }
        x if x == u64::from(CKA_KEY_TYPE)
            || x == u64::from(CKA_KEY_GEN_MECHANISM)
            || x == u64::from(CKA_OBJECT_VALIDATION_FLAGS)
            || x == u64::from(CKA_MODULUS_BITS)
            || x == u64::from(CKA_VALUE_LEN) =>
        {
            AttributeKind::Unsigned
        }
        x if x == u64::from(CKA_LABEL) || x == u64::from(CKA_UNIQUE_ID) => AttributeKind::Text,
        x if x == u64::from(CKA_ALLOWED_MECHANISMS) => AttributeKind::Mechanisms,
        x if x == u64::from(CKA_WRAP_TEMPLATE)
            || x == u64::from(CKA_UNWRAP_TEMPLATE)
            || x == u64::from(CKA_DERIVE_TEMPLATE) =>
        {
            AttributeKind::Template
        }
        x if x == u64::from(CKA_ID)
            || x == u64::from(CKA_START_DATE)
            || x == u64::from(CKA_END_DATE)
            || x == u64::from(CKA_SUBJECT)
            || x == u64::from(CKA_PUBLIC_KEY_INFO)
            || x == u64::from(CKA_PUBLIC_CRC64_VALUE)
            || x == u64::from(CKA_CHECK_VALUE)
            || x == u64::from(CKA_MODULUS)
            || x == u64::from(CKA_PUBLIC_EXPONENT)
            || x == u64::from(CKA_PRIVATE_EXPONENT)
            || x == u64::from(CKA_PRIME_1)
            || x == u64::from(CKA_PRIME_2)
            || x == u64::from(CKA_EXPONENT_1)
            || x == u64::from(CKA_EXPONENT_2)
            || x == u64::from(CKA_COEFFICIENT)
            || x == u64::from(CKA_EC_PARAMS)
            || x == u64::from(CKA_EC_POINT)
            || x == u64::from(CKA_VALUE) =>
        {
            AttributeKind::Bytes
        }
        x if x >= u64::from(CKA_VENDOR_DEFINED) => AttributeKind::Bytes,
        _ => return Err(KeyMetadataError::UnsupportedAttribute(attribute)),
    };
    Ok(kind)
}

fn encode_attributes(
    encoder: &mut Encoder<&mut Vec<u8>>,
    attributes: &KeyAttributes,
) -> Result<(), KeyMetadataError> {
    validate_attributes(attributes)?;
    encoder.map(
        u64::try_from(attributes.attributes.len())
            .map_err(|_| KeyMetadataError::Malformed("attribute count overflow"))?,
    )?;
    for (attribute, value) in &attributes.attributes {
        encoder.u64(*attribute)?;
        encode_attribute_value(encoder, value)?;
    }
    Ok(())
}

fn encode_attribute_value(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: &KeyAttributeValue,
) -> Result<(), KeyMetadataError> {
    match value {
        KeyAttributeValue::Boolean(value) => {
            encoder.bool(*value)?;
        }
        KeyAttributeValue::Unsigned(value) => {
            encoder.u64(*value)?;
        }
        KeyAttributeValue::Bytes(value) => {
            encoder.bytes(value)?;
        }
        KeyAttributeValue::Text(value) => {
            encoder.str(value)?;
        }
        KeyAttributeValue::Mechanisms(mechanisms) => {
            encoder.array(
                u64::try_from(mechanisms.len())
                    .map_err(|_| KeyMetadataError::Malformed("mechanism count overflow"))?,
            )?;
            for mechanism in mechanisms {
                encoder.u64(*mechanism)?;
            }
        }
        KeyAttributeValue::Template(attributes) => encode_attributes(encoder, attributes)?,
    }
    Ok(())
}

fn decode_aspects(
    decoder: &mut Decoder<'_>,
) -> Result<BTreeMap<u64, KeyAttributes>, KeyMetadataError> {
    let count = definite_map(decoder, "key aspects are not a definite map")?;
    if count > MAX_ASPECTS {
        return Err(KeyMetadataError::Malformed("too many key aspects"));
    }
    let mut aspects = BTreeMap::new();
    for _ in 0..count {
        let class = decoder.u64()?;
        validate_key_class(class)?;
        let attributes = decode_attributes(decoder, 0)?;
        if aspects.insert(class, attributes).is_some() {
            return Err(KeyMetadataError::Malformed("duplicate key aspect"));
        }
    }
    Ok(aspects)
}

fn decode_attributes(
    decoder: &mut Decoder<'_>,
    depth: usize,
) -> Result<KeyAttributes, KeyMetadataError> {
    if depth > MAX_TEMPLATE_DEPTH {
        return Err(KeyMetadataError::Malformed(
            "attribute template nesting is too deep",
        ));
    }
    let count = definite_map(decoder, "key attributes are not a definite map")?;
    if count > MAX_ATTRIBUTES {
        return Err(KeyMetadataError::Malformed("too many key attributes"));
    }
    let mut attributes = KeyAttributes::new();
    for _ in 0..count {
        let attribute = decoder.u64()?;
        let value = decode_attribute_value(decoder, depth)?;
        if attributes.insert(attribute, value)?.is_some() {
            return Err(KeyMetadataError::Malformed("duplicate key attribute"));
        }
    }
    Ok(attributes)
}

fn decode_attribute_value(
    decoder: &mut Decoder<'_>,
    depth: usize,
) -> Result<KeyAttributeValue, KeyMetadataError> {
    match decoder.datatype()? {
        Type::Bool => Ok(KeyAttributeValue::Boolean(decoder.bool()?)),
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            Ok(KeyAttributeValue::Unsigned(decoder.u64()?))
        }
        Type::Bytes => Ok(KeyAttributeValue::Bytes(decoder.bytes()?.to_vec())),
        Type::String => Ok(KeyAttributeValue::Text(decoder.str()?.to_owned())),
        Type::Array => {
            let count = decoder.array()?.ok_or(KeyMetadataError::Malformed(
                "mechanism list is not a definite array",
            ))?;
            if count > MAX_ATTRIBUTES as u64 {
                return Err(KeyMetadataError::Malformed("too many mechanisms"));
            }
            let mut mechanisms = Vec::with_capacity(count as usize);
            for _ in 0..count {
                mechanisms.push(decoder.u64()?);
            }
            Ok(KeyAttributeValue::Mechanisms(mechanisms))
        }
        Type::Map => Ok(KeyAttributeValue::Template(decode_attributes(
            decoder,
            depth + 1,
        )?)),
        _ => Err(KeyMetadataError::Malformed(
            "unsupported key attribute CBOR value",
        )),
    }
}

fn definite_map(
    decoder: &mut Decoder<'_>,
    reason: &'static str,
) -> Result<usize, KeyMetadataError> {
    decoder
        .map()?
        .ok_or(KeyMetadataError::Malformed(reason))?
        .try_into()
        .map_err(|_| KeyMetadataError::Malformed("CBOR map is too large"))
}

fn validate_single_cbor_item(encoded: &[u8]) -> Result<(), KeyMetadataError> {
    if encoded.is_empty() {
        return Err(KeyMetadataError::Malformed("empty backing provider data"));
    }
    let mut decoder = Decoder::new(encoded);
    decoder
        .skip()
        .map_err(|_| KeyMetadataError::Malformed("invalid backing provider CBOR"))?;
    if decoder.position() != encoded.len() {
        return Err(KeyMetadataError::Malformed(
            "trailing backing provider data",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{LocalStorageProvider, StorageProvider};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pkcs11rs-key-metadata-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn record() -> BackedKeyMetadata {
        let backing = KeyBacking::new(
            "pkcs11rs.preview-sign",
            [0xa1, 0x01, 0x58, 0x20]
                .into_iter()
                .chain([0x11; 32])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut private = KeyAttributes::new();
        private
            .insert(
                u64::from(CKA_KEY_TYPE),
                KeyAttributeValue::Unsigned(u64::from(CKK_EC)),
            )
            .unwrap();
        private
            .insert(
                u64::from(CKA_LABEL),
                KeyAttributeValue::Text("preview signing key".to_owned()),
            )
            .unwrap();
        private
            .insert(u64::from(CKA_SIGN), KeyAttributeValue::Boolean(true))
            .unwrap();
        let mut record = BackedKeyMetadata::new(backing);
        record
            .insert_aspect(u64::from(CKO_PRIVATE_KEY), private)
            .unwrap();
        record
            .insert_aspect(u64::from(CKO_PUBLIC_KEY), KeyAttributes::new())
            .unwrap();
        record
    }

    #[test]
    fn private_and_empty_public_aspects_round_trip_canonically() {
        let record = record();
        let encoded = record.to_cbor().unwrap();
        assert_eq!(BackedKeyMetadata::from_cbor(&encoded).unwrap(), record);
        assert!(record.aspect(u64::from(CKO_PUBLIC_KEY)).unwrap().is_empty());

        let directory = TestDirectory::new();
        let provider = LocalStorageProvider::open(&directory.0).unwrap();
        let reference = provider.put(&encoded).unwrap();
        assert_eq!(provider.get(&reference).unwrap(), Some(encoded));
    }

    #[test]
    fn semantic_attribute_types_are_architecture_independent() {
        let mut nested = KeyAttributes::new();
        nested
            .insert(u64::from(CKA_SIGN), KeyAttributeValue::Boolean(true))
            .unwrap();
        let mut attributes = KeyAttributes::new();
        attributes
            .insert(
                u64::from(CKA_ALLOWED_MECHANISMS),
                KeyAttributeValue::Mechanisms(vec![u64::from(CKM_ECDSA), u64::from(CKM_SHA256)]),
            )
            .unwrap();
        attributes
            .insert(
                u64::from(CKA_DERIVE_TEMPLATE),
                KeyAttributeValue::Template(nested),
            )
            .unwrap();
        attributes
            .insert(u64::from(CKA_ID), KeyAttributeValue::Bytes(vec![0, 1, 2]))
            .unwrap();
        assert!(matches!(
            attributes.insert(
                u64::from(CKA_SIGN),
                KeyAttributeValue::Unsigned(1)
            ),
            Err(KeyMetadataError::InvalidAttributeType(attribute))
                if attribute == u64::from(CKA_SIGN)
        ));
    }

    #[test]
    fn structural_and_unknown_standard_attributes_are_rejected() {
        let mut attributes = KeyAttributes::new();
        assert!(matches!(
            attributes.insert(u64::from(CKA_TOKEN), KeyAttributeValue::Boolean(true)),
            Err(KeyMetadataError::Malformed(
                "structural attribute present in key aspect"
            ))
        ));
        assert!(matches!(
            attributes.insert(0x7fff, KeyAttributeValue::Bytes(Vec::new())),
            Err(KeyMetadataError::UnsupportedAttribute(0x7fff))
        ));
        attributes
            .insert(
                u64::from(CKA_VENDOR_DEFINED) + 7,
                KeyAttributeValue::Bytes(vec![0xa1, 1, 2]),
            )
            .unwrap();
    }

    #[test]
    fn malformed_and_noncanonical_records_are_rejected() {
        let encoded = record().to_cbor().unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            BackedKeyMetadata::from_cbor(&trailing),
            Err(KeyMetadataError::Malformed("trailing backed-key data"))
        ));

        let mut noncanonical = encoded.clone();
        let schema_key = noncanonical
            .iter()
            .position(|byte| *byte == 1)
            .expect("schema key");
        noncanonical.splice(schema_key..=schema_key, [0x18, 0x01]);
        assert!(matches!(
            BackedKeyMetadata::from_cbor(&noncanonical),
            Err(KeyMetadataError::Malformed(
                "backed key is not canonically encoded"
            ))
        ));

        assert!(matches!(
            KeyBacking::new("Invalid Provider", [0xa0]),
            Err(KeyMetadataError::Malformed(
                "invalid backing provider identifier"
            ))
        ));
        assert!(matches!(
            KeyBacking::new("pkcs11rs.test", [0xa0, 0]),
            Err(KeyMetadataError::Malformed(
                "trailing backing provider data"
            ))
        ));
    }
}
