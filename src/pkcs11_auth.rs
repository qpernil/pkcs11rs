//! Safe, session-oriented PKCS #11 operations needed by authentication clients.
//! Implemented once over the shared Rust handlers for every slot backend. No
//! C entry point, tracing wrapper, raw pointer, or output buffer crosses this API.
use crate::{pkcs11_provider::ProviderSession, *};
use software_key_core::counter_kdf::CounterKdfField;

pub(crate) enum Derivation<'a> {
    Ecdh(&'a [u8]),
    AppendKey(CK_OBJECT_HANDLE),
    AppendData(&'a [u8]),
    Extract { offset_bits: usize },
    Sha256,
    Counter(&'a [CounterKdfField<'a>]),
}

/// An authorized session on a PKCS #11 slot. Hardware and software slots use
/// the same implementation; object policy and capability checks remain in the
/// handlers shared with the public C API. Handles belong to this slot instance.
pub(crate) trait Pkcs11Auth {
    fn create(
        &self,
        template: TokenObjectTemplate,
        attributes: &[(u32, &[u8])],
    ) -> Result<CK_OBJECT_HANDLE, Error>;
    fn copy(&self, key: CK_OBJECT_HANDLE) -> Result<CK_OBJECT_HANDLE, Error>;
    fn destroy(&self, key: CK_OBJECT_HANDLE) -> Result<(), Error>;
    fn attribute(&self, key: CK_OBJECT_HANDLE, kind: u32) -> Result<Zeroizing<Vec<u8>>, Error>;
    fn generate_p256(&self) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error>;
    fn derive(
        &self,
        key: CK_OBJECT_HANDLE,
        mechanism: Derivation<'_>,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<CK_OBJECT_HANDLE, Error>;
    fn verify_cmac(
        &self,
        key: CK_OBJECT_HANDLE,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;
}

/// Owns ABI inputs, including imported secret values, for one synchronous call.
struct Attributes {
    values: Vec<(CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>)>,
    policies: Vec<(CK_ATTRIBUTE_TYPE, object::OwnedPolicyTemplate)>,
}
impl Attributes {
    fn new(template: TokenObjectTemplate) -> Result<Self, Error> {
        let mut result = Self {
            values: Vec::new(),
            policies: Vec::new(),
        };
        if let Some(value) = template.class {
            result.ulong(CKA_CLASS, value);
        }
        if let Some(value) = template.key_type {
            result.ulong(CKA_KEY_TYPE, value);
        }
        for (kind, value) in [
            (CKA_TOKEN, template.token),
            (CKA_PRIVATE, template.private),
            (CKA_ENCRYPT, template.encrypt),
            (CKA_DECRYPT, template.decrypt),
            (CKA_SIGN, template.sign),
            (CKA_VERIFY, template.verify),
            (CKA_DERIVE, template.derive),
            (CKA_WRAP, template.wrap),
            (CKA_UNWRAP, template.unwrap),
        ] {
            result.bytes(kind, &[u8::from(value)]);
        }
        if let Some(value) = template.sensitive {
            result.bytes(CKA_SENSITIVE, &[u8::from(value)]);
        }
        if let Some(value) = template.extractable {
            result.bytes(CKA_EXTRACTABLE, &[u8::from(value)]);
        }
        if let Some(mechanisms) = template.allowed_mechanisms {
            result.bytes(
                CKA_ALLOWED_MECHANISMS,
                &mechanisms
                    .iter()
                    .flat_map(|m| m.to_ne_bytes())
                    .collect::<Vec<_>>(),
            );
        }
        result.bytes(CKA_LABEL, template.label.as_bytes());
        result.bytes(CKA_ID, &template.id);
        for (kind, value) in [
            (CKA_ENCAPSULATE, template.encapsulate),
            (CKA_DECAPSULATE, template.decapsulate),
            (CKA_WRAP_WITH_TRUSTED, template.wrap_with_trusted),
        ] {
            result.bytes(kind, &[u8::from(value)]);
        }
        for (kind, value) in [
            (CKA_WRAP_TEMPLATE, template.policy_templates.wrap),
            (CKA_UNWRAP_TEMPLATE, template.policy_templates.unwrap),
            (CKA_DERIVE_TEMPLATE, template.policy_templates.derive),
        ] {
            if let Some(value) = value {
                result.policies.push((
                    kind as _,
                    object::OwnedPolicyTemplate::from_semantic(&value).map_err(Error::from)?,
                ));
            }
        }
        Ok(result)
    }
    fn bytes(&mut self, kind: u32, value: &[u8]) {
        self.values
            .push((kind as _, Zeroizing::new(value.to_vec())));
    }
    fn ulong(&mut self, kind: u32, value: CK_ULONG) {
        self.bytes(kind, &value.to_ne_bytes());
    }
    fn raw(&mut self) -> Vec<CK_ATTRIBUTE> {
        let mut raw: Vec<_> = self
            .values
            .iter_mut()
            .map(|(kind, value)| CK_ATTRIBUTE {
                type_: *kind,
                pValue: value.as_mut_ptr().cast(),
                ulValueLen: value.len() as _,
            })
            .collect();
        for (kind, policy) in &mut self.policies {
            let attributes = policy.as_slice();
            raw.push(CK_ATTRIBUTE {
                type_: *kind,
                pValue: attributes.as_ptr().cast_mut().cast(),
                ulValueLen: std::mem::size_of_val(attributes) as _,
            });
        }
        raw
    }
}
fn mechanism(kind: u32) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: kind as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    }
}
fn parameter<T>(kind: u32, value: &mut T) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: kind as _,
        pParameter: (value as *mut T).cast(),
        ulParameterLen: std::mem::size_of::<T>() as _,
    }
}
pub(crate) const P256_PARAMS: &[u8] = &[6, 8, 42, 134, 72, 206, 61, 3, 1, 7];
pub(crate) fn ec_template() -> TokenObjectTemplate {
    TokenObjectTemplate {
        class: Some(CKO_PRIVATE_KEY as _),
        key_type: Some(CKK_EC as _),
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        derive: true,
        allowed_mechanisms: Some(vec![CKM_ECDH1_DERIVE as _]),
        ..Default::default()
    }
}

impl ProviderSession {
    fn derive_raw(
        &self,
        base: CK_OBJECT_HANDLE,
        mut mechanism: CK_MECHANISM,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        let mut attributes = Attributes::new(template)?;
        attributes.ulong(CKA_VALUE_LEN, length as _);
        let mut raw = attributes.raw();
        let mut handle = 0;
        self.call(|| {
            api::rust::derive_key(
                self.handle,
                &mut mechanism,
                base,
                raw.as_mut_ptr(),
                raw.len() as _,
                &mut handle,
            )
        })?;
        Ok(handle)
    }
    fn counter(
        &self,
        base: CK_OBJECT_HANDLE,
        fields: &[CounterKdfField<'_>],
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        use software_key_core::counter_kdf::{CounterKdfField, LengthMethod};
        enum Field {
            Bytes(Vec<u8>),
            Counter(CK_SP800_108_COUNTER_FORMAT),
            Length(CK_SP800_108_DKM_LENGTH_FORMAT),
        }
        let mut owned: Vec<_> = fields
            .iter()
            .map(|field| match field {
                CounterKdfField::Bytes(value) => Field::Bytes(value.to_vec()),
                CounterKdfField::Counter(format) => Field::Counter(CK_SP800_108_COUNTER_FORMAT {
                    bLittleEndian: u8::from(format.little_endian),
                    ulWidthInBits: format.width_bits as _,
                }),
                CounterKdfField::Length(format, method) => {
                    Field::Length(CK_SP800_108_DKM_LENGTH_FORMAT {
                        bLittleEndian: u8::from(format.little_endian),
                        ulWidthInBits: format.width_bits as _,
                        dkmLengthMethod: match method {
                            LengthMethod::Key => CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS as _,
                            LengthMethod::Segments => CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS as _,
                        },
                    })
                }
            })
            .collect();
        let mut raw: Vec<_> = owned
            .iter_mut()
            .map(|field| {
                let (kind, pointer, length) = match field {
                    Field::Bytes(value) => (
                        CK_SP800_108_BYTE_ARRAY,
                        value.as_mut_ptr().cast(),
                        value.len(),
                    ),
                    Field::Counter(value) => (
                        CK_SP800_108_ITERATION_VARIABLE,
                        (value as *mut CK_SP800_108_COUNTER_FORMAT).cast(),
                        std::mem::size_of_val(value),
                    ),
                    Field::Length(value) => (
                        CK_SP800_108_DKM_LENGTH,
                        (value as *mut CK_SP800_108_DKM_LENGTH_FORMAT).cast(),
                        std::mem::size_of_val(value),
                    ),
                };
                CK_PRF_DATA_PARAM {
                    type_: kind as _,
                    pValue: pointer,
                    ulValueLen: length as _,
                }
            })
            .collect();
        let mut params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_AES_CMAC as _,
            ulNumberOfDataParams: raw.len() as _,
            pDataParams: raw.as_mut_ptr(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        self.derive_raw(
            base,
            parameter(CKM_SP800_108_COUNTER_KDF, &mut params),
            template,
            length,
        )
    }
}

impl Pkcs11Auth for ProviderSession {
    fn create(
        &self,
        template: TokenObjectTemplate,
        extra: &[(u32, &[u8])],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        let mut attributes = Attributes::new(template)?;
        for (kind, value) in extra {
            attributes.bytes(*kind, value);
        }
        let mut raw = attributes.raw();
        let mut handle = 0;
        self.call(|| {
            api::rust::create_object(self.handle, raw.as_mut_ptr(), raw.len() as _, &mut handle)
        })?;
        Ok(handle)
    }
    fn copy(&self, key: CK_OBJECT_HANDLE) -> Result<CK_OBJECT_HANDLE, Error> {
        let mut handle = 0;
        self.call(|| {
            api::rust::copy_object(self.handle, key, std::ptr::null_mut(), 0, &mut handle)
        })?;
        Ok(handle)
    }
    fn destroy(&self, key: CK_OBJECT_HANDLE) -> Result<(), Error> {
        self.call(|| api::rust::destroy_object(self.handle, key))
    }
    fn attribute(&self, key: CK_OBJECT_HANDLE, kind: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut attribute = CK_ATTRIBUTE {
            type_: kind as _,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        self.call(|| api::rust::get_attribute_value(self.handle, key, &mut attribute, 1))?;
        if attribute.ulValueLen > 65536 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut output = Zeroizing::new(vec![0; attribute.ulValueLen as usize]);
        attribute.pValue = output.as_mut_ptr().cast();
        self.call(|| api::rust::get_attribute_value(self.handle, key, &mut attribute, 1))?;
        if attribute.ulValueLen as usize > output.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        output.truncate(attribute.ulValueLen as usize);
        Ok(output)
    }
    fn generate_p256(&self) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
        let mut public = Attributes::new(TokenObjectTemplate {
            class: Some(CKO_PUBLIC_KEY as _),
            key_type: Some(CKK_EC as _),
            ..Default::default()
        })?;
        public.bytes(CKA_EC_PARAMS, P256_PARAMS);
        let mut private = Attributes::new(ec_template())?;
        let mut public = public.raw();
        let mut private = private.raw();
        let (mut pubkey, mut privkey) = (0, 0);
        self.call(|| {
            api::rust::generate_key_pair(
                self.handle,
                &mut mechanism(CKM_EC_KEY_PAIR_GEN),
                public.as_mut_ptr(),
                public.len() as _,
                private.as_mut_ptr(),
                private.len() as _,
                &mut pubkey,
                &mut privkey,
            )
        })?;
        Ok((pubkey, privkey))
    }
    fn derive(
        &self,
        base: CK_OBJECT_HANDLE,
        operation: Derivation<'_>,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        match operation {
            Derivation::Ecdh(peer) => {
                let mut params = CK_ECDH1_DERIVE_PARAMS {
                    kdf: CKD_NULL as _,
                    pSharedData: std::ptr::null_mut(),
                    ulSharedDataLen: 0,
                    pPublicData: peer.as_ptr().cast_mut(),
                    ulPublicDataLen: peer.len() as _,
                };
                self.derive_raw(
                    base,
                    parameter(CKM_ECDH1_DERIVE, &mut params),
                    template,
                    length,
                )
            }
            Derivation::AppendKey(mut other) => self.derive_raw(
                base,
                parameter(CKM_CONCATENATE_BASE_AND_KEY, &mut other),
                template,
                length,
            ),
            Derivation::AppendData(data) => {
                let mut params = CK_KEY_DERIVATION_STRING_DATA {
                    pData: data.as_ptr().cast_mut(),
                    ulLen: data.len() as _,
                };
                self.derive_raw(
                    base,
                    parameter(CKM_CONCATENATE_BASE_AND_DATA, &mut params),
                    template,
                    length,
                )
            }
            Derivation::Extract { offset_bits } => {
                let mut offset = offset_bits as CK_EXTRACT_PARAMS;
                self.derive_raw(
                    base,
                    parameter(CKM_EXTRACT_KEY_FROM_KEY, &mut offset),
                    template,
                    length,
                )
            }
            Derivation::Sha256 => {
                self.derive_raw(base, mechanism(CKM_SHA256_KEY_DERIVATION), template, length)
            }
            Derivation::Counter(fields) => self.counter(base, fields, template, length),
        }
    }
    fn verify_cmac(
        &self,
        key: CK_OBJECT_HANDLE,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if signature.is_empty() || signature.len() > 16 {
            return Err(CKR_SIGNATURE_LEN_RANGE.into());
        }
        let mut length = signature.len() as CK_ULONG;
        let mut mechanism = if signature.len() == 16 {
            mechanism(CKM_AES_CMAC)
        } else {
            parameter(CKM_AES_CMAC_GENERAL, &mut length)
        };
        self.call(|| api::rust::verify_init(self.handle, &mut mechanism, key))?;
        self.call(|| {
            api::rust::verify(
                self.handle,
                input.as_ptr().cast_mut(),
                input.len() as _,
                signature.as_ptr().cast_mut(),
                signature.len() as _,
            )
        })
    }
}
