#[derive(Debug, Clone)]
struct TokenObject {
    slot_id: Option<CK_SLOT_ID>,
    unique_id: String,
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    label: String,
    id: Vec<u8>,
    token: bool,
    private: bool,
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    derive: bool,
    sensitive: bool,
    extractable: bool,
    always_sensitive: bool,
    never_extractable: bool,
    local: bool,
    key_gen_mechanism: Option<CK_MECHANISM_TYPE>,
    owner_session: Option<CK_SESSION_HANDLE>,
    material: KeyMaterial,
}

#[derive(Clone)]
#[cfg_attr(not(any(test, feature = "abi-tests")), allow(dead_code))]
enum KeyMaterial {
    None,
    Profile {
        profile_id: CK_PROFILE_ID,
    },
    RsaPrivate(Box<RsaPrivateKey>),
    RsaPublic(RsaPublicKey),
    PivPrivate {
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        pin_policy: u8,
        touch_policy: u8,
    },
    PivPublic {
        algorithm: piv::Algorithm,
        public_key: Vec<u8>,
    },
    OpenPgpPrivate {
        key_ref: OpenPgpKeyRef,
        algorithm: OpenPgpAlgorithm,
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        #[allow(dead_code)]
        public_key: Vec<u8>,
        pin_policy: u8,
        touch_policy: u8,
    },
    OpenPgpPublic {
        algorithm: OpenPgpAlgorithm,
        public_key: Vec<u8>,
    },
    PivCertificate {
        algorithm: piv::Algorithm,
        value: Vec<u8>,
        attestation: bool,
    },
    PivData {
        object_id: u32,
        value: Vec<u8>,
    },
    PivAttestation {
        connector: Rc<dyn Connector>,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        value: Rc<RefCell<Option<Vec<u8>>>>,
        attempted: Rc<Cell<bool>>,
    },
    OpenPgpCertificate {
        value: Vec<u8>,
    },
    OpenPgpData {
        tag: u16,
        connector: Rc<dyn Connector>,
        value: Rc<RefCell<Option<Vec<u8>>>>,
        attempted: Rc<Cell<bool>>,
    },
    IssuerSecurityDomainData {
        value: Vec<u8>,
        application: String,
        object_id: Vec<u8>,
    },
    IssuerSecurityDomainCertificate {
        value: Vec<u8>,
    },
    HsmAuthCredential {
        algorithm: HsmAuthAlgorithm,
        retries: u8,
        touch_required: bool,
    },
    HsmAuthPublic {
        public_key: Vec<u8>,
    },
    YubiHsm {
        id: u16,
        object_type: u8,
        algorithm: u8,
        length: usize,
        #[allow(dead_code)]
        domains: u16,
        capabilities: [u8; 8],
        #[allow(dead_code)]
        delegated_capabilities: [u8; 8],
        public_key: Vec<u8>,
        value: Rc<RefCell<Option<Vec<u8>>>>,
    },
    YubiHsmDevicePublic {
        public_key: Vec<u8>,
        public_key_info: Vec<u8>,
    },
    YubiHsmAttestation {
        connector: Rc<dyn Connector>,
        session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
        id: u16,
        algorithm: u8,
        value: Rc<RefCell<Option<Vec<u8>>>>,
        attempted: Rc<Cell<bool>>,
    },
    Secret(Zeroizing<Vec<u8>>),
    DerivedSecret(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => fmt.write_str("None"),
            Self::Profile { profile_id } => fmt
                .debug_struct("Profile")
                .field("profile_id", profile_id)
                .finish(),
            Self::RsaPrivate(key) => fmt.debug_tuple("RsaPrivate").field(&key.size()).finish(),
            Self::RsaPublic(key) => fmt.debug_tuple("RsaPublic").field(&key.size()).finish(),
            Self::PivPrivate {
                slot,
                algorithm,
                modulus,
                public_exponent: _,
                touch_policy,
                ..
            } => fmt
                .debug_struct("PivPrivate")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("size", &modulus.len())
                .field("touch_policy", touch_policy)
                .finish(),
            Self::PivPublic {
                algorithm,
                public_key,
            } => fmt
                .debug_struct("PivPublic")
                .field("algorithm", algorithm)
                .field("size", &public_key.len())
                .finish(),
            Self::OpenPgpPrivate {
                key_ref,
                algorithm,
                modulus,
                pin_policy,
                ..
            } => fmt
                .debug_struct("OpenPgpPrivate")
                .field("key_ref", key_ref)
                .field("algorithm", algorithm)
                .field("size", &modulus.len())
                .field("pin_policy", pin_policy)
                .finish(),
            Self::OpenPgpPublic {
                algorithm,
                public_key,
            } => fmt
                .debug_struct("OpenPgpPublic")
                .field("algorithm", algorithm)
                .field("size", &public_key.len())
                .finish(),
            Self::YubiHsm {
                id,
                object_type,
                algorithm,
                length,
                ..
            } => fmt
                .debug_struct("YubiHsm")
                .field("id", id)
                .field("object_type", object_type)
                .field("algorithm", algorithm)
                .field("length", length)
                .finish(),
            Self::YubiHsmDevicePublic { public_key, .. } => fmt
                .debug_struct("YubiHsmDevicePublic")
                .field("size", &public_key.len())
                .finish(),
            Self::YubiHsmAttestation {
                id,
                algorithm,
                value,
                ..
            } => fmt
                .debug_struct("YubiHsmAttestation")
                .field("id", id)
                .field("algorithm", algorithm)
                .field("cached", &value.borrow().is_some())
                .finish(),
            Self::Secret(key) => fmt.debug_tuple("Secret").field(&key.len()).finish(),
            Self::DerivedSecret(key) => fmt.debug_tuple("DerivedSecret").field(&key.len()).finish(),
            Self::PivCertificate {
                value,
                algorithm,
                attestation,
            } => fmt
                .debug_struct("PivCertificate")
                .field("algorithm", algorithm)
                .field("attestation", attestation)
                .field("size", &value.len())
                .finish(),
            Self::PivAttestation {
                slot,
                algorithm,
                value,
                ..
            } => fmt
                .debug_struct("PivAttestation")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("cached", &value.borrow().is_some())
                .finish(),
            Self::PivData { object_id, value } => fmt
                .debug_struct("PivData")
                .field("object_id", object_id)
                .field("size", &value.len())
                .finish(),
            Self::OpenPgpCertificate { value } => fmt
                .debug_struct("OpenPgpCertificate")
                .field("size", &value.len())
                .finish(),
            Self::OpenPgpData { tag, value, .. } => fmt
                .debug_struct("OpenPgpData")
                .field("tag", tag)
                .field("cached", &value.borrow().is_some())
                .finish(),
            Self::IssuerSecurityDomainData {
                value,
                application,
                object_id,
            } => fmt
                .debug_struct("IssuerSecurityDomainData")
                .field("size", &value.len())
                .field("application", application)
                .field("object_id", object_id)
                .finish(),
            Self::IssuerSecurityDomainCertificate { value } => fmt
                .debug_struct("IssuerSecurityDomainCertificate")
                .field("size", &value.len())
                .finish(),
            Self::HsmAuthCredential {
                algorithm,
                retries,
                touch_required,
            } => fmt
                .debug_struct("HsmAuthCredential")
                .field("algorithm", algorithm)
                .field("retries", retries)
                .field("touch_required", touch_required)
                .finish(),
            Self::HsmAuthPublic { public_key } => fmt
                .debug_struct("HsmAuthPublic")
                .field("size", &public_key.len())
                .finish(),
        }
    }
}

#[derive(Debug, Default)]
struct TokenObjectTemplate {
    class: Option<CK_OBJECT_CLASS>,
    key_type: Option<CK_KEY_TYPE>,
    label: String,
    id: Vec<u8>,
    token: bool,
    private: bool,
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    derive: bool,
    sensitive: Option<bool>,
    extractable: Option<bool>,
}

#[derive(Debug)]
struct FindOperation {
    objects: Vec<CK_OBJECT_HANDLE>,
    next: usize,
}

#[derive(Debug, Clone)]
struct SignatureOperation {
    key: KeyMaterial,
    slot_id: CK_SLOT_ID,
    requires_login: bool,
    context_specific_extended: bool,
    mechanism: CK_MECHANISM_TYPE,
    pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    piv_pin_policy: Option<u8>,
    buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
struct GcmParameters {
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag_bits: usize,
}

#[derive(Clone)]
struct CryptOperation {
    key: KeyMaterial,
    slot_id: CK_SLOT_ID,
    requires_login: bool,
    context_specific_extended: bool,
    mechanism: CK_MECHANISM_TYPE,
    iv: Option<[u8; 16]>,
    gcm: Option<GcmParameters>,
    oaep: Option<(u8, CK_MECHANISM_TYPE, Vec<u8>)>,
    piv_pin_policy: Option<u8>,
    result: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for CryptOperation {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("CryptOperation")
            .field("key", &self.key)
            .field("slot_id", &self.slot_id)
            .field("requires_login", &self.requires_login)
            .field("context_specific_extended", &self.context_specific_extended)
            .field("mechanism", &self.mechanism)
            .field("iv", &self.iv)
            .field("gcm", &self.gcm)
            .field("oaep", &self.oaep)
            .field("piv_pin_policy", &self.piv_pin_policy)
            .field("result_length", &self.result.as_ref().map(|result| result.len()))
            .finish()
    }
}


fn ulong_attribute(value: CK_ULONG) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn bool_attribute(value: bool) -> Vec<u8> {
    vec![if value {
        CK_TRUE as CK_BBOOL
    } else {
        CK_FALSE as CK_BBOOL
    }]
}

fn piv_object_tag(object_id: u32) -> Vec<u8> {
    let bytes = object_id.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    bytes[first..].to_vec()
}

fn piv_certificate_attribute(value: &[u8], attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    match attribute_type {
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => Some(value.to_vec()),
        x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE => {
            Some(ulong_attribute(CKC_X_509 as CK_ULONG))
        }
        x if x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(0)),
        x if x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE => {
            Some(hash(MessageDigest::sha1(), value).ok()?[..3].to_vec())
        }
        x if x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE => crate::certificate_chain::subject(value).ok(),
        x if x == CKA_ISSUER as CK_ATTRIBUTE_TYPE => crate::certificate_chain::issuer(value).ok(),
        x if x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE => {
            let serial = crate::certificate_chain::serial_number(value).ok()?;
            der_integer(&serial)
        }
        x if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE => {
            crate::certificate_chain::public_key_info(value).ok()
        }
        _ => None,
    }
}

fn der_integer(magnitude: &[u8]) -> Option<Vec<u8>> {
    let first_nonzero = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    let magnitude = &magnitude[first_nonzero..];
    let needs_sign_padding = magnitude.first().is_some_and(|byte| byte & 0x80 != 0);
    let content_length = magnitude.len().max(1) + usize::from(needs_sign_padding);
    let mut encoded = Vec::with_capacity(content_length + 3);
    encoded.push(0x02);
    if content_length < 128 {
        encoded.push(content_length as u8);
    } else if content_length <= u8::MAX as usize {
        encoded.extend_from_slice(&[0x81, content_length as u8]);
    } else {
        return None;
    }
    if magnitude.is_empty() || needs_sign_padding {
        encoded.push(0);
    }
    encoded.extend_from_slice(magnitude);
    Some(encoded)
}

fn is_certificate_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
            || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
            || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
            || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
    )
}

fn lazy_piv_attestation_certificate(
    connector: &dyn Connector,
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    value: &RefCell<Option<Vec<u8>>>,
    attempted: &Cell<bool>,
) -> Option<Vec<u8>> {
    if attempted.replace(true) {
        return value.borrow().clone();
    }

    let certificate = PivClient.attestation(connector, slot).ok()?;
    if piv_algorithm_from_certificate(&certificate)? != algorithm {
        return None;
    }
    piv_public_key_from_certificate(algorithm, &certificate).ok()?;
    *value.borrow_mut() = Some(certificate.clone());
    Some(certificate)
}

fn lazy_yubihsm_attestation_certificate(
    connector: &dyn Connector,
    session: &RefCell<Option<YubiHsmSecureSession>>,
    id: u16,
    value: &RefCell<Option<Vec<u8>>>,
    attempted: &Cell<bool>,
) -> Option<Vec<u8>> {
    if attempted.replace(true) {
        return value.borrow().clone();
    }

    let certificate = send_yubihsm_secure_command(
        connector,
        session,
        &YubiHsmCommand::sign_attestation_certificate(id, 0),
    )
    .ok()?;
    crate::certificate_chain::validate(&certificate).ok()?;
    *value.borrow_mut() = Some(certificate.clone());
    Some(certificate)
}

impl TokenObject {
    fn has_sensitive_attributes(&self) -> bool {
        self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    fn is_visible_to(
        &self,
        session_handle: CK_SESSION_HANDLE,
        slot_id: CK_SLOT_ID,
        logged_in: bool,
    ) -> bool {
        self.slot_id == Some(slot_id)
            && (!self.private || logged_in)
            && self
                .owner_session
                .map(|owner| owner == session_handle)
                .unwrap_or(true)
    }

    fn set_owner(&mut self, session_handle: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID) {
        self.slot_id = Some(slot_id);
        self.owner_session = (!self.token).then_some(session_handle);
    }

    fn size(&self) -> CK_ULONG {
        let defer_certificate_attributes = matches!(
            &self.material,
            KeyMaterial::PivAttestation { attempted, .. }
                | KeyMaterial::YubiHsmAttestation { attempted, .. }
                if !attempted.get()
        );
        [
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            CKA_PROFILE_ID as CK_ATTRIBUTE_TYPE,
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            CKA_LABEL as CK_ATTRIBUTE_TYPE,
            CKA_ID as CK_ATTRIBUTE_TYPE,
            CKA_APPLICATION as CK_ATTRIBUTE_TYPE,
            CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE,
            CKA_PKCS11RS_PIV_OBJECT_TAG,
            CKA_YUBICO_HSMAUTH_ALGORITHM,
            CKA_YUBICO_HSMAUTH_RETRIES,
            CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED,
            CKA_YUBICO_TOUCH_POLICY,
            CKA_YUBICO_PIN_POLICY,
            CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE,
            CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            CKA_DERIVE as CK_ATTRIBUTE_TYPE,
            CKA_WRAP as CK_ATTRIBUTE_TYPE,
            CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
            CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE,
            CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE,
            CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE,
            CKA_COPYABLE as CK_ATTRIBUTE_TYPE,
            CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE,
            CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            CKA_VALUE_BITS as CK_ATTRIBUTE_TYPE,
            CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            CKA_MODULUS as CK_ATTRIBUTE_TYPE,
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
            CKA_VALUE as CK_ATTRIBUTE_TYPE,
            CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE,
            CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE,
            CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE,
            CKA_SUBJECT as CK_ATTRIBUTE_TYPE,
            CKA_ISSUER as CK_ATTRIBUTE_TYPE,
            CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE,
            CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE,
            CKA_TRUSTED as CK_ATTRIBUTE_TYPE,
        ]
        .iter()
        .filter(|&&attribute_type| {
            !defer_certificate_attributes || !is_certificate_attribute(attribute_type)
        })
        .filter_map(|&attribute_type| self.attribute_value(attribute_type))
        .map(|value| value.len() as CK_ULONG)
        .sum()
    }

    fn attribute_value(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        match attribute_type {
            x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(self.class)),
            x if x == CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE => {
                Some(self.unique_id.as_bytes().to_vec())
            }
            x if x == CKA_PROFILE_ID as CK_ATTRIBUTE_TYPE => match self.material {
                KeyMaterial::Profile { profile_id } => Some(ulong_attribute(profile_id)),
                _ => None,
            },
            x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(ulong_attribute(self.key_type))
            }
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => Some(self.label.as_bytes().to_vec()),
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE
                && matches!(self.material, KeyMaterial::Profile { .. }) =>
            {
                None
            }
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::PivData { object_id, .. } => piv::data_object_mapping(*object_id)
                    .map(|mapping| vec![mapping.cka_id]),
                _ => Some(self.id.clone()),
            },
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.token)),
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.private)),
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE
                && self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS =>
            {
                Some(bool_attribute(match &self.material {
                    KeyMaterial::PivPrivate {
                        slot, pin_policy, ..
                    } => piv_effective_pin_policy(*slot, *pin_policy) == 3,
                    KeyMaterial::OpenPgpPrivate {
                        key_ref,
                        pin_policy,
                        ..
                    } => openpgp_signature_requires_context_specific_login(*key_ref, *pin_policy),
                    _ => false,
                }))
            }
            x if x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.encrypt))
            }
            x if x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.decrypt))
            }
            x if x == CKA_SIGN as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.sign))
            }
            x if x == CKA_VERIFY as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.verify))
            }
            x if x == CKA_DERIVE as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.derive))
            }
            x if x == CKA_WRAP as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.can_wrap()))
            }
            x if x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.can_unwrap()))
            }
            x if self.is_key_object()
                && (x == CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE
                    || x == CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE
                    || x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE) =>
            {
                Some(bool_attribute(false))
            }
            x if x == CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(bool_attribute(true))
            }
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE
                && matches!(
                    self.material,
                    KeyMaterial::PivPrivate { .. }
                        | KeyMaterial::PivCertificate { .. }
                        | KeyMaterial::PivData { .. }
                ) =>
            {
                Some(bool_attribute(true))
            }
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE
                && (self.is_certificate_object() || self.is_yubihsm_opaque()) =>
            {
                Some(bool_attribute(false))
            }
            x if x == CKA_APPLICATION as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { .. } if self.is_yubihsm_opaque() => {
                    Some(b"Opaque object".to_vec())
                }
                KeyMaterial::IssuerSecurityDomainData { application, .. } => {
                    Some(application.as_bytes().to_vec())
                }
                KeyMaterial::PivData { .. } => Some(b"PIV".to_vec()),
                KeyMaterial::OpenPgpData { .. } => Some(b"OpenPGP".to_vec()),
                _ => None,
            },
            x if x == CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { .. } if self.is_yubihsm_opaque() => Some(Vec::new()),
                KeyMaterial::IssuerSecurityDomainData { object_id, .. } => Some(object_id.clone()),
                KeyMaterial::PivData { object_id, .. } => piv::data_object_mapping(*object_id)
                    .map(piv::data_object_oid),
                KeyMaterial::OpenPgpData { tag, .. } => Some(tag.to_be_bytes().to_vec()),
                _ => None,
            },
            x if x == CKA_PKCS11RS_PIV_OBJECT_TAG => match &self.material {
                KeyMaterial::PivData { object_id, .. } => Some(piv_object_tag(*object_id)),
                _ => None,
            },
            x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE && self.is_certificate_object() => {
                Some(ulong_attribute(CKC_X_509 as CK_ULONG))
            }
            x if x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::Secret(value) | KeyMaterial::DerivedSecret(value) => {
                    Some(ulong_attribute(value.len() as CK_ULONG))
                }
                KeyMaterial::HsmAuthCredential { .. } => Some(ulong_attribute(32)),
                KeyMaterial::YubiHsm { length, .. }
                    if self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS =>
                {
                    Some(ulong_attribute(*length as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_VALUE_BITS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::Secret(value) | KeyMaterial::DerivedSecret(value) => {
                    Some(ulong_attribute((value.len() * 8) as CK_ULONG))
                }
                KeyMaterial::YubiHsm { length, .. }
                    if self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS =>
                {
                    Some(ulong_attribute((*length * 8) as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(self.sensitive))
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(
                    self.extractable && !self.is_nonextractable_key_object(),
                ))
            }
            x if x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(self.always_sensitive))
            }
            x if x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(
                    self.never_extractable || self.is_nonextractable_key_object(),
                ))
            }
            x if x == CKA_LOCAL as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.local))
            }
            x if x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(ulong_attribute(
                    self.key_gen_mechanism
                        .unwrap_or(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                ))
            }
            x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.n().to_bytes_be()),
                KeyMaterial::RsaPublic(key) => Some(key.n().to_bytes_be()),
                KeyMaterial::PivPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(modulus.clone())
                }
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(modulus.clone())
                }
                KeyMaterial::YubiHsm {
                    algorithm,
                    public_key,
                    ..
                } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                    Some(public_key.clone())
                }
                _ => None,
            },
            x if x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.e().to_bytes_be()),
                KeyMaterial::RsaPublic(key) => Some(key.e().to_bytes_be()),
                KeyMaterial::PivPrivate {
                    public_exponent, ..
                } if !public_exponent.is_empty() => Some(public_exponent.clone()),
                KeyMaterial::OpenPgpPrivate {
                    public_exponent, ..
                } if !public_exponent.is_empty() => Some(public_exponent.clone()),
                KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                    Some(vec![0x01, 0x00, 0x01])
                }
                _ => None,
            },
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(ulong_attribute((key.size() * 8) as CK_ULONG)),
                KeyMaterial::RsaPublic(key) => Some(ulong_attribute((key.size() * 8) as CK_ULONG)),
                KeyMaterial::PivPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(ulong_attribute((modulus.len() * 8) as CK_ULONG))
                }
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(ulong_attribute((modulus.len() * 8) as CK_ULONG))
                }
                KeyMaterial::YubiHsm {
                    algorithm,
                    public_key,
                    ..
                } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                    Some(ulong_attribute((public_key.len() * 8) as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { algorithm, .. } => {
                    yubihsm_ec_parameters(*algorithm).map(<[u8]>::to_vec)
                }
                KeyMaterial::YubiHsmDevicePublic { .. } => {
                    piv_ec_parameters(piv::Algorithm::EccP256).map(<[u8]>::to_vec)
                }
                KeyMaterial::PivPrivate { algorithm, .. }
                | KeyMaterial::PivPublic { algorithm, .. } => {
                    piv_ec_parameters(*algorithm).map(<[u8]>::to_vec)
                }
                KeyMaterial::OpenPgpPrivate { algorithm, .. }
                | KeyMaterial::OpenPgpPublic { algorithm, .. } => openpgp_ec_params(*algorithm),
                KeyMaterial::HsmAuthPublic { .. } => {
                    piv_ec_parameters(piv::Algorithm::EccP256).map(<[u8]>::to_vec)
                }
                _ => None,
            },
            x if x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
                && self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS =>
            {
                match &self.material {
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if is_yubihsm_ec(*algorithm) && !public_key.is_empty() => {
                        let mut point = Vec::with_capacity(public_key.len() + 1);
                        point.push(0x04);
                        point.extend_from_slice(public_key);
                        der_octet_string(&point)
                    }
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if *algorithm == YUBIHSM_ALGO_ED25519 && !public_key.is_empty() => {
                        der_octet_string(public_key)
                    }
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if is_yubihsm_x25519(*algorithm) && !public_key.is_empty() => {
                        der_octet_string(public_key)
                    }
                    KeyMaterial::PivPublic {
                        algorithm,
                        public_key,
                    } if !public_key.is_empty() => {
                        let point = if piv_ec_coordinate_length(*algorithm).is_some() {
                            let mut point = Vec::with_capacity(public_key.len() + 1);
                            point.push(0x04);
                            point.extend_from_slice(public_key);
                            point
                        } else {
                            public_key.clone()
                        };
                        der_octet_string(&point)
                    }
                    KeyMaterial::OpenPgpPublic {
                        algorithm,
                        public_key,
                    } if !public_key.is_empty() => {
                        let point = if matches!(
                            algorithm,
                            OpenPgpAlgorithm::Ecdsa(_) | OpenPgpAlgorithm::Ecdh(_)
                        ) {
                            let mut point = Vec::with_capacity(public_key.len() + 1);
                            point.push(0x04);
                            point.extend_from_slice(public_key);
                            point
                        } else {
                            public_key.clone()
                        };
                        der_octet_string(&point)
                    }
                    KeyMaterial::HsmAuthPublic { public_key }
                        if public_key.len() == 65 && public_key[0] == 0x04 =>
                    {
                        der_octet_string(public_key)
                    }
                    KeyMaterial::YubiHsmDevicePublic { public_key, .. } => {
                        der_octet_string(public_key)
                    }
                    _ => None,
                }
            }
            x if x == CKA_YUBICO_HSMAUTH_ALGORITHM => match &self.material {
                KeyMaterial::HsmAuthCredential { algorithm, .. } => {
                    Some(ulong_attribute(*algorithm as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_YUBICO_HSMAUTH_RETRIES => match &self.material {
                KeyMaterial::HsmAuthCredential { retries, .. } => {
                    Some(ulong_attribute(*retries as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED => match &self.material {
                KeyMaterial::HsmAuthCredential { touch_required, .. } => {
                    Some(bool_attribute(*touch_required))
                }
                _ => None,
            },
            x if x == CKA_YUBICO_TOUCH_POLICY => match &self.material {
                KeyMaterial::PivPrivate { touch_policy, .. } => {
                    Some(ulong_attribute(*touch_policy as CK_ULONG))
                }
                KeyMaterial::OpenPgpPrivate { touch_policy, .. } => {
                    Some(ulong_attribute(*touch_policy as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_YUBICO_PIN_POLICY => match &self.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => {
                    Some(ulong_attribute(*pin_policy as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
                || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
                || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
                || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE =>
            {
                match &self.material {
                    KeyMaterial::DerivedSecret(value) if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => {
                        Some(value.to_vec())
                    }
                    KeyMaterial::PivCertificate { value, .. }
                    | KeyMaterial::OpenPgpCertificate { value }
                    | KeyMaterial::IssuerSecurityDomainCertificate { value } => {
                        piv_certificate_attribute(value, x)
                    }
                    KeyMaterial::IssuerSecurityDomainData { value, .. }
                        if x == CKA_VALUE as CK_ATTRIBUTE_TYPE =>
                    {
                        Some(value.clone())
                    }
                    KeyMaterial::PivData { value, .. } if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => {
                        Some(value.clone())
                    }
                    KeyMaterial::OpenPgpData {
                        connector,
                        tag,
                        value,
                        attempted,
                    }
                        if x == CKA_VALUE as CK_ATTRIBUTE_TYPE =>
                    {
                        if !attempted.replace(true) {
                            *value.borrow_mut() = OpenPgpClient.get_data(connector.as_ref(), *tag).ok();
                        }
                        value.borrow().clone().or_else(|| Some(Vec::new()))
                    }
                    KeyMaterial::YubiHsmDevicePublic {
                        public_key_info, ..
                    } if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE => {
                        Some(public_key_info.clone())
                    }
                    KeyMaterial::PivAttestation {
                        connector,
                        slot,
                        algorithm,
                        value,
                        attempted,
                    } => lazy_piv_attestation_certificate(
                        connector.as_ref(),
                        *slot,
                        *algorithm,
                        value,
                        attempted,
                    )
                    .and_then(|value| piv_certificate_attribute(&value, x)),
                    KeyMaterial::YubiHsmAttestation {
                        connector,
                        session,
                        id,
                        value,
                        attempted,
                        ..
                    } => lazy_yubihsm_attestation_certificate(
                        connector.as_ref(),
                        session,
                        *id,
                        value,
                        attempted,
                    )
                    .and_then(|value| piv_certificate_attribute(&value, x)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn is_key_object(&self) -> bool {
        self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    fn can_wrap(&self) -> bool {
        matches!(
            &self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_WRAP_KEY | YUBIHSM_PUBLIC_WRAP_KEY,
                capabilities,
                ..
            } if yubihsm_capability(capabilities, 0x0c)
        )
    }

    fn can_unwrap(&self) -> bool {
        matches!(
            &self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_WRAP_KEY,
                capabilities,
                ..
            } if yubihsm_capability(capabilities, 0x0d)
        )
    }

    fn is_nonextractable_key_object(&self) -> bool {
        (self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS)
            && !matches!(&self.material, KeyMaterial::DerivedSecret(_))
    }

    fn is_certificate_object(&self) -> bool {
        self.class == CKO_CERTIFICATE as CK_OBJECT_CLASS
    }

    fn is_yubihsm_opaque(&self) -> bool {
        matches!(
            self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )
    }

    fn is_immutable_object(&self) -> bool {
        matches!(
            &self.material,
            KeyMaterial::Profile { .. }
                | KeyMaterial::PivPrivate { .. }
                | KeyMaterial::PivPublic { .. }
                | KeyMaterial::PivCertificate { .. }
                | KeyMaterial::PivAttestation { .. }
                | KeyMaterial::PivData { .. }
                | KeyMaterial::OpenPgpPrivate { .. }
                | KeyMaterial::OpenPgpPublic { .. }
                | KeyMaterial::OpenPgpCertificate { .. }
                | KeyMaterial::OpenPgpData { .. }
                | KeyMaterial::IssuerSecurityDomainData { .. }
                | KeyMaterial::IssuerSecurityDomainCertificate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::HsmAuthPublic { .. }
                | KeyMaterial::YubiHsm { .. }
                | KeyMaterial::YubiHsmDevicePublic { .. }
                | KeyMaterial::YubiHsmAttestation { .. }
                | KeyMaterial::DerivedSecret(_)
        )
    }

    fn set_attribute_value(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        let value = read_attribute_value(attribute)?;
        match attribute.type_ {
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => {
                self.label = String::from_utf8(value)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID as CK_RV)?;
                Ok(())
            }
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => {
                self.id = value;
                Ok(())
            }
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE => {
                if !self.has_sensitive_attributes() {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
                let requested = read_bool_template_attribute(attribute)?;
                if self.sensitive && !requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                self.sensitive = requested;
                Ok(())
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE => {
                if !self.has_sensitive_attributes() {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
                let requested = read_bool_template_attribute(attribute)?;
                if self.is_nonextractable_key_object() && requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                if !self.extractable && requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                self.extractable = requested;
                Ok(())
            }
            x if self.attribute_value(x).is_some() => Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV),
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    fn set_copy_attribute_value(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        match attribute.type_ {
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => {
                self.token = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => {
                self.private = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            _ => self.set_attribute_value(attribute),
        }
    }

    fn matches_template(&self, templ: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        templ.iter().all(|(type_, expected)| {
            self.attribute_value(*type_)
                .map(|value| expected == &value)
                .unwrap_or(false)
        })
    }
}

fn validate_new_object_access(
    object: &TokenObject,
    session_flags: CK_FLAGS,
    logged_in: bool,
) -> Result<(), Error> {
    if object.private && !logged_in {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }
    if object.token && session_flags & CKF_RW_SESSION as CK_FLAGS == 0 {
        return Err(CKR_SESSION_READ_ONLY.into());
    }
    Ok(())
}

impl TokenObjectTemplate {
    fn apply_attribute(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        match attribute.type_ {
            x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE => {
                self.class = Some(read_ulong_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE => {
                self.key_type = Some(read_ulong_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => {
                self.label = String::from_utf8(read_attribute_value(attribute)?)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID as CK_RV)?;
                Ok(())
            }
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => {
                self.id = read_attribute_value(attribute)?;
                Ok(())
            }
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => {
                self.token = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => {
                self.private = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE => {
                self.encrypt = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE => {
                self.decrypt = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_SIGN as CK_ATTRIBUTE_TYPE => {
                self.sign = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_VERIFY as CK_ATTRIBUTE_TYPE => {
                self.verify = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_DERIVE as CK_ATTRIBUTE_TYPE => {
                self.derive = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE => {
                self.sensitive = Some(read_bool_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE => {
                self.extractable = Some(read_bool_template_attribute(attribute)?);
                Ok(())
            }
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    fn into_object(self) -> Result<TokenObject, CK_RV> {
        let sensitive = self.sensitive.unwrap_or(false);
        let class = self.class.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?;
        let nonextractable_key = class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || class == CKO_SECRET_KEY as CK_OBJECT_CLASS;
        let extractable = self.extractable.unwrap_or(!nonextractable_key);
        if nonextractable_key && extractable {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
        }
        Ok(TokenObject {
            slot_id: None,
            unique_id: String::new(),
            class,
            key_type: self.key_type.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?,
            label: self.label,
            id: self.id,
            token: self.token,
            private: self.private,
            encrypt: self.encrypt,
            decrypt: self.decrypt,
            sign: self.sign,
            verify: self.verify,
            derive: self.derive,
            sensitive,
            extractable,
            always_sensitive: sensitive,
            never_extractable: !extractable || nonextractable_key,
            local: false,
            key_gen_mechanism: None,
            owner_session: None,
            material: KeyMaterial::None,
        })
    }
}
