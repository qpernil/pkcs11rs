use crate::key_metadata::{
    AttributeKind, KeyAttributeValue, KeyAttributes, KeyMetadataError, attribute_kind,
    cryptoki_ulong_to_u64,
};
use crate::piv;
use crate::pkcs11::*;
use crate::{
    CKA_PKCS11RS_FIDO_RP_ID, CKA_PKCS11RS_PIV_OBJECT_TAG, CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
    CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION, CKA_YUBICO_HSMAUTH_ALGORITHM,
    CKA_YUBICO_HSMAUTH_RETRIES, CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED, CKA_YUBICO_PIN_POLICY,
    CKA_YUBICO_TOUCH_POLICY, Connector, Error, HsmAuthAlgorithm, MessageDigest, OpenPgpAlgorithm,
    OpenPgpClient, OpenPgpKeyRef, PivClient, YUBIHSM_ALGO_ED25519, YUBIHSM_OPAQUE,
    YUBIHSM_PUBLIC_KEY, YUBIHSM_WRAP_KEY_PUBLIC, YubiHsmCommand, YubiHsmSessionState,
    der_octet_string, hash, is_yubihsm_ec, is_yubihsm_rsa, is_yubihsm_x25519,
    openpgp_signature_requires_context_specific_login, piv_algorithm_from_certificate,
    piv_effective_pin_policy, piv_public_key_from_certificate, send_yubihsm_secure_command,
    yubihsm_capabilities_to_attributes, yubihsm_capability, yubihsm_ec_parameters,
};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use std::{cell::RefCell, rc::Rc, slice};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct KeyPolicyTemplates {
    pub(crate) wrap: Option<KeyAttributes>,
    pub(crate) unwrap: Option<KeyAttributes>,
    pub(crate) derive: Option<KeyAttributes>,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenObject {
    pub(crate) slot_id: Option<CK_SLOT_ID>,
    pub(crate) unique_id: String,
    pub(crate) class: CK_OBJECT_CLASS,
    pub(crate) key_type: CK_KEY_TYPE,
    pub(crate) label: String,
    pub(crate) id: Vec<u8>,
    pub(crate) token: bool,
    pub(crate) private: bool,
    pub(crate) encrypt: bool,
    pub(crate) decrypt: bool,
    pub(crate) sign: bool,
    pub(crate) verify: bool,
    pub(crate) derive: bool,
    pub(crate) wrap: bool,
    pub(crate) unwrap: bool,
    pub(crate) sensitive: bool,
    pub(crate) extractable: bool,
    pub(crate) always_sensitive: bool,
    pub(crate) never_extractable: bool,
    pub(crate) local: bool,
    pub(crate) key_gen_mechanism: Option<CK_MECHANISM_TYPE>,
    pub(crate) allowed_mechanisms: Option<Vec<CK_MECHANISM_TYPE>>,
    pub(crate) wrap_with_trusted: bool,
    pub(crate) policy_templates: KeyPolicyTemplates,
    pub(crate) creator_session: Option<CK_SESSION_HANDLE>,
    pub(crate) public_key: Option<PublicKeyMaterial>,
    pub(crate) rp_id: Option<String>,
    pub(crate) material: KeyMaterial,
}

#[derive(Clone, Debug)]
pub(crate) enum PublicKeyMaterial {
    Rsa(RsaPublicKey),
    Ec {
        parameters: Vec<u8>,
        public_key: Vec<u8>,
    },
}

#[derive(Clone)]
pub(crate) enum SoftwarePrivateKeyMaterial {
    Rsa(Box<RsaPrivateKey>),
    P224(p224::SecretKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    K256(k256::SecretKey),
    BrainpoolP256(bp256::r1::SecretKey),
    BrainpoolP384(bp384::r1::SecretKey),
    BrainpoolP512(crate::brainpool512::SecretKey),
    Ed25519(ed25519_dalek::SigningKey),
    X25519(x25519_dalek::StaticSecret),
}

impl std::fmt::Debug for SoftwarePrivateKeyMaterial {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(key) => fmt.debug_tuple("Rsa").field(&key.size()).finish(),
            Self::P224(_) => fmt.write_str("P224([REDACTED])"),
            Self::P256(_) => fmt.write_str("P256([REDACTED])"),
            Self::P384(_) => fmt.write_str("P384([REDACTED])"),
            Self::P521(_) => fmt.write_str("P521([REDACTED])"),
            Self::K256(_) => fmt.write_str("K256([REDACTED])"),
            Self::BrainpoolP256(_) => fmt.write_str("BrainpoolP256([REDACTED])"),
            Self::BrainpoolP384(_) => fmt.write_str("BrainpoolP384([REDACTED])"),
            Self::BrainpoolP512(_) => fmt.write_str("BrainpoolP512([REDACTED])"),
            Self::Ed25519(_) => fmt.write_str("Ed25519([REDACTED])"),
            Self::X25519(_) => fmt.write_str("X25519([REDACTED])"),
        }
    }
}

impl SoftwarePrivateKeyMaterial {
    pub(crate) fn weierstrass_curve(&self) -> Option<crate::EcCurve> {
        match self {
            Self::P224(_) => Some(crate::EcCurve::P224),
            Self::P256(_) => Some(crate::EcCurve::P256),
            Self::P384(_) => Some(crate::EcCurve::P384),
            Self::P521(_) => Some(crate::EcCurve::P521),
            Self::K256(_) => Some(crate::EcCurve::K256),
            Self::BrainpoolP256(_) => Some(crate::EcCurve::BrainpoolP256),
            Self::BrainpoolP384(_) => Some(crate::EcCurve::BrainpoolP384),
            Self::BrainpoolP512(_) => Some(crate::EcCurve::BrainpoolP512),
            Self::Rsa(_) | Self::Ed25519(_) | Self::X25519(_) => None,
        }
    }

    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        match self {
            Self::Rsa(_) => CKK_RSA as CK_KEY_TYPE,
            Self::P224(_)
            | Self::P256(_)
            | Self::P384(_)
            | Self::P521(_)
            | Self::K256(_)
            | Self::BrainpoolP256(_)
            | Self::BrainpoolP384(_)
            | Self::BrainpoolP512(_) => CKK_EC as CK_KEY_TYPE,
            Self::Ed25519(_) => CKK_EC_EDWARDS as CK_KEY_TYPE,
            Self::X25519(_) => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
        }
    }

    pub(crate) fn public_key(&self) -> Result<PublicKeyMaterial, Error> {
        macro_rules! weierstrass {
            ($key:expr, $curve:expr) => {{
                let encoded =
                    elliptic_curve::sec1::ToSec1Point::to_sec1_point(&$key.public_key(), false);
                let public_key = encoded
                    .as_bytes()
                    .strip_prefix(&[0x04])
                    .ok_or(CKR_DATA_INVALID)?
                    .to_vec();
                Ok(PublicKeyMaterial::Ec {
                    parameters: crate::ec_curve_parameters($curve).to_vec(),
                    public_key,
                })
            }};
        }
        match self {
            Self::Rsa(key) => Ok(PublicKeyMaterial::Rsa(RsaPublicKey::from(key.as_ref()))),
            Self::P224(key) => weierstrass!(key, crate::EcCurve::P224),
            Self::P256(key) => weierstrass!(key, crate::EcCurve::P256),
            Self::P384(key) => weierstrass!(key, crate::EcCurve::P384),
            Self::P521(key) => weierstrass!(key, crate::EcCurve::P521),
            Self::K256(key) => weierstrass!(key, crate::EcCurve::K256),
            Self::BrainpoolP256(key) => weierstrass!(key, crate::EcCurve::BrainpoolP256),
            Self::BrainpoolP384(key) => weierstrass!(key, crate::EcCurve::BrainpoolP384),
            Self::BrainpoolP512(key) => weierstrass!(key, crate::EcCurve::BrainpoolP512),
            Self::Ed25519(key) => Ok(PublicKeyMaterial::Ec {
                parameters: crate::piv_ec_parameters(piv::Algorithm::Ed25519)
                    .ok_or(CKR_CURVE_NOT_SUPPORTED)?
                    .to_vec(),
                public_key: key.verifying_key().to_bytes().to_vec(),
            }),
            Self::X25519(key) => Ok(PublicKeyMaterial::Ec {
                parameters: crate::piv_ec_parameters(piv::Algorithm::X25519)
                    .ok_or(CKR_CURVE_NOT_SUPPORTED)?
                    .to_vec(),
                public_key: x25519_dalek::PublicKey::from(key).as_bytes().to_vec(),
            }),
        }
    }

    pub(crate) fn private_value(&self) -> Option<Vec<u8>> {
        match self {
            Self::Rsa(_) => None,
            Self::P224(key) => Some(key.to_bytes().to_vec()),
            Self::P256(key) => Some(key.to_bytes().to_vec()),
            Self::P384(key) => Some(key.to_bytes().to_vec()),
            Self::P521(key) => Some(key.to_bytes().to_vec()),
            Self::K256(key) => Some(key.to_bytes().to_vec()),
            Self::BrainpoolP256(key) => Some(key.to_bytes().to_vec()),
            Self::BrainpoolP384(key) => Some(key.to_bytes().to_vec()),
            Self::BrainpoolP512(key) => Some(key.to_bytes().to_vec()),
            Self::Ed25519(key) => Some(key.to_bytes().to_vec()),
            Self::X25519(key) => Some(key.to_bytes().to_vec()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) enum LazyCache<T> {
    #[default]
    Unattempted,
    Missing,
    Value(T),
}

impl<T> LazyCache<T> {
    pub(crate) fn is_unattempted(&self) -> bool {
        matches!(self, Self::Unattempted)
    }

    pub(crate) fn value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Unattempted | Self::Missing => None,
        }
    }
}

pub(crate) type SharedLazyBytes = Rc<RefCell<LazyCache<Vec<u8>>>>;

#[derive(Clone)]
#[cfg_attr(not(any(test, feature = "abi-tests")), allow(dead_code))]
pub(crate) enum KeyMaterial {
    None,
    Profile {
        profile_id: CK_PROFILE_ID,
    },
    Public(PublicKeyMaterial),
    SoftwarePrivate(SoftwarePrivateKeyMaterial),
    PivPrivate {
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        pin_policy: u8,
        touch_policy: u8,
    },
    OpenPgpPrivate {
        key_ref: OpenPgpKeyRef,
        algorithm: OpenPgpAlgorithm,
        pin_policy: u8,
        touch_policy: u8,
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
        cache: SharedLazyBytes,
    },
    OpenPgpCertificate {
        value: Vec<u8>,
    },
    OpenPgpData {
        tag: u16,
        connector: Rc<dyn Connector>,
        cache: SharedLazyBytes,
    },
    IssuerSecurityDomainData {
        value: Vec<u8>,
        application: String,
        object_id: Vec<u8>,
    },
    IssuerSecurityDomainCertificate {
        value: Vec<u8>,
    },
    FidoCredential {
        rp_id_hash: [u8; 32],
        response_cbor: Vec<u8>,
    },
    FidoResidentPrivate {
        credential_id: Vec<u8>,
    },
    FidoPreviewCredential {
        registration: crate::preview_sign::PreviewSignRegistration,
    },
    PreviewSignRegistration {
        registration: crate::preview_sign::PreviewSignRegistration,
    },
    PreviewSignDerived {
        registration: crate::preview_sign::PreviewSignRegistration,
        derived: crate::preview_sign::PreviewSignDerivedKeyRecord,
    },
    HsmAuthCredential {
        algorithm: HsmAuthAlgorithm,
        retries: u8,
        touch_required: bool,
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
    YubiHsmAttestation {
        connector: Rc<dyn Connector>,
        session: Rc<RefCell<YubiHsmSessionState>>,
        id: u16,
        algorithm: u8,
        cache: SharedLazyBytes,
    },
    #[allow(dead_code)]
    SoftwareSecret(Zeroizing<Vec<u8>>),
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
            Self::Public(key) => fmt.debug_tuple("Public").field(key).finish(),
            Self::SoftwarePrivate(key) => fmt.debug_tuple("SoftwarePrivate").field(key).finish(),
            Self::PivPrivate {
                slot,
                algorithm,
                touch_policy,
                ..
            } => fmt
                .debug_struct("PivPrivate")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("touch_policy", touch_policy)
                .finish(),
            Self::OpenPgpPrivate {
                key_ref,
                algorithm,
                pin_policy,
                ..
            } => fmt
                .debug_struct("OpenPgpPrivate")
                .field("key_ref", key_ref)
                .field("algorithm", algorithm)
                .field("pin_policy", pin_policy)
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
            Self::YubiHsmAttestation {
                id,
                algorithm,
                cache,
                ..
            } => fmt
                .debug_struct("YubiHsmAttestation")
                .field("id", id)
                .field("algorithm", algorithm)
                .field("cached", &cache.borrow().value().is_some())
                .finish(),
            Self::SoftwareSecret(key) => {
                fmt.debug_tuple("SoftwareSecret").field(&key.len()).finish()
            }
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
                cache,
                ..
            } => fmt
                .debug_struct("PivAttestation")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("cached", &cache.borrow().value().is_some())
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
            Self::OpenPgpData { tag, cache, .. } => fmt
                .debug_struct("OpenPgpData")
                .field("tag", tag)
                .field("cached", &cache.borrow().value().is_some())
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
            Self::FidoCredential {
                rp_id_hash,
                response_cbor,
                ..
            } => fmt
                .debug_struct("FidoCredential")
                .field("rp_id_hash", rp_id_hash)
                .field("response_size", &response_cbor.len())
                .finish(),
            Self::FidoResidentPrivate { .. } => fmt
                .debug_struct("FidoResidentPrivate")
                .finish_non_exhaustive(),
            Self::FidoPreviewCredential { .. } => fmt
                .debug_struct("FidoPreviewCredential")
                .finish_non_exhaustive(),
            Self::PreviewSignRegistration { .. } => fmt
                .debug_struct("PreviewSignRegistration")
                .finish_non_exhaustive(),
            Self::PreviewSignDerived { .. } => fmt
                .debug_struct("PreviewSignDerived")
                .finish_non_exhaustive(),
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
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct TokenObjectTemplate {
    pub(crate) class: Option<CK_OBJECT_CLASS>,
    pub(crate) key_type: Option<CK_KEY_TYPE>,
    pub(crate) label: String,
    pub(crate) id: Vec<u8>,
    pub(crate) token: bool,
    pub(crate) private: bool,
    pub(crate) encrypt: bool,
    pub(crate) decrypt: bool,
    pub(crate) sign: bool,
    pub(crate) verify: bool,
    pub(crate) derive: bool,
    pub(crate) wrap: bool,
    pub(crate) unwrap: bool,
    pub(crate) sensitive: Option<bool>,
    pub(crate) extractable: Option<bool>,
    pub(crate) allowed_mechanisms: Option<Vec<CK_MECHANISM_TYPE>>,
    pub(crate) wrap_with_trusted: bool,
    pub(crate) policy_templates: KeyPolicyTemplates,
}

#[derive(Debug)]
pub(crate) struct FindOperation {
    pub(crate) objects: Vec<CK_OBJECT_HANDLE>,
    pub(crate) next: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct SignatureOperation {
    pub(crate) key: KeyMaterial,
    pub(crate) public_key: Option<PublicKeyMaterial>,
    pub(crate) slot_id: CK_SLOT_ID,
    pub(crate) requires_login: bool,
    pub(crate) context_specific_extended: bool,
    pub(crate) context_specific_rp_id: Option<String>,
    pub(crate) fido_authorization: Option<crate::ctap::CredentialAuthorization>,
    pub(crate) mechanism: CK_MECHANISM_TYPE,
    pub(crate) mac_length: Option<usize>,
    pub(crate) gmac: Option<GcmParameters>,
    pub(crate) pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    pub(crate) piv_pin_policy: Option<u8>,
    pub(crate) buffer: Vec<u8>,
    pub(crate) result: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct GcmParameters {
    pub(crate) iv: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) tag_bits: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct CtrParameters {
    pub(crate) counter_bits: usize,
    pub(crate) counter_block: [u8; 16],
}

#[derive(Debug, Clone)]
pub(crate) struct CcmParameters {
    pub(crate) data_len: usize,
    pub(crate) nonce: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) mac_len: usize,
}

#[derive(Clone)]
pub(crate) struct CryptOperation {
    pub(crate) key: KeyMaterial,
    pub(crate) public_key: Option<PublicKeyMaterial>,
    pub(crate) slot_id: CK_SLOT_ID,
    pub(crate) requires_login: bool,
    pub(crate) context_specific_extended: bool,
    pub(crate) mechanism: CK_MECHANISM_TYPE,
    pub(crate) iv: Option<[u8; 16]>,
    pub(crate) des3_iv: Option<[u8; 8]>,
    pub(crate) ctr: Option<CtrParameters>,
    pub(crate) ccm: Option<CcmParameters>,
    pub(crate) gcm: Option<GcmParameters>,
    pub(crate) key_wrap_iv: Option<Vec<u8>>,
    pub(crate) oaep: Option<(u8, CK_MECHANISM_TYPE, Vec<u8>)>,
    pub(crate) piv_pin_policy: Option<u8>,
    pub(crate) buffer: Zeroizing<Vec<u8>>,
    pub(crate) multipart: bool,
    pub(crate) result: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for CryptOperation {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("CryptOperation")
            .field("key", &self.key)
            .field("public_key", &self.public_key)
            .field("slot_id", &self.slot_id)
            .field("requires_login", &self.requires_login)
            .field("context_specific_extended", &self.context_specific_extended)
            .field("mechanism", &self.mechanism)
            .field("iv", &self.iv)
            .field("des3_iv", &self.des3_iv)
            .field("ctr", &self.ctr)
            .field("ccm", &self.ccm)
            .field("gcm", &self.gcm)
            .field("key_wrap_iv", &self.key_wrap_iv)
            .field("oaep", &self.oaep)
            .field("piv_pin_policy", &self.piv_pin_policy)
            .field("buffer_length", &self.buffer.len())
            .field("multipart", &self.multipart)
            .field(
                "result_length",
                &self.result.as_ref().map(|result| result.len()),
            )
            .finish()
    }
}

pub(crate) fn ulong_attribute(value: CK_ULONG) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

pub(crate) fn bool_attribute(value: bool) -> Vec<u8> {
    vec![if value {
        CK_TRUE as CK_BBOOL
    } else {
        CK_FALSE as CK_BBOOL
    }]
}

fn is_common_storage_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE
            || x == CKA_TOKEN as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE
            || x == CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_LABEL as CK_ATTRIBUTE_TYPE
            || x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE
    )
}

fn is_common_key_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE
            || x == CKA_ID as CK_ATTRIBUTE_TYPE
            || x == CKA_START_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_END_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_DERIVE as CK_ATTRIBUTE_TYPE
            || x == CKA_LOCAL as CK_ATTRIBUTE_TYPE
            || x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE
            || x == CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE
            || x == CKA_OBJECT_VALIDATION_FLAGS as CK_ATTRIBUTE_TYPE
    )
}

fn is_common_public_key_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
            || x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE
            || x == CKA_VERIFY as CK_ATTRIBUTE_TYPE
            || x == CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP as CK_ATTRIBUTE_TYPE
            || x == CKA_ENCAPSULATE as CK_ATTRIBUTE_TYPE
            || x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_CRC64_VALUE as CK_ATTRIBUTE_TYPE
    )
}

fn is_common_private_key_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
            || x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE
            || x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE
            || x == CKA_SIGN as CK_ATTRIBUTE_TYPE
            || x == CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE
            || x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE
            || x == CKA_DECAPSULATE as CK_ATTRIBUTE_TYPE
            || x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
            || x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE
            || x == CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
            || x == CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_CRC64_VALUE as CK_ATTRIBUTE_TYPE
    )
}

fn is_common_secret_key_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE
            || x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE
            || x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE
            || x == CKA_SIGN as CK_ATTRIBUTE_TYPE
            || x == CKA_VERIFY as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP as CK_ATTRIBUTE_TYPE
            || x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE
            || x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
            || x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
            || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE
            || x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE
            || x == CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE
            || x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE
    )
}

fn is_x509_certificate_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE
            || x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE
            || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
            || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_START_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_END_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
            || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
            || x == CKA_ID as CK_ATTRIBUTE_TYPE
            || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
            || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
            || x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_URL as CK_ATTRIBUTE_TYPE
            || x == CKA_HASH_OF_SUBJECT_PUBLIC_KEY as CK_ATTRIBUTE_TYPE
            || x == CKA_HASH_OF_ISSUER_PUBLIC_KEY as CK_ATTRIBUTE_TYPE
            || x == CKA_JAVA_MIDP_SECURITY_DOMAIN as CK_ATTRIBUTE_TYPE
            || x == CKA_NAME_HASH_ALGORITHM as CK_ATTRIBUTE_TYPE
    )
}

fn is_rsa_public_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
            || x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
    )
}

fn is_rsa_private_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
    )
}

fn is_ec_public_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
            || x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
    )
}

fn is_ec_private_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE || x == CKA_VALUE as CK_ATTRIBUTE_TYPE
    )
}

const PKCS11_OBJECT_ATTRIBUTE_TYPES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_CLASS as CK_ATTRIBUTE_TYPE,
    CKA_TOKEN as CK_ATTRIBUTE_TYPE,
    CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
    CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE,
    CKA_LABEL as CK_ATTRIBUTE_TYPE,
    CKA_COPYABLE as CK_ATTRIBUTE_TYPE,
    CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE,
    CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
    CKA_APPLICATION as CK_ATTRIBUTE_TYPE,
    CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE,
    CKA_VALUE as CK_ATTRIBUTE_TYPE,
    CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE,
    CKA_TRUSTED as CK_ATTRIBUTE_TYPE,
    CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE,
    CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE,
    CKA_START_DATE as CK_ATTRIBUTE_TYPE,
    CKA_END_DATE as CK_ATTRIBUTE_TYPE,
    CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE,
    CKA_SUBJECT as CK_ATTRIBUTE_TYPE,
    CKA_ID as CK_ATTRIBUTE_TYPE,
    CKA_ISSUER as CK_ATTRIBUTE_TYPE,
    CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE,
    CKA_URL as CK_ATTRIBUTE_TYPE,
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY as CK_ATTRIBUTE_TYPE,
    CKA_HASH_OF_ISSUER_PUBLIC_KEY as CK_ATTRIBUTE_TYPE,
    CKA_JAVA_MIDP_SECURITY_DOMAIN as CK_ATTRIBUTE_TYPE,
    CKA_NAME_HASH_ALGORITHM as CK_ATTRIBUTE_TYPE,
    CKA_PROFILE_ID as CK_ATTRIBUTE_TYPE,
    CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
    CKA_DERIVE as CK_ATTRIBUTE_TYPE,
    CKA_LOCAL as CK_ATTRIBUTE_TYPE,
    CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
    CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE,
    CKA_OBJECT_VALIDATION_FLAGS as CK_ATTRIBUTE_TYPE,
    CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
    CKA_VERIFY as CK_ATTRIBUTE_TYPE,
    CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE,
    CKA_WRAP as CK_ATTRIBUTE_TYPE,
    CKA_ENCAPSULATE as CK_ATTRIBUTE_TYPE,
    CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
    CKA_PUBLIC_CRC64_VALUE as CK_ATTRIBUTE_TYPE,
    CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
    CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
    CKA_SIGN as CK_ATTRIBUTE_TYPE,
    CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE,
    CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
    CKA_DECAPSULATE as CK_ATTRIBUTE_TYPE,
    CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
    CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
    CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
    CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
    CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
    CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE,
    CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE,
    CKA_MODULUS as CK_ATTRIBUTE_TYPE,
    CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
    CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
    CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE,
    CKA_PRIME_1 as CK_ATTRIBUTE_TYPE,
    CKA_PRIME_2 as CK_ATTRIBUTE_TYPE,
    CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE,
    CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE,
    CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE,
    CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
    CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
    CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
];

pub(crate) fn piv_object_tag(object_id: u32) -> Vec<u8> {
    let bytes = object_id.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    bytes[first..].to_vec()
}

pub(crate) fn piv_certificate_attribute(
    value: &[u8],
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    match attribute_type {
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => Some(value.to_vec()),
        x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE => {
            Some(ulong_attribute(CKC_X_509 as CK_ULONG))
        }
        x if x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE => Some(bool_attribute(false)),
        x if x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(
            CK_CERTIFICATE_CATEGORY_UNSPECIFIED as CK_ULONG,
        )),
        x if x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE => {
            Some(hash(MessageDigest::sha1(), value).ok()?[..3].to_vec())
        }
        x if x == CKA_START_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_END_DATE as CK_ATTRIBUTE_TYPE
            || x == CKA_URL as CK_ATTRIBUTE_TYPE
            || x == CKA_HASH_OF_SUBJECT_PUBLIC_KEY as CK_ATTRIBUTE_TYPE
            || x == CKA_HASH_OF_ISSUER_PUBLIC_KEY as CK_ATTRIBUTE_TYPE =>
        {
            Some(Vec::new())
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
        x if x == CKA_JAVA_MIDP_SECURITY_DOMAIN as CK_ATTRIBUTE_TYPE => {
            Some(ulong_attribute(CK_SECURITY_DOMAIN_UNSPECIFIED as CK_ULONG))
        }
        x if x == CKA_NAME_HASH_ALGORITHM as CK_ATTRIBUTE_TYPE => {
            Some(ulong_attribute(CKM_SHA_1 as CK_ULONG))
        }
        _ => None,
    }
}

pub(crate) fn der_integer(magnitude: &[u8]) -> Option<Vec<u8>> {
    let first_nonzero = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    let magnitude = &magnitude[first_nonzero..];
    let needs_sign_padding = magnitude.first().is_some_and(|byte| byte & 0x80 != 0);
    let content_length = magnitude.len().max(1) + usize::from(needs_sign_padding);
    let mut content = Vec::with_capacity(content_length);
    if magnitude.is_empty() || needs_sign_padding {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    Some(der_tlv(0x02, &content))
}

pub(crate) fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 1 + std::mem::size_of::<usize>());
    encoded.push(tag);
    if value.len() < 128 {
        encoded.push(value.len() as u8);
    } else {
        let length = value.len().to_be_bytes();
        let first = length
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(length.len() - 1);
        encoded.push(0x80 | (length.len() - first) as u8);
        encoded.extend_from_slice(&length[first..]);
    }
    encoded.extend_from_slice(value);
    encoded
}

pub(crate) fn rsa_public_key_info(modulus: &[u8], public_exponent: &[u8]) -> Option<Vec<u8>> {
    if modulus.is_empty() || public_exponent.is_empty() {
        return None;
    }
    let mut public_key = der_integer(modulus)?;
    public_key.extend(der_integer(public_exponent)?);
    let public_key = der_tlv(0x30, &public_key);
    let mut subject_public_key = vec![0];
    subject_public_key.extend(public_key);

    let algorithm = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut info = algorithm.to_vec();
    info.extend(der_tlv(0x03, &subject_public_key));
    Some(der_tlv(0x30, &info))
}

pub(crate) fn ec_public_key_info(
    key_type: CK_KEY_TYPE,
    parameters: Option<&[u8]>,
    public_key: &[u8],
) -> Option<Vec<u8>> {
    if public_key.is_empty() {
        return None;
    }
    let mut algorithm = match key_type {
        x if x == CKK_EC as CK_KEY_TYPE => {
            let mut algorithm = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
            algorithm.extend_from_slice(parameters?);
            der_tlv(0x30, &algorithm)
        }
        x if x == CKK_EC_EDWARDS as CK_KEY_TYPE => der_tlv(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]),
        x if x == CKK_EC_MONTGOMERY as CK_KEY_TYPE => {
            der_tlv(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x6e])
        }
        _ => return None,
    };
    let mut subject_public_key = vec![0];
    if key_type == CKK_EC as CK_KEY_TYPE {
        subject_public_key.push(0x04);
    }
    subject_public_key.extend_from_slice(public_key);
    algorithm.extend(der_tlv(0x03, &subject_public_key));
    Some(der_tlv(0x30, &algorithm))
}

pub(crate) fn is_certificate_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
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

pub(crate) fn lazy_piv_attestation_certificate(
    connector: &dyn Connector,
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    cache: &RefCell<LazyCache<Vec<u8>>>,
) -> Option<Vec<u8>> {
    if !cache.borrow().is_unattempted() {
        return cache.borrow().value().cloned();
    }

    let certificate = PivClient
        .attestation(connector, slot)
        .ok()
        .filter(|certificate| piv_algorithm_from_certificate(certificate) == Some(algorithm))
        .and_then(|certificate| {
            piv_public_key_from_certificate(algorithm, &certificate)
                .ok()
                .map(|_| certificate)
        });
    *cache.borrow_mut() = match certificate {
        Some(ref certificate) => LazyCache::Value(certificate.clone()),
        None => LazyCache::Missing,
    };
    certificate
}

pub(crate) fn lazy_yubihsm_attestation_certificate(
    connector: &dyn Connector,
    session: &RefCell<YubiHsmSessionState>,
    id: u16,
    cache: &RefCell<LazyCache<Vec<u8>>>,
) -> Option<Vec<u8>> {
    if !cache.borrow().is_unattempted() {
        return cache.borrow().value().cloned();
    }

    let certificate = send_yubihsm_secure_command(
        connector,
        session,
        &YubiHsmCommand::sign_attestation_certificate(id, 0),
    )
    .ok()
    .filter(|certificate| crate::certificate_chain::validate(certificate).is_ok());
    *cache.borrow_mut() = match certificate {
        Some(ref certificate) => LazyCache::Value(certificate.clone()),
        None => LazyCache::Missing,
    };
    certificate
}

impl TokenObject {
    pub(crate) fn allows_mechanism(&self, mechanism: CK_MECHANISM_TYPE) -> bool {
        self.allowed_mechanisms
            .as_ref()
            .is_none_or(|allowed| allowed.contains(&mechanism))
    }

    pub(crate) fn policy_template(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&KeyAttributes> {
        match attribute {
            x if x == CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE => self.policy_templates.wrap.as_ref(),
            x if x == CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE => {
                self.policy_templates.unwrap.as_ref()
            }
            x if x == CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE => {
                self.policy_templates.derive.as_ref()
            }
            _ => None,
        }
    }

    pub(crate) fn matches_policy_template(&self, template: &KeyAttributes) -> bool {
        template.iter().all(|(attribute, expected)| {
            let Some(type_) = policy_u64_to_ulong(*attribute) else {
                return false;
            };
            if let KeyAttributeValue::Template(expected) = expected {
                return self
                    .policy_template(type_)
                    .map_or_else(|| expected.is_empty(), |actual| actual == expected);
            }
            if !self.supports_attribute(type_) || self.attribute_is_sensitive(type_) {
                return false;
            }
            let Some(bytes) = self.attribute_value(type_) else {
                return false;
            };
            semantic_native_value(type_, &bytes).as_ref() == Ok(expected)
        })
    }

    pub(crate) fn supports_public_projection(&self) -> bool {
        self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS && self.public_key_info().is_some()
    }

    pub(crate) fn allows_derive(&self) -> bool {
        self.derive || self.supports_public_projection()
    }

    pub(crate) fn supports_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
        if is_common_storage_attribute(attribute_type) {
            return true;
        }
        if attribute_type == CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE
            && self.is_key_object()
            && self.allowed_mechanisms.is_none()
        {
            return false;
        }

        let standard = match self.class {
            x if x == CKO_DATA as CK_OBJECT_CLASS => matches!(
                attribute_type,
                x if x == CKA_APPLICATION as CK_ATTRIBUTE_TYPE
                    || x == CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE
                    || x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            ),
            x if x == CKO_CERTIFICATE as CK_OBJECT_CLASS => {
                is_x509_certificate_attribute(attribute_type)
            }
            x if x == CKO_PROFILE as CK_OBJECT_CLASS => {
                attribute_type == CKA_PROFILE_ID as CK_ATTRIBUTE_TYPE
            }
            x if x == CKO_PUBLIC_KEY as CK_OBJECT_CLASS => {
                is_common_key_attribute(attribute_type)
                    || is_common_public_key_attribute(attribute_type)
                    || match self.key_type {
                        x if x == CKK_RSA as CK_KEY_TYPE => is_rsa_public_attribute(attribute_type),
                        x if x == CKK_EC as CK_KEY_TYPE
                            || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                            || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE =>
                        {
                            is_ec_public_attribute(attribute_type)
                        }
                        _ => false,
                    }
            }
            x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
                is_common_key_attribute(attribute_type)
                    || is_common_private_key_attribute(attribute_type)
                    || match self.key_type {
                        x if x == CKK_RSA as CK_KEY_TYPE => {
                            is_rsa_private_attribute(attribute_type)
                        }
                        x if x == CKK_EC as CK_KEY_TYPE
                            || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                            || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE =>
                        {
                            is_ec_private_attribute(attribute_type)
                        }
                        _ => false,
                    }
            }
            x if x == CKO_SECRET_KEY as CK_OBJECT_CLASS => {
                is_common_key_attribute(attribute_type)
                    || is_common_secret_key_attribute(attribute_type)
                    || attribute_type == CKA_VALUE as CK_ATTRIBUTE_TYPE
            }
            _ => false,
        };
        standard
            || self.supports_vendor_attribute(attribute_type)
            || self.supports_compatibility_attribute(attribute_type)
    }

    fn supports_compatibility_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
        // OpenSC queries this public-key capability while rendering secret keys.
        self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
            && attribute_type == CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE
    }

    fn supports_vendor_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
        if attribute_type == CKA_PKCS11RS_FIDO_RP_ID {
            return self.rp_id.is_some();
        }
        match &self.material {
            KeyMaterial::PivData { .. } => attribute_type == CKA_PKCS11RS_PIV_OBJECT_TAG,
            KeyMaterial::PivPrivate { .. } => {
                attribute_type == CKA_YUBICO_TOUCH_POLICY || attribute_type == CKA_YUBICO_PIN_POLICY
            }
            KeyMaterial::OpenPgpPrivate { .. } => attribute_type == CKA_YUBICO_TOUCH_POLICY,
            KeyMaterial::HsmAuthCredential { .. } => matches!(
                attribute_type,
                CKA_YUBICO_HSMAUTH_ALGORITHM
                    | CKA_YUBICO_HSMAUTH_RETRIES
                    | CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED
            ),
            KeyMaterial::FidoPreviewCredential { .. }
            | KeyMaterial::PreviewSignRegistration { .. } => {
                attribute_type == CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION
            }
            KeyMaterial::PreviewSignDerived { .. } => matches!(
                attribute_type,
                CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION | CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY
            ),
            _ => false,
        }
    }

    pub(crate) fn attribute_is_sensitive(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
        if !self.supports_attribute(attribute_type) {
            return false;
        }
        if self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
            && attribute_type == CKA_VALUE as CK_ATTRIBUTE_TYPE
        {
            return self.sensitive
                || (matches!(self.material, KeyMaterial::SoftwareSecret(_)) && !self.extractable);
        }
        if self.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS || !self.sensitive {
            return false;
        }
        match self.key_type {
            x if x == CKK_RSA as CK_KEY_TYPE => matches!(
                attribute_type,
                x if x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
                    || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
                    || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
                    || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
                    || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
                    || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
            ),
            x if x == CKK_EC as CK_KEY_TYPE
                || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                || x == CKK_EC_MONTGOMERY as CK_KEY_TYPE =>
            {
                attribute_type == CKA_VALUE as CK_ATTRIBUTE_TYPE
            }
            _ => false,
        }
    }

    pub(crate) fn attribute_types(&self) -> Vec<CK_ATTRIBUTE_TYPE> {
        let mut types = PKCS11_OBJECT_ATTRIBUTE_TYPES
            .iter()
            .copied()
            .filter(|attribute_type| self.supports_attribute(*attribute_type))
            .collect::<Vec<_>>();
        for attribute_type in [
            CKA_PKCS11RS_PIV_OBJECT_TAG,
            CKA_YUBICO_HSMAUTH_ALGORITHM,
            CKA_YUBICO_HSMAUTH_RETRIES,
            CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED,
            CKA_YUBICO_TOUCH_POLICY,
            CKA_YUBICO_PIN_POLICY,
            CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            CKA_PKCS11RS_FIDO_RP_ID,
        ] {
            if self.supports_attribute(attribute_type) {
                types.push(attribute_type);
            }
        }
        types
    }

    pub(crate) fn public_key_info(&self) -> Option<Vec<u8>> {
        if !matches!(
            self.class,
            x if x == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                || x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
        ) {
            return None;
        }
        if let Ok(public_key) = self.projected_public_key() {
            return match &public_key {
                PublicKeyMaterial::Rsa(key) => {
                    rsa_public_key_info(&key.n().to_bytes_be(), &key.e().to_bytes_be())
                }
                PublicKeyMaterial::Ec {
                    parameters,
                    public_key,
                } => ec_public_key_info(self.key_type, Some(parameters), public_key),
            };
        }
        None
    }

    pub(crate) fn projected_public_key(&self) -> Result<PublicKeyMaterial, Error> {
        if let Some(public_key) = &self.public_key {
            return Ok(public_key.clone());
        }
        match &self.material {
            KeyMaterial::Public(public_key) => Ok(public_key.clone()),
            KeyMaterial::SoftwarePrivate(key) => key.public_key(),
            KeyMaterial::YubiHsm {
                algorithm,
                public_key,
                ..
            } if is_yubihsm_rsa(*algorithm) => {
                RsaPublicKey::new(BigUint::from_bytes_be(public_key), BigUint::from(65537u32))
                    .map(PublicKeyMaterial::Rsa)
                    .map_err(|_| Error::from(CKR_DATA_INVALID))
            }
            KeyMaterial::YubiHsm {
                algorithm,
                public_key,
                ..
            } => yubihsm_ec_parameters(*algorithm)
                .map(|parameters| PublicKeyMaterial::Ec {
                    parameters: parameters.to_vec(),
                    public_key: public_key.clone(),
                })
                .ok_or_else(|| Error::from(CKR_KEY_TYPE_INCONSISTENT)),
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        }
    }

    pub(crate) fn has_sensitive_attributes(&self) -> bool {
        self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    pub(crate) fn is_visible_to(&self, logged_in: bool) -> bool {
        !self.private || logged_in
    }

    pub(crate) fn set_creator(&mut self, session_handle: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID) {
        self.slot_id = Some(slot_id);
        self.creator_session = (!self.token).then_some(session_handle);
    }

    pub(crate) fn size(&self) -> CK_ULONG {
        let defer_certificate_attributes = matches!(
            &self.material,
            KeyMaterial::PivAttestation { cache, .. }
                | KeyMaterial::YubiHsmAttestation { cache, .. }
                if cache.borrow().is_unattempted()
        );
        self.attribute_types()
            .into_iter()
            .filter(|&attribute_type| {
                !defer_certificate_attributes || !is_certificate_attribute(attribute_type)
            })
            .filter(|&attribute_type| !self.attribute_is_sensitive(attribute_type))
            .filter_map(|attribute_type| self.attribute_value(attribute_type))
            .map(|value| value.len() as CK_ULONG)
            .sum()
    }

    pub(crate) fn attribute_value(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        if !self.supports_attribute(attribute_type) {
            return None;
        }
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
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => Some(self.id.clone()),
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.token)),
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.private)),
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
                    KeyMaterial::FidoResidentPrivate { .. } => true,
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
                Some(bool_attribute(self.allows_derive()))
            }
            x if x == CKA_WRAP as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.can_wrap()))
            }
            x if x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.can_unwrap()))
            }
            x if x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE
                && matches!(
                    self.class,
                    x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                        || x == CKO_SECRET_KEY as CK_OBJECT_CLASS
                ) =>
            {
                Some(bool_attribute(self.wrap_with_trusted))
            }
            x if x == CKA_ENCAPSULATE as CK_ATTRIBUTE_TYPE
                || x == CKA_DECAPSULATE as CK_ATTRIBUTE_TYPE
                || x == CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE
                || x == CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE =>
            {
                Some(bool_attribute(false))
            }
            x if x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE
                && matches!(self.material, KeyMaterial::YubiHsm { .. }) =>
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
            x if x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE => Some(bool_attribute(false)),
            x if x == CKA_APPLICATION as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { .. } if self.is_yubihsm_opaque() => {
                    Some(b"Opaque object".to_vec())
                }
                KeyMaterial::YubiHsm {
                    object_type: crate::YUBIHSM_TEMPLATE,
                    ..
                } => Some(b"Template object".to_vec()),
                KeyMaterial::YubiHsm { .. } => Some(b"YubiHSM object".to_vec()),
                KeyMaterial::IssuerSecurityDomainData { application, .. } => {
                    Some(application.as_bytes().to_vec())
                }
                KeyMaterial::PivData { .. } => Some(b"PIV".to_vec()),
                KeyMaterial::OpenPgpData { .. } => Some(b"OpenPGP".to_vec()),
                KeyMaterial::FidoCredential { .. } => {
                    Some(b"FIDO2 discoverable credential".to_vec())
                }
                _ => None,
            },
            x if x == CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { .. } if self.is_yubihsm_opaque() => Some(Vec::new()),
                KeyMaterial::YubiHsm { .. } => Some(Vec::new()),
                KeyMaterial::IssuerSecurityDomainData { object_id, .. } => Some(object_id.clone()),
                KeyMaterial::PivData { object_id, .. } => {
                    piv::data_object_mapping(*object_id).and_then(piv::data_object_oid)
                }
                KeyMaterial::OpenPgpData { tag, .. } => Some(tag.to_be_bytes().to_vec()),
                KeyMaterial::FidoCredential { rp_id_hash, .. } => Some(rp_id_hash.to_vec()),
                _ => None,
            },
            x if x == CKA_PKCS11RS_PIV_OBJECT_TAG => match &self.material {
                KeyMaterial::PivData { object_id, .. } => Some(piv_object_tag(*object_id)),
                _ => None,
            },
            x if x == CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION => match &self.material {
                KeyMaterial::FidoPreviewCredential { registration, .. }
                | KeyMaterial::PreviewSignRegistration { registration }
                | KeyMaterial::PreviewSignDerived { registration, .. } => {
                    registration.to_cbor().ok()
                }
                _ => None,
            },
            x if x == CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY => match &self.material {
                KeyMaterial::PreviewSignDerived { derived, .. } => derived.to_cbor().ok(),
                _ => None,
            },
            x if x == CKA_PKCS11RS_FIDO_RP_ID => {
                self.rp_id.as_ref().map(|rp_id| rp_id.as_bytes().to_vec())
            }
            x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE && self.is_certificate_object() => {
                Some(ulong_attribute(CKC_X_509 as CK_ULONG))
            }
            x if x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwareSecret(value)
                | KeyMaterial::Secret(value)
                | KeyMaterial::DerivedSecret(value) => {
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
            x if x == CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                self.allowed_mechanisms.as_ref().map(|mechanisms| {
                    mechanisms
                        .iter()
                        .flat_map(|mechanism| mechanism.to_ne_bytes())
                        .collect()
                })
            }
            x if x == CKA_START_DATE as CK_ATTRIBUTE_TYPE
                || x == CKA_END_DATE as CK_ATTRIBUTE_TYPE
                || x == CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
                || x == CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE
                || x == CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_CRC64_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_URL as CK_ATTRIBUTE_TYPE
                || x == CKA_HASH_OF_SUBJECT_PUBLIC_KEY as CK_ATTRIBUTE_TYPE
                || x == CKA_HASH_OF_ISSUER_PUBLIC_KEY as CK_ATTRIBUTE_TYPE =>
            {
                Some(Vec::new())
            }
            x if x == CKA_OBJECT_VALIDATION_FLAGS as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(0)),
            x if x == CKA_JAVA_MIDP_SECURITY_DOMAIN as CK_ATTRIBUTE_TYPE => {
                Some(ulong_attribute(CK_SECURITY_DOMAIN_UNSPECIFIED as CK_ULONG))
            }
            x if x == CKA_NAME_HASH_ALGORITHM as CK_ATTRIBUTE_TYPE => {
                Some(ulong_attribute(CKM_SHA_1 as CK_ULONG))
            }
            x if x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE && self.is_key_object() => Some(Vec::new()),
            x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE => match self.projected_public_key().ok() {
                Some(PublicKeyMaterial::Rsa(key)) => Some(key.n().to_bytes_be()),
                _ => match &self.material {
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                        Some(public_key.clone())
                    }
                    _ => None,
                },
            },
            x if x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE => {
                match self.projected_public_key().ok() {
                    Some(PublicKeyMaterial::Rsa(key)) => Some(key.e().to_bytes_be()),
                    _ => match &self.material {
                        KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                            Some(vec![0x01, 0x00, 0x01])
                        }
                        _ => None,
                    },
                }
            }
            x if x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    Some(key.d().to_bytes_be())
                }
                _ => None,
            },
            x if x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    key.primes().first().map(BigUint::to_bytes_be)
                }
                _ => None,
            },
            x if x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    key.primes().get(1).map(BigUint::to_bytes_be)
                }
                _ => None,
            },
            x if x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    key.dp().map(BigUint::to_bytes_be)
                }
                _ => None,
            },
            x if x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    key.dq().map(BigUint::to_bytes_be)
                }
                _ => None,
            },
            x if x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(key)) => {
                    key.qinv().map(|value| value.to_signed_bytes_be())
                }
                _ => None,
            },
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE => {
                match self.projected_public_key().ok() {
                    Some(PublicKeyMaterial::Rsa(key)) => {
                        Some(ulong_attribute((key.size() * 8) as CK_ULONG))
                    }
                    _ => match &self.material {
                        KeyMaterial::YubiHsm {
                            algorithm,
                            public_key,
                            ..
                        } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                            Some(ulong_attribute((public_key.len() * 8) as CK_ULONG))
                        }
                        _ => None,
                    },
                }
            }
            x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE => {
                match self.projected_public_key().ok() {
                    Some(PublicKeyMaterial::Ec { parameters, .. }) => Some(parameters),
                    _ => match &self.material {
                        KeyMaterial::YubiHsm { algorithm, .. } => {
                            yubihsm_ec_parameters(*algorithm).map(<[u8]>::to_vec)
                        }
                        _ => None,
                    },
                }
            }
            x if x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
                && self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS =>
            {
                match self.projected_public_key().ok() {
                    Some(PublicKeyMaterial::Ec { public_key, .. }) if !public_key.is_empty() => {
                        let point = if self.key_type == CKK_EC as CK_KEY_TYPE {
                            let mut point = Vec::with_capacity(public_key.len() + 1);
                            point.push(0x04);
                            point.extend_from_slice(&public_key);
                            point
                        } else {
                            public_key
                        };
                        der_octet_string(&point)
                    }
                    _ => match &self.material {
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
                        _ => None,
                    },
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
            x if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(self.public_key_info().unwrap_or_default())
            }
            x if x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
                && self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS =>
            {
                Some(Vec::new())
            }
            x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
                || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
                || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
                || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE =>
            {
                match &self.material {
                    KeyMaterial::SoftwarePrivate(key) if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => {
                        key.private_value()
                    }
                    KeyMaterial::SoftwareSecret(value)
                    | KeyMaterial::Secret(value)
                    | KeyMaterial::DerivedSecret(value)
                        if x == CKA_VALUE as CK_ATTRIBUTE_TYPE =>
                    {
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
                    KeyMaterial::FidoCredential { response_cbor, .. }
                        if x == CKA_VALUE as CK_ATTRIBUTE_TYPE =>
                    {
                        Some(response_cbor.clone())
                    }
                    KeyMaterial::OpenPgpData {
                        connector,
                        tag,
                        cache,
                    } if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => {
                        if cache.borrow().is_unattempted() {
                            *cache.borrow_mut() =
                                match OpenPgpClient.get_data(connector.as_ref(), *tag) {
                                    Ok(value) => LazyCache::Value(value),
                                    Err(_) => LazyCache::Missing,
                                };
                        }
                        Some(cache.borrow().value().cloned().unwrap_or_default())
                    }
                    KeyMaterial::PivAttestation {
                        connector,
                        slot,
                        algorithm,
                        cache,
                    } => lazy_piv_attestation_certificate(
                        connector.as_ref(),
                        *slot,
                        *algorithm,
                        cache,
                    )
                    .and_then(|value| piv_certificate_attribute(&value, x)),
                    KeyMaterial::YubiHsmAttestation {
                        connector,
                        session,
                        id,
                        cache,
                        ..
                    } => lazy_yubihsm_attestation_certificate(
                        connector.as_ref(),
                        session,
                        *id,
                        cache,
                    )
                    .and_then(|value| piv_certificate_attribute(&value, x)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub(crate) fn is_key_object(&self) -> bool {
        self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    pub(crate) fn can_wrap(&self) -> bool {
        self.wrap
            || matches!(
                &self.material,
                KeyMaterial::YubiHsm {
                    object_type,
                    algorithm,
                    capabilities,
                    ..
                } if yubihsm_capabilities_to_attributes(*object_type, *algorithm, capabilities).wrap
            )
    }

    pub(crate) fn can_unwrap(&self) -> bool {
        self.unwrap
            || matches!(
                &self.material,
                KeyMaterial::YubiHsm {
                    object_type,
                    algorithm,
                    capabilities,
                    ..
                } if yubihsm_capabilities_to_attributes(*object_type, *algorithm, capabilities).unwrap
            )
    }

    pub(crate) fn is_nonextractable_key_object(&self) -> bool {
        (self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS)
            && !matches!(&self.material, KeyMaterial::DerivedSecret(_))
            && !matches!(&self.material, KeyMaterial::SoftwarePrivate(_))
            && !matches!(&self.material, KeyMaterial::SoftwareSecret(_))
            && !matches!(
                &self.material,
                KeyMaterial::YubiHsm { capabilities, .. }
                    if yubihsm_capability(capabilities, 0x10)
            )
    }

    pub(crate) fn is_certificate_object(&self) -> bool {
        self.class == CKO_CERTIFICATE as CK_OBJECT_CLASS
    }

    pub(crate) fn is_yubihsm_opaque(&self) -> bool {
        matches!(
            self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )
    }

    pub(crate) fn is_yubihsm_public_projection(&self) -> bool {
        matches!(
            self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC,
                ..
            }
        )
    }

    pub(crate) fn is_immutable_object(&self) -> bool {
        matches!(
            &self.material,
            KeyMaterial::Profile { .. }
                | KeyMaterial::PivPrivate { .. }
                | KeyMaterial::PivCertificate { .. }
                | KeyMaterial::PivAttestation { .. }
                | KeyMaterial::PivData { .. }
                | KeyMaterial::OpenPgpPrivate { .. }
                | KeyMaterial::OpenPgpCertificate { .. }
                | KeyMaterial::OpenPgpData { .. }
                | KeyMaterial::IssuerSecurityDomainData { .. }
                | KeyMaterial::IssuerSecurityDomainCertificate { .. }
                | KeyMaterial::FidoCredential { .. }
                | KeyMaterial::FidoResidentPrivate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::YubiHsmAttestation { .. }
                | KeyMaterial::DerivedSecret(_)
        )
    }

    pub(crate) fn set_attribute_value(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        let value = read_attribute_value(attribute)?;
        match attribute.type_ {
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => {
                self.label =
                    String::from_utf8(value).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID as CK_RV)?;
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
            x if self.supports_attribute(x) => Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV),
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    pub(crate) fn set_copy_attribute_value(
        &mut self,
        attribute: &CK_ATTRIBUTE,
    ) -> Result<(), CK_RV> {
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
}

pub(crate) fn rsa_public_key_material(
    material: &KeyMaterial,
) -> Result<Option<RsaPublicKey>, Error> {
    match material {
        KeyMaterial::Public(PublicKeyMaterial::Rsa(key)) => Ok(Some(key.clone())),
        KeyMaterial::YubiHsm {
            object_type: YUBIHSM_PUBLIC_KEY,
            algorithm,
            public_key,
            ..
        } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
            RsaPublicKey::new(BigUint::from_bytes_be(public_key), BigUint::from(65537u32))
                .map(Some)
                .map_err(|_| Error::from(CKR_DATA_INVALID))
        }
        _ => Ok(None),
    }
}

pub(crate) fn validate_new_object_access(
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
    pub(crate) fn apply_attribute(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
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
            x if x == CKA_WRAP as CK_ATTRIBUTE_TYPE => {
                self.wrap = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE => {
                self.unwrap = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE => {
                self.wrap_with_trusted = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE => {
                self.policy_templates.wrap = Some(read_policy_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE => {
                self.policy_templates.unwrap = Some(read_policy_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE => {
                self.policy_templates.derive = Some(read_policy_template_attribute(attribute)?);
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
            x if x == CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE => {
                let value = read_attribute_value(attribute)?;
                let width = std::mem::size_of::<CK_MECHANISM_TYPE>();
                if !crate::is_multiple_of(value.len(), width) {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
                }
                let mut mechanisms = value
                    .chunks_exact(width)
                    .map(|bytes| {
                        let mut encoded = [0; std::mem::size_of::<CK_MECHANISM_TYPE>()];
                        encoded.copy_from_slice(bytes);
                        CK_MECHANISM_TYPE::from_ne_bytes(encoded)
                    })
                    .collect::<Vec<_>>();
                mechanisms.sort_unstable();
                if mechanisms.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(CKR_TEMPLATE_INCONSISTENT as CK_RV);
                }
                self.allowed_mechanisms = Some(mechanisms);
                Ok(())
            }
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    pub(crate) fn into_object(self) -> Result<TokenObject, CK_RV> {
        self.into_object_with_software_secret_policy(false)
    }

    pub(crate) fn into_software_secret_object(self) -> Result<TokenObject, CK_RV> {
        self.into_object_with_software_secret_policy(true)
    }

    fn into_object_with_software_secret_policy(
        self,
        software_secret: bool,
    ) -> Result<TokenObject, CK_RV> {
        let sensitive = self.sensitive.unwrap_or(false);
        let class = self.class.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?;
        let nonextractable_key = class == CKO_SECRET_KEY as CK_OBJECT_CLASS;
        let private_key = class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
        if self.wrap_with_trusted
            && !matches!(
                class,
                x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                    || x == CKO_SECRET_KEY as CK_OBJECT_CLASS
            )
        {
            return Err(CKR_TEMPLATE_INCONSISTENT as CK_RV);
        }
        if self.policy_templates.wrap.is_some()
            && class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            && class != CKO_SECRET_KEY as CK_OBJECT_CLASS
            || self.policy_templates.unwrap.is_some()
                && class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && class != CKO_SECRET_KEY as CK_OBJECT_CLASS
            || self.policy_templates.derive.is_some()
                && class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && class != CKO_SECRET_KEY as CK_OBJECT_CLASS
        {
            return Err(CKR_TEMPLATE_INCONSISTENT as CK_RV);
        }
        let extractable = self
            .extractable
            .unwrap_or(!(private_key || (nonextractable_key && !software_secret)));
        if nonextractable_key && !software_secret && extractable {
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
            wrap: self.wrap,
            unwrap: self.unwrap,
            sensitive,
            extractable,
            always_sensitive: sensitive,
            never_extractable: !extractable || (nonextractable_key && !software_secret),
            local: false,
            key_gen_mechanism: None,
            allowed_mechanisms: self.allowed_mechanisms,
            wrap_with_trusted: self.wrap_with_trusted,
            policy_templates: self.policy_templates,
            creator_session: None,
            public_key: None,
            rp_id: None,
            material: KeyMaterial::None,
        })
    }
}

pub(crate) fn read_attribute_value(attribute: &CK_ATTRIBUTE) -> Result<Vec<u8>, CK_RV> {
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

fn key_metadata_error(error: KeyMetadataError) -> CK_RV {
    match error {
        KeyMetadataError::UnsupportedAttribute(_) => CKR_ATTRIBUTE_TYPE_INVALID as CK_RV,
        _ => CKR_ATTRIBUTE_VALUE_INVALID as CK_RV,
    }
}

fn semantic_native_value(
    attribute: CK_ATTRIBUTE_TYPE,
    bytes: &[u8],
) -> Result<KeyAttributeValue, CK_RV> {
    match attribute_kind(cryptoki_ulong_to_u64(attribute)).map_err(key_metadata_error)? {
        AttributeKind::Boolean if bytes.len() == std::mem::size_of::<CK_BBOOL>() => {
            match bytes[0] {
                x if x == CK_FALSE as CK_BBOOL => Ok(KeyAttributeValue::Boolean(false)),
                x if x == CK_TRUE as CK_BBOOL => Ok(KeyAttributeValue::Boolean(true)),
                _ => Err(CKR_DATA_INVALID as CK_RV),
            }
        }
        AttributeKind::Unsigned if bytes.len() == std::mem::size_of::<CK_ULONG>() => {
            let mut encoded = [0; std::mem::size_of::<CK_ULONG>()];
            encoded.copy_from_slice(bytes);
            Ok(KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(
                CK_ULONG::from_ne_bytes(encoded),
            )))
        }
        AttributeKind::Bytes => Ok(KeyAttributeValue::Bytes(bytes.to_vec())),
        AttributeKind::Text => String::from_utf8(bytes.to_vec())
            .map(KeyAttributeValue::Text)
            .map_err(|_| CKR_DATA_INVALID as CK_RV),
        AttributeKind::Mechanisms
            if crate::is_multiple_of(bytes.len(), std::mem::size_of::<CK_MECHANISM_TYPE>()) =>
        {
            let values = bytes
                .chunks_exact(std::mem::size_of::<CK_MECHANISM_TYPE>())
                .map(|bytes| {
                    let mut encoded = [0; std::mem::size_of::<CK_MECHANISM_TYPE>()];
                    encoded.copy_from_slice(bytes);
                    cryptoki_ulong_to_u64(CK_MECHANISM_TYPE::from_ne_bytes(encoded))
                })
                .collect();
            Ok(KeyAttributeValue::Mechanisms(values))
        }
        _ => Err(CKR_DATA_INVALID as CK_RV),
    }
}

pub(crate) fn key_attribute_native_value(value: &KeyAttributeValue) -> Result<Vec<u8>, CK_RV> {
    match value {
        KeyAttributeValue::Boolean(value) => Ok(bool_attribute(*value)),
        KeyAttributeValue::Unsigned(value) => policy_u64_to_ulong(*value)
            .map(ulong_attribute)
            .ok_or(CKR_DATA_INVALID as CK_RV),
        KeyAttributeValue::Bytes(value) => Ok(value.clone()),
        KeyAttributeValue::Text(value) => Ok(value.as_bytes().to_vec()),
        KeyAttributeValue::Mechanisms(values) => values
            .iter()
            .copied()
            .map(CK_MECHANISM_TYPE::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map(|values| {
                values
                    .iter()
                    .flat_map(|value| value.to_ne_bytes())
                    .collect()
            })
            .map_err(|_| CKR_DATA_INVALID as CK_RV),
        KeyAttributeValue::Template(_) => Err(CKR_DATA_INVALID as CK_RV),
    }
}

fn policy_u64_to_ulong(value: u64) -> Option<CK_ULONG> {
    #[cfg(any(windows, target_pointer_width = "32"))]
    {
        CK_ULONG::try_from(value).ok()
    }
    #[cfg(all(not(windows), target_pointer_width = "64"))]
    {
        Some(value)
    }
}

#[derive(Debug)]
struct OwnedPolicyAttribute {
    type_: CK_ATTRIBUTE_TYPE,
    value: Vec<u8>,
    nested: Option<OwnedPolicyTemplate>,
}

#[derive(Debug)]
pub(crate) struct OwnedPolicyTemplate {
    attributes: Vec<OwnedPolicyAttribute>,
    ffi: Vec<CK_ATTRIBUTE>,
}

impl OwnedPolicyTemplate {
    fn from_semantic(template: &KeyAttributes) -> Result<Self, CK_RV> {
        let mut attributes = Vec::with_capacity(template.iter().count());
        for (type_, value) in template.iter() {
            let type_ = policy_u64_to_ulong(*type_).ok_or(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV)?;
            let (value, nested) = match value {
                KeyAttributeValue::Template(nested) => {
                    (Vec::new(), Some(Self::from_semantic(nested)?))
                }
                value => (key_attribute_native_value(value)?, None),
            };
            attributes.push(OwnedPolicyAttribute {
                type_,
                value,
                nested,
            });
        }
        Ok(Self {
            attributes,
            ffi: Vec::new(),
        })
    }

    fn refresh(&mut self) {
        for attribute in &mut self.attributes {
            if let Some(nested) = &mut attribute.nested {
                nested.refresh();
            }
        }
        self.ffi.clear();
        self.ffi.reserve(self.attributes.len());
        for attribute in &mut self.attributes {
            let (pointer, length) = match &mut attribute.nested {
                Some(nested) => (
                    nested.ffi.as_mut_ptr().cast(),
                    nested.ffi.len() * std::mem::size_of::<CK_ATTRIBUTE>(),
                ),
                None => (attribute.value.as_mut_ptr().cast(), attribute.value.len()),
            };
            self.ffi.push(CK_ATTRIBUTE {
                type_: attribute.type_,
                pValue: pointer,
                ulValueLen: length as CK_ULONG,
            });
        }
    }

    pub(crate) fn as_slice(&mut self) -> &[CK_ATTRIBUTE] {
        self.refresh();
        &self.ffi
    }
}

pub(crate) fn merge_policy_template(
    caller: &[CK_ATTRIBUTE],
    policy: Option<&KeyAttributes>,
) -> Result<OwnedPolicyTemplate, Error> {
    let mut merged = read_semantic_template(caller).map_err(Error::from)?;
    if let Some(policy) = policy {
        for (type_, value) in policy.iter() {
            if let Some(supplied) = merged.get(*type_) {
                if supplied != value {
                    return Err(CKR_TEMPLATE_INCONSISTENT.into());
                }
            } else {
                merged
                    .insert_template(*type_, value.clone())
                    .map_err(|_| Error::from(CKR_TEMPLATE_INCONSISTENT))?;
            }
        }
    }
    OwnedPolicyTemplate::from_semantic(&merged).map_err(Error::from)
}

fn read_policy_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<KeyAttributes, CK_RV> {
    read_policy_template(attribute, 0)
}

fn read_policy_value(attribute: &CK_ATTRIBUTE) -> Result<Vec<u8>, CK_RV> {
    let value = unsafe {
        crate::from_raw_parts(
            attribute.pValue.cast::<u8>().cast_const(),
            attribute.ulValueLen as usize,
        )
    }
    .map_err(CK_RV::from)?;
    Ok(value.to_vec())
}

fn read_policy_bool(attribute: &CK_ATTRIBUTE) -> Result<bool, CK_RV> {
    if attribute.ulValueLen as usize != std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    match read_policy_value(attribute)?[0] {
        x if x == CK_FALSE as CK_BBOOL => Ok(false),
        x if x == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV),
    }
}

fn read_policy_ulong(attribute: &CK_ATTRIBUTE) -> Result<CK_ULONG, CK_RV> {
    if attribute.ulValueLen as usize != std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_policy_value(attribute)?;
    let mut bytes = [0; std::mem::size_of::<CK_ULONG>()];
    bytes.copy_from_slice(&value);
    Ok(CK_ULONG::from_ne_bytes(bytes))
}

fn read_policy_template(attribute: &CK_ATTRIBUTE, depth: usize) -> Result<KeyAttributes, CK_RV> {
    let width = std::mem::size_of::<CK_ATTRIBUTE>();
    if depth >= 4 || !crate::is_multiple_of(attribute.ulValueLen as usize, width) {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let count = attribute.ulValueLen as usize / width;
    if count > 256 {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let nested = unsafe { crate::from_raw_parts(attribute.pValue.cast::<CK_ATTRIBUTE>(), count) }
        .map_err(CK_RV::from)?;
    read_semantic_template_at_depth(nested, depth)
}

pub(crate) fn read_semantic_template(items: &[CK_ATTRIBUTE]) -> Result<KeyAttributes, CK_RV> {
    read_semantic_template_at_depth(items, 0)
}

fn read_semantic_template_at_depth(
    nested: &[CK_ATTRIBUTE],
    depth: usize,
) -> Result<KeyAttributes, CK_RV> {
    let mut result = KeyAttributes::new();
    for item in nested {
        let kind = attribute_kind(cryptoki_ulong_to_u64(item.type_)).map_err(key_metadata_error)?;
        let value = match kind {
            AttributeKind::Boolean => KeyAttributeValue::Boolean(read_policy_bool(item)?),
            AttributeKind::Unsigned => {
                KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(read_policy_ulong(item)?))
            }
            AttributeKind::Bytes => KeyAttributeValue::Bytes(read_policy_value(item)?),
            AttributeKind::Text => KeyAttributeValue::Text(
                String::from_utf8(read_policy_value(item)?)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID as CK_RV)?,
            ),
            AttributeKind::Mechanisms => {
                let bytes = read_policy_value(item)?;
                let mechanism_width = std::mem::size_of::<CK_MECHANISM_TYPE>();
                if !crate::is_multiple_of(bytes.len(), mechanism_width) {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
                }
                let mut mechanisms = bytes
                    .chunks_exact(mechanism_width)
                    .map(|bytes| {
                        let mut encoded = [0; std::mem::size_of::<CK_MECHANISM_TYPE>()];
                        encoded.copy_from_slice(bytes);
                        cryptoki_ulong_to_u64(CK_MECHANISM_TYPE::from_ne_bytes(encoded))
                    })
                    .collect::<Vec<_>>();
                mechanisms.sort_unstable();
                if mechanisms.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(CKR_TEMPLATE_INCONSISTENT as CK_RV);
                }
                KeyAttributeValue::Mechanisms(mechanisms)
            }
            AttributeKind::Template => {
                KeyAttributeValue::Template(read_policy_template(item, depth + 1)?)
            }
        };
        if result
            .insert_template(cryptoki_ulong_to_u64(item.type_), value)
            .map_err(key_metadata_error)?
            .is_some()
        {
            return Err(CKR_TEMPLATE_INCONSISTENT as CK_RV);
        }
    }
    Ok(result)
}

pub(crate) fn read_ulong_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<CK_ULONG, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?;
    let mut bytes = [0u8; ::std::mem::size_of::<CK_ULONG>()];
    bytes.copy_from_slice(&value);
    Ok(CK_ULONG::from_ne_bytes(bytes))
}

pub(crate) fn read_bool_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<bool, CK_RV> {
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
