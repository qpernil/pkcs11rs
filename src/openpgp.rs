#![allow(dead_code)]

use crate::{
    error::Error,
    scp03::{select_application, CommandApdu},
    Connector, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED, CKR_KEY_TYPE_INCONSISTENT, CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_USER_NOT_LOGGED_IN,
};
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

pub(crate) const OPENPGP_AID: [u8; 6] = [0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
pub(crate) const PW1_ONE_SIGNATURE: u8 = 0x00;
pub(crate) const PW1_MULTIPLE_SIGNATURES: u8 = 0x01;

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
const INS_RESET_RETRY_COUNTER: u8 = 0x2c;
const INS_PUT_DATA: u8 = 0xda;
const INS_PUT_DATA_ODD: u8 = 0xdb;
const INS_PSO: u8 = 0x2a;
const INS_GET_DATA: u8 = 0xca;
const INS_GET_DATA_ODD: u8 = 0xcb;
const INS_GET_NEXT_DATA: u8 = 0xcc;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_ACTIVATE_FILE: u8 = 0x44;
const INS_TERMINATE_DF: u8 = 0xe6;
const INS_MANAGE_SECURITY_ENVIRONMENT: u8 = 0x22;
const INS_GET_VERSION: u8 = 0xf1;
const INS_SET_PIN_RETRIES: u8 = 0xf2;
const INS_GET_ATTESTATION: u8 = 0xfb;
const SELECT_CERTIFICATE_DATA: [u8; 6] = [0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21];
const STATUS_SUCCESS: u16 = 0x9000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum KeyRef {
    Signature = 1,
    Decipher = 2,
    Authentication = 3,
    Attestation = 0x81,
}

impl KeyRef {
    pub(crate) const ALL: [Self; 3] = [Self::Signature, Self::Decipher, Self::Authentication];

    fn certificate_occurrence(self) -> Option<u8> {
        match self {
            Self::Authentication => Some(0),
            Self::Decipher => Some(1),
            Self::Signature => Some(2),
            Self::Attestation => None,
        }
    }

    pub(crate) fn crt(self) -> &'static [u8] {
        match self {
            Self::Signature => &[0xb6, 0x00],
            Self::Decipher => &[0xb8, 0x00],
            Self::Authentication => &[0xa4, 0x00],
            Self::Attestation => &[0xb6, 0x03, 0x84, 0x01, 0x81],
        }
    }

    fn algorithm_tag(self) -> u32 {
        match self {
            Self::Signature => 0xc1,
            Self::Decipher => 0xc2,
            Self::Authentication => 0xc3,
            Self::Attestation => 0xda,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PasswordRef {
    UserSignature = 0x81,
    UserOperations = 0x82,
    Admin = 0x83,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityOperation {
    Authenticate,
    Decipher,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum DataObject {
    PrivateUse1 = 0x0101,
    PrivateUse2 = 0x0102,
    PrivateUse3 = 0x0103,
    PrivateUse4 = 0x0104,
    Aid = 0x004f,
    Name = 0x005b,
    LoginData = 0x005e,
    Language = 0x5f2d,
    Sex = 0x5f35,
    Url = 0x5f50,
    HistoricalBytes = 0x5f52,
    CardholderRelatedData = 0x0065,
    ApplicationRelatedData = 0x006e,
    SecuritySupportTemplate = 0x007a,
    CardholderCertificate = 0x7f21,
    ExtendedLengthInformation = 0x7f66,
    GeneralFeatureManagement = 0x7f74,
    SignatureCounter = 0x0093,
    ExtendedCapabilities = 0x00c0,
    AlgorithmAttributesSignature = 0x00c1,
    AlgorithmAttributesDecipher = 0x00c2,
    AlgorithmAttributesAuthentication = 0x00c3,
    PasswordStatus = 0x00c4,
    Fingerprints = 0x00c5,
    CaFingerprints = 0x00c6,
    FingerprintSignature = 0x00c7,
    FingerprintDecipher = 0x00c8,
    FingerprintAuthentication = 0x00c9,
    CaFingerprint1 = 0x00ca,
    CaFingerprint2 = 0x00cb,
    CaFingerprint3 = 0x00cc,
    GenerationTimes = 0x00cd,
    GenerationTimeSignature = 0x00ce,
    GenerationTimeDecipher = 0x00cf,
    GenerationTimeAuthentication = 0x00d0,
    ResettingCode = 0x00d3,
    UifSignature = 0x00d6,
    UifDecipher = 0x00d7,
    UifAuthentication = 0x00d8,
    UifAttestation = 0x00d9,
    AlgorithmAttributesAttestation = 0x00da,
    FingerprintAttestation = 0x00db,
    CaFingerprint4 = 0x00dc,
    GenerationTimeAttestation = 0x00dd,
    KeyInformation = 0x00de,
    Kdf = 0x00f9,
    AlgorithmInformation = 0x00fa,
    AttestationCertificate = 0x00fc,
}

impl DataObject {
    pub(crate) const fn tag(self) -> u16 {
        self as u16
    }
}

pub(crate) const EXPORTED_DATA_OBJECTS: &[(DataObject, &str)] = &[
    (DataObject::PrivateUse1, "Private use 1"),
    (DataObject::PrivateUse2, "Private use 2"),
    (DataObject::Name, "Cardholder name"),
    (DataObject::LoginData, "Login data"),
    (DataObject::Language, "Language preferences"),
    (DataObject::Sex, "Sex"),
    (DataObject::Url, "Public key URL"),
    (DataObject::Fingerprints, "Key fingerprints"),
    (DataObject::CaFingerprints, "CA fingerprints"),
    (DataObject::GenerationTimes, "Key generation times"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
    Secp256k1,
    Ed25519,
    X25519,
}

impl Curve {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        [
            (
                Self::P256,
                &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..],
            ),
            (Self::P384, &[0x2b, 0x81, 0x04, 0x00, 0x22][..]),
            (Self::P521, &[0x2b, 0x81, 0x04, 0x00, 0x23][..]),
            (
                Self::BrainpoolP256,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07][..],
            ),
            (
                Self::BrainpoolP384,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b][..],
            ),
            (
                Self::BrainpoolP512,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d][..],
            ),
            (Self::Secp256k1, &[0x2b, 0x81, 0x04, 0x00, 0x0a][..]),
            (
                Self::Ed25519,
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01][..],
            ),
            (
                Self::X25519,
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01][..],
            ),
        ]
        .into_iter()
        .find_map(|(curve, value)| (oid == value).then_some(curve))
    }

    pub(crate) fn oid(self) -> &'static [u8] {
        match self {
            Self::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            Self::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            Self::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
            Self::BrainpoolP256 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
            ],
            Self::BrainpoolP384 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
            ],
            Self::BrainpoolP512 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
            ],
            Self::Secp256k1 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
            Self::Ed25519 => &[
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
            ],
            Self::X25519 => &[
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
            ],
        }
    }

    pub(crate) fn coordinate_length(self) -> Option<usize> {
        match self {
            Self::P256 | Self::BrainpoolP256 | Self::Secp256k1 => Some(32),
            Self::P384 | Self::BrainpoolP384 => Some(48),
            Self::P521 => Some(66),
            Self::BrainpoolP512 => Some(64),
            Self::Ed25519 | Self::X25519 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Algorithm {
    Rsa { bits: usize },
    Ecdsa(Curve),
    Ecdh(Curve),
    Ed25519,
}

impl Algorithm {
    pub(crate) fn key_type(self) -> u64 {
        match self {
            Self::Rsa { .. } => crate::CKK_RSA as u64,
            Self::Ecdsa(_) | Self::Ecdh(_) => crate::CKK_EC as u64,
            Self::Ed25519 => crate::CKK_EC_EDWARDS as u64,
        }
    }

    pub(crate) fn is_rsa(self) -> bool {
        matches!(self, Self::Rsa { .. })
    }

    pub(crate) fn is_ec_signature(self) -> bool {
        matches!(self, Self::Ecdsa(_) | Self::Ed25519)
    }

    pub(crate) fn is_decryption(self) -> bool {
        matches!(self, Self::Rsa { .. } | Self::Ecdh(Curve::X25519))
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    Ec { curve: Curve, point: Vec<u8> },
    Raw { curve: Curve, key: Vec<u8> },
}

#[derive(Clone, Debug)]
pub(crate) struct KeyInfo {
    pub(crate) key_ref: KeyRef,
    pub(crate) algorithm: Algorithm,
    pub(crate) public_key: PublicKey,
    pub(crate) pin_policy: u8,
    pub(crate) touch_policy: u8,
    pub(crate) local: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyStatus {
    None,
    Generated,
    Imported,
}

#[derive(Clone, Debug)]
pub(crate) struct ApplicationInfo {
    pub(crate) version: (u8, u8),
    pub(crate) serial: String,
    pub(crate) pin_policy: u8,
    pub(crate) pin_min: u8,
    pub(crate) pin_max: u8,
    pub(crate) admin_pin_min: u8,
    pub(crate) admin_pin_max: u8,
    pub(crate) kdf: Option<KdfParams>,
    algorithms: Vec<(KeyRef, Algorithm)>,
    algorithm_attributes: Vec<(KeyRef, Vec<u8>)>,
    key_statuses: Vec<(KeyRef, KeyStatus)>,
}

#[derive(Clone, Debug)]
pub(crate) struct KdfParams {
    hash_algorithm: u8,
    iteration_count: u32,
    user_salt: Vec<u8>,
    reset_salt: Option<Vec<u8>>,
    admin_salt: Option<Vec<u8>>,
}

impl KdfParams {
    pub(crate) fn derive_user_pin(&self, pin: &[u8]) -> Result<Vec<u8>, Error> {
        self.derive_pin(PasswordRef::UserSignature, pin)
    }

    pub(crate) fn derive_pin(&self, password: PasswordRef, pin: &[u8]) -> Result<Vec<u8>, Error> {
        let salt = match password {
            PasswordRef::UserSignature | PasswordRef::UserOperations => &self.user_salt,
            PasswordRef::Admin => self.admin_salt.as_ref().unwrap_or(&self.user_salt),
        };
        self.derive_with_salt(salt, pin)
    }

    pub(crate) fn derive_reset_code(&self, code: &[u8]) -> Result<Vec<u8>, Error> {
        self.derive_with_salt(self.reset_salt.as_ref().unwrap_or(&self.user_salt), code)
    }

    fn derive_with_salt(&self, salt: &[u8], pin: &[u8]) -> Result<Vec<u8>, Error> {
        if self.iteration_count == 0 || salt.is_empty() {
            return Err(CKR_DATA_INVALID.into());
        }
        let mut salted_pin = Vec::with_capacity(salt.len() + pin.len());
        salted_pin.extend_from_slice(salt);
        salted_pin.extend_from_slice(pin);
        if salted_pin.is_empty() {
            return Err(CKR_DATA_INVALID.into());
        }

        fn derive<D: Digest>(salted_pin: &[u8], iteration_count: usize) -> Vec<u8> {
            let mut hasher = D::new();
            let mut remaining = iteration_count;
            while remaining > 0 {
                let length = remaining.min(salted_pin.len());
                hasher.update(&salted_pin[..length]);
                remaining -= length;
            }
            hasher.finalize().to_vec()
        }

        match self.hash_algorithm {
            0x08 => Ok(derive::<Sha256>(&salted_pin, self.iteration_count as usize)),
            0x0a => Ok(derive::<Sha512>(&salted_pin, self.iteration_count as usize)),
            _ => Err(CKR_DATA_INVALID.into()),
        }
    }
}

impl ApplicationInfo {
    pub(crate) fn algorithm(&self, key_ref: KeyRef) -> Option<Algorithm> {
        self.algorithms
            .iter()
            .find_map(|(reference, algorithm)| (*reference == key_ref).then_some(*algorithm))
    }

    pub(crate) fn key_status(&self, key_ref: KeyRef) -> Option<KeyStatus> {
        self.key_statuses
            .iter()
            .find_map(|(reference, status)| (*reference == key_ref).then_some(*status))
    }

    pub(crate) fn algorithm_attributes(&self, key_ref: KeyRef) -> Option<&[u8]> {
        self.algorithm_attributes
            .iter()
            .find_map(|(reference, value)| (*reference == key_ref).then_some(value.as_slice()))
    }

    pub(crate) fn key_is_local(&self, key_ref: KeyRef) -> bool {
        self.key_status(key_ref) == Some(KeyStatus::Generated)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Client;

impl Client {
    pub(crate) fn select(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
    ) -> Result<ApplicationInfo, Error> {
        select_application(connector, application_aid)?;
        let data = self.get_data(connector, 0x006e)?;
        let mut info = parse_application_info(&data)?;
        info.kdf = self
            .get_data(connector, 0x00f9)
            .ok()
            .map(|data| parse_kdf(&data))
            .transpose()?
            .flatten();
        Ok(info)
    }

    pub(crate) fn public_key(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        algorithm: Algorithm,
    ) -> Result<PublicKey, Error> {
        self.read_or_generate_key(connector, key_ref, algorithm, false)
    }

    pub(crate) fn generate_key_pair(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        algorithm: Algorithm,
    ) -> Result<PublicKey, Error> {
        self.read_or_generate_key(connector, key_ref, algorithm, true)
    }

    pub(crate) fn generate_key_pair_if_empty(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
        key_ref: KeyRef,
        algorithm: Algorithm,
    ) -> Result<PublicKey, Error> {
        let info = self.select(connector, application_aid)?;
        if info.key_status(key_ref) != Some(KeyStatus::None) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        if info.algorithm(key_ref) != Some(algorithm) {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        self.read_or_generate_key_unchecked(connector, key_ref, algorithm)
    }

    fn read_or_generate_key_unchecked(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        algorithm: Algorithm,
    ) -> Result<PublicKey, Error> {
        let response = self.transmit_key_creation(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GENERATE_ASYMMETRIC,
                p1: 0x80,
                p2: 0,
                data: key_ref.crt().to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        parse_generated_public_key(algorithm, &response)
    }

    fn read_or_generate_key(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        algorithm: Algorithm,
        generate: bool,
    ) -> Result<PublicKey, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GENERATE_ASYMMETRIC,
                p1: if generate { 0x80 } else { 0x81 },
                p2: 0,
                data: key_ref.crt().to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        parse_generated_public_key(algorithm, &response)
    }

    pub(crate) fn certificate(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
    ) -> Result<Vec<u8>, Error> {
        match key_ref.certificate_occurrence() {
            Some(occurrence) => {
                if connector
                    .firmware_version()
                    .is_some_and(|version| version < (5, 2, 0))
                {
                    if key_ref == KeyRef::Authentication {
                        return self.get_data(connector, DataObject::CardholderCertificate.tag());
                    }
                    return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
                }
                self.select_data(connector, occurrence, DataObject::CardholderCertificate)?;
                self.get_data(connector, DataObject::CardholderCertificate.tag())
            }
            None => self.get_data(connector, DataObject::AttestationCertificate.tag()),
        }
    }

    pub(crate) fn put_certificate(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        certificate: &[u8],
    ) -> Result<(), Error> {
        match key_ref.certificate_occurrence() {
            Some(occurrence) => {
                if connector
                    .firmware_version()
                    .is_some_and(|version| version < (5, 2, 0))
                {
                    if key_ref == KeyRef::Authentication {
                        return self.put_data(
                            connector,
                            DataObject::CardholderCertificate.tag(),
                            certificate,
                        );
                    }
                    return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
                }
                self.select_data(connector, occurrence, DataObject::CardholderCertificate)?;
                self.put_data(
                    connector,
                    DataObject::CardholderCertificate.tag(),
                    certificate,
                )
            }
            None => self.put_data(
                connector,
                DataObject::AttestationCertificate.tag(),
                certificate,
            ),
        }
    }

    pub(crate) fn select_data(
        &self,
        connector: &dyn Connector,
        occurrence: u8,
        object: DataObject,
    ) -> Result<(), Error> {
        if occurrence > 2 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut data = if object == DataObject::CardholderCertificate {
            SELECT_CERTIFICATE_DATA.to_vec()
        } else {
            let tag = object.tag();
            let tag_bytes = if tag <= 0xff {
                vec![tag as u8]
            } else {
                tag.to_be_bytes().to_vec()
            };
            encode_tlv(0x60, &encode_tlv(0x5c, &tag_bytes)?)?
        };
        if object == DataObject::CardholderCertificate
            && connector
                .firmware_version()
                .is_some_and(|version| ((5, 2, 0)..=(5, 4, 3)).contains(&version))
        {
            data.insert(0, data.len() as u8);
        }
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: 0xa5,
                p1: occurrence,
                p2: 0x04,
                data,
                le: Some(256),
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn verify_pin(
        &self,
        connector: &dyn Connector,
        pin: &[u8],
        extended: bool,
    ) -> Result<(), Error> {
        self.verify_password(
            connector,
            if extended {
                PasswordRef::UserOperations
            } else {
                PasswordRef::UserSignature
            },
            pin,
        )
    }

    pub(crate) fn verify_admin(&self, connector: &dyn Connector, pin: &[u8]) -> Result<(), Error> {
        self.verify_password(connector, PasswordRef::Admin, pin)
    }

    pub(crate) fn verify_password(
        &self,
        connector: &dyn Connector,
        password: PasswordRef,
        value: &[u8],
    ) -> Result<(), Error> {
        if value.is_empty() {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0,
                p2: password as u8,
                data: value.to_vec(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn verification_status(
        &self,
        connector: &dyn Connector,
        password: PasswordRef,
    ) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0,
                p2: password as u8,
                data: Vec::new(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn change_user_pin(
        &self,
        connector: &dyn Connector,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        self.change_password(connector, PasswordRef::UserSignature, old_pin, new_pin)
    }

    pub(crate) fn change_admin_pin(
        &self,
        connector: &dyn Connector,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        self.change_password(connector, PasswordRef::Admin, old_pin, new_pin)
    }

    pub(crate) fn change_password(
        &self,
        connector: &dyn Connector,
        password: PasswordRef,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        if password == PasswordRef::UserOperations {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if old_pin.is_empty() || new_pin.is_empty() {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let mut data = Vec::with_capacity(old_pin.len() + new_pin.len());
        data.extend_from_slice(old_pin);
        data.extend_from_slice(new_pin);
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_CHANGE_REFERENCE_DATA,
                p1: 0,
                p2: password as u8,
                data,
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn unverify(&self, connector: &dyn Connector, extended: bool) {
        let password = if extended {
            PasswordRef::UserOperations
        } else {
            PasswordRef::UserSignature
        };
        let _ = self.unverify_password(connector, password);
    }

    pub(crate) fn unverify_password(
        &self,
        connector: &dyn Connector,
        password: PasswordRef,
    ) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0xff,
                p2: password as u8,
                data: Vec::new(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn reset_user_pin(
        &self,
        connector: &dyn Connector,
        new_pin: &[u8],
        reset_code: Option<&[u8]>,
    ) -> Result<(), Error> {
        if new_pin.is_empty() {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let mut data = Vec::new();
        let p1 = if let Some(reset_code) = reset_code {
            if reset_code.is_empty() {
                return Err(CKR_PIN_LEN_RANGE.into());
            }
            data.reserve(reset_code.len() + new_pin.len());
            data.extend_from_slice(reset_code);
            0x00
        } else {
            data.reserve(new_pin.len());
            0x02
        };
        data.extend_from_slice(new_pin);
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_RESET_RETRY_COUNTER,
                p1,
                p2: PasswordRef::UserSignature as u8,
                extended: false,
                data,
                le: None,
            },
        )?;
        Ok(())
    }

    pub(crate) fn sign(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (ins, p1, p2) = match key_ref {
            KeyRef::Authentication => (INS_INTERNAL_AUTHENTICATE, 0, 0),
            KeyRef::Signature => (INS_PSO, 0x9e, 0x9a),
            KeyRef::Decipher | KeyRef::Attestation => {
                return Err(crate::CKR_KEY_FUNCTION_NOT_PERMITTED.into())
            }
        };
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins,
                p1,
                p2,
                data: input.to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        Ok(response)
    }

    pub(crate) fn decipher(
        &self,
        connector: &dyn Connector,
        input: &[u8],
        raw: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(input.len() + 1);
        data.push(if raw { 0x00 } else { 0x02 });
        data.extend_from_slice(input);
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PSO,
                p1: 0x80,
                p2: 0x86,
                data,
                le: Some(256),
                extended: false,
            },
        )?;
        Ok(response)
    }

    pub(crate) fn ecdh(
        &self,
        connector: &dyn Connector,
        curve: Curve,
        public_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let data = ecdh_cipher_do(curve, public_key)?;
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PSO,
                p1: 0x80,
                p2: 0x86,
                data,
                le: Some(256),
                extended: false,
            },
        )
    }

    pub(crate) fn encipher(
        &self,
        connector: &dyn Connector,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let response_length = plaintext
            .len()
            .checked_add(1)
            .and_then(|length| u32::try_from(length).ok())
            .filter(|length| *length <= 65_536)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PSO,
                p1: 0x86,
                p2: 0x80,
                data: plaintext.to_vec(),
                le: Some(response_length.max(256)),
                extended: false,
            },
        )
    }

    pub(crate) fn manage_security_environment(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        operation: SecurityOperation,
    ) -> Result<(), Error> {
        if !matches!(key_ref, KeyRef::Decipher | KeyRef::Authentication) {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_MANAGE_SECURITY_ENVIRONMENT,
                p1: 0x41,
                p2: match operation {
                    SecurityOperation::Authenticate => 0xa4,
                    SecurityOperation::Decipher => 0xb8,
                },
                data: vec![0x83, 0x01, key_ref as u8],
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn challenge(
        &self,
        connector: &dyn Connector,
        length: usize,
    ) -> Result<Vec<u8>, Error> {
        let length = u32::try_from(length)
            .ok()
            .filter(|length| (1..=65_536).contains(length))
            .ok_or(CKR_DATA_LEN_RANGE)?;
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_CHALLENGE,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(length),
                extended: false,
            },
        )?;
        if response.len() != length as usize {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(response)
    }

    pub(crate) fn get_data(&self, connector: &dyn Connector, tag: u16) -> Result<Vec<u8>, Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_DATA,
                p1: (tag >> 8) as u8,
                p2: tag as u8,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            },
        )
    }

    pub(crate) fn get_next_data(
        &self,
        connector: &dyn Connector,
        tag: u16,
    ) -> Result<Vec<u8>, Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_NEXT_DATA,
                p1: (tag >> 8) as u8,
                p2: tag as u8,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            },
        )
    }

    pub(crate) fn get_data_odd(
        &self,
        connector: &dyn Connector,
        p1: u8,
        p2: u8,
        tag_list: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let data = encode_tlv(0x5c, tag_list)?;
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_DATA_ODD,
                p1,
                p2,
                data,
                le: Some(256),
                extended: false,
            },
        )
    }

    pub(crate) fn put_data(
        &self,
        connector: &dyn Connector,
        tag: u16,
        value: &[u8],
    ) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PUT_DATA,
                p1: (tag >> 8) as u8,
                p2: tag as u8,
                data: value.to_vec(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn put_data_odd(
        &self,
        connector: &dyn Connector,
        p1: u8,
        p2: u8,
        value: &[u8],
    ) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PUT_DATA_ODD,
                p1,
                p2,
                data: value.to_vec(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn import_private_key(
        &self,
        connector: &dyn Connector,
        private_key_template: &[u8],
    ) -> Result<(), Error> {
        self.put_data_odd(connector, 0x3f, 0xff, private_key_template)
    }

    pub(crate) fn import_private_key_if_empty(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
        key_ref: KeyRef,
        algorithm: Algorithm,
        private_key_template: &[u8],
    ) -> Result<(), Error> {
        let info = self.select(connector, application_aid)?;
        if info.key_status(key_ref) != Some(KeyStatus::None) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        if info.algorithm(key_ref) != Some(algorithm) {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        self.transmit_key_creation(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PUT_DATA_ODD,
                p1: 0x3f,
                p2: 0xff,
                data: private_key_template.to_vec(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn firmware_version(
        &self,
        connector: &dyn Connector,
    ) -> Result<(u8, u8, u8), Error> {
        let encoded = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_VERSION,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            },
        )?;
        match encoded.as_slice() {
            [major, minor, patch] => Ok((bcd(*major), bcd(*minor), bcd(*patch))),
            _ => Err(CKR_DATA_INVALID.into()),
        }
    }

    pub(crate) fn set_pin_attempts(
        &self,
        connector: &dyn Connector,
        user: u8,
        reset: u8,
        admin: u8,
    ) -> Result<(), Error> {
        if !(1..=99).contains(&user) || !(1..=99).contains(&reset) || !(1..=99).contains(&admin) {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_SET_PIN_RETRIES,
                p1: 0,
                p2: 0,
                data: vec![user, reset, admin],
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn attest_key(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
    ) -> Result<(), Error> {
        if key_ref == KeyRef::Attestation {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        self.transmit(
            connector,
            CommandApdu {
                cla: 0x80,
                ins: INS_GET_ATTESTATION,
                p1: key_ref as u8,
                p2: 0,
                data: Vec::new(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn terminate(&self, connector: &dyn Connector) -> Result<(), Error> {
        self.command_without_data(connector, INS_TERMINATE_DF)
    }

    pub(crate) fn activate(&self, connector: &dyn Connector) -> Result<(), Error> {
        self.command_without_data(connector, INS_ACTIVATE_FILE)
    }

    fn command_without_data(&self, connector: &dyn Connector, ins: u8) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    fn transmit(&self, connector: &dyn Connector, command: CommandApdu) -> Result<Vec<u8>, Error> {
        if command_may_delete_keys(&command) {
            log!(
                2,
                "OpenPGP refused potentially key-destructive command {:02x}{:02x}{:02x}{:02x}",
                command.cla,
                command.ins,
                command.p1,
                command.p2
            );
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        let response = connector.send_apdu(&command)?;
        require_success(response.status, &command)?;
        Ok(response.data)
    }

    fn transmit_key_creation(
        &self,
        connector: &dyn Connector,
        command: CommandApdu,
    ) -> Result<Vec<u8>, Error> {
        let response = connector.send_apdu(&command)?;
        require_success(response.status, &command)?;
        Ok(response.data)
    }
}

fn parse_generated_public_key(algorithm: Algorithm, response: &[u8]) -> Result<PublicKey, Error> {
    let body = tlv_value(0x7f49, response)?;
    let fields = parse_tlvs(&body)?;
    match algorithm {
        Algorithm::Rsa { bits } => {
            let modulus = field_value(&fields, 0x81).ok_or(CKR_DATA_INVALID)?;
            let exponent = field_value(&fields, 0x82).ok_or(CKR_DATA_INVALID)?;
            if modulus.len() * 8 != bits {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PublicKey::Rsa(
                RsaPublicKey::new(
                    BigUint::from_bytes_be(modulus),
                    BigUint::from_bytes_be(exponent),
                )
                .map_err(|_| Error::from(CKR_DATA_INVALID))?,
            ))
        }
        Algorithm::Ecdsa(curve) | Algorithm::Ecdh(curve) if curve.coordinate_length().is_some() => {
            let point = field_value(&fields, 0x86).ok_or(CKR_DATA_INVALID)?;
            let expected = curve.coordinate_length().unwrap() * 2 + 1;
            if point.len() != expected || point[0] != 0x04 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PublicKey::Ec {
                curve,
                point: point[1..].to_vec(),
            })
        }
        Algorithm::Ed25519 | Algorithm::Ecdh(Curve::X25519) => {
            let key = field_value(&fields, 0x86).ok_or(CKR_DATA_INVALID)?;
            if key.len() != 32 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PublicKey::Raw {
                curve: if algorithm == Algorithm::Ed25519 {
                    Curve::Ed25519
                } else {
                    Curve::X25519
                },
                key: key.to_vec(),
            })
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn command_may_delete_keys(command: &CommandApdu) -> bool {
    matches!(command.ins, INS_TERMINATE_DF | INS_ACTIVATE_FILE)
        || command.ins == INS_SET_PIN_RETRIES
        || (command.ins == INS_GENERATE_ASYMMETRIC && command.p1 == 0x80)
        || (command.ins == INS_PUT_DATA_ODD && command.p1 == 0x3f && command.p2 == 0xff)
        || (command.ins == INS_PUT_DATA
            && command.p1 == 0
            && matches!(command.p2, 0xc1 | 0xc2 | 0xc3 | 0xda))
}

fn require_success(status: u16, command: &CommandApdu) -> Result<(), Error> {
    match status {
        STATUS_SUCCESS => Ok(()),
        0x6983 => Err(CKR_PIN_LOCKED.into()),
        0x6982 | 0x6985 => Err(CKR_USER_NOT_LOGGED_IN.into()),
        0x63c0..=0x63cf => Err(CKR_PIN_INCORRECT.into()),
        0x6700 => Err(CKR_DATA_LEN_RANGE.into()),
        0x6a80 | 0x6a88 => Err(CKR_DATA_INVALID.into()),
        0x6a86 | 0x6b00 => Err(CKR_ARGUMENTS_BAD.into()),
        0x6d00 => Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
        _ => {
            log!(
                1,
                "OpenPGP command {:02x}{:02x}{:02x}{:02x} failed with status {:04x} ({} data bytes, Le {:?}, extended {})",
                command.cla,
                command.ins,
                command.p1,
                command.p2,
                status,
                command.data.len(),
                command.le,
                command.extended
            );
            Err(CKR_DEVICE_ERROR.into())
        }
    }
}

fn parse_application_info(encoded: &[u8]) -> Result<ApplicationInfo, Error> {
    let body = tlv_value(0x6e, encoded)?;
    let fields = parse_tlvs(&body)?;
    let aid = field_value(&fields, 0x4f).ok_or(CKR_DATA_INVALID)?;
    if aid.len() < 14 || aid[..6] != OPENPGP_AID {
        return Err(CKR_DATA_INVALID.into());
    }
    let version = (bcd(aid[6]), bcd(aid[7]));
    let serial = if aid[10..14]
        .iter()
        .all(|value| value >> 4 < 10 && value & 0x0f < 10)
    {
        aid[10..14]
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect()
    } else {
        u32::from_be_bytes(aid[10..14].try_into().unwrap()).to_string()
    };
    let discretionary = field_value(&fields, 0x73)
        .map(parse_tlvs)
        .transpose()?
        .unwrap_or_else(|| fields.clone());
    let pin_status = field_value(&discretionary, 0xc4).ok_or(CKR_DATA_INVALID)?;
    if pin_status.len() < 4 {
        return Err(CKR_DATA_INVALID.into());
    }
    let mut algorithms = Vec::new();
    let mut algorithm_attributes = Vec::new();
    for key_ref in KeyRef::ALL {
        if let Some(value) = field_value(&discretionary, key_ref.algorithm_tag()) {
            algorithms.push((key_ref, parse_algorithm(value)?));
            algorithm_attributes.push((key_ref, value.to_vec()));
        }
    }
    if let Some(value) = field_value(&discretionary, KeyRef::Attestation.algorithm_tag()) {
        if let Ok(algorithm) = parse_algorithm(value) {
            algorithms.push((KeyRef::Attestation, algorithm));
            algorithm_attributes.push((KeyRef::Attestation, value.to_vec()));
        }
    }
    let key_statuses = field_value(&discretionary, DataObject::KeyInformation.tag().into())
        .map(parse_key_information)
        .transpose()?
        .unwrap_or_default();
    Ok(ApplicationInfo {
        version,
        serial,
        pin_policy: pin_status[0],
        pin_min: 6,
        pin_max: pin_status[1],
        admin_pin_min: 8,
        admin_pin_max: pin_status[3],
        kdf: None,
        algorithms,
        algorithm_attributes,
        key_statuses,
    })
}

fn parse_key_information(encoded: &[u8]) -> Result<Vec<(KeyRef, KeyStatus)>, Error> {
    if !encoded.len().is_multiple_of(2) {
        return Err(CKR_DATA_INVALID.into());
    }
    encoded
        .chunks_exact(2)
        .filter_map(|entry| {
            let key_ref = match entry[0] {
                0x01 => KeyRef::Signature,
                0x02 => KeyRef::Decipher,
                0x03 => KeyRef::Authentication,
                0x81 => KeyRef::Attestation,
                _ => return None,
            };
            Some(match entry[1] {
                0 => Ok((key_ref, KeyStatus::None)),
                1 => Ok((key_ref, KeyStatus::Generated)),
                2 => Ok((key_ref, KeyStatus::Imported)),
                _ => Err(CKR_DATA_INVALID.into()),
            })
        })
        .collect()
}

fn parse_kdf(encoded: &[u8]) -> Result<Option<KdfParams>, Error> {
    let body = match tlv_value(0xf9, encoded) {
        Ok(body) => body,
        Err(_) => encoded.to_vec(),
    };
    let fields = parse_tlvs(&body)?;
    let algorithm = *field_value(&fields, 0x81)
        .ok_or(CKR_DATA_INVALID)?
        .first()
        .ok_or(CKR_DATA_INVALID)?;
    if algorithm == 0 {
        return Ok(None);
    }
    if algorithm != 3 {
        return Err(CKR_DATA_INVALID.into());
    }
    let hash_algorithm = *field_value(&fields, 0x82)
        .ok_or(CKR_DATA_INVALID)?
        .first()
        .ok_or(CKR_DATA_INVALID)?;
    if !matches!(hash_algorithm, 0x08 | 0x0a) {
        return Err(CKR_DATA_INVALID.into());
    }
    let iteration_bytes = field_value(&fields, 0x83).ok_or(CKR_DATA_INVALID)?;
    if iteration_bytes.len() != 4 {
        return Err(CKR_DATA_INVALID.into());
    }
    let user_salt = field_value(&fields, 0x84).ok_or(CKR_DATA_INVALID)?.to_vec();
    if user_salt.is_empty() {
        return Err(CKR_DATA_INVALID.into());
    }
    let reset_salt = field_value(&fields, 0x85).map(<[u8]>::to_vec);
    let admin_salt = field_value(&fields, 0x86).map(<[u8]>::to_vec);
    if reset_salt.as_ref().is_some_and(Vec::is_empty)
        || admin_salt.as_ref().is_some_and(Vec::is_empty)
    {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(Some(KdfParams {
        hash_algorithm,
        iteration_count: u32::from_be_bytes(iteration_bytes.try_into().unwrap()),
        user_salt,
        reset_salt,
        admin_salt,
    }))
}

fn parse_algorithm(value: &[u8]) -> Result<Algorithm, Error> {
    let algorithm = *value.first().ok_or(CKR_DATA_INVALID)?;
    match algorithm {
        0x01 => {
            if value.len() < 6 {
                return Err(CKR_DATA_INVALID.into());
            }
            let bits = u16::from_be_bytes([value[1], value[2]]) as usize;
            if !matches!(bits, 1024 | 2048 | 3072 | 4096) {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(Algorithm::Rsa { bits })
        }
        0x12 | 0x13 | 0x16 => {
            let oid = value[1..].strip_suffix(&[0xff]).unwrap_or(&value[1..]);
            let curve = Curve::from_oid(oid).ok_or(CKR_DATA_INVALID)?;
            match algorithm {
                0x12 => Ok(Algorithm::Ecdh(curve)),
                0x13 => Ok(Algorithm::Ecdsa(curve)),
                0x16 => Ok(Algorithm::Ed25519),
                _ => unreachable!(),
            }
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn ecdh_cipher_do(curve: Curve, public_key: &[u8]) -> Result<Vec<u8>, Error> {
    let expected_length = curve
        .coordinate_length()
        .map(|length| length * 2 + 1)
        .unwrap_or(32);
    if public_key.len() != expected_length {
        return Err(CKR_DATA_INVALID.into());
    }
    if curve.coordinate_length().is_some() && public_key.first() != Some(&0x04) {
        return Err(CKR_DATA_INVALID.into());
    }

    let public_key_do = encode_tlv(0x86, public_key)?;
    let public_key_template = encode_tlv(0x7f49, &public_key_do)?;
    encode_tlv(0xa6, &public_key_template)
}

fn encode_tlv(tag: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    match tag {
        0..=0xff => encoded.push(tag as u8),
        0x100..=0xffff => encoded.extend_from_slice(&(tag as u16).to_be_bytes()),
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    let length = value.len();
    match length {
        0..=0x7f => encoded.push(length as u8),
        0x80..=0xff => {
            encoded.extend([0x81, length as u8]);
        }
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn bcd(value: u8) -> u8 {
    (value >> 4) * 10 + (value & 0x0f)
}

fn field_value(fields: &[(u32, Vec<u8>)], tag: u32) -> Option<&[u8]> {
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == tag).then_some(value.as_slice()))
}

fn tlv_value(tag: u32, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let fields = parse_tlvs(encoded)?;
    field_value(&fields, tag)
        .map(<[u8]>::to_vec)
        .ok_or(CKR_DATA_INVALID.into())
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, Error> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        let (tag, tag_len) = parse_tag(encoded)?;
        encoded = &encoded[tag_len..];
        let (length, length_len) = parse_length(encoded)?;
        encoded = &encoded[length_len..];
        if encoded.len() < length {
            return Err(CKR_DATA_INVALID.into());
        }
        fields.push((tag, encoded[..length].to_vec()));
        encoded = &encoded[length..];
    }
    Ok(fields)
}

fn parse_tag(encoded: &[u8]) -> Result<(u32, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x1f != 0x1f {
        return Ok((first as u32, 1));
    }
    let second = *encoded.get(1).ok_or(CKR_DATA_INVALID)?;
    if second & 0x80 == 0 {
        Ok((((first as u32) << 8) | second as u32, 2))
    } else {
        Err(CKR_DATA_INVALID.into())
    }
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    match first {
        0..=0x7f => Ok((first as usize, 1)),
        0x81 => Ok((*encoded.get(1).ok_or(CKR_DATA_INVALID)? as usize, 2)),
        0x82 => {
            let bytes = encoded.get(1..3).ok_or(CKR_DATA_INVALID)?;
            Ok((u16::from_be_bytes([bytes[0], bytes[1]]) as usize, 3))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

#[cfg(test)]
mod tests;
