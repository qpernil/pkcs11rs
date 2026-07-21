#[derive(Debug)]
struct PivSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    slot_description: Option<String>,
    authenticated: Rc<Cell<bool>>,
    management_authenticated: Rc<Cell<bool>>,
    version: piv::Version,
    serial: String,
    keys: Vec<PivKey>,
    certificates: Vec<PivCertificate>,
    data_objects: Vec<PivDataObject>,
}

#[derive(Clone, Debug)]
struct PivKey {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    public_key: PivPublicKey,
    attestation: Rc<RefCell<Option<Vec<u8>>>>,
    attestation_attempted: Rc<Cell<bool>>,
    pin_policy: u8,
    touch_policy: u8,
}

#[derive(Clone, Debug)]
struct PivCertificate {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    value: Vec<u8>,
    attestation: bool,
}

#[derive(Clone, Debug)]
struct PivDataObject {
    object_id: u32,
    value: Vec<u8>,
}

#[derive(Clone, Debug)]
enum PivPublicKey {
    Rsa(Rsa<Public>),
    Ec(Vec<u8>),
    Raw(Vec<u8>),
}

impl PivPublicKey {
    fn key_type(&self, algorithm: piv::Algorithm) -> CK_KEY_TYPE {
        match algorithm {
            piv::Algorithm::Rsa1024
            | piv::Algorithm::Rsa2048
            | piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096 => CKK_RSA as CK_KEY_TYPE,
            piv::Algorithm::Ed25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
            piv::Algorithm::X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => CKK_EC as CK_KEY_TYPE,
        }
    }
}

fn piv_ec_parameters(algorithm: piv::Algorithm) -> Option<&'static [u8]> {
    match algorithm {
        piv::Algorithm::EccP256 => {
            Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
        }
        piv::Algorithm::EccP384 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        piv::Algorithm::Ed25519 => Some(&[
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        piv::Algorithm::X25519 => Some(&[
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        _ => None,
    }
}

fn piv_algorithm_supported(version: piv::Version, algorithm: piv::Algorithm) -> bool {
    !matches!(
        algorithm,
        piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096
            | piv::Algorithm::Ed25519
            | piv::Algorithm::X25519
    ) || (version.major, version.minor) >= (5, 7)
}

fn piv_effective_pin_policy(slot: piv::Slot, policy: u8) -> u8 {
    if policy != 0 {
        return policy;
    }
    match slot {
        piv::Slot::Signature => 3,
        piv::Slot::CardAuthentication => 1,
        _ => 2,
    }
}

fn piv_policy_requires_login(slot: piv::Slot, policy: u8) -> bool {
    piv_effective_pin_policy(slot, policy) != 1
}

fn piv_slot_label(slot: piv::Slot, certificate: bool, attestation: bool) -> String {
    let kind = if attestation {
        "Attestation certificate"
    } else if certificate {
        "Certificate"
    } else {
        "PIV slot"
    };
    format!("{kind} {:02X}", slot as u8)
}

fn piv_public_key_from_metadata(
    algorithm: piv::Algorithm,
    metadata: MetadataPublicKey,
) -> Result<PivPublicKey, Error> {
    match (algorithm, metadata) {
        (
            piv::Algorithm::Rsa1024
            | piv::Algorithm::Rsa2048
            | piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096,
            MetadataPublicKey::Rsa { modulus, exponent },
        ) => {
            let modulus = BigNum::from_slice(&modulus).map_err(Error::from)?;
            let exponent = BigNum::from_slice(&exponent).map_err(Error::from)?;
            let public_key = Rsa::from_public_components(modulus, exponent).map_err(Error::from)?;
            if public_key.size() as usize != algorithm.rsa_input_length().unwrap_or_default() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Rsa(public_key))
        }
        (piv::Algorithm::EccP256 | piv::Algorithm::EccP384, MetadataPublicKey::Ec(point)) => {
            let coordinate_length = piv_ec_coordinate_length(algorithm).unwrap_or_default();
            if point.len() != coordinate_length * 2 + 1 || point[0] != 0x04 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PivPublicKey::Ec(point[1..].to_vec()))
        }
        (piv::Algorithm::Ed25519 | piv::Algorithm::X25519, MetadataPublicKey::Raw(key)) => {
            if key.len() != 32 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PivPublicKey::Raw(key))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn piv_algorithm_from_certificate(certificate: &[u8]) -> Option<piv::Algorithm> {
    let certificate = openssl::x509::X509::from_der(certificate).ok()?;
    let key = certificate.public_key().ok()?;
    match key.id() {
        Id::RSA => match key.rsa().ok()?.size() {
            128 => Some(piv::Algorithm::Rsa1024),
            256 => Some(piv::Algorithm::Rsa2048),
            384 => Some(piv::Algorithm::Rsa3072),
            512 => Some(piv::Algorithm::Rsa4096),
            _ => None,
        },
        Id::EC => {
            let curve = key.ec_key().ok()?.group().curve_name()?;
            match curve {
                Nid::X9_62_PRIME256V1 => Some(piv::Algorithm::EccP256),
                Nid::SECP384R1 => Some(piv::Algorithm::EccP384),
                _ => None,
            }
        }
        Id::ED25519 => Some(piv::Algorithm::Ed25519),
        Id::X25519 => Some(piv::Algorithm::X25519),
        _ => None,
    }
}

fn piv_public_key_from_certificate(
    algorithm: piv::Algorithm,
    certificate_der: &[u8],
) -> Result<PivPublicKey, Error> {
    let certificate = openssl::x509::X509::from_der(certificate_der).map_err(Error::from)?;
    let certificate_key = certificate.public_key().map_err(Error::from)?;
    match algorithm {
        piv::Algorithm::Rsa1024
        | piv::Algorithm::Rsa2048
        | piv::Algorithm::Rsa3072
        | piv::Algorithm::Rsa4096 => {
            let public_key = certificate_key.rsa().map_err(Error::from)?;
            if public_key.size() as usize != algorithm.rsa_input_length().unwrap_or_default() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Rsa(public_key))
        }
        piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => {
            let public_key = certificate_key.ec_key().map_err(Error::from)?;
            let coordinate_length = piv_ec_coordinate_length(algorithm).unwrap_or_default();
            let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
            let point = public_key
                .public_key()
                .to_bytes(
                    public_key.group(),
                    PointConversionForm::UNCOMPRESSED,
                    &mut context,
                )
                .map_err(Error::from)?;
            if point.len() != coordinate_length * 2 + 1 || point[0] != 0x04 {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Ec(point[1..].to_vec()))
        }
        piv::Algorithm::Ed25519 | piv::Algorithm::X25519 => {
            if !matches!(
                (algorithm, certificate_key.id()),
                (piv::Algorithm::Ed25519, Id::ED25519) | (piv::Algorithm::X25519, Id::X25519)
            ) {
                return Err(CKR_DATA_INVALID.into());
            }
            let public_key = certificate_key.raw_public_key().map_err(Error::from)?;
            if public_key.len() != 32 {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Raw(public_key))
        }
    }
}

fn piv_ec_coordinate_length(algorithm: piv::Algorithm) -> Option<usize> {
    match algorithm {
        piv::Algorithm::EccP256 => Some(32),
        piv::Algorithm::EccP384 => Some(48),
        _ => None,
    }
}

fn piv_sign_mechanism_supported(algorithm: piv::Algorithm, mechanism: CK_MECHANISM_TYPE) -> bool {
    match algorithm {
        piv::Algorithm::Rsa1024
        | piv::Algorithm::Rsa2048
        | piv::Algorithm::Rsa3072
        | piv::Algorithm::Rsa4096 => matches!(
            mechanism,
            x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        ),
        piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => {
            matches!(
                mechanism,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
            )
        }
        piv::Algorithm::Ed25519 => mechanism == CKM_EDDSA as CK_MECHANISM_TYPE,
        piv::Algorithm::X25519 => false,
    }
}


impl PivSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let version = connector
            .firmware_version()
            .map(|(major, minor, patch)| piv::Version {
                major,
                minor,
                patch,
            })
            .unwrap_or(piv::Version {
                major: 0,
                minor: 0,
                patch: 0,
            });
        let serial = connector.serial().to_owned();
        Self {
            connector,
            application_aid,
            slot_description: None,
            authenticated: Rc::new(Cell::new(false)),
            management_authenticated: Rc::new(Cell::new(false)),
            version,
            serial,
            keys: Vec::new(),
            certificates: Vec::new(),
            data_objects: Vec::new(),
        }
    }

    fn update_device_info(&mut self, info: PivDeviceInfo) {
        self.version = info.version;
        let serial = info.serial.map(|serial| serial.to_string());
        self.connector.set_device_identity(
            Some((info.version.major, info.version.minor, info.version.patch)),
            serial.as_deref(),
        );
        if let Some(serial) = serial {
            self.serial = serial;
        }
    }

    fn reported_version(&self) -> piv::Version {
        if self.version
            != (piv::Version {
                major: 0,
                minor: 0,
                patch: 0,
            })
        {
            return self.version;
        }
        self.connector
            .firmware_version()
            .map(|(major, minor, patch)| piv::Version {
                major,
                minor,
                patch,
            })
            .unwrap_or(self.version)
    }
}

impl Slot for PivSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.slot_description
            .clone()
            .unwrap_or_else(|| format!("{} PIV", self.connector.name()))
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiKey PIV"
    }
    fn serial(&self) -> &str {
        if self.serial == "0" || self.serial.is_empty() {
            self.connector.serial()
        } else {
            &self.serial
        }
    }
    fn major(&self) -> u8 {
        self.version.major
    }
    fn minor(&self) -> u8 {
        self.version.minor
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        if let Err(error) = self.connector.refresh() {
            self.authenticated.set(false);
            return Err(error);
        }
        Ok(())
    }
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PivSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            authenticated: self.authenticated.clone(),
            management_authenticated: self.management_authenticated.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = PivClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_device_info(info);
            let only_never = !self.keys.is_empty()
                && self
                    .keys
                    .iter()
                    .all(|key| !piv_policy_requires_login(key.slot, key.pin_policy));
            if pin.is_empty() && only_never {
                self.authenticated.set(true);
            } else {
                PivClient.verify_pin(self.connector.as_ref(), pin)?;
            }
            self.authenticated.set(true);
            Ok(())
        })();
        if result.is_err() {
            self.connector.clear_secure_channel();
        }
        result
    }
    fn login_so(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        let key_text = std::str::from_utf8(pin).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        let key = parse_hex(key_text).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = PivClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_device_info(info);
            PivClient.authenticate_management_key(self.connector.as_ref(), &key)?;
            self.management_authenticated.set(true);
            Ok(())
        })();
        if result.is_err() {
            self.connector.clear_secure_channel();
        }
        result
    }
    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = if let Some(old_puk) = old_pin.strip_prefix(b"puk:") {
            if let Some(new_pin) = new_pin.strip_prefix(b"pin:") {
                PivClient.unblock_pin(self.connector.as_ref(), old_puk, new_pin)
            } else {
                let new_puk = new_pin.strip_prefix(b"puk:").unwrap_or(new_pin);
                PivClient.change_puk(self.connector.as_ref(), old_puk, new_puk)
            }
        } else {
            PivClient.change_pin(self.connector.as_ref(), old_pin, new_pin)
        };
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        self.connector.clear_secure_channel();
        result
    }
    fn set_so_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let old_text = std::str::from_utf8(old_pin).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        let new_text = std::str::from_utf8(new_pin).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        let old_key = parse_hex(old_text).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        let new_key = parse_hex(new_text).map_err(|_| Error::from(CKR_PIN_INVALID))?;
        PivClient.authenticate_management_key(self.connector.as_ref(), &old_key)?;
        let result = PivClient.set_management_key(self.connector.as_ref(), &new_key);
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        self.connector.clear_secure_channel();
        result
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        let result = PivClient.select(self.connector.as_ref(), &self.application_aid);
        if let Ok(info) = result.as_ref() {
            self.version = info.version;
            self.serial = info.serial.unwrap_or_default().to_string();
        }
        self.connector.clear_secure_channel();
        result.map(|_| ())
    }
    fn login_context_specific(&mut self, pin: &[u8], _extended: bool) -> Result<(), Error> {
        PivClient.verify_pin(self.connector.as_ref(), pin)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        let info = PivClient.select(self.connector.as_ref(), &self.application_aid)?;
        self.update_device_info(info);
        self.keys.clear();
        self.certificates.clear();
        self.data_objects.clear();
        for slot in piv::Slot::all().iter().copied() {
            let metadata = if slot == piv::Slot::Attestation {
                None
            } else {
                PivClient.metadata(self.connector.as_ref(), slot).ok()
            };
            let metadata_key = metadata.as_ref().and_then(|metadata| {
                let algorithm = metadata
                    .algorithm
                    .and_then(piv::Algorithm::from_id)
                    .filter(|algorithm| piv_algorithm_supported(self.version, *algorithm))?;
                let public_key = metadata
                    .public_key
                    .as_deref()
                    .and_then(|encoded| piv::parse_metadata_public_key(algorithm, encoded).ok())
                    .and_then(|key| piv_public_key_from_metadata(algorithm, key).ok())?;
                Some((algorithm, public_key, metadata.clone()))
            });
            let certificate = PivClient.certificate(self.connector.as_ref(), slot).ok();
            let certificate_algorithm = certificate
                .as_deref()
                .and_then(piv_algorithm_from_certificate);
            if let (Some(algorithm), Some(value)) = (certificate_algorithm, certificate.clone()) {
                if piv_algorithm_supported(self.version, algorithm) {
                    self.certificates.push(PivCertificate {
                        slot,
                        algorithm,
                        value,
                        attestation: slot == piv::Slot::Attestation,
                    });
                }
            }
            if slot == piv::Slot::Attestation {
                continue;
            }
            let (algorithm, public_key, metadata) = if let Some(key) = metadata_key {
                (key.0, key.1, key.2)
            } else if let (Some(certificate), Some(algorithm)) =
                (certificate.as_deref(), certificate_algorithm)
            {
                if !piv_algorithm_supported(self.version, algorithm) {
                    continue;
                }
                let Ok(public_key) = piv_public_key_from_certificate(algorithm, certificate) else {
                    continue;
                };
                let metadata = metadata.unwrap_or(piv::Metadata {
                    algorithm: None,
                    pin_policy: None,
                    touch_policy: None,
                    origin: None,
                    public_key: None,
                });
                (algorithm, public_key, metadata)
            } else {
                continue;
            };
            self.keys.push(PivKey {
                slot,
                algorithm,
                public_key,
                attestation: Rc::new(RefCell::new(None)),
                attestation_attempted: Rc::new(Cell::new(false)),
                pin_policy: metadata.pin_policy.unwrap_or(0),
                touch_policy: metadata.touch_policy.unwrap_or(0),
            });
        }
        for (object_id, _) in piv::DATA_OBJECTS {
            if let Ok(value) = PivClient.get_data(self.connector.as_ref(), *object_id) {
                self.data_objects.push(PivDataObject {
                    object_id: *object_id,
                    value,
                });
            }
        }
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        let version = self.reported_version();
        info.firmwareVersion.major = version.major;
        info.firmwareVersion.minor = version.minor.saturating_mul(10) + version.patch;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        info.ulMaxPinLen = 8;
        info.ulMinPinLen = 6;
        let version = self.reported_version();
        info.firmwareVersion.major = version.major;
        info.firmwareVersion.minor = version.minor.saturating_mul(10) + version.patch;
        Ok(())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        let mut mechanisms = Vec::new();
        let rsa_sizes = [1024, 2048, 3072, 4096];
        let ec_sizes = [256, 384];
        let mut add = |type_, min_key_size, max_key_size, flags| {
            mechanisms.push(MechanismDetails {
                type_,
                min_key_size,
                max_key_size,
                flags,
            });
        };
        for type_ in [
            CKM_RSA_X_509,
            CKM_RSA_PKCS,
            CKM_RSA_PKCS_OAEP,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS,
            CKM_SHA224_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA3_224_RSA_PKCS,
            CKM_SHA3_256_RSA_PKCS,
            CKM_SHA3_384_RSA_PKCS,
            CKM_SHA3_512_RSA_PKCS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA224_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
            CKM_SHA3_224_RSA_PKCS_PSS,
            CKM_SHA3_256_RSA_PKCS_PSS,
            CKM_SHA3_384_RSA_PKCS_PSS,
            CKM_SHA3_512_RSA_PKCS_PSS,
        ] {
            let flags = if type_ == CKM_RSA_PKCS {
                (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            } else if type_ == CKM_RSA_PKCS_OAEP {
                (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS
            } else if type_ == CKM_RSA_X_509 {
                (CKF_ENCRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            } else {
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            };
            add(
                type_ as CK_MECHANISM_TYPE,
                rsa_sizes[0],
                rsa_sizes[3],
                flags,
            );
        }
        for type_ in [
            CKM_ECDSA,
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA224,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
        ] {
            add(
                type_ as CK_MECHANISM_TYPE,
                ec_sizes[0],
                ec_sizes[1],
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            );
        }
        mechanisms.push(MechanismDetails {
            type_: CKM_EDDSA as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 255,
            flags: (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        });
        mechanisms.push(MechanismDetails {
            type_: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 384,
            flags: CKF_DERIVE as CK_FLAGS,
        });
        mechanisms.push(MechanismDetails {
            type_: CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 384,
            flags: CKF_DERIVE as CK_FLAGS,
        });
        mechanisms
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.management_authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get() || self.management_authenticated.get()
    }
    fn is_piv(&self) -> bool {
        true
    }
    fn piv_generate_key_pair(
        &mut self,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !piv_algorithm_supported(self.reported_version(), algorithm) {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        let public_key = PivClient.generate_key_pair(
            self.connector.as_ref(),
            slot,
            algorithm,
            pin_policy,
            touch_policy,
        )?;
        let public_key = piv_public_key_from_metadata(algorithm, public_key)?;
        self.keys.retain(|key| key.slot != slot);
        self.keys.push(PivKey {
            slot,
            algorithm,
            public_key,
            attestation: Rc::new(RefCell::new(None)),
            attestation_attempted: Rc::new(Cell::new(false)),
            pin_policy,
            touch_policy,
        });
        Ok(())
    }
    fn piv_import_private_key(
        &mut self,
        slot: piv::Slot,
        key: &piv::PrivateKeyImport,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !piv_algorithm_supported(self.reported_version(), key.algorithm) {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        PivClient.import_private_key(
            self.connector.as_ref(),
            slot,
            key,
            pin_policy,
            touch_policy,
        )?;
        let public_key = piv_public_key_from_metadata(key.algorithm, key.public_key.clone())?;
        self.keys.retain(|candidate| candidate.slot != slot);
        self.keys.push(PivKey {
            slot,
            algorithm: key.algorithm,
            public_key,
            attestation: Rc::new(RefCell::new(None)),
            attestation_attempted: Rc::new(Cell::new(false)),
            pin_policy,
            touch_policy,
        });
        Ok(())
    }
    fn piv_import_certificate(
        &mut self,
        slot: piv::Slot,
        certificate: &[u8],
    ) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let algorithm = piv_algorithm_from_certificate(certificate).ok_or(CKR_DATA_INVALID)?;
        if !piv_algorithm_supported(self.reported_version(), algorithm) {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        PivClient.put_certificate(self.connector.as_ref(), slot, certificate)?;
        self.certificates.retain(|candidate| candidate.slot != slot);
        self.certificates.push(PivCertificate {
            slot,
            algorithm,
            value: certificate.to_vec(),
            attestation: slot == piv::Slot::Attestation,
        });
        if slot != piv::Slot::Attestation && !self.keys.iter().any(|key| key.slot == slot) {
            let public_key = piv_public_key_from_certificate(algorithm, certificate)?;
            self.keys.push(PivKey {
                slot,
                algorithm,
                public_key,
                attestation: Rc::new(RefCell::new(None)),
                attestation_attempted: Rc::new(Cell::new(false)),
                pin_policy: 0,
                touch_policy: 0,
            });
        }
        Ok(())
    }
    fn piv_delete_key(&mut self, slot: piv::Slot) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if (self.reported_version().major, self.reported_version().minor) < (5, 7) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        PivClient.delete_key(self.connector.as_ref(), slot)?;
        self.keys.retain(|key| key.slot != slot);
        Ok(())
    }
    fn piv_delete_certificate(&mut self, slot: piv::Slot) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        PivClient.delete_certificate(self.connector.as_ref(), slot)?;
        self.certificates
            .retain(|certificate| certificate.slot != slot);
        Ok(())
    }
    fn piv_write_data(&mut self, object_id: u32, value: &[u8]) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !piv::data_object_allowed(object_id) {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
        PivClient.put_data(self.connector.as_ref(), object_id, value)?;
        self.data_objects
            .retain(|object| object.object_id != object_id);
        self.data_objects.push(PivDataObject {
            object_id,
            value: value.to_vec(),
        });
        Ok(())
    }
    fn piv_delete_data(&mut self, object_id: u32) -> Result<(), Error> {
        if !self.management_authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !piv::data_object_allowed(object_id) {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
        PivClient.put_data(self.connector.as_ref(), object_id, &[])?;
        self.data_objects
            .retain(|object| object.object_id != object_id);
        Ok(())
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = Vec::with_capacity(self.keys.len() * 2 + self.certificates.len() + 4);
        for key in &self.keys {
            if key.slot == piv::Slot::Attestation {
                continue;
            }
            let id = vec![key.slot as u8];
            let label = format!("PIV slot {:02X}", key.slot as u8);
            let key_type = key.public_key.key_type(key.algorithm);
            let is_rsa = key.algorithm.rsa_input_length().is_some();
            let can_sign = !matches!(key.algorithm, piv::Algorithm::X25519);
            let private = piv_policy_requires_login(key.slot, key.pin_policy);
            let can_decrypt = is_rsa
                && matches!(
                    key.slot,
                    piv::Slot::KeyManagement
                        | piv::Slot::Retired1
                        | piv::Slot::Retired2
                        | piv::Slot::Retired3
                        | piv::Slot::Retired4
                        | piv::Slot::Retired5
                        | piv::Slot::Retired6
                        | piv::Slot::Retired7
                        | piv::Slot::Retired8
                        | piv::Slot::Retired9
                        | piv::Slot::Retired10
                        | piv::Slot::Retired11
                        | piv::Slot::Retired12
                        | piv::Slot::Retired13
                        | piv::Slot::Retired14
                        | piv::Slot::Retired15
                        | piv::Slot::Retired16
                        | piv::Slot::Retired17
                        | piv::Slot::Retired18
                        | piv::Slot::Retired19
                        | piv::Slot::Retired20
                );
            let public_material = match &key.public_key {
                PivPublicKey::Rsa(public_key) => KeyMaterial::RsaPublic(public_key.clone()),
                PivPublicKey::Ec(public_key) | PivPublicKey::Raw(public_key) => {
                    KeyMaterial::PivPublic {
                        algorithm: key.algorithm,
                        public_key: public_key.clone(),
                    }
                }
            };
            let (modulus, public_exponent) = match &key.public_key {
                PivPublicKey::Rsa(public_key) => (public_key.n().to_vec(), public_key.e().to_vec()),
                _ => (Vec::new(), Vec::new()),
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-public", key.slot as u8),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type,
                label: label.clone(),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: is_rsa,
                decrypt: false,
                sign: false,
                verify: can_sign,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: public_material,
            });
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-private", key.slot as u8),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type,
                label,
                id,
                token: true,
                private,
                encrypt: false,
                decrypt: can_decrypt,
                sign: can_sign,
                verify: false,
                derive: matches!(
                    key.algorithm,
                    piv::Algorithm::EccP256 | piv::Algorithm::EccP384 | piv::Algorithm::X25519
                ),
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::PivPrivate {
                    slot: key.slot,
                    algorithm: key.algorithm,
                    modulus,
                    public_exponent,
                    pin_policy: key.pin_policy,
                    touch_policy: key.touch_policy,
                },
            });
        }
        for certificate in &self.certificates {
            let key_type = match certificate.algorithm {
                piv::Algorithm::Rsa1024
                | piv::Algorithm::Rsa2048
                | piv::Algorithm::Rsa3072
                | piv::Algorithm::Rsa4096 => CKK_RSA as CK_KEY_TYPE,
                piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => CKK_EC as CK_KEY_TYPE,
                piv::Algorithm::Ed25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
                piv::Algorithm::X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!(
                    "piv-{:02x}-{}certificate",
                    certificate.slot as u8,
                    if certificate.attestation {
                        "attestation-"
                    } else {
                        ""
                    }
                ),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type,
                label: piv_slot_label(certificate.slot, true, certificate.attestation),
                id: vec![certificate.slot as u8],
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::PivCertificate {
                    algorithm: certificate.algorithm,
                    value: certificate.value.clone(),
                    attestation: certificate.attestation,
                },
            });
        }
        for key in &self.keys {
            if key.slot == piv::Slot::Attestation {
                continue;
            }
            let key_type = key.public_key.key_type(key.algorithm);
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-attestation", key.slot as u8),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type,
                label: piv_slot_label(key.slot, true, true),
                id: vec![key.slot as u8],
                token: false,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::PivAttestation {
                    connector: self.connector.clone(),
                    slot: key.slot,
                    algorithm: key.algorithm,
                    value: key.attestation.clone(),
                    attempted: key.attestation_attempted.clone(),
                },
            });
        }
        for data in &self.data_objects {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-data-{:06x}", data.object_id),
                class: CKO_DATA as CK_OBJECT_CLASS,
                key_type: 0,
                label: piv::data_object_name(data.object_id),
                id: Vec::new(),
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::PivData {
                    object_id: data.object_id,
                    value: data.value.clone(),
                },
            });
        }
        Ok(objects)
    }

    fn session_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(self
            .token_objects(slot_id)?
            .into_iter()
            .filter(|object| !object.token)
            .collect())
    }
}

#[derive(Debug)]

struct PivSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    authenticated: Rc<Cell<bool>>,
    management_authenticated: Rc<Cell<bool>>,
}

impl Session for PivSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        if self.management_authenticated.get() {
            return Ok(());
        }
        let retries = PivClient.pin_retries(self.connector.as_ref())?;
        if self.authenticated.get() && retries != u8::MAX {
            self.authenticated.set(false);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        Ok(())
    }
    fn piv_sign(
        &self,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if piv_policy_requires_login(slot, pin_policy) && !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = PivClient.sign(self.connector.as_ref(), slot, algorithm, input);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn piv_decipher(
        &self,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if piv_policy_requires_login(slot, pin_policy) && !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = PivClient.decipher(self.connector.as_ref(), slot, algorithm, input);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
}
