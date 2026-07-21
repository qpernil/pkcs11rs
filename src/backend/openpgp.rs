#[derive(Debug)]
struct OpenPgpSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Rc<Cell<bool>>,
    version: (u8, u8),
    serial: String,
    pin_min: u8,
    pin_max: u8,
    admin_pin_min: u8,
    admin_pin_max: u8,
    kdf: Option<openpgp::KdfParams>,
    keys: Vec<openpgp::KeyInfo>,
    certificates: Vec<OpenPgpCertificate>,
}

#[derive(Clone, Debug)]
struct OpenPgpCertificate {
    key_ref: OpenPgpKeyRef,
    key_type: CK_KEY_TYPE,
    value: Vec<u8>,
}

impl OpenPgpSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let serial = connector.serial().to_owned();
        let version = connector
            .firmware_version()
            .map(|(major, minor, _patch)| (major, minor))
            .unwrap_or((0, 0));
        Self {
            connector,
            application_aid,
            authenticated: Rc::new(Cell::new(false)),
            version,
            serial,
            pin_min: 6,
            pin_max: 127,
            admin_pin_min: 8,
            admin_pin_max: 127,
            kdf: None,
            keys: Vec::new(),
            certificates: Vec::new(),
        }
    }

    fn update_info(&mut self, info: &openpgp::ApplicationInfo) {
        self.version = info.version;
        self.serial = info.serial.clone();
        self.connector.set_device_identity(None, Some(&info.serial));
        self.pin_min = info.pin_min;
        self.pin_max = info.pin_max;
        self.admin_pin_min = info.admin_pin_min;
        self.admin_pin_max = info.admin_pin_max;
        self.kdf = info.kdf.clone();
    }

    fn validate_user_pin(&self, pin: &[u8]) -> Result<(), Error> {
        Self::validate_pin_length(pin, self.pin_min, self.pin_max)
    }

    fn validate_admin_pin(&self, pin: &[u8]) -> Result<(), Error> {
        Self::validate_pin_length(pin, self.admin_pin_min, self.admin_pin_max)
    }

    fn validate_pin_length(pin: &[u8], min: u8, max: u8) -> Result<(), Error> {
        if !(min as usize..=max as usize).contains(&pin.len()) {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn reported_version(&self) -> (u8, u8) {
        if self.version != (0, 0) {
            return self.version;
        }
        self.connector
            .firmware_version()
            .map(|(major, minor, _patch)| (major, minor))
            .unwrap_or(self.version)
    }
}

fn openpgp_public_material(key: &OpenPgpPublicKey) -> Vec<u8> {
    match key {
        OpenPgpPublicKey::Rsa(key) => key.n().to_vec(),
        OpenPgpPublicKey::Ec { point, .. } | OpenPgpPublicKey::Raw { key: point, .. } => {
            point.clone()
        }
    }
}

fn openpgp_rsa_components(key: &OpenPgpPublicKey) -> (Vec<u8>, Vec<u8>) {
    match key {
        OpenPgpPublicKey::Rsa(key) => (key.n().to_vec(), key.e().to_vec()),
        _ => (Vec::new(), Vec::new()),
    }
}

fn openpgp_key_can_sign(key_ref: OpenPgpKeyRef, algorithm: OpenPgpAlgorithm) -> bool {
    matches!(
        key_ref,
        OpenPgpKeyRef::Signature | OpenPgpKeyRef::Authentication
    ) && !matches!(algorithm, OpenPgpAlgorithm::Ecdh(_))
}

fn openpgp_key_can_verify(key_ref: OpenPgpKeyRef, algorithm: OpenPgpAlgorithm) -> bool {
    matches!(
        key_ref,
        OpenPgpKeyRef::Signature
            | OpenPgpKeyRef::Authentication
            | OpenPgpKeyRef::Attestation
    ) && !matches!(algorithm, OpenPgpAlgorithm::Ecdh(_))
}

fn openpgp_key_generation_mechanism(
    algorithm: OpenPgpAlgorithm,
) -> Option<CK_MECHANISM_TYPE> {
    match algorithm {
        OpenPgpAlgorithm::Rsa { .. } => Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
        OpenPgpAlgorithm::Ed25519 => {
            Some(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
        }
        OpenPgpAlgorithm::Ecdh(openpgp::Curve::X25519) => {
            Some(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
        }
        OpenPgpAlgorithm::Ecdsa(_) | OpenPgpAlgorithm::Ecdh(_) => {
            Some(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
        }
    }
}

fn openpgp_signature_requires_context_specific_login(
    key_ref: OpenPgpKeyRef,
    pin_policy: u8,
) -> bool {
    key_ref == OpenPgpKeyRef::Signature && pin_policy == openpgp::PW1_ONE_SIGNATURE
}

impl Slot for OpenPgpSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} OpenPGP", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiKey OpenPGP"
    }
    fn serial(&self) -> &str {
        if self.serial == "0" {
            self.connector.serial()
        } else {
            &self.serial
        }
    }
    fn major(&self) -> u8 {
        self.version.0
    }
    fn minor(&self) -> u8 {
        self.version.1
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
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
        Box::new(OpenPgpSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            authenticated: self.authenticated.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.validate_user_pin(pin)?;
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = OpenPgpClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_info(&info);
            let pin = self
                .kdf
                .as_ref()
                .map(|kdf| kdf.derive_user_pin(pin))
                .transpose()?
                .unwrap_or_else(|| pin.to_vec());
            OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, true)?;
            if info.pin_policy == openpgp::PW1_MULTIPLE_SIGNATURES {
                OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, false)?;
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
        self.validate_admin_pin(pin)?;
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = OpenPgpClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_info(&info);
            let pin = self
                .kdf
                .as_ref()
                .map(|kdf| kdf.derive_pin(openpgp::PasswordRef::Admin, pin))
                .transpose()?
                .unwrap_or_else(|| pin.to_vec());
            OpenPgpClient.verify_admin(self.connector.as_ref(), &pin)?;
            self.authenticated.set(true);
            Ok(())
        })();
        if result.is_err() {
            self.connector.clear_secure_channel();
        }
        result
    }
    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        self.validate_user_pin(old_pin)?;
        self.validate_user_pin(new_pin)?;
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = OpenPgpClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_info(&info);
            let derive = |input: &[u8]| {
                if let Some(kdf) = &self.kdf {
                    kdf.derive_user_pin(input)
                } else {
                    Ok(input.to_vec())
                }
            };
            let old_pin = derive(old_pin)?;
            let new_pin = derive(new_pin)?;
            OpenPgpClient.change_user_pin(self.connector.as_ref(), &old_pin, &new_pin)
        })();
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        result
    }
    fn set_so_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        self.validate_admin_pin(old_pin)?;
        self.validate_admin_pin(new_pin)?;
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = OpenPgpClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_info(&info);
            let derive = |input: &[u8]| {
                if let Some(kdf) = &self.kdf {
                    kdf.derive_pin(openpgp::PasswordRef::Admin, input)
                } else {
                    Ok(input.to_vec())
                }
            };
            let old_pin = derive(old_pin)?;
            let new_pin = derive(new_pin)?;
            OpenPgpClient.change_admin_pin(self.connector.as_ref(), &old_pin, &new_pin)
        })();
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        result
    }
    fn init_user_pin(&mut self, new_pin: &[u8]) -> Result<(), Error> {
        self.validate_user_pin(new_pin)?;
        let new_pin = self
            .kdf
            .as_ref()
            .map(|kdf| kdf.derive_user_pin(new_pin))
            .transpose()?
            .unwrap_or_else(|| new_pin.to_vec());
        let result = OpenPgpClient.reset_user_pin(self.connector.as_ref(), &new_pin, None);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as CK_RV) {
            self.authenticated.set(false);
        }
        result
    }
    fn login_context_specific(&mut self, pin: &[u8], extended: bool) -> Result<(), Error> {
        self.validate_user_pin(pin)?;
        let pin = self
            .kdf
            .as_ref()
            .map(|kdf| kdf.derive_user_pin(pin))
            .transpose()?
            .unwrap_or_else(|| pin.to_vec());
        OpenPgpClient.unverify(self.connector.as_ref(), extended);
        OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, extended)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        OpenPgpClient.unverify(self.connector.as_ref(), false);
        OpenPgpClient.unverify(self.connector.as_ref(), true);
        let _ = OpenPgpClient.unverify_password(
            self.connector.as_ref(),
            openpgp::PasswordRef::Admin,
        );
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let info = OpenPgpClient
            .select(self.connector.as_ref(), &self.application_aid)
            .map_err(|error| {
                log!(
                    1,
                    "OpenPGP application metadata discovery failed: {:?}",
                    error
                );
                error
            })?;
        self.update_info(&info);
        self.keys.clear();
        self.certificates.clear();
        for key_ref in OpenPgpKeyRef::ALL {
            if info.key_status(key_ref) == Some(openpgp::KeyStatus::None) {
                log!(2, "OpenPGP key reference {:?} is empty", key_ref);
                continue;
            }
            let Some(algorithm) = info.algorithm(key_ref) else {
                log!(
                    1,
                    "OpenPGP key reference {:?} has no supported algorithm",
                    key_ref
                );
                continue;
            };
            let public_key =
                match OpenPgpClient.public_key(self.connector.as_ref(), key_ref, algorithm) {
                    Ok(public_key) => public_key,
                    Err(error) => {
                        log!(
                            1,
                            "OpenPGP public-key discovery failed for {:?}: {:?}",
                            key_ref,
                            error
                        );
                        continue;
                    }
                };
            self.keys.push(openpgp::KeyInfo {
                key_ref,
                algorithm,
                public_key,
                pin_policy: info.pin_policy,
                local: info.key_is_local(key_ref),
            });
            if let Ok(value) = OpenPgpClient.certificate(self.connector.as_ref(), key_ref) {
                self.certificates.push(OpenPgpCertificate {
                    key_ref,
                    key_type: algorithm.key_type() as CK_KEY_TYPE,
                    value,
                });
            }
        }
        if let Some(algorithm) = info.algorithm(OpenPgpKeyRef::Attestation) {
            if info.key_status(OpenPgpKeyRef::Attestation) == Some(openpgp::KeyStatus::None) {
                log!(2, "OpenPGP attestation key reference is empty");
            } else {
                match OpenPgpClient.public_key(
                    self.connector.as_ref(),
                    OpenPgpKeyRef::Attestation,
                    algorithm,
                ) {
                    Ok(public_key) => self.keys.push(openpgp::KeyInfo {
                        key_ref: OpenPgpKeyRef::Attestation,
                        algorithm,
                        public_key,
                        pin_policy: info.pin_policy,
                        local: info.key_is_local(OpenPgpKeyRef::Attestation),
                    }),
                    Err(error) => log!(
                        2,
                        "OpenPGP attestation public-key discovery failed: {:?}",
                        error
                    ),
                }
            }
            if let Ok(value) = OpenPgpClient
                .certificate(self.connector.as_ref(), OpenPgpKeyRef::Attestation)
            {
                if !value.is_empty() {
                    self.certificates.push(OpenPgpCertificate {
                        key_ref: OpenPgpKeyRef::Attestation,
                        key_type: algorithm.key_type() as CK_KEY_TYPE,
                        value,
                    });
                } else {
                    log!(
                    2,
                        "OpenPGP attestation certificate data object is empty"
                    );
                }
            }
        }
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        if let Some((major, minor)) = self.connector.hardware_version() {
            info.hardwareVersion.major = major;
            info.hardwareVersion.minor = minor;
        }
        let (major, minor) = self.reported_version();
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        let (major, minor) = self.reported_version();
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor;
        info.ulMinPinLen = self.pin_min as CK_ULONG;
        info.ulMaxPinLen = self.pin_max as CK_ULONG;
        Ok(())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        let mut mechanisms = Vec::new();
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
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
        ] {
            add(
                type_ as CK_MECHANISM_TYPE,
                2048,
                4096,
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            );
        }
        for type_ in [CKM_RSA_PKCS, CKM_RSA_X_509] {
            add(
                type_ as CK_MECHANISM_TYPE,
                2048,
                4096,
                (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
            );
        }
        add(
            CKM_ECDSA as CK_MECHANISM_TYPE,
            256,
            521,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        );
        add(
            CKM_EDDSA as CK_MECHANISM_TYPE,
            255,
            255,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        );
        if self
            .keys
            .iter()
            .any(|key| matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)))
        {
            add(
                CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
                255,
                521,
                CKF_DERIVE as CK_FLAGS,
            );
        }
        mechanisms
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = Vec::with_capacity(self.keys.len() * 2 + self.certificates.len());
        for key in &self.keys {
            let public_bytes = openpgp_public_material(&key.public_key);
            let key_type = key.algorithm.key_type() as CK_KEY_TYPE;
            let (modulus, public_exponent) = openpgp_rsa_components(&key.public_key);
            let can_sign = openpgp_key_can_sign(key.key_ref, key.algorithm);
            let can_verify = openpgp_key_can_verify(key.key_ref, key.algorithm);
            let can_decrypt = key.key_ref == OpenPgpKeyRef::Decipher && key.algorithm.is_rsa();
            let key_gen_mechanism = key
                .local
                .then(|| openpgp_key_generation_mechanism(key.algorithm))
                .flatten();
            let label = format!("OpenPGP {:?} key", key.key_ref);
            let id = vec![key.key_ref as u8];
            let public_material = match &key.public_key {
                OpenPgpPublicKey::Rsa(public_key) => KeyMaterial::RsaPublic(public_key.clone()),
                OpenPgpPublicKey::Ec { curve, point } => KeyMaterial::OpenPgpPublic {
                    algorithm: if matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)) {
                        OpenPgpAlgorithm::Ecdh(*curve)
                    } else {
                        OpenPgpAlgorithm::Ecdsa(*curve)
                    },
                    public_key: point.clone(),
                },
                OpenPgpPublicKey::Raw { curve, key } => KeyMaterial::OpenPgpPublic {
                    algorithm: if *curve == openpgp::Curve::Ed25519 {
                        OpenPgpAlgorithm::Ed25519
                    } else {
                        OpenPgpAlgorithm::Ecdh(*curve)
                    },
                    public_key: key.clone(),
                },
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-public", key.key_ref as u8),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type,
                label: label.clone(),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: key.key_ref == OpenPgpKeyRef::Decipher && key.algorithm.is_rsa(),
                decrypt: false,
                sign: false,
                verify: can_verify,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: key.local,
                key_gen_mechanism,
                owner_session: None,
                material: public_material,
            });
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-private", key.key_ref as u8),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type,
                label,
                id,
                token: true,
                private: true,
                encrypt: false,
                decrypt: can_decrypt,
                sign: can_sign,
                verify: false,
                derive: key.key_ref == OpenPgpKeyRef::Decipher
                    && matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)),
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: key.local,
                key_gen_mechanism,
                owner_session: None,
                material: KeyMaterial::OpenPgpPrivate {
                    key_ref: key.key_ref,
                    algorithm: key.algorithm,
                    modulus,
                    public_exponent,
                    public_key: public_bytes,
                    pin_policy: key.pin_policy,
                },
            });
        }
        for certificate in &self.certificates {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-certificate", certificate.key_ref as u8),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type: certificate.key_type,
                label: format!("OpenPGP {:?} certificate", certificate.key_ref),
                id: vec![certificate.key_ref as u8],
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
                material: KeyMaterial::OpenPgpCertificate {
                    value: certificate.value.clone(),
                },
            });
        }
        Ok(objects)
    }
}


#[derive(Debug)]
struct OpenPgpSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    authenticated: Rc<Cell<bool>>,
}

impl Session for OpenPgpSession {
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
        Ok(())
    }
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let random = OpenPgpClient.challenge(self.connector.as_ref(), chunk.len())?;
            chunk.copy_from_slice(&random);
        }
        Ok(())
    }
    fn openpgp_sign(
        &self,
        key_ref: OpenPgpKeyRef,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = OpenPgpClient.sign(self.connector.as_ref(), key_ref, input);
        if key_ref == OpenPgpKeyRef::Signature && pin_policy == openpgp::PW1_ONE_SIGNATURE {
            self.authenticated.set(false);
        }
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn openpgp_decipher(&self, input: &[u8], raw: bool) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = OpenPgpClient.decipher(self.connector.as_ref(), input, raw);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn openpgp_derive(
        &self,
        key_ref: OpenPgpKeyRef,
        algorithm: OpenPgpAlgorithm,
        public_key: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if key_ref != OpenPgpKeyRef::Decipher {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let curve = match algorithm {
            OpenPgpAlgorithm::Ecdh(curve) => curve,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        let result = OpenPgpClient.ecdh(self.connector.as_ref(), curve, public_key);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
}
