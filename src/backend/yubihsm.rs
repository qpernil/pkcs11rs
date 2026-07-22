#[derive(Clone, Debug)]
struct HsmAuthProvider {
    connector: Rc<dyn Connector>,
    credential: HsmAuthCredential,
    version: (u8, u8, u8),
}

impl HsmAuthProvider {
    fn source_identifier(&self) -> String {
        let serial = self.connector.serial();
        if serial.is_empty() {
            self.connector.name()
        } else {
            serial.to_owned()
        }
    }

    fn authenticate(
        &self,
        yubihsm_connector: &dyn Connector,
        authkey_id: u16,
        credential_password: &[u8],
    ) -> Result<YubiHsmSecureSession, Error> {
        match self.credential.algorithm {
            HsmAuthAlgorithm::Aes128YubicoAuthentication => {
                log!(
                    2,
                    "YubiHSM Auth starting symmetric session on {} with authentication key {:04x}",
                    yubihsm_connector.name(),
                    authkey_id
                );
                let mut challenge = [0; 8];
                openssl::rand::rand_bytes(&mut challenge)
                    .map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
                let handshake = YubiHsmSecureSession::begin_symmetric(
                    yubihsm_connector,
                    authkey_id,
                    challenge,
                )?;
                log!(
                    2,
                    "YubiHSM Auth target {} created symmetric session {}",
                    yubihsm_connector.name(),
                    handshake.sid
                );
                log!(
                    2,
                    "YubiHSM Auth requesting symmetric session keys for credential {:?}",
                    self.credential.label
                );
                let keys = HsmAuthClient.calculate_session_keys_symmetric(
                    self.connector.as_ref(),
                    &self.credential.label,
                    &handshake.context,
                    &handshake.card_cryptogram,
                    credential_password,
                );
                let keys = match keys {
                    Ok(keys) => keys,
                    Err(error) => {
                        log!(
                            2,
                            "YubiHSM Auth finalizing failed symmetric target session {}",
                            handshake.sid
                        );
                        YubiHsmSecureSession::finish_failed_symmetric_handshake(
                            yubihsm_connector,
                            handshake,
                        );
                        return Err(error);
                    }
                };
                log!(
                    2,
                    "YubiHSM Auth received symmetric session keys for target session {}",
                    handshake.sid
                );
                let session_id = handshake.sid;
                let session = YubiHsmSecureSession::complete_symmetric_with_session_keys(
                    yubihsm_connector,
                    handshake,
                    keys.enc,
                    keys.mac,
                    keys.rmac,
                )?;
                log!(
                    2,
                    "YubiHSM Auth authenticated symmetric target session {}",
                    session_id
                );
                Ok(session)
            }
            HsmAuthAlgorithm::EcP256YubicoAuthentication => {
                let challenge_password =
                    (self.version.0 == 0 || self.version >= (5, 7, 1))
                        .then_some(credential_password);
                log!(
                    2,
                    "YubiHSM Auth requesting an asymmetric challenge for credential {:?}{}",
                    self.credential.label,
                    if challenge_password.is_some() {
                        " with credential-password authentication"
                    } else {
                        " without credential-password authentication"
                    }
                );
                let host_public_key = HsmAuthClient.get_challenge(
                    self.connector.as_ref(),
                    &self.credential.label,
                    challenge_password,
                )?;
                log!(
                    2,
                    "YubiHSM Auth starting asymmetric session on {} with authentication key {:04x}",
                    yubihsm_connector.name(),
                    authkey_id
                );
                let handshake = YubiHsmSecureSession::begin_asymmetric(
                    yubihsm_connector,
                    authkey_id,
                    &host_public_key,
                )?;
                log!(
                    2,
                    "YubiHSM Auth target {} created asymmetric session {}",
                    yubihsm_connector.name(),
                    handshake.sid
                );
                log!(
                    2,
                    "YubiHSM Auth reading the target YubiHSM device public key for session {}",
                    handshake.sid
                );
                let device_public_key = match get_yubihsm_device_public_key(yubihsm_connector) {
                    Ok(public_key) => public_key,
                    Err(error) => {
                        log!(
                            2,
                            "YubiHSM Auth closing failed asymmetric target session {}",
                            handshake.sid
                        );
                        YubiHsmSecureSession::close_failed_asymmetric_handshake(
                            yubihsm_connector,
                            handshake,
                        );
                        return Err(error);
                    }
                };
                log!(
                    2,
                    "YubiHSM Auth requesting asymmetric session keys for credential {:?}",
                    self.credential.label
                );
                let keys = HsmAuthClient.calculate_session_keys_asymmetric(
                    self.connector.as_ref(),
                    &self.credential.label,
                    &handshake.context,
                    &device_public_key,
                    &handshake.receipt,
                    credential_password,
                );
                let keys = match keys {
                    Ok(keys) => keys,
                    Err(error) => {
                        log!(
                            2,
                            "YubiHSM Auth closing failed asymmetric target session {}",
                            handshake.sid
                        );
                        YubiHsmSecureSession::close_failed_asymmetric_handshake(
                            yubihsm_connector,
                            handshake,
                        );
                        return Err(error);
                    }
                };
                let session_id = handshake.sid;
                let session = YubiHsmSecureSession::complete_asymmetric_with_session_keys(
                    handshake,
                    keys.enc,
                    keys.mac,
                    keys.rmac,
                );
                log!(
                    2,
                    "YubiHSM Auth accepted the asymmetric receipt for target session {}",
                    session_id
                );
                Ok(session)
            }
        }
    }
}

#[derive(Debug)]
struct YubiHsmSlot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
    version: (u8, u8, u8),
    algorithms: Vec<u8>,
    hsmauth_providers: Rc<RefCell<Vec<HsmAuthProvider>>>,
    object_metadata: RefCell<HashMap<YubiHsmObjectKey, YubiHsmObjectMetadata>>,
    object_generations: RefCell<HashMap<YubiHsmObjectKey, (u8, u64)>>,
    next_object_generation: Cell<u64>,
}

type YubiHsmObjectKey = (u8, u16);
type YubiHsmObjectMetadata = (YubiHsmObjectInfo, Option<YubiHsmPublicKey>, u64);

impl YubiHsmSlot {
    fn new(connector: Rc<dyn Connector>, version: (u8, u8, u8), algorithms: Vec<u8>) -> Self {
        Self {
            connector,
            session: Rc::new(RefCell::new(None)),
            version,
            algorithms,
            hsmauth_providers: Rc::new(RefCell::new(Vec::new())),
            object_metadata: RefCell::new(HashMap::new()),
            object_generations: RefCell::new(HashMap::new()),
            next_object_generation: Cell::new(1),
        }
    }

    fn with_hsmauth_providers(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
        hsmauth_providers: Rc<RefCell<Vec<HsmAuthProvider>>>,
    ) -> Self {
        let mut slot = Self::new(connector, version, algorithms);
        slot.hsmauth_providers = hsmauth_providers;
        slot
    }
}

fn send_yubihsm_secure_command(
    connector: &dyn Connector,
    shared_session: &RefCell<Option<YubiHsmSecureSession>>,
    command: &YubiHsmCommand,
) -> Result<Vec<u8>, Error> {
    let mut session_guard = shared_session.try_borrow_mut()?;
    let session = session_guard
        .as_mut()
        .ok_or_else(|| Error::from(CKR_USER_NOT_LOGGED_IN))?;
    YubiHsmSecureSession::validate_command(connector, command)?;
    let result = session.send_command(connector, command);
    if !session.is_valid() {
        *session_guard = None;
    }
    result
}

fn yubihsm_key_type(algorithm: u8) -> CK_KEY_TYPE {
    match algorithm {
        YUBIHSM_ALGO_AES128_CCM_WRAP => CKK_YUBICO_AES128_CCM_WRAP,
        YUBIHSM_ALGO_AES192_CCM_WRAP => CKK_YUBICO_AES192_CCM_WRAP,
        YUBIHSM_ALGO_AES256_CCM_WRAP => CKK_YUBICO_AES256_CCM_WRAP,
        YUBIHSM_ALGO_HMAC_SHA1 => CKK_SHA_1_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA256 => CKK_SHA256_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA384 => CKK_SHA384_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA512 => CKK_SHA512_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION | YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION => {
            CKK_GENERIC_SECRET as CK_KEY_TYPE
        }
        YUBIHSM_ALGO_AES128 | YUBIHSM_ALGO_AES192 | YUBIHSM_ALGO_AES256 => CKK_AES as CK_KEY_TYPE,
        YUBIHSM_ALGO_ED25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
        YUBIHSM_ALGO_X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
        algorithm if is_yubihsm_rsa(algorithm) => CKK_RSA as CK_KEY_TYPE,
        algorithm if is_yubihsm_ec(algorithm) => CKK_EC as CK_KEY_TYPE,
        algorithm => CKK_VENDOR_DEFINED as CK_KEY_TYPE | algorithm as CK_KEY_TYPE,
    }
}

fn yubihsm_algorithm_supported(algorithm: u8) -> bool {
    yubihsm_key_type(algorithm) < CKK_VENDOR_DEFINED as CK_KEY_TYPE
}

fn yubihsm_key_generation_mechanism(algorithm: u8) -> Option<CK_MECHANISM_TYPE> {
    if is_yubihsm_rsa(algorithm) {
        Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if is_yubihsm_x25519(algorithm) {
        Some(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if algorithm == YUBIHSM_ALGO_ED25519 {
        Some(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if is_yubihsm_ec(algorithm) {
        Some(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if matches!(
        algorithm,
        YUBIHSM_ALGO_AES128 | YUBIHSM_ALGO_AES192 | YUBIHSM_ALGO_AES256
    ) {
        Some(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE)
    } else if matches!(
        algorithm,
        YUBIHSM_ALGO_HMAC_SHA1
            | YUBIHSM_ALGO_HMAC_SHA256
            | YUBIHSM_ALGO_HMAC_SHA384
            | YUBIHSM_ALGO_HMAC_SHA512
    ) {
        Some(CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE)
    } else {
        None
    }
}

fn yubihsm_remote_material(info: &YubiHsmObjectInfo, public_key: Vec<u8>) -> KeyMaterial {
    yubihsm_remote_material_with_type(info, info.object_type, public_key)
}

fn yubihsm_remote_material_with_type(
    info: &YubiHsmObjectInfo,
    object_type: u8,
    public_key: Vec<u8>,
) -> KeyMaterial {
    KeyMaterial::YubiHsm {
        id: info.id,
        object_type,
        algorithm: info.algorithm,
        length: info.length as usize,
        domains: info.domains,
        capabilities: info.capabilities,
        delegated_capabilities: info.delegated_capabilities,
        public_key,
        value: Rc::new(RefCell::new(None)),
    }
}

fn yubihsm_object_has_public_key(info: &YubiHsmObjectInfo) -> bool {
    matches!(
        info.object_type,
        YUBIHSM_ASYMMETRIC_KEY | YUBIHSM_PUBLIC_WRAP_KEY
    ) || (info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(info.algorithm))
}

#[cfg(any(test, feature = "abi-tests"))]
fn yubihsm_token_objects(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
) -> Result<Vec<TokenObject>, Error> {
    let generation = info.sequence as u64;
    yubihsm_token_objects_with_generation(slot_id, info, public_key, generation)
}

fn yubihsm_token_objects_with_generation(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
    generation: u64,
) -> Result<Vec<TokenObject>, Error> {
    let key_type = yubihsm_key_type(info.algorithm);
    let label = info.label.clone();
    if info.object_type == YUBIHSM_OPAQUE
        && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA
        && label.starts_with("Meta object")
    {
        return Ok(Vec::new());
    }
    let id = info.id.to_be_bytes().to_vec();
    let unique = format!(
        "yubihsm-{:02x}-{:04x}-{:02x}-{generation}",
        info.object_type, info.id, info.sequence
    );
    let generated = info.origin & 0x01 != 0;
    let algorithm_supported = yubihsm_algorithm_supported(info.algorithm);
    let authentication_key = info.object_type == YUBIHSM_AUTHENTICATION_KEY;
    let rsa_wrap_key = info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(info.algorithm);
    let ccm_wrap_key = info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_ccm_wrap(info.algorithm);
    let montgomery = is_montgomery_key_type(key_type);
    let sign = !authentication_key
        && (info.object_type == YUBIHSM_ASYMMETRIC_KEY
            || (info.object_type == YUBIHSM_HMAC_KEY && is_hmac_key_type(key_type)))
        && algorithm_supported
        && !is_yubihsm_x25519(info.algorithm)
        && (yubihsm_capability(&info.capabilities, 0x05)
            || yubihsm_capability(&info.capabilities, 0x06)
            || yubihsm_capability(&info.capabilities, 0x07)
            || yubihsm_capability(&info.capabilities, 0x08)
            || yubihsm_capability(&info.capabilities, 0x16));
    let decrypt = if ccm_wrap_key {
        yubihsm_capability(&info.capabilities, 0x26)
    } else {
        !authentication_key
            && !rsa_wrap_key
            && info.object_type != YUBIHSM_PUBLIC_WRAP_KEY
            && !montgomery
            && algorithm_supported
            && (yubihsm_capability(&info.capabilities, 0x09)
                || yubihsm_capability(&info.capabilities, 0x0a)
                || yubihsm_capability(&info.capabilities, 0x32)
                || yubihsm_capability(&info.capabilities, 0x34))
    };
    let encrypt = if ccm_wrap_key {
        yubihsm_capability(&info.capabilities, 0x25)
    } else {
        !authentication_key
            && !rsa_wrap_key
            && info.object_type != YUBIHSM_PUBLIC_WRAP_KEY
            && !montgomery
            && algorithm_supported
            && (yubihsm_capability(&info.capabilities, 0x33)
                || yubihsm_capability(&info.capabilities, 0x35))
    };
    let derive = !authentication_key
        && algorithm_supported
        && (is_yubihsm_ec(info.algorithm) || is_yubihsm_x25519(info.algorithm))
        && yubihsm_capability(&info.capabilities, 0x0b);
    let material = yubihsm_remote_material(
        &info,
        public_key
            .as_ref()
            .map(|key| key.key.clone())
            .unwrap_or_default(),
    );
    let class = match info.object_type {
        YUBIHSM_OPAQUE if info.algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE => {
            CKO_CERTIFICATE as CK_OBJECT_CLASS
        }
        YUBIHSM_OPAQUE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_ASYMMETRIC_KEY => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        YUBIHSM_WRAP_KEY if rsa_wrap_key => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        YUBIHSM_PUBLIC_WRAP_KEY => CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        YUBIHSM_TEMPLATE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_AUTHENTICATION_KEY
        | YUBIHSM_WRAP_KEY
        | YUBIHSM_HMAC_KEY
        | YUBIHSM_SYMMETRIC_KEY
        | YUBIHSM_OTP_AEAD_KEY => CKO_SECRET_KEY as CK_OBJECT_CLASS,
        _ => CKO_DATA as CK_OBJECT_CLASS,
    };
    let private =
        class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS && class != CKO_DATA as CK_OBJECT_CLASS;
    let mut objects = vec![TokenObject {
        slot_id: Some(slot_id),
        unique_id: unique.clone(),
        class,
        key_type,
        label: label.clone(),
        id: id.clone(),
        token: true,
        private,
        encrypt,
        decrypt,
        sign,
        verify: false,
        derive,
        sensitive: private,
        extractable: yubihsm_capability(&info.capabilities, 0x10)
            && class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            && class != CKO_SECRET_KEY as CK_OBJECT_CLASS,
        always_sensitive: private,
        never_extractable: class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || class == CKO_SECRET_KEY as CK_OBJECT_CLASS
            || !yubihsm_capability(&info.capabilities, 0x10),
        local: generated,
        key_gen_mechanism: generated
            .then(|| yubihsm_key_generation_mechanism(info.algorithm))
            .flatten(),
        owner_session: None,
        material,
    }];

    if info.object_type == YUBIHSM_ASYMMETRIC_KEY || rsa_wrap_key {
        let public_key = public_key.ok_or(CKR_DEVICE_ERROR)?;
        if public_key.algorithm != info.algorithm {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let public_material = if rsa_wrap_key {
            yubihsm_remote_material_with_type(
                &info,
                YUBIHSM_WRAP_KEY_PUBLIC,
                public_key.key.clone(),
            )
        } else if is_yubihsm_rsa(info.algorithm) {
            let modulus = BigNum::from_slice(&public_key.key).map_err(Error::from)?;
            let exponent = BigNum::from_u32(65537).map_err(Error::from)?;
            KeyMaterial::RsaPublic(
                Rsa::from_public_components(modulus, exponent).map_err(Error::from)?,
            )
        } else {
            yubihsm_remote_material(&info, public_key.key)
        };
        objects.push(TokenObject {
            slot_id: Some(slot_id),
            unique_id: format!("{unique}-public"),
            class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            key_type,
            label,
            id,
            token: true,
            private: false,
            encrypt: !rsa_wrap_key && algorithm_supported && is_yubihsm_rsa(info.algorithm),
            decrypt: false,
            sign: false,
            verify: !rsa_wrap_key && algorithm_supported && sign,
            derive: false,
            sensitive: false,
            extractable: true,
            always_sensitive: false,
            never_extractable: false,
            local: generated,
            key_gen_mechanism: objects[0].key_gen_mechanism,
            owner_session: None,
            material: public_material,
        });
    }
    Ok(objects)
}

impl Slot for YubiHsmSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.connector.name()
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        self.connector.product()
    }
    fn serial(&self) -> &str {
        self.connector.serial()
    }
    fn major(&self) -> u8 {
        self.connector.major()
    }
    fn minor(&self) -> u8 {
        self.connector.minor()
    }
    fn hardware_major(&self) -> u8 {
        self.connector
            .hardware_version()
            .map(|(major, _)| major)
            .unwrap_or(1)
    }
    fn hardware_minor(&self) -> u8 {
        self.connector
            .hardware_version()
            .map(|(_, minor)| minor)
            .unwrap_or(0)
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(YubiHsmSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            session: self.session.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        let (username, password) = split_yubihsm_login(pin)?;
        self.login_user(username, password)
    }
    fn login_user(&mut self, username: &[u8], password: &[u8]) -> Result<(), Error> {
        *self.session.try_borrow_mut()? = None;
        let session = match parse_yubihsm_login_username(username)? {
            YubiHsmLoginUsername::HsmAuth(login) => {
                if password.len() > 16 {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                log!(
                    2,
                    "YubiHSM login requested through YubiHSM Auth credential {:?}, source {:?}, authentication key {:04x}",
                    login.label,
                    login.source,
                    login.authkey_id
                );
                let provider = {
                    let providers = self
                        .hsmauth_providers
                        .try_borrow()
                        .map_err(|_| CKR_CANT_LOCK)?;
                    log!(
                        2,
                        "YubiHSM Auth searching {} discovered credential providers",
                        providers.len()
                    );
                    let mut matches = providers.iter().filter(|provider| {
                        provider.credential.label == login.label
                            && login
                                .source
                                .as_ref()
                                .is_none_or(|source| provider.source_identifier() == *source)
                    });
                    let provider = match matches.next().cloned() {
                        Some(provider) => provider,
                        None => {
                            log!(
                                2,
                                "YubiHSM Auth found no credential matching label {:?} and source {:?}",
                                login.label,
                                login.source
                            );
                            return Err(CKR_PIN_INCORRECT.into());
                        }
                    };
                    if matches.next().is_some() {
                        log!(
                            2,
                            "YubiHSM Auth credential label is ambiguous; add the source serial postfix"
                        );
                        return Err(CKR_PIN_INCORRECT.into());
                    }
                    provider
                };
                log!(
                    2,
                    "YubiHSM Auth matched credential {:?} from {:?} using algorithm {:?}",
                    provider.credential.label,
                    provider.source_identifier(),
                    provider.credential.algorithm
                );
                let session = match provider.authenticate(
                    self.connector.as_ref(),
                    login.authkey_id,
                    password,
                ) {
                    Ok(session) => session,
                    Err(error) => {
                        log!(
                            2,
                            "YubiHSM Auth secure-session authentication failed: {:?}",
                            error
                        );
                        return Err(error);
                    }
                };
                log!(
                    2,
                    "YubiHSM Auth established a secure session with {} using authentication key {:04x}",
                    self.connector.name(),
                    login.authkey_id
                );
                session
            }
            YubiHsmLoginUsername::Asymmetric(authkey_id) => {
                if !(8..=64).contains(&password.len()) {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                YubiHsmSecureSession::authenticate_asymmetric(
                    self.connector.as_ref(),
                    authkey_id,
                    password,
                )?
            }
            YubiHsmLoginUsername::Symmetric(authkey_id) => {
                if !(8..=64).contains(&password.len()) {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                YubiHsmSecureSession::authenticate(
                    self.connector.as_ref(),
                    authkey_id,
                    password,
                )?
            }
        };
        *self.session.try_borrow_mut()? = Some(session);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        let mut session = self.session.try_borrow_mut()?.take();
        match session.as_mut() {
            Some(session) => session
                .send_command(self.connector.as_ref(), &YubiHsmCommand::close_session())
                .map(|_| ()),
            None => Err(CKR_USER_NOT_LOGGED_IN.into()),
        }
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.version = (device_info.major, device_info.minor, device_info.patch);
        self.algorithms = device_info.algorithms;
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        info.firmwareVersion.major = self.version.0;
        info.firmwareVersion.minor = self.version.1.saturating_mul(10) + self.version.2;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.format_token_info(info);
        str_pad(&device_info.serial.to_string(), &mut info.serialNumber);
        info.firmwareVersion.major = device_info.major;
        info.firmwareVersion.minor = device_info.minor.saturating_mul(10) + device_info.patch;
        let has_hsmauth = !self
            .hsmauth_providers
            .try_borrow()
            .map_err(|_| CKR_CANT_LOCK)?
            .is_empty();
        if has_hsmauth {
            info.ulMaxPinLen = 216;
            info.ulMinPinLen = 8;
        } else {
            info.ulMaxPinLen = 69;
            info.ulMinPinLen = 12;
        }
        Ok(())
    }
    fn clear_session(&mut self) {
        *self.session.borrow_mut() = None;
    }
    fn login_is_active(&self) -> bool {
        self.session.borrow().is_some()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let listed = send_yubihsm_secure_command(
            self.connector.as_ref(),
            self.session.as_ref(),
            &YubiHsmCommand::list_objects(&[])?,
        )?;
        let mut discovered = Vec::new();
        for entry in parse_yubihsm_object_list(&listed)? {
            let info = YubiHsmObjectInfo::parse(&send_yubihsm_secure_command(
                self.connector.as_ref(),
                self.session.as_ref(),
                &YubiHsmCommand::get_object_info(entry.id, entry.object_type),
            )?)?;
            if info.id != entry.id
                || info.object_type != entry.object_type
                || info.sequence != entry.sequence
            {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let public_key = if yubihsm_object_has_public_key(&info) {
                Some(YubiHsmPublicKey::parse(&send_yubihsm_secure_command(
                    self.connector.as_ref(),
                    self.session.as_ref(),
                    &YubiHsmCommand::get_public_key(info.id, Some(info.object_type)),
                )?)?)
            } else {
                None
            };
            discovered.push((info, public_key));
        }

        let discovered_keys = discovered
            .iter()
            .map(|(info, _)| (info.object_type, info.id))
            .collect::<HashSet<_>>();
        let mut generations = self
            .object_generations
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        generations.retain(|key, _| discovered_keys.contains(key));

        let mut objects = Vec::new();
        let mut metadata = HashMap::new();
        for (info, public_key) in discovered {
            let key = (info.object_type, info.id);
            let generation = match generations.get(&key) {
                Some((sequence, generation)) if *sequence == info.sequence => *generation,
                _ => {
                    let generation = self.next_object_generation.get();
                    self.next_object_generation.set(
                        generation
                            .checked_add(1)
                            .ok_or(CKR_DEVICE_MEMORY)?,
                    );
                    generations.insert(key, (info.sequence, generation));
                    generation
                }
            };
            metadata.insert(key, (info.clone(), public_key.clone(), generation));
            objects.extend(yubihsm_token_objects_with_generation(
                slot_id,
                info,
                public_key,
                generation,
            )?);
        }
        drop(generations);
        *self.object_metadata.try_borrow_mut()? = metadata;
        Ok(objects)
    }
    fn token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        let metadata = self
            .object_metadata
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for (info, public_key, generation) in metadata {
            if let Some(object) =
                yubihsm_token_objects_with_generation(slot_id, info, public_key, generation)?
                .into_iter()
                .find(|object| object.unique_id == unique_id)
            {
                return Ok(Some(object));
            }
        }
        Ok(None)
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        yubihsm_mechanisms(&self.algorithms)
    }
    fn is_yubihsm(&self) -> bool {
        true
    }
}

#[derive(Debug, Eq, PartialEq)]
struct HsmAuthLogin<'a> {
    label: &'a str,
    source: Option<&'a str>,
    authkey_id: u16,
}

enum YubiHsmLoginUsername<'a> {
    Symmetric(u16),
    Asymmetric(u16),
    HsmAuth(HsmAuthLogin<'a>),
}

fn parse_yubihsm_authkey_id(value: &[u8]) -> Result<u16, Error> {
    if value.len() != 4 {
        return Err(CKR_PIN_INCORRECT.into());
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| u16::from_str_radix(value, 16).ok())
        .ok_or_else(|| CKR_PIN_INCORRECT.into())
}

fn parse_hsmauth_username(username: &[u8]) -> Result<HsmAuthLogin<'_>, Error> {
    if username.len() < 6 || username.first() != Some(&b':') {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let authkey_id = parse_yubihsm_authkey_id(&username[1..5])?;
    let selector = &username[5..];
    let (label, source) = match selector.iter().position(|byte| *byte == b'@') {
        Some(position) => (&selector[..position], Some(&selector[position + 1..])),
        None => (selector, None),
    };
    let label = parse_hsmauth_selector_part(label, 64)?;
    let source = source
        .map(|source| parse_hsmauth_selector_part(source, 128))
        .transpose()?;
    Ok(HsmAuthLogin {
        label,
        source,
        authkey_id,
    })
}

fn parse_yubihsm_login_username(username: &[u8]) -> Result<YubiHsmLoginUsername<'_>, Error> {
    match username.first() {
        Some(b':') => parse_hsmauth_username(username).map(YubiHsmLoginUsername::HsmAuth),
        Some(b'@') => parse_yubihsm_authkey_id(&username[1..])
            .map(YubiHsmLoginUsername::Asymmetric),
        _ => parse_yubihsm_authkey_id(username).map(YubiHsmLoginUsername::Symmetric),
    }
}

fn split_yubihsm_login(pin: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let username_length = match pin.first() {
        Some(b':') => pin
            .get(5..)
            .and_then(|value| value.iter().position(|byte| *byte == b':'))
            .map(|position| position + 5)
            .ok_or(CKR_PIN_INCORRECT)?,
        Some(b'@') => 5,
        _ => 4,
    };
    if pin.len() < username_length {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let password_offset = username_length + usize::from(pin.first() == Some(&b':'));
    let password = pin
        .get(password_offset..)
        .ok_or(CKR_PIN_INCORRECT)?;
    Ok((&pin[..username_length], password))
}

fn parse_hsmauth_selector_part(value: &[u8], maximum_length: usize) -> Result<&str, Error> {
    if value.is_empty() || value.len() > maximum_length {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let value = std::str::from_utf8(value).map_err(|_| CKR_PIN_INCORRECT)?;
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '@' | ':'))
    {
        return Err(CKR_PIN_INCORRECT.into());
    }
    Ok(value)
}

#[derive(Debug)]

struct YubiHsmSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
}

impl Session for YubiHsmSession {
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
        self.send_secure_cmd(&YubiHsmCommand::get_storage_info())
            .map(|_| ())
    }
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(1024) {
            let random =
                self.send_secure_cmd(&YubiHsmCommand::get_pseudo_random(chunk.len() as u16))?;
            if random.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&random);
        }
        Ok(())
    }
    fn yubihsm_command(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        self.send_secure_cmd(command)
    }
}

impl YubiHsmSession {
    fn send_secure_cmd(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        send_yubihsm_secure_command(self.connector.as_ref(), self.session.as_ref(), command)
    }
}
