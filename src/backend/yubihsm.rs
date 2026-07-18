#[derive(Debug)]
struct YubiHsmSlot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
    version: (u8, u8, u8),
    algorithms: Vec<u8>,
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

fn yubihsm_token_objects(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
) -> Result<Vec<TokenObject>, Error> {
    let key_type = yubihsm_key_type(info.algorithm);
    let label = info
        .label
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
        .to_vec();
    if info.object_type == YUBIHSM_OPAQUE
        && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA
        && label.starts_with(b"Meta object")
    {
        return Ok(Vec::new());
    }
    let id = info.id.to_be_bytes().to_vec();
    let unique = format!("yubihsm-{:02x}-{:04x}", info.object_type, info.id);
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
        unique_id: unique.as_bytes().to_vec(),
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
            unique_id: format!("{unique}-public").into_bytes(),
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
        *self.session.try_borrow_mut()? = None;
        let session = if pin.first() == Some(&b'@') {
            let (authkey_id, password) = parse_yubihsm_asymmetric_pin(pin)?;
            YubiHsmSecureSession::authenticate_asymmetric(
                self.connector.as_ref(),
                authkey_id,
                password,
            )?
        } else {
            let (authkey_id, password) = parse_yubihsm_pin(pin)?;
            YubiHsmSecureSession::authenticate(self.connector.as_ref(), authkey_id, password)?
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
        info.ulMaxPinLen = 69;
        info.ulMinPinLen = 12;
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
        let mut objects = Vec::new();
        for entry in parse_yubihsm_object_list(&listed)? {
            let info = YubiHsmObjectInfo::parse(&send_yubihsm_secure_command(
                self.connector.as_ref(),
                self.session.as_ref(),
                &YubiHsmCommand::get_object_info(entry.id, entry.object_type),
            )?)?;
            if info.id != entry.id || info.object_type != entry.object_type {
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
            objects.extend(yubihsm_token_objects(slot_id, info, public_key)?);
        }
        Ok(objects)
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        yubihsm_mechanisms(&self.algorithms)
    }
    fn is_yubihsm(&self) -> bool {
        true
    }
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
