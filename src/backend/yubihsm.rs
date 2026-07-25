use crate::*;

#[derive(Clone, Debug)]
pub(crate) struct HsmAuthProvider {
    pub(crate) connector: Rc<dyn Connector>,
    pub(crate) credential: HsmAuthCredential,
    pub(crate) version: (u8, u8, u8),
    pub(crate) trust_prefix: Option<std::ffi::OsString>,
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

    fn slot_label(&self) -> String {
        format!("YubiHSM Auth #{}", self.source_identifier())
    }

    pub(crate) fn authenticate(
        &self,
        yubihsm_connector: &dyn Connector,
        authkey_id: u16,
        credential_password: &[u8],
    ) -> Result<YubiHsmSecureSession, Error> {
        self.authenticate_with_trust_prefix(
            yubihsm_connector,
            authkey_id,
            credential_password,
            self.trust_prefix.as_deref(),
        )
    }

    fn authenticate_with_trust_prefix(
        &self,
        yubihsm_connector: &dyn Connector,
        authkey_id: u16,
        credential_password: &[u8],
        trust_prefix: Option<&std::ffi::OsStr>,
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
                getrandom::fill(&mut challenge).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
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
                let challenge_password = (self.version.0 == 0 || self.version >= (5, 7, 1))
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
                if let Err(error) = crate::yubihsm::validate_device_public_key_with_prefix(
                    &device_public_key,
                    trust_prefix,
                ) {
                    log!(
                        2,
                        "YubiHSM device public-key certificate validation failed: {:?}",
                        error
                    );
                    YubiHsmSecureSession::close_failed_asymmetric_handshake(
                        yubihsm_connector,
                        handshake,
                    );
                    return Err(error);
                }
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
                    handshake, keys.enc, keys.mac, keys.rmac,
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
pub(crate) struct YubiHsmSlot {
    pub(crate) connector: Rc<dyn Connector>,
    pub(crate) session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
    pub(crate) session_role: Cell<Option<YubiHsmSessionRole>>,
    pub(crate) public_discovery_credential: Option<Rc<YubiHsmPublicDiscoveryCredential>>,
    pub(crate) object_cache: RefCell<YubiHsmObjectCache>,
    pub(crate) version: (u8, u8, u8),
    pub(crate) algorithms: Vec<u8>,
    pub(crate) trust_prefix: Option<std::ffi::OsString>,
    pub(crate) hsmauth_providers: Rc<RefCell<Vec<HsmAuthProvider>>>,
    pub(crate) object_metadata: RefCell<HashMap<YubiHsmObjectKey, YubiHsmObjectMetadata>>,
    pub(crate) object_generations: RefCell<HashMap<YubiHsmObjectKey, (u8, u64)>>,
    pub(crate) attestation_cache:
        RefCell<HashMap<(YubiHsmObjectKey, u64), YubiHsmAttestationCache>>,
    pub(crate) next_object_generation: Cell<u64>,
    pub(crate) device_public_key: OnceLock<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum YubiHsmSessionRole {
    PublicDiscovery,
    User,
}

#[cfg_attr(feature = "abi-tests", allow(dead_code))]
pub(crate) const YUBIHSM_DISCOVERY_ENV: &str = "PKCS11RS_YUBIHSM_DISCOVERY";

pub(crate) struct YubiHsmPublicDiscoveryCredential {
    pub(crate) username: Vec<u8>,
    pub(crate) authkey_id: u16,
    pub(crate) password: RefCell<Option<Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for YubiHsmPublicDiscoveryCredential {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("YubiHsmPublicDiscoveryCredential")
            .field("username", &"[CONFIGURED SELECTOR]")
            .field("authkey_id", &format_args!("{:04x}", self.authkey_id))
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl YubiHsmPublicDiscoveryCredential {
    pub(crate) fn uses_hsmauth(&self) -> bool {
        self.username.first() == Some(&b':')
    }

    fn with_password<T>(
        &self,
        prompt: pinentry::Prompt<'_>,
        operation: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut password = self.password.try_borrow_mut()?;
        if password.is_none() {
            let entered = pinentry::request(prompt)?;
            match parse_yubihsm_login_username(&self.username)? {
                YubiHsmLoginUsername::Direct(_) if !(8..=64).contains(&entered.len()) => {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                YubiHsmLoginUsername::HsmAuth(_) if entered.len() > 16 => {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                _ => {}
            }
            *password = Some(entered);
        }
        operation(password.as_deref().ok_or(CKR_PIN_INCORRECT)?.as_slice())
    }
}

#[derive(Debug, Default)]
pub(crate) struct YubiHsmObjectCache {
    pub(crate) connection_epoch: u64,
    pub(crate) attempted: bool,
    pub(crate) available: bool,
    pub(crate) authkey_domains: Option<u16>,
    pub(crate) native_objects: HashMap<YubiHsmObjectKey, YubiHsmCachedObjectProperties>,
    pub(crate) objects: Vec<TokenObject>,
}

#[cfg_attr(feature = "abi-tests", allow(dead_code))]
pub(crate) fn configured_yubihsm_public_discovery_credential(
    credential: Option<std::ffi::OsString>,
) -> Result<Option<Rc<YubiHsmPublicDiscoveryCredential>>, Error> {
    let Some(credential) = credential else {
        return Ok(None);
    };
    let credential = credential.into_string().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let (username, password) =
        split_yubihsm_login(credential.as_bytes()).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let login = parse_yubihsm_login_username(username).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let authkey_id = match &login {
        YubiHsmLoginUsername::Direct(authkey_id) => {
            if password
                .is_some_and(|password| !password.is_empty() && !(8..=64).contains(&password.len()))
            {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            *authkey_id
        }
        YubiHsmLoginUsername::HsmAuth(login) => {
            if password.is_some_and(|password| password.len() > 16) {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            login.authkey_id
        }
    };
    let password = match login {
        YubiHsmLoginUsername::Direct(_) => password.filter(|password| !password.is_empty()),
        YubiHsmLoginUsername::HsmAuth(_) => password,
    };
    if password.is_none() && !pinentry::is_configured() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(Some(Rc::new(YubiHsmPublicDiscoveryCredential {
        username: username.to_vec(),
        authkey_id,
        password: RefCell::new(password.map(|password| Zeroizing::new(password.to_vec()))),
    })))
}

pub(crate) type YubiHsmObjectKey = (u8, u16);
pub(crate) type YubiHsmMetadataTarget = (u8, u16, u8);
pub(crate) type YubiHsmObjectMetadata = (
    YubiHsmObjectInfo,
    Option<YubiHsmPublicKey>,
    u64,
    Option<YubiHsmPkcs11Metadata>,
);
pub(crate) type YubiHsmDiscoveredObjects = (
    Vec<(YubiHsmObjectInfo, Option<YubiHsmPublicKey>)>,
    HashMap<(u8, u16, u8, u16), YubiHsmPkcs11Metadata>,
);

#[derive(Clone, Debug)]
pub(crate) struct YubiHsmCachedObjectProperties {
    pub(crate) sequence: Option<u8>,
    pub(crate) info: Option<YubiHsmObjectInfo>,
    pub(crate) public_key: Option<YubiHsmPublicKey>,
    pub(crate) object_value: Rc<RefCell<Option<Vec<u8>>>>,
    pub(crate) metadata_sources: Vec<(u16, u8)>,
    pub(crate) inferred_authentication_algorithm: Option<YubiHsmAuthAlgorithm>,
}

impl YubiHsmCachedObjectProperties {
    fn new(sequence: Option<u8>) -> Self {
        Self {
            sequence,
            info: None,
            public_key: None,
            object_value: Rc::new(RefCell::new(None)),
            metadata_sources: Vec::new(),
            inferred_authentication_algorithm: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct YubiHsmAttestationCache {
    pub(crate) value: Rc<RefCell<Option<Vec<u8>>>>,
    pub(crate) attempted: Rc<Cell<bool>>,
}

impl YubiHsmAttestationCache {
    fn new() -> Self {
        Self {
            value: Rc::new(RefCell::new(None)),
            attempted: Rc::new(Cell::new(false)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct YubiHsmPkcs11Metadata {
    pub(crate) target_type: u8,
    pub(crate) target_id: u16,
    pub(crate) target_sequence: u8,
    pub(crate) id: Option<Vec<u8>>,
    pub(crate) label: Option<String>,
    pub(crate) public_id: Option<Vec<u8>>,
    pub(crate) public_label: Option<String>,
}

impl YubiHsmPkcs11Metadata {
    fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.label.is_none()
            && self.public_id.is_none()
            && self.public_label.is_none()
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        const MAX_ATTRIBUTE_LENGTH: usize = 256;

        let mut value = b"MDB1".to_vec();
        value.push(self.target_type);
        value.extend_from_slice(&self.target_id.to_be_bytes());
        value.push(self.target_sequence);
        for (tag, item) in [
            (1, self.id.as_deref()),
            (2, self.label.as_deref().map(str::as_bytes)),
            (3, self.public_id.as_deref()),
            (4, self.public_label.as_deref().map(str::as_bytes)),
        ] {
            let Some(item) = item else {
                continue;
            };
            if item.len() > MAX_ATTRIBUTE_LENGTH {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            value.push(tag);
            value.extend_from_slice(&(item.len() as u16).to_be_bytes());
            value.extend_from_slice(item);
        }
        Ok(value)
    }
}

impl YubiHsmSlot {
    fn authentication_algorithm(info: &YubiHsmObjectInfo) -> Option<YubiHsmAuthAlgorithm> {
        match (info.object_type, info.algorithm) {
            (YUBIHSM_AUTHENTICATION_KEY, YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION) => {
                Some(YubiHsmAuthAlgorithm::Symmetric)
            }
            (YUBIHSM_AUTHENTICATION_KEY, YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION) => {
                Some(YubiHsmAuthAlgorithm::Asymmetric)
            }
            _ => None,
        }
    }

    pub(crate) fn new(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
    ) -> Self {
        Self {
            connector,
            session: Rc::new(RefCell::new(None)),
            session_role: Cell::new(None),
            public_discovery_credential: None,
            object_cache: RefCell::new(YubiHsmObjectCache::default()),
            version,
            algorithms,
            trust_prefix: None,
            hsmauth_providers: Rc::new(RefCell::new(Vec::new())),
            object_metadata: RefCell::new(HashMap::new()),
            object_generations: RefCell::new(HashMap::new()),
            attestation_cache: RefCell::new(HashMap::new()),
            next_object_generation: Cell::new(1),
            device_public_key: OnceLock::new(),
        }
    }

    pub(crate) fn with_hsmauth_providers(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
        hsmauth_providers: Rc<RefCell<Vec<HsmAuthProvider>>>,
    ) -> Self {
        let mut slot = Self::new(connector, version, algorithms);
        slot.hsmauth_providers = hsmauth_providers;
        slot
    }

    pub(crate) fn with_hsmauth_providers_and_public_discovery(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
        hsmauth_providers: Rc<RefCell<Vec<HsmAuthProvider>>>,
        public_discovery_credential: Option<Rc<YubiHsmPublicDiscoveryCredential>>,
    ) -> Self {
        let mut slot =
            Self::with_hsmauth_providers(connector, version, algorithms, hsmauth_providers);
        slot.public_discovery_credential = public_discovery_credential;
        slot
    }

    fn device_public_key(&self) -> Result<&[u8], Error> {
        if self.device_public_key.get().is_none() {
            let public_key = get_yubihsm_device_public_key(self.connector.as_ref())?.to_vec();
            let _ = self.device_public_key.set(public_key);
        }
        self.device_public_key
            .get()
            .map(Vec::as_slice)
            .ok_or_else(|| CKR_DEVICE_ERROR.into())
    }

    fn hsmauth_provider(&self, login: &HsmAuthLogin<'_>) -> Result<HsmAuthProvider, Error> {
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
        Ok(provider)
    }

    fn cache_object_info(&self, info: &YubiHsmObjectInfo) -> Result<(), Error> {
        let mut state = self.object_cache.try_borrow_mut()?;
        let key = (info.object_type, info.id);
        let sequence_changed = {
            let entry = state
                .native_objects
                .entry(key)
                .or_insert_with(|| YubiHsmCachedObjectProperties::new(Some(info.sequence)));
            let sequence_changed = entry
                .sequence
                .is_some_and(|sequence| sequence != info.sequence);
            if sequence_changed {
                *entry = YubiHsmCachedObjectProperties::new(Some(info.sequence));
            } else {
                entry.sequence = Some(info.sequence);
            }
            entry.info = Some(info.clone());
            entry.inferred_authentication_algorithm = None;
            sequence_changed
        };
        if sequence_changed && info.object_type == YUBIHSM_OPAQUE {
            for entry in state.native_objects.values_mut() {
                entry
                    .metadata_sources
                    .retain(|(source_id, _)| *source_id != info.id);
            }
        }

        Ok(())
    }

    fn cached_object_info(
        &self,
        id: u16,
        object_type: u8,
        sequence: Option<u8>,
    ) -> Result<Option<YubiHsmObjectInfo>, Error> {
        Ok(self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&(object_type, id))
            .filter(|entry| sequence.is_none_or(|sequence| entry.sequence == Some(sequence)))
            .and_then(|entry| entry.info.clone()))
    }

    pub(crate) fn read_object_info(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        id: u16,
        object_type: u8,
        expected_sequence: Option<u8>,
    ) -> Result<YubiHsmObjectInfo, Error> {
        let info = YubiHsmObjectInfo::parse(&send_yubihsm_secure_command(
            self.connector.as_ref(),
            session,
            &YubiHsmCommand::get_object_info(id, object_type),
        )?)?;
        if info.id != id
            || info.object_type != object_type
            || expected_sequence.is_some_and(|sequence| info.sequence != sequence)
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        self.cache_object_info(&info)?;
        Ok(info)
    }

    fn listed_object_info(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        id: u16,
        object_type: u8,
        sequence: u8,
    ) -> Result<YubiHsmObjectInfo, Error> {
        let cached = {
            let mut state = self.object_cache.try_borrow_mut()?;
            let (cached, sequence_changed) = {
                let entry = state
                    .native_objects
                    .entry((object_type, id))
                    .or_insert_with(|| YubiHsmCachedObjectProperties::new(Some(sequence)));
                let sequence_changed = entry.sequence.is_some_and(|cached| cached != sequence);
                if sequence_changed {
                    *entry = YubiHsmCachedObjectProperties::new(Some(sequence));
                } else {
                    entry.sequence = Some(sequence);
                }
                (entry.info.clone(), sequence_changed)
            };
            if sequence_changed && object_type == YUBIHSM_OPAQUE {
                for entry in state.native_objects.values_mut() {
                    entry
                        .metadata_sources
                        .retain(|(source_id, _)| *source_id != id);
                }
            }
            cached
        };
        if let Some(info) = cached {
            return Ok(info);
        }
        self.read_object_info(session, id, object_type, Some(sequence))
    }

    fn object_info_with_session(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        id: u16,
        object_type: u8,
    ) -> Result<YubiHsmObjectInfo, Error> {
        if let Some(info) = self.cached_object_info(id, object_type, None)? {
            return Ok(info);
        }
        self.read_object_info(session, id, object_type, None)
    }

    fn object_value_cache_entry(
        &self,
        info: &YubiHsmObjectInfo,
    ) -> Result<Rc<RefCell<Option<Vec<u8>>>>, Error> {
        let mut state = self.object_cache.try_borrow_mut()?;
        let entry = state
            .native_objects
            .entry((info.object_type, info.id))
            .or_insert_with(|| YubiHsmCachedObjectProperties::new(Some(info.sequence)));
        if entry
            .sequence
            .is_some_and(|sequence| sequence != info.sequence)
        {
            *entry = YubiHsmCachedObjectProperties::new(Some(info.sequence));
        } else {
            entry.sequence = Some(info.sequence);
        }
        entry.info.get_or_insert_with(|| info.clone());
        Ok(entry.object_value.clone())
    }

    fn read_object_value_with_session(
        &self,
        info: &YubiHsmObjectInfo,
        session: &RefCell<Option<YubiHsmSecureSession>>,
    ) -> Result<Vec<u8>, Error> {
        let cached = self.object_value_cache_entry(info)?;
        if let Some(value) = cached
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .clone()
        {
            return Ok(value);
        }
        let command = match info.object_type {
            YUBIHSM_OPAQUE => YubiHsmCommandCode::GetOpaque,
            YUBIHSM_TEMPLATE => YubiHsmCommandCode::GetTemplate,
            _ => return Err(CKR_ATTRIBUTE_TYPE_INVALID.into()),
        };
        let value = send_yubihsm_secure_command(
            self.connector.as_ref(),
            session,
            &YubiHsmCommand::get_object(command, info.id)?,
        )?;
        *cached.try_borrow_mut()? = Some(value.clone());
        Ok(value)
    }

    fn read_opaque_with_session(
        &self,
        info: &YubiHsmObjectInfo,
        session: &RefCell<Option<YubiHsmSecureSession>>,
    ) -> Result<Vec<u8>, Error> {
        if info.object_type != YUBIHSM_OPAQUE {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID.into());
        }
        self.read_object_value_with_session(info, session)
    }

    fn read_object_value_by_id(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        id: u16,
        object_type: u8,
    ) -> Result<Vec<u8>, Error> {
        let info = self.object_info_with_session(session, id, object_type)?;
        self.read_object_value_with_session(&info, session)
    }

    fn public_key_with_session(
        &self,
        info: &YubiHsmObjectInfo,
        session: &RefCell<Option<YubiHsmSecureSession>>,
    ) -> Result<YubiHsmPublicKey, Error> {
        if let Some(public_key) = self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&(info.object_type, info.id))
            .filter(|entry| entry.sequence == Some(info.sequence))
            .and_then(|entry| entry.public_key.clone())
        {
            return Ok(public_key);
        }
        let encoded = send_yubihsm_secure_command(
            self.connector.as_ref(),
            session,
            &YubiHsmCommand::get_public_key(info.id, Some(info.object_type)),
        )?;
        let public_key = YubiHsmPublicKey::parse(&encoded)?;
        let mut state = self.object_cache.try_borrow_mut()?;
        let entry = state
            .native_objects
            .entry((info.object_type, info.id))
            .or_insert_with(|| YubiHsmCachedObjectProperties::new(Some(info.sequence)));
        if entry
            .sequence
            .is_some_and(|sequence| sequence != info.sequence)
        {
            *entry = YubiHsmCachedObjectProperties::new(Some(info.sequence));
        } else {
            entry.sequence = Some(info.sequence);
        }
        entry.info.get_or_insert_with(|| info.clone());
        entry.public_key = Some(public_key.clone());
        Ok(public_key)
    }

    fn replace_metadata_links(
        &self,
        links: HashMap<YubiHsmMetadataTarget, Vec<(u16, u8)>>,
    ) -> Result<(), Error> {
        let mut state = self.object_cache.try_borrow_mut()?;
        for entry in state.native_objects.values_mut() {
            entry.metadata_sources.clear();
        }
        for ((object_type, id, sequence), sources) in links {
            let Some(entry) = state.native_objects.get_mut(&(object_type, id)) else {
                continue;
            };
            if entry.sequence == Some(sequence) {
                entry.metadata_sources = sources;
            }
        }
        Ok(())
    }

    fn authentication_key_info(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        authkey_id: u16,
    ) -> Result<YubiHsmObjectInfo, Error> {
        self.read_object_info(session, authkey_id, YUBIHSM_AUTHENTICATION_KEY, None)
    }

    pub(crate) fn cached_authentication_algorithm(
        &self,
        authkey_id: u16,
    ) -> Result<Option<YubiHsmAuthAlgorithm>, Error> {
        Ok(self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&(YUBIHSM_AUTHENTICATION_KEY, authkey_id))
            .and_then(|entry| {
                entry
                    .info
                    .as_ref()
                    .and_then(Self::authentication_algorithm)
                    .or(entry.inferred_authentication_algorithm)
            }))
    }

    fn authenticate_direct(
        &self,
        authkey_id: u16,
        password: &[u8],
    ) -> Result<YubiHsmSecureSession, Error> {
        self.synchronize_caches()?;
        let cached_algorithm = self.cached_authentication_algorithm(authkey_id)?;
        let (session, algorithm) = YubiHsmSecureSession::authenticate_direct(
            self.connector.as_ref(),
            authkey_id,
            password,
            self.trust_prefix.as_deref(),
            cached_algorithm,
        )?;
        let mut state = self.object_cache.try_borrow_mut()?;
        let entry = state
            .native_objects
            .entry((YUBIHSM_AUTHENTICATION_KEY, authkey_id))
            .or_insert_with(|| YubiHsmCachedObjectProperties::new(None));
        match entry.info.as_ref().and_then(Self::authentication_algorithm) {
            Some(cached) if cached == algorithm => {
                entry.inferred_authentication_algorithm = None;
            }
            Some(_) => {
                let sequence = entry.sequence;
                *entry = YubiHsmCachedObjectProperties::new(sequence);
                entry.inferred_authentication_algorithm = Some(algorithm);
            }
            None => entry.inferred_authentication_algorithm = Some(algorithm),
        }
        Ok(session)
    }

    fn authenticate_login(
        &self,
        username: &[u8],
        password: &[u8],
    ) -> Result<(YubiHsmSecureSession, u16), Error> {
        match parse_yubihsm_login_username(username)? {
            YubiHsmLoginUsername::HsmAuth(login) => {
                if password.len() > 16 {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                log!(
                    2,
                    "YubiHSM authentication requested through YubiHSM Auth credential {:?}, source {:?}, authentication key {:04x}",
                    login.label,
                    login.source,
                    login.authkey_id
                );
                let provider = self.hsmauth_provider(&login)?;
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
                            1,
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
                Ok((session, login.authkey_id))
            }
            YubiHsmLoginUsername::Direct(authkey_id) => {
                if !(8..=64).contains(&password.len()) {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                Ok((self.authenticate_direct(authkey_id, password)?, authkey_id))
            }
        }
    }

    fn authenticate_public_discovery(
        &self,
        credential: &YubiHsmPublicDiscoveryCredential,
    ) -> Result<(YubiHsmSecureSession, u16), Error> {
        let title = format!("Public discovery on {}", self.label());
        let description = match parse_yubihsm_login_username(&credential.username)? {
            YubiHsmLoginUsername::Direct(authkey_id) => {
                format!("Enter the password for YubiHSM Authentication Key {authkey_id:04x}.")
            }
            YubiHsmLoginUsername::HsmAuth(login) => {
                format!("Enter the authentication password for {:?}.", login.label)
            }
        };
        credential.with_password(
            pinentry::Prompt {
                title: &title,
                description: &description,
                label: "Authentication password:",
            },
            |password| self.authenticate_login(&credential.username, password),
        )
    }

    fn has_session_role(&self, role: YubiHsmSessionRole) -> bool {
        let present = self
            .session
            .try_borrow()
            .map(|session| session.is_some())
            .unwrap_or(false);
        present && self.session_role.get() == Some(role)
    }

    fn close_session_cell(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
        purpose: &str,
    ) -> Result<(), Error> {
        let mut session = session.try_borrow_mut()?;
        let Some(mut session) = session.take() else {
            return Ok(());
        };
        let result =
            session.send_command(self.connector.as_ref(), &YubiHsmCommand::close_session());
        if let Err(error) = &result {
            log!(
                2,
                "YubiHSM {purpose} session close failed on {}: {:?}",
                self.connector.name(),
                error
            );
        }
        result.map(|_| ())
    }

    fn close_active_session(&self, purpose: &str) -> Result<(), Error> {
        self.session_role.set(None);
        self.close_session_cell(self.session.as_ref(), purpose)
    }

    fn ensure_read_session(&self) -> Result<(), Error> {
        self.synchronize_caches()?;
        if self
            .session_role
            .get()
            .is_some_and(|role| self.has_session_role(role))
        {
            return Ok(());
        }
        if self.session_role.get() == Some(YubiHsmSessionRole::User) {
            self.session_role.set(None);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        self.session_role.set(None);
        let credential = self
            .public_discovery_credential
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let expected_domains = {
            let state = self
                .object_cache
                .try_borrow()
                .map_err(|_| Error::from(CKR_CANT_LOCK))?;
            state.authkey_domains
        };
        let (session, authkey_id) = match self.authenticate_public_discovery(credential) {
            Ok(authenticated) => authenticated,
            Err(error) => {
                log!(
                    2,
                    "YubiHSM pre-login authentication failed while reopening public discovery on {} with authentication key {:04x}: {:?}",
                    self.connector.name(),
                    credential.authkey_id,
                    error
                );
                return Err(error);
            }
        };
        let session = RefCell::new(Some(session));
        let validation = (|| {
            let info = self.authentication_key_info(&session, authkey_id)?;
            if expected_domains.is_some_and(|expected| info.domains != expected)
                || !yubihsm_capability(&info.capabilities, 0)
            {
                return Err(CKR_FUNCTION_REJECTED.into());
            }
            Ok(())
        })();
        if let Err(error) = validation {
            let _ = self.close_session_cell(&session, "rejected public discovery");
            return Err(error);
        }
        *self.session.try_borrow_mut()? = session.into_inner();
        self.session_role
            .set(Some(YubiHsmSessionRole::PublicDiscovery));
        log!(
            2,
            "YubiHSM public discovery session reopened on {}",
            self.connector.name()
        );
        Ok(())
    }

    fn read_object_value_with_public_discovery(
        &self,
        id: u16,
        object_type: u8,
    ) -> Result<Vec<u8>, Error> {
        for attempt in 0..2 {
            self.ensure_read_session()?;
            match self.read_object_value_by_id(self.session.as_ref(), id, object_type) {
                Ok(value) => {
                    log!(
                        2,
                        "YubiHSM public discovery cached object {} type {} from {}",
                        id,
                        object_type,
                        self.connector.name()
                    );
                    return Ok(value);
                }
                Err(error) => {
                    let invalidated = self
                        .session
                        .try_borrow()
                        .map_err(|_| Error::from(CKR_CANT_LOCK))?
                        .is_none();
                    if !invalidated || attempt == 1 {
                        return Err(error);
                    }
                    self.session_role.set(None);
                    log!(
                        2,
                        "YubiHSM public discovery session was invalidated on {}; reopening once",
                        self.connector.name()
                    );
                }
            }
        }
        Err(CKR_DEVICE_ERROR.into())
    }

    fn bind_cached_object_value(
        &self,
        info: &YubiHsmObjectInfo,
        objects: &mut [TokenObject],
    ) -> Result<(), Error> {
        if !matches!(info.object_type, YUBIHSM_OPAQUE | YUBIHSM_TEMPLATE) {
            return Ok(());
        }
        let cached = self.object_value_cache_entry(info)?;
        for object in objects {
            if let KeyMaterial::YubiHsm {
                object_type, value, ..
            } = &mut object.material
            {
                if *object_type == YUBIHSM_OPAQUE {
                    *value = cached.clone();
                }
            }
        }
        Ok(())
    }

    fn discover_objects(
        &self,
        session: &RefCell<Option<YubiHsmSecureSession>>,
    ) -> Result<YubiHsmDiscoveredObjects, Error> {
        let listed = send_yubihsm_secure_command(
            self.connector.as_ref(),
            session,
            &YubiHsmCommand::list_objects(&[])?,
        )?;
        let listed = parse_yubihsm_object_list(&listed)?;
        log!(
            2,
            "YubiHSM discovery listed {} hardware objects on {}",
            listed.len(),
            self.connector.name()
        );
        let mut discovered = Vec::new();
        let mut pkcs11_metadata = HashMap::new();
        let mut ambiguous_metadata = HashSet::new();
        let mut related_metadata = HashMap::<_, Vec<_>>::new();
        for entry in listed {
            let info =
                self.listed_object_info(session, entry.id, entry.object_type, entry.sequence)?;
            if info.object_type == YUBIHSM_OPAQUE && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA {
                let Some((target_sequence, target_type, target_id)) =
                    yubihsm_metadata_label_target(&info.label)
                else {
                    discovered.push((info, None));
                    continue;
                };
                related_metadata
                    .entry((target_type, target_id, target_sequence))
                    .or_default()
                    .push((info.id, info.sequence));
                let value = self.read_opaque_with_session(&info, session)?;
                match parse_yubihsm_pkcs11_metadata(&info, &value) {
                    Ok(metadata) => {
                        let target = (
                            metadata.target_type,
                            metadata.target_id,
                            metadata.target_sequence,
                            info.domains,
                        );
                        if ambiguous_metadata.contains(&target) {
                            continue;
                        }
                        if pkcs11_metadata.remove(&target).is_some() {
                            ambiguous_metadata.insert(target);
                            log!(
                                2,
                                "YubiHSM has duplicate PKCS11 metadata for object type {:02x} ID {:04x}",
                                target.0,
                                target.1
                            );
                        } else {
                            pkcs11_metadata.insert(target, metadata);
                        }
                        continue;
                    }
                    Err(error) => log!(
                        2,
                        "YubiHSM opaque object {} has a metadata label but invalid contents: {:?}",
                        info.id,
                        error
                    ),
                }
                continue;
            }
            let public_key = if yubihsm_object_has_public_key(&info) {
                match self.public_key_with_session(&info, session) {
                    Ok(public_key) => Some(public_key),
                    Err(error) => {
                        log!(
                            2,
                            "YubiHSM discovery skipped object type {:02x} ID {:04x} on {} because its public key is invalid: {:?}",
                            info.object_type,
                            info.id,
                            self.connector.name(),
                            error
                        );
                        continue;
                    }
                }
            } else {
                None
            };
            discovered.push((info, public_key));
        }
        log!(
            2,
            "YubiHSM discovery resolved {} objects and {} PKCS11 metadata records on {}",
            discovered.len(),
            pkcs11_metadata.len(),
            self.connector.name()
        );
        self.replace_metadata_links(related_metadata)?;
        Ok((discovered, pkcs11_metadata))
    }

    fn object_generation(&self, info: &YubiHsmObjectInfo) -> Result<u64, Error> {
        let key = (info.object_type, info.id);
        let mut generations = self
            .object_generations
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        if let Some((sequence, generation)) = generations.get(&key) {
            if *sequence == info.sequence {
                return Ok(*generation);
            }
        }
        let generation = self.next_object_generation.get();
        self.next_object_generation
            .set(generation.checked_add(1).ok_or(CKR_DEVICE_MEMORY)?);
        generations.insert(key, (info.sequence, generation));
        Ok(generation)
    }

    fn build_public_discovery_objects(
        &self,
        slot_id: CK_SLOT_ID,
        session: &RefCell<Option<YubiHsmSecureSession>>,
    ) -> Result<Vec<TokenObject>, Error> {
        let (discovered, mut metadata) = self.discover_objects(session)?;
        let mut candidates = Vec::new();
        'discovered: for (info, public_key) in discovered {
            let certificate = if info.object_type == YUBIHSM_OPAQUE
                && info.algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE
            {
                Some(self.read_opaque_with_session(&info, session)?)
            } else {
                None
            };
            let generation = self.object_generation(&info)?;
            let attribute_metadata =
                metadata.remove(&(info.object_type, info.id, info.sequence, info.domains));
            let mut objects = match yubihsm_token_objects_with_generation(
                slot_id,
                info.clone(),
                public_key,
                generation,
                attribute_metadata.as_ref(),
            ) {
                Ok(objects) => objects,
                Err(error) => {
                    log!(
                        2,
                        "YubiHSM public discovery skipped object type {:02x} ID {:04x} on {} because it could not be represented in PKCS11: {:?}",
                        info.object_type,
                        info.id,
                        self.connector.name(),
                        error
                    );
                    continue;
                }
            };
            self.bind_cached_object_value(&info, &mut objects)?;
            for object in &mut objects {
                if object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS {
                    let certificate = certificate.as_deref().ok_or(CKR_DEVICE_ERROR)?;
                    if piv_certificate_attribute(certificate, CKA_SUBJECT as CK_ATTRIBUTE_TYPE)
                        .is_none()
                    {
                        log!(
                            2,
                            "YubiHSM public discovery rejected certificate {:?} with CKA_ID {:02x?} on {} because its X.509 value is invalid",
                            object.label,
                            object.id,
                            self.connector.name()
                        );
                        continue 'discovered;
                    }
                    object.private = false;
                }
            }
            candidates.append(&mut objects);
        }

        let certificate_count = candidates
            .iter()
            .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
            .count();
        let public_key_count = candidates
            .iter()
            .filter(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
            .count();
        let private_key_count = candidates
            .iter()
            .filter(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            .count();
        log!(
            2,
            "YubiHSM public discovery found {} certificates, {} public keys, and {} private key references on {}",
            certificate_count,
            public_key_count,
            private_key_count,
            self.connector.name()
        );
        let objects = candidates
            .into_iter()
            .filter(|object| {
                let retained = !object.private;
                log!(
                    2,
                    "YubiHSM public discovery {} class {:#x} object {:?} with CKA_ID {:02x?} on {} because {}",
                    if retained { "retained" } else { "filtered" },
                    object.class,
                    object.label,
                    object.id,
                    self.connector.name(),
                    if retained {
                        "CKA_PRIVATE is false"
                    } else {
                        "CKA_PRIVATE is true"
                    }
                );
                retained
            })
            .collect::<Vec<_>>();
        log!(
            2,
            "YubiHSM public discovery selected {} public PKCS11 objects on {}",
            objects.len(),
            self.connector.name()
        );
        Ok(objects)
    }

    fn public_discovery_available(&self, slot_id: CK_SLOT_ID) -> bool {
        if self.synchronize_caches().is_err() {
            return false;
        }
        let Some(credential) = self.public_discovery_credential.as_ref() else {
            return false;
        };
        if credential.uses_hsmauth() {
            let provider_available = match parse_yubihsm_login_username(&credential.username) {
                Ok(YubiHsmLoginUsername::HsmAuth(login)) => match self.hsmauth_provider(&login) {
                    Ok(_) => true,
                    Err(error) => {
                        log!(
                                1,
                                "YubiHSM pre-login authentication could not resolve YubiHSM Auth credential {:?}, source {:?}, for authentication key {:04x} on {}: {:?}; public discovery remains retryable",
                                login.label,
                                login.source,
                                login.authkey_id,
                                self.connector.name(),
                                error
                            );
                        false
                    }
                },
                _ => false,
            };
            if !provider_available {
                return false;
            }
        }
        {
            let Ok(mut state) = self.object_cache.try_borrow_mut() else {
                return false;
            };
            if state.available {
                return true;
            }
            if state.attempted {
                return false;
            }
            state.attempted = true;
        }

        log!(
            2,
            "YubiHSM public discovery starting on {} with authentication key {:04x}",
            self.connector.name(),
            credential.authkey_id
        );
        let session = self.authenticate_public_discovery(credential);
        let session = match session {
            Ok((session, _)) => session,
            Err(error) => {
                log!(
                    1,
                    "YubiHSM pre-login authentication failed on {} with authentication key {:04x}: {:?}",
                    self.connector.name(),
                    credential.authkey_id,
                    error
                );
                return false;
            }
        };
        log!(
            2,
            "YubiHSM public discovery authenticated on {}",
            self.connector.name()
        );
        let session = RefCell::new(Some(session));
        let discovery: Result<(Vec<TokenObject>, u16), Error> = (|| {
            let info = self.authentication_key_info(&session, credential.authkey_id)?;
            if !yubihsm_capability(&info.capabilities, 0) {
                return Err(CKR_FUNCTION_REJECTED.into());
            }
            let objects = self.build_public_discovery_objects(slot_id, &session)?;
            Ok((objects, info.domains))
        })();
        let mut state = match self.object_cache.try_borrow_mut() {
            Ok(state) => state,
            Err(_) => {
                let _ = self.close_session_cell(&session, "public discovery");
                return false;
            }
        };
        match discovery {
            Ok((objects, authkey_domains)) => {
                let mut retained = state
                    .objects
                    .drain(..)
                    .map(|object| (object.unique_id.clone(), object))
                    .collect::<HashMap<_, _>>();
                for object in objects {
                    retained.insert(object.unique_id.clone(), object);
                }
                state.objects = retained.into_values().collect();
                state.available = true;
                state.authkey_domains = Some(authkey_domains);
                drop(state);
                let retained_session = session.into_inner();
                if self
                    .session
                    .try_borrow_mut()
                    .map(|mut active| *active = retained_session)
                    .is_err()
                {
                    return false;
                }
                self.session_role
                    .set(Some(YubiHsmSessionRole::PublicDiscovery));
                log!(
                    2,
                    "YubiHSM public discovery completed on {}; retained its session and cached token objects",
                    self.connector.name(),
                );
                true
            }
            Err(error) => {
                let _ = self.close_session_cell(&session, "failed public discovery");
                log!(
                    2,
                    "YubiHSM public object discovery failed on {}: {:?}",
                    self.connector.name(),
                    error
                );
                false
            }
        }
    }

    fn synchronize_caches(&self) -> Result<(), Error> {
        let connection_epoch = self.connector.connection_epoch();
        let changed = {
            let mut state = self.object_cache.try_borrow_mut()?;
            if state.connection_epoch == connection_epoch {
                false
            } else {
                *state = YubiHsmObjectCache {
                    connection_epoch,
                    ..YubiHsmObjectCache::default()
                };
                true
            }
        };
        if changed {
            let user_session_was_active = self.session_role.get() == Some(YubiHsmSessionRole::User);
            self.session.try_borrow_mut()?.take();
            self.session_role
                .set(user_session_was_active.then_some(YubiHsmSessionRole::User));
            log!(
                2,
                "YubiHSM discovery cache reset on {} after connector state changed",
                self.connector.name()
            );
            self.object_metadata.try_borrow_mut()?.clear();
            self.object_generations.try_borrow_mut()?.clear();
            self.attestation_cache.try_borrow_mut()?.clear();
        }
        Ok(())
    }

    fn cached_objects(&self) -> Vec<TokenObject> {
        let Ok(state) = self.object_cache.try_borrow() else {
            return Vec::new();
        };
        let mut objects = state.objects.clone();
        objects.sort_by(|left, right| left.unique_id.cmp(&right.unique_id));
        objects
    }

    fn update_cached_objects(&self, objects: &[TokenObject]) -> Result<(), Error> {
        let mut state = self.object_cache.try_borrow_mut()?;
        let updated_hardware_objects = objects
            .iter()
            .filter_map(|object| match object.material {
                KeyMaterial::YubiHsm {
                    id, object_type, ..
                } => Some((id, object_type & !0x80)),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let mut retained = state
            .objects
            .drain(..)
            .filter(|object| match object.material {
                KeyMaterial::YubiHsm {
                    id, object_type, ..
                } => !updated_hardware_objects.contains(&(id, object_type & !0x80)),
                _ => true,
            })
            .map(|object| (object.unique_id.clone(), object))
            .collect::<HashMap<_, _>>();
        for object in objects {
            if object.token && object.class != CKO_PROFILE as CK_OBJECT_CLASS {
                retained.insert(object.unique_id.clone(), object.clone());
            }
        }
        state.objects = retained.into_values().collect();
        Ok(())
    }

    fn clear_cached_private_objects(&self) -> Result<(), Error> {
        let private_targets = {
            let mut state = self.object_cache.try_borrow_mut()?;
            let mut private_targets = HashSet::new();
            state.objects.retain(|object| {
                if !object.private {
                    return true;
                }
                if let KeyMaterial::YubiHsm {
                    id, object_type, ..
                } = object.material
                {
                    private_targets.insert((object_type & !0x80, id));
                }
                false
            });
            let metadata_ids = private_targets
                .iter()
                .filter_map(|key| state.native_objects.get(key))
                .flat_map(|entry| entry.metadata_sources.iter())
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>();
            state.native_objects.retain(|(object_type, id), entry| {
                if private_targets.contains(&(*object_type, *id)) {
                    if *object_type != YUBIHSM_AUTHENTICATION_KEY {
                        return false;
                    }
                    let sequence = entry.sequence;
                    let authentication_algorithm = entry
                        .info
                        .as_ref()
                        .and_then(Self::authentication_algorithm)
                        .or(entry.inferred_authentication_algorithm);
                    *entry = YubiHsmCachedObjectProperties::new(sequence);
                    entry.inferred_authentication_algorithm = authentication_algorithm;
                    return true;
                }
                *object_type != YUBIHSM_OPAQUE || !metadata_ids.contains(id)
            });
            private_targets
        };
        if private_targets.is_empty() {
            return Ok(());
        }

        self.object_metadata
            .try_borrow_mut()?
            .retain(|key, _| !private_targets.contains(key));

        let mut attestation_cache = self.attestation_cache.try_borrow_mut()?;
        for ((target, _), cache) in attestation_cache.iter() {
            if private_targets.contains(target) {
                *cache.value.try_borrow_mut()? = None;
                cache.attempted.set(false);
            }
        }
        attestation_cache.retain(|(target, _), _| !private_targets.contains(target));
        Ok(())
    }

    fn forget_cached_object(&self, id: u16, object_type: u8) -> Result<(), Error> {
        let key = (object_type & !0x80, id);
        {
            let mut state = self.object_cache.try_borrow_mut()?;
            state.objects.retain(|object| {
                !matches!(
                    object.material,
                    KeyMaterial::YubiHsm {
                        id: candidate_id,
                        object_type: candidate_type,
                        ..
                    } if candidate_id == id
                        && candidate_type & !0x80 == object_type & !0x80
                )
            });
            state.native_objects.remove(&key);
            for entry in state.native_objects.values_mut() {
                entry
                    .metadata_sources
                    .retain(|(source_id, _)| *source_id != id);
            }
        }
        self.object_metadata.try_borrow_mut()?.remove(&key);
        self.object_generations.try_borrow_mut()?.remove(&key);
        self.attestation_cache
            .try_borrow_mut()?
            .retain(|(candidate, _), _| *candidate != key);
        Ok(())
    }

    fn related_metadata_object(&self, id: u16, object_type: u8) -> Result<Vec<(u16, u8)>, Error> {
        Ok(self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&(object_type & !0x80, id))
            .map(|entry| entry.metadata_sources.clone())
            .unwrap_or_default())
    }

    fn metadata_target_by_unique_id(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<(YubiHsmObjectInfo, Option<YubiHsmPkcs11Metadata>, bool), Error> {
        let metadata = self
            .object_metadata
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        for (info, public_key, generation, attributes) in metadata.values() {
            let objects = yubihsm_token_objects_with_generation(
                slot_id,
                info.clone(),
                public_key.clone(),
                *generation,
                attributes.as_ref(),
            )?;
            if let Some((index, _)) = objects
                .iter()
                .enumerate()
                .find(|(_, object)| object.unique_id == unique_id)
            {
                return Ok((info.clone(), attributes.clone(), index != 0));
            }
        }
        Err(CKR_ATTRIBUTE_READ_ONLY.into())
    }

    fn delete_metadata_objects(&self, objects: &[(u16, u8)]) -> Result<(), Error> {
        let mut first_error = None;
        for (id, _) in objects {
            match send_yubihsm_secure_command(
                self.connector.as_ref(),
                self.session.as_ref(),
                &YubiHsmCommand::delete_object(*id, YUBIHSM_OPAQUE),
            ) {
                Ok(_) => {
                    if let Err(error) = self.forget_cached_object(*id, YUBIHSM_OPAQUE) {
                        first_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn replace_pkcs11_metadata(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
        id: Option<&[u8]>,
        label: Option<&str>,
    ) -> Result<(), Error> {
        let (info, current, public) = self.metadata_target_by_unique_id(slot_id, unique_id)?;
        let old_objects = self.related_metadata_object(info.id, info.object_type)?;
        let mut metadata = current.unwrap_or(YubiHsmPkcs11Metadata {
            target_type: info.object_type,
            target_id: info.id,
            target_sequence: info.sequence,
            id: None,
            label: None,
            public_id: None,
            public_label: None,
        });

        if let Some(id) = id {
            let value = (id != info.id.to_be_bytes()).then(|| id.to_vec());
            if public {
                metadata.public_id = value;
            } else {
                metadata.id = value;
            }
        }
        if let Some(label) = label {
            let value = (label != yubihsm_object_label(&info)).then(|| label.to_owned());
            if public {
                metadata.public_label = value;
            } else {
                metadata.label = value;
            }
        }

        if metadata.is_empty() {
            return self.delete_metadata_objects(&old_objects);
        }

        let value = metadata.encode()?;
        let metadata_label = format!(
            "Meta object for 0x{:02x}{:02x}{:04x}",
            info.sequence, info.object_type, info.id
        );
        let capabilities = if yubihsm_capability(&info.capabilities, 0x10) {
            yubihsm_capabilities(&[0x10])
        } else {
            [0; 8]
        };
        let response = send_yubihsm_secure_command(
            self.connector.as_ref(),
            self.session.as_ref(),
            &YubiHsmCommand::put_object(
                YubiHsmCommandCode::PutOpaque,
                &YubiHsmObjectParameters {
                    id: 0,
                    label: &metadata_label,
                    domains: info.domains,
                    capabilities,
                    algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
                },
                &value,
            )?,
        )?;
        let new_id = parse_yubihsm_object_id(&response)?;
        let old_objects = old_objects
            .into_iter()
            .filter(|(id, _)| *id != new_id)
            .collect::<Vec<_>>();
        self.delete_metadata_objects(&old_objects)
    }
}

pub(crate) fn send_yubihsm_secure_command(
    connector: &dyn Connector,
    shared_session: &RefCell<Option<YubiHsmSecureSession>>,
    command: &YubiHsmCommand,
) -> Result<Vec<u8>, Error> {
    let mut session_guard = shared_session.try_borrow_mut()?;
    send_yubihsm_secure_command_with_session(connector, &mut session_guard, command)
}

pub(crate) fn send_yubihsm_secure_command_with_session(
    connector: &dyn Connector,
    shared_session: &mut Option<YubiHsmSecureSession>,
    command: &YubiHsmCommand,
) -> Result<Vec<u8>, Error> {
    let session = shared_session
        .as_mut()
        .ok_or_else(|| Error::from(CKR_USER_NOT_LOGGED_IN))?;
    YubiHsmSecureSession::validate_command(connector, command)?;
    let result = session.send_command(connector, command);
    if !session.is_valid() {
        *shared_session = None;
    }
    result
}

pub(crate) fn yubihsm_key_type(algorithm: u8) -> CK_KEY_TYPE {
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

pub(crate) fn yubihsm_algorithm_supported(algorithm: u8) -> bool {
    yubihsm_key_type(algorithm) < CKK_VENDOR_DEFINED as CK_KEY_TYPE
}

pub(crate) fn yubihsm_key_generation_mechanism(algorithm: u8) -> Option<CK_MECHANISM_TYPE> {
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

pub(crate) fn yubihsm_remote_material(
    info: &YubiHsmObjectInfo,
    public_key: Vec<u8>,
) -> KeyMaterial {
    yubihsm_remote_material_with_type(info, info.object_type, public_key)
}

pub(crate) fn yubihsm_remote_material_with_type(
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

pub(crate) fn yubihsm_object_label(info: &YubiHsmObjectInfo) -> String {
    if !info.label.is_empty() {
        return info.label.clone();
    }
    let kind = match (info.object_type, info.algorithm) {
        (YUBIHSM_OPAQUE, YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE) => "certificate",
        (YUBIHSM_OPAQUE, _) => "opaque object",
        (YUBIHSM_AUTHENTICATION_KEY, _) => "authentication key",
        (YUBIHSM_ASYMMETRIC_KEY, _) => "asymmetric key",
        (YUBIHSM_WRAP_KEY, _) => "wrap key",
        (YUBIHSM_HMAC_KEY, _) => "HMAC key",
        (YUBIHSM_TEMPLATE, _) => "template",
        (YUBIHSM_OTP_AEAD_KEY, _) => "OTP AEAD key",
        (YUBIHSM_SYMMETRIC_KEY, _) => "symmetric key",
        (YUBIHSM_PUBLIC_WRAP_KEY, _) => "public wrap key",
        _ => "object",
    };
    format!("YubiHSM {kind} {}", info.id)
}

pub(crate) fn yubihsm_device_public_key_object(
    slot_id: CK_SLOT_ID,
    public_key: &[u8],
) -> Result<TokenObject, Error> {
    let public_key_info = crate::yubihsm::trust::device_spki(public_key)?;
    Ok(TokenObject {
        slot_id: Some(slot_id),
        unique_id: "yubihsm-device-public".to_owned(),
        class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: "YubiHSM device public key".to_owned(),
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
        local: true,
        key_gen_mechanism: None,
        owner_session: None,
        material: KeyMaterial::YubiHsmDevicePublic {
            public_key: public_key.to_vec(),
            public_key_info,
        },
    })
}

pub(crate) fn yubihsm_object_has_public_key(info: &YubiHsmObjectInfo) -> bool {
    matches!(
        info.object_type,
        YUBIHSM_ASYMMETRIC_KEY | YUBIHSM_PUBLIC_WRAP_KEY
    ) || (info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(info.algorithm))
}

pub(crate) fn yubihsm_metadata_label_target(label: &str) -> Option<(u8, u8, u16)> {
    let encoded = label.strip_prefix("Meta object for 0x")?;
    if encoded.len() != 8 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((
        u8::from_str_radix(&encoded[..2], 16).ok()?,
        u8::from_str_radix(&encoded[2..4], 16).ok()?,
        u16::from_str_radix(&encoded[4..], 16).ok()?,
    ))
}

pub(crate) fn parse_yubihsm_pkcs11_metadata(
    info: &YubiHsmObjectInfo,
    value: &[u8],
) -> Result<YubiHsmPkcs11Metadata, Error> {
    if info.object_type != YUBIHSM_OPAQUE || info.algorithm != YUBIHSM_ALGO_OPAQUE_DATA {
        return Err(CKR_DATA_INVALID.into());
    }
    let label_target = yubihsm_metadata_label_target(&info.label).ok_or(CKR_DATA_INVALID)?;
    if value.len() < 8 || &value[..4] != b"MDB1" {
        return Err(CKR_DATA_INVALID.into());
    }
    let target_type = value[4];
    let target_id = u16::from_be_bytes([value[5], value[6]]);
    let target_sequence = value[7];
    if label_target != (target_sequence, target_type, target_id) {
        return Err(CKR_DATA_INVALID.into());
    }

    let mut metadata = YubiHsmPkcs11Metadata {
        target_type,
        target_id,
        target_sequence,
        id: None,
        label: None,
        public_id: None,
        public_label: None,
    };
    let mut offset = 8;
    while offset < value.len() {
        if value.len() - offset < 3 {
            return Err(CKR_DATA_INVALID.into());
        }
        let tag = value[offset];
        let length = u16::from_be_bytes([value[offset + 1], value[offset + 2]]) as usize;
        offset += 3;
        let end = offset.checked_add(length).ok_or(CKR_DATA_INVALID)?;
        let item = value.get(offset..end).ok_or(CKR_DATA_INVALID)?;
        offset = end;
        let destination = match tag {
            1 => &mut metadata.id,
            2 => {
                if metadata.label.is_some() {
                    return Err(CKR_DATA_INVALID.into());
                }
                metadata.label = Some(
                    std::str::from_utf8(item)
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_owned(),
                );
                continue;
            }
            3 => &mut metadata.public_id,
            4 => {
                if metadata.public_label.is_some() {
                    return Err(CKR_DATA_INVALID.into());
                }
                metadata.public_label = Some(
                    std::str::from_utf8(item)
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_owned(),
                );
                continue;
            }
            _ => return Err(CKR_DATA_INVALID.into()),
        };
        if destination.replace(item.to_vec()).is_some() {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    Ok(metadata)
}

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn yubihsm_token_objects(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
) -> Result<Vec<TokenObject>, Error> {
    let generation = info.sequence as u64;
    yubihsm_token_objects_with_generation(slot_id, info, public_key, generation, None)
}

pub(crate) fn yubihsm_token_objects_with_generation(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
    generation: u64,
    metadata: Option<&YubiHsmPkcs11Metadata>,
) -> Result<Vec<TokenObject>, Error> {
    let key_type = yubihsm_key_type(info.algorithm);
    let hardware_label = yubihsm_object_label(&info);
    let label = metadata
        .and_then(|metadata| metadata.label.clone())
        .unwrap_or_else(|| hardware_label.clone());
    let id = metadata
        .and_then(|metadata| metadata.id.clone())
        .unwrap_or_else(|| info.id.to_be_bytes().to_vec());
    let unique = format!(
        "yubihsm-{:02x}-{:04x}-{:02x}-{generation}",
        info.object_type, info.id, info.sequence
    );
    let generated = info.origin & 0x01 != 0;
    let algorithm_supported = yubihsm_algorithm_supported(info.algorithm);
    let operational_algorithm_supported =
        algorithm_supported || is_yubihsm_ccm_wrap(info.algorithm);
    let rsa_wrap_key = info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(info.algorithm);
    let attributes =
        yubihsm_capabilities_to_attributes(info.object_type, info.algorithm, &info.capabilities);
    let sign = operational_algorithm_supported && attributes.sign;
    let verify = operational_algorithm_supported && attributes.verify;
    let decrypt = operational_algorithm_supported && attributes.decrypt;
    let encrypt = operational_algorithm_supported && attributes.encrypt;
    let derive = operational_algorithm_supported && attributes.derive;
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
        class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS || class == CKO_SECRET_KEY as CK_OBJECT_CLASS;
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
        verify,
        derive,
        sensitive: private,
        extractable: attributes.extractable,
        always_sensitive: private,
        never_extractable: !attributes.extractable,
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
        let public_object_type = if rsa_wrap_key {
            YUBIHSM_WRAP_KEY_PUBLIC
        } else {
            YUBIHSM_PUBLIC_KEY
        };
        let public_attributes = yubihsm_capabilities_to_attributes(
            public_object_type,
            info.algorithm,
            &info.capabilities,
        );
        let public_material = if rsa_wrap_key {
            yubihsm_remote_material_with_type(&info, public_object_type, public_key.key.clone())
        } else {
            yubihsm_remote_material_with_type(&info, public_object_type, public_key.key)
        };
        objects.push(TokenObject {
            slot_id: Some(slot_id),
            unique_id: format!("{unique}-public"),
            class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            key_type,
            label: metadata
                .and_then(|metadata| {
                    metadata
                        .public_label
                        .clone()
                        .or_else(|| metadata.label.clone())
                })
                .unwrap_or(hardware_label),
            id: metadata
                .and_then(|metadata| metadata.public_id.clone().or_else(|| metadata.id.clone()))
                .unwrap_or_else(|| info.id.to_be_bytes().to_vec()),
            token: true,
            private: false,
            encrypt: algorithm_supported && public_attributes.encrypt,
            decrypt: false,
            sign: false,
            verify: algorithm_supported && public_attributes.verify,
            derive: false,
            sensitive: false,
            extractable: public_attributes.extractable,
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
    fn model(&self) -> &str {
        "YubiHSM"
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
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn yubihsm_provisioning_connector(&self) -> Option<Rc<dyn Connector>> {
        Some(self.connector.clone())
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        let (username, password) = split_yubihsm_login(pin)?;
        if let Some(password) = password {
            log!(
                2,
                "YubiHSM combined login parsed {} selector bytes and {} password bytes",
                username.len(),
                password.len()
            );
            return self.login_user(username, password);
        }
        let YubiHsmLoginUsername::HsmAuth(login) = parse_yubihsm_login_username(username)? else {
            return Err(CKR_PIN_INCORRECT.into());
        };
        let provider = self.hsmauth_provider(&login)?;
        let title = format!("{} accessing {}", provider.slot_label(), self.label());
        let description = format!("Enter the authentication password for {:?}.", login.label);
        let password = pinentry::request(pinentry::Prompt {
            title: &title,
            description: &description,
            label: "Authentication password:",
        })?;
        self.login_user(username, password.as_slice())
    }
    fn login_user(&mut self, username: &[u8], password: &[u8]) -> Result<(), Error> {
        let _ = self.close_active_session("pre-login");
        self.clear_cached_private_objects()?;
        let (session, authkey_id) = self.authenticate_login(username, password)?;
        let session = RefCell::new(Some(session));
        let discovery_domains = {
            let state = self
                .object_cache
                .try_borrow()
                .map_err(|_| Error::from(CKR_CANT_LOCK))?;
            state.available.then_some(state.authkey_domains).flatten()
        };
        if let Some(discovery_domains) = discovery_domains {
            let user_info = self.authentication_key_info(&session, authkey_id);
            match user_info {
                Ok(info) if info.domains == discovery_domains => {}
                Ok(_) => {
                    log!(
                        2,
                        "YubiHSM user Authentication Key domains do not match the public discovery Authentication Key domains on {}",
                        self.connector.name()
                    );
                    let _ = self.close_session_cell(&session, "rejected user");
                    return Err(CKR_FUNCTION_REJECTED.into());
                }
                Err(error) => {
                    let _ = self.close_session_cell(&session, "rejected user");
                    return Err(error);
                }
            }
        }
        *self.session.try_borrow_mut()? = Some(session.into_inner().ok_or(CKR_DEVICE_ERROR)?);
        self.session_role.set(Some(YubiHsmSessionRole::User));
        for cache in self
            .attestation_cache
            .try_borrow()
            .map_err(|_| CKR_CANT_LOCK)?
            .values()
        {
            if cache
                .value
                .try_borrow()
                .map_err(|_| CKR_CANT_LOCK)?
                .is_none()
            {
                cache.attempted.set(false);
            }
        }
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        if !self.has_session_role(YubiHsmSessionRole::User) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let close_result = self.close_active_session("user");
        let clear_result = self.clear_cached_private_objects();
        close_result.and(clear_result)
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let _ = self.close_active_session("slot initialization");
        let _ = self.device_public_key.take();
        if let Ok(mut state) = self.object_cache.try_borrow_mut() {
            *state = YubiHsmObjectCache {
                connection_epoch: self.connector.connection_epoch(),
                ..YubiHsmObjectCache::default()
            };
        }
        self.object_metadata.try_borrow_mut()?.clear();
        self.object_generations.try_borrow_mut()?.clear();
        self.attestation_cache.try_borrow_mut()?.clear();
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
        str_pad(
            &format!("{} #{}", self.model(), device_info.serial),
            &mut info.label,
        );
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
        let _ = self.close_active_session("slot cleanup");
        if let Err(error) = self.clear_cached_private_objects() {
            log!(
                2,
                "YubiHSM private object cache cleanup failed on {}: {:?}",
                self.connector.name(),
                error
            );
        }
    }
    fn login_is_active(&self) -> bool {
        let active = self.has_session_role(YubiHsmSessionRole::User);
        if !active && self.session_role.get() == Some(YubiHsmSessionRole::User) {
            self.session_role.set(None);
        }
        active
    }
    fn backend_session_is_active(&self) -> bool {
        self.session_role
            .get()
            .is_some_and(|role| self.has_session_role(role))
    }
    fn ensure_backend_read_session(&self) -> Result<(), Error> {
        self.ensure_read_session()
    }
    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if !self.has_session_role(YubiHsmSessionRole::User) {
            return Ok(self.cached_objects());
        }
        let (discovered, mut pkcs11_metadata) = self.discover_objects(self.session.as_ref())?;

        let discovered_keys = discovered
            .iter()
            .map(|(info, _)| (info.object_type, info.id))
            .collect::<HashSet<_>>();
        let mut generations = self
            .object_generations
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        generations.retain(|key, _| discovered_keys.contains(key));

        let mut objects = match self.device_public_key() {
            Ok(public_key) => vec![yubihsm_device_public_key_object(slot_id, public_key)?],
            Err(error) => {
                log!(2, "YubiHSM GET DEVICE PUBLIC KEY: {:?}", error);
                Vec::new()
            }
        };
        let mut metadata = HashMap::new();
        for (info, public_key) in discovered {
            let key = (info.object_type, info.id);
            let generation = match generations.get(&key) {
                Some((sequence, generation)) if *sequence == info.sequence => *generation,
                _ => {
                    let generation = self.next_object_generation.get();
                    self.next_object_generation
                        .set(generation.checked_add(1).ok_or(CKR_DEVICE_MEMORY)?);
                    generations.insert(key, (info.sequence, generation));
                    generation
                }
            };
            let attribute_metadata =
                pkcs11_metadata.remove(&(info.object_type, info.id, info.sequence, info.domains));
            metadata.insert(
                key,
                (
                    info.clone(),
                    public_key.clone(),
                    generation,
                    attribute_metadata.clone(),
                ),
            );
            let mut discovered_objects = yubihsm_token_objects_with_generation(
                slot_id,
                info.clone(),
                public_key,
                generation,
                attribute_metadata.as_ref(),
            )?;
            self.bind_cached_object_value(&info, &mut discovered_objects)?;
            objects.extend(discovered_objects);
        }
        drop(generations);
        let current_generations = metadata
            .iter()
            .map(|(key, (_, _, generation, _))| ((*key, *generation), ()))
            .collect::<HashMap<_, _>>();
        self.attestation_cache
            .try_borrow_mut()?
            .retain(|key, _| current_generations.contains_key(key));
        *self.object_metadata.try_borrow_mut()? = metadata;
        self.update_cached_objects(&objects)?;
        Ok(self.cached_objects())
    }
    fn backend_token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        self.synchronize_caches()?;
        if let Some(object) = self
            .cached_objects()
            .into_iter()
            .find(|object| object.unique_id == unique_id)
        {
            return Ok(Some(object));
        }
        if let Some(public_key) = self.device_public_key.get() {
            let object = yubihsm_device_public_key_object(slot_id, public_key)?;
            if object.unique_id == unique_id {
                return Ok(Some(object));
            }
        }
        let metadata = self
            .object_metadata
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for (info, public_key, generation, attribute_metadata) in metadata {
            let mut objects = yubihsm_token_objects_with_generation(
                slot_id,
                info.clone(),
                public_key,
                generation,
                attribute_metadata.as_ref(),
            )?;
            self.bind_cached_object_value(&info, &mut objects)?;
            if let Some(object) = objects
                .into_iter()
                .find(|object| object.unique_id == unique_id)
            {
                return Ok(Some(object));
            }
        }
        Ok(None)
    }
    fn session_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let metadata = self
            .object_metadata
            .try_borrow()
            .map_err(|_| CKR_CANT_LOCK)?;
        let mut cache = self.attestation_cache.try_borrow_mut()?;
        let mut objects = Vec::new();
        for (key, (info, public_key, generation, attribute_metadata)) in metadata.iter() {
            if info.object_type != YUBIHSM_ASYMMETRIC_KEY || info.origin & 0x01 == 0 {
                continue;
            }
            let Some(public_key) = public_key else {
                continue;
            };
            let cache = cache
                .entry((*key, *generation))
                .or_insert_with(YubiHsmAttestationCache::new)
                .clone();
            let id = attribute_metadata
                .as_ref()
                .and_then(|metadata| metadata.id.clone())
                .unwrap_or_else(|| info.id.to_be_bytes().to_vec());
            let label = attribute_metadata
                .as_ref()
                .and_then(|metadata| metadata.label.clone())
                .unwrap_or_else(|| yubihsm_object_label(info));
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!(
                    "yubihsm-{:02x}-{:04x}-{:02x}-{generation}-attestation",
                    info.object_type, info.id, info.sequence
                ),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type: yubihsm_key_type(info.algorithm),
                label: format!("{label} attestation certificate"),
                id,
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
                material: KeyMaterial::YubiHsmAttestation {
                    connector: self.connector.clone(),
                    session: self.session.clone(),
                    id: info.id,
                    algorithm: public_key.algorithm,
                    value: cache.value,
                    attempted: cache.attempted,
                },
            });
        }
        Ok(objects)
    }
    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        yubihsm_mechanisms(&self.algorithms)
    }
    fn supports_extended_provider_profile(&self) -> bool {
        true
    }
    fn supports_public_certificates_token_profile(&self, slot_id: CK_SLOT_ID) -> bool {
        self.public_discovery_available(slot_id)
    }
    fn is_yubihsm(&self) -> bool {
        true
    }
    fn yubihsm_read_opaque(&self, id: u16) -> Result<Vec<u8>, Error> {
        self.yubihsm_read_object(id, YUBIHSM_OPAQUE)
    }
    fn yubihsm_read_object(&self, id: u16, object_type: u8) -> Result<Vec<u8>, Error> {
        if self.has_session_role(YubiHsmSessionRole::User) {
            return self.read_object_value_by_id(self.session.as_ref(), id, object_type);
        }
        self.read_object_value_with_public_discovery(id, object_type)
    }
    fn yubihsm_forget_object(&self, id: u16, object_type: u8) -> Result<(), Error> {
        self.forget_cached_object(id, object_type)
    }
    fn yubihsm_related_metadata_object(
        &self,
        id: u16,
        object_type: u8,
    ) -> Result<Vec<(u16, u8)>, Error> {
        self.related_metadata_object(id, object_type)
    }
    fn yubihsm_set_attributes(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
        id: Option<&[u8]>,
        label: Option<&str>,
    ) -> Result<(), Error> {
        self.replace_pkcs11_metadata(slot_id, unique_id, id, label)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HsmAuthLogin<'a> {
    pub(crate) label: &'a str,
    pub(crate) source: Option<&'a str>,
    pub(crate) authkey_id: u16,
}

pub(crate) enum YubiHsmLoginUsername<'a> {
    Direct(u16),
    HsmAuth(HsmAuthLogin<'a>),
}

pub(crate) fn parse_yubihsm_authkey_id(value: &[u8]) -> Result<u16, Error> {
    if value.len() != 4 {
        return Err(CKR_PIN_INCORRECT.into());
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| u16::from_str_radix(value, 16).ok())
        .ok_or_else(|| CKR_PIN_INCORRECT.into())
}

pub(crate) fn parse_hsmauth_username(username: &[u8]) -> Result<HsmAuthLogin<'_>, Error> {
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

pub(crate) fn parse_yubihsm_login_username(
    username: &[u8],
) -> Result<YubiHsmLoginUsername<'_>, Error> {
    match username.first() {
        Some(b':') => parse_hsmauth_username(username).map(YubiHsmLoginUsername::HsmAuth),
        _ => parse_yubihsm_authkey_id(username).map(YubiHsmLoginUsername::Direct),
    }
}

pub(crate) fn split_yubihsm_login(pin: &[u8]) -> Result<(&[u8], Option<&[u8]>), Error> {
    let username_length = match pin.first() {
        Some(b':') => match pin
            .get(5..)
            .and_then(|value| value.iter().position(|byte| *byte == b':'))
        {
            Some(position) => position + 5,
            None => return Ok((pin, None)),
        },
        _ => 4,
    };
    if pin.len() < username_length {
        return Err(CKR_PIN_INCORRECT.into());
    }
    let password_offset = username_length + usize::from(pin.first() == Some(&b':'));
    let password = pin.get(password_offset..).ok_or(CKR_PIN_INCORRECT)?;
    Ok((&pin[..username_length], Some(password)))
}

pub(crate) fn parse_hsmauth_selector_part(
    value: &[u8],
    maximum_length: usize,
) -> Result<&str, Error> {
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

pub(crate) struct YubiHsmSession {
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
    fn yubihsm_device_public_key(&self) -> Result<Vec<u8>, Error> {
        crate::get_yubihsm_device_public_key(self.connector.as_ref()).map(Vec::from)
    }
}

impl YubiHsmSession {
    fn send_secure_cmd(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        send_yubihsm_secure_command(self.connector.as_ref(), self.session.as_ref(), command)
    }
}
