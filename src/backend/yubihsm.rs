use crate::key_metadata::{
    cryptoki_ulong_to_u64, BackedKeyMetadata, KeyAttributeValue, KeyAttributes, KeyBacking,
    KeyMetadataError,
};
use crate::storage::{ContentReference, StorageError, StorageProvider};
use crate::*;
use minicbor::{Decoder, Encoder};

const YUBIHSM_BACKING_PROVIDER: &str = "pkcs11rs.yubihsm";
const YUBIHSM_BACKING_SCHEMA: &str = "pkcs11rs.yubihsm.object";
const YUBIHSM_BACKING_SCHEMA_VERSION: u64 = 1;
const YUBIHSM_LEGACY_METADATA_LABEL_PREFIX: &str = "Meta object for 0x";
const YUBIHSM_CANONICAL_METADATA_LABEL_PREFIX: &str = "pkcs11rs metadata 0x";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YubiHsmMetadataPhysicalFormat {
    LegacyMdb1,
    CanonicalCbor,
}

#[derive(Clone, Debug)]
pub(crate) struct HsmAuthProvider {
    pub(crate) connector: HsmAuthProviderConnector,
    pub(crate) credential: HsmAuthCredential,
    pub(crate) version: (u8, u8, u8),
    pub(crate) trust_prefix: Option<std::ffi::OsString>,
    pub(crate) source: String,
}

#[derive(Clone)]
pub(crate) enum HsmAuthProviderConnector {
    Shared(SharedConnector),
    #[cfg(test)]
    Local(Rc<dyn Connector>),
}

impl std::fmt::Debug for HsmAuthProviderConnector {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().as_debug().fmt(fmt)
    }
}

impl AsRef<dyn Connector> for HsmAuthProviderConnector {
    fn as_ref(&self) -> &(dyn Connector + 'static) {
        match self {
            Self::Shared(connector) => connector.as_ref(),
            #[cfg(test)]
            Self::Local(connector) => connector.as_ref(),
        }
    }
}

impl From<SharedConnector> for HsmAuthProviderConnector {
    fn from(connector: SharedConnector) -> Self {
        Self::Shared(connector)
    }
}

#[cfg(test)]
impl From<Rc<dyn Connector>> for HsmAuthProviderConnector {
    fn from(connector: Rc<dyn Connector>) -> Self {
        Self::Local(connector)
    }
}

#[cfg(test)]
impl<T: Connector + 'static> From<Rc<T>> for HsmAuthProviderConnector {
    fn from(connector: Rc<T>) -> Self {
        Self::Local(connector)
    }
}

// Test-only providers may use single-threaded protocol peers. Production
// providers contain only SharedConnector and derive Send without assistance.
#[cfg(test)]
unsafe impl Send for HsmAuthProvider {}

#[derive(Debug, Default)]
pub(crate) struct HsmAuthProviderRegistry {
    providers: Mutex<Vec<HsmAuthProvider>>,
}

impl HsmAuthProviderRegistry {
    #[cfg(test)]
    pub(crate) fn new(providers: Vec<HsmAuthProvider>) -> Self {
        Self {
            providers: Mutex::new(providers),
        }
    }

    pub(crate) fn extend(
        &self,
        providers: impl IntoIterator<Item = HsmAuthProvider>,
    ) -> Result<(), Error> {
        self.providers
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .extend(providers);
        Ok(())
    }

    fn with_provider<T>(
        &self,
        login: &HsmAuthLogin<'_>,
        operation: impl FnOnce(&HsmAuthProvider) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let providers = self
            .providers
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
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
        let provider = match matches.next() {
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
        operation(provider)
    }
}

impl HsmAuthProvider {
    fn source_identifier(&self) -> String {
        if self.source.is_empty() || self.source == "0" {
            self.connector.as_ref().name()
        } else {
            self.source.clone()
        }
    }

    fn slot_label(&self) -> String {
        format!("HSM Auth #{}", self.source_identifier())
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
        let physical_device = self.connector.as_ref().device_context();
        let _device_operation = physical_device
            .as_ref()
            .map(|device| device.lock_operation(crate::device::DeviceOperationKind::Ccid))
            .transpose()?;
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
    pub(crate) session: Rc<RefCell<YubiHsmSessionState>>,
    pub(crate) public_discovery_config: Option<Arc<YubiHsmPublicDiscoveryConfig>>,
    pub(crate) recreate_sessions: bool,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
    pub(crate) object_cache: RefCell<YubiHsmObjectCache>,
    pub(crate) version: (u8, u8, u8),
    pub(crate) hardware_version: Option<(u8, u8)>,
    pub(crate) algorithms: Vec<u8>,
    pub(crate) model: String,
    pub(crate) serial: String,
    pub(crate) trust_prefix: Option<std::ffi::OsString>,
    pub(crate) hsmauth_providers: Arc<HsmAuthProviderRegistry>,
    pub(crate) object_metadata: RefCell<HashMap<YubiHsmObjectKey, YubiHsmObjectMetadata>>,
    pub(crate) object_generations: RefCell<HashMap<YubiHsmObjectKey, (u8, u64)>>,
    pub(crate) attestation_cache:
        RefCell<HashMap<(YubiHsmObjectKey, u64), YubiHsmAttestationCache>>,
    metadata_storage_writes: RefCell<HashMap<ContentReference, u16>>,
    pub(crate) next_object_generation: Cell<u64>,
    pub(crate) device_public_key: OnceLock<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum YubiHsmSessionRole {
    PublicDiscovery,
    User,
}

#[derive(Debug, Default)]
pub(crate) enum YubiHsmSessionState {
    #[default]
    LoggedOut,
    InvalidatedUser,
    Active {
        session: YubiHsmSecureSession,
        role: YubiHsmSessionRole,
        reauthentication: Option<Box<YubiHsmSessionReauthentication>>,
    },
}

pub(crate) enum YubiHsmSessionReauthentication {
    Direct {
        authkey_id: u16,
        material: YubiHsmDirectAuthenticationMaterial,
    },
    HsmAuth {
        authkey_id: u16,
        provider: HsmAuthProvider,
        password: Zeroizing<Vec<u8>>,
    },
}

impl std::fmt::Debug for YubiHsmSessionReauthentication {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct {
                authkey_id,
                material,
            } => fmt
                .debug_struct("Direct")
                .field("authkey_id", &format_args!("{authkey_id:04x}"))
                .field("material", material)
                .finish(),
            Self::HsmAuth {
                authkey_id,
                provider,
                ..
            } => fmt
                .debug_struct("HsmAuth")
                .field("authkey_id", &format_args!("{authkey_id:04x}"))
                .field("credential", &provider.credential.label)
                .field("source", &provider.source_identifier())
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

impl YubiHsmSessionReauthentication {
    fn authenticate(&self, connector: &dyn Connector) -> Result<YubiHsmSecureSession, Error> {
        match self {
            Self::Direct {
                authkey_id,
                material,
            } => material.authenticate(connector, *authkey_id),
            Self::HsmAuth {
                authkey_id,
                provider,
                password,
            } => provider.authenticate(connector, *authkey_id, password),
        }
    }
}

impl YubiHsmSessionState {
    pub(crate) fn role(&self) -> Option<YubiHsmSessionRole> {
        match self {
            Self::Active { role, .. } => Some(*role),
            Self::LoggedOut | Self::InvalidatedUser => None,
        }
    }

    fn is_active_as(&self, expected: YubiHsmSessionRole) -> bool {
        self.role() == Some(expected)
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

pub(crate) struct YubiHsmPublicDiscoveryConfig {
    pub(crate) authkey_id: u16,
    pub(crate) hsmauth_credential: Option<HsmAuthCredentialSelector>,
    pub(crate) configured_password: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HsmAuthCredentialSelector {
    pub(crate) label: String,
    pub(crate) source: Option<String>,
}

impl std::fmt::Debug for YubiHsmPublicDiscoveryConfig {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("YubiHsmPublicDiscoveryConfig")
            .field("authkey_id", &format_args!("{:04x}", self.authkey_id))
            .field("hsmauth_credential", &self.hsmauth_credential)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl YubiHsmPublicDiscoveryConfig {
    fn login(&self) -> YubiHsmLoginUsername<'_> {
        match self.hsmauth_credential.as_ref() {
            Some(credential) => YubiHsmLoginUsername::HsmAuth(HsmAuthLogin {
                label: &credential.label,
                source: credential.source.as_deref(),
                authkey_id: self.authkey_id,
            }),
            None => YubiHsmLoginUsername::Direct(self.authkey_id),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct YubiHsmObjectCache {
    pub(crate) connection_epoch: u64,
    pub(crate) discovery: YubiHsmDiscoveryCache,
    pub(crate) native_objects: HashMap<YubiHsmObjectKey, YubiHsmCachedObjectProperties>,
    pub(crate) objects: Vec<TokenObject>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum YubiHsmDiscoveryCache {
    #[default]
    Unattempted,
    Failed,
    Available {
        authkey_domains: u16,
    },
}

impl YubiHsmDiscoveryCache {
    fn authkey_domains(self) -> Option<u16> {
        match self {
            Self::Available { authkey_domains } => Some(authkey_domains),
            Self::Unattempted | Self::Failed => None,
        }
    }
}

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn configured_yubihsm_public_discovery_credential(
    credential: Option<std::ffi::OsString>,
) -> Result<Option<Arc<YubiHsmPublicDiscoveryConfig>>, Error> {
    #[cfg(test)]
    let pinentry = match crate::lock_context_read() {
        Ok(module) => module.as_ref().map(|context| context.pinentry.clone()),
        Err(_) => None,
    };
    #[cfg(test)]
    let pinentry = match pinentry {
        Some(pinentry) => pinentry,
        None => Arc::new(pinentry::Pinentry::unconfigured()),
    };
    #[cfg(not(test))]
    let pinentry = Arc::new(pinentry::Pinentry::unconfigured());
    configured_yubihsm_public_discovery_credential_with_pinentry(credential, pinentry.as_ref())
}

pub(crate) fn configured_yubihsm_public_discovery_credential_with_pinentry(
    credential: Option<std::ffi::OsString>,
    pinentry: &pinentry::Pinentry,
) -> Result<Option<Arc<YubiHsmPublicDiscoveryConfig>>, Error> {
    let Some(credential) = credential else {
        return Ok(None);
    };
    let credential = credential.into_string().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let (username, password) =
        split_yubihsm_login(credential.as_bytes()).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let login = parse_yubihsm_login_username(username).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let (authkey_id, hsmauth_credential) = match &login {
        YubiHsmLoginUsername::Direct(authkey_id) => {
            if password
                .is_some_and(|password| !password.is_empty() && !(8..=64).contains(&password.len()))
            {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            (*authkey_id, None)
        }
        YubiHsmLoginUsername::HsmAuth(login) => {
            if password.is_some_and(|password| password.len() > 16) {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            (
                login.authkey_id,
                Some(HsmAuthCredentialSelector {
                    label: login.label.to_owned(),
                    source: login.source.map(str::to_owned),
                }),
            )
        }
    };
    let password = match login {
        YubiHsmLoginUsername::Direct(_) => password.filter(|password| !password.is_empty()),
        YubiHsmLoginUsername::HsmAuth(_) => password,
    };
    if password.is_none() && !pinentry.is_configured() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(Some(Arc::new(YubiHsmPublicDiscoveryConfig {
        authkey_id,
        hsmauth_credential,
        configured_password: password.map(|password| Zeroizing::new(password.to_vec())),
    })))
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct YubiHsmObjectKey {
    pub(crate) object_type: u8,
    pub(crate) id: u16,
}

impl YubiHsmObjectKey {
    pub(crate) fn new(object_type: u8, id: u16) -> Self {
        Self { object_type, id }
    }

    fn from_info(info: &YubiHsmObjectInfo) -> Self {
        Self::new(info.object_type, info.id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct YubiHsmMetadataTarget {
    pub(crate) object: YubiHsmObjectKey,
    pub(crate) sequence: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct YubiHsmMetadataScope {
    pub(crate) target: YubiHsmMetadataTarget,
    pub(crate) domains: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct YubiHsmObjectMetadata {
    pub(crate) info: YubiHsmObjectInfo,
    pub(crate) public_key: Option<YubiHsmPublicKey>,
    pub(crate) generation: u64,
    pub(crate) attributes: Option<YubiHsmPkcs11Metadata>,
}

#[derive(Clone, Debug)]
pub(crate) struct YubiHsmDiscoveredObject {
    pub(crate) info: YubiHsmObjectInfo,
    pub(crate) public_key: Option<YubiHsmPublicKey>,
}

pub(crate) struct YubiHsmDiscoveredObjects {
    pub(crate) objects: Vec<YubiHsmDiscoveredObject>,
    pub(crate) metadata: HashMap<YubiHsmMetadataScope, YubiHsmPkcs11Metadata>,
}

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
    pub(crate) cache: SharedLazyBytes,
}

impl YubiHsmAttestationCache {
    fn new() -> Self {
        Self {
            cache: Rc::new(RefCell::new(LazyCache::Unattempted)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct YubiHsmPkcs11Metadata {
    pub(crate) target_type: u8,
    pub(crate) target_id: u16,
    pub(crate) target_sequence: u8,
    pub(crate) primary_class: Option<CK_OBJECT_CLASS>,
    pub(crate) id: Option<Vec<u8>>,
    pub(crate) label: Option<String>,
    pub(crate) public: bool,
    pub(crate) public_id: Option<Vec<u8>>,
    pub(crate) public_label: Option<String>,
    pub(crate) public_attributes: KeyAttributes,
}

impl YubiHsmPkcs11Metadata {
    fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.label.is_none()
            && !self.public
            && self.public_id.is_none()
            && self.public_label.is_none()
            && self.public_attributes.is_empty()
    }

    fn persisted_public_key_info(&self) -> Option<&[u8]> {
        if !self.public {
            return None;
        }
        match self.public_attributes.get(u64::from(CKA_PUBLIC_KEY_INFO)) {
            Some(KeyAttributeValue::Bytes(value)) => Some(value),
            _ => None,
        }
    }

    fn encode(&self, target: &YubiHsmObjectInfo) -> Result<Vec<u8>, Error> {
        self.to_backed_key(target, false)?
            .to_cbor()
            .map_err(key_metadata_error)
    }

    fn to_backed_key(
        &self,
        target: &YubiHsmObjectInfo,
        legacy_public_default: bool,
    ) -> Result<BackedKeyMetadata, Error> {
        if self.target_type != target.object_type
            || self.target_id != target.id
            || self.target_sequence != target.sequence
        {
            return Err(CKR_DATA_INVALID.into());
        }
        let primary_class = cryptoki_ulong_to_u64(yubihsm_object_class(target));
        if self
            .primary_class
            .is_some_and(|class| cryptoki_ulong_to_u64(class) != primary_class)
        {
            return Err(CKR_DATA_INVALID.into());
        }
        if !is_key_class(primary_class) {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID.into());
        }
        let backing = KeyBacking::new(
            YUBIHSM_BACKING_PROVIDER,
            encode_yubihsm_key_backing(target, primary_class)?,
        )
        .map_err(key_metadata_error)?;
        let mut record = BackedKeyMetadata::new(backing);
        let mut primary = KeyAttributes::new();
        insert_sparse_identity(&mut primary, self.id.as_deref(), self.label.as_deref())?;
        record
            .insert_aspect(primary_class, primary)
            .map_err(key_metadata_error)?;

        let public = self.public
            || legacy_public_default
                && primary_class != u64::from(CKO_PUBLIC_KEY)
                && yubihsm_object_has_public_key(target);
        if public {
            if primary_class == u64::from(CKO_PUBLIC_KEY) || !yubihsm_object_has_public_key(target)
            {
                return Err(CKR_DATA_INVALID.into());
            }
            let mut public_attributes = self.public_attributes.clone();
            public_attributes.remove(u64::from(CKA_ID));
            public_attributes.remove(u64::from(CKA_LABEL));
            insert_sparse_identity(
                &mut public_attributes,
                self.public_id.as_deref(),
                self.public_label.as_deref(),
            )?;
            record
                .insert_aspect(u64::from(CKO_PUBLIC_KEY), public_attributes)
                .map_err(key_metadata_error)?;
        } else if self.public_id.is_some()
            || self.public_label.is_some()
            || !self.public_attributes.is_empty()
        {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(record)
    }

    fn from_backed_key(
        metadata_object: &YubiHsmObjectInfo,
        record: &BackedKeyMetadata,
    ) -> Result<Self, Error> {
        if record.backing().provider() != YUBIHSM_BACKING_PROVIDER {
            return Err(CKR_DATA_INVALID.into());
        }
        let backing = decode_yubihsm_key_backing(record.backing().data_cbor())?;
        let (format, label_target) =
            yubihsm_metadata_label(&metadata_object.label).ok_or(CKR_DATA_INVALID)?;
        if format != YubiHsmMetadataPhysicalFormat::CanonicalCbor {
            return Err(CKR_DATA_INVALID.into());
        }
        if label_target != (backing.sequence, backing.object_type, backing.id)
            || metadata_object.domains != backing.domains
        {
            return Err(CKR_DATA_INVALID.into());
        }
        let primary = record
            .aspect(backing.primary_class)
            .ok_or(CKR_DATA_INVALID)?;
        let (id, label) = sparse_identity(primary)?;
        let projected_public = backing.primary_class != u64::from(CKO_PUBLIC_KEY)
            && record.aspect(u64::from(CKO_PUBLIC_KEY)).is_some();
        let (public_id, public_label, public_attributes) =
            match record.aspect(u64::from(CKO_PUBLIC_KEY)) {
                Some(public) if backing.primary_class != u64::from(CKO_PUBLIC_KEY) => {
                    let (id, label) = metadata_identity(public)?;
                    (id, label, public.clone())
                }
                Some(_) | None => (None, None, KeyAttributes::new()),
            };
        let expected_aspects = 1 + usize::from(projected_public);
        if record.aspects().count() != expected_aspects {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(Self {
            target_type: backing.object_type,
            target_id: backing.id,
            target_sequence: backing.sequence,
            primary_class: Some(
                CK_OBJECT_CLASS::try_from(backing.primary_class)
                    .map_err(|_| Error::from(CKR_DATA_INVALID))?,
            ),
            id,
            label,
            public: projected_public,
            public_id,
            public_label,
            public_attributes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct YubiHsmKeyBacking {
    object_type: u8,
    id: u16,
    sequence: u8,
    domains: u16,
    primary_class: u64,
}

fn is_key_class(class: u64) -> bool {
    matches!(
        class,
        x if x == u64::from(CKO_PUBLIC_KEY)
            || x == u64::from(CKO_PRIVATE_KEY)
            || x == u64::from(CKO_SECRET_KEY)
    )
}

fn key_metadata_error(_error: KeyMetadataError) -> Error {
    CKR_DATA_INVALID.into()
}

fn insert_sparse_identity(
    attributes: &mut KeyAttributes,
    id: Option<&[u8]>,
    label: Option<&str>,
) -> Result<(), Error> {
    if let Some(id) = id {
        attributes
            .insert(u64::from(CKA_ID), KeyAttributeValue::Bytes(id.to_vec()))
            .map_err(key_metadata_error)?;
    }
    if let Some(label) = label {
        attributes
            .insert(
                u64::from(CKA_LABEL),
                KeyAttributeValue::Text(label.to_owned()),
            )
            .map_err(key_metadata_error)?;
    }
    Ok(())
}

fn sparse_identity(attributes: &KeyAttributes) -> Result<(Option<Vec<u8>>, Option<String>), Error> {
    let mut id = None;
    let mut label = None;
    for (attribute, value) in attributes.iter() {
        match (*attribute, value) {
            (attribute, KeyAttributeValue::Bytes(value)) if attribute == u64::from(CKA_ID) => {
                id = Some(value.clone());
            }
            (attribute, KeyAttributeValue::Text(value)) if attribute == u64::from(CKA_LABEL) => {
                label = Some(value.clone());
            }
            _ => return Err(CKR_ATTRIBUTE_TYPE_INVALID.into()),
        }
    }
    Ok((id, label))
}

fn metadata_identity(
    attributes: &KeyAttributes,
) -> Result<(Option<Vec<u8>>, Option<String>), Error> {
    let mut id = None;
    let mut label = None;
    for (attribute, value) in attributes.iter() {
        match (*attribute, value) {
            (attribute, KeyAttributeValue::Bytes(value)) if attribute == u64::from(CKA_ID) => {
                id = Some(value.clone());
            }
            (attribute, KeyAttributeValue::Text(value)) if attribute == u64::from(CKA_LABEL) => {
                label = Some(value.clone());
            }
            _ => {}
        }
    }
    Ok((id, label))
}

fn encode_yubihsm_key_backing(
    info: &YubiHsmObjectInfo,
    primary_class: u64,
) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(7)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(YUBIHSM_BACKING_SCHEMA))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.u8(YUBIHSM_BACKING_SCHEMA_VERSION as u8))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.u8(info.object_type))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.u16(info.id))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u8(info.sequence))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.u16(info.domains))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.u64(primary_class))
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    Ok(encoded)
}

fn decode_yubihsm_key_backing(encoded: &[u8]) -> Result<YubiHsmKeyBacking, Error> {
    let mut decoder = Decoder::new(encoded);
    if decoder.map().map_err(|_| Error::from(CKR_DATA_INVALID))? != Some(7) {
        return Err(CKR_DATA_INVALID.into());
    }
    let mut schema = None;
    let mut version = None;
    let mut object_type = None;
    let mut id = None;
    let mut sequence = None;
    let mut domains = None;
    let mut primary_class = None;
    for _ in 0..7 {
        match decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))? {
            1 if schema.is_none() => {
                schema = Some(
                    decoder
                        .str()
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?
                        .to_owned(),
                )
            }
            2 if version.is_none() => {
                version = Some(decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            3 if object_type.is_none() => {
                object_type = Some(decoder.u8().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            4 if id.is_none() => {
                id = Some(decoder.u16().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            5 if sequence.is_none() => {
                sequence = Some(decoder.u8().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            6 if domains.is_none() => {
                domains = Some(decoder.u16().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            7 if primary_class.is_none() => {
                primary_class = Some(decoder.u64().map_err(|_| Error::from(CKR_DATA_INVALID))?)
            }
            _ => return Err(CKR_DATA_INVALID.into()),
        }
    }
    if decoder.position() != encoded.len()
        || schema.as_deref() != Some(YUBIHSM_BACKING_SCHEMA)
        || version != Some(YUBIHSM_BACKING_SCHEMA_VERSION)
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let backing = YubiHsmKeyBacking {
        object_type: object_type.ok_or(CKR_DATA_INVALID)?,
        id: id.ok_or(CKR_DATA_INVALID)?,
        sequence: sequence.ok_or(CKR_DATA_INVALID)?,
        domains: domains.ok_or(CKR_DATA_INVALID)?,
        primary_class: primary_class.ok_or(CKR_DATA_INVALID)?,
    };
    if !is_key_class(backing.primary_class)
        || encode_yubihsm_key_backing(
            &YubiHsmObjectInfo {
                capabilities: [0; 8],
                id: backing.id,
                length: 0,
                domains: backing.domains,
                object_type: backing.object_type,
                algorithm: 0,
                sequence: backing.sequence,
                origin: 0,
                label: String::new(),
                delegated_capabilities: [0; 8],
            },
            backing.primary_class,
        )? != encoded
    {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(backing)
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
        let hardware_version = connector.hardware_version();
        Self {
            connector,
            session: Rc::new(RefCell::new(YubiHsmSessionState::LoggedOut)),
            public_discovery_config: None,
            recreate_sessions: false,
            pinentry: Arc::new(pinentry::Pinentry::unconfigured()),
            object_cache: RefCell::new(YubiHsmObjectCache::default()),
            version,
            hardware_version,
            algorithms,
            model: String::from("YubiHSM"),
            serial: String::from("0"),
            trust_prefix: None,
            hsmauth_providers: Arc::new(HsmAuthProviderRegistry::default()),
            object_metadata: RefCell::new(HashMap::new()),
            object_generations: RefCell::new(HashMap::new()),
            attestation_cache: RefCell::new(HashMap::new()),
            metadata_storage_writes: RefCell::new(HashMap::new()),
            next_object_generation: Cell::new(1),
            device_public_key: OnceLock::new(),
        }
    }

    pub(crate) fn with_hsmauth_providers(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
        hsmauth_providers: Arc<HsmAuthProviderRegistry>,
    ) -> Self {
        let mut slot = Self::new(connector, version, algorithms);
        slot.hsmauth_providers = hsmauth_providers;
        slot
    }

    pub(crate) fn with_hsmauth_providers_and_public_discovery(
        connector: Rc<dyn Connector>,
        version: (u8, u8, u8),
        algorithms: Vec<u8>,
        hsmauth_providers: Arc<HsmAuthProviderRegistry>,
        public_discovery_config: Option<Arc<YubiHsmPublicDiscoveryConfig>>,
    ) -> Self {
        let mut slot =
            Self::with_hsmauth_providers(connector, version, algorithms, hsmauth_providers);
        slot.public_discovery_config = public_discovery_config;
        slot
    }

    pub(crate) fn set_pinentry(&mut self, pinentry: Arc<pinentry::Pinentry>) {
        self.pinentry = pinentry;
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

    fn with_hsmauth_provider<T>(
        &self,
        login: &HsmAuthLogin<'_>,
        operation: impl FnOnce(&HsmAuthProvider) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.hsmauth_providers.with_provider(login, operation)
    }

    fn cache_object_info(&self, info: &YubiHsmObjectInfo) -> Result<(), Error> {
        let mut state = self.object_cache.try_borrow_mut()?;
        let key = YubiHsmObjectKey::from_info(info);
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
            .get(&YubiHsmObjectKey::new(object_type, id))
            .filter(|entry| sequence.is_none_or(|sequence| entry.sequence == Some(sequence)))
            .and_then(|entry| entry.info.clone()))
    }

    pub(crate) fn read_object_info(
        &self,
        session: &impl YubiHsmSessionCell,
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
        session: &impl YubiHsmSessionCell,
        id: u16,
        object_type: u8,
        sequence: u8,
    ) -> Result<YubiHsmObjectInfo, Error> {
        let cached = {
            let mut state = self.object_cache.try_borrow_mut()?;
            let (cached, sequence_changed) = {
                let entry = state
                    .native_objects
                    .entry(YubiHsmObjectKey::new(object_type, id))
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
        session: &impl YubiHsmSessionCell,
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
            .entry(YubiHsmObjectKey::from_info(info))
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
        session: &impl YubiHsmSessionCell,
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
        session: &impl YubiHsmSessionCell,
    ) -> Result<Vec<u8>, Error> {
        if info.object_type != YUBIHSM_OPAQUE {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID.into());
        }
        self.read_object_value_with_session(info, session)
    }

    fn read_object_value_by_id(
        &self,
        session: &impl YubiHsmSessionCell,
        id: u16,
        object_type: u8,
    ) -> Result<Vec<u8>, Error> {
        let info = self.object_info_with_session(session, id, object_type)?;
        self.read_object_value_with_session(&info, session)
    }

    fn public_key_with_session(
        &self,
        info: &YubiHsmObjectInfo,
        session: &impl YubiHsmSessionCell,
    ) -> Result<YubiHsmPublicKey, Error> {
        if let Some(public_key) = self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&YubiHsmObjectKey::from_info(info))
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
            .entry(YubiHsmObjectKey::from_info(info))
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
        for (target, sources) in links {
            let Some(entry) = state.native_objects.get_mut(&target.object) else {
                continue;
            };
            if entry.sequence == Some(target.sequence) {
                entry.metadata_sources = sources;
            }
        }
        Ok(())
    }

    fn authentication_key_info(
        &self,
        session: &impl YubiHsmSessionCell,
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
            .get(&YubiHsmObjectKey::new(
                YUBIHSM_AUTHENTICATION_KEY,
                authkey_id,
            ))
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
    ) -> Result<(YubiHsmSecureSession, YubiHsmSessionReauthentication), Error> {
        self.synchronize_caches()?;
        let cached_algorithm = self.cached_authentication_algorithm(authkey_id)?;
        let (session, algorithm, material) = YubiHsmSecureSession::authenticate_direct(
            self.connector.as_ref(),
            authkey_id,
            password,
            self.trust_prefix.as_deref(),
            cached_algorithm,
        )?;
        let mut state = self.object_cache.try_borrow_mut()?;
        let entry = state
            .native_objects
            .entry(YubiHsmObjectKey::new(
                YUBIHSM_AUTHENTICATION_KEY,
                authkey_id,
            ))
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
        Ok((
            session,
            YubiHsmSessionReauthentication::Direct {
                authkey_id,
                material,
            },
        ))
    }

    fn authenticate_login(
        &self,
        username: &[u8],
        password: &[u8],
    ) -> Result<(YubiHsmSecureSession, u16, YubiHsmSessionReauthentication), Error> {
        self.authenticate_parsed_login(parse_yubihsm_login_username(username)?, password)
    }

    fn authenticate_parsed_login(
        &self,
        login: YubiHsmLoginUsername<'_>,
        password: &[u8],
    ) -> Result<(YubiHsmSecureSession, u16, YubiHsmSessionReauthentication), Error> {
        match login {
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
                self.with_hsmauth_provider(&login, |provider| {
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
                    Ok((
                        session,
                        login.authkey_id,
                        YubiHsmSessionReauthentication::HsmAuth {
                            authkey_id: login.authkey_id,
                            provider: provider.clone(),
                            password: Zeroizing::new(password.to_vec()),
                        },
                    ))
                })
            }
            YubiHsmLoginUsername::Direct(authkey_id) => {
                if !(8..=64).contains(&password.len()) {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                let (session, reauthentication) = self.authenticate_direct(authkey_id, password)?;
                Ok((session, authkey_id, reauthentication))
            }
        }
    }

    fn authenticate_public_discovery(
        &self,
        config: &YubiHsmPublicDiscoveryConfig,
    ) -> Result<(YubiHsmSecureSession, u16, YubiHsmSessionReauthentication), Error> {
        let title = format!("Public discovery on {}", self.label());
        let description = match config.login() {
            YubiHsmLoginUsername::Direct(authkey_id) => {
                format!("Enter the password for YubiHSM Authentication Key {authkey_id:04x}.")
            }
            YubiHsmLoginUsername::HsmAuth(login) => {
                format!("Enter the authentication password for {:?}.", login.label)
            }
        };
        if let Some(password) = config.configured_password.as_ref() {
            return self.authenticate_parsed_login(config.login(), password);
        }
        let entered = self.pinentry.request(pinentry::Prompt {
            title: &title,
            description: &description,
            label: "Authentication password:",
        })?;
        match config.login() {
            YubiHsmLoginUsername::Direct(_) if !(8..=64).contains(&entered.len()) => {
                return Err(CKR_PIN_INCORRECT.into());
            }
            YubiHsmLoginUsername::HsmAuth(_) if entered.len() > 16 => {
                return Err(CKR_PIN_INCORRECT.into());
            }
            _ => {}
        }
        self.authenticate_parsed_login(config.login(), entered.as_slice())
    }

    fn has_session_role(&self, role: YubiHsmSessionRole) -> bool {
        self.session
            .try_borrow()
            .is_ok_and(|state| state.is_active_as(role))
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
        let active = {
            let mut state = self.session.try_borrow_mut()?;
            match std::mem::take(&mut *state) {
                YubiHsmSessionState::Active { session, .. } => Some(session),
                YubiHsmSessionState::LoggedOut | YubiHsmSessionState::InvalidatedUser => None,
            }
        };
        let Some(session) = active else {
            return Ok(());
        };
        self.close_session_cell(&RefCell::new(Some(session)), purpose)
    }

    fn ensure_read_session(&self) -> Result<(), Error> {
        self.synchronize_caches()?;
        {
            let mut state = self.session.try_borrow_mut()?;
            match &*state {
                YubiHsmSessionState::Active { .. } => return Ok(()),
                YubiHsmSessionState::InvalidatedUser => {
                    *state = YubiHsmSessionState::LoggedOut;
                    return Err(CKR_USER_NOT_LOGGED_IN.into());
                }
                YubiHsmSessionState::LoggedOut => {}
            }
        }
        let config = self
            .public_discovery_config
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let expected_domains = {
            let state = self
                .object_cache
                .try_borrow()
                .map_err(|_| Error::from(CKR_CANT_LOCK))?;
            state.discovery.authkey_domains()
        };
        let (session, authkey_id, reauthentication) = match self
            .authenticate_public_discovery(config)
        {
            Ok(authenticated) => authenticated,
            Err(error) => {
                log!(
                    2,
                    "YubiHSM pre-login authentication failed while reopening public discovery on {} with authentication key {:04x}: {:?}",
                    self.connector.name(),
                    config.authkey_id,
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
        let session = session.into_inner().ok_or(CKR_DEVICE_ERROR)?;
        *self.session.try_borrow_mut()? = YubiHsmSessionState::Active {
            session,
            role: YubiHsmSessionRole::PublicDiscovery,
            reauthentication: self.recreate_sessions.then(|| Box::new(reauthentication)),
        };
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
                    let invalidated = matches!(
                        *self
                            .session
                            .try_borrow()
                            .map_err(|_| Error::from(CKR_CANT_LOCK))?,
                        YubiHsmSessionState::LoggedOut
                    );
                    if !invalidated || attempt == 1 {
                        return Err(error);
                    }
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
        session: &impl YubiHsmSessionCell,
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
        let mut legacy_metadata = HashMap::new();
        let mut ambiguous_legacy_metadata = HashSet::new();
        let mut canonical_metadata = HashMap::new();
        let mut ambiguous_canonical_metadata = HashSet::new();
        let mut canonical_metadata_present = HashSet::new();
        let mut related_metadata = HashMap::<_, Vec<_>>::new();
        for entry in listed {
            let info =
                self.listed_object_info(session, entry.id, entry.object_type, entry.sequence)?;
            if info.object_type == YUBIHSM_OPAQUE && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA {
                let Some((format, (target_sequence, target_type, target_id))) =
                    yubihsm_metadata_label(&info.label)
                else {
                    discovered.push(YubiHsmDiscoveredObject {
                        info,
                        public_key: None,
                    });
                    continue;
                };
                related_metadata
                    .entry(YubiHsmMetadataTarget {
                        object: YubiHsmObjectKey::new(target_type, target_id),
                        sequence: target_sequence,
                    })
                    .or_default()
                    .push((info.id, info.sequence));
                let label_scope = YubiHsmMetadataScope {
                    target: YubiHsmMetadataTarget {
                        object: YubiHsmObjectKey::new(target_type, target_id),
                        sequence: target_sequence,
                    },
                    domains: info.domains,
                };
                if format == YubiHsmMetadataPhysicalFormat::CanonicalCbor {
                    canonical_metadata_present.insert(label_scope);
                }
                let value = self.read_opaque_with_session(&info, session)?;
                match parse_yubihsm_pkcs11_metadata(&info, &value) {
                    Ok(metadata) => {
                        let target = YubiHsmMetadataScope {
                            target: YubiHsmMetadataTarget {
                                object: YubiHsmObjectKey::new(
                                    metadata.target_type,
                                    metadata.target_id,
                                ),
                                sequence: metadata.target_sequence,
                            },
                            domains: info.domains,
                        };
                        let (selected, ambiguous) = match format {
                            YubiHsmMetadataPhysicalFormat::LegacyMdb1 => {
                                (&mut legacy_metadata, &mut ambiguous_legacy_metadata)
                            }
                            YubiHsmMetadataPhysicalFormat::CanonicalCbor => {
                                (&mut canonical_metadata, &mut ambiguous_canonical_metadata)
                            }
                        };
                        if !ambiguous.contains(&target) {
                            if selected.remove(&target).is_some() {
                                ambiguous.insert(target);
                                log!(
                                    2,
                                    "YubiHSM has duplicate {:?} PKCS11 metadata for object type {:02x} ID {:04x}",
                                    format,
                                    target.target.object.object_type,
                                    target.target.object.id
                                );
                            } else {
                                selected.insert(target, metadata);
                            }
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
            discovered.push(YubiHsmDiscoveredObject { info, public_key });
        }
        let mut pkcs11_metadata = legacy_metadata;
        for target in ambiguous_legacy_metadata {
            pkcs11_metadata.remove(&target);
        }
        for target in canonical_metadata_present {
            pkcs11_metadata.remove(&target);
        }
        for (target, metadata) in canonical_metadata {
            if !ambiguous_canonical_metadata.contains(&target) {
                pkcs11_metadata.insert(target, metadata);
            }
        }
        log!(
            2,
            "YubiHSM discovery resolved {} objects and {} PKCS11 metadata records on {}",
            discovered.len(),
            pkcs11_metadata.len(),
            self.connector.name()
        );
        self.replace_metadata_links(related_metadata)?;
        Ok(YubiHsmDiscoveredObjects {
            objects: discovered,
            metadata: pkcs11_metadata,
        })
    }

    fn object_generation(&self, info: &YubiHsmObjectInfo) -> Result<u64, Error> {
        let key = YubiHsmObjectKey::from_info(info);
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
        session: &impl YubiHsmSessionCell,
    ) -> Result<Vec<TokenObject>, Error> {
        let YubiHsmDiscoveredObjects {
            objects: discovered,
            mut metadata,
        } = self.discover_objects(session)?;
        let mut candidates = Vec::new();
        'discovered: for YubiHsmDiscoveredObject { info, public_key } in discovered {
            let certificate = if info.object_type == YUBIHSM_OPAQUE
                && info.algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE
            {
                Some(self.read_opaque_with_session(&info, session)?)
            } else {
                None
            };
            let generation = self.object_generation(&info)?;
            let attribute_metadata = metadata
                .remove(&YubiHsmMetadataScope {
                    target: YubiHsmMetadataTarget {
                        object: YubiHsmObjectKey::from_info(&info),
                        sequence: info.sequence,
                    },
                    domains: info.domains,
                })
                .filter(|metadata| {
                    metadata
                        .primary_class
                        .is_none_or(|class| class == yubihsm_object_class(&info))
                });
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
        let Some(config) = self.public_discovery_config.as_ref() else {
            return false;
        };
        match self.object_cache.try_borrow() {
            Ok(state) if matches!(state.discovery, YubiHsmDiscoveryCache::Available { .. }) => {
                return true;
            }
            Err(_) => return false,
            _ => {}
        }
        if self.has_session_role(YubiHsmSessionRole::User) {
            return false;
        }
        if let YubiHsmLoginUsername::HsmAuth(login) = config.login() {
            let provider_available = match self.with_hsmauth_provider(&login, |_| Ok(())) {
                Ok(()) => true,
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
            };
            if !provider_available {
                return false;
            }
        }
        {
            let Ok(mut state) = self.object_cache.try_borrow_mut() else {
                return false;
            };
            if state.discovery != YubiHsmDiscoveryCache::Unattempted {
                return false;
            }
            state.discovery = YubiHsmDiscoveryCache::Failed;
        }

        log!(
            2,
            "YubiHSM public discovery starting on {} with authentication key {:04x}",
            self.connector.name(),
            config.authkey_id
        );
        let session = self.authenticate_public_discovery(config);
        let session = match session {
            Ok((session, _, reauthentication)) => (session, reauthentication),
            Err(error) => {
                log!(
                    1,
                    "YubiHSM pre-login authentication failed on {} with authentication key {:04x}: {:?}",
                    self.connector.name(),
                    config.authkey_id,
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
        let (session, reauthentication) = session;
        let session = RefCell::new(Some(session));
        let discovery: Result<(Vec<TokenObject>, u16), Error> = (|| {
            let info = self.authentication_key_info(&session, config.authkey_id)?;
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
                state.discovery = YubiHsmDiscoveryCache::Available { authkey_domains };
                drop(state);
                let Some(retained_session) = session.into_inner() else {
                    return false;
                };
                let Ok(mut active) = self.session.try_borrow_mut() else {
                    return false;
                };
                *active = YubiHsmSessionState::Active {
                    session: retained_session,
                    role: YubiHsmSessionRole::PublicDiscovery,
                    reauthentication: self.recreate_sessions.then(|| Box::new(reauthentication)),
                };
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
            let mut session = self.session.try_borrow_mut()?;
            *session = if session.is_active_as(YubiHsmSessionRole::User) {
                YubiHsmSessionState::InvalidatedUser
            } else {
                YubiHsmSessionState::LoggedOut
            };
            log!(
                2,
                "YubiHSM discovery cache reset on {} after connector state changed",
                self.connector.name()
            );
            self.object_metadata.try_borrow_mut()?.clear();
            self.object_generations.try_borrow_mut()?.clear();
            self.attestation_cache.try_borrow_mut()?.clear();
            self.metadata_storage_writes.try_borrow_mut()?.clear();
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
                    private_targets.insert(YubiHsmObjectKey::new(object_type & !0x80, id));
                }
                false
            });
            let metadata_ids = private_targets
                .iter()
                .filter_map(|key| state.native_objects.get(key))
                .flat_map(|entry| entry.metadata_sources.iter())
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>();
            state.native_objects.retain(|key, entry| {
                if private_targets.contains(key) {
                    if key.object_type != YUBIHSM_AUTHENTICATION_KEY {
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
                key.object_type != YUBIHSM_OPAQUE || !metadata_ids.contains(&key.id)
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
                *cache.cache.try_borrow_mut()? = LazyCache::Unattempted;
            }
        }
        attestation_cache.retain(|(target, _), _| !private_targets.contains(target));
        Ok(())
    }

    fn forget_cached_object(&self, id: u16, object_type: u8) -> Result<(), Error> {
        let key = YubiHsmObjectKey::new(object_type & !0x80, id);
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
        if object_type & !0x80 == YUBIHSM_OPAQUE {
            self.metadata_storage_writes
                .try_borrow_mut()?
                .retain(|_, candidate_id| *candidate_id != id);
        }
        Ok(())
    }

    fn related_metadata_object(&self, id: u16, object_type: u8) -> Result<Vec<(u16, u8)>, Error> {
        Ok(self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .native_objects
            .get(&YubiHsmObjectKey::new(object_type & !0x80, id))
            .map(|entry| entry.metadata_sources.clone())
            .unwrap_or_default())
    }

    fn metadata_objects_in_format(
        &self,
        objects: &[(u16, u8)],
        format: YubiHsmMetadataPhysicalFormat,
    ) -> Result<Vec<(u16, u8)>, Error> {
        let state = self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        Ok(objects
            .iter()
            .copied()
            .filter(|(id, sequence)| {
                state
                    .native_objects
                    .get(&YubiHsmObjectKey::new(YUBIHSM_OPAQUE, *id))
                    .filter(|entry| entry.sequence == Some(*sequence))
                    .and_then(|entry| entry.info.as_ref())
                    .and_then(|info| yubihsm_metadata_label(&info.label))
                    .is_some_and(|(candidate, _)| candidate == format)
            })
            .collect())
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
        for metadata in metadata.values() {
            let objects = yubihsm_token_objects_with_generation(
                slot_id,
                metadata.info.clone(),
                metadata.public_key.clone(),
                metadata.generation,
                metadata.attributes.as_ref(),
            )?;
            if let Some((index, _)) = objects
                .iter()
                .enumerate()
                .find(|(_, object)| object.unique_id == unique_id)
            {
                return Ok((
                    metadata.info.clone(),
                    metadata.attributes.clone(),
                    index != 0,
                ));
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
        let mut metadata = current
            .clone()
            .unwrap_or_else(|| Self::empty_pkcs11_metadata(&info));

        if let Some(id) = id {
            let value = (id != info.id.to_be_bytes()).then(|| id.to_vec());
            if public {
                metadata.public = true;
                metadata.public_id = value;
            } else {
                metadata.id = value;
            }
        }
        if let Some(label) = label {
            let value = (label != yubihsm_object_label(&info)).then(|| label.to_owned());
            if public {
                metadata.public = true;
                metadata.public_label = value;
            } else {
                metadata.label = value;
            }
        }

        self.replace_pkcs11_metadata_record(&info, current.as_ref(), &metadata)
    }

    fn empty_pkcs11_metadata(info: &YubiHsmObjectInfo) -> YubiHsmPkcs11Metadata {
        YubiHsmPkcs11Metadata {
            target_type: info.object_type,
            target_id: info.id,
            target_sequence: info.sequence,
            primary_class: Some(yubihsm_object_class(info)),
            id: None,
            label: None,
            public: false,
            public_id: None,
            public_label: None,
            public_attributes: KeyAttributes::new(),
        }
    }

    fn replace_pkcs11_metadata_record(
        &self,
        info: &YubiHsmObjectInfo,
        current: Option<&YubiHsmPkcs11Metadata>,
        metadata: &YubiHsmPkcs11Metadata,
    ) -> Result<(), Error> {
        let old_objects = self.related_metadata_object(info.id, info.object_type)?;
        let old_canonical_objects = self.metadata_objects_in_format(
            &old_objects,
            YubiHsmMetadataPhysicalFormat::CanonicalCbor,
        )?;
        let has_legacy_metadata = !self
            .metadata_objects_in_format(&old_objects, YubiHsmMetadataPhysicalFormat::LegacyMdb1)?
            .is_empty();
        let mut old_references = Vec::new();
        for (id, sequence) in &old_canonical_objects {
            let info = self
                .cached_object_info(*id, YUBIHSM_OPAQUE, Some(*sequence))?
                .ok_or(CKR_DEVICE_ERROR)?;
            let value = self.storage_object_value(&info)?;
            let reference = ContentReference::for_object(&value);
            if !old_references.contains(&reference) {
                old_references.push(reference);
            }
        }

        if metadata.is_empty() && !has_legacy_metadata {
            for reference in old_references {
                StorageProvider::delete(self, &reference)
                    .map_err(crate::backed_object::storage_error)?;
            }
            return Ok(());
        }

        let value = metadata.encode(info)?;
        if !old_canonical_objects.is_empty()
            && current
                .and_then(|current| current.encode(info).ok())
                .as_deref()
                == Some(value.as_slice())
        {
            return Ok(());
        }
        let new_reference =
            StorageProvider::put(self, &value).map_err(crate::backed_object::storage_error)?;
        for reference in old_references {
            if reference != new_reference {
                StorageProvider::delete(self, &reference)
                    .map_err(crate::backed_object::storage_error)?;
            }
        }
        Ok(())
    }

    fn persist_public_projection(
        &self,
        slot_id: CK_SLOT_ID,
        base_unique_id: &str,
        projection: &TokenObject,
    ) -> Result<(), Error> {
        let (info, current, public) = self.metadata_target_by_unique_id(slot_id, base_unique_id)?;
        if public {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let mut metadata = current
            .clone()
            .unwrap_or_else(|| Self::empty_pkcs11_metadata(&info));
        metadata.public = true;
        metadata.public_id =
            (projection.id != info.id.to_be_bytes()).then(|| projection.id.clone());
        metadata.public_label =
            (projection.label != yubihsm_object_label(&info)).then(|| projection.label.clone());
        metadata.public_attributes = yubihsm_public_projection_attributes(projection)?;
        self.replace_pkcs11_metadata_record(&info, current.as_ref(), &metadata)
    }

    fn destroy_public_projection(&self, slot_id: CK_SLOT_ID, unique_id: &str) -> Result<(), Error> {
        let (info, current, public) = self.metadata_target_by_unique_id(slot_id, unique_id)?;
        let mut metadata = current.ok_or(CKR_ACTION_PROHIBITED)?;
        if !public || metadata.persisted_public_key_info().is_none() {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        let previous = metadata.clone();
        metadata.public = false;
        metadata.public_id = None;
        metadata.public_label = None;
        metadata.public_attributes = KeyAttributes::new();
        self.replace_pkcs11_metadata_record(&info, Some(&previous), &metadata)
    }

    fn write_backed_key_metadata(&self, object: &[u8]) -> Result<u16, Error> {
        let record = BackedKeyMetadata::from_cbor(object).map_err(key_metadata_error)?;
        if record.backing().provider() != YUBIHSM_BACKING_PROVIDER {
            return Err(CKR_DATA_INVALID.into());
        }
        let backing = decode_yubihsm_key_backing(record.backing().data_cbor())?;
        self.ensure_read_session()?;
        let target =
            self.object_info_with_session(self.session.as_ref(), backing.id, backing.object_type)?;
        let synthetic_metadata_info = YubiHsmObjectInfo {
            capabilities: [0; 8],
            id: 0,
            length: u16::try_from(object.len()).unwrap_or(u16::MAX),
            domains: target.domains,
            object_type: YUBIHSM_OPAQUE,
            algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
            sequence: 0,
            origin: 0,
            label: yubihsm_metadata_label_for_target(
                &target,
                YubiHsmMetadataPhysicalFormat::CanonicalCbor,
            ),
            delegated_capabilities: [0; 8],
        };
        validate_yubihsm_backed_key(&synthetic_metadata_info, &target, &record)?;
        let physical_label = yubihsm_metadata_label_for_target(
            &target,
            YubiHsmMetadataPhysicalFormat::CanonicalCbor,
        );
        let capabilities = if yubihsm_capability(&target.capabilities, 0x10) {
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
                    label: &physical_label,
                    domains: target.domains,
                    capabilities,
                    algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
                },
                object,
            )?,
        )?;
        let id = parse_yubihsm_object_id(&response)?;
        self.forget_cached_object(id, YUBIHSM_OPAQUE)?;
        Ok(id)
    }

    fn refresh_canonical_storage_objects(&self) -> Result<Vec<YubiHsmObjectInfo>, Error> {
        if self
            .session
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?
            .role()
            .is_some()
        {
            let _ = self.discover_objects(self.session.as_ref())?;
        }
        self.cached_canonical_storage_objects()
    }

    fn cached_canonical_storage_objects(&self) -> Result<Vec<YubiHsmObjectInfo>, Error> {
        let state = self
            .object_cache
            .try_borrow()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        Ok(state
            .native_objects
            .values()
            .filter_map(|entry| entry.info.as_ref())
            .filter(|info| {
                info.object_type == YUBIHSM_OPAQUE
                    && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA
                    && yubihsm_metadata_label(&info.label).is_some_and(|(format, _)| {
                        format == YubiHsmMetadataPhysicalFormat::CanonicalCbor
                    })
            })
            .cloned()
            .collect())
    }

    fn storage_object_value(&self, info: &YubiHsmObjectInfo) -> Result<Vec<u8>, Error> {
        if self.has_session_role(YubiHsmSessionRole::User) {
            self.read_object_value_with_session(info, self.session.as_ref())
        } else {
            self.read_object_value_with_public_discovery(info.id, info.object_type)
        }
    }
}

fn yubihsm_storage_error(error: Error) -> StorageError {
    StorageError::Provider(format!("{error:?}"))
}

impl StorageProvider for YubiHsmSlot {
    fn supports_mutation(&self) -> bool {
        self.has_session_role(YubiHsmSessionRole::User)
    }

    fn list(&self) -> Result<Vec<ContentReference>, StorageError> {
        let mut references = Vec::new();
        for info in self
            .refresh_canonical_storage_objects()
            .map_err(yubihsm_storage_error)?
        {
            let object = self
                .storage_object_value(&info)
                .map_err(yubihsm_storage_error)?;
            BackedKeyMetadata::from_cbor(&object)
                .map_err(|error| StorageError::Provider(error.to_string()))?;
            let reference = ContentReference::for_object(&object);
            if !references.contains(&reference) {
                references.push(reference);
            }
        }
        references.sort();
        Ok(references)
    }

    fn get(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError> {
        for info in self
            .refresh_canonical_storage_objects()
            .map_err(yubihsm_storage_error)?
        {
            let object = self
                .storage_object_value(&info)
                .map_err(yubihsm_storage_error)?;
            if ContentReference::for_object(&object) == *reference {
                return Ok(Some(object));
            }
        }
        Ok(None)
    }

    fn put(&self, object: &[u8]) -> Result<ContentReference, StorageError> {
        let record = BackedKeyMetadata::from_cbor(object)
            .map_err(|error| StorageError::Provider(error.to_string()))?;
        if record.backing().provider() != YUBIHSM_BACKING_PROVIDER {
            return Err(StorageError::Provider(String::from(
                "YubiHSM storage rejected a non-YubiHSM backing record",
            )));
        }
        let reference = ContentReference::for_object(object);
        if self
            .metadata_storage_writes
            .try_borrow()
            .map_err(|_| {
                StorageError::Provider(String::from(
                    "YubiHSM metadata storage cache is already borrowed",
                ))
            })?
            .contains_key(&reference)
        {
            return Ok(reference);
        }
        for info in self
            .cached_canonical_storage_objects()
            .map_err(yubihsm_storage_error)?
        {
            let existing = self
                .storage_object_value(&info)
                .map_err(yubihsm_storage_error)?;
            if ContentReference::for_object(&existing) == reference && existing == object {
                return Ok(reference);
            }
        }
        let id = self
            .write_backed_key_metadata(object)
            .map_err(yubihsm_storage_error)?;
        self.metadata_storage_writes
            .try_borrow_mut()
            .map_err(|_| {
                StorageError::Provider(String::from(
                    "YubiHSM metadata storage cache is already borrowed",
                ))
            })?
            .insert(reference.clone(), id);
        Ok(reference)
    }

    fn delete(&self, reference: &ContentReference) -> Result<bool, StorageError> {
        let mut matches = Vec::new();
        if let Some(id) = self
            .metadata_storage_writes
            .try_borrow()
            .map_err(|_| {
                StorageError::Provider(String::from(
                    "YubiHSM metadata storage cache is already borrowed",
                ))
            })?
            .get(reference)
            .copied()
        {
            matches.push((id, 0));
        }
        for info in self
            .cached_canonical_storage_objects()
            .map_err(yubihsm_storage_error)?
        {
            let object = self
                .storage_object_value(&info)
                .map_err(yubihsm_storage_error)?;
            if ContentReference::for_object(&object) == *reference
                && !matches.iter().any(|(id, _)| *id == info.id)
            {
                matches.push((info.id, info.sequence));
            }
        }
        if matches.is_empty() {
            return Ok(false);
        }
        self.delete_metadata_objects(&matches)
            .map_err(yubihsm_storage_error)?;
        Ok(true)
    }
}

fn validate_yubihsm_backed_key(
    metadata_object: &YubiHsmObjectInfo,
    target: &YubiHsmObjectInfo,
    record: &BackedKeyMetadata,
) -> Result<(), Error> {
    if record.backing().provider() != YUBIHSM_BACKING_PROVIDER {
        return Err(CKR_DATA_INVALID.into());
    }
    let backing = decode_yubihsm_key_backing(record.backing().data_cbor())?;
    if backing.object_type != target.object_type
        || backing.id != target.id
        || backing.sequence != target.sequence
        || backing.domains != target.domains
        || backing.primary_class != cryptoki_ulong_to_u64(yubihsm_object_class(target))
        || metadata_object.domains != target.domains
        || yubihsm_metadata_label_target(&metadata_object.label)
            != Some((target.sequence, target.object_type, target.id))
        || record.aspect(backing.primary_class).is_none()
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let projected_public = backing.primary_class != u64::from(CKO_PUBLIC_KEY)
        && record.aspect(u64::from(CKO_PUBLIC_KEY)).is_some();
    if projected_public && !yubihsm_object_has_public_key(target) {
        return Err(CKR_DATA_INVALID.into());
    }
    if record.aspects().count() != 1 + usize::from(projected_public) {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(())
}

pub(crate) trait YubiHsmSessionCell {
    fn send_secure_command(
        &self,
        connector: &dyn Connector,
        command: &YubiHsmCommand,
    ) -> Result<Vec<u8>, Error>;
}

impl YubiHsmSessionCell for RefCell<Option<YubiHsmSecureSession>> {
    fn send_secure_command(
        &self,
        connector: &dyn Connector,
        command: &YubiHsmCommand,
    ) -> Result<Vec<u8>, Error> {
        let mut session_guard = self.try_borrow_mut()?;
        send_yubihsm_secure_command_with_session(connector, &mut session_guard, command)
    }
}

impl YubiHsmSessionCell for RefCell<YubiHsmSessionState> {
    fn send_secure_command(
        &self,
        connector: &dyn Connector,
        command: &YubiHsmCommand,
    ) -> Result<Vec<u8>, Error> {
        let mut state = self.try_borrow_mut()?;
        let (mut session, role, reauthentication) = match std::mem::take(&mut *state) {
            YubiHsmSessionState::Active {
                session,
                role,
                reauthentication,
            } => (session, role, reauthentication),
            inactive => {
                *state = inactive;
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
        };
        if let Err(error) = YubiHsmSecureSession::validate_command(connector, command) {
            *state = YubiHsmSessionState::Active {
                session,
                role,
                reauthentication,
            };
            return Err(error);
        }
        let mut result = session.send_command(connector, command);
        let expired = matches!(
            result,
            Err(Error::Generic(rv)) if rv == CKR_SESSION_CLOSED as CK_RV
        );
        if expired {
            if let Some(recipe) = reauthentication.as_ref() {
                log!(
                    2,
                    "YubiHSM secure session expired on {}; recreating it once",
                    connector.name()
                );
                match recipe.authenticate(connector) {
                    Ok(mut replacement) => {
                        result = replacement.send_command(connector, command);
                        session = replacement;
                    }
                    Err(error) => result = Err(error),
                }
            }
        }
        if session.is_valid() {
            *state = YubiHsmSessionState::Active {
                session,
                role,
                reauthentication,
            };
        } else {
            *state = match role {
                YubiHsmSessionRole::User => YubiHsmSessionState::InvalidatedUser,
                YubiHsmSessionRole::PublicDiscovery => YubiHsmSessionState::LoggedOut,
            };
        }
        result
    }
}

pub(crate) fn send_yubihsm_secure_command<S: YubiHsmSessionCell + ?Sized>(
    connector: &dyn Connector,
    shared_session: &S,
    command: &YubiHsmCommand,
) -> Result<Vec<u8>, Error> {
    shared_session.send_secure_command(connector, command)
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
    crate::yubihsm::trust::device_spki(public_key)?;
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
        wrap: false,
        unwrap: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: true,
        key_gen_mechanism: None,
        allowed_mechanisms: None,
        wrap_with_trusted: false,
        policy_templates: crate::KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: KeyMaterial::Public(PublicKeyMaterial::Ec {
            parameters: piv_ec_parameters(piv::Algorithm::EccP256)
                .ok_or(CKR_DEVICE_ERROR)?
                .to_vec(),
            public_key: public_key
                .strip_prefix(&[0x04])
                .unwrap_or(public_key)
                .to_vec(),
        }),
    })
}

pub(crate) fn yubihsm_object_has_public_key(info: &YubiHsmObjectInfo) -> bool {
    matches!(
        info.object_type,
        YUBIHSM_ASYMMETRIC_KEY | YUBIHSM_PUBLIC_WRAP_KEY
    ) || (info.object_type == YUBIHSM_WRAP_KEY && is_yubihsm_rsa(info.algorithm))
}

fn yubihsm_metadata_label(label: &str) -> Option<(YubiHsmMetadataPhysicalFormat, (u8, u8, u16))> {
    let (format, encoded) =
        if let Some(encoded) = label.strip_prefix(YUBIHSM_LEGACY_METADATA_LABEL_PREFIX) {
            (YubiHsmMetadataPhysicalFormat::LegacyMdb1, encoded)
        } else {
            (
                YubiHsmMetadataPhysicalFormat::CanonicalCbor,
                label.strip_prefix(YUBIHSM_CANONICAL_METADATA_LABEL_PREFIX)?,
            )
        };
    if encoded.len() != 8 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((
        format,
        (
            u8::from_str_radix(&encoded[..2], 16).ok()?,
            u8::from_str_radix(&encoded[2..4], 16).ok()?,
            u16::from_str_radix(&encoded[4..], 16).ok()?,
        ),
    ))
}

fn yubihsm_metadata_label_for_target(
    target: &YubiHsmObjectInfo,
    format: YubiHsmMetadataPhysicalFormat,
) -> String {
    let prefix = match format {
        YubiHsmMetadataPhysicalFormat::LegacyMdb1 => YUBIHSM_LEGACY_METADATA_LABEL_PREFIX,
        YubiHsmMetadataPhysicalFormat::CanonicalCbor => YUBIHSM_CANONICAL_METADATA_LABEL_PREFIX,
    };
    format!(
        "{prefix}{:02x}{:02x}{:04x}",
        target.sequence, target.object_type, target.id
    )
}

pub(crate) fn yubihsm_metadata_label_target(label: &str) -> Option<(u8, u8, u16)> {
    yubihsm_metadata_label(label).map(|(_, target)| target)
}

pub(crate) fn parse_yubihsm_pkcs11_metadata(
    info: &YubiHsmObjectInfo,
    value: &[u8],
) -> Result<YubiHsmPkcs11Metadata, Error> {
    if info.object_type != YUBIHSM_OPAQUE || info.algorithm != YUBIHSM_ALGO_OPAQUE_DATA {
        return Err(CKR_DATA_INVALID.into());
    }
    let (format, label_target) = yubihsm_metadata_label(&info.label).ok_or(CKR_DATA_INVALID)?;
    match format {
        YubiHsmMetadataPhysicalFormat::CanonicalCbor if !value.starts_with(b"MDB1") => {
            let record = BackedKeyMetadata::from_cbor(value).map_err(key_metadata_error)?;
            return YubiHsmPkcs11Metadata::from_backed_key(info, &record);
        }
        YubiHsmMetadataPhysicalFormat::LegacyMdb1 if value.starts_with(b"MDB1") => {}
        YubiHsmMetadataPhysicalFormat::LegacyMdb1
        | YubiHsmMetadataPhysicalFormat::CanonicalCbor => {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    if value.len() < 8 {
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
        primary_class: None,
        id: None,
        label: None,
        public: false,
        public_id: None,
        public_label: None,
        public_attributes: KeyAttributes::new(),
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
    metadata.public = metadata.public_id.is_some() || metadata.public_label.is_some();
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
    let class = yubihsm_object_class(&info);
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
        wrap: operational_algorithm_supported && attributes.wrap,
        unwrap: operational_algorithm_supported && attributes.unwrap,
        sensitive: private,
        extractable: attributes.extractable,
        always_sensitive: private,
        never_extractable: !attributes.extractable,
        local: generated,
        key_gen_mechanism: generated
            .then(|| yubihsm_key_generation_mechanism(info.algorithm))
            .flatten(),
        allowed_mechanisms: None,
        wrap_with_trusted: false,
        policy_templates: crate::KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material,
    }];

    if (info.object_type == YUBIHSM_ASYMMETRIC_KEY || rsa_wrap_key)
        && metadata
            .and_then(YubiHsmPkcs11Metadata::persisted_public_key_info)
            .is_some()
    {
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
        let mut public_object = TokenObject {
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
            wrap: false,
            unwrap: false,
            sensitive: false,
            extractable: public_attributes.extractable,
            always_sensitive: false,
            never_extractable: false,
            local: generated,
            key_gen_mechanism: objects[0].key_gen_mechanism,
            allowed_mechanisms: None,
            wrap_with_trusted: false,
            policy_templates: crate::KeyPolicyTemplates::default(),
            creator_session: None,
            public_key: None,
            rp_id: None,
            material: public_material,
        };
        match apply_yubihsm_public_projection_metadata(&mut public_object, metadata) {
            Ok(()) => objects.push(public_object),
            Err(error) => log!(
                2,
                "YubiHSM ignored invalid persisted public projection for object type {:02x} ID {:04x}: {:?}",
                info.object_type,
                info.id,
                error
            ),
        }
    }
    Ok(objects)
}

fn apply_yubihsm_public_projection_metadata(
    object: &mut TokenObject,
    metadata: Option<&YubiHsmPkcs11Metadata>,
) -> Result<(), Error> {
    let metadata = metadata.ok_or(CKR_DATA_INVALID)?;
    let expected_key_info = metadata
        .persisted_public_key_info()
        .ok_or(CKR_DATA_INVALID)?;
    if object
        .attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
        .as_deref()
        != Some(expected_key_info)
    {
        return Err(CKR_DATA_INVALID.into());
    }
    for (attribute, value) in metadata.public_attributes.iter() {
        match (*attribute, value) {
            (attribute, KeyAttributeValue::Bytes(value)) if attribute == u64::from(CKA_ID) => {
                if metadata.public_id.as_deref() != Some(value.as_slice()) {
                    return Err(CKR_DATA_INVALID.into());
                }
            }
            (attribute, KeyAttributeValue::Text(value)) if attribute == u64::from(CKA_LABEL) => {
                if metadata.public_label.as_deref() != Some(value.as_str()) {
                    return Err(CKR_DATA_INVALID.into());
                }
            }
            (attribute, KeyAttributeValue::Bytes(value))
                if attribute == u64::from(CKA_PUBLIC_KEY_INFO) =>
            {
                if value.as_slice() != expected_key_info {
                    return Err(CKR_DATA_INVALID.into());
                }
            }
            (attribute, KeyAttributeValue::Unsigned(value))
                if attribute == u64::from(CKA_KEY_TYPE) =>
            {
                if *value != cryptoki_ulong_to_u64(object.key_type) {
                    return Err(CKR_DATA_INVALID.into());
                }
            }
            (attribute, KeyAttributeValue::Boolean(value))
                if attribute == u64::from(CKA_PRIVATE) =>
            {
                object.private = *value;
            }
            (attribute, KeyAttributeValue::Boolean(value))
                if attribute == u64::from(CKA_ENCRYPT) =>
            {
                if *value && object.key_type != CKK_RSA as CK_KEY_TYPE {
                    return Err(CKR_DATA_INVALID.into());
                }
                object.encrypt = *value;
            }
            (attribute, KeyAttributeValue::Boolean(value))
                if attribute == u64::from(CKA_VERIFY) =>
            {
                if *value
                    && !matches!(
                        object.key_type,
                        x if x == CKK_RSA as CK_KEY_TYPE
                            || x == CKK_EC as CK_KEY_TYPE
                            || x == CKK_EC_EDWARDS as CK_KEY_TYPE
                    )
                {
                    return Err(CKR_DATA_INVALID.into());
                }
                object.verify = *value;
            }
            (attribute, KeyAttributeValue::Boolean(value))
                if attribute == u64::from(CKA_EXTRACTABLE) =>
            {
                if !*value {
                    return Err(CKR_DATA_INVALID.into());
                }
                object.extractable = true;
            }
            (attribute, KeyAttributeValue::Boolean(value)) if attribute == u64::from(CKA_LOCAL) => {
                object.local = *value;
            }
            (attribute, KeyAttributeValue::Unsigned(value))
                if attribute == u64::from(CKA_KEY_GEN_MECHANISM) =>
            {
                object.key_gen_mechanism = Some(
                    CK_MECHANISM_TYPE::try_from(*value)
                        .map_err(|_| Error::from(CKR_DATA_INVALID))?,
                );
            }
            _ => return Err(CKR_DATA_INVALID.into()),
        }
    }
    Ok(())
}

fn yubihsm_public_projection_attributes(object: &TokenObject) -> Result<KeyAttributes, Error> {
    if object.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS || !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let public_key_info = object
        .attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
        .ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let mut attributes = KeyAttributes::new();
    for (attribute, value) in [
        (
            u64::from(CKA_KEY_TYPE),
            KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(object.key_type)),
        ),
        (
            u64::from(CKA_LABEL),
            KeyAttributeValue::Text(object.label.clone()),
        ),
        (
            u64::from(CKA_ID),
            KeyAttributeValue::Bytes(object.id.clone()),
        ),
        (
            u64::from(CKA_PRIVATE),
            KeyAttributeValue::Boolean(object.private),
        ),
        (
            u64::from(CKA_ENCRYPT),
            KeyAttributeValue::Boolean(object.encrypt),
        ),
        (
            u64::from(CKA_VERIFY),
            KeyAttributeValue::Boolean(object.verify),
        ),
        (
            u64::from(CKA_EXTRACTABLE),
            KeyAttributeValue::Boolean(object.extractable),
        ),
        (
            u64::from(CKA_LOCAL),
            KeyAttributeValue::Boolean(object.local),
        ),
        (
            u64::from(CKA_PUBLIC_KEY_INFO),
            KeyAttributeValue::Bytes(public_key_info),
        ),
    ] {
        attributes
            .insert(attribute, value)
            .map_err(key_metadata_error)?;
    }
    if let Some(mechanism) = object.key_gen_mechanism {
        attributes
            .insert(
                u64::from(CKA_KEY_GEN_MECHANISM),
                KeyAttributeValue::Unsigned(cryptoki_ulong_to_u64(mechanism)),
            )
            .map_err(key_metadata_error)?;
    }
    Ok(attributes)
}

#[cfg(feature = "abi-tests")]
pub(crate) fn yubihsm_abi_public_projection_metadata(
    target: &YubiHsmObjectInfo,
    projection: &TokenObject,
) -> Result<(String, Vec<u8>), Error> {
    let metadata = YubiHsmPkcs11Metadata {
        target_type: target.object_type,
        target_id: target.id,
        target_sequence: target.sequence,
        primary_class: None,
        id: None,
        label: None,
        public: true,
        public_id: (projection.id != target.id.to_be_bytes()).then(|| projection.id.clone()),
        public_label: (projection.label != yubihsm_object_label(target))
            .then(|| projection.label.clone()),
        public_attributes: yubihsm_public_projection_attributes(projection)?,
    };
    Ok((
        yubihsm_metadata_label_for_target(target, YubiHsmMetadataPhysicalFormat::CanonicalCbor),
        metadata.encode(target)?,
    ))
}

fn yubihsm_object_class(info: &YubiHsmObjectInfo) -> CK_OBJECT_CLASS {
    match info.object_type {
        YUBIHSM_OPAQUE if info.algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE => {
            CKO_CERTIFICATE as CK_OBJECT_CLASS
        }
        YUBIHSM_OPAQUE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_ASYMMETRIC_KEY => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        YUBIHSM_WRAP_KEY if is_yubihsm_rsa(info.algorithm) => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        YUBIHSM_PUBLIC_WRAP_KEY => CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        YUBIHSM_TEMPLATE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_AUTHENTICATION_KEY
        | YUBIHSM_WRAP_KEY
        | YUBIHSM_HMAC_KEY
        | YUBIHSM_SYMMETRIC_KEY
        | YUBIHSM_OTP_AEAD_KEY => CKO_SECRET_KEY as CK_OBJECT_CLASS,
        _ => CKO_DATA as CK_OBJECT_CLASS,
    }
}

impl Slot for YubiHsmSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn kind(&self) -> SlotKind {
        SlotKind::YubiHsm
    }
    fn native_storage_provider(&self) -> Option<&dyn StorageProvider> {
        Some(self)
    }
    fn native_storage_objects_are_backend_managed(&self) -> bool {
        true
    }
    fn name(&self) -> String {
        self.connector.name()
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiHSM"
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn label(&self) -> String {
        format!("{} #{}", self.product(), self.serial())
    }
    fn serial(&self) -> &str {
        &self.serial
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
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
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
        Err(CKR_ARGUMENTS_BAD.into())
    }
    fn login_with_pinentry(
        &mut self,
        pin: &[u8],
        pinentry: &pinentry::Pinentry,
    ) -> Result<(), Error> {
        let (username, password) = split_yubihsm_login(pin)?;
        if let Some(password) = password {
            return self.login_user(username, password);
        }
        let YubiHsmLoginUsername::HsmAuth(login) = parse_yubihsm_login_username(username)? else {
            return Err(CKR_PIN_INCORRECT.into());
        };
        let title = self.with_hsmauth_provider(&login, |provider| {
            Ok(format!(
                "{} accessing {}",
                provider.slot_label(),
                self.label()
            ))
        })?;
        let description = format!("Enter the authentication password for {:?}.", login.label);
        let password = pinentry.request(pinentry::Prompt {
            title: &title,
            description: &description,
            label: "Authentication password:",
        })?;
        self.login_user(username, password.as_slice())
    }
    fn login_user(&mut self, username: &[u8], password: &[u8]) -> Result<(), Error> {
        let _ = self.close_active_session("pre-login");
        self.clear_cached_private_objects()?;
        let (session, authkey_id, reauthentication) =
            self.authenticate_login(username, password)?;
        let session = RefCell::new(Some(session));
        let discovery_domains = {
            let state = self
                .object_cache
                .try_borrow()
                .map_err(|_| Error::from(CKR_CANT_LOCK))?;
            state.discovery.authkey_domains()
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
        *self.session.try_borrow_mut()? = YubiHsmSessionState::Active {
            session: session.into_inner().ok_or(CKR_DEVICE_ERROR)?,
            role: YubiHsmSessionRole::User,
            reauthentication: self.recreate_sessions.then(|| Box::new(reauthentication)),
        };
        for cache in self
            .attestation_cache
            .try_borrow()
            .map_err(|_| CKR_CANT_LOCK)?
            .values()
        {
            if !matches!(
                *cache
                    .cache
                    .try_borrow()
                    .map_err(|_| Error::from(CKR_CANT_LOCK))?,
                LazyCache::Value(_)
            ) {
                *cache.cache.try_borrow_mut()? = LazyCache::Unattempted;
            }
        }
        Ok(())
    }
    fn supports_login_user(&self) -> bool {
        true
    }
    fn login_user_without_pin(
        &mut self,
        username: &[u8],
        pinentry: &pinentry::Pinentry,
    ) -> Result<(), Error> {
        let title = self.label();
        let username = std::str::from_utf8(username).map_err(|_| CKR_ARGUMENTS_BAD)?;
        let description = format!("Enter the authentication password for {username} on {title}.");
        let pin = pinentry.request(pinentry::Prompt {
            title: &title,
            description: &description,
            label: "Authentication password:",
        })?;
        self.login_user(username.as_bytes(), pin.as_slice())
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
        self.metadata_storage_writes.try_borrow_mut()?.clear();
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.version = (device_info.major, device_info.minor, device_info.patch);
        self.serial = device_info.serial.to_string();
        self.algorithms = device_info.algorithms;
        self.model = device_info
            .part_number
            .unwrap_or_else(|| String::from("YubiHSM"));
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        if let Some((major, minor)) = self.hardware_version {
            info.hardwareVersion.major = major;
            info.hardwareVersion.minor = minor;
        }
        info.firmwareVersion.major = self.version.0;
        info.firmwareVersion.minor = self.version.1.saturating_mul(10) + self.version.2;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.format_token_info(info);
        let model = device_info.part_number.as_deref().unwrap_or(self.model());
        str_pad(model, &mut info.model);
        str_pad(
            &format!("{} #{}", self.product(), device_info.serial),
            &mut info.label,
        );
        str_pad(&device_info.serial.to_string(), &mut info.serialNumber);
        info.firmwareVersion.major = device_info.major;
        info.firmwareVersion.minor = device_info.minor.saturating_mul(10) + device_info.patch;
        info.ulMaxPinLen = 215;
        info.ulMinPinLen = 0;
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
        self.has_session_role(YubiHsmSessionRole::User)
    }
    fn backend_session_is_active(&self) -> bool {
        self.session
            .try_borrow()
            .is_ok_and(|state| matches!(*state, YubiHsmSessionState::Active { .. }))
    }
    fn ensure_backend_read_session(&self) -> Result<(), Error> {
        self.ensure_read_session()
    }
    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if !self.has_session_role(YubiHsmSessionRole::User) {
            return Ok(self.cached_objects());
        }
        let YubiHsmDiscoveredObjects {
            objects: discovered,
            metadata: mut pkcs11_metadata,
        } = self.discover_objects(self.session.as_ref())?;

        let discovered_keys = discovered
            .iter()
            .map(|object| YubiHsmObjectKey::from_info(&object.info))
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
        for YubiHsmDiscoveredObject { info, public_key } in discovered {
            let key = YubiHsmObjectKey::from_info(&info);
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
            let attribute_metadata = pkcs11_metadata
                .remove(&YubiHsmMetadataScope {
                    target: YubiHsmMetadataTarget {
                        object: key,
                        sequence: info.sequence,
                    },
                    domains: info.domains,
                })
                .filter(|metadata| {
                    metadata
                        .primary_class
                        .is_none_or(|class| class == yubihsm_object_class(&info))
                });
            metadata.insert(
                key,
                YubiHsmObjectMetadata {
                    info: info.clone(),
                    public_key: public_key.clone(),
                    generation,
                    attributes: attribute_metadata.clone(),
                },
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
            .map(|(key, metadata)| ((*key, metadata.generation), ()))
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
        for metadata in metadata {
            let mut objects = yubihsm_token_objects_with_generation(
                slot_id,
                metadata.info.clone(),
                metadata.public_key,
                metadata.generation,
                metadata.attributes.as_ref(),
            )?;
            self.bind_cached_object_value(&metadata.info, &mut objects)?;
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
        for (key, metadata) in metadata.iter() {
            if metadata.info.object_type != YUBIHSM_ASYMMETRIC_KEY
                || metadata.info.origin & 0x01 == 0
            {
                continue;
            }
            let Some(public_key) = metadata.public_key.as_ref() else {
                continue;
            };
            let cache = cache
                .entry((*key, metadata.generation))
                .or_insert_with(YubiHsmAttestationCache::new)
                .clone();
            let id = metadata
                .attributes
                .as_ref()
                .and_then(|metadata| metadata.id.clone())
                .unwrap_or_else(|| metadata.info.id.to_be_bytes().to_vec());
            let label = metadata
                .attributes
                .as_ref()
                .and_then(|metadata| metadata.label.clone())
                .unwrap_or_else(|| yubihsm_object_label(&metadata.info));
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!(
                    "yubihsm-{:02x}-{:04x}-{:02x}-{}-attestation",
                    metadata.info.object_type,
                    metadata.info.id,
                    metadata.info.sequence,
                    metadata.generation
                ),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type: yubihsm_key_type(metadata.info.algorithm),
                label: format!("{label} attestation certificate"),
                id,
                token: false,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                wrap: false,
                unwrap: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: None,
                allowed_mechanisms: None,
                wrap_with_trusted: false,
                policy_templates: crate::KeyPolicyTemplates::default(),
                creator_session: None,
                public_key: None,
                rp_id: None,
                material: KeyMaterial::YubiHsmAttestation {
                    connector: self.connector.clone(),
                    session: self.session.clone(),
                    id: metadata.info.id,
                    algorithm: public_key.algorithm,
                    cache: cache.cache,
                },
            });
        }
        Ok(objects)
    }
    fn refresh_token_objects_after_login(&self) -> bool {
        true
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
    fn supports_protected_authentication_path(&self) -> bool {
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
    fn yubihsm_owned_metadata_objects(
        &self,
        id: u16,
        object_type: u8,
    ) -> Result<Vec<(u16, u8)>, Error> {
        let objects = self.related_metadata_object(id, object_type)?;
        self.metadata_objects_in_format(&objects, YubiHsmMetadataPhysicalFormat::CanonicalCbor)
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
    fn yubihsm_persist_public_projection(
        &self,
        slot_id: CK_SLOT_ID,
        base_unique_id: &str,
        projection: &TokenObject,
    ) -> Result<(), Error> {
        self.persist_public_projection(slot_id, base_unique_id, projection)
    }
    fn yubihsm_destroy_public_projection(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<(), Error> {
        self.destroy_public_projection(slot_id, unique_id)
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
    session: Rc<RefCell<YubiHsmSessionState>>,
}

impl BackendSession for YubiHsmSession {
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
