#[cfg(not(feature = "abi-tests"))]
use crate::configured_yubihsm_public_discovery_credential_with_pinentry;
#[cfg(feature = "native-hardware")]
use crate::ctap_hid::{enumerate_fido_devices, CtapHidTransport};
use crate::device::{DeviceContext, DeviceIdentity, PhysicalDeviceKey};
use crate::pkcs11::*;
use crate::storage::{
    LocalStorageProvider, MemoryStorageProvider, StorageProvider, UnavailableStorageProvider,
};
#[cfg(feature = "mock-yubikey")]
use crate::MockYubiKeyConnector;
#[cfg(feature = "abi-tests")]
use crate::{
    abi_test_piv_slot, abi_test_yubihsm_slots, AbiScp03Slot, AbiTestSlot, ABI_TEST_PIV_SLOT_ID,
    ABI_TEST_SCP03_SLOT_ID, ABI_TEST_SCP11_SLOT_ID,
};
use crate::{
    backed_object::{backed_object_unique_id, put_backed_object, stored_objects},
    ccid_application_label, pinentry, select_application, str_pad, BackendSession, CcidApplication,
    CcidConfiguration, Connector, CryptOperation, DigestOperation, Error, Fido2Slot, FindOperation,
    HsmAuthProviderRegistry, HsmAuthSlot, HttpConnector, HttpConnectorTlsConfig,
    IssuerSecurityDomainSlot, ModuleConfiguration, OpenPgpSlot, PivSlot,
    SecureChannelConfiguration, SharedConnector, SignatureOperation, Slot, SlotKind, SoftwareSlot,
    TokenObject, YubiHsmPublicDiscoveryConfig, YubiHsmSlot, YubiKeyClient,
};
#[cfg(feature = "native-hardware")]
use crate::{HidFidoEndpoint, PcscAppletConnector, PcscConnector, UsbConnector};
#[cfg(any(test, feature = "abi-tests"))]
use crate::{KeyMaterial, PublicKeyMaterial, SoftwarePrivateKeyMaterial, ABI_TEST_SLOT_ID};
#[cfg(any(test, feature = "abi-tests"))]
use rsa::RsaPublicKey;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};
use zeroize::Zeroizing;

const TOKEN_STORAGE_SCHEMA_DIRECTORY: &str = "tokens-v1";
const FIDO2_STORAGE_SCHEMA_DIRECTORY: &str = "fido2-v1";

#[derive(Clone, Debug)]
pub(crate) struct TokenStorageConfig {
    root: PathBuf,
}

impl TokenStorageConfig {
    fn open(root: PathBuf) -> Result<Self, Error> {
        validate_storage_root(&root)?;
        Ok(Self { root })
    }

    fn token_root(&self, key: &PhysicalDeviceKey, kind: SlotKind) -> PathBuf {
        self.root
            .join(TOKEN_STORAGE_SCHEMA_DIRECTORY)
            .join(physical_device_directory(key))
            .join(slot_storage_directory(kind))
    }

    fn provider(
        &self,
        key: &PhysicalDeviceKey,
        kind: SlotKind,
    ) -> Result<LocalStorageProvider, Error> {
        LocalStorageProvider::open(self.token_root(key, kind))
            .map_err(crate::backed_object::storage_error)
    }

    pub(crate) fn software_token_root(&self, name: &str) -> PathBuf {
        self.root.join(TOKEN_STORAGE_SCHEMA_DIRECTORY).join(format!(
            "software-name-{}",
            encode_path_component(name.as_bytes())
        ))
    }

    #[cfg(test)]
    fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FidoStorageConfig {
    root: PathBuf,
}

impl FidoStorageConfig {
    fn open(root: PathBuf) -> Result<Self, Error> {
        validate_storage_root(&root)?;
        Ok(Self { root })
    }

    fn token_root(&self, key: &PhysicalDeviceKey) -> PathBuf {
        self.root
            .join(FIDO2_STORAGE_SCHEMA_DIRECTORY)
            .join(physical_device_directory(key))
    }

    fn provider(&self, key: &PhysicalDeviceKey) -> Result<LocalStorageProvider, Error> {
        LocalStorageProvider::open(self.token_root(key))
            .map_err(crate::backed_object::storage_error)
    }

    #[cfg(test)]
    fn root(&self) -> &std::path::Path {
        &self.root
    }
}

fn validate_storage_root(root: &std::path::Path) -> Result<(), Error> {
    std::fs::create_dir_all(root)?;
    if !std::fs::metadata(root)?.is_dir() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(())
}

fn configured_storage_root<T>(
    value: Option<std::ffi::OsString>,
    open: impl FnOnce(PathBuf) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let root = PathBuf::from(value);
    if !root.is_absolute() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    open(root).map(Some)
}

pub(crate) fn configured_token_storage(
    value: Option<std::ffi::OsString>,
) -> Result<Option<TokenStorageConfig>, Error> {
    configured_storage_root(value, TokenStorageConfig::open)
}

pub(crate) fn configured_fido_storage(
    value: Option<std::ffi::OsString>,
) -> Result<Option<FidoStorageConfig>, Error> {
    configured_storage_root(value, FidoStorageConfig::open)
}

fn physical_device_directory(key: &PhysicalDeviceKey) -> String {
    match key {
        PhysicalDeviceKey::YubicoSerial(serial) => {
            format!("yubico-serial-{}", encode_path_component(serial.as_bytes()))
        }
    }
}

fn slot_storage_directory(kind: SlotKind) -> &'static str {
    match kind {
        #[cfg(any(test, feature = "abi-tests"))]
        SlotKind::Synthetic => "synthetic",
        SlotKind::Software => "software",
        SlotKind::YubiHsm => "yubihsm",
        SlotKind::Fido2 | SlotKind::Ccid(CcidApplication::Fido2) => "fido2",
        SlotKind::Ccid(CcidApplication::Piv) => "piv",
        SlotKind::Ccid(CcidApplication::OpenPgp) => "openpgp",
        SlotKind::Ccid(CcidApplication::HsmAuth) => "yubihsm-auth",
        SlotKind::Ccid(CcidApplication::IssuerSecurityDomain) => "issuer-security-domain",
    }
}

fn encode_path_component(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn token_storage_for_slot(
    slot: &dyn Slot,
    token_storage: Option<&TokenStorageConfig>,
    fido_storage: Option<&FidoStorageConfig>,
) -> Result<Box<dyn StorageProvider>, Error> {
    if slot.kind() == SlotKind::YubiHsm {
        return Ok(Box::new(UnavailableStorageProvider));
    }
    if slot.kind() == SlotKind::Software {
        return Ok(Box::new(UnavailableStorageProvider));
    }
    let configured =
        token_storage.is_some() || (slot.kind() == SlotKind::Fido2 && fido_storage.is_some());
    if !configured {
        return Ok(Box::new(UnavailableStorageProvider));
    }
    let Some(key) = slot.physical_device_key() else {
        log!(
            1,
            "Token persistence disabled for {} because no stable physical token identity is available",
            slot.name()
        );
        return Ok(Box::new(UnavailableStorageProvider));
    };
    let provider = if let Some(config) = token_storage {
        config.provider(&key, slot.kind())?
    } else {
        fido_storage.ok_or(CKR_GENERAL_ERROR)?.provider(&key)?
    };
    log!(
        2,
        "Token persistence for {} uses {:?}",
        slot.name(),
        provider.root()
    );
    Ok(Box::new(provider))
}

pub(crate) fn configured_yubihsm_http_tls(
    certificate_bundle_path: Option<std::ffi::OsString>,
    private_key_path: Option<std::ffi::OsString>,
    ca_certificate_bundle_path: Option<std::ffi::OsString>,
    pinentry: &pinentry::Pinentry,
) -> Result<HttpConnectorTlsConfig, Error> {
    let mut tls = match (certificate_bundle_path, private_key_path) {
        (None, None) => HttpConnectorTlsConfig::default(),
        (Some(certificate_bundle_path), Some(private_key_path))
            if !certificate_bundle_path.is_empty() && !private_key_path.is_empty() =>
        {
            let certificate_bundle = std::fs::read(certificate_bundle_path)?;
            let encrypted_private_key = std::fs::read(private_key_path)?;
            let private_key = crate::private_key::decrypt_file(
                &encrypted_private_key,
                pinentry,
                "Unlock the YubiHSM TLS client private key",
            )?;
            HttpConnectorTlsConfig::from_client_identity(&certificate_bundle, &private_key)?
        }
        _ => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    if let Some(ca_certificate_bundle_path) = ca_certificate_bundle_path {
        if ca_certificate_bundle_path.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let certificate_bundle = std::fs::read(ca_certificate_bundle_path)?;
        tls = tls.with_ca_bundle(&certificate_bundle)?;
    }
    Ok(tls)
}

// Initialized module resources and the registry of independently locked slots.
// The registry lock protects lazy discovery and session-handle routing; slot
// operations release it before taking an individual SlotContext lock.
pub(crate) struct ModuleContext {
    pub(crate) debug_level: u8,
    pub(crate) hardware_discovery: bool,
    pub(crate) yubihsm_usb: bool,
    pub(crate) software_slots: Vec<String>,
    pub(crate) software_discovery_pins: HashMap<String, Zeroizing<Vec<u8>>>,
    #[cfg(feature = "native-hardware")]
    pub(crate) pcsc: Option<pcsc::Context>,
    pub(crate) yubihsm_urls: Vec<String>,
    pub(crate) yubihsm_http_tls: HttpConnectorTlsConfig,
    pub(crate) yubihsm_public_discovery_config: Option<Arc<YubiHsmPublicDiscoveryConfig>>,
    pub(crate) yubihsm_device_trust_prefix: std::ffi::OsString,
    pub(crate) ccid_configurations: Vec<CcidConfiguration>,
    pub(crate) ccid_aids: crate::configuration::CcidAidConfiguration,
    pub(crate) secure_channels: Arc<SecureChannelConfiguration>,
    pub(crate) token_storage: Option<TokenStorageConfig>,
    pub(crate) fido_storage: Option<FidoStorageConfig>,
    pub(crate) handles: Arc<HandleCounters>,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
    pub(crate) trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    pub(crate) slot_contexts: RwLock<SlotContextRegistry>,
}

// Mutable token state shared by every PKCS #11 session opened on this slot.
pub(crate) struct SlotContext {
    pub(crate) slot_id: CK_SLOT_ID,
    pub(crate) slot: Box<dyn Slot>,
    pub(crate) device: Option<Arc<crate::device::DeviceContext>>,
    pub(crate) device_operation_kind: crate::device::DeviceOperationKind,
    handles: Arc<HandleCounters>,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
    pub(crate) trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    token_storage: Box<dyn StorageProvider>,
    pub(crate) sessions: HashMap<CK_SESSION_HANDLE, SessionContext>,
    pub(crate) login_role: Option<LoginRole>,
    pub(crate) memory_objects: HashMap<CK_OBJECT_HANDLE, TokenObject>,
    pub(crate) token_object_handles: HashMap<CK_OBJECT_HANDLE, TokenObjectLocator>,
    backed_token_objects: HashMap<String, TokenObject>,
    backed_object_references: HashMap<String, crate::storage::ContentReference>,
    backed_object_handles: HashMap<CK_OBJECT_HANDLE, crate::storage::ContentReference>,
}

// Mutable PKCS #11 operation state belonging to one application session.
pub(crate) struct SessionContext {
    backend: Box<dyn BackendSession>,
    storage: MemoryStorageProvider,
    pub(crate) find_operation: Option<FindOperation>,
    pub(crate) digest_operation: Option<DigestOperation>,
    pub(crate) encrypt_operation: Option<CryptOperation>,
    pub(crate) decrypt_operation: Option<CryptOperation>,
    pub(crate) sign_operation: Option<SignatureOperation>,
    pub(crate) verify_operation: Option<SignatureOperation>,
}

pub(crate) struct SlotContextRegistry {
    slots: HashMap<CK_SLOT_ID, Arc<Mutex<SlotContext>>>,
    session_slots: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    discovered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FidoDuplicateResolution {
    Independent,
    KeepSecuredCcid(CK_SLOT_ID),
    ReplaceCcidWithHid(CK_SLOT_ID),
}

fn resolve_fido_duplicate(
    ccid_slots: &HashMap<PhysicalDeviceKey, (CK_SLOT_ID, bool)>,
    key: &PhysicalDeviceKey,
) -> FidoDuplicateResolution {
    match ccid_slots.get(key).copied() {
        Some((slot_id, true)) => FidoDuplicateResolution::KeepSecuredCcid(slot_id),
        Some((slot_id, false)) => FidoDuplicateResolution::ReplaceCcidWithHid(slot_id),
        None => FidoDuplicateResolution::Independent,
    }
}

fn hid_device_context(
    pcsc_devices: &HashMap<PhysicalDeviceKey, Arc<DeviceContext>>,
    identity: DeviceIdentity,
) -> (Arc<DeviceContext>, bool) {
    match identity
        .physical_key()
        .and_then(|key| pcsc_devices.get(&key))
    {
        Some(device) => (device.clone(), true),
        None => (Arc::new(DeviceContext::new(identity)), false),
    }
}

impl SlotContextRegistry {
    fn new() -> Self {
        Self {
            slots: HashMap::new(),
            session_slots: HashMap::new(),
            discovered: false,
        }
    }

    fn begin_discovery(&mut self) -> bool {
        if self.discovered {
            return false;
        }
        self.discovered = true;
        true
    }

    pub(crate) fn register_session(
        &mut self,
        session_handle: CK_SESSION_HANDLE,
        slot_id: CK_SLOT_ID,
    ) -> Result<(), Error> {
        if !self.slots.contains_key(&slot_id) {
            return Err(CKR_SESSION_HANDLE_INVALID.into());
        }
        match self.session_slots.entry(session_handle) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(slot_id);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(CKR_SESSION_HANDLE_INVALID.into());
            }
        }
        Ok(())
    }

    pub(crate) fn unregister_session(&mut self, session_handle: CK_SESSION_HANDLE) {
        self.session_slots.remove(&session_handle);
    }

    pub(crate) fn session_slot(&self, session_handle: CK_SESSION_HANDLE) -> Option<CK_SLOT_ID> {
        self.session_slots.get(&session_handle).copied()
    }

    fn insert_yubihsm_slot_context(&mut self, slot_id: CK_SLOT_ID, context: SlotContext) {
        self.slots.insert(slot_id, Arc::new(Mutex::new(context)));
    }

    fn insert_slot_contexts(
        &mut self,
        slots: Vec<(CK_SLOT_ID, Box<dyn Slot>, Vec<TokenObject>)>,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
        token_storage: Option<&TokenStorageConfig>,
        fido_storage: Option<&FidoStorageConfig>,
    ) -> Result<Vec<CK_SLOT_ID>, Error> {
        // Each discovered application or authenticator is a separate PKCS
        // token with its own logical state.
        let slot_ids = slots
            .iter()
            .map(|(slot_id, _, _)| *slot_id)
            .collect::<Vec<_>>();
        let distinct_slot_ids = slot_ids.iter().copied().collect::<HashSet<_>>();
        if slot_ids.is_empty()
            || distinct_slot_ids.len() != slot_ids.len()
            || slot_ids
                .iter()
                .any(|slot_id| self.slots.contains_key(slot_id))
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut contexts = Vec::with_capacity(slots.len());
        let mut storage_error = None;
        for (slot_id, slot, token_objects) in slots {
            let configured_storage = token_storage.is_some()
                || (slot.kind() == SlotKind::Fido2 && fido_storage.is_some());
            let context = token_storage_for_slot(slot.as_ref(), token_storage, fido_storage)
                .and_then(|token_storage| {
                    SlotContext::new_with_storage(
                        slot_id,
                        slot,
                        token_objects,
                        handles.clone(),
                        pinentry.clone(),
                        trust_store.clone(),
                        token_storage,
                    )
                });
            match context {
                Ok(context) => contexts.push((slot_id, Arc::new(Mutex::new(context)))),
                Err(error) if configured_storage => {
                    log!(
                        1,
                        "Slot {} rejected its configured storage: {:?}",
                        slot_id,
                        error
                    );
                    storage_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        if contexts.is_empty() {
            return Err(storage_error.unwrap_or_else(|| Error::from(CKR_ARGUMENTS_BAD)));
        }
        let inserted_slot_ids = contexts
            .iter()
            .map(|(slot_id, _)| *slot_id)
            .collect::<Vec<_>>();
        for (slot_id, context) in contexts {
            self.slots.insert(slot_id, context);
        }
        Ok(inserted_slot_ids)
    }

    fn next_slot_id(&self) -> Option<CK_SLOT_ID> {
        self.slots
            .keys()
            .max()
            .copied()
            .map_or(Some(0), |slot_id| slot_id.checked_add(1))
    }
}

impl std::ops::Deref for SlotContextRegistry {
    type Target = HashMap<CK_SLOT_ID, Arc<Mutex<SlotContext>>>;

    fn deref(&self) -> &Self::Target {
        &self.slots
    }
}

impl std::ops::DerefMut for SlotContextRegistry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slots
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TokenObjectLocator {
    pub(crate) unique_id: String,
}

pub(crate) struct HandleCounters {
    next_object: std::sync::atomic::AtomicU64,
    next_session: std::sync::atomic::AtomicU64,
}

impl HandleCounters {
    pub(crate) fn new() -> Self {
        Self {
            next_object: std::sync::atomic::AtomicU64::new(1),
            next_session: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub(crate) fn allocate_object(&self) -> Result<CK_OBJECT_HANDLE, Error> {
        allocate_handle(&self.next_object).map(|handle| handle as CK_OBJECT_HANDLE)
    }

    pub(crate) fn allocate_session(&self) -> Result<CK_SESSION_HANDLE, Error> {
        allocate_handle(&self.next_session).map(|handle| handle as CK_SESSION_HANDLE)
    }

    #[cfg(test)]
    pub(crate) fn set_next_object(&self, handle: u64) {
        self.next_object
            .store(handle, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_next_session(&self, handle: u64) {
        self.next_session
            .store(handle, std::sync::atomic::Ordering::Relaxed);
    }
}

fn allocate_handle(counter: &std::sync::atomic::AtomicU64) -> Result<u64, Error> {
    counter
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |candidate| {
                if candidate == 0 || u128::from(candidate) > u128::from(CK_ULONG::MAX) {
                    return None;
                }
                Some(candidate.wrapping_add(1))
            },
        )
        .map_err(|_| CKR_HOST_MEMORY.into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginRole {
    User,
    So,
}

impl std::fmt::Debug for ModuleContext {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let slot_ids = self
            .slot_contexts
            .try_read()
            .ok()
            .map(|contexts| contexts.keys().copied().collect::<Vec<_>>());
        #[cfg(feature = "native-hardware")]
        let pcsc = self.pcsc.as_ref().map(|_| "Context { .. }");
        #[cfg(not(feature = "native-hardware"))]
        let pcsc: Option<&str> = None;
        fmt.debug_struct("ModuleContext")
            .field("hardware_discovery", &self.hardware_discovery)
            .field("yubihsm_usb", &self.yubihsm_usb)
            .field("software_slots", &self.software_slots)
            .field(
                "software_public_discovery",
                &self.software_discovery_pins.keys().collect::<Vec<_>>(),
            )
            .field("pcsc", &pcsc)
            .field("yubihsm_urls", &self.yubihsm_urls)
            .field("yubihsm_http_tls", &self.yubihsm_http_tls)
            .field(
                "yubihsm_public_discovery_config",
                &self.yubihsm_public_discovery_config,
            )
            .field("token_storage", &self.token_storage)
            .field("fido_storage", &self.fido_storage)
            .field("slot_contexts", &slot_ids)
            .finish()
    }
}

impl std::fmt::Debug for SlotContext {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("SlotContext")
            .field("slot_id", &self.slot_id)
            .field("slot", &self.slot)
            .field("sessions", &self.sessions)
            .field("memory_objects", &self.memory_objects)
            .field("token_object_handles", &self.token_object_handles)
            .finish()
    }
}

impl SessionContext {
    pub(crate) fn new(backend: Box<dyn BackendSession>) -> Self {
        Self {
            backend,
            storage: MemoryStorageProvider::new(),
            find_operation: None,
            digest_operation: None,
            encrypt_operation: None,
            decrypt_operation: None,
            sign_operation: None,
            verify_operation: None,
        }
    }

    fn clear_operations(&mut self) {
        self.find_operation = None;
        self.digest_operation = None;
        self.encrypt_operation = None;
        self.decrypt_operation = None;
        self.sign_operation = None;
        self.verify_operation = None;
    }

    pub(crate) fn backend(&self) -> &(dyn BackendSession + '_) {
        self.backend.as_ref()
    }

    pub(crate) fn crypt_operation(&self, encrypting: bool) -> Option<&CryptOperation> {
        if encrypting {
            self.encrypt_operation.as_ref()
        } else {
            self.decrypt_operation.as_ref()
        }
    }

    pub(crate) fn crypt_operation_mut(&mut self, encrypting: bool) -> Option<&mut CryptOperation> {
        if encrypting {
            self.encrypt_operation.as_mut()
        } else {
            self.decrypt_operation.as_mut()
        }
    }

    pub(crate) fn set_crypt_operation(&mut self, encrypting: bool, operation: CryptOperation) {
        if encrypting {
            self.encrypt_operation = Some(operation);
        } else {
            self.decrypt_operation = Some(operation);
        }
    }

    pub(crate) fn take_crypt_operation(&mut self, encrypting: bool) -> Option<CryptOperation> {
        if encrypting {
            self.encrypt_operation.take()
        } else {
            self.decrypt_operation.take()
        }
    }

    pub(crate) fn clear_crypt_operations(&mut self) {
        self.encrypt_operation = None;
        self.decrypt_operation = None;
    }
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("SessionContext")
            .field("backend", &self.backend)
            .field("find_operation_active", &self.find_operation.is_some())
            .field("digest_operation_active", &self.digest_operation.is_some())
            .field(
                "encrypt_operation_active",
                &self.encrypt_operation.is_some(),
            )
            .field(
                "decrypt_operation_active",
                &self.decrypt_operation.is_some(),
            )
            .field("sign_operation_active", &self.sign_operation.is_some())
            .field("verify_operation_active", &self.verify_operation.is_some())
            .finish()
    }
}

impl ModuleContext {
    #[allow(unused_mut)]
    pub(crate) fn new_with_configuration(
        configuration: ModuleConfiguration,
    ) -> Result<ModuleContext, Error> {
        #[cfg(feature = "abi-tests")]
        let _ = (
            configuration.yubihsm_usb,
            configuration.yubihsm_public_discovery.as_ref(),
        );
        let debug_level = configuration.debug_level;
        let pinentry = Arc::new(pinentry::Pinentry::from_configuration(
            configuration.pinentry,
        )?);
        let handles = Arc::new(HandleCounters::new());
        let trust_store = Arc::new(crate::yubihsm::trust::TrustStore::new_with_prefix(
            configuration.yubihsm_device_trust_prefix.clone(),
        ));
        #[cfg(feature = "abi-tests")]
        let mut slots = HashMap::from([
            (ABI_TEST_SLOT_ID, Box::new(AbiTestSlot) as Box<dyn Slot>),
            (
                ABI_TEST_PIV_SLOT_ID,
                Box::new(abi_test_piv_slot()?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP03_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP03")?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP11_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP11A")?) as Box<dyn Slot>,
            ),
        ]);
        #[cfg(feature = "abi-tests")]
        slots.extend(abi_test_yubihsm_slots()?);
        #[cfg(feature = "native-hardware")]
        let hardware_discovery = configuration.hardware_discovery;
        #[cfg(not(feature = "native-hardware"))]
        let hardware_discovery = false;
        let yubihsm_urls = configuration.yubihsm_urls;
        let software_slots = configuration.software_slots;
        let token_storage = configured_token_storage(configuration.token_storage)?;
        let software_discovery_pins = if token_storage.is_some() {
            configuration.software_discovery_pins
        } else {
            HashMap::new()
        };
        let fido_storage = if token_storage.is_none() {
            configured_fido_storage(configuration.fido2_storage)?
        } else {
            None
        };
        let yubihsm_http_tls = configured_yubihsm_http_tls(
            configuration.yubihsm_tls_client_certificate_bundle,
            configuration.yubihsm_tls_client_private_key,
            configuration.yubihsm_tls_ca_certificate_bundle,
            pinentry.as_ref(),
        )?;
        #[cfg(not(feature = "abi-tests"))]
        let yubihsm_public_discovery_config =
            configured_yubihsm_public_discovery_credential_with_pinentry(
                configuration.yubihsm_public_discovery,
                pinentry.as_ref(),
            )?;
        #[cfg(feature = "abi-tests")]
        let yubihsm_public_discovery_config = None;
        #[cfg(all(not(feature = "abi-tests"), feature = "native-hardware"))]
        let yubihsm_usb = configuration.yubihsm_usb;
        let secure_channels = Arc::new(configuration.secure_channels);
        let mut context = ModuleContext {
            debug_level,
            hardware_discovery,
            #[cfg(any(feature = "abi-tests", not(feature = "native-hardware")))]
            yubihsm_usb: false,
            #[cfg(all(not(feature = "abi-tests"), feature = "native-hardware"))]
            yubihsm_usb,
            software_slots,
            software_discovery_pins,
            #[cfg(all(feature = "native-hardware", feature = "abi-tests"))]
            pcsc: None,
            #[cfg(all(feature = "native-hardware", not(feature = "abi-tests")))]
            pcsc: if hardware_discovery {
                match pcsc::Context::establish(pcsc::Scope::System) {
                    Ok(context) => Some(context),
                    Err(e) => {
                        log!(1, "pcsc::Context::establish: {}", e);
                        None
                    }
                }
            } else {
                None
            },
            yubihsm_urls,
            yubihsm_http_tls,
            yubihsm_public_discovery_config,
            yubihsm_device_trust_prefix: configuration.yubihsm_device_trust_prefix,
            ccid_configurations: configuration.ccid_configurations,
            ccid_aids: configuration.ccid_aids,
            secure_channels,
            token_storage,
            fido_storage,
            handles: handles.clone(),
            pinentry: pinentry.clone(),
            trust_store: trust_store.clone(),
            slot_contexts: RwLock::new(SlotContextRegistry::new()),
        };
        #[cfg(feature = "abi-tests")]
        for (slot_id, slot) in {
            let mut slots = slots.into_iter().collect::<Vec<_>>();
            slots.sort_by_key(|(slot_id, _)| *slot_id);
            slots
        } {
            let discover_objects = !cfg!(test);
            let mut token_objects = if discover_objects {
                slot.token_objects(slot_id)?
            } else {
                Vec::new()
            };
            let initial_token_objects = if slot_id == ABI_TEST_SLOT_ID {
                Vec::new()
            } else {
                std::mem::take(&mut token_objects)
            };
            let mut child = SlotContext::new(
                slot_id,
                slot,
                initial_token_objects,
                handles.clone(),
                pinentry.clone(),
                trust_store.clone(),
            )?;
            if slot_id == ABI_TEST_SLOT_ID {
                let mut objects = default_objects()?.into_iter().collect::<Vec<_>>();
                objects.sort_by_key(|(handle, _)| *handle);
                for (_, object) in objects {
                    child.insert_object(object)?;
                }
                child.reconcile_slot_token_objects(slot_id, token_objects)?;
            }
            context
                .slot_contexts
                .get_mut()
                .map_err(|_| Error::from(CKR_MUTEX_BAD))?
                .insert(slot_id, Arc::new(Mutex::new(child)));
        }
        log!(2, "ModuleContext.new {:?}", context);
        Ok(context)
    }

    fn new_yubihsm_slot_context(
        slot_id: CK_SLOT_ID,
        slot: Box<dyn Slot>,
        discover_objects: bool,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    ) -> Result<SlotContext, Error> {
        let token_objects = if discover_objects && slot.is_present() {
            match slot.token_objects(slot_id) {
                Ok(objects) => objects,
                Err(error) => {
                    log!(2, "YubiHSM public object discovery: {:?}", error);
                    slot.profile_objects(slot_id)
                }
            }
        } else {
            Vec::new()
        };
        SlotContext::new(slot_id, slot, token_objects, handles, pinentry, trust_store)
    }

    #[cfg(test)]
    pub(crate) fn insert_yubihsm_slot(
        &self,
        slot_id: CK_SLOT_ID,
        slot: Box<dyn Slot>,
    ) -> Result<(), Error> {
        let mut slot_contexts = self
            .slot_contexts
            .write()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        Self::insert_yubihsm_slot_with_discovery(
            &mut slot_contexts,
            slot_id,
            slot,
            true,
            self.handles.clone(),
            self.pinentry.clone(),
            self.trust_store.clone(),
        )
    }

    fn insert_yubihsm_slot_with_discovery(
        slot_contexts: &mut SlotContextRegistry,
        slot_id: CK_SLOT_ID,
        slot: Box<dyn Slot>,
        discover_objects: bool,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    ) -> Result<(), Error> {
        let context = Self::new_yubihsm_slot_context(
            slot_id,
            slot,
            discover_objects,
            handles,
            pinentry,
            trust_store,
        )?;
        slot_contexts.insert_yubihsm_slot_context(slot_id, context);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_pcsc_slots(
        &self,
        slots: Vec<(CK_SLOT_ID, Box<dyn Slot>)>,
    ) -> Result<(), Error> {
        let slots = slots
            .into_iter()
            .map(|(slot_id, slot)| {
                let token_objects = slot.token_objects(slot_id)?;
                Ok((slot_id, slot, token_objects))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        self.slot_contexts
            .write()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .insert_slot_contexts(
                slots,
                self.handles.clone(),
                self.pinentry.clone(),
                self.trust_store.clone(),
                self.token_storage.as_ref(),
                self.fido_storage.as_ref(),
            )
            .map(|_| ())
    }
    pub(crate) fn get_info(&self, info: &mut CK_INFO) -> Result<(), Error> {
        info.cryptokiVersion.major = 3;
        info.cryptokiVersion.minor = 2;
        info.libraryVersion.major = 1;
        info.libraryVersion.minor = 0;
        info.flags = 0;
        str_pad(crate::MODULE_DESCRIPTION, &mut info.libraryDescription);
        str_pad(crate::MODULE_MANUFACTURER, &mut info.manufacturerID);
        Ok(())
    }
}

impl SlotContext {
    pub(crate) fn new(
        slot_id: CK_SLOT_ID,
        slot: Box<dyn Slot>,
        token_objects: Vec<TokenObject>,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    ) -> Result<Self, Error> {
        Self::new_with_storage(
            slot_id,
            slot,
            token_objects,
            handles,
            pinentry,
            trust_store,
            Box::new(UnavailableStorageProvider),
        )
    }

    pub(crate) fn new_with_storage(
        slot_id: CK_SLOT_ID,
        slot: Box<dyn Slot>,
        token_objects: Vec<TokenObject>,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
        token_storage: Box<dyn StorageProvider>,
    ) -> Result<Self, Error> {
        let device = slot.device_context();
        let device_operation_kind = slot.device_operation_kind();
        let mut context = Self {
            slot_id,
            slot,
            device,
            device_operation_kind,
            handles,
            pinentry,
            trust_store,
            token_storage,
            sessions: HashMap::new(),
            login_role: None,
            memory_objects: HashMap::new(),
            token_object_handles: HashMap::new(),
            backed_token_objects: HashMap::new(),
            backed_object_references: HashMap::new(),
            backed_object_handles: HashMap::new(),
        };
        let mut token_objects = token_objects;
        let stored = context.stored_token_objects()?;
        context.record_backed_objects(&stored);
        token_objects.extend(stored.into_iter().map(|(_, object)| object));
        context.reconcile_slot_token_objects(slot_id, token_objects)?;
        Ok(context)
    }

    fn token_storage_provider(&self) -> &dyn StorageProvider {
        self.slot
            .native_storage_provider()
            .unwrap_or(self.token_storage.as_ref())
    }

    fn stored_token_objects(
        &self,
    ) -> Result<Vec<(crate::storage::ContentReference, TokenObject)>, Error> {
        if self.slot.native_storage_objects_are_backend_managed() {
            return Ok(Vec::new());
        }
        stored_objects(self.token_storage_provider(), self.slot_id, true)
    }

    fn record_backed_objects(
        &mut self,
        objects: &[(crate::storage::ContentReference, TokenObject)],
    ) {
        self.backed_object_references.clear();
        self.backed_token_objects = objects
            .iter()
            .map(|(_, object)| (object.unique_id.clone(), object.clone()))
            .collect();
        for (reference, object) in objects {
            self.backed_object_references
                .insert(object.unique_id.clone(), reference.clone());
        }
        for (handle, locator) in &self.token_object_handles {
            if let Some(reference) = self.backed_object_references.get(&locator.unique_id) {
                self.backed_object_handles
                    .insert(*handle, reference.clone());
            }
        }
    }

    pub(crate) fn store_backed_object(
        &mut self,
        session_handle: CK_SESSION_HANDLE,
        mut object: TokenObject,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        let reference = if object.token {
            put_backed_object(self.token_storage_provider(), &object)?
        } else {
            let session = self.get_session_context(session_handle)?;
            put_backed_object(&session.storage, &object)?
        };
        if object.token {
            object.unique_id = backed_object_unique_id(&reference);
            self.backed_object_references
                .insert(object.unique_id.clone(), reference.clone());
            let unique_id = object.unique_id.clone();
            self.refresh_slot_token_objects(self.slot_id)?;
            let handle = self
                .token_object_handles
                .iter()
                .find_map(|(handle, locator)| (locator.unique_id == unique_id).then_some(*handle))
                .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))?;
            self.backed_object_handles.insert(handle, reference);
            Ok(handle)
        } else {
            object.set_creator(session_handle, self.slot_id);
            let handle = self.insert_object(object)?;
            self.backed_object_handles.insert(handle, reference);
            Ok(handle)
        }
    }

    fn backed_reference_is_shared(
        &self,
        handle: CK_OBJECT_HANDLE,
        reference: &crate::storage::ContentReference,
        object: &TokenObject,
    ) -> bool {
        self.backed_object_handles
            .iter()
            .any(|(candidate, candidate_reference)| {
                if *candidate == handle || candidate_reference != reference {
                    return false;
                }
                if object.token {
                    self.token_object_handles.contains_key(candidate)
                } else {
                    self.memory_objects.get(candidate).is_some_and(|candidate| {
                        !candidate.token && candidate.creator_session == object.creator_session
                    })
                }
            })
    }

    pub(crate) fn destroy_backed_object(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        object: &TokenObject,
    ) -> Result<bool, Error> {
        let Some(reference) = self
            .backed_object_handles
            .get(&handle)
            .cloned()
            .or_else(|| {
                self.backed_object_references
                    .get(&object.unique_id)
                    .cloned()
            })
        else {
            return Ok(false);
        };
        let shared = self.backed_reference_is_shared(handle, &reference, object);
        let deleted = if shared {
            true
        } else if object.token {
            self.token_storage_provider()
                .delete(&reference)
                .map_err(crate::backed_object::storage_error)?
        } else {
            let creator = object.creator_session.ok_or(CKR_DEVICE_ERROR)?;
            self.get_session_context(creator)?
                .storage
                .delete(&reference)
                .map_err(crate::backed_object::storage_error)?
        };
        if !deleted {
            return Err(CKR_DEVICE_ERROR.into());
        }
        self.backed_object_handles.remove(&handle);
        if object.token {
            self.backed_object_references.remove(&object.unique_id);
        }
        if object.token {
            self.refresh_slot_token_objects(self.slot_id)?;
        } else {
            self.remove_object_handle(handle);
        }
        Ok(true)
    }

    pub(crate) fn replace_backed_object(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        previous: &TokenObject,
        mut replacement: TokenObject,
    ) -> Result<bool, Error> {
        let Some(previous_reference) =
            self.backed_object_handles
                .get(&handle)
                .cloned()
                .or_else(|| {
                    self.backed_object_references
                        .get(&previous.unique_id)
                        .cloned()
                })
        else {
            return Ok(false);
        };
        let replacement_reference = if replacement.token {
            put_backed_object(self.token_storage_provider(), &replacement)?
        } else {
            let creator = previous.creator_session.ok_or(CKR_DEVICE_ERROR)?;
            put_backed_object(&self.get_session_context(creator)?.storage, &replacement)?
        };
        let shared = self.backed_reference_is_shared(handle, &previous_reference, previous);
        if replacement_reference != previous_reference && !shared {
            let deleted = if replacement.token {
                self.token_storage_provider()
                    .delete(&previous_reference)
                    .map_err(crate::backed_object::storage_error)?
            } else {
                let creator = previous.creator_session.ok_or(CKR_DEVICE_ERROR)?;
                self.get_session_context(creator)?
                    .storage
                    .delete(&previous_reference)
                    .map_err(crate::backed_object::storage_error)?
            };
            if !deleted {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }
        if replacement.token {
            self.backed_object_references.remove(&previous.unique_id);
            replacement.unique_id = backed_object_unique_id(&replacement_reference);
            self.backed_object_references
                .insert(replacement.unique_id.clone(), replacement_reference.clone());
        } else {
            replacement.unique_id = previous.unique_id.clone();
        }
        self.backed_object_handles
            .insert(handle, replacement_reference);
        if replacement.token {
            let mut objects = self.slot.token_objects(self.slot_id)?;
            let stored = self.stored_token_objects()?;
            self.record_backed_objects(&stored);
            objects.extend(stored.into_iter().map(|(_, object)| object));
            self.reconcile_slot_token_objects_with_rebindings(
                self.slot_id,
                objects,
                &[(handle, replacement.unique_id)],
            )?;
        } else {
            let creator = previous.creator_session.ok_or(CKR_DEVICE_ERROR)?;
            replacement.set_creator(creator, self.slot_id);
            self.memory_objects.insert(handle, replacement);
        }
        Ok(true)
    }

    fn require_slot_id(&self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        if slot_id == self.slot_id {
            Ok(())
        } else {
            Err(CKR_SLOT_ID_INVALID.into())
        }
    }

    pub(crate) fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        self.require_slot_id(slot_id)?;
        Ok(self.slot.as_ref())
    }
    pub(crate) fn get_present_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        let slot = self.get_slot(slot_id)?;
        if slot.is_present() {
            Ok(slot)
        } else {
            Err(CKR_TOKEN_NOT_PRESENT.into())
        }
    }
    pub(crate) fn _get_slot_mut(
        &mut self,
        slot_id: CK_SLOT_ID,
    ) -> Result<&mut (dyn Slot + '_), Error> {
        self.require_slot_id(slot_id)?;
        Ok(self.slot.as_mut())
    }
    pub(crate) fn get_session_(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Option<(&(dyn Slot + '_), &(dyn BackendSession + '_))> {
        let session = self.sessions.get(&session_handle)?;
        (session.backend().slotID() == self.slot_id)
            .then_some((self.slot.as_ref(), session.backend()))
    }
    pub(crate) fn _get_session(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(&(dyn Slot + '_), &(dyn BackendSession + '_)), Error> {
        match self.get_session_(session_handle) {
            Some(ctx) => Ok(ctx),
            None => Err(CKR_SESSION_HANDLE_INVALID.into()),
        }
    }
    pub(crate) fn get_session_context(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<&SessionContext, Error> {
        let session = self
            .sessions
            .get(&session_handle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if session.backend().slotID() != self.slot_id {
            return Err(CKR_SESSION_HANDLE_INVALID.into());
        }
        Ok(session)
    }
    pub(crate) fn get_session_context_mut(
        &mut self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<&mut SessionContext, Error> {
        let session = self
            .sessions
            .get_mut(&session_handle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if session.backend().slotID() != self.slot_id {
            return Err(CKR_SESSION_HANDLE_INVALID.into());
        }
        Ok(session)
    }
    pub(crate) fn session_details(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(CK_SLOT_ID, CK_FLAGS, bool), Error> {
        let session = self._get_session(session_handle)?.1;
        let slot_id = session.slotID();
        Ok((
            slot_id,
            session.flags(),
            !self.slot.private_objects_require_login()
                || self.login_role(slot_id) == Some(LoginRole::User),
        ))
    }

    pub(crate) fn login_role(&self, slot_id: CK_SLOT_ID) -> Option<LoginRole> {
        (slot_id == self.slot_id && self.slot.login_is_active())
            .then_some(self.login_role)
            .flatten()
    }

    pub(crate) fn is_slot_logged_in(&self, slot_id: CK_SLOT_ID) -> bool {
        self.login_role(slot_id).is_some()
    }

    pub(crate) fn is_slot_user_logged_in(&self, slot_id: CK_SLOT_ID) -> bool {
        self.login_role(slot_id) == Some(LoginRole::User)
    }

    pub(crate) fn reconcile_login_state(&mut self, slot_id: CK_SLOT_ID) {
        if self.login_role.is_some() && !self.is_slot_logged_in(slot_id) {
            self.clear_login_state(slot_id);
        }
    }

    pub(crate) fn insert_object(
        &mut self,
        mut object: TokenObject,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        let handle = self.handles.allocate_object()?;
        if object.unique_id.is_empty() {
            object.unique_id = handle.to_string();
        }
        self.memory_objects.insert(handle, object);
        Ok(handle)
    }

    pub(crate) fn resolve_object(
        &self,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<Option<TokenObject>, Error> {
        if let Some(object) = self.memory_objects.get(&handle) {
            return Ok(Some(object.clone()));
        }
        let Some(locator) = self.token_object_handles.get(&handle) else {
            return Ok(None);
        };
        if let Some(object) = self.backed_token_objects.get(&locator.unique_id) {
            return Ok(Some(object.clone()));
        }
        self.slot.token_object(self.slot_id, &locator.unique_id)
    }

    pub(crate) fn is_native_token_object_handle(&self, handle: CK_OBJECT_HANDLE) -> bool {
        self.token_object_handles.contains_key(&handle)
            && !self.backed_object_handles.contains_key(&handle)
    }

    pub(crate) fn resolved_objects(&self) -> Result<Vec<(CK_OBJECT_HANDLE, TokenObject)>, Error> {
        let mut objects = self
            .memory_objects
            .iter()
            .map(|(handle, object)| (*handle, object.clone()))
            .collect::<Vec<_>>();
        let mut token_objects = self
            .slot
            .token_objects(self.slot_id)?
            .into_iter()
            .filter(|object| object.token)
            .map(|object| (object.unique_id.clone(), object))
            .collect::<HashMap<_, _>>();
        token_objects.extend(self.backed_token_objects.clone());
        for (handle, locator) in &self.token_object_handles {
            if let Some(object) = token_objects.get(&locator.unique_id) {
                objects.push((*handle, object.clone()));
            }
        }
        Ok(objects)
    }

    pub(crate) fn remove_object_handle(&mut self, handle: CK_OBJECT_HANDLE) {
        self.backed_object_handles.remove(&handle);
        if let Some(object) = self.memory_objects.remove(&handle) {
            if !object.token {
                self.backed_object_references.remove(&object.unique_id);
            }
        }
        self.token_object_handles.remove(&handle);
        for session in self.sessions.values_mut() {
            if let Some(operation) = &mut session.find_operation {
                let already_returned = operation.next.min(operation.objects.len());
                let removed_before_cursor = operation.objects[..already_returned]
                    .iter()
                    .filter(|&&candidate| candidate == handle)
                    .count();
                operation.objects.retain(|&candidate| candidate != handle);
                operation.next -= removed_before_cursor;
            }
        }
    }

    pub(crate) fn reconcile_slot_token_objects(
        &mut self,
        slot_id: CK_SLOT_ID,
        objects: Vec<TokenObject>,
    ) -> Result<(), Error> {
        self.reconcile_slot_token_objects_with_rebindings(slot_id, objects, &[])
    }

    pub(crate) fn reconcile_slot_token_objects_with_rebindings(
        &mut self,
        slot_id: CK_SLOT_ID,
        objects: Vec<TokenObject>,
        rebindings: &[(CK_OBJECT_HANDLE, String)],
    ) -> Result<(), Error> {
        self.require_slot_id(slot_id)?;
        let mut objects_by_id = HashMap::new();
        for object in objects.into_iter().filter(|object| object.token) {
            if object.unique_id.is_empty()
                || objects_by_id
                    .insert(object.unique_id.clone(), object)
                    .is_some()
            {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }

        let rebound_handles = rebindings
            .iter()
            .map(|(handle, _)| *handle)
            .collect::<HashSet<_>>();
        let rebound_ids = rebindings
            .iter()
            .map(|(_, unique_id)| unique_id.as_str())
            .collect::<HashSet<_>>();
        for (handle, unique_id) in rebindings {
            if !self.token_object_handles.contains_key(handle) {
                return Err(CKR_OBJECT_HANDLE_INVALID.into());
            }
            if !objects_by_id.contains_key(unique_id) {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }
        let conflicts = self
            .token_object_handles
            .iter()
            .filter_map(|(handle, locator)| {
                (rebound_ids.contains(locator.unique_id.as_str())
                    && !rebound_handles.contains(handle))
                .then_some(*handle)
            })
            .collect::<Vec<_>>();
        for handle in conflicts {
            self.remove_object_handle(handle);
        }
        for (handle, unique_id) in rebindings {
            self.token_object_handles
                .get_mut(handle)
                .ok_or(CKR_OBJECT_HANDLE_INVALID)?
                .unique_id = unique_id.clone();
        }

        let removed = self
            .token_object_handles
            .iter()
            .filter_map(|(handle, locator)| {
                (!objects_by_id.contains_key(&locator.unique_id)).then_some(*handle)
            })
            .collect::<Vec<_>>();
        for handle in removed {
            self.remove_object_handle(handle);
        }
        let existing = self
            .token_object_handles
            .values()
            .map(|locator| locator.unique_id.clone())
            .collect::<HashSet<_>>();
        let mut new_unique_ids = objects_by_id
            .keys()
            .filter(|unique_id| !existing.contains(*unique_id))
            .cloned()
            .collect::<Vec<_>>();
        new_unique_ids.sort();
        for unique_id in new_unique_ids {
            self.token_object_handles.insert(
                self.handles.allocate_object()?,
                TokenObjectLocator { unique_id },
            );
        }
        Ok(())
    }

    pub(crate) fn refresh_slot_token_objects(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self.require_slot_id(slot_id)?;
        let mut objects = self.slot.token_objects(slot_id)?;
        let stored = self.stored_token_objects()?;
        self.record_backed_objects(&stored);
        objects.extend(stored.into_iter().map(|(_, object)| object));
        self.reconcile_slot_token_objects(slot_id, objects)
    }

    pub(crate) fn init_token(
        &mut self,
        so_pin: &[u8],
        label: [CK_UTF8CHAR; 32],
    ) -> Result<(), Error> {
        if !self.sessions.is_empty() {
            return Err(CKR_SESSION_EXISTS.into());
        }
        self.slot.init_token(so_pin, label)?;
        self.login_role = None;
        self.refresh_slot_token_objects(self.slot_id)
    }

    #[cfg(test)]
    pub(crate) fn set_token_storage_provider(
        &mut self,
        provider: Box<dyn StorageProvider>,
    ) -> Result<(), Error> {
        if self.slot.native_storage_provider().is_some() {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        self.token_storage = provider;
        self.refresh_slot_token_objects(self.slot_id)
    }

    pub(crate) fn insert_session_objects(
        &mut self,
        slot_id: CK_SLOT_ID,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        self.require_slot_id(slot_id)?;
        let objects = self.slot.session_objects(slot_id)?;
        for mut object in objects.into_iter().filter(|object| !object.token) {
            if !object.unique_id.is_empty()
                && self
                    .memory_objects
                    .values()
                    .any(|existing| !existing.token && existing.unique_id == object.unique_id)
            {
                continue;
            }
            object.set_creator(session_handle, slot_id);
            self.insert_object(object)?;
        }
        Ok(())
    }

    pub(crate) fn clear_login_state(&mut self, slot_id: CK_SLOT_ID) {
        if self.require_slot_id(slot_id).is_err() {
            return;
        }
        self.login_role = None;
        for session in self.sessions.values_mut() {
            session.clear_operations();
        }
        self.memory_objects
            .retain(|_, object| object.token || !object.private);
    }

    pub(crate) fn logout_slot(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self._get_slot_mut(slot_id)?.logout()?;
        self.clear_login_state(slot_id);
        if self.get_slot(slot_id)?.refresh_token_objects_after_logout() {
            self.refresh_slot_token_objects(slot_id)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn close_slot_state(&mut self, slot_id: CK_SLOT_ID, remove_token_objects: bool) {
        if self.require_slot_id(slot_id).is_err() {
            return;
        }
        self.login_role = None;
        self.slot.clear_session();
        self.sessions.clear();
        self.memory_objects
            .retain(|_, object| !remove_token_objects && object.token);
        if remove_token_objects {
            let handles = self
                .token_object_handles
                .keys()
                .copied()
                .collect::<Vec<_>>();
            for handle in handles {
                self.remove_object_handle(handle);
            }
        }
    }
}

impl ModuleContext {
    #[allow(unreachable_code)]
    pub(crate) fn init(&self) -> Result<(), Error> {
        let mut slot_contexts = self
            .slot_contexts
            .write()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        if !slot_contexts.begin_discovery() {
            return Ok(());
        }
        if !self.software_slots.is_empty() {
            let first_slot_id = slot_contexts.next_slot_id().ok_or(CKR_DEVICE_ERROR)?;
            let mut slots = Vec::with_capacity(self.software_slots.len());
            for (ordinal, name) in self.software_slots.iter().enumerate() {
                let offset = CK_SLOT_ID::try_from(ordinal).map_err(|_| CKR_DEVICE_ERROR)?;
                let slot_id = first_slot_id.checked_add(offset).ok_or(CKR_DEVICE_ERROR)?;
                let private_root = self
                    .token_storage
                    .as_ref()
                    .map(|config| config.software_token_root(name));
                let mut slot = Box::new(SoftwareSlot::new_with_storage(
                    name.clone(),
                    ordinal,
                    private_root,
                    self.software_discovery_pins
                        .get(name)
                        .map(|pin| pin.as_slice().to_vec()),
                )?) as Box<dyn Slot>;
                slot.init_slot()?;
                let token_objects = slot.token_objects(slot_id)?;
                slots.push((slot_id, slot, token_objects));
            }
            slot_contexts.insert_slot_contexts(
                slots,
                self.handles.clone(),
                self.pinentry.clone(),
                self.trust_store.clone(),
                self.token_storage.as_ref(),
                None,
            )?;
        }
        #[cfg(feature = "abi-tests")]
        {
            return Ok(());
        }
        #[cfg(feature = "mock-yubikey")]
        {
            let connector = Rc::new(MockYubiKeyConnector::process_device()?);
            select_application(connector.as_ref(), &crate::ctap::FIDO2_AID)?;
            let slot_id = slot_contexts.next_slot_id().ok_or(CKR_DEVICE_ERROR)?;
            let device = Arc::new(crate::device::DeviceContext::new(
                crate::device::DeviceIdentity {
                    manufacturer: String::from("Yubico"),
                    product: String::from("Mock YubiKey FIDO2"),
                    serial: String::from("MOCK0001"),
                    hardware_version: Some((1, 0)),
                    firmware_version: None,
                },
            ));
            let mut slot = Box::new(Fido2Slot::new_with_device(
                connector,
                crate::ctap::FIDO2_AID.to_vec(),
                device,
            )) as Box<dyn Slot>;
            slot.init_slot()?;
            let token_objects = slot.token_objects(slot_id)?;
            slot_contexts.insert_slot_contexts(
                vec![(slot_id, slot, token_objects)],
                self.handles.clone(),
                self.pinentry.clone(),
                self.trust_store.clone(),
                self.token_storage.as_ref(),
                self.fido_storage.as_ref(),
            )?;
            // A mock build is a deterministic, self-contained PKCS #11
            // artifact. Do not mix its synthetic slot with USB, HTTP, or
            // PC/SC hardware discovery.
            return Ok(());
        }
        let hsmauth_providers = Arc::new(HsmAuthProviderRegistry::default());
        #[cfg(feature = "native-hardware")]
        let mut ccid_fido_slots: HashMap<PhysicalDeviceKey, (CK_SLOT_ID, bool)> = HashMap::new();
        #[cfg(feature = "native-hardware")]
        let mut pcsc_devices: HashMap<PhysicalDeviceKey, Arc<DeviceContext>> = HashMap::new();
        #[cfg(feature = "native-hardware")]
        if self.yubihsm_usb {
            let candidates = match pkcs11rs_local_hardware::yubihsm_candidates_blocking() {
                Ok(candidates) => Some(candidates),
                Err(error) => {
                    log!(1, "YubiHSM USB enumeration: {}", error);
                    None
                }
            };
            for candidate in candidates.into_iter().flatten() {
                let mut connector: UsbConnector = match candidate.open_blocking() {
                    Ok(connector) => connector,
                    Err(error) => {
                        log!(1, "YubiHSM USB open: {}", error);
                        continue;
                    }
                };
                let name = connector.name();
                log!(2, "{}", name);
                if slot_contexts.values().any(|context| {
                    context
                        .lock()
                        .ok()
                        .map(|context| context.slot.name() == name)
                        .unwrap_or(false)
                }) {
                    continue;
                }
                if let Err(error) = connector.connect_blocking() {
                    log!(1, "YubiHSM USB claim interface: {}", error);
                    continue;
                }
                let Some(slot_id) = slot_contexts.next_slot_id() else {
                    log!(1, "YubiHSM slot ID space exhausted");
                    continue;
                };
                let mut yubihsm_slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
                    Rc::new(connector),
                    (0, 0, 0),
                    Vec::new(),
                    hsmauth_providers.clone(),
                    self.yubihsm_public_discovery_config.clone(),
                );
                yubihsm_slot.set_pinentry(self.pinentry.clone());
                yubihsm_slot.trust_prefix = Some(self.yubihsm_device_trust_prefix.clone());
                let mut slot = Box::new(yubihsm_slot);
                if let Err(error) = slot.init_slot() {
                    log!(1, "YubiHSM GET DEVICE INFO: {:?}", error);
                    continue;
                }
                if let Err(error) = Self::insert_yubihsm_slot_with_discovery(
                    &mut slot_contexts,
                    slot_id,
                    slot,
                    true,
                    self.handles.clone(),
                    self.pinentry.clone(),
                    self.trust_store.clone(),
                ) {
                    log!(1, "YubiHSM slot registration: {:?}", error);
                    continue;
                }
            }
        }
        // Remote connector slots are explicitly configured and remain
        // independent of automatic local hardware discovery.
        for url in self.yubihsm_urls.clone() {
            let connectors =
                match HttpConnector::discover_with_tls(url.clone(), &self.yubihsm_http_tls) {
                    Ok(connectors) => connectors,
                    Err(error) => {
                        log!(1, "YubiHSM connector discovery at {url}: {:?}", error);
                        continue;
                    }
                };
            for mut connector in connectors {
                let connected = match connector.connect() {
                    Ok(()) => true,
                    Err(error) => {
                        log!(1, "YubiHSM connector connection to {url}: {:?}", error);
                        false
                    }
                };
                let name = connector.name();
                log!(2, "{} at {}", name, url);
                let Some(slot_id) = slot_contexts.next_slot_id() else {
                    log!(1, "YubiHSM connector slot ID space exhausted");
                    break;
                };
                let connector = Rc::new(connector);
                let mut yubihsm_slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
                    connector.clone(),
                    (0, 0, 0),
                    Vec::new(),
                    hsmauth_providers.clone(),
                    self.yubihsm_public_discovery_config.clone(),
                );
                yubihsm_slot.set_pinentry(self.pinentry.clone());
                yubihsm_slot.trust_prefix = Some(self.yubihsm_device_trust_prefix.clone());
                let mut slot = Box::new(yubihsm_slot);
                if connected {
                    if let Err(error) = slot.init_slot() {
                        log!(1, "YubiHSM GET DEVICE INFO through {url}: {:?}", error);
                        connector.set_unavailable();
                    }
                }
                if let Err(error) = Self::insert_yubihsm_slot_with_discovery(
                    &mut slot_contexts,
                    slot_id,
                    slot,
                    true,
                    self.handles.clone(),
                    self.pinentry.clone(),
                    self.trust_store.clone(),
                ) {
                    log!(
                        1,
                        "YubiHSM connector slot registration for {url}: {:?}",
                        error
                    );
                    continue;
                }
            }
        }
        #[cfg(feature = "native-hardware")]
        if let Some(context) = self.pcsc.clone() {
            if let Ok(readers) = context.list_readers_owned() {
                for reader in readers {
                    let connector = PcscConnector {
                        reader,
                        context: context.clone(),
                        state: Arc::new(Default::default()),
                    };
                    let name = connector.name();
                    if let Err(error) = connector.refresh() {
                        log!(1, "PCSC reader {} has no usable card: {:?}", name, error);
                        continue;
                    }
                    log!(2, "PCSC reader {} opened", name);
                    match YubiKeyClient.discover(&connector) {
                        Ok(info) => {
                            if let Err(error) = connector.set_yubikey_device_info(info) {
                                log!(
                                    1,
                                    "YubiKey physical-device identity for {}: {:?}",
                                    name,
                                    error
                                );
                            }
                        }
                        Err(error) => log!(
                            2,
                            "YubiKey Management device-information discovery failed on {}: {:?}",
                            name,
                            error
                        ),
                    }
                    let connection_epoch = connector.connection_epoch();
                    if let Some(key) = connector
                        .state
                        .device
                        .identity(connection_epoch)
                        .physical_key()
                    {
                        pcsc_devices
                            .entry(key)
                            .or_insert_with(|| connector.state.device.clone());
                    }
                    let configurations = self.ccid_configurations.clone();
                    let reader_state = connector.state.clone();
                    let base_connector: SharedConnector = Arc::new(connector);
                    let mut reader_slots = Vec::new();
                    let mut reader_fido_slots = Vec::new();
                    let Some(mut next_reader_slot_id) = slot_contexts.next_slot_id() else {
                        log!(1, "PCSC slot ID space exhausted");
                        break;
                    };
                    for configuration in configurations {
                        let application_label = ccid_application_label(configuration.application);
                        let slot_id = next_reader_slot_id;
                        let Some(next_slot_id) = next_reader_slot_id.checked_add(1) else {
                            log!(1, "PCSC slot ID space exhausted");
                            break;
                        };
                        next_reader_slot_id = next_slot_id;
                        let application_aid = self
                            .ccid_aids
                            .for_application(configuration.application)
                            .to_vec();
                        if let Err(error) =
                            select_application(base_connector.as_ref(), &application_aid)
                        {
                            log!(
                                1,
                                "CCID application AID selection for {}: {:?}",
                                application_label,
                                error
                            );
                            continue;
                        }
                        if let Err(error) = reader_state.set_selected_application(&application_aid)
                        {
                            log!(
                                1,
                                "CCID application selection state for {}: {:?}",
                                application_label,
                                error
                            );
                            continue;
                        }
                        let application_connector = PcscAppletConnector::new_configured(
                            base_connector.clone(),
                            &application_aid,
                            configuration.secure_channel,
                            reader_state.clone(),
                            self.secure_channels.clone(),
                            self.pinentry.clone(),
                        );
                        let shared_application_connector: SharedConnector =
                            Arc::new(application_connector.clone());
                        let application_connector: Rc<dyn Connector> =
                            Rc::new(application_connector);
                        let mut slot: Box<dyn Slot> = match configuration.application {
                            CcidApplication::Piv => Box::new(PivSlot::new_with_device(
                                application_connector,
                                application_aid.clone(),
                                reader_state.device.clone(),
                            )),
                            CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new_with_device(
                                application_connector,
                                application_aid.clone(),
                                reader_state.device.clone(),
                            )),
                            CcidApplication::HsmAuth => {
                                let hsmauth_slot = HsmAuthSlot::new_shared_with_device(
                                    application_connector,
                                    shared_application_connector,
                                    application_aid,
                                    reader_state.device.clone(),
                                );
                                match hsmauth_slot.providers() {
                                    Ok(mut providers) => {
                                        for provider in &mut providers {
                                            provider.trust_prefix =
                                                Some(self.yubihsm_device_trust_prefix.clone());
                                        }
                                        if let Err(error) = hsmauth_providers.extend(providers) {
                                            log!(
                                                1,
                                                "YubiHSM Auth provider registration: {:?}",
                                                error
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        log!(2, "YubiHSM Auth credential discovery: {:?}", error)
                                    }
                                }
                                Box::new(hsmauth_slot)
                            }
                            CcidApplication::IssuerSecurityDomain => {
                                Box::new(IssuerSecurityDomainSlot::new_with_device(
                                    application_connector,
                                    application_aid,
                                    reader_state.device.clone(),
                                ))
                            }
                            CcidApplication::Fido2 => {
                                let fido_slot = Fido2Slot::new_with_device(
                                    application_connector,
                                    application_aid,
                                    reader_state.device.clone(),
                                );
                                if let Some(key) = fido_slot.physical_device_key() {
                                    log!(2, "FIDO CCID physical-device candidate: {:?}", key);
                                    reader_fido_slots.push((
                                        key,
                                        slot_id,
                                        configuration.secure_channel.is_some(),
                                    ));
                                }
                                Box::new(fido_slot)
                            }
                        };
                        if slot.is_present() {
                            if let Err(error) = slot.init_slot() {
                                log!(
                                    1,
                                    "CCID application initialization failed for reader {}, applet {}: {:?}",
                                    base_connector.name(),
                                    application_label,
                                    error
                                );
                                slot.set_discovery_error(&error);
                            } else {
                                slot.clear_discovery_error();
                            }
                        }
                        let token_objects = if slot.is_present() {
                            match slot.token_objects(slot_id) {
                                Ok(objects) => objects,
                                Err(error) => {
                                    log!(2, "CCID object discovery: {:?}", error);
                                    slot.set_discovery_error(&error);
                                    Vec::new()
                                }
                            }
                        } else {
                            Vec::new()
                        };
                        reader_slots.push((slot_id, slot, token_objects));
                    }
                    if !reader_slots.is_empty() {
                        match slot_contexts.insert_slot_contexts(
                            reader_slots,
                            self.handles.clone(),
                            self.pinentry.clone(),
                            self.trust_store.clone(),
                            self.token_storage.as_ref(),
                            self.fido_storage.as_ref(),
                        ) {
                            Ok(inserted_slot_ids) => {
                                for (key, slot_id, secure_channel) in reader_fido_slots {
                                    if inserted_slot_ids.contains(&slot_id) {
                                        ccid_fido_slots.insert(key, (slot_id, secure_channel));
                                    }
                                }
                            }
                            Err(error) => {
                                log!(1, "PCSC slot context registration: {:?}", error);
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "native-hardware")]
        let hid_descriptors = if self.hardware_discovery {
            match enumerate_fido_devices() {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    log!(1, "FIDO HID enumeration: {:?}", error);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        #[cfg(feature = "native-hardware")]
        for descriptor in hid_descriptors {
            let io = match descriptor.open() {
                Ok(io) => io,
                Err(error) => {
                    log!(1, "FIDO HID open for {}: {:?}", descriptor.name(), error);
                    continue;
                }
            };
            let (transport, init) = match CtapHidTransport::connect(Box::new(io)) {
                Ok(connected) => connected,
                Err(error) => {
                    log!(
                        1,
                        "FIDO HID channel initialization for {}: {:?}",
                        descriptor.name(),
                        error
                    );
                    continue;
                }
            };
            let transport = Rc::new(transport);
            let device_info = if descriptor.is_yubico() {
                match YubiKeyClient
                    .discover_from_config_pages(Some(init.firmware_version), |page| {
                        transport.command(0x42, &[page])
                    }) {
                    Ok(info) => Some(info),
                    Err(error) => {
                        log!(
                            2,
                            "YubiKey device-information discovery through FIDO HID on {}: {:?}",
                            descriptor.name(),
                            error
                        );
                        None
                    }
                }
            } else {
                None
            };
            let identity = DeviceIdentity {
                manufacturer: descriptor.manufacturer().to_owned(),
                product: descriptor.product().to_owned(),
                serial: device_info
                    .as_ref()
                    .and_then(|info| info.serial.clone())
                    .or_else(|| descriptor.serial().map(str::to_owned))
                    .unwrap_or_else(|| String::from("0")),
                hardware_version: None,
                firmware_version: device_info
                    .as_ref()
                    .and_then(|info| info.version)
                    .or(Some(init.firmware_version)),
            };
            let (device, shares_pcsc_gate) = hid_device_context(&pcsc_devices, identity);
            if shares_pcsc_gate {
                log!(
                    2,
                    "FIDO HID endpoint {} shares the physical-device operation gate with PC/SC",
                    descriptor.name()
                );
            }
            let endpoint = Rc::new(HidFidoEndpoint::new(
                descriptor,
                transport,
                init,
                device_info.as_ref(),
                device,
            ));
            let hid_slot = Fido2Slot::new_with_endpoint(endpoint);
            if let Some(key) = hid_slot.physical_device_key() {
                log!(2, "FIDO HID physical-device candidate: {:?}", key);
                match resolve_fido_duplicate(&ccid_fido_slots, &key) {
                    FidoDuplicateResolution::KeepSecuredCcid(ccid_slot_id) => {
                        log!(
                            2,
                            "FIDO HID endpoint {:?} omitted in favor of explicitly secured CCID slot {}",
                            key,
                            ccid_slot_id
                        );
                        continue;
                    }
                    FidoDuplicateResolution::ReplaceCcidWithHid(ccid_slot_id) => {
                        slot_contexts.remove(&ccid_slot_id);
                        ccid_fido_slots.remove(&key);
                        log!(
                            2,
                            "FIDO CCID slot {} replaced by the native HID endpoint for {:?}",
                            ccid_slot_id,
                            key
                        );
                    }
                    FidoDuplicateResolution::Independent => {}
                }
            }
            let mut slot = Box::new(hid_slot) as Box<dyn Slot>;
            if let Err(error) = slot.init_slot() {
                log!(
                    1,
                    "FIDO HID authenticator initialization for {}: {:?}",
                    slot.name(),
                    error
                );
                slot.set_discovery_error(&error);
            } else {
                slot.clear_discovery_error();
            }
            let Some(slot_id) = slot_contexts.next_slot_id() else {
                log!(1, "FIDO HID slot ID space exhausted");
                break;
            };
            let token_objects = match slot.token_objects(slot_id) {
                Ok(objects) => objects,
                Err(error) => {
                    log!(2, "FIDO HID object discovery: {:?}", error);
                    slot.set_discovery_error(&error);
                    Vec::new()
                }
            };
            if let Err(error) = slot_contexts.insert_slot_contexts(
                vec![(slot_id, slot, token_objects)],
                self.handles.clone(),
                self.pinentry.clone(),
                self.trust_store.clone(),
                self.token_storage.as_ref(),
                self.fido_storage.as_ref(),
            ) {
                log!(1, "FIDO HID slot context registration: {:?}", error);
            }
        }
        let yubihsm_slot_ids = slot_contexts
            .keys()
            .filter(|slot_id| {
                slot_contexts
                    .get(slot_id)
                    .and_then(|context| context.lock().ok())
                    .is_some_and(|context| context.slot.kind() == SlotKind::YubiHsm)
            })
            .copied()
            .collect::<Vec<_>>();
        for slot_id in yubihsm_slot_ids {
            if let Some(context) = slot_contexts.get(&slot_id) {
                match context.lock() {
                    Ok(mut context) => {
                        if let Err(error) = context.refresh_slot_token_objects(slot_id) {
                            log!(2, "YubiHSM object registration: {:?}", error);
                        }
                    }
                    Err(_) => log!(1, "YubiHSM slot state lock is poisoned"),
                }
            }
        }
        drop(slot_contexts);
        log!(2, "ModuleContext.init {:?}", self);
        Ok(())
    }
}

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn default_objects() -> Result<HashMap<CK_OBJECT_HANDLE, TokenObject>, Error> {
    let private_key = crate::certificate_builder::rsa_key();
    let public_key = RsaPublicKey::from(&private_key);
    let objects = HashMap::from([
        (
            1,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: "1".to_owned(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: "Test RSA public key".to_owned(),
                id: vec![1],
                token: true,
                private: false,
                encrypt: true,
                decrypt: false,
                sign: false,
                verify: true,
                derive: false,
                wrap: false,
                unwrap: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                allowed_mechanisms: None,
                wrap_with_trusted: false,
                policy_templates: crate::KeyPolicyTemplates::default(),
                creator_session: None,
                public_key: None,
                rp_id: None,
                material: KeyMaterial::Public(PublicKeyMaterial::Rsa(public_key)),
            },
        ),
        (
            2,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: "2".to_owned(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: "Test RSA private key".to_owned(),
                id: vec![1],
                token: true,
                private: true,
                encrypt: false,
                decrypt: true,
                sign: true,
                verify: false,
                derive: false,
                wrap: false,
                unwrap: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                allowed_mechanisms: None,
                wrap_with_trusted: false,
                policy_templates: crate::KeyPolicyTemplates::default(),
                creator_session: None,
                public_key: Some(PublicKeyMaterial::Rsa(RsaPublicKey::from(&private_key))),
                rp_id: None,
                material: KeyMaterial::SoftwarePrivate(SoftwarePrivateKeyMaterial::Rsa(Box::new(
                    private_key,
                ))),
            },
        ),
    ]);

    Ok(objects)
}

// SAFETY: Each SlotContext and every Rc reachable from it is owned by one
// slot-context mutex and accessed only while that mutex is held. The lock
// helpers require returned values to be Send, preventing ordinary non-Send
// slot state from escaping their guards. Physical PC/SC state and HSM Auth
// providers cross slot boundaries only through synchronized Arc handles.
unsafe impl Send for SlotContext {}

// Presence is the module lifecycle state. Ordinary calls retain a shared guard
// for their complete duration; C_Initialize and C_Finalize require exclusivity.
pub(crate) static MODULE_CONTEXT: RwLock<Option<ModuleContext>> = RwLock::new(None);

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_STORAGE_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_STORAGE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pkcs11rs-fido-config-test-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn identity(serial: &str) -> DeviceIdentity {
        DeviceIdentity {
            manufacturer: String::from("Yubico"),
            product: String::from("YubiKey"),
            serial: serial.to_owned(),
            hardware_version: None,
            firmware_version: None,
        }
    }

    fn key(serial: &str) -> PhysicalDeviceKey {
        PhysicalDeviceKey::YubicoSerial(serial.to_owned())
    }

    #[test]
    fn disabled_local_discovery_without_explicit_slots_yields_zero_slots() {
        let configuration = ModuleConfiguration::resolve(None).unwrap();
        let context = ModuleContext {
            debug_level: 0,
            hardware_discovery: false,
            yubihsm_usb: false,
            software_slots: Vec::new(),
            software_discovery_pins: HashMap::new(),
            pcsc: None,
            yubihsm_urls: Vec::new(),
            yubihsm_http_tls: HttpConnectorTlsConfig::default(),
            yubihsm_public_discovery_config: None,
            yubihsm_device_trust_prefix: std::ffi::OsString::new(),
            ccid_configurations: configuration.ccid_configurations,
            ccid_aids: configuration.ccid_aids,
            secure_channels: Arc::new(configuration.secure_channels),
            token_storage: None,
            fido_storage: None,
            handles: Arc::new(HandleCounters::new()),
            pinentry: Arc::new(pinentry::Pinentry::unconfigured()),
            trust_store: Arc::new(crate::yubihsm::trust::TrustStore::new_with_prefix(
                std::ffi::OsString::new(),
            )),
            slot_contexts: RwLock::new(SlotContextRegistry::new()),
        };

        context.init().unwrap();

        let slots = context.slot_contexts.read().unwrap();
        assert!(slots.discovered);
        assert!(slots.slots.is_empty());
    }

    #[test]
    fn native_hid_replaces_an_unsecured_ccid_view_of_the_same_fido_device() {
        let slots = HashMap::from([(key("12345678"), (7, false))]);
        assert_eq!(
            resolve_fido_duplicate(&slots, &key("12345678")),
            FidoDuplicateResolution::ReplaceCcidWithHid(7)
        );
    }

    #[test]
    fn explicitly_secured_ccid_wins_over_hid_for_the_same_fido_device() {
        let slots = HashMap::from([(key("12345678"), (7, true))]);
        assert_eq!(
            resolve_fido_duplicate(&slots, &key("12345678")),
            FidoDuplicateResolution::KeepSecuredCcid(7)
        );
    }

    #[test]
    fn different_physical_serials_remain_independent() {
        let slots = HashMap::from([(key("12345678"), (7, false))]);
        assert_eq!(
            resolve_fido_duplicate(&slots, &key("87654321")),
            FidoDuplicateResolution::Independent
        );
    }

    #[test]
    fn hid_and_pcsc_views_with_the_same_serial_share_a_device_context() {
        let pcsc_device = Arc::new(DeviceContext::new(identity("0012345678")));
        let devices = HashMap::from([(key("12345678"), pcsc_device.clone())]);
        let (hid_device, shared) = hid_device_context(&devices, identity("12345678"));
        assert!(shared);
        assert!(Arc::ptr_eq(&hid_device, &pcsc_device));
    }

    #[test]
    fn hid_without_a_matching_pcsc_serial_gets_an_independent_device_context() {
        let pcsc_device = Arc::new(DeviceContext::new(identity("12345678")));
        let devices = HashMap::from([(key("12345678"), pcsc_device.clone())]);
        let (hid_device, shared) = hid_device_context(&devices, identity("87654321"));
        assert!(!shared);
        assert!(!Arc::ptr_eq(&hid_device, &pcsc_device));
    }

    #[test]
    fn token_storage_configuration_is_explicit_and_applet_scoped() {
        assert!(configured_token_storage(None).unwrap().is_none());
        assert!(configured_token_storage(Some(std::ffi::OsString::new())).is_err());
        assert!(configured_token_storage(Some("relative/path".into())).is_err());

        let generic = TestDirectory::new();
        let config = configured_token_storage(Some(generic.0.clone().into_os_string()))
            .unwrap()
            .unwrap();
        assert_eq!(config.root(), generic.0);
        assert_eq!(
            config.token_root(&key("12345678"), SlotKind::Fido2),
            generic
                .0
                .join(TOKEN_STORAGE_SCHEMA_DIRECTORY)
                .join("yubico-serial-3132333435363738")
                .join("fido2")
        );
        assert_eq!(
            config.token_root(&key("12345678"), SlotKind::Ccid(CcidApplication::Piv)),
            generic
                .0
                .join(TOKEN_STORAGE_SCHEMA_DIRECTORY)
                .join("yubico-serial-3132333435363738")
                .join("piv")
        );
        assert_eq!(
            config.software_token_root("build signing"),
            generic
                .0
                .join(TOKEN_STORAGE_SCHEMA_DIRECTORY)
                .join("software-name-6275696c64207369676e696e67")
        );

        assert!(configured_fido_storage(None).unwrap().is_none());
        assert!(configured_fido_storage(Some(std::ffi::OsString::new())).is_err());
        assert!(configured_fido_storage(Some("relative/path".into())).is_err());

        let directory = TestDirectory::new();
        let file = directory.0.join("not-a-directory");
        std::fs::write(&file, []).unwrap();
        assert!(configured_fido_storage(Some(file.into_os_string())).is_err());
        let config = configured_fido_storage(Some(directory.0.clone().into_os_string()))
            .unwrap()
            .unwrap();
        assert_eq!(config.root(), directory.0);
        assert_eq!(
            config.token_root(&key("12345678")),
            directory
                .0
                .join(FIDO2_STORAGE_SCHEMA_DIRECTORY)
                .join("yubico-serial-3132333435363738")
        );
        assert_eq!(
            config.token_root(&key("87654321")),
            directory
                .0
                .join(FIDO2_STORAGE_SCHEMA_DIRECTORY)
                .join("yubico-serial-3837363534333231")
        );
    }
}
