use crate::pkcs11::*;
#[cfg(feature = "abi-tests")]
use crate::{
    abi_test_piv_slot, abi_test_yubihsm_slots, AbiScp03Slot, AbiTestSlot, ABI_TEST_PIV_SLOT_ID,
    ABI_TEST_SCP03_SLOT_ID, ABI_TEST_SCP11_SLOT_ID,
};
use crate::{
    bulk_out_packet_size, ccid_application_aid, ccid_application_label,
    configured_ccid_configurations, pinentry, select_application, str_pad, BackendSession,
    CcidApplication, Connector, CryptOperation, DigestOperation, Error, Fido2Slot, FindOperation,
    HsmAuthProviderRegistry, HsmAuthSlot, HttpConnector, IssuerSecurityDomainSlot, OpenPgpSlot,
    PcscAppletConnector, PcscConnector, PivSlot, SignatureOperation, Slot, SlotKind, TokenObject,
    UsbConnector, YubiHsmPublicDiscoveryCredential, YubiHsmSlot, YubiKeyClient,
};
#[cfg(not(feature = "abi-tests"))]
use crate::{configured_yubihsm_public_discovery_credential_with_pinentry, YUBIHSM_DISCOVERY_ENV};
#[cfg(any(test, feature = "abi-tests"))]
use crate::{KeyMaterial, ABI_TEST_SLOT_ID};
#[cfg(any(test, feature = "abi-tests"))]
use rsa::RsaPublicKey;
use rusb::UsbContext;
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::{Arc, Mutex, OnceLock, RwLock},
};

pub(crate) fn configured_yubihsm_urls(
    value: Option<std::ffi::OsString>,
) -> Result<Vec<String>, Error> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let value = value.into_string().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let mut urls = Vec::new();
    for url in value.split(',') {
        let url = url.trim().trim_end_matches('/');
        if url.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        urls.push(url.to_owned());
    }
    Ok(urls)
}

#[cfg(any(not(feature = "abi-tests"), test))]
pub(crate) fn configured_yubihsm_usb(value: Option<std::ffi::OsString>) -> Result<bool, Error> {
    match value {
        None => Ok(true),
        Some(value) if value == "0" => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(_) => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

// Initialized module resources and the registry of independently locked slots.
// The registry lock protects lazy discovery and session-handle routing; slot
// operations release it before taking an individual SlotContext lock.
pub(crate) struct ModuleContext {
    pub(crate) debug_level: u8,
    pub(crate) libusb: Option<rusb::Context>,
    pub(crate) pcsc: Option<pcsc::Context>,
    pub(crate) yubihsm_urls: Vec<String>,
    pub(crate) yubihsm_public_discovery_credential: Option<Arc<YubiHsmPublicDiscoveryCredential>>,
    pub(crate) handles: Arc<HandleCounters>,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
    pub(crate) trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    pub(crate) slot_contexts: RwLock<SlotContextRegistry>,
}

// Mutable token state shared by every PKCS #11 session opened on this slot.
pub(crate) struct SlotContext {
    pub(crate) slot_id: CK_SLOT_ID,
    pub(crate) slot: Box<dyn Slot>,
    handles: Arc<HandleCounters>,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
    pub(crate) trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    pub(crate) sessions: HashMap<CK_SESSION_HANDLE, SessionContext>,
    pub(crate) login_role: Option<LoginRole>,
    pub(crate) memory_objects: HashMap<CK_OBJECT_HANDLE, TokenObject>,
    pub(crate) token_object_handles: HashMap<CK_OBJECT_HANDLE, TokenObjectLocator>,
}

// Mutable PKCS #11 operation state belonging to one application session.
pub(crate) struct SessionContext {
    backend: Box<dyn BackendSession>,
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

    fn insert_pcsc_slot_contexts(
        &mut self,
        slots: Vec<(CK_SLOT_ID, Box<dyn Slot>, Vec<TokenObject>)>,
        handles: Arc<HandleCounters>,
        pinentry: Arc<pinentry::Pinentry>,
        trust_store: Arc<crate::yubihsm::trust::TrustStore>,
    ) -> Result<Vec<CK_SLOT_ID>, Error> {
        // Each applet is a separate PKCS token with its own logical state.
        // Their connectors share PcscReaderState for physical reader access.
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
        let contexts = slots
            .into_iter()
            .map(|(slot_id, slot, token_objects)| {
                let context = SlotContext::new(
                    slot_id,
                    slot,
                    token_objects,
                    handles.clone(),
                    pinentry.clone(),
                    trust_store.clone(),
                )?;
                Ok((slot_id, Arc::new(Mutex::new(context))))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        for (slot_id, context) in contexts {
            self.slots.insert(slot_id, context);
        }
        Ok(slot_ids)
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
        fmt.debug_struct("ModuleContext")
            .field("libusb", &self.libusb)
            .field("pcsc", &self.pcsc.as_ref().map(|_| "Context { .. }"))
            .field("yubihsm_urls", &self.yubihsm_urls)
            .field(
                "yubihsm_public_discovery_credential",
                &self.yubihsm_public_discovery_credential,
            )
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
    pub(crate) fn new() -> Result<ModuleContext, Error> {
        let debug_level = crate::configured_debug_level()?;
        let pinentry = Arc::new(pinentry::Pinentry::from_environment()?);
        let handles = Arc::new(HandleCounters::new());
        let trust_store = Arc::new(crate::yubihsm::trust::TrustStore::new());
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
        let yubihsm_urls = configured_yubihsm_urls(std::env::var_os("PKCS11RS_YUBIHSM_URLS"))?;
        #[cfg(not(feature = "abi-tests"))]
        let yubihsm_public_discovery_credential =
            configured_yubihsm_public_discovery_credential_with_pinentry(
                std::env::var_os(YUBIHSM_DISCOVERY_ENV),
                pinentry.as_ref(),
            )?;
        #[cfg(feature = "abi-tests")]
        let yubihsm_public_discovery_credential = None;
        #[cfg(not(feature = "abi-tests"))]
        let yubihsm_usb = configured_yubihsm_usb(std::env::var_os("PKCS11RS_YUBIHSM_USB"))?;
        let mut context = ModuleContext {
            debug_level,
            #[cfg(feature = "abi-tests")]
            libusb: None,
            #[cfg(not(feature = "abi-tests"))]
            libusb: if yubihsm_usb {
                match rusb::Context::new() {
                    Ok(context) => Some(context),
                    Err(e) => {
                        log!(1, "libusb::Context::new: {}", e);
                        None
                    }
                }
            } else {
                None
            },
            #[cfg(feature = "abi-tests")]
            pcsc: None,
            #[cfg(not(feature = "abi-tests"))]
            pcsc: match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => Some(context),
                Err(e) => {
                    log!(1, "pcsc::Context::establish: {}", e);
                    None
                }
            },
            yubihsm_urls,
            yubihsm_public_discovery_credential,
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
            .insert_pcsc_slot_contexts(
                slots,
                self.handles.clone(),
                self.pinentry.clone(),
                self.trust_store.clone(),
            )
            .map(|_| ())
    }
    pub(crate) fn get_info(&self, info: &mut CK_INFO) -> Result<(), Error> {
        info.cryptokiVersion.major = 3;
        info.cryptokiVersion.minor = 2;
        info.libraryVersion.major = 1;
        info.libraryVersion.minor = 0;
        info.flags = 0;
        str_pad(
            "YubiHSM & YubiKey PKCS#11 module",
            &mut info.libraryDescription,
        );
        str_pad("Yubico", &mut info.manufacturerID);
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
        let mut context = Self {
            slot_id,
            slot,
            handles,
            pinentry,
            trust_store,
            sessions: HashMap::new(),
            login_role: None,
            memory_objects: HashMap::new(),
            token_object_handles: HashMap::new(),
        };
        context.reconcile_slot_token_objects(slot_id, token_objects)?;
        Ok(context)
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
            self.login_role(slot_id) == Some(LoginRole::User),
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
        self.slot.token_object(self.slot_id, &locator.unique_id)
    }

    pub(crate) fn resolved_objects(&self) -> Result<Vec<(CK_OBJECT_HANDLE, TokenObject)>, Error> {
        let mut objects = self
            .memory_objects
            .iter()
            .map(|(handle, object)| (*handle, object.clone()))
            .collect::<Vec<_>>();
        let token_objects = self
            .slot
            .token_objects(self.slot_id)?
            .into_iter()
            .filter(|object| object.token)
            .map(|object| (object.unique_id.clone(), object))
            .collect::<HashMap<_, _>>();
        for (handle, locator) in &self.token_object_handles {
            if let Some(object) = token_objects.get(&locator.unique_id) {
                objects.push((*handle, object.clone()));
            }
        }
        Ok(objects)
    }

    pub(crate) fn remove_object_handle(&mut self, handle: CK_OBJECT_HANDLE) {
        self.memory_objects.remove(&handle);
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
        let objects = self.slot.token_objects(slot_id)?;
        self.reconcile_slot_token_objects(slot_id, objects)
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
        #[cfg(feature = "abi-tests")]
        {
            return Ok(());
        }
        let hsmauth_providers = Arc::new(HsmAuthProviderRegistry::default());
        if let Some(context) = self.libusb.as_ref() {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(desc) = device.device_descriptor() {
                        //eprintln!("USB Bus {} Device {}: ID {}: {}", device.bus_number(), device.address(), desc.vendor_id(), desc.product_id());
                        if desc.vendor_id() == 0x1050 && desc.product_id() == 0x30 {
                            match device.open() {
                                Ok(handle) => {
                                    let version = desc.device_version();
                                    let packet_size = match bulk_out_packet_size(&device) {
                                        Ok(packet_size) => packet_size,
                                        Err(error) => {
                                            log!(1, "libusb bulk OUT endpoint: {:?}", error);
                                            continue;
                                        }
                                    };
                                    let manufacturer = handle
                                        .read_manufacturer_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let product =
                                        handle.read_product_string_ascii(&desc).unwrap_or_default();
                                    let serial = handle
                                        .read_serial_number_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let mut connector = UsbConnector {
                                        handle,
                                        version,
                                        manufacturer,
                                        product,
                                        serial,
                                        packet_size,
                                        claimed: false,
                                        connection_epoch: 0,
                                        connected_once: false,
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
                                    if let Err(error) = connector.connect() {
                                        log!(1, "libusb.claim_interface: {:?}", error);
                                        continue;
                                    }
                                    let Some(slot_id) = slot_contexts.next_slot_id() else {
                                        log!(1, "YubiHSM slot ID space exhausted");
                                        continue;
                                    };
                                    let mut yubihsm_slot =
                                        YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
                                            Rc::new(connector),
                                            (0, 0, 0),
                                            Vec::new(),
                                            hsmauth_providers.clone(),
                                            self.yubihsm_public_discovery_credential.clone(),
                                        );
                                    yubihsm_slot.set_pinentry(self.pinentry.clone());
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
                                Err(e) => {
                                    log!(1, "libusb.open: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        for url in self.yubihsm_urls.clone() {
            let mut connector = match HttpConnector::new(url.clone()) {
                Ok(connector) => connector,
                Err(error) => {
                    log!(1, "YubiHSM connector configuration for {url}: {:?}", error);
                    continue;
                }
            };
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
                continue;
            };
            let connector = Rc::new(connector);
            let mut yubihsm_slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
                connector.clone(),
                (0, 0, 0),
                Vec::new(),
                hsmauth_providers.clone(),
                self.yubihsm_public_discovery_credential.clone(),
            );
            yubihsm_slot.set_pinentry(self.pinentry.clone());
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
        if let Some(context) = self.pcsc.clone() {
            if let Ok(readers) = context.list_readers_owned() {
                for reader in readers {
                    let connector = PcscConnector {
                        reader,
                        context: context.clone(),
                        yubikey_device_info: OnceLock::new(),
                        firmware_version: Cell::new(None),
                        serial_number: OnceLock::new(),
                        state: Arc::new(Default::default()),
                    };
                    let name = connector.name();
                    log!(2, "{}", name);
                    if let Err(error) = connector.refresh() {
                        log!(1, "PCSC reader has no usable card: {:?}", error);
                        continue;
                    }
                    match YubiKeyClient.discover(&connector) {
                        Ok(info) => connector.set_yubikey_device_info(info),
                        Err(error) => log!(
                            2,
                            "YubiKey Management device-information discovery failed on {}: {:?}",
                            name,
                            error
                        ),
                    }
                    let configurations = match configured_ccid_configurations() {
                        Ok(configurations) => configurations,
                        Err(error) => {
                            log!(1, "CCID application configuration: {:?}", error);
                            continue;
                        }
                    };
                    let reader_state = connector.state.clone();
                    let base_connector: Rc<dyn Connector> = Rc::new(connector);
                    let mut reader_slots = Vec::new();
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
                        let application_aid = match ccid_application_aid(
                            configuration.application,
                            configuration.secure_channel,
                        ) {
                            Ok(aid) => aid,
                            Err(error) => {
                                log!(1, "CCID application AID configuration: {:?}", error);
                                continue;
                            }
                        };
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
                        let application_connector: Rc<dyn Connector> =
                            Rc::new(PcscAppletConnector::new(
                                base_connector.clone(),
                                &application_aid,
                                configuration.secure_channel,
                                reader_state.clone(),
                            ));
                        let mut slot: Box<dyn Slot> = match configuration.application {
                            CcidApplication::Piv => Box::new(PivSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::HsmAuth => {
                                let hsmauth_slot =
                                    HsmAuthSlot::new(application_connector, application_aid);
                                match hsmauth_slot.providers() {
                                    Ok(providers) => {
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
                                Box::new(IssuerSecurityDomainSlot::new(
                                    application_connector,
                                    application_aid,
                                ))
                            }
                            CcidApplication::Fido2 => {
                                Box::new(Fido2Slot::new(application_connector, application_aid))
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
                        if let Err(error) = slot_contexts.insert_pcsc_slot_contexts(
                            reader_slots,
                            self.handles.clone(),
                            self.pinentry.clone(),
                            self.trust_store.clone(),
                        ) {
                            log!(1, "PCSC slot context registration: {:?}", error);
                        }
                    }
                }
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
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                creator_session: None,
                material: KeyMaterial::RsaPublic(public_key),
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
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                creator_session: None,
                material: KeyMaterial::RsaPrivate(Box::new(private_key)),
            },
        ),
    ]);

    Ok(objects)
}

// A SlotContext is always protected by its slot-context mutex. Connector handles
// that are not marked Send by their dependency crates never escape that guard.
unsafe impl Send for SlotContext {}

// ModuleContext is always protected by MODULE_CONTEXT.
// Connector handles that are not marked Send by their dependency crates never
// escape their owning context guard.
unsafe impl Send for ModuleContext {}

// Presence is the module lifecycle state. Ordinary calls retain a shared guard
// for their complete duration; C_Initialize and C_Finalize require exclusivity.
pub(crate) static MODULE_CONTEXT: RwLock<Option<ModuleContext>> = RwLock::new(None);
