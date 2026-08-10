use crate::device::{DeviceContext, DeviceIdentity, DeviceOperationLifecycle};
use crate::*;
use block2::RcBlock;
use objc2::{rc::Retained, rc::autoreleasepool, runtime::Bool};
use objc2_crypto_token_kit::{
    TKErrorCode, TKSmartCard, TKSmartCardSlot, TKSmartCardSlotManager, TKSmartCardSlotNFCSession,
    TKSmartCardSlotState,
};
use objc2_foundation::{NSData, NSError, NSString};
use std::ffi::{c_char, c_int, c_void};
use std::sync::{
    Arc, Condvar, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Instant;

fn nfc_diagnostic(message: std::fmt::Arguments<'_>) {
    eprintln!("[pkcs11rs:nfc] {message}");
}

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const NFC_PROMPT: &str = "Hold your YubiKey near the top of this iPhone.";
const NFC_READING: &str = "YubiKey found. Reading YubiHSM Auth credentials…";
const NFC_CARD_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
const NFC_CARD_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NFC_SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const NFC_REMOVAL_POLL_INTERVAL: Duration = Duration::from_millis(200);
const NFC_REMOVAL_CONFIRMATION: Duration = Duration::from_millis(250);
const NFC_CANCEL_COOLDOWN: Duration = Duration::from_millis(500);
const NFC_IDLE: &str = "Idle — you may remove your YubiKey";
const RTLD_LAZY: c_int = 0x1;
const CRYPTO_TOKEN_KIT_PATH: &[u8] =
    b"/System/Library/Frameworks/CryptoTokenKit.framework/CryptoTokenKit\0";

fn load_crypto_token_kit() -> Result<(), Error> {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    let available = *AVAILABLE.get_or_init(|| {
        // Keep the public system framework loaded for the lifetime of the process.
        // This is necessary for a static XCFramework: unlike a final executable,
        // its archive cannot retain a transitive framework dependency for the app
        // linker to apply later.
        !unsafe { dlopen(CRYPTO_TOKEN_KIT_PATH.as_ptr().cast::<c_char>(), RTLD_LAZY) }.is_null()
    });
    available
        .then_some(())
        .ok_or_else(|| CKR_DEVICE_ERROR.into())
}

enum WorkerRequest {
    BeginOperation {
        reply: mpsc::SyncSender<Result<(), CK_RV>>,
    },
    EndOperation {
        reply: mpsc::SyncSender<()>,
    },
    Refresh {
        reply: mpsc::SyncSender<Result<(), CK_RV>>,
    },
    Transmit {
        command: Vec<u8>,
        timeout: Duration,
        reply: mpsc::SyncSender<Result<Vec<u8>, CK_RV>>,
    },
}

struct AppleCcidWorker {
    requests: mpsc::Sender<WorkerRequest>,
}

struct AppleCcidLifecycle {
    reader_name: String,
    worker: Arc<OnceLock<Result<AppleCcidWorker, CK_RV>>>,
    reader_state: Weak<PcscReaderState>,
    nfc: Option<Arc<NfcTransport>>,
}

impl std::fmt::Debug for AppleCcidLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppleCcidLifecycle")
            .field("reader_name", &self.reader_name)
            .field("nfc", &self.nfc.is_some())
            .finish_non_exhaustive()
    }
}

impl AppleCcidLifecycle {
    fn worker(&self) -> Result<&AppleCcidWorker, Error> {
        self.worker
            .get_or_init(|| AppleCcidWorker::spawn(self.reader_name.clone(), self.nfc.clone()))
            .as_ref()
            .map_err(|error| Error::from(*error))
    }
}

impl DeviceOperationLifecycle for AppleCcidLifecycle {
    fn enter(&self, message: &str) -> Result<(), Error> {
        if let Some(nfc) = &self.nfc {
            nfc.enter(message)?;
        }
        let Some(reader_state) = self.reader_state.upgrade() else {
            if let Some(nfc) = &self.nfc {
                nfc.exit();
            }
            return Err(CKR_DEVICE_ERROR.into());
        };
        if let Err(error) = reader_state.begin_transaction() {
            if let Some(nfc) = &self.nfc {
                nfc.exit();
            }
            return Err(error);
        }
        if let Err(error) = self.worker().and_then(AppleCcidWorker::begin_operation) {
            reader_state.end_transaction();
            if let Some(nfc) = &self.nfc {
                nfc.exit();
            }
            return Err(error);
        }
        Ok(())
    }

    fn exit(&self) {
        if let Ok(worker) = self.worker() {
            if let Err(error) = worker.end_operation() {
                tracing::debug!(
                    target: "pkcs11rs::transport",
                    reader = %self.reader_name,
                    ?error,
                    "failed to end CryptoTokenKit device operation"
                );
            }
        }
        if let Some(reader_state) = self.reader_state.upgrade() {
            reader_state.end_transaction();
        }
        if let Some(nfc) = &self.nfc {
            nfc.exit();
        }
    }
}

impl AppleCcidWorker {
    fn spawn(reader_name: String, nfc: Option<Arc<NfcTransport>>) -> Result<Self, CK_RV> {
        let (requests, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("pkcs11rs-apple-ccid".to_owned())
            .spawn(move || run_worker(reader_name, nfc, receiver))
            .map_err(|_| CKR_HOST_MEMORY)?;
        Ok(Self { requests })
    }

    fn refresh(&self) -> Result<(), Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::Refresh { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver
            .recv()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map_err(Error::from)
    }

    fn begin_operation(&self) -> Result<(), Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::BeginOperation { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver
            .recv()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map_err(Error::from)
    }

    fn end_operation(&self) -> Result<(), Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::EndOperation { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver.recv().map_err(|_| Error::from(CKR_DEVICE_ERROR))
    }

    fn transmit(&self, command: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::Transmit {
                command: command.to_vec(),
                timeout,
                reply,
            })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver
            .recv()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map_err(Error::from)
    }
}

fn resolve_card(reader_name: &str) -> Result<Retained<TKSmartCard>, CK_RV> {
    autoreleasepool(|_| unsafe {
        let manager = TKSmartCardSlotManager::defaultManager().ok_or(CKR_DEVICE_ERROR as CK_RV)?;
        let reader_name = NSString::from_str(reader_name);
        let slot = manager
            .slotNamed(&reader_name)
            .ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
        slot.makeSmartCard().ok_or(CKR_DEVICE_REMOVED as CK_RV)
    })
}

fn card_is_valid(card: &TKSmartCard) -> bool {
    unsafe { card.valid() }
}

fn tk_error_rv(error: Option<&NSError>) -> CK_RV {
    match error.map(NSError::code) {
        Some(code) if code == TKErrorCode::CanceledByUser.0 => CKR_FUNCTION_CANCELED as CK_RV,
        Some(code) if code == TKErrorCode::ObjectNotFound.0 => CKR_FUNCTION_CANCELED as CK_RV,
        Some(code) if code == TKErrorCode::TokenNotFound.0 => CKR_DEVICE_REMOVED as CK_RV,
        _ => CKR_DEVICE_ERROR as CK_RV,
    }
}

fn begin_session(card: &TKSmartCard, timeout: Duration) -> Result<(), CK_RV> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else {
            Err(tk_error_rv(unsafe { error.as_ref() }))
        };
        let _ = sender.try_send(result);
    });
    unsafe { card.beginSessionWithReply(&reply) };
    match receiver.recv_timeout(timeout) {
        Ok(Ok(())) => {
            nfc_diagnostic(format_args!("smart-card session began"));
            Ok(())
        }
        Ok(Err(error)) => {
            nfc_diagnostic(format_args!("smart-card session was rejected"));
            Err(error)
        }
        Err(error) => {
            nfc_diagnostic(format_args!("smart-card session wait failed: {error}"));
            Err(CKR_DEVICE_ERROR as CK_RV)
        }
    }
}

struct SessionGuard<'a>(&'a TKSmartCard);

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        nfc_diagnostic(format_args!("smart-card session ended"));
        unsafe { self.0.endSession() };
    }
}

struct OwnedSessionGuard(Retained<TKSmartCard>);

impl OwnedSessionGuard {
    fn card(&self) -> &TKSmartCard {
        &self.0
    }
}

impl Drop for OwnedSessionGuard {
    fn drop(&mut self) {
        nfc_diagnostic(format_args!("smart-card session ended"));
        unsafe { self.0.endSession() };
    }
}

fn transmit_card(card: &TKSmartCard, command: &[u8], timeout: Duration) -> Result<Vec<u8>, CK_RV> {
    autoreleasepool(|_| {
        let request = NSData::with_bytes(command);
        let (sender, receiver) = mpsc::sync_channel(1);
        let reply = RcBlock::new(move |response: *mut NSData, error: *mut NSError| {
            let response = unsafe { response.as_ref() }.map(NSData::to_vec);
            let error = unsafe { error.as_ref() };
            let result = match response {
                Some(response) => Ok(response),
                None => {
                    if let Some(error) = error {
                        nfc_diagnostic(format_args!(
                            "APDU callback failed: code={} description={}",
                            error.code(),
                            error.localizedDescription()
                        ));
                    } else {
                        nfc_diagnostic(format_args!("APDU callback returned no response or error"));
                    }
                    Err(tk_error_rv(error))
                }
            };
            let _ = sender.try_send(result);
        });
        unsafe { card.transmitRequest_reply(&request, &reply) };
        match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => Err(CKR_DEVICE_ERROR as CK_RV),
        }
    })
}

fn run_worker(
    reader_name: String,
    nfc: Option<Arc<NfcTransport>>,
    receiver: mpsc::Receiver<WorkerRequest>,
) {
    let mut card: Option<Retained<TKSmartCard>> = None;
    let mut card_generation = None;
    let mut operation_active = false;
    let mut active_session: Option<OwnedSessionGuard> = None;

    loop {
        let request = match receiver.recv() {
            Ok(request) => request,
            Err(_) => break,
        };

        match request {
            WorkerRequest::BeginOperation { reply } => {
                let result = if operation_active {
                    Err(CKR_OPERATION_ACTIVE as CK_RV)
                } else {
                    operation_active = true;
                    Ok(())
                };
                let _ = reply.try_send(result);
            }
            WorkerRequest::EndOperation { reply } => {
                active_session = None;
                operation_active = false;
                let _ = reply.try_send(());
            }
            WorkerRequest::Refresh { reply } => {
                let result = if nfc.as_ref().is_some_and(|nfc| nfc.is_mounted()) {
                    Ok(())
                } else if nfc.is_some() {
                    Err(CKR_TOKEN_NOT_PRESENT as CK_RV)
                } else if card.as_deref().is_some_and(card_is_valid) {
                    Ok(())
                } else {
                    match resolve_card(&reader_name) {
                        Ok(resolved) if card_is_valid(&resolved) => {
                            card = Some(resolved);
                            Ok(())
                        }
                        Ok(resolved) => {
                            card = Some(resolved);
                            Err(CKR_DEVICE_REMOVED as CK_RV)
                        }
                        Err(error) => {
                            card = None;
                            Err(error)
                        }
                    }
                };
                let _ = reply.try_send(result);
            }
            WorkerRequest::Transmit {
                command,
                timeout,
                reply,
            } => {
                let result = (|| {
                    if let Some(nfc) = &nfc {
                        let prepared = nfc.prepare()?;
                        loop {
                            if card_generation != Some(prepared.generation) {
                                card = None;
                                card_generation = Some(prepared.generation);
                            }
                            if !card.as_deref().is_some_and(card_is_valid) {
                                card = Some(resolve_card(&prepared.slot_name)?);
                            }
                            if !prepared.verify_serial {
                                break;
                            }
                            let current = card.as_deref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                            let identity = discover_card_identity(current, timeout)?;
                            if nfc.verify_serial(prepared.generation, identity.serial.as_deref())? {
                                break;
                            }
                            nfc.wait_for_replacement(prepared.generation)?;
                            card = None;
                        }
                    }
                    if !card.as_deref().is_some_and(card_is_valid) {
                        card = Some(resolve_card(&reader_name)?);
                    }
                    if operation_active {
                        if active_session.is_none() {
                            let current = card.as_ref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                            begin_session(current, timeout)?;
                            active_session = Some(OwnedSessionGuard(current.clone()));
                        }
                        transmit_card(
                            active_session
                                .as_ref()
                                .ok_or(CKR_DEVICE_ERROR as CK_RV)?
                                .card(),
                            &command,
                            timeout,
                        )
                    } else {
                        let current = card.as_deref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                        begin_session(current, timeout)?;
                        let _session = SessionGuard(current);
                        transmit_card(current, &command, timeout)
                    }
                })();
                if let Err(error) = result.as_ref() {
                    nfc_diagnostic(format_args!(
                        "APDU failed ({} bytes): 0x{error:08x}",
                        command.len()
                    ));
                    if let Some(nfc) = &nfc {
                        nfc.mark_session_unverified(*error);
                        card = None;
                        card_generation = None;
                    }
                    active_session = None;
                }
                if result.is_err() && !card.as_deref().is_some_and(card_is_valid) {
                    card = None;
                }
                let _ = reply.try_send(result);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct CcidConnector {
    reader_name: String,
    atr: Vec<u8>,
    max_input_length: usize,
    max_output_length: usize,
    state: Arc<PcscReaderState>,
    present: Arc<AtomicBool>,
    worker: Arc<OnceLock<Result<AppleCcidWorker, CK_RV>>>,
    nfc: Option<Arc<NfcTransport>>,
}

impl CcidConnector {
    fn new_with_nfc(
        reader_name: String,
        atr: Vec<u8>,
        max_input_length: usize,
        max_output_length: usize,
        nfc: Option<Arc<NfcTransport>>,
    ) -> Self {
        let worker = Arc::new(OnceLock::new());
        let state = Arc::new_cyclic(|reader_state| {
            let lifecycle = Arc::new(AppleCcidLifecycle {
                reader_name: reader_name.clone(),
                worker: worker.clone(),
                reader_state: reader_state.clone(),
                nfc: nfc.clone(),
            });
            let device = Arc::new(DeviceContext::with_lifecycle(
                DeviceIdentity::unknown("Yubico", reader_name.clone()),
                lifecycle,
            ));
            PcscReaderState::new(device)
        });
        Self {
            reader_name,
            atr,
            max_input_length,
            max_output_length,
            state,
            present: Arc::new(AtomicBool::new(true)),
            worker,
            nfc,
        }
    }

    fn new(
        reader_name: String,
        atr: Vec<u8>,
        max_input_length: usize,
        max_output_length: usize,
    ) -> Self {
        Self::new_with_nfc(reader_name, atr, max_input_length, max_output_length, None)
    }

    fn new_nfc(
        reader_name: String,
        atr: Vec<u8>,
        max_input_length: usize,
        max_output_length: usize,
        nfc: Arc<NfcTransport>,
    ) -> Self {
        Self::new_with_nfc(
            reader_name,
            atr,
            max_input_length,
            max_output_length,
            Some(nfc),
        )
    }

    pub(crate) fn enumerate() -> Result<Vec<Self>, Error> {
        load_crypto_token_kit()?;
        let _operation = crate::logging::Operation::info(tracing::info_span!(
            target: "pkcs11rs::discovery",
            "cryptotokenkit.enumerate"
        ));
        autoreleasepool(|_| unsafe {
            let Some(manager) = TKSmartCardSlotManager::defaultManager() else {
                return Ok(Vec::new());
            };
            let mut readers = Vec::new();
            for name in manager.slotNames().to_vec() {
                let Some(slot) = manager.slotNamed(&name) else {
                    continue;
                };
                let max_input_length = usize::try_from(slot.maxInputLength())
                    .ok()
                    .filter(|length| *length > 0)
                    .ok_or(CKR_DEVICE_ERROR)?;
                let max_output_length = usize::try_from(slot.maxOutputLength())
                    .ok()
                    .filter(|length| *length > 0)
                    .ok_or(CKR_DEVICE_ERROR)?;
                let atr = slot
                    .ATR()
                    .map(|atr| atr.bytes().to_vec())
                    .unwrap_or_default();
                readers.push(Self::new(
                    name.to_string(),
                    atr,
                    max_input_length,
                    max_output_length,
                ));
            }
            Ok(readers)
        })
    }

    fn from_slot(reader_name: &str, slot: &TKSmartCardSlot) -> Result<Self, Error> {
        let max_input_length = usize::try_from(unsafe { slot.maxInputLength() })
            .ok()
            .filter(|length| *length > 0)
            .ok_or(CKR_DEVICE_ERROR)?;
        let max_output_length = usize::try_from(unsafe { slot.maxOutputLength() })
            .ok()
            .filter(|length| *length > 0)
            .ok_or(CKR_DEVICE_ERROR)?;
        let atr = unsafe { slot.ATR().map(|atr| atr.bytes().to_vec()) }.unwrap_or_default();
        Ok(Self::new(
            reader_name.to_owned(),
            atr,
            max_input_length,
            max_output_length,
        ))
    }

    fn wait_for_named_card(
        reader_name: &str,
        session: &NfcSessionGuard,
        message: &str,
    ) -> Result<Self, Error> {
        load_crypto_token_kit()?;
        let manager =
            unsafe { TKSmartCardSlotManager::defaultManager() }.ok_or(CKR_DEVICE_ERROR)?;
        let name = NSString::from_str(reader_name);
        let deadline = Instant::now() + NFC_CARD_WAIT_TIMEOUT;
        let mut next_session_check = Instant::now();
        let mut last_state = None;

        loop {
            let Some(slot) = (unsafe { manager.slotNamed(&name) }) else {
                let now = Instant::now();
                if now >= next_session_check {
                    session.check_active(message)?;
                    next_session_check = now + NFC_SESSION_CHECK_INTERVAL;
                }
                if last_state != Some(TKSmartCardSlotState::Missing) {
                    tracing::debug!(
                        target: "pkcs11rs::transport",
                        slot = reader_name,
                        "waiting for CryptoTokenKit NFC slot registration"
                    );
                    last_state = Some(TKSmartCardSlotState::Missing);
                }
                if Instant::now() >= deadline {
                    return Err(CKR_DEVICE_ERROR.into());
                }
                std::thread::sleep(NFC_CARD_POLL_INTERVAL);
                continue;
            };

            let state = unsafe { slot.state() };
            if last_state != Some(state) {
                tracing::debug!(
                    target: "pkcs11rs::transport",
                    slot = reader_name,
                    ?state,
                    "CryptoTokenKit NFC slot state changed"
                );
                last_state = Some(state);
            }
            if state == TKSmartCardSlotState::ValidCard {
                return autoreleasepool(|_| Self::from_slot(reader_name, &slot));
            }
            if state == TKSmartCardSlotState::MuteCard {
                return Err(CKR_DEVICE_ERROR.into());
            }
            if state != TKSmartCardSlotState::Probing {
                let now = Instant::now();
                if now >= next_session_check {
                    session.check_active(message)?;
                    next_session_check = now + NFC_SESSION_CHECK_INTERVAL;
                }
            }
            if Instant::now() >= deadline {
                return Err(CKR_DEVICE_ERROR.into());
            }
            std::thread::sleep(NFC_CARD_POLL_INTERVAL);
        }
    }

    pub(crate) fn reader_state(&self) -> Arc<PcscReaderState> {
        self.state.clone()
    }

    pub(crate) fn presence(&self) -> Arc<AtomicBool> {
        self.present.clone()
    }

    fn worker(&self) -> Result<&AppleCcidWorker, Error> {
        self.worker
            .get_or_init(|| AppleCcidWorker::spawn(self.reader_name.clone(), self.nfc.clone()))
            .as_ref()
            .map_err(|error| Error::from(*error))
    }

    fn transmit_owned(&self, command: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let timeout = if timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };
        self.worker()?.transmit(command, timeout)
    }
}

struct NfcSessionGuard(Retained<TKSmartCardSlotNFCSession>);

impl NfcSessionGuard {
    fn check_active(&self, message: &str) -> Result<(), Error> {
        self.update_message_checked(message)
    }

    fn update_message_checked(&self, message: &str) -> Result<(), Error> {
        autoreleasepool(|_| {
            let message = NSString::from_str(message);
            unsafe { self.0.updateWithMessage_error(&message) }.map_err(|error| {
                nfc_diagnostic(format_args!(
                    "NFC session message update failed: code={} description={}",
                    error.code(),
                    error.localizedDescription()
                ));
                tracing::debug!(
                    target: "pkcs11rs::transport",
                    error_code = error.code(),
                    error = %error.localizedDescription(),
                    "CryptoTokenKit NFC session is no longer active"
                );
                if matches!(
                    error.code(),
                    code if code == TKErrorCode::CanceledByUser.0
                        || code == TKErrorCode::ObjectNotFound.0
                ) {
                    Error::from(CKR_FUNCTION_CANCELED)
                } else {
                    Error::from(CKR_DEVICE_ERROR)
                }
            })
        })
    }
}

impl Drop for NfcSessionGuard {
    fn drop(&mut self) {
        nfc_diagnostic(format_args!("ending NFC slot session"));
        unsafe { self.0.endSession() };
    }
}

fn create_nfc_session(message: &str) -> Result<(NfcSessionGuard, String), Error> {
    load_crypto_token_kit()?;
    let manager = unsafe { TKSmartCardSlotManager::defaultManager() }.ok_or(CKR_DEVICE_ERROR)?;
    if !unsafe { manager.isNFCSupported() } {
        return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    let completion = RcBlock::new(
        move |session: *mut TKSmartCardSlotNFCSession, error: *mut NSError| {
            let result = unsafe {
                let Some(session) = Retained::retain(session) else {
                    let return_value = Retained::retain(error)
                        .map(|error| {
                            tracing::debug!(
                                target: "pkcs11rs::transport",
                                error_code = error.code(),
                                error = %error.localizedDescription(),
                                "CryptoTokenKit NFC session creation failed"
                            );
                            if error.code() == TKErrorCode::CanceledByUser.0 {
                                CKR_FUNCTION_CANCELED as CK_RV
                            } else {
                                CKR_DEVICE_ERROR as CK_RV
                            }
                        })
                        .unwrap_or(CKR_DEVICE_ERROR as CK_RV);
                    let _ = sender.try_send(Err(return_value));
                    return;
                };
                let Some(slot_name) = session.slotName() else {
                    session.endSession();
                    let _ = sender.try_send(Err(CKR_DEVICE_ERROR as CK_RV));
                    return;
                };
                let slot_name = slot_name.to_string();
                nfc_diagnostic(format_args!("created NFC slot session: {slot_name}"));
                Ok((NfcSessionGuard(session), slot_name))
            };
            let _ = sender.try_send(result);
        },
    );
    autoreleasepool(|_| {
        let prompt = NSString::from_str(message);
        unsafe { manager.createNFCSlotWithMessage_completion(Some(&prompt), &completion) };
    });
    receiver
        .recv()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map_err(Error::from)
}

fn nfc_prompt(expected_serial: Option<&str>) -> String {
    expected_serial.map_or_else(
        || NFC_PROMPT.to_owned(),
        |serial| format!("Hold YubiKey {serial} near the top of this iPhone."),
    )
}

fn communication_message(expected_serial: Option<&str>) -> String {
    expected_serial.map_or_else(
        || "Communicating with the YubiKey…".to_owned(),
        |serial| format!("Communicating with YubiKey {serial}…"),
    )
}

struct PreparedNfcCard {
    generation: u64,
    slot_name: String,
    verify_serial: bool,
}

struct NfcTransportState {
    mounted: bool,
    session: Option<NfcSessionGuard>,
    slot_name: Option<String>,
    generation: u64,
    verified_generation: Option<u64>,
    expected_serial: Option<String>,
    active_operations: usize,
    operation_message: String,
    deadline: Option<Instant>,
    missing_since: Option<Instant>,
    cancel_retry_after: Option<Instant>,
    shutdown: bool,
}

pub(crate) struct NfcTransport {
    state: Mutex<NfcTransportState>,
    acquire: Mutex<()>,
    wake: Condvar,
}

impl std::fmt::Debug for NfcTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.try_lock().ok();
        formatter
            .debug_struct("NfcTransport")
            .field("mounted", &state.as_ref().map(|state| state.mounted))
            .field("generation", &state.as_ref().map(|state| state.generation))
            .field(
                "expected_serial",
                &state
                    .as_ref()
                    .and_then(|state| state.expected_serial.as_deref()),
            )
            .finish_non_exhaustive()
    }
}

impl NfcTransport {
    fn new(session: NfcSessionGuard, slot_name: String) -> Result<Arc<Self>, Error> {
        let transport = Arc::new(Self {
            state: Mutex::new(NfcTransportState {
                mounted: true,
                session: Some(session),
                slot_name: Some(slot_name),
                generation: 1,
                verified_generation: Some(1),
                expected_serial: None,
                active_operations: 0,
                operation_message: NFC_READING.to_owned(),
                deadline: None,
                missing_since: None,
                cancel_retry_after: None,
                shutdown: false,
            }),
            acquire: Mutex::new(()),
            wake: Condvar::new(),
        });
        let timer = transport.clone();
        std::thread::Builder::new()
            .name("pkcs11rs-apple-nfc-idle".to_owned())
            .spawn(move || timer.run_timer())
            .map_err(|_| CKR_HOST_MEMORY)?;
        Ok(transport)
    }

    fn run_timer(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        loop {
            if state.shutdown {
                return;
            }
            let Some(deadline) = state.deadline else {
                state = match self.wake.wait(state) {
                    Ok(state) => state,
                    Err(_) => return,
                };
                continue;
            };
            let now = Instant::now();
            if now < deadline {
                let duration = deadline.saturating_duration_since(now);
                let result = self.wake.wait_timeout(state, duration);
                state = match result {
                    Ok((state, _)) => state,
                    Err(_) => return,
                };
                continue;
            }
            state.deadline = None;
            if state.active_operations != 0 || state.session.is_none() {
                continue;
            }

            let card_present = state
                .slot_name
                .as_deref()
                .is_some_and(nfc_slot_has_valid_card);
            if !card_present {
                let missing_since = *state.missing_since.get_or_insert(now);
                let confirmed_at = missing_since + NFC_REMOVAL_CONFIRMATION;
                if now < confirmed_at {
                    state.deadline = Some(confirmed_at);
                    continue;
                }
                let ended = state.session.take();
                state.slot_name = None;
                state.verified_generation = None;
                state.missing_since = None;
                drop(state);
                drop(ended);
                state = match self.state.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                continue;
            }
            state.missing_since = None;
            state.deadline = Some(Instant::now() + NFC_REMOVAL_POLL_INTERVAL);
        }
    }

    fn operation_display_message(state: &NfcTransportState) -> String {
        if state.operation_message == crate::logging::COMMUNICATING_MESSAGE {
            communication_message(state.expected_serial.as_deref())
        } else {
            state.operation_message.clone()
        }
    }

    fn prepare(&self) -> Result<PreparedNfcCard, CK_RV> {
        let _acquire = self.acquire.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        let mut stale = None;
        let mut inactive_error = None;
        let expected_serial;
        {
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
            if !state.mounted || state.shutdown {
                return Err(CKR_TOKEN_NOT_PRESENT as CK_RV);
            }
            let now = Instant::now();
            if state
                .cancel_retry_after
                .is_some_and(|retry_after| now < retry_after)
            {
                return Err(CKR_FUNCTION_CANCELED as CK_RV);
            }
            state.cancel_retry_after = None;
            let message = Self::operation_display_message(&state);
            if let Some(session) = &state.session {
                match session.update_message_checked(&message) {
                    Ok(()) => {
                        return Ok(PreparedNfcCard {
                            generation: state.generation,
                            slot_name: state.slot_name.clone().ok_or(CKR_DEVICE_ERROR as CK_RV)?,
                            verify_serial: state.verified_generation != Some(state.generation),
                        });
                    }
                    Err(error) => {
                        let error = CK_RV::from(error);
                        if error == CKR_FUNCTION_CANCELED as CK_RV {
                            state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
                        }
                        inactive_error = Some(error);
                    }
                }
                nfc_diagnostic(format_args!(
                    "discarding inactive NFC slot session generation {}",
                    state.generation
                ));
                stale = state.session.take();
                state.slot_name = None;
                state.verified_generation = None;
            }
            expected_serial = state.expected_serial.clone();
        }
        drop(stale);
        if let Some(error) = inactive_error {
            return Err(error);
        }

        nfc_diagnostic(format_args!("requesting replacement NFC slot session"));
        let prompt = nfc_prompt(expected_serial.as_deref());
        let (session, slot_name) =
            create_nfc_session(&prompt).map_err(|error| self.latch_cancellation(error))?;
        CcidConnector::wait_for_named_card(&slot_name, &session, &prompt)
            .map_err(|error| self.latch_cancellation(error))?;
        let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        if !state.mounted || state.shutdown {
            drop(state);
            drop(session);
            return Err(CKR_TOKEN_NOT_PRESENT as CK_RV);
        }
        let message = Self::operation_display_message(&state);
        session
            .update_message_checked(&message)
            .map_err(CK_RV::from)?;
        state.generation = state.generation.wrapping_add(1).max(1);
        nfc_diagnostic(format_args!(
            "installed NFC slot session generation {}",
            state.generation
        ));
        state.verified_generation = state.expected_serial.is_none().then_some(state.generation);
        state.slot_name = Some(slot_name.clone());
        state.session = Some(session);
        state.missing_since = None;
        Ok(PreparedNfcCard {
            generation: state.generation,
            slot_name,
            verify_serial: state.verified_generation != Some(state.generation),
        })
    }

    fn verify_serial(&self, generation: u64, serial: Option<&str>) -> Result<bool, CK_RV> {
        let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        if state.generation != generation {
            return Err(CKR_DEVICE_REMOVED as CK_RV);
        }
        let matches = state
            .expected_serial
            .as_deref()
            .zip(serial)
            .is_some_and(|(expected, presented)| expected == presented);
        if matches {
            state.verified_generation = Some(generation);
            return Ok(true);
        }
        if let Some(session) = &state.session {
            session
                .update_message_checked("Wrong YubiKey — please remove it.")
                .map_err(CK_RV::from)?;
        }
        Ok(false)
    }

    fn wait_for_replacement(&self, generation: u64) -> Result<(), CK_RV> {
        let deadline = Instant::now() + NFC_CARD_WAIT_TIMEOUT;
        let mut removed = false;
        let mut next_session_check = Instant::now();
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(CKR_DEVICE_ERROR as CK_RV);
            }
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
            if state.generation != generation || !state.mounted || state.shutdown {
                return Err(CKR_DEVICE_REMOVED as CK_RV);
            }
            let slot_name = state
                .slot_name
                .as_deref()
                .ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
            let card_present = nfc_slot_has_valid_card(slot_name);
            if removed && card_present {
                return Ok(());
            }
            if !card_present {
                removed = true;
            }
            if now >= next_session_check {
                let expected = state
                    .expected_serial
                    .as_deref()
                    .unwrap_or("the mounted key");
                let message = if removed {
                    format!("Please present YubiKey {expected}.")
                } else {
                    "Wrong YubiKey — please remove it.".to_owned()
                };
                if let Err(error) = state
                    .session
                    .as_ref()
                    .ok_or(CKR_DEVICE_REMOVED as CK_RV)?
                    .update_message_checked(&message)
                {
                    let error = CK_RV::from(error);
                    if error == CKR_FUNCTION_CANCELED as CK_RV {
                        state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
                    }
                    return Err(error);
                }
                next_session_check = now + NFC_SESSION_CHECK_INTERVAL;
            }
            drop(state);
            std::thread::sleep(NFC_CARD_POLL_INTERVAL);
        }
    }

    fn latch_cancellation(&self, error: Error) -> CK_RV {
        let error = CK_RV::from(error);
        if error == CKR_FUNCTION_CANCELED as CK_RV {
            if let Ok(mut state) = self.state.lock() {
                state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
            }
        }
        error
    }

    fn mark_session_unverified(&self, error: CK_RV) {
        if let Ok(mut state) = self.state.lock() {
            if error == CKR_FUNCTION_CANCELED as CK_RV {
                state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
            }
            state.verified_generation = None;
        }
    }

    pub(crate) fn bind_serial(&self, serial: &str) -> Result<(), Error> {
        if serial.is_empty() || serial.chars().all(|character| character == '0') {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD)?;
        if state
            .expected_serial
            .as_deref()
            .is_some_and(|expected| expected != serial)
        {
            return Err(CKR_DEVICE_REMOVED.into());
        }
        state.expected_serial = Some(serial.to_owned());
        state.verified_generation = Some(state.generation);
        Ok(())
    }

    pub(crate) fn slot_name(&self) -> Result<String, Error> {
        self.state
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .slot_name
            .clone()
            .ok_or_else(|| Error::from(CKR_DEVICE_REMOVED))
    }

    pub(crate) fn is_mounted(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.mounted && !state.shutdown)
    }

    pub(crate) fn shutdown(&self) {
        let ended = self.state.lock().ok().and_then(|mut state| {
            state.mounted = false;
            state.shutdown = true;
            state.deadline = None;
            state.missing_since = None;
            state.slot_name = None;
            state.verified_generation = None;
            state.session.take()
        });
        self.wake.notify_all();
        drop(ended);
    }
}

impl DeviceOperationLifecycle for NfcTransport {
    fn enter(&self, message: &str) -> Result<(), Error> {
        let mut ended = None;
        {
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD)?;
            if !state.mounted || state.shutdown {
                return Err(CKR_TOKEN_NOT_PRESENT.into());
            }
            state.active_operations = state
                .active_operations
                .checked_add(1)
                .ok_or(CKR_DEVICE_ERROR)?;
            state.operation_message = message.to_owned();
            state.deadline = None;
            state.missing_since = None;
            let message = Self::operation_display_message(&state);
            if let Some(session) = &state.session {
                if session.update_message_checked(&message).is_err() {
                    // This session was usable when the preceding operation went
                    // idle. A failure first observed by a new operation therefore
                    // represents an idle cancellation; the new operation is an
                    // explicit request to acquire another NFC session.
                    ended = state.session.take();
                    state.slot_name = None;
                    state.verified_generation = None;
                }
            }
        }
        self.wake.notify_all();
        drop(ended);
        Ok(())
    }

    fn exit(&self) {
        let mut ended = None;
        {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.active_operations = state.active_operations.saturating_sub(1);
            if state.active_operations == 0 && state.session.is_some() && !state.shutdown {
                let update_error = state
                    .session
                    .as_ref()
                    .and_then(|session| session.update_message_checked(NFC_IDLE).err());
                if let Some(error) = update_error {
                    if CK_RV::from(error) == CKR_FUNCTION_CANCELED as CK_RV {
                        state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
                    }
                    ended = state.session.take();
                    state.slot_name = None;
                    state.verified_generation = None;
                    state.missing_since = None;
                } else {
                    state.deadline = Some(Instant::now());
                    self.wake.notify_all();
                }
            }
        }
        drop(ended);
    }
}

fn nfc_slot_has_valid_card(slot_name: &str) -> bool {
    autoreleasepool(|_| unsafe {
        let Some(manager) = TKSmartCardSlotManager::defaultManager() else {
            return false;
        };
        let name = NSString::from_str(slot_name);
        manager
            .slotNamed(&name)
            .is_some_and(|slot| slot.state() == TKSmartCardSlotState::ValidCard)
    })
}

#[derive(Debug)]
struct DirectCardConnector<'a> {
    card: &'a TKSmartCard,
    timeout: Duration,
}

impl Connector for DirectCardConnector<'_> {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Yubico"
    }

    fn product(&self) -> &str {
        "NFC smart card"
    }

    fn major(&self) -> u8 {
        0
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        card_is_valid(self.card)
    }

    fn buffer_size(&self) -> usize {
        4096
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = transmit_card(self.card, send_buffer, self.timeout).map_err(Error::from)?;
        if response.len() > receive_buffer.len() {
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

fn discover_card_identity(
    card: &TKSmartCard,
    timeout: Duration,
) -> Result<crate::yubikey::DeviceInfo, CK_RV> {
    begin_session(card, timeout)?;
    let _session = SessionGuard(card);
    crate::YubiKeyClient
        .discover(&DirectCardConnector { card, timeout })
        .map_err(CK_RV::from)
}

pub(crate) fn begin_nfc_mount() -> Result<(Arc<NfcTransport>, CcidConnector, DeviceIdentity), Error>
{
    let prompt = nfc_prompt(None);
    let (session, slot_name) = create_nfc_session(&prompt)?;
    let profile = CcidConnector::wait_for_named_card(&slot_name, &session, &prompt)?;
    let card = resolve_card(&slot_name).map_err(Error::from)?;
    let info = discover_card_identity(&card, DEFAULT_TIMEOUT).map_err(Error::from)?;
    let serial = info
        .serial
        .filter(|serial| !serial.is_empty() && !serial.chars().all(|character| character == '0'))
        .ok_or(CKR_DEVICE_ERROR)?;
    let identity = DeviceIdentity {
        manufacturer: String::from("Yubico"),
        product: info.part_number.unwrap_or_else(|| String::from("YubiKey")),
        serial,
        hardware_version: None,
        firmware_version: info.version,
    };
    let transport = NfcTransport::new(session, slot_name.clone())?;
    let connector = CcidConnector::new_nfc(
        slot_name,
        profile.atr,
        profile.max_input_length,
        profile.max_output_length,
        transport.clone(),
    );
    Ok((transport, connector, identity))
}

impl std::fmt::Debug for CcidConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CcidConnector")
            .field("reader_name", &self.reader_name)
            .field("atr", &self.atr)
            .field("max_input_length", &self.max_input_length)
            .field("max_output_length", &self.max_output_length)
            .finish_non_exhaustive()
    }
}

impl Connector for CcidConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        Some(self.state.device.clone())
    }

    fn name(&self) -> String {
        self.reader_name.clone()
    }

    fn manufacturer(&self) -> &str {
        "Yubico"
    }

    fn product(&self) -> &str {
        &self.reader_name
    }

    fn major(&self) -> u8 {
        self.firmware_version()
            .map(|(major, _, _)| major)
            .unwrap_or(0)
    }

    fn minor(&self) -> u8 {
        self.firmware_version()
            .map(|(_, minor, patch)| minor.saturating_mul(10).saturating_add(patch))
            .unwrap_or(0)
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.state.device.identity(0).firmware_version
    }

    fn is_present(&self) -> bool {
        self.nfc.as_ref().map_or_else(
            || self.present.load(Ordering::Acquire),
            |nfc| nfc.is_mounted(),
        )
    }

    fn buffer_size(&self) -> usize {
        self.max_output_length
    }

    fn apdu_capabilities(&self) -> ApduCapabilities {
        let card = crate::iso7816::atr_apdu_capabilities(&self.atr)
            .unwrap_or(ApduCapabilities::SHORT_ONLY);
        ApduCapabilities {
            command_chaining: card.command_chaining,
            extended: card.extended && self.max_input_length > 261,
        }
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let operation = crate::logging::Operation::trace(tracing::trace_span!(
            target: "pkcs11rs::transport",
            "cryptotokenkit.transmit",
            reader = %self.reader_name,
            request_bytes = send_buffer.len(),
            timeout_ms = timeout.as_millis() as u64
        ));
        let _entered = operation.enter();
        let response = self.transmit_owned(send_buffer, timeout)?;
        if response.len() > receive_buffer.len() {
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }

    fn refresh(&self) -> Result<(), Error> {
        if let Some(nfc) = &self.nfc {
            return nfc
                .is_mounted()
                .then_some(())
                .ok_or_else(|| Error::from(CKR_TOKEN_NOT_PRESENT));
        }
        self.worker()?.refresh()
    }
}

pub(crate) struct CcidReader {
    pub(crate) connector: SharedConnector,
    pub(crate) reader_state: Arc<PcscReaderState>,
    pub(crate) inventory_presence: Option<Arc<AtomicBool>>,
}

pub(crate) struct CcidProvider {
    enabled: bool,
}

impl CcidProvider {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub(crate) fn name(&self) -> &'static str {
        "cryptotokenkit"
    }

    pub(crate) fn enumerate(&self) -> Result<Vec<CcidReader>, Error> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        CcidConnector::enumerate()?
            .into_iter()
            .map(|connector| {
                let reader_state = connector.reader_state();
                let inventory_presence = Some(connector.presence());
                Ok(CcidReader {
                    connector: Arc::new(connector) as SharedConnector,
                    reader_state,
                    inventory_presence,
                })
            })
            .collect()
    }
}

impl std::fmt::Debug for CcidProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CcidProvider")
            .field("name", &self.name())
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}
