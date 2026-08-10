use crate::device::{DeviceContext, DeviceIdentity};
use crate::*;
use block2::RcBlock;
use objc2::{rc::Retained, rc::autoreleasepool, runtime::Bool};
use objc2_crypto_token_kit::{TKSmartCard, TKSmartCardSlotManager};
use objc2_foundation::{NSData, NSError, NSString};
use std::ffi::{c_char, c_int, c_void};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
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

impl AppleCcidWorker {
    fn spawn(reader_name: String) -> Result<Self, CK_RV> {
        let (requests, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("pkcs11rs-apple-ccid".to_owned())
            .spawn(move || run_worker(reader_name, receiver))
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

fn begin_session(card: &TKSmartCard, timeout: Duration) -> Result<(), CK_RV> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        let _ = sender.try_send(success.as_bool());
    });
    unsafe { card.beginSessionWithReply(&reply) };
    match receiver.recv_timeout(timeout) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(CKR_DEVICE_ERROR as CK_RV),
    }
}

struct SessionGuard<'a>(&'a TKSmartCard);

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        unsafe { self.0.endSession() };
    }
}

fn transmit_card(card: &TKSmartCard, command: &[u8], timeout: Duration) -> Result<Vec<u8>, CK_RV> {
    autoreleasepool(|_| {
        let request = NSData::with_bytes(command);
        let (sender, receiver) = mpsc::sync_channel(1);
        let reply = RcBlock::new(move |response: *mut NSData, _error: *mut NSError| {
            let response = unsafe { response.as_ref() }.map(NSData::to_vec);
            let _ = sender.try_send(response);
        });
        unsafe { card.transmitRequest_reply(&request, &reply) };
        match receiver.recv_timeout(timeout) {
            Ok(Some(response)) => Ok(response),
            Ok(None) | Err(_) => Err(CKR_DEVICE_ERROR as CK_RV),
        }
    })
}

fn run_worker(reader_name: String, receiver: mpsc::Receiver<WorkerRequest>) {
    let mut card: Option<Retained<TKSmartCard>> = None;

    loop {
        let request = match receiver.recv() {
            Ok(request) => request,
            Err(_) => break,
        };

        match request {
            WorkerRequest::Refresh { reply } => {
                let result = if card.as_deref().is_some_and(card_is_valid) {
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
                    if !card.as_deref().is_some_and(card_is_valid) {
                        card = Some(resolve_card(&reader_name)?);
                    }
                    let current = card.as_deref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                    begin_session(current, timeout)?;
                    let _session = SessionGuard(current);
                    transmit_card(current, &command, timeout)
                })();
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
}

impl CcidConnector {
    fn new(
        reader_name: String,
        atr: Vec<u8>,
        max_input_length: usize,
        max_output_length: usize,
    ) -> Self {
        let device = Arc::new(DeviceContext::new(DeviceIdentity::unknown(
            "Yubico",
            reader_name.clone(),
        )));
        Self {
            reader_name,
            atr,
            max_input_length,
            max_output_length,
            state: Arc::new(PcscReaderState::new(device)),
            present: Arc::new(AtomicBool::new(true)),
            worker: Arc::new(OnceLock::new()),
        }
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

    pub(crate) fn reader_state(&self) -> Arc<PcscReaderState> {
        self.state.clone()
    }

    pub(crate) fn presence(&self) -> Arc<AtomicBool> {
        self.present.clone()
    }

    fn worker(&self) -> Result<&AppleCcidWorker, Error> {
        self.worker
            .get_or_init(|| AppleCcidWorker::spawn(self.reader_name.clone()))
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
        self.present.load(Ordering::Acquire)
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
