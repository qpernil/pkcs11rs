mod card;
mod nfc;
mod provider;
mod worker;

pub(crate) use nfc::{NfcTransport, begin_nfc_mount};
pub(crate) use provider::{CcidConnector, CcidProvider, CcidReader};

use crate::device::DeviceOperationLifecycle;
use crate::*;
use std::ffi::{c_char, c_int, c_void};
use std::sync::{Arc, OnceLock, Weak, atomic::AtomicBool};
use worker::AppleCcidWorker;

fn nfc_diagnostic(message: std::fmt::Arguments<'_>) {
    eprintln!("[pkcs11rs:nfc] {message}");
}

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

struct AppleCcidLifecycle {
    reader_name: String,
    worker: Arc<OnceLock<Result<AppleCcidWorker, CK_RV>>>,
    reader_state: Weak<PcscReaderState>,
    present: Arc<AtomicBool>,
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
            .get_or_init(|| {
                AppleCcidWorker::spawn(
                    self.reader_name.clone(),
                    self.nfc.clone(),
                    self.present.clone(),
                )
            })
            .as_ref()
            .map_err(|error| Error::from(*error))
    }
}

impl DeviceOperationLifecycle for AppleCcidLifecycle {
    fn enter(&self, kind: crate::device::DeviceOperationKind, message: &str) -> Result<(), Error> {
        if kind == crate::device::DeviceOperationKind::Hid {
            return Ok(());
        }
        if let Some(nfc) = &self.nfc {
            nfc.enter(kind, message)?;
        }
        let Some(reader_state) = self.reader_state.upgrade() else {
            if let Some(nfc) = &self.nfc {
                nfc.exit(kind);
            }
            return Err(CKR_DEVICE_ERROR.into());
        };
        if let Err(error) = reader_state.begin_transaction() {
            if let Some(nfc) = &self.nfc {
                nfc.exit(kind);
            }
            return Err(error);
        }
        if let Err(error) = self.worker().and_then(AppleCcidWorker::begin_operation) {
            reader_state.end_transaction();
            if let Some(nfc) = &self.nfc {
                nfc.exit(kind);
            }
            return Err(error);
        }
        Ok(())
    }

    fn exit(&self, kind: crate::device::DeviceOperationKind) {
        if kind == crate::device::DeviceOperationKind::Hid {
            return;
        }
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
            nfc.exit(kind);
        }
    }
}
