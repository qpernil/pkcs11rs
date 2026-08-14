use super::card::card_is_valid;
use super::nfc::{
    NFC_CARD_POLL_INTERVAL, NFC_CARD_WAIT_TIMEOUT, NFC_SESSION_CHECK_INTERVAL, NfcSessionGuard,
    NfcTransport,
};
use super::worker::AppleCcidWorker;
use super::{AppleCcidLifecycle, DEFAULT_TIMEOUT, load_crypto_token_kit};
use crate::device::{DeviceContext, DeviceIdentity, DeviceOperationLifecycle};
use crate::*;
use objc2::rc::autoreleasepool;
use objc2_crypto_token_kit::{TKSmartCardSlot, TKSmartCardSlotManager, TKSmartCardSlotState};
use objc2_foundation::NSString;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;

#[derive(Clone)]
pub(crate) struct CcidConnector {
    reader_name: String,
    atr: Vec<u8>,
    max_input_length: usize,
    max_output_length: usize,
    state: Arc<PcscReaderState>,
    present: Arc<AtomicBool>,
    connection_epoch: Arc<AtomicU64>,
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
        let present = nfc
            .as_ref()
            .map_or_else(|| Arc::new(AtomicBool::new(true)), |nfc| nfc.presence());
        let worker = Arc::new(OnceLock::new());
        let connection_epoch = Arc::new(AtomicU64::new(0));
        let state = Arc::new_cyclic(|reader_state| {
            let lifecycle = Arc::new(AppleCcidLifecycle {
                reader_name: reader_name.clone(),
                worker: worker.clone(),
                reader_state: reader_state.clone(),
                present: present.clone(),
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
            present,
            connection_epoch,
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

    pub(super) fn new_nfc(
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

    pub(super) fn into_transport_profile(self) -> (Vec<u8>, usize, usize) {
        (self.atr, self.max_input_length, self.max_output_length)
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

    pub(super) fn wait_for_named_card(
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

    fn connection_epoch(&self) -> u64 {
        self.connection_epoch.load(Ordering::Acquire)
    }

    fn transport_verified_serial(&self) -> Option<String> {
        self.nfc
            .as_ref()
            .filter(|nfc| nfc.has_verified_card())
            .and_then(|nfc| nfc.mounted_serial())
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

    fn begin_transport_operation(&self, message: &str) -> Result<(), Error> {
        if let Some(nfc) = &self.nfc {
            nfc.enter(crate::device::DeviceOperationKind::Ccid, message)?;
        }
        if let Err(error) = self.worker()?.begin_operation() {
            if let Some(nfc) = &self.nfc {
                nfc.exit(crate::device::DeviceOperationKind::Ccid);
            }
            return Err(error);
        }
        Ok(())
    }

    fn end_transport_operation(&self) {
        if let Ok(worker) = self.worker() {
            if let Err(error) = worker.end_operation() {
                tracing::debug!(
                    target: "pkcs11rs::transport",
                    reader = %self.reader_name,
                    ?error,
                    "failed to end CryptoTokenKit transport operation"
                );
            }
        }
        if let Some(nfc) = &self.nfc {
            nfc.exit(crate::device::DeviceOperationKind::Ccid);
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
        if self.worker()?.refresh()? {
            self.connection_epoch.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
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
