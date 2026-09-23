use super::card::{discover_card_identity, resolve_card};
use super::{CcidConnector, DEFAULT_TIMEOUT, load_crypto_token_kit, nfc_diagnostic};
use crate::device::{DeviceIdentity, DeviceOperationLifecycle};
use crate::*;
use block2::RcBlock;
use objc2::{rc::Retained, rc::autoreleasepool};
use objc2_crypto_token_kit::{
    TKErrorCode, TKSmartCardSlotManager, TKSmartCardSlotNFCSession, TKSmartCardSlotState,
};
use objc2_foundation::{NSError, NSString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Instant;

pub(super) const NFC_CARD_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
pub(super) const NFC_CARD_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const NFC_SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const NFC_REMOVAL_POLL_INTERVAL: Duration = Duration::from_millis(200);
const NFC_REMOVAL_CONFIRMATION: Duration = Duration::from_millis(250);
const NFC_CANCEL_COOLDOWN: Duration = Duration::from_millis(500);
const NFC_PROMPT: &str = "Hold your YubiKey near the top of this iPhone.";
const NFC_READING: &str = "YubiKey found. Reading YubiHSM Auth credentials…";
const NFC_IDLE: &str = "Idle — you may remove your YubiKey";

static NEXT_NFC_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub(super) struct NfcSessionGuard {
    session: Retained<TKSmartCardSlotNFCSession>,
    id: u64,
    created: Instant,
    close_reason: &'static str,
}

impl NfcSessionGuard {
    fn new(session: Retained<TKSmartCardSlotNFCSession>) -> Self {
        let guard = Self {
            session,
            id: NEXT_NFC_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            created: Instant::now(),
            close_reason: "creation callback result was not adopted",
        };
        nfc_diagnostic(format_args!("NFC session {}: created", guard.id));
        guard
    }

    pub(super) fn check_active(&self, message: &str) -> Result<(), Error> {
        self.update_message_checked(message)
    }

    fn update_message_checked(&self, message: &str) -> Result<(), Error> {
        autoreleasepool(|_| {
            let message = NSString::from_str(message);
            unsafe { self.session.updateWithMessage_error(&message) }.map_err(|error| {
                nfc_diagnostic(format_args!(
                    "NFC session {}: message update failed: domain={} code={} description={}",
                    self.id,
                    error.domain(),
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
        nfc_diagnostic(format_args!(
            "NFC session {}: requesting dialog close via endSession; reason={}; age_ms={}; unwinding={}",
            self.id,
            self.close_reason,
            self.created.elapsed().as_millis(),
            std::thread::panicking()
        ));
        unsafe { self.session.endSession() };
        nfc_diagnostic(format_args!("NFC session {}: endSession returned", self.id));
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
                let mut session = NfcSessionGuard::new(session);
                let Some(slot_name) = session.session.slotName() else {
                    session.close_reason = "creation callback returned no slot name";
                    drop(session);
                    let _ = sender.try_send(Err(CKR_DEVICE_ERROR as CK_RV));
                    return;
                };
                let slot_name = slot_name.to_string();
                nfc_diagnostic(format_args!("NFC session {}: slot={slot_name}", session.id));
                Ok((session, slot_name))
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

pub(super) struct PreparedNfcCard {
    pub(super) generation: u64,
    pub(super) slot_name: String,
    pub(super) verify_serial: bool,
}

// CryptoTokenKit NFC slot names are session-scoped. The initial identity scan
// binds one device serial to the module-lifetime PKCS #11 slots; every later
// session is only transport state for that same stable identity.
struct NfcTransportState {
    mounted_serial: Option<String>,
    session: Option<NfcSessionGuard>,
    slot_name: Option<String>,
    generation: u64,
    verified_generation: Option<u64>,
    operation_active: bool,
    operation_message: String,
    deadline: Option<Instant>,
    missing_since: Option<Instant>,
    cancel_retry_after: Option<Instant>,
}

impl NfcTransportState {
    fn take_session(&mut self, reason: &'static str) -> Option<NfcSessionGuard> {
        self.session.take().map(|mut session| {
            session.close_reason = reason;
            nfc_diagnostic(format_args!(
                "NFC session {}: releasing generation={}; operation_active={}; slot={:?}; reason={reason}",
                session.id, self.generation, self.operation_active, self.slot_name
            ));
            session
        })
    }
}

pub(crate) struct NfcTransport {
    state: Mutex<NfcTransportState>,
    present: Arc<AtomicBool>,
    acquire: Mutex<()>,
    wake: Condvar,
}

impl std::fmt::Debug for NfcTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.try_lock().ok();
        formatter
            .debug_struct("NfcTransport")
            .field(
                "mounted_serial",
                &state
                    .as_ref()
                    .and_then(|state| state.mounted_serial.as_deref()),
            )
            .field("generation", &state.as_ref().map(|state| state.generation))
            .finish_non_exhaustive()
    }
}

impl NfcTransport {
    fn new(
        mut session: NfcSessionGuard,
        slot_name: String,
        expected_serial: String,
    ) -> Result<Arc<Self>, Error> {
        session.close_reason = "transport dropped (including idle worker startup failure)";
        let transport = Arc::new(Self {
            state: Mutex::new(NfcTransportState {
                mounted_serial: Some(expected_serial),
                session: Some(session),
                slot_name: Some(slot_name),
                generation: 1,
                verified_generation: Some(1),
                operation_active: false,
                operation_message: NFC_READING.to_owned(),
                deadline: None,
                missing_since: None,
                cancel_retry_after: None,
            }),
            present: Arc::new(AtomicBool::new(true)),
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
            if state.mounted_serial.is_none() {
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
            if state.operation_active || state.session.is_none() {
                continue;
            }

            let slot_state = state.slot_name.as_deref().and_then(nfc_slot_state);
            if nfc_slot_is_absent(slot_state) {
                let first_missing = state.missing_since.is_none();
                let missing_since = *state.missing_since.get_or_insert(now);
                if first_missing {
                    nfc_diagnostic(format_args!(
                        "idle NFC slot reports no card ({slot_state:?}); waiting for removal confirmation"
                    ));
                }
                let confirmed_at = missing_since + NFC_REMOVAL_CONFIRMATION;
                if now < confirmed_at {
                    state.deadline = Some(confirmed_at);
                    continue;
                }
                nfc_diagnostic(format_args!(
                    "idle NFC removal confirmed ({slot_state:?}); releasing slot session"
                ));
                let ended = state.take_session("idle removal confirmation expired");
                state.slot_name = None;
                state.verified_generation = None;
                state.missing_since = None;
                self.present.store(false, Ordering::Release);
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
            communication_message(state.mounted_serial.as_deref())
        } else {
            state.operation_message.clone()
        }
    }

    pub(super) fn prepare(&self) -> Result<PreparedNfcCard, CK_RV> {
        let _acquire = self.acquire.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        let mut stale = None;
        let mut inactive_error = None;
        let expected_serial;
        {
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
            expected_serial = state
                .mounted_serial
                .clone()
                .ok_or(CKR_TOKEN_NOT_PRESENT as CK_RV)?;
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
                stale = state.take_session("preparing APDU found an inactive NFC session");
                state.slot_name = None;
                state.verified_generation = None;
                self.present.store(false, Ordering::Release);
            }
        }
        drop(stale);
        if let Some(error) = inactive_error {
            return Err(error);
        }

        nfc_diagnostic(format_args!("requesting replacement NFC slot session"));
        let prompt = nfc_prompt(Some(&expected_serial));
        let (mut session, slot_name) =
            create_nfc_session(&prompt).map_err(|error| self.latch_cancellation(error))?;
        session.close_reason = "replacement card wait failed";
        CcidConnector::wait_for_named_card(&slot_name, &session, &prompt)
            .map_err(|error| self.latch_cancellation(error))?;
        session.close_reason = "replacement transport state lock failed";
        let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        if state.mounted_serial.is_none() {
            session.close_reason = "mount shut down during replacement acquisition";
            drop(state);
            drop(session);
            return Err(CKR_TOKEN_NOT_PRESENT as CK_RV);
        }
        let message = Self::operation_display_message(&state);
        session.close_reason = "replacement session message update failed";
        session
            .update_message_checked(&message)
            .map_err(CK_RV::from)?;
        state.generation = state.generation.wrapping_add(1).max(1);
        nfc_diagnostic(format_args!(
            "installed NFC slot session generation {}",
            state.generation
        ));
        state.verified_generation = None;
        state.slot_name = Some(slot_name.clone());
        session.close_reason = "transport dropped";
        state.session = Some(session);
        state.missing_since = None;
        self.present.store(false, Ordering::Release);
        Ok(PreparedNfcCard {
            generation: state.generation,
            slot_name,
            verify_serial: state.verified_generation != Some(state.generation),
        })
    }

    pub(super) fn verify_serial(
        &self,
        generation: u64,
        serial: Option<&str>,
    ) -> Result<bool, CK_RV> {
        let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
        if state.generation != generation {
            return Err(CKR_DEVICE_REMOVED as CK_RV);
        }
        let matches = state
            .mounted_serial
            .as_deref()
            .zip(serial)
            .is_some_and(|(mounted, presented)| mounted == presented);
        if matches {
            state.verified_generation = Some(generation);
            self.present.store(true, Ordering::Release);
            return Ok(true);
        }
        self.present.store(false, Ordering::Release);
        if let Some(session) = &state.session {
            session
                .update_message_checked("Wrong YubiKey — please remove it.")
                .map_err(CK_RV::from)?;
        }
        Ok(false)
    }

    pub(super) fn wait_for_replacement(&self, generation: u64) -> Result<(), CK_RV> {
        let deadline = Instant::now() + NFC_CARD_WAIT_TIMEOUT;
        let mut removed = false;
        let mut next_session_check = Instant::now();
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(CKR_DEVICE_ERROR as CK_RV);
            }
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD as CK_RV)?;
            if state.generation != generation || state.mounted_serial.is_none() {
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
                    .mounted_serial
                    .as_deref()
                    .ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
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

    pub(super) fn mark_session_unverified(&self, error: CK_RV) {
        if let Ok(mut state) = self.state.lock() {
            if error == CKR_FUNCTION_CANCELED as CK_RV {
                state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
            }
            state.verified_generation = None;
        }
        // A transport failure means this session is no longer evidence that
        // the mounted key is physically present. Reacquisition will set this
        // again only after it verifies the stable serial.
        self.present.store(false, Ordering::Release);
    }

    pub(crate) fn slot_name(&self) -> Result<String, Error> {
        self.state
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .slot_name
            .clone()
            .ok_or_else(|| Error::from(CKR_DEVICE_REMOVED))
    }

    // A mount survives removal of the physical card so its identity remains
    // available for lifecycle management and verified reacquisition.
    pub(crate) fn mounted_serial(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.mounted_serial.clone())
    }

    pub(crate) fn presence(&self) -> Arc<AtomicBool> {
        self.present.clone()
    }

    // Avoid running the interactive preparation path during an ordinary
    // refresh while the already verified CryptoTokenKit card is still valid.
    pub(super) fn has_verified_card(&self) -> bool {
        let slot_name = self.state.lock().ok().and_then(|state| {
            (state.mounted_serial.is_some() && state.verified_generation == Some(state.generation))
                .then(|| state.slot_name.clone())
                .flatten()
        });
        slot_name.as_deref().is_some_and(nfc_slot_has_valid_card)
    }

    pub(crate) fn shutdown(&self, reason: &'static str) {
        nfc_diagnostic(format_args!("NFC mount shutdown requested: {reason}"));
        let ended = self.state.lock().ok().and_then(|mut state| {
            let ended = state.take_session(reason);
            state.mounted_serial = None;
            state.deadline = None;
            state.missing_since = None;
            state.slot_name = None;
            state.verified_generation = None;
            ended
        });
        self.present.store(false, Ordering::Release);
        self.wake.notify_all();
        drop(ended);
    }
}

impl DeviceOperationLifecycle for NfcTransport {
    fn enter(&self, _kind: crate::device::DeviceOperationKind, message: &str) -> Result<(), Error> {
        let mut ended = None;
        {
            let mut state = self.state.lock().map_err(|_| CKR_MUTEX_BAD)?;
            if state.mounted_serial.is_none() {
                return Err(CKR_TOKEN_NOT_PRESENT.into());
            }
            if state.operation_active {
                return Err(CKR_OPERATION_ACTIVE.into());
            }
            state.operation_active = true;
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
                    ended = state.take_session("new operation found an inactive NFC session");
                    nfc_diagnostic(format_args!(
                        "new operation found an inactive NFC slot session; releasing it"
                    ));
                    state.slot_name = None;
                    state.verified_generation = None;
                    self.present.store(false, Ordering::Release);
                }
            }
        }
        self.wake.notify_all();
        drop(ended);
        Ok(())
    }

    fn exit(&self, _kind: crate::device::DeviceOperationKind) {
        let mut ended = None;
        {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.operation_active = false;
            if state.session.is_some() && state.mounted_serial.is_some() {
                let update_error = state
                    .session
                    .as_ref()
                    .and_then(|session| session.update_message_checked(NFC_IDLE).err());
                if let Some(error) = update_error {
                    if CK_RV::from(error) == CKR_FUNCTION_CANCELED as CK_RV {
                        state.cancel_retry_after = Some(Instant::now() + NFC_CANCEL_COOLDOWN);
                    }
                    ended = state.take_session("idle message update failed");
                    nfc_diagnostic(format_args!(
                        "idle message update failed; releasing NFC slot session"
                    ));
                    state.slot_name = None;
                    state.verified_generation = None;
                    state.missing_since = None;
                    self.present.store(false, Ordering::Release);
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
    nfc_slot_state(slot_name) == Some(TKSmartCardSlotState::ValidCard)
}

fn nfc_slot_state(slot_name: &str) -> Option<TKSmartCardSlotState> {
    autoreleasepool(|_| unsafe {
        let manager = TKSmartCardSlotManager::defaultManager()?;
        let name = NSString::from_str(slot_name);
        manager.slotNamed(&name).map(|slot| slot.state())
    })
}

fn nfc_slot_is_absent(state: Option<TKSmartCardSlotState>) -> bool {
    state.is_none_or(|state| {
        state == TKSmartCardSlotState::Missing || state == TKSmartCardSlotState::Empty
    })
}

pub(crate) fn begin_nfc_mount() -> Result<(Arc<NfcTransport>, CcidConnector, DeviceIdentity), Error>
{
    let prompt = nfc_prompt(None);
    let (mut session, slot_name) = create_nfc_session(&prompt)?;
    session.close_reason = "initial card wait failed";
    let profile = CcidConnector::wait_for_named_card(&slot_name, &session, &prompt)?;
    session.close_reason = "initial card resolution failed";
    let card = resolve_card(&slot_name).map_err(Error::from)?;
    session.close_reason = "initial card identity discovery failed";
    let info = discover_card_identity(&card, DEFAULT_TIMEOUT).map_err(Error::from)?;
    session.close_reason = "initial card identity has no usable serial";
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
    let transport = NfcTransport::new(session, slot_name.clone(), identity.serial.clone())?;
    let (atr, max_input_length, max_output_length) = profile.into_transport_profile();
    let connector = CcidConnector::new_nfc(
        slot_name,
        atr,
        max_input_length,
        max_output_length,
        transport.clone(),
    );
    Ok((transport, connector, identity))
}
