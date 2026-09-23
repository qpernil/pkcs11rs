use super::card::{
    OwnedSessionGuard, begin_session, card_is_valid, discover_card_identity, resolve_card,
    transmit_card,
};
use super::nfc::SharedNfcSession;
use super::{DEFAULT_TIMEOUT, NfcTransport, nfc_diagnostic};
use crate::nested_session::NestedSession;
use crate::*;
use objc2::rc::Retained;
use objc2_crypto_token_kit::TKSmartCard;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};

enum WorkerRequest {
    ReleaseNfcSession {
        id: u64,
    },
    BeginOperation {
        reply: mpsc::SyncSender<Result<(), CK_RV>>,
    },
    EndOperation {
        reply: mpsc::SyncSender<()>,
    },
    Refresh {
        reply: mpsc::SyncSender<Result<bool, CK_RV>>,
    },
    Transmit {
        command: Vec<u8>,
        timeout: Duration,
        reply: mpsc::SyncSender<Result<Vec<u8>, CK_RV>>,
    },
}

struct ActiveCardSession {
    nested: NestedSession<OwnedSessionGuard, SharedNfcSession>,
}

impl ActiveCardSession {
    fn new(card: Retained<TKSmartCard>, nfc_session: Option<SharedNfcSession>) -> Self {
        Self {
            nested: NestedSession {
                inner: Some(OwnedSessionGuard::new(card)),
                outer: nfc_session,
            },
        }
    }

    fn card(&self) -> &TKSmartCard {
        self.nested
            .inner
            .as_ref()
            .expect("active card session")
            .card()
    }

    fn nfc_session_id(&self) -> Option<u64> {
        self.nested.outer.as_ref().map(|session| session.id())
    }
}

pub(super) struct AppleCcidWorker {
    requests: mpsc::Sender<WorkerRequest>,
}
impl AppleCcidWorker {
    pub(super) fn release_nfc_session(&self, id: u64) {
        let _ = self.requests.send(WorkerRequest::ReleaseNfcSession { id });
    }

    pub(super) fn spawn(
        reader_name: String,
        nfc: Option<Arc<NfcTransport>>,
        present: Arc<AtomicBool>,
        connection_epoch: Arc<AtomicU64>,
    ) -> Result<Self, CK_RV> {
        let (requests, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("pkcs11rs-apple-ccid".to_owned())
            .spawn(move || run_worker(reader_name, nfc, present, connection_epoch, receiver))
            .map_err(|_| CKR_HOST_MEMORY)?;
        Ok(Self { requests })
    }

    pub(super) fn refresh(&self) -> Result<bool, Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::Refresh { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver
            .recv()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map_err(Error::from)
    }

    pub(super) fn begin_operation(&self) -> Result<(), Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::BeginOperation { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver
            .recv()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map_err(Error::from)
    }

    pub(super) fn end_operation(&self) -> Result<(), Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(WorkerRequest::EndOperation { reply })
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        receiver.recv().map_err(|_| Error::from(CKR_DEVICE_ERROR))
    }

    pub(super) fn transmit(&self, command: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
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

fn run_worker(
    reader_name: String,
    nfc: Option<Arc<NfcTransport>>,
    present: Arc<AtomicBool>,
    connection_epoch: Arc<AtomicU64>,
    receiver: mpsc::Receiver<WorkerRequest>,
) {
    let mut card: Option<Retained<TKSmartCard>> = None;
    let mut card_generation = None;
    let mut operation_active = false;
    let mut active_session: Option<ActiveCardSession> = None;

    loop {
        let request = match receiver.recv() {
            Ok(request) => request,
            Err(_) => break,
        };

        match request {
            WorkerRequest::ReleaseNfcSession { id } => {
                if active_session
                    .as_ref()
                    .and_then(ActiveCardSession::nfc_session_id)
                    == Some(id)
                {
                    active_session = None;
                    card = None;
                    card_generation = None;
                    connection_epoch.fetch_add(1, Ordering::AcqRel);
                }
            }
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
                operation_active = false;
                let _ = reply.try_send(());
            }
            WorkerRequest::Refresh { reply } => {
                let result = if let Some(nfc) = &nfc {
                    if nfc.has_verified_card() {
                        Ok(false)
                    } else {
                        prepare_nfc_card(
                            nfc,
                            &mut card,
                            &mut card_generation,
                            &mut active_session,
                            DEFAULT_TIMEOUT,
                        )
                        .map(|(changed, _)| changed)
                    }
                } else if card.as_deref().is_some_and(card_is_valid) {
                    Ok(false)
                } else {
                    active_session = None;
                    match resolve_card(&reader_name) {
                        Ok(resolved) if card_is_valid(&resolved) => {
                            card = Some(resolved);
                            Ok(true)
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
                if result.as_ref().is_ok_and(|changed| *changed) {
                    connection_epoch.fetch_add(1, Ordering::AcqRel);
                }
                present.store(result.is_ok(), Ordering::Release);
                let _ = reply.try_send(result);
            }
            WorkerRequest::Transmit {
                command,
                timeout,
                reply,
            } => {
                let result = (|| {
                    let mut changed = false;
                    let nfc_session = if let Some(nfc) = &nfc {
                        let (prepared_changed, session) = prepare_nfc_card(
                            nfc,
                            &mut card,
                            &mut card_generation,
                            &mut active_session,
                            timeout,
                        )?;
                        changed |= prepared_changed;
                        Some(session)
                    } else {
                        None
                    };
                    if !card.as_deref().is_some_and(card_is_valid) {
                        active_session = None;
                        card = Some(resolve_card(&reader_name)?);
                        changed = true;
                    }
                    if changed {
                        connection_epoch.fetch_add(1, Ordering::AcqRel);
                    }
                    if active_session.is_none() {
                        let current = card.as_ref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                        unsafe { current.setSensitive(true) };
                        begin_session(current, timeout)?;
                        active_session = Some(ActiveCardSession::new(current.clone(), nfc_session));
                    }
                    transmit_card(
                        active_session
                            .as_ref()
                            .ok_or(CKR_DEVICE_ERROR as CK_RV)?
                            .card(),
                        &command,
                        timeout,
                    )
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
                    connection_epoch.fetch_add(1, Ordering::AcqRel);
                }
                if result.is_err() && !card.as_deref().is_some_and(card_is_valid) {
                    card = None;
                }
                let _ = reply.try_send(result);
            }
        }
    }
}

fn prepare_nfc_card(
    nfc: &NfcTransport,
    card: &mut Option<Retained<TKSmartCard>>,
    card_generation: &mut Option<u64>,
    active_session: &mut Option<ActiveCardSession>,
    timeout: Duration,
) -> Result<(bool, SharedNfcSession), CK_RV> {
    let active_id = active_session
        .as_ref()
        .and_then(ActiveCardSession::nfc_session_id);
    let prepared = nfc.prepare(active_id, || *active_session = None)?;
    let mut changed = false;
    loop {
        if *card_generation != Some(prepared.generation) {
            *active_session = None;
            *card = None;
            *card_generation = Some(prepared.generation);
            changed = true;
        }
        if !card.as_deref().is_some_and(card_is_valid) {
            *active_session = None;
            *card = Some(resolve_card(&prepared.slot_name)?);
            changed = true;
        }
        if !prepared.verify_serial {
            return Ok((changed, prepared.session));
        }
        *active_session = None;
        let current = card.as_deref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
        unsafe { current.setSensitive(true) };
        let identity = discover_card_identity(current, timeout)?;
        if nfc.verify_serial(prepared.generation, identity.serial.as_deref())? {
            return Ok((changed, prepared.session));
        }
        *active_session = None;
        nfc.wait_for_replacement(prepared.generation)?;
        *card = None;
        changed = true;
    }
}
