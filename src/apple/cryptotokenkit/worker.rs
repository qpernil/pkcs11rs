use super::card::{
    OwnedSessionGuard, SessionGuard, begin_session, card_is_valid, discover_card_identity,
    resolve_card, transmit_card,
};
use super::{DEFAULT_TIMEOUT, NfcTransport, nfc_diagnostic};
use crate::*;
use objc2::rc::Retained;
use objc2_crypto_token_kit::TKSmartCard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

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

pub(super) struct AppleCcidWorker {
    requests: mpsc::Sender<WorkerRequest>,
}
impl AppleCcidWorker {
    pub(super) fn spawn(
        reader_name: String,
        nfc: Option<Arc<NfcTransport>>,
        present: Arc<AtomicBool>,
    ) -> Result<Self, CK_RV> {
        let (requests, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("pkcs11rs-apple-ccid".to_owned())
            .spawn(move || run_worker(reader_name, nfc, present, receiver))
            .map_err(|_| CKR_HOST_MEMORY)?;
        Ok(Self { requests })
    }

    pub(super) fn refresh(&self) -> Result<(), Error> {
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
                let result = if let Some(nfc) = &nfc {
                    if nfc.has_verified_card() {
                        Ok(())
                    } else {
                        prepare_nfc_card(nfc, &mut card, &mut card_generation, DEFAULT_TIMEOUT)
                    }
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
                present.store(result.is_ok(), Ordering::Release);
                let _ = reply.try_send(result);
            }
            WorkerRequest::Transmit {
                command,
                timeout,
                reply,
            } => {
                let result = (|| {
                    if let Some(nfc) = &nfc {
                        prepare_nfc_card(nfc, &mut card, &mut card_generation, timeout)?;
                    }
                    if !card.as_deref().is_some_and(card_is_valid) {
                        card = Some(resolve_card(&reader_name)?);
                    }
                    if operation_active {
                        if active_session.is_none() {
                            let current = card.as_ref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
                            begin_session(current, timeout)?;
                            active_session = Some(OwnedSessionGuard::new(current.clone()));
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
                        let _session = SessionGuard::new(current);
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

fn prepare_nfc_card(
    nfc: &NfcTransport,
    card: &mut Option<Retained<TKSmartCard>>,
    card_generation: &mut Option<u64>,
    timeout: Duration,
) -> Result<(), CK_RV> {
    let prepared = nfc.prepare()?;
    loop {
        if *card_generation != Some(prepared.generation) {
            *card = None;
            *card_generation = Some(prepared.generation);
        }
        if !card.as_deref().is_some_and(card_is_valid) {
            *card = Some(resolve_card(&prepared.slot_name)?);
        }
        if !prepared.verify_serial {
            return Ok(());
        }
        let current = card.as_deref().ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
        let identity = discover_card_identity(current, timeout)?;
        if nfc.verify_serial(prepared.generation, identity.serial.as_deref())? {
            return Ok(());
        }
        nfc.wait_for_replacement(prepared.generation)?;
        *card = None;
    }
}
