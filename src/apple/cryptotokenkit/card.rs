use super::nfc_diagnostic;
use crate::*;
use block2::RcBlock;
use objc2::{rc::Retained, rc::autoreleasepool, runtime::Bool};
use objc2_crypto_token_kit::{TKErrorCode, TKSmartCard, TKSmartCardSlotManager};
use objc2_foundation::{NSData, NSError, NSString};
use std::sync::mpsc;

pub(super) fn resolve_card(reader_name: &str) -> Result<Retained<TKSmartCard>, CK_RV> {
    autoreleasepool(|_| unsafe {
        let manager = TKSmartCardSlotManager::defaultManager().ok_or(CKR_DEVICE_ERROR as CK_RV)?;
        let reader_name = NSString::from_str(reader_name);
        let slot = manager
            .slotNamed(&reader_name)
            .ok_or(CKR_DEVICE_REMOVED as CK_RV)?;
        slot.makeSmartCard().ok_or(CKR_DEVICE_REMOVED as CK_RV)
    })
}

pub(super) fn card_is_valid(card: &TKSmartCard) -> bool {
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

pub(super) fn begin_session(card: &TKSmartCard, timeout: Duration) -> Result<(), CK_RV> {
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

pub(super) struct SessionGuard<'a>(&'a TKSmartCard);

impl<'a> SessionGuard<'a> {
    pub(super) fn new(card: &'a TKSmartCard) -> Self {
        Self(card)
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        nfc_diagnostic(format_args!("smart-card session ended"));
        unsafe { self.0.endSession() };
    }
}

pub(super) struct OwnedSessionGuard(Retained<TKSmartCard>);

impl OwnedSessionGuard {
    pub(super) fn new(card: Retained<TKSmartCard>) -> Self {
        Self(card)
    }

    pub(super) fn card(&self) -> &TKSmartCard {
        &self.0
    }
}

impl Drop for OwnedSessionGuard {
    fn drop(&mut self) {
        nfc_diagnostic(format_args!("smart-card session ended"));
        unsafe { self.0.endSession() };
    }
}

pub(super) fn transmit_card(
    card: &TKSmartCard,
    command: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, CK_RV> {
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

pub(super) fn discover_card_identity(
    card: &TKSmartCard,
    timeout: Duration,
) -> Result<crate::yubikey::DeviceInfo, CK_RV> {
    begin_session(card, timeout)?;
    let _session = SessionGuard::new(card);
    crate::YubiKeyClient
        .discover(&DirectCardConnector { card, timeout })
        .map_err(CK_RV::from)
}
