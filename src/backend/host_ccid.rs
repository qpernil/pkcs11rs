use crate::device::{DeviceContext, DeviceIdentity};
use crate::*;
use std::{
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const MAX_READER_NAME_LENGTH: usize = 4 * 1024;
const MAX_ATR_LENGTH: usize = 64;

pub(crate) type HostCcidTransmit = unsafe extern "C" fn(
    context: *mut c_void,
    command: *const CK_BYTE,
    command_length: CK_ULONG,
    response: *mut CK_BYTE,
    response_length: *mut CK_ULONG,
    timeout_milliseconds: CK_ULONG,
) -> CK_RV;

pub(crate) type HostCcidAddReader = unsafe extern "C" fn(
    sink_context: *mut c_void,
    reader_name: *const CK_UTF8CHAR,
    reader_name_length: CK_ULONG,
    atr: *const CK_BYTE,
    atr_length: CK_ULONG,
    max_input_length: CK_ULONG,
    max_output_length: CK_ULONG,
    context: *mut c_void,
    transmit: Option<HostCcidTransmit>,
) -> CK_RV;

pub(crate) type HostCcidEnumerate = unsafe extern "C" fn(
    context: *mut c_void,
    sink_context: *mut c_void,
    add_reader: Option<HostCcidAddReader>,
) -> CK_RV;

#[derive(Clone, Copy)]
pub(crate) struct HostCcidProvider {
    context: usize,
    enumerate: HostCcidEnumerate,
}

impl HostCcidProvider {
    pub(crate) fn new(context: *mut c_void, enumerate: HostCcidEnumerate) -> Self {
        Self {
            context: context as usize,
            enumerate,
        }
    }

    pub(crate) fn enumerate(self) -> Result<Vec<HostCcidRegistration>, Error> {
        let _operation = crate::logging::Operation::info(tracing::info_span!(
            target: "pkcs11rs::discovery",
            "host_ccid.enumerate"
        ));
        let mut registrations = Vec::new();
        let result = unsafe {
            (self.enumerate)(
                self.context as *mut c_void,
                (&mut registrations as *mut Vec<HostCcidRegistration>).cast(),
                Some(add_host_ccid_reader),
            )
        };
        if result != CKR_OK as CK_RV {
            return Err(result.into());
        }
        Ok(registrations)
    }
}

impl std::fmt::Debug for HostCcidProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCcidProvider")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct HostCcidRegistration {
    pub(crate) reader_name: String,
    pub(crate) atr: Vec<u8>,
    pub(crate) max_input_length: usize,
    pub(crate) max_output_length: usize,
    pub(crate) context: usize,
    pub(crate) transmit: HostCcidTransmit,
}

impl std::fmt::Debug for HostCcidRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCcidRegistration")
            .field("reader_name", &self.reader_name)
            .field("atr", &self.atr)
            .field("max_input_length", &self.max_input_length)
            .field("max_output_length", &self.max_output_length)
            .finish_non_exhaustive()
    }
}

unsafe extern "C" fn add_host_ccid_reader(
    sink_context: *mut c_void,
    reader_name: *const CK_UTF8CHAR,
    reader_name_length: CK_ULONG,
    atr: *const CK_BYTE,
    atr_length: CK_ULONG,
    max_input_length: CK_ULONG,
    max_output_length: CK_ULONG,
    context: *mut c_void,
    transmit: Option<HostCcidTransmit>,
) -> CK_RV {
    catch_unwind(AssertUnwindSafe(|| {
        let result = (|| {
            let registrations = unsafe {
                sink_context
                    .cast::<Vec<HostCcidRegistration>>()
                    .as_mut()
                    .ok_or(CKR_ARGUMENTS_BAD)?
            };
            let reader_name_length = usize::try_from(reader_name_length)
                .ok()
                .filter(|length| *length > 0 && *length <= MAX_READER_NAME_LENGTH)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let atr_length = usize::try_from(atr_length)
                .ok()
                .filter(|length| *length <= MAX_ATR_LENGTH)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let max_input_length = usize::try_from(max_input_length)
                .ok()
                .filter(|length| *length > 0)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let max_output_length = usize::try_from(max_output_length)
                .ok()
                .filter(|length| *length > 0)
                .ok_or(CKR_ARGUMENTS_BAD)?;
            let transmit = transmit.ok_or(CKR_ARGUMENTS_BAD)?;
            let reader_name =
                unsafe { from_raw_parts(reader_name, reader_name_length) }.and_then(|bytes| {
                    std::str::from_utf8(bytes)
                        .map(str::to_owned)
                        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
                })?;
            let atr = if atr_length == 0 {
                Vec::new()
            } else {
                unsafe { from_raw_parts(atr, atr_length) }?.to_vec()
            };
            let registration = HostCcidRegistration {
                reader_name,
                atr,
                max_input_length,
                max_output_length,
                context: context as usize,
                transmit,
            };
            if let Some(existing) = registrations
                .iter_mut()
                .find(|existing| existing.reader_name == registration.reader_name)
            {
                *existing = registration;
            } else {
                registrations.push(registration);
            }
            Ok::<(), Error>(())
        })();
        match result {
            Ok(()) => CKR_OK as CK_RV,
            Err(error) => error.into(),
        }
    }))
    .unwrap_or(CKR_GENERAL_ERROR as CK_RV)
}

#[derive(Clone)]
pub(crate) struct HostCcidConnector {
    registration: HostCcidRegistration,
    state: Arc<PcscReaderState>,
    present: Arc<AtomicBool>,
}

impl HostCcidConnector {
    pub(crate) fn new(registration: HostCcidRegistration) -> Self {
        let device = Arc::new(DeviceContext::new(DeviceIdentity::unknown(
            "Yubico",
            registration.reader_name.clone(),
        )));
        Self {
            registration,
            state: Arc::new(PcscReaderState::new(device)),
            present: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(crate) fn reader_state(&self) -> Arc<PcscReaderState> {
        self.state.clone()
    }

    pub(crate) fn presence(&self) -> Arc<AtomicBool> {
        self.present.clone()
    }
}

impl std::fmt::Debug for HostCcidConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCcidConnector")
            .field("registration", &self.registration)
            .field("state", &self.state)
            .finish()
    }
}

impl Connector for HostCcidConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        Some(self.state.device.clone())
    }

    fn name(&self) -> String {
        self.registration.reader_name.clone()
    }

    fn manufacturer(&self) -> &str {
        "Yubico"
    }

    fn product(&self) -> &str {
        &self.registration.reader_name
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
        self.registration.max_output_length
    }

    fn apdu_capabilities(&self) -> ApduCapabilities {
        let card = crate::iso7816::atr_apdu_capabilities(&self.registration.atr)
            .unwrap_or(ApduCapabilities::SHORT_ONLY);
        ApduCapabilities {
            command_chaining: card.command_chaining,
            extended: card.extended && self.registration.max_input_length > 261,
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
            "host_ccid.transmit",
            reader = %self.registration.reader_name,
            request_bytes = send_buffer.len(),
            timeout_ms = timeout.as_millis() as u64
        ));
        let _entered = operation.enter();
        let command_length =
            CK_ULONG::try_from(send_buffer.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let mut response_length =
            CK_ULONG::try_from(receive_buffer.len()).map_err(|_| CKR_BUFFER_TOO_SMALL)?;
        let timeout_milliseconds = CK_ULONG::try_from(timeout.as_millis()).unwrap_or(CK_ULONG::MAX);
        let result = unsafe {
            (self.registration.transmit)(
                self.registration.context as *mut c_void,
                send_buffer.as_ptr(),
                command_length,
                receive_buffer.as_mut_ptr(),
                &mut response_length,
                timeout_milliseconds,
            )
        };
        if result != CKR_OK as CK_RV {
            return Err(Error::from(result));
        }
        let response_length = usize::try_from(response_length).map_err(|_| CKR_DEVICE_ERROR)?;
        if response_length > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(&receive_buffer[..response_length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn echo_status(
        _context: *mut c_void,
        _command: *const CK_BYTE,
        _command_length: CK_ULONG,
        response: *mut CK_BYTE,
        response_length: *mut CK_ULONG,
        _timeout_milliseconds: CK_ULONG,
    ) -> CK_RV {
        if response.is_null() || response_length.is_null() || unsafe { *response_length } < 2 {
            return CKR_BUFFER_TOO_SMALL as CK_RV;
        }
        unsafe {
            *response = 0x90;
            *response.add(1) = 0x00;
            *response_length = 2;
        }
        CKR_OK as CK_RV
    }

    fn connector() -> HostCcidConnector {
        HostCcidConnector::new(HostCcidRegistration {
            reader_name: String::from("Yubico YubiKey FIDO+CCID"),
            atr: vec![0x3b, 0xfd],
            max_input_length: 3062,
            max_output_length: 3062,
            context: 0,
            transmit: echo_status,
        })
    }

    #[test]
    fn delegates_raw_apdus_to_the_host_callback() {
        let connector = connector();
        let response = connector
            .send(&[0, 0xa4, 4, 0], Duration::from_secs(1))
            .unwrap();
        assert_eq!(response, [0x90, 0x00]);
        assert_eq!(connector.buffer_size(), 3062);
    }

    #[test]
    fn inventory_presence_changes_without_replacing_the_connector() {
        let connector = connector();
        let presence = connector.presence();
        assert!(connector.is_present());
        presence.store(false, Ordering::Release);
        assert!(!connector.is_present());
        presence.store(true, Ordering::Release);
        assert!(connector.is_present());
    }

    unsafe extern "C" fn enumerate_one_reader(
        _context: *mut c_void,
        sink_context: *mut c_void,
        add_reader: Option<HostCcidAddReader>,
    ) -> CK_RV {
        let Some(add_reader) = add_reader else {
            return CKR_ARGUMENTS_BAD as CK_RV;
        };
        let name = b"YubiKey over host CCID";
        let atr = [0x3b, 0xfd];
        unsafe {
            add_reader(
                sink_context,
                name.as_ptr(),
                name.len() as CK_ULONG,
                atr.as_ptr(),
                atr.len() as CK_ULONG,
                3062,
                3062,
                std::ptr::null_mut(),
                Some(echo_status),
            )
        }
    }

    #[test]
    fn provider_collects_readers_through_the_shared_sink() {
        let provider = HostCcidProvider::new(std::ptr::null_mut(), enumerate_one_reader);
        let registrations = provider.enumerate().unwrap();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].reader_name, "YubiKey over host CCID");
        assert_eq!(registrations[0].atr, [0x3b, 0xfd]);
    }
}
