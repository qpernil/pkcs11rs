use crate::{CtapTransport, Error, CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED};
use std::{
    cell::RefCell,
    ffi::CString,
    fmt::Debug,
    time::{Duration, Instant},
};

pub(crate) const FIDO_USAGE_PAGE: u16 = 0xf1d0;
pub(crate) const FIDO_USAGE: u16 = 0x0001;

const HID_REPORT_SIZE: usize = 64;
const INITIAL_DATA_SIZE: usize = HID_REPORT_SIZE - 7;
const CONTINUATION_DATA_SIZE: usize = HID_REPORT_SIZE - 5;
const MAX_CONTINUATIONS: usize = 128;
const MAX_MESSAGE_SIZE: usize = INITIAL_DATA_SIZE + MAX_CONTINUATIONS * CONTINUATION_DATA_SIZE;
const BROADCAST_CHANNEL: u32 = 0xffff_ffff;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(60);

const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_CBOR: u8 = 0x10;
#[cfg(test)]
const CTAPHID_CANCEL: u8 = 0x11;
const CTAPHID_KEEPALIVE: u8 = 0x3b;
const CTAPHID_ERROR: u8 = 0x3f;

const CAPABILITY_CBOR: u8 = 0x04;
const ERR_INVALID_CHANNEL: u8 = 0x0b;
const KEEPALIVE_PROCESSING: u8 = 0x01;
const KEEPALIVE_UP_NEEDED: u8 = 0x02;

pub(crate) trait HidReportIo: Debug {
    fn write_packet(&mut self, packet: &[u8; HID_REPORT_SIZE]) -> Result<(), Error>;
    fn read_packet(
        &mut self,
        packet: &mut [u8; HID_REPORT_SIZE],
        timeout: Duration,
    ) -> Result<(), Error>;
}

#[cfg(feature = "native-hardware")]
pub(crate) struct HidApiReportIo {
    device: hidapi::HidDevice,
}

#[cfg(feature = "native-hardware")]
impl HidApiReportIo {
    pub(crate) fn new(device: hidapi::HidDevice) -> Self {
        Self { device }
    }
}

#[cfg(feature = "native-hardware")]
impl Debug for HidApiReportIo {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("HidApiReportIo").finish_non_exhaustive()
    }
}

#[cfg(feature = "native-hardware")]
impl HidReportIo for HidApiReportIo {
    fn write_packet(&mut self, packet: &[u8; HID_REPORT_SIZE]) -> Result<(), Error> {
        let mut report = [0u8; HID_REPORT_SIZE + 1];
        report[1..].copy_from_slice(packet);
        let written = self.device.write(&report)?;
        if written != report.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(())
    }

    fn read_packet(
        &mut self,
        packet: &mut [u8; HID_REPORT_SIZE],
        timeout: Duration,
    ) -> Result<(), Error> {
        let timeout_ms = timeout
            .as_millis()
            .clamp(1, i32::MAX as u128)
            .try_into()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let read = self.device.read_timeout(packet, timeout_ms)?;
        if read == 0 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        if read != HID_REPORT_SIZE {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CtapHidInit {
    pub(crate) channel: u32,
    pub(crate) protocol_version: u8,
    pub(crate) firmware_version: (u8, u8, u8),
    pub(crate) capabilities: u8,
}

impl CtapHidInit {
    pub(crate) fn supports_cbor(self) -> bool {
        self.capabilities & CAPABILITY_CBOR != 0
    }
}

#[derive(Debug)]
struct CtapHidState {
    io: Option<Box<dyn HidReportIo>>,
    init: Option<CtapHidInit>,
}

#[derive(Debug)]
pub(crate) struct CtapHidTransport {
    state: RefCell<CtapHidState>,
}

impl CtapHidTransport {
    pub(crate) fn connect(io: Box<dyn HidReportIo>) -> Result<(Self, CtapHidInit), Error> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        Self::connect_with_nonce(io, nonce)
    }

    fn connect_with_nonce(
        mut io: Box<dyn HidReportIo>,
        nonce: [u8; 8],
    ) -> Result<(Self, CtapHidInit), Error> {
        let init = initialize_channel(io.as_mut(), nonce)?;
        if !init.supports_cbor() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok((
            Self {
                state: RefCell::new(CtapHidState {
                    io: Some(io),
                    init: Some(init),
                }),
            },
            init,
        ))
    }

    pub(crate) fn reconnect(&self, io: Box<dyn HidReportIo>) -> Result<CtapHidInit, Error> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        self.reconnect_with_nonce(io, nonce)
    }

    fn reconnect_with_nonce(
        &self,
        mut io: Box<dyn HidReportIo>,
        nonce: [u8; 8],
    ) -> Result<CtapHidInit, Error> {
        let init = initialize_channel(io.as_mut(), nonce)?;
        if !init.supports_cbor() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        *self
            .state
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))? = CtapHidState {
            io: Some(io),
            init: Some(init),
        };
        Ok(init)
    }

    pub(crate) fn disconnect(&self) {
        if let Ok(mut state) = self.state.try_borrow_mut() {
            state.io = None;
            state.init = None;
        }
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.state
            .try_borrow()
            .map(|state| state.io.is_some() && state.init.is_some())
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn cancel(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let channel = state.init.ok_or(CKR_DEVICE_REMOVED)?.channel;
        let io = state.io.as_mut().ok_or(CKR_DEVICE_REMOVED)?;
        write_message(io.as_mut(), channel, CTAPHID_CANCEL, &[])
    }

    pub(crate) fn command(&self, command: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let channel = state.init.ok_or(CKR_DEVICE_REMOVED)?.channel;
        let io = state.io.as_mut().ok_or(CKR_DEVICE_REMOVED)?;
        exchange(io.as_mut(), channel, command, payload, TRANSACTION_TIMEOUT)
            .map_err(ExchangeError::into_error)
    }

    fn transact_once(state: &mut CtapHidState, request: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        let channel = state
            .init
            .ok_or_else(|| ExchangeError::Other(CKR_DEVICE_REMOVED.into()))?
            .channel;
        let io = state
            .io
            .as_mut()
            .ok_or_else(|| ExchangeError::Other(CKR_DEVICE_REMOVED.into()))?;
        exchange(
            io.as_mut(),
            channel,
            CTAPHID_CBOR,
            request,
            TRANSACTION_TIMEOUT,
        )
    }

    fn reinitialize(state: &mut CtapHidState) -> Result<(), Error> {
        let io = state.io.as_mut().ok_or(CKR_DEVICE_REMOVED)?;
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let init = initialize_channel(io.as_mut(), nonce)?;
        if !init.supports_cbor() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        state.init = Some(init);
        Ok(())
    }
}

impl CtapTransport for CtapHidTransport {
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if request.is_empty() || request.len() > MAX_MESSAGE_SIZE {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        match Self::transact_once(&mut state, request) {
            Ok(response) => Ok(response),
            Err(ExchangeError::InvalidChannel) => {
                if let Err(error) = Self::reinitialize(&mut state) {
                    state.io = None;
                    state.init = None;
                    return Err(error);
                }
                match Self::transact_once(&mut state, request) {
                    Ok(response) => Ok(response),
                    Err(error) => {
                        state.io = None;
                        state.init = None;
                        Err(error.into_error())
                    }
                }
            }
            Err(ExchangeError::Other(error)) => {
                state.io = None;
                state.init = None;
                Err(error)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "native-hardware")]
pub(crate) struct HidDeviceDescriptor {
    path: CString,
    vendor_id: u16,
    product_id: u16,
    serial: Option<String>,
    manufacturer: String,
    product: String,
    interface_number: i32,
}

#[cfg(feature = "native-hardware")]
impl HidDeviceDescriptor {
    fn from_device(device: &hidapi::DeviceInfo) -> Self {
        Self {
            path: device.path().to_owned(),
            vendor_id: device.vendor_id(),
            product_id: device.product_id(),
            serial: device
                .serial_number()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            manufacturer: device
                .manufacturer_string()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("FIDO Alliance")
                .to_owned(),
            product: device
                .product_string()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("FIDO authenticator")
                .to_owned(),
            interface_number: device.interface_number(),
        }
    }

    pub(crate) fn manufacturer(&self) -> &str {
        &self.manufacturer
    }

    pub(crate) fn is_yubico(&self) -> bool {
        self.vendor_id == 0x1050
    }

    pub(crate) fn product(&self) -> &str {
        &self.product
    }

    pub(crate) fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    pub(crate) fn name(&self) -> String {
        match self.serial() {
            Some(serial) => format!("{} {} {} HID", self.manufacturer, self.product, serial),
            None => format!(
                "{} {} {:04x}:{:04x} HID",
                self.manufacturer, self.product, self.vendor_id, self.product_id
            ),
        }
    }

    pub(crate) fn open(&self) -> Result<HidApiReportIo, Error> {
        let api = hidapi::HidApi::new()?;
        let mut compatible = api.device_list().filter(|candidate| {
            is_fido_device(candidate)
                && candidate.vendor_id() == self.vendor_id
                && candidate.product_id() == self.product_id
                && candidate.interface_number() == self.interface_number
        });
        let selected = compatible
            .find(|candidate| candidate.path() == self.path.as_c_str())
            .or_else(|| {
                let serial = self.serial.as_deref()?;
                api.device_list().find(|candidate| {
                    is_fido_device(candidate)
                        && candidate.vendor_id() == self.vendor_id
                        && candidate.product_id() == self.product_id
                        && candidate.interface_number() == self.interface_number
                        && candidate.serial_number() == Some(serial)
                })
            })
            .or_else(|| {
                let candidates = api
                    .device_list()
                    .filter(|candidate| {
                        is_fido_device(candidate)
                            && candidate.vendor_id() == self.vendor_id
                            && candidate.product_id() == self.product_id
                            && candidate.interface_number() == self.interface_number
                            && candidate.product_string() == Some(self.product.as_str())
                    })
                    .collect::<Vec<_>>();
                if candidates.len() == 1 {
                    candidates.first().copied()
                } else {
                    None
                }
            })
            .ok_or(CKR_DEVICE_REMOVED)?;
        Ok(HidApiReportIo::new(selected.open_device(&api)?))
    }
}

#[cfg(feature = "native-hardware")]
pub(crate) fn enumerate_fido_devices() -> Result<Vec<HidDeviceDescriptor>, Error> {
    let api = hidapi::HidApi::new()?;
    Ok(api
        .device_list()
        .filter(|device| is_fido_device(device))
        .map(HidDeviceDescriptor::from_device)
        .collect())
}

#[cfg(feature = "native-hardware")]
fn is_fido_device(device: &hidapi::DeviceInfo) -> bool {
    matches!(device.bus_type(), hidapi::BusType::Usb)
        && device.usage_page() == FIDO_USAGE_PAGE
        && device.usage() == FIDO_USAGE
}

#[derive(Debug)]
enum ExchangeError {
    InvalidChannel,
    Other(Error),
}

impl ExchangeError {
    fn into_error(self) -> Error {
        match self {
            Self::InvalidChannel => CKR_DEVICE_ERROR.into(),
            Self::Other(error) => error,
        }
    }
}

fn initialize_channel(io: &mut dyn HidReportIo, nonce: [u8; 8]) -> Result<CtapHidInit, Error> {
    let response = exchange(
        io,
        BROADCAST_CHANNEL,
        CTAPHID_INIT,
        &nonce,
        TRANSACTION_TIMEOUT,
    )
    .map_err(ExchangeError::into_error)?;
    if response.len() < 17 || response[..8] != nonce {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let channel = u32::from_be_bytes(
        response[8..12]
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
    );
    if channel == 0 || channel == BROADCAST_CHANNEL {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(CtapHidInit {
        channel,
        protocol_version: response[12],
        firmware_version: (response[13], response[14], response[15]),
        capabilities: response[16],
    })
}

fn exchange(
    io: &mut dyn HidReportIo,
    channel: u32,
    command: u8,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    let operation = crate::logging::Operation::trace(tracing::trace_span!(
        target: "pkcs11rs::transport",
        "ctap_hid.exchange",
        command,
        request_bytes = payload.len(),
        timeout_ms = timeout.as_millis() as u64
    ));
    let _entered = operation.enter();
    write_message(io, channel, command, payload).map_err(ExchangeError::Other)?;
    read_message(io, channel, command, timeout)
}

fn write_message(
    io: &mut dyn HidReportIo,
    channel: u32,
    command: u8,
    payload: &[u8],
) -> Result<(), Error> {
    for packet in packetize(channel, command, payload)? {
        io.write_packet(&packet)?;
    }
    Ok(())
}

fn packetize(channel: u32, command: u8, payload: &[u8]) -> Result<Vec<[u8; 64]>, Error> {
    if command & 0x80 != 0 || payload.len() > MAX_MESSAGE_SIZE {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let payload_length: u16 = payload
        .len()
        .try_into()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let mut packets = Vec::with_capacity(1 + payload.len().saturating_sub(1) / 59);
    let mut initial = [0u8; HID_REPORT_SIZE];
    initial[..4].copy_from_slice(&channel.to_be_bytes());
    initial[4] = command | 0x80;
    initial[5..7].copy_from_slice(&payload_length.to_be_bytes());
    let initial_length = payload.len().min(INITIAL_DATA_SIZE);
    initial[7..7 + initial_length].copy_from_slice(&payload[..initial_length]);
    packets.push(initial);

    for (sequence, chunk) in payload[initial_length..]
        .chunks(CONTINUATION_DATA_SIZE)
        .enumerate()
    {
        let sequence: u8 = sequence
            .try_into()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        if sequence & 0x80 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut continuation = [0u8; HID_REPORT_SIZE];
        continuation[..4].copy_from_slice(&channel.to_be_bytes());
        continuation[4] = sequence;
        continuation[5..5 + chunk.len()].copy_from_slice(chunk);
        packets.push(continuation);
    }
    Ok(packets)
}

fn read_message(
    io: &mut dyn HidReportIo,
    channel: u32,
    expected_command: u8,
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ExchangeError::Other(CKR_ARGUMENTS_BAD.into()))?;
    loop {
        let packet = read_packet_until(io, deadline).map_err(ExchangeError::Other)?;
        let packet_channel = u32::from_be_bytes(
            packet[..4]
                .try_into()
                .map_err(|_| ExchangeError::Other(CKR_DEVICE_ERROR.into()))?,
        );
        if packet_channel != channel {
            continue;
        }
        if packet[4] & 0x80 == 0 {
            return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
        }
        let command = packet[4] & 0x7f;
        let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        if length > MAX_MESSAGE_SIZE {
            return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
        }
        if command == CTAPHID_KEEPALIVE {
            if length != 1 || !matches!(packet[7], KEEPALIVE_PROCESSING | KEEPALIVE_UP_NEEDED) {
                return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
            }
            continue;
        }
        if command == CTAPHID_ERROR {
            if length == 1 && packet[7] == ERR_INVALID_CHANNEL {
                return Err(ExchangeError::InvalidChannel);
            }
            return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
        }
        if command != expected_command {
            return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
        }

        let mut response = Vec::with_capacity(length);
        let initial_length = length.min(INITIAL_DATA_SIZE);
        response.extend_from_slice(&packet[7..7 + initial_length]);
        let mut sequence = 0u8;
        while response.len() < length {
            let continuation = read_packet_until(io, deadline).map_err(ExchangeError::Other)?;
            let continuation_channel = u32::from_be_bytes(
                continuation[..4]
                    .try_into()
                    .map_err(|_| ExchangeError::Other(CKR_DEVICE_ERROR.into()))?,
            );
            if continuation_channel != channel {
                continue;
            }
            if continuation[4] != sequence {
                return Err(ExchangeError::Other(CKR_DEVICE_ERROR.into()));
            }
            let remaining = length - response.len();
            let chunk_length = remaining.min(CONTINUATION_DATA_SIZE);
            response.extend_from_slice(&continuation[5..5 + chunk_length]);
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| ExchangeError::Other(CKR_DEVICE_ERROR.into()))?;
        }
        return Ok(response);
    }
}

fn read_packet_until(
    io: &mut dyn HidReportIo,
    deadline: Instant,
) -> Result<[u8; HID_REPORT_SIZE], Error> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))?;
    let mut packet = [0u8; HID_REPORT_SIZE];
    io.read_packet(&mut packet, remaining)?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Default)]
    struct ScriptedHid {
        expected_writes: VecDeque<[u8; HID_REPORT_SIZE]>,
        reads: VecDeque<Result<[u8; HID_REPORT_SIZE], Error>>,
    }

    impl ScriptedHid {
        fn new(
            expected_writes: Vec<[u8; HID_REPORT_SIZE]>,
            reads: Vec<[u8; HID_REPORT_SIZE]>,
        ) -> Self {
            Self {
                expected_writes: expected_writes.into(),
                reads: reads.into_iter().map(Ok).collect(),
            }
        }
    }

    impl Drop for ScriptedHid {
        fn drop(&mut self) {
            assert!(self.expected_writes.is_empty());
            assert!(self.reads.is_empty());
        }
    }

    impl HidReportIo for ScriptedHid {
        fn write_packet(&mut self, packet: &[u8; HID_REPORT_SIZE]) -> Result<(), Error> {
            let expected = self
                .expected_writes
                .pop_front()
                .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))?;
            assert_eq!(*packet, expected);
            Ok(())
        }

        fn read_packet(
            &mut self,
            packet: &mut [u8; HID_REPORT_SIZE],
            _timeout: Duration,
        ) -> Result<(), Error> {
            let response = self
                .reads
                .pop_front()
                .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))??;
            *packet = response;
            Ok(())
        }
    }

    fn response_packet(channel: u32, command: u8, payload: &[u8]) -> [u8; 64] {
        packetize(channel, command, payload).unwrap()[0]
    }

    fn init_response(nonce: [u8; 8], channel: u32) -> [u8; 64] {
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&channel.to_be_bytes());
        payload.extend_from_slice(&[2, 5, 2, 4, CAPABILITY_CBOR]);
        response_packet(BROADCAST_CHANNEL, CTAPHID_INIT, &payload)
    }

    #[test]
    fn packetization_matches_ctaphid_initial_and_continuation_layout() {
        let payload = (0u8..100).collect::<Vec<_>>();
        let packets = packetize(0x0102_0304, CTAPHID_CBOR, &payload).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(&packets[0][..7], &[1, 2, 3, 4, 0x90, 0, 100]);
        assert_eq!(&packets[0][7..], &payload[..57]);
        assert_eq!(&packets[1][..5], &[1, 2, 3, 4, 0]);
        assert_eq!(&packets[1][5..48], &payload[57..]);
        assert!(packets[1][48..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn packetization_accepts_the_ctaphid_maximum_and_rejects_larger_messages() {
        let maximum = vec![0xa5; MAX_MESSAGE_SIZE];
        let packets = packetize(1, CTAPHID_CBOR, &maximum).unwrap();
        assert_eq!(packets.len(), 129);
        assert_eq!(packets.last().unwrap()[4], 127);
        assert!(packetize(1, CTAPHID_CBOR, &[0; MAX_MESSAGE_SIZE + 1]).is_err());
    }

    #[test]
    fn channel_initialization_validates_nonce_channel_and_cbor_capability() {
        let nonce = *b"12345678";
        let writes = packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &nonce).unwrap();
        let io = ScriptedHid::new(writes, vec![init_response(nonce, 0x0102_0304)]);
        let (transport, init) = CtapHidTransport::connect_with_nonce(Box::new(io), nonce).unwrap();
        assert_eq!(init.channel, 0x0102_0304);
        assert_eq!(init.protocol_version, 2);
        assert_eq!(init.firmware_version, (5, 2, 4));
        assert!(init.supports_cbor());
        transport.disconnect();

        for payload in [
            {
                let mut response = nonce.to_vec();
                response.extend_from_slice(&0x0102_0304u32.to_be_bytes());
                response.extend_from_slice(&[2, 5, 2, 4, 0]);
                response
            },
            {
                let mut response = b"87654321".to_vec();
                response.extend_from_slice(&0x0102_0304u32.to_be_bytes());
                response.extend_from_slice(&[2, 5, 2, 4, CAPABILITY_CBOR]);
                response
            },
        ] {
            let writes = packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &nonce).unwrap();
            let response = response_packet(BROADCAST_CHANNEL, CTAPHID_INIT, &payload);
            let io = ScriptedHid::new(writes, vec![response]);
            assert!(CtapHidTransport::connect_with_nonce(Box::new(io), nonce).is_err());
        }
    }

    #[test]
    fn cbor_transaction_consumes_keepalive_and_reassembles_continuations() {
        let nonce = *b"12345678";
        let channel = 0x0102_0304;
        let request = vec![0x04];
        let response = (0u8..100).collect::<Vec<_>>();
        let mut writes = packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &nonce).unwrap();
        writes.extend(packetize(channel, CTAPHID_CBOR, &request).unwrap());
        let mut reads = vec![
            init_response(nonce, channel),
            response_packet(channel, CTAPHID_KEEPALIVE, &[KEEPALIVE_PROCESSING]),
        ];
        reads.extend(packetize(channel, CTAPHID_CBOR, &response).unwrap());
        let io = ScriptedHid::new(writes, reads);
        let (transport, _) = CtapHidTransport::connect_with_nonce(Box::new(io), nonce).unwrap();
        assert_eq!(transport.transact(&request).unwrap(), response);
    }

    #[test]
    fn malformed_keepalive_error_and_continuation_sequence_are_rejected() {
        let channel = 0x0102_0304;
        for response in [
            response_packet(channel, CTAPHID_KEEPALIVE, &[3]),
            response_packet(channel, CTAPHID_ERROR, &[1]),
            response_packet(channel, CTAPHID_INIT, &[]),
        ] {
            let mut state = CtapHidState {
                io: Some(Box::new(ScriptedHid::new(
                    packetize(channel, CTAPHID_CBOR, &[0x04]).unwrap(),
                    vec![response],
                ))),
                init: Some(CtapHidInit {
                    channel,
                    protocol_version: 2,
                    firmware_version: (5, 2, 4),
                    capabilities: CAPABILITY_CBOR,
                }),
            };
            assert!(CtapHidTransport::transact_once(&mut state, &[0x04]).is_err());
        }

        let mut response = packetize(channel, CTAPHID_CBOR, &[0xa5; 58]).unwrap();
        response[1][4] = 1;
        let mut io = ScriptedHid::new(Vec::new(), response);
        assert!(read_message(&mut io, channel, CTAPHID_CBOR, Duration::from_secs(1)).is_err());

        let mut declared_longer_than_initial =
            response_packet(channel, CTAPHID_CBOR, &[0xa5; INITIAL_DATA_SIZE]);
        declared_longer_than_initial[5..7]
            .copy_from_slice(&((INITIAL_DATA_SIZE + 1) as u16).to_be_bytes());
        let mut io = ScriptedHid::new(Vec::new(), vec![declared_longer_than_initial]);
        assert!(read_message(&mut io, channel, CTAPHID_CBOR, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn response_reassembly_ignores_other_channels_and_classifies_invalid_channel() {
        let channel = 0x0102_0304;
        let mut io = ScriptedHid::new(
            Vec::new(),
            vec![
                response_packet(0x0506_0708, CTAPHID_CBOR, &[0xff]),
                response_packet(channel, CTAPHID_CBOR, &[0x00, 0xa1]),
            ],
        );
        assert_eq!(
            read_message(&mut io, channel, CTAPHID_CBOR, Duration::from_secs(1)).unwrap(),
            [0x00, 0xa1]
        );

        let mut io = ScriptedHid::new(
            Vec::new(),
            vec![response_packet(
                channel,
                CTAPHID_ERROR,
                &[ERR_INVALID_CHANNEL],
            )],
        );
        assert!(matches!(
            read_message(&mut io, channel, CTAPHID_CBOR, Duration::from_secs(1)),
            Err(ExchangeError::InvalidChannel)
        ));
    }

    #[test]
    fn reconnect_replaces_the_hid_handle_and_allocates_a_fresh_channel() {
        let first_nonce = *b"12345678";
        let second_nonce = *b"abcdefgh";
        let first_channel = 0x0102_0304;
        let second_channel = 0x0506_0708;
        let first = ScriptedHid::new(
            packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &first_nonce).unwrap(),
            vec![init_response(first_nonce, first_channel)],
        );
        let (transport, _) =
            CtapHidTransport::connect_with_nonce(Box::new(first), first_nonce).unwrap();
        transport.disconnect();
        assert!(!transport.is_connected());

        let second = ScriptedHid::new(
            packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &second_nonce).unwrap(),
            vec![init_response(second_nonce, second_channel)],
        );
        let init = transport
            .reconnect_with_nonce(Box::new(second), second_nonce)
            .unwrap();
        assert_eq!(init.channel, second_channel);
        assert!(transport.is_connected());
        transport.disconnect();
    }

    #[test]
    fn cancel_uses_the_allocated_channel_without_waiting_for_a_response() {
        let nonce = *b"12345678";
        let channel = 0x0102_0304;
        let mut writes = packetize(BROADCAST_CHANNEL, CTAPHID_INIT, &nonce).unwrap();
        writes.extend(packetize(channel, CTAPHID_CANCEL, &[]).unwrap());
        let io = ScriptedHid::new(writes, vec![init_response(nonce, channel)]);
        let (transport, _) = CtapHidTransport::connect_with_nonce(Box::new(io), nonce).unwrap();
        transport.cancel().unwrap();
    }
}
