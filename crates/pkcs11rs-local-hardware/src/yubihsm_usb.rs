#[cfg(feature = "blocking")]
use nusb::MaybeFuture;
use std::time::Duration;

pub type UsbDeviceId = nusb::DeviceId;

pub const YUBICO_VENDOR_ID: u16 = 0x1050;
pub const YUBIHSM_PRODUCT_ID: u16 = 0x0030;

const YUBIHSM_INTERFACE: u8 = 0;
const YUBIHSM_BULK_OUT_ENDPOINT: u8 = 0x01;
const YUBIHSM_BULK_IN_ENDPOINT: u8 = 0x81;
const YUBIHSM_MESSAGE_HEADER_SIZE: usize = 3;
const YUBIHSM_LEGACY_MAX_MESSAGE_SIZE: usize = 2048;
const YUBIHSM_MAX_MESSAGE_SIZE: usize = 3136;
const YUBIHSM_LARGE_MESSAGE_MIN_VERSION: (u8, u8) = (2, 4);
const YUBIHSM_USB_SEND_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum Error {
    Usb(nusb::Error),
    Transfer(nusb::transfer::TransferError),
    DeviceFailure,
    DeviceRemoved,
    InvalidMessageLength {
        actual: usize,
        expected: Option<usize>,
    },
    SendBufferTooLarge {
        actual: usize,
        maximum: usize,
        firmware_version: (u8, u8),
    },
    ReceiveBufferTooLarge,
    IncompleteWrite {
        actual: usize,
        expected: usize,
    },
    MissingBulkOutEndpoint,
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usb(error) => write!(fmt, "USB error: {error}"),
            Self::Transfer(error) => write!(fmt, "USB transfer error: {error}"),
            Self::DeviceFailure => write!(fmt, "USB device operation failed"),
            Self::DeviceRemoved => write!(fmt, "USB device is not connected"),
            Self::InvalidMessageLength {
                actual,
                expected: Some(expected),
            } => write!(
                fmt,
                "invalid YubiHSM message length: received {actual} bytes, expected {expected}"
            ),
            Self::InvalidMessageLength {
                actual,
                expected: None,
            } => write!(
                fmt,
                "invalid YubiHSM message length: received {actual} bytes, expected at least {YUBIHSM_MESSAGE_HEADER_SIZE}"
            ),
            Self::SendBufferTooLarge {
                actual,
                maximum,
                firmware_version: (major, minor),
            } => write!(
                fmt,
                "YubiHSM message is too large: received {actual} bytes, maximum {maximum} bytes for firmware {major}.{minor}"
            ),
            Self::ReceiveBufferTooLarge => write!(fmt, "USB receive buffer is too large"),
            Self::IncompleteWrite { actual, expected } => {
                write!(
                    fmt,
                    "incomplete USB write: sent {actual} of {expected} bytes"
                )
            }
            Self::MissingBulkOutEndpoint => write!(fmt, "YubiHSM bulk OUT endpoint is missing"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Usb(error) => Some(error),
            Self::Transfer(error) => Some(error),
            _ => None,
        }
    }
}

impl From<nusb::Error> for Error {
    fn from(error: nusb::Error) -> Self {
        Self::Usb(error)
    }
}

impl From<nusb::transfer::TransferError> for Error {
    fn from(error: nusb::transfer::TransferError) -> Self {
        Self::Transfer(error)
    }
}

#[derive(Debug)]
pub struct YubiHsmUsbCandidate {
    info: nusb::DeviceInfo,
}

impl YubiHsmUsbCandidate {
    pub fn id(&self) -> UsbDeviceId {
        self.info.id()
    }

    pub fn manufacturer(&self) -> &str {
        self.info.manufacturer_string().unwrap_or("Yubico")
    }

    pub fn product(&self) -> &str {
        self.info.product_string().unwrap_or("YubiHSM")
    }

    pub fn version(&self) -> (u8, u8) {
        usb_bcd_version(self.info.device_version())
    }

    #[cfg(feature = "async-tokio")]
    pub async fn serial(&self) -> Result<Option<String>, Error> {
        if let Some(serial) = self.info.serial_number() {
            return Ok(Some(serial.to_owned()));
        }
        let device = self.info.open().await?;
        let descriptor = device.device_descriptor();
        Ok(read_nusb_string_async(&device, descriptor.serial_number_string_index()).await)
    }

    #[cfg(feature = "blocking")]
    pub fn open_blocking(self) -> Result<YubiHsmUsbDevice, Error> {
        let device = self.info.open().wait()?;
        self.opened_device_blocking(device)
    }

    #[cfg(feature = "async-tokio")]
    pub async fn open(self) -> Result<YubiHsmUsbDevice, Error> {
        let device = self.info.open().await?;
        self.opened_device(device).await
    }

    #[cfg(feature = "blocking")]
    fn opened_device_blocking(self, device: nusb::Device) -> Result<YubiHsmUsbDevice, Error> {
        let descriptor = device.device_descriptor();
        let manufacturer = self
            .info
            .manufacturer_string()
            .map(str::to_owned)
            .or_else(|| read_nusb_string(&device, descriptor.manufacturer_string_index()));
        let product = self
            .info
            .product_string()
            .map(str::to_owned)
            .or_else(|| read_nusb_string(&device, descriptor.product_string_index()));
        let serial = self
            .info
            .serial_number()
            .map(str::to_owned)
            .or_else(|| read_nusb_string(&device, descriptor.serial_number_string_index()));

        self.opened_device_with_strings(device, manufacturer, product, serial)
    }

    #[cfg(feature = "async-tokio")]
    async fn opened_device(self, device: nusb::Device) -> Result<YubiHsmUsbDevice, Error> {
        let descriptor = device.device_descriptor();
        let manufacturer = match self.info.manufacturer_string() {
            Some(value) => Some(value.to_owned()),
            None => read_nusb_string_async(&device, descriptor.manufacturer_string_index()).await,
        };
        let product = match self.info.product_string() {
            Some(value) => Some(value.to_owned()),
            None => read_nusb_string_async(&device, descriptor.product_string_index()).await,
        };
        let serial = match self.info.serial_number() {
            Some(value) => Some(value.to_owned()),
            None => read_nusb_string_async(&device, descriptor.serial_number_string_index()).await,
        };

        self.opened_device_with_strings(device, manufacturer, product, serial)
    }

    fn opened_device_with_strings(
        self,
        device: nusb::Device,
        manufacturer: Option<String>,
        product: Option<String>,
        serial: Option<String>,
    ) -> Result<YubiHsmUsbDevice, Error> {
        Ok(YubiHsmUsbDevice {
            id: self.info.id(),
            packet_size: bulk_out_packet_size(&device)?,
            device,
            interface: None,
            version: usb_bcd_version(self.info.device_version()),
            manufacturer: manufacturer.unwrap_or_else(|| String::from("Yubico")),
            product: product.unwrap_or_else(|| String::from("YubiHSM")),
            serial: serial.unwrap_or_default(),
            connection_epoch: 0,
            connected_once: false,
        })
    }
}

#[cfg(feature = "blocking")]
pub fn yubihsm_candidates_blocking() -> Result<Vec<YubiHsmUsbCandidate>, Error> {
    Ok(nusb::list_devices()
        .wait()?
        .filter(|device| {
            device.vendor_id() == YUBICO_VENDOR_ID && device.product_id() == YUBIHSM_PRODUCT_ID
        })
        .map(|info| YubiHsmUsbCandidate { info })
        .collect())
}

#[cfg(feature = "async-tokio")]
pub async fn yubihsm_candidates() -> Result<Vec<YubiHsmUsbCandidate>, Error> {
    Ok(nusb::list_devices()
        .await?
        .filter(|device| {
            device.vendor_id() == YUBICO_VENDOR_ID && device.product_id() == YUBIHSM_PRODUCT_ID
        })
        .map(|info| YubiHsmUsbCandidate { info })
        .collect())
}

#[cfg(feature = "async-tokio")]
pub enum YubiHsmHotplugEvent {
    Connected(YubiHsmUsbCandidate),
    Disconnected(UsbDeviceId),
}

#[cfg(feature = "async-tokio")]
pub struct YubiHsmHotplugWatch {
    inner: nusb::hotplug::HotplugWatch,
}

#[cfg(feature = "async-tokio")]
impl YubiHsmHotplugWatch {
    pub async fn next_event(&mut self) -> Option<YubiHsmHotplugEvent> {
        use futures_util::StreamExt;

        loop {
            match self.inner.next().await? {
                nusb::hotplug::HotplugEvent::Connected(info)
                    if info.vendor_id() == YUBICO_VENDOR_ID
                        && info.product_id() == YUBIHSM_PRODUCT_ID =>
                {
                    return Some(YubiHsmHotplugEvent::Connected(YubiHsmUsbCandidate { info }));
                }
                nusb::hotplug::HotplugEvent::Connected(_) => {}
                nusb::hotplug::HotplugEvent::Disconnected(id) => {
                    return Some(YubiHsmHotplugEvent::Disconnected(id));
                }
            }
        }
    }
}

#[cfg(feature = "async-tokio")]
pub fn watch_yubihsms() -> Result<YubiHsmHotplugWatch, Error> {
    Ok(YubiHsmHotplugWatch {
        inner: nusb::watch_devices()?,
    })
}

#[derive(Debug)]
pub struct YubiHsmUsbDevice {
    id: UsbDeviceId,
    device: nusb::Device,
    interface: Option<nusb::Interface>,
    version: (u8, u8),
    manufacturer: String,
    product: String,
    serial: String,
    packet_size: usize,
    connection_epoch: u64,
    connected_once: bool,
}

impl YubiHsmUsbDevice {
    pub fn id(&self) -> UsbDeviceId {
        self.id
    }

    pub fn manufacturer(&self) -> &str {
        &self.manufacturer
    }

    pub fn product(&self) -> &str {
        &self.product
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn version(&self) -> (u8, u8) {
        self.version
    }

    pub fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }

    pub fn is_present(&self) -> bool {
        self.interface.is_some()
    }

    pub fn buffer_size(&self) -> usize {
        YUBIHSM_MAX_MESSAGE_SIZE + self.packet_size
    }

    #[cfg(feature = "blocking")]
    pub fn connect_blocking(&mut self) -> Result<(), Error> {
        let interface = self.device.claim_interface(YUBIHSM_INTERFACE).wait()?;
        if let Ok(mut bulk_in) =
            interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(YUBIHSM_BULK_IN_ENDPOINT)
        {
            let _ = bulk_in.transfer_blocking(
                nusb::transfer::Buffer::new(self.buffer_size()),
                Duration::from_millis(1),
            );
        }
        self.install_interface(interface);
        Ok(())
    }

    #[cfg(feature = "async-tokio")]
    pub async fn connect(&mut self) -> Result<(), Error> {
        let interface = self.device.claim_interface(YUBIHSM_INTERFACE).await?;
        if let Ok(mut bulk_in) =
            interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(YUBIHSM_BULK_IN_ENDPOINT)
        {
            let _ = nusb_transfer(
                &mut bulk_in,
                nusb::transfer::Buffer::new(self.buffer_size()),
                Duration::from_millis(1),
            )
            .await;
        }
        self.install_interface(interface);
        Ok(())
    }

    fn install_interface(&mut self, interface: nusb::Interface) {
        if self.connected_once {
            self.connection_epoch = self.connection_epoch.wrapping_add(1);
        }
        self.connected_once = true;
        self.interface = Some(interface);
    }

    pub fn disconnect(&mut self) {
        self.interface = None;
    }

    #[cfg(feature = "blocking")]
    pub fn transmit_blocking<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        response_timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let (mut bulk_out, mut bulk_in) =
            self.transfer_endpoints(send_buffer, receive_buffer.len())?;
        let completion = nusb_transfer_blocking(
            &mut bulk_out,
            nusb::transfer::Buffer::from(send_buffer),
            YUBIHSM_USB_SEND_TIMEOUT,
        );
        if self.write_needs_zero_length_packet(completion, send_buffer.len())? {
            let completion = nusb_transfer_blocking(
                &mut bulk_out,
                nusb::transfer::Buffer::new(0),
                YUBIHSM_USB_SEND_TIMEOUT,
            );
            completion.status?;
        }

        let completion = nusb_transfer_blocking(
            &mut bulk_in,
            nusb::transfer::Buffer::new(receive_buffer.len()),
            response_timeout,
        );
        copy_received(completion, receive_buffer)
    }

    #[cfg(feature = "async-tokio")]
    pub async fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        response_timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let (mut bulk_out, mut bulk_in) =
            self.transfer_endpoints(send_buffer, receive_buffer.len())?;
        let completion = nusb_transfer(
            &mut bulk_out,
            nusb::transfer::Buffer::from(send_buffer),
            YUBIHSM_USB_SEND_TIMEOUT,
        )
        .await;
        if self.write_needs_zero_length_packet(completion, send_buffer.len())? {
            let completion = nusb_transfer(
                &mut bulk_out,
                nusb::transfer::Buffer::new(0),
                YUBIHSM_USB_SEND_TIMEOUT,
            )
            .await;
            completion.status?;
        }

        let completion = nusb_transfer(
            &mut bulk_in,
            nusb::transfer::Buffer::new(receive_buffer.len()),
            response_timeout,
        )
        .await;
        copy_received(completion, receive_buffer)
    }

    fn transfer_endpoints(
        &self,
        send_buffer: &[u8],
        receive_len: usize,
    ) -> Result<(BulkOutEndpoint, BulkInEndpoint), Error> {
        ensure_yubihsm_message(self.version, send_buffer)?;
        u32::try_from(receive_len).map_err(|_| Error::ReceiveBufferTooLarge)?;
        let interface = self.interface.as_ref().ok_or(Error::DeviceRemoved)?;
        Ok((
            interface.endpoint(YUBIHSM_BULK_OUT_ENDPOINT)?,
            interface.endpoint(YUBIHSM_BULK_IN_ENDPOINT)?,
        ))
    }

    fn write_needs_zero_length_packet(
        &self,
        completion: nusb::transfer::Completion,
        expected: usize,
    ) -> Result<bool, Error> {
        let written = completion.actual_len;
        completion.status?;
        ensure_complete_write(written, expected)?;
        Ok(needs_zero_length_packet(written, self.packet_size))
    }
}

fn yubihsm_max_message_size(version: (u8, u8)) -> usize {
    if version < YUBIHSM_LARGE_MESSAGE_MIN_VERSION {
        YUBIHSM_LEGACY_MAX_MESSAGE_SIZE
    } else {
        YUBIHSM_MAX_MESSAGE_SIZE
    }
}

fn ensure_yubihsm_message(version: (u8, u8), message: &[u8]) -> Result<(), Error> {
    if message.len() < YUBIHSM_MESSAGE_HEADER_SIZE {
        return Err(Error::InvalidMessageLength {
            actual: message.len(),
            expected: None,
        });
    }

    let payload_len = usize::from(u16::from_be_bytes([message[1], message[2]]));
    let expected = YUBIHSM_MESSAGE_HEADER_SIZE + payload_len;
    if message.len() != expected {
        return Err(Error::InvalidMessageLength {
            actual: message.len(),
            expected: Some(expected),
        });
    }

    ensure_yubihsm_message_size(version, message.len())
}

fn ensure_yubihsm_message_size(version: (u8, u8), actual: usize) -> Result<(), Error> {
    let maximum = yubihsm_max_message_size(version);
    if actual <= maximum {
        Ok(())
    } else {
        Err(Error::SendBufferTooLarge {
            actual,
            maximum,
            firmware_version: version,
        })
    }
}

type BulkOutEndpoint = nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>;
type BulkInEndpoint = nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>;

fn copy_received(
    completion: nusb::transfer::Completion,
    receive_buffer: &mut [u8],
) -> Result<&[u8], Error> {
    let received = completion.actual_len;
    completion.status?;
    receive_buffer[..received].copy_from_slice(&completion.buffer[..received]);
    Ok(&receive_buffer[..received])
}

#[cfg(feature = "async-tokio")]
async fn nusb_transfer<EpType, Direction>(
    endpoint: &mut nusb::Endpoint<EpType, Direction>,
    buffer: nusb::transfer::Buffer,
    timeout: Duration,
) -> nusb::transfer::Completion
where
    EpType: nusb::transfer::BulkOrInterrupt,
    Direction: nusb::transfer::EndpointDirection,
{
    endpoint.submit(buffer);
    if timeout.is_zero() {
        return endpoint.next_complete().await;
    }
    match tokio::time::timeout(timeout, endpoint.next_complete()).await {
        Ok(completion) => completion,
        Err(_) => {
            endpoint.cancel_all();
            endpoint.next_complete().await
        }
    }
}

#[cfg(feature = "blocking")]
fn nusb_transfer_blocking<EpType, Direction>(
    endpoint: &mut nusb::Endpoint<EpType, Direction>,
    buffer: nusb::transfer::Buffer,
    timeout: Duration,
) -> nusb::transfer::Completion
where
    EpType: nusb::transfer::BulkOrInterrupt,
    Direction: nusb::transfer::EndpointDirection,
{
    if !timeout.is_zero() {
        return endpoint.transfer_blocking(buffer, timeout);
    }

    // The YubiHSM Connector convention is that a zero duration means no
    // timeout. nusb treats zero as an immediate timeout, so retain the pending
    // transfer and poll it in bounded intervals.
    endpoint.submit(buffer);
    loop {
        if let Some(completion) = endpoint.wait_next_complete(Duration::from_secs(60)) {
            return completion;
        }
    }
}

pub fn ensure_complete_write(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::IncompleteWrite { actual, expected })
    }
}

pub fn needs_zero_length_packet(length: usize, packet_size: usize) -> bool {
    packet_size != 0 && length % packet_size == 0
}

pub fn usb_bcd_version(raw: u16) -> (u8, u8) {
    let major = (((raw >> 12) & 0x0f) * 10 + ((raw >> 8) & 0x0f)) as u8;
    let minor = ((raw >> 4) & 0x0f) as u8;
    (major, minor)
}

fn bulk_out_packet_size(device: &nusb::Device) -> Result<usize, Error> {
    let config = device.active_configuration().map_err(nusb::Error::from)?;
    for interface in config.interfaces() {
        for descriptor in interface.alt_settings() {
            for endpoint in descriptor.endpoints() {
                if endpoint.address() == YUBIHSM_BULK_OUT_ENDPOINT
                    && endpoint.transfer_type() == nusb::descriptors::TransferType::Bulk
                {
                    return Ok(endpoint.max_packet_size());
                }
            }
        }
    }
    Err(Error::MissingBulkOutEndpoint)
}

#[cfg(feature = "blocking")]
fn read_nusb_string(device: &nusb::Device, index: Option<std::num::NonZeroU8>) -> Option<String> {
    let index = index?;
    let timeout = Duration::from_millis(100);
    let mut languages = device
        .get_string_descriptor_supported_languages(timeout)
        .wait()
        .ok()?;
    let language = languages
        .next()
        .unwrap_or(nusb::descriptors::language_id::US_ENGLISH);
    device
        .get_string_descriptor(index, language, timeout)
        .wait()
        .ok()
}

#[cfg(feature = "async-tokio")]
async fn read_nusb_string_async(
    device: &nusb::Device,
    index: Option<std::num::NonZeroU8>,
) -> Option<String> {
    let index = index?;
    let timeout = Duration::from_millis(100);
    let mut languages = device
        .get_string_descriptor_supported_languages(timeout)
        .await
        .ok()?;
    let language = languages
        .next()
        .unwrap_or(nusb::descriptors::language_id::US_ENGLISH);
    device
        .get_string_descriptor(index, language, timeout)
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_write_requires_the_full_buffer() {
        assert!(ensure_complete_write(64, 64).is_ok());
        assert!(matches!(
            ensure_complete_write(63, 64),
            Err(Error::IncompleteWrite {
                actual: 63,
                expected: 64
            })
        ));
    }

    #[test]
    fn zero_length_packet_is_required_after_a_full_packet() {
        assert!(needs_zero_length_packet(64, 64));
        assert!(needs_zero_length_packet(128, 64));
        assert!(!needs_zero_length_packet(63, 64));
        assert!(!needs_zero_length_packet(0, 0));
    }

    #[test]
    fn bcd_version_extracts_major_and_minor_components() {
        assert_eq!(usb_bcd_version(0x0210), (2, 1));
        assert_eq!(usb_bcd_version(0x1234), (12, 3));
    }

    #[test]
    fn message_size_limit_tracks_yubihsm_firmware() {
        assert_eq!(yubihsm_max_message_size((1, 9)), 2048);
        assert_eq!(yubihsm_max_message_size((2, 3)), 2048);
        assert_eq!(yubihsm_max_message_size((2, 4)), 3136);
        assert_eq!(yubihsm_max_message_size((2, 9)), 3136);
        assert_eq!(yubihsm_max_message_size((0, 0)), 2048);
        assert_eq!(yubihsm_max_message_size((3, 0)), 3136);

        assert!(ensure_yubihsm_message((2, 3), &message_with_total_size(2048)).is_ok());
        assert!(matches!(
            ensure_yubihsm_message((2, 3), &message_with_total_size(2049)),
            Err(Error::SendBufferTooLarge {
                actual: 2049,
                maximum: 2048,
                firmware_version: (2, 3)
            })
        ));
        assert!(ensure_yubihsm_message((2, 4), &message_with_total_size(3136)).is_ok());
        assert!(matches!(
            ensure_yubihsm_message((2, 4), &message_with_total_size(3137)),
            Err(Error::SendBufferTooLarge {
                actual: 3137,
                maximum: 3136,
                firmware_version: (2, 4)
            })
        ));
    }

    #[test]
    fn message_framing_requires_an_exact_declared_payload_length() {
        assert!(ensure_yubihsm_message((2, 4), &[0x03, 0x00, 0x00]).is_ok());
        assert!(ensure_yubihsm_message((2, 4), &[0x03, 0x00, 0x01, 0xff]).is_ok());

        for message in [
            &[][..],
            &[0x03, 0x00][..],
            &[0x03, 0x00, 0x01][..],
            &[0x03, 0x00, 0x00, 0xff][..],
        ] {
            assert!(matches!(
                ensure_yubihsm_message((2, 4), message),
                Err(Error::InvalidMessageLength { .. })
            ));
        }
    }

    fn message_with_total_size(total: usize) -> Vec<u8> {
        let payload_len = total - YUBIHSM_MESSAGE_HEADER_SIZE;
        let payload_len = u16::try_from(payload_len).unwrap();
        let mut message = vec![0x03];
        message.extend_from_slice(&payload_len.to_be_bytes());
        message.resize(total, 0);
        message
    }
}
