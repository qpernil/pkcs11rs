use super::*;

pub(crate) trait Connector {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn hardware_version(&self) -> Option<(u8, u8)> {
        None
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn set_device_identity(&self, _firmware: Option<(u8, u8, u8)>, _serial: Option<&str>) {}
    fn is_present(&self) -> bool;
    fn buffer_size(&self) -> usize;
    fn apdu_capabilities(&self) -> ApduCapabilities {
        ApduCapabilities::EXTENDED
    }
    fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        crate::iso7816::transmit(self, command)
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error>;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }

    #[allow(dead_code)]
    fn set_applet_present(&self, _present: bool) {}
    fn set_discovery_error(&self, _error: &Error) {}
    fn clear_discovery_error(&self) {}

    fn establish_secure_channel(&self, _application_aid: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn clear_secure_channel(&self) {}

    fn name(&self) -> String {
        format!(
            "{} {} {}",
            self.manufacturer(),
            self.product(),
            self.serial()
        )
    }

    fn send(&self, send_buffer: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let mut receive_buffer = vec![0u8; self.buffer_size()];
        let slice = self.transmit(send_buffer, &mut receive_buffer, timeout)?;
        let len = slice.len();
        receive_buffer.truncate(len);
        Ok(receive_buffer)
    }
}

#[derive(Debug, Default)]
pub(crate) struct SecureChannelState {
    pub(crate) application_aid: Vec<u8>,
    pub(crate) session: Option<Scp03Session>,
}

#[derive(Debug)]
pub(crate) struct PcscAppletConnector {
    pub(crate) base: Rc<dyn Connector>,
    pub(crate) application_aid: Vec<u8>,
    pub(crate) protocol: Option<SecureChannelProtocol>,
    pub(crate) state: Rc<RefCell<SecureChannelState>>,
    pub(crate) enabled: Cell<bool>,
    pub(crate) applet_present: Cell<bool>,
    pub(crate) discovery_error: RefCell<Option<String>>,
}

impl PcscAppletConnector {
    pub(crate) fn new(
        base: Rc<dyn Connector>,
        application_aid: &[u8],
        protocol: Option<SecureChannelProtocol>,
        state: Rc<RefCell<SecureChannelState>>,
    ) -> Self {
        let applet_present = base.is_present();
        Self {
            base,
            application_aid: application_aid.to_vec(),
            protocol,
            state,
            enabled: Cell::new(false),
            applet_present: Cell::new(applet_present),
            discovery_error: RefCell::new(None),
        }
    }

    fn ensure_selected(&self) -> Result<(), Error> {
        let mut state = self.state.try_borrow_mut()?;
        if state.application_aid != self.application_aid {
            state.session = None;
            state.application_aid.clear();
            select_application(self.base.as_ref(), &self.application_aid)?;
            state.application_aid = self.application_aid.clone();
        }

        if self.protocol.is_none() || !self.enabled.get() || state.session.is_some() {
            return Ok(());
        }

        let established = match self.protocol.ok_or(CKR_ARGUMENTS_BAD)? {
            SecureChannelProtocol::Scp03 => {
                let keys = Scp03KeySet::from_environment()?;
                let security_level = configured_security_level()?;
                Scp03Session::authenticate_selected(
                    self.base.as_ref(),
                    &keys,
                    security_level,
                    &self.application_aid,
                )?
            }
            SecureChannelProtocol::Scp11a => Scp11KeySet::from_environment(Scp11Variant::A)?
                .authenticate_selected(self.base.as_ref())?,
            SecureChannelProtocol::Scp11b => Scp11KeySet::from_environment(Scp11Variant::B)?
                .authenticate_selected(self.base.as_ref())?,
        };
        state.application_aid = self.application_aid.clone();
        state.session = Some(established);
        Ok(())
    }

    fn record_discovery_error(&self, error: &Error) {
        *self.discovery_error.borrow_mut() = Some(format!("{error:?}"));
    }

    fn forget_discovery_error(&self) {
        *self.discovery_error.borrow_mut() = None;
    }
}

impl Connector for PcscAppletConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        self.base.name()
    }

    fn manufacturer(&self) -> &str {
        self.base.manufacturer()
    }

    fn product(&self) -> &str {
        self.base.product()
    }

    fn serial(&self) -> &str {
        self.base.serial()
    }

    fn major(&self) -> u8 {
        self.base.major()
    }

    fn minor(&self) -> u8 {
        self.base.minor()
    }
    fn hardware_version(&self) -> Option<(u8, u8)> {
        self.base.hardware_version()
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.base.firmware_version()
    }
    fn set_device_identity(&self, firmware: Option<(u8, u8, u8)>, serial: Option<&str>) {
        self.base.set_device_identity(firmware, serial);
    }

    fn is_present(&self) -> bool {
        self.base.is_present() && self.applet_present.get()
    }

    fn buffer_size(&self) -> usize {
        self.base.buffer_size()
    }

    fn apdu_capabilities(&self) -> ApduCapabilities {
        self.base.apdu_capabilities()
    }

    fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.ensure_selected()?;
        if self.protocol.is_none() || !self.enabled.get() {
            return self.base.send_apdu(command);
        }
        let mut state = self.state.try_borrow_mut()?;
        let channel = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let result = channel.transmit(self.base.as_ref(), command);
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        result
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.ensure_selected()?;
        if self.protocol.is_none() || !self.enabled.get() {
            return self.base.transmit(send_buffer, receive_buffer, timeout);
        }
        let command = CommandApdu::decode(send_buffer)?;
        let encoded = self.send_apdu(&command)?.encode();
        if encoded.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..encoded.len()].copy_from_slice(&encoded);
        Ok(&receive_buffer[..encoded.len()])
    }

    fn refresh(&self) -> Result<(), Error> {
        let result = self.base.refresh();
        if result.is_err() || !self.base.is_present() {
            self.applet_present.set(false);
            if let Err(error) = &result {
                self.record_discovery_error(error);
            } else {
                self.record_discovery_error(&Error::from(CKR_DEVICE_REMOVED));
            }
            self.clear_secure_channel();
            return result;
        }

        self.clear_secure_channel();
        match select_application(self.base.as_ref(), &self.application_aid) {
            Ok(()) => {
                if let Ok(mut state) = self.state.try_borrow_mut() {
                    state.session = None;
                    state.application_aid = self.application_aid.clone();
                }
                self.applet_present.set(true);
                self.forget_discovery_error();
                Ok(())
            }
            Err(error) => {
                self.applet_present.set(false);
                self.record_discovery_error(&error);
                Err(error)
            }
        }
    }

    fn set_applet_present(&self, present: bool) {
        self.applet_present.set(present);
        if !present {
            self.clear_secure_channel();
        }
    }

    fn set_discovery_error(&self, error: &Error) {
        self.record_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.forget_discovery_error();
    }

    fn establish_secure_channel(&self, application_aid: &[u8]) -> Result<(), Error> {
        if application_aid != self.application_aid {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        self.enabled.set(true);
        if let Err(error) = self.ensure_selected() {
            self.enabled.set(false);
            return Err(error);
        }
        Ok(())
    }

    fn clear_secure_channel(&self) {
        self.enabled.set(false);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            if state.application_aid == self.application_aid {
                state.session = None;
                state.application_aid.clear();
            }
        }
    }
}

impl std::fmt::Debug for dyn Connector + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[derive(Debug)]
pub(crate) struct UsbConnector {
    pub(crate) handle: rusb::DeviceHandle<rusb::Context>,
    pub(crate) version: rusb::Version,
    pub(crate) manufacturer: String,
    pub(crate) product: String,
    pub(crate) serial: String,
    pub(crate) packet_size: usize,
    pub(crate) claimed: bool,
}

impl Connector for UsbConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        &self.manufacturer
    }
    fn product(&self) -> &str {
        &self.product
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn major(&self) -> u8 {
        self.version.major()
    }
    fn minor(&self) -> u8 {
        self.version.minor()
    }
    fn hardware_version(&self) -> Option<(u8, u8)> {
        Some((self.version.major(), self.version.minor()))
    }
    fn is_present(&self) -> bool {
        self.claimed
    }
    fn buffer_size(&self) -> usize {
        3136 + self.packet_size
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let len = self.handle.write_bulk(0x01, send_buffer, timeout)?;
        log!(2, "libusb.write_bulk({:?}) -> {}", send_buffer, len);
        ensure_complete_write(len, send_buffer.len())?;
        if needs_zero_length_packet(len, self.packet_size) {
            // Write a ZLP if last packet is full
            let zlp = self.handle.write_bulk(0x01, &[], timeout)?;
            log!(2, "libusb.write_bulk'zlp() -> {}", zlp);
        }
        let len = self.handle.read_bulk(0x81, receive_buffer, timeout)?;
        log!(
            2,
            "libusb.read_bulk({:?}) -> {}",
            &receive_buffer[..len],
            len
        );
        Ok(&receive_buffer[..len])
    }
}

pub(crate) fn ensure_complete_write(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(CKR_DEVICE_ERROR.into())
    }
}

pub(crate) fn needs_zero_length_packet(length: usize, packet_size: usize) -> bool {
    packet_size != 0 && length.is_multiple_of(packet_size)
}

pub(crate) fn bulk_out_packet_size(device: &rusb::Device<rusb::Context>) -> Result<usize, Error> {
    let config = device.active_config_descriptor()?;
    for interface in config.interfaces() {
        for descriptor in interface.descriptors() {
            for endpoint in descriptor.endpoint_descriptors() {
                if endpoint.address() == 0x01
                    && endpoint.transfer_type() == rusb::TransferType::Bulk
                {
                    return Ok(endpoint.max_packet_size() as usize);
                }
            }
        }
    }
    Err(rusb::Error::NotFound.into())
}

impl UsbConnector {
    pub(crate) fn connect(&mut self) -> Result<(), Error> {
        self.handle.claim_interface(0)?;
        let mut stale = vec![0; self.buffer_size()];
        if let Ok(length) = self
            .handle
            .read_bulk(0x81, &mut stale, Duration::from_millis(1))
        {
            log!(2, "libusb drained {length} stale bytes");
        }
        self.claimed = true;
        Ok(())
    }
    fn _disconnect(&mut self) -> Result<(), Error> {
        self.handle.release_interface(0)?;
        self.claimed = false;
        Ok(())
    }
}

pub(crate) struct PcscConnector {
    pub(crate) reader: std::ffi::CString,
    pub(crate) context: Rc<pcsc::Context>,
    pub(crate) card: RefCell<Option<pcsc::Card>>,
    pub(crate) firmware_version: Cell<Option<(u8, u8, u8)>>,
    pub(crate) serial_number: OnceLock<String>,
    pub(crate) apdu_capabilities: Cell<ApduCapabilities>,
}

impl std::fmt::Debug for PcscConnector {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("PcscConnector")
            .field("reader", &self.reader)
            .field("card", &self.card.borrow().as_ref().map(|_| "Card"))
            .finish_non_exhaustive()
    }
}

impl Connector for PcscConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.reader.to_string_lossy().to_string()
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "YubiKey"
    }
    fn serial(&self) -> &str {
        self.serial_number.get().map(String::as_str).unwrap_or("0")
    }
    fn major(&self) -> u8 {
        0
    }
    fn minor(&self) -> u8 {
        0
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.firmware_version.get()
    }
    fn set_device_identity(&self, firmware: Option<(u8, u8, u8)>, serial: Option<&str>) {
        if let Some(firmware) = firmware {
            self.firmware_version.set(Some(firmware));
        }
        if let Some(serial) = serial {
            let _ = self.serial_number.set(serial.to_string());
        }
    }
    fn is_present(&self) -> bool {
        self.card.borrow().is_some()
    }
    fn buffer_size(&self) -> usize {
        pcsc::MAX_BUFFER_SIZE_EXTENDED
    }
    fn apdu_capabilities(&self) -> ApduCapabilities {
        self.apdu_capabilities.get()
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let card = self.card.borrow();
        match card.as_ref() {
            Some(card) => {
                let received = card.transmit(send_buffer, receive_buffer)?;
                log!(
                    2,
                    "pcsc.transmit({} bytes) -> {} bytes",
                    send_buffer.len(),
                    received.len()
                );
                Ok(received)
            }
            None => Err(Error::from(pcsc::Error::NoSmartcard)),
        }
    }
    fn refresh(&self) -> Result<(), Error> {
        if let Some(card) = self.card.borrow().as_ref() {
            if card.status2_owned().is_ok() {
                self.apdu_capabilities
                    .set(detect_pcsc_apdu_capabilities(card));
                return Ok(());
            }
        }
        *self.card.borrow_mut() = None;
        let card = self.context.connect(
            &self.reader,
            pcsc::ShareMode::Exclusive,
            pcsc::Protocols::T0 | pcsc::Protocols::T1,
        )?;
        self.apdu_capabilities
            .set(detect_pcsc_apdu_capabilities(&card));
        *self.card.borrow_mut() = Some(card);
        Ok(())
    }
}

fn detect_pcsc_apdu_capabilities(card: &pcsc::Card) -> ApduCapabilities {
    let Ok(status) = card.status2_owned() else {
        return ApduCapabilities::SHORT_ONLY;
    };
    if pcsc_transport_is_nfc(card, status.atr()) {
        log!(2, "PCSC transport detected as NFC; using short APDUs");
        return ApduCapabilities::SHORT_ONLY;
    }
    let card_capabilities = crate::iso7816::atr_apdu_capabilities(status.atr());
    let max_input = card
        .get_attribute_owned(pcsc::Attribute::Maxinput)
        .ok()
        .and_then(|encoded| pcsc_dword(&encoded))
        .map(|length| length as usize);
    let reader_supports_extended = status.protocol2() == Some(pcsc::Protocol::T1)
        && max_input.is_none_or(|length| length > 261);
    let capabilities = card_capabilities.unwrap_or(ApduCapabilities::SHORT_ONLY);
    ApduCapabilities {
        command_chaining: capabilities.command_chaining,
        extended: capabilities.extended && reader_supports_extended,
    }
}

const PCSC_CHANNEL_TYPE_NFC: u16 = 0x0100;
const PCSC_READER_CONTACTLESS: u32 = 0x0000_0008;
const PCSC_ICC_TYPE_14443_A: u8 = 5;
const PCSC_ICC_TYPE_14443_B: u8 = 6;
const PCSC_ICC_TYPE_15693: u8 = 7;

fn pcsc_transport_is_nfc(card: &pcsc::Card, atr: &[u8]) -> bool {
    let channel_is_nfc = card
        .get_attribute_owned(pcsc::Attribute::ChannelId)
        .ok()
        .is_some_and(|encoded| pcsc_channel_is_nfc(&encoded));
    let reader_is_contactless = card
        .get_attribute_owned(pcsc::Attribute::Characteristics)
        .ok()
        .is_some_and(|encoded| pcsc_reader_is_contactless(&encoded));
    let icc_is_contactless = card
        .get_attribute_owned(pcsc::Attribute::IccTypePerAtr)
        .ok()
        .is_some_and(|encoded| pcsc_icc_is_contactless(&encoded));

    channel_is_nfc || reader_is_contactless || icc_is_contactless || yubikey_atr_is_nfc(atr)
}

fn pcsc_dword(encoded: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = encoded.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

fn pcsc_channel_is_nfc(encoded: &[u8]) -> bool {
    pcsc_dword(encoded).is_some_and(|channel| (channel >> 16) as u16 == PCSC_CHANNEL_TYPE_NFC)
}

fn pcsc_reader_is_contactless(encoded: &[u8]) -> bool {
    pcsc_dword(encoded)
        .is_some_and(|characteristics| characteristics & PCSC_READER_CONTACTLESS != 0)
}

fn pcsc_icc_is_contactless(encoded: &[u8]) -> bool {
    encoded.first().is_some_and(|icc_type| {
        matches!(
            *icc_type,
            PCSC_ICC_TYPE_14443_A | PCSC_ICC_TYPE_14443_B | PCSC_ICC_TYPE_15693
        )
    })
}

fn yubikey_atr_is_nfc(atr: &[u8]) -> bool {
    atr.get(1).is_some_and(|t0| t0 & 0xf0 != 0xf0)
}

impl PcscConnector {
    fn _reconnect(&self) -> Result<(), Error> {
        match self.card.borrow_mut().as_mut() {
            Some(card) => card
                .reconnect(
                    pcsc::ShareMode::Exclusive,
                    pcsc::Protocols::T0 | pcsc::Protocols::T1,
                    pcsc::Disposition::ResetCard,
                )
                .map_err(|e| e.into()),
            None => Err(Error::from(pcsc::Error::NoSmartcard)),
        }
    }
    fn _disconnect(&self) -> Result<(), Error> {
        *self.card.borrow_mut() = None;
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct CurlConnector {
    serial: String,
    url: String,
    connected: bool,
    curl: RefCell<curl::easy::Easy>,
}

impl Connector for CurlConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "CurlConnector"
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn major(&self) -> u8 {
        0
    }
    fn minor(&self) -> u8 {
        1
    }
    fn is_present(&self) -> bool {
        self.connected
    }
    fn buffer_size(&self) -> usize {
        2048
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let mut write_len = 0usize;
        let mut read_len = 0usize;
        let mut curl = self.curl.try_borrow_mut()?;
        curl.post_field_size(send_buffer.len() as u64)?;
        {
            let mut transfer = curl.transfer();
            transfer.read_function(|mut slice| match slice.write(&send_buffer[read_len..]) {
                Ok(read) => {
                    read_len += read;
                    Ok(read)
                }
                Err(_) => Err(curl::easy::ReadError::Abort),
            })?;
            transfer.write_function(|slice| {
                let mut rslice = &mut receive_buffer[write_len..];
                match rslice.write(slice) {
                    Ok(writ) => {
                        write_len += writ;
                        Ok(writ)
                    }
                    Err(_) => Err(curl::easy::WriteError::Pause),
                }
            })?;
            transfer.perform()?;
        }
        let received = &receive_buffer[..write_len];
        log!(2, "curl.post({:?}) -> {:?}", send_buffer, received);
        Ok(received)
    }
}

impl CurlConnector {
    #[allow(dead_code)]
    fn connect(&mut self) -> Result<(), Error> {
        let mut received = Vec::new();
        let mut curl = self.curl.try_borrow_mut()?;
        curl.url(&format!("{}/connector/status", self.url))?;
        {
            let mut transfer = curl.transfer();
            transfer.write_function(|slice| {
                received.extend(slice);
                Ok(slice.len())
            })?;
            transfer.perform()?;
        }
        log!(
            2,
            "curl.get() -> {:?}",
            String::from_utf8_lossy(&received).to_string()
        );
        curl.url(&format!("{}/connector/api", self.url))?;
        curl.post(true)?;
        self.connected = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nfc_pcsc_channel() {
        assert!(pcsc_channel_is_nfc(&0x0100_0000u32.to_ne_bytes()));
        assert!(!pcsc_channel_is_nfc(&0x0020_0000u32.to_ne_bytes()));
        assert!(!pcsc_channel_is_nfc(&[0x00, 0x01]));
    }

    #[test]
    fn detects_contactless_pcsc_characteristic() {
        assert!(pcsc_reader_is_contactless(
            &PCSC_READER_CONTACTLESS.to_ne_bytes()
        ));
        assert!(!pcsc_reader_is_contactless(&0u32.to_ne_bytes()));
    }

    #[test]
    fn detects_contactless_icc_types() {
        for icc_type in [
            PCSC_ICC_TYPE_14443_A,
            PCSC_ICC_TYPE_14443_B,
            PCSC_ICC_TYPE_15693,
        ] {
            assert!(pcsc_icc_is_contactless(&[icc_type]));
        }
        assert!(!pcsc_icc_is_contactless(&[0]));
        assert!(!pcsc_icc_is_contactless(&[]));
    }

    #[test]
    fn detects_yubico_nfc_atr_convention() {
        assert!(yubikey_atr_is_nfc(&[0x3b, 0x8d]));
        assert!(!yubikey_atr_is_nfc(&[0x3b, 0xfd]));
        assert!(!yubikey_atr_is_nfc(&[]));
    }
}
