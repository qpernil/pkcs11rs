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
    fn connection_epoch(&self) -> u64 {
        0
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
    fn send_short_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        crate::iso7816::transmit_short(self, command)
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

    #[allow(dead_code)]
    fn secure_channel_is_active(&self) -> bool {
        false
    }

    fn security_domain_put_scp03_key_set(
        &self,
        _new_kvn: u8,
        _replace_kvn: u8,
        _keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    fn security_domain_delete_scp03_key_set(
        &self,
        _kvn: u8,
        _delete_last: bool,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    fn security_domain_scp11_administration(
        &self,
        _operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

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
    pub(crate) validated_scp11_keys: HashMap<Scp11CertificateCacheKey, Vec<u8>>,
    pub(crate) connection_epoch: u64,
}

impl SecureChannelState {
    fn synchronize_connection(&mut self, connection_epoch: u64) {
        if self.connection_epoch != connection_epoch {
            self.session = None;
            self.application_aid.clear();
            self.validated_scp11_keys.clear();
            self.connection_epoch = connection_epoch;
        }
    }

    fn invalidate_scp11_certificates(&mut self) {
        self.validated_scp11_keys.clear();
    }
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
        let connection_epoch = self.base.connection_epoch();
        state.synchronize_connection(connection_epoch);
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
            SecureChannelProtocol::Scp03 => (|| {
                let keys = Scp03KeySet::from_environment()?;
                let security_level = configured_security_level()?;
                Scp03Session::authenticate_selected(
                    self.base.as_ref(),
                    &keys,
                    security_level,
                    &self.application_aid,
                )
            })(),
            SecureChannelProtocol::Scp11a => self.establish_scp11(&mut state, Scp11Variant::A),
            SecureChannelProtocol::Scp11b => self.establish_scp11(&mut state, Scp11Variant::B),
            SecureChannelProtocol::Scp11c => self.establish_scp11(&mut state, Scp11Variant::C),
        };
        let established = match established {
            Ok(established) => established,
            Err(error) => {
                state.session = None;
                state.application_aid.clear();
                return Err(error);
            }
        };
        state.application_aid = self.application_aid.clone();
        state.session = Some(established);
        Ok(())
    }

    fn establish_scp11(
        &self,
        state: &mut SecureChannelState,
        variant: Scp11Variant,
    ) -> Result<Scp03Session, Error> {
        let keys = Scp11KeySet::from_environment(variant)?;
        let cache_key = keys.certificate_cache_key();
        let cached = cache_key
            .as_ref()
            .and_then(|key| state.validated_scp11_keys.get(key))
            .cloned();
        let first = keys.authenticate_application(
            self.base.as_ref(),
            &self.application_aid,
            cached.as_deref(),
        );
        let (session, validated) = match first {
            Err(_) if cached.is_some() => {
                if let Some(key) = cache_key.as_ref() {
                    state.validated_scp11_keys.remove(key);
                }
                keys.authenticate_application(self.base.as_ref(), &self.application_aid, None)?
            }
            result => result?,
        };
        if let (Some(key), Some(point)) = (cache_key, validated) {
            state.validated_scp11_keys.insert(key, point);
        }
        Ok(session)
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
    fn connection_epoch(&self) -> u64 {
        self.base.connection_epoch()
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

    fn send_short_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.ensure_selected()?;
        if self.protocol.is_none() || !self.enabled.get() {
            return crate::iso7816::transmit_short(self.base.as_ref(), command);
        }
        let mut state = self.state.try_borrow_mut()?;
        let channel = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let result = channel.transmit_short(self.base.as_ref(), command);
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

    fn secure_channel_is_active(&self) -> bool {
        if self.protocol.is_none() || !self.enabled.get() {
            return false;
        }
        self.state.try_borrow().is_ok_and(|state| {
            state.application_aid == self.application_aid && state.session.is_some()
        })
    }

    fn security_domain_put_scp03_key_set(
        &self,
        new_kvn: u8,
        replace_kvn: u8,
        keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        self.ensure_selected()?;
        if !self.enabled.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let mut state = self.state.try_borrow_mut()?;
        let session = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        if session.static_dek()?.len() != 16 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        let result = SecurityDomainClient.put_scp03_key_set(
            self.base.as_ref(),
            session,
            new_kvn,
            replace_kvn,
            keys,
        );
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        result
    }

    fn security_domain_delete_scp03_key_set(
        &self,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), Error> {
        self.ensure_selected()?;
        if !self.enabled.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let mut state = self.state.try_borrow_mut()?;
        let result = SecurityDomainClient.delete_scp03_key_set(
            self.base.as_ref(),
            state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?,
            kvn,
            delete_last,
        );
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        result
    }

    fn security_domain_scp11_administration(
        &self,
        operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        self.ensure_selected()?;
        if !self.enabled.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let mut state = self.state.try_borrow_mut()?;
        let session = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let prepared = SecurityDomainClient.prepare_scp11_administration(session, operation)?;
        let result = SecurityDomainClient.execute_scp11_administration(
            self.base.as_ref(),
            session,
            prepared,
        );
        if result.is_ok() {
            state.invalidate_scp11_certificates();
        } else {
            state.session = None;
            state.application_aid.clear();
        }
        result
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
    pub(crate) connection_epoch: Cell<u64>,
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
    fn connection_epoch(&self) -> u64 {
        self.connection_epoch.get()
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
        self.connection_epoch
            .set(self.connection_epoch.get().wrapping_add(1));
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

const YUBIHSM_CONNECTOR_BUFFER_SIZE: usize = 3139;

#[derive(Debug, Eq, PartialEq)]
struct YubiHsmConnectorStatus {
    serial: String,
    version: (u8, u8, u8),
}

fn parse_yubihsm_connector_status(value: &[u8]) -> Result<YubiHsmConnectorStatus, Error> {
    let value = std::str::from_utf8(value).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut status = None;
    let mut serial = None;
    let mut version = None;
    for line in value.lines() {
        let Some((name, value)) = line.split_once('=') else {
            return Err(CKR_DEVICE_ERROR.into());
        };
        match name {
            "status" => status = Some(value),
            "serial" => serial = Some(value.to_owned()),
            "version" => {
                let components = value
                    .split('.')
                    .map(str::parse::<u8>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                let [major, minor, patch] = components.as_slice() else {
                    return Err(CKR_DEVICE_ERROR.into());
                };
                version = Some((*major, *minor, *patch));
            }
            _ => {}
        }
    }
    if status != Some("OK") {
        return Err(CKR_DEVICE_REMOVED.into());
    }
    Ok(YubiHsmConnectorStatus {
        serial: serial.ok_or(CKR_DEVICE_ERROR)?,
        version: version.ok_or(CKR_DEVICE_ERROR)?,
    })
}

#[derive(Debug)]
pub(crate) struct CurlConnector {
    serial: String,
    url: String,
    version: (u8, u8, u8),
    connected: Cell<bool>,
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
        "YubiHSM Connector"
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn major(&self) -> u8 {
        self.version.0
    }
    fn minor(&self) -> u8 {
        self.version.1
    }
    fn is_present(&self) -> bool {
        self.connected.get()
    }
    fn name(&self) -> String {
        format!("Yubico YubiHSM Connector {}", self.url)
    }
    fn buffer_size(&self) -> usize {
        YUBIHSM_CONNECTOR_BUFFER_SIZE
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let mut received = Vec::new();
        let mut curl = self.curl.try_borrow_mut()?;
        curl.url(&format!("{}/connector/api", self.url))?;
        curl.timeout(timeout)?;
        curl.fail_on_error(true)?;
        curl.post(true)?;
        curl.post_fields_copy(send_buffer)?;
        let mut headers = curl::easy::List::new();
        headers.append("Content-Type: application/octet-stream")?;
        curl.http_headers(headers)?;
        {
            let mut transfer = curl.transfer();
            transfer.write_function(|slice| {
                received.extend_from_slice(slice);
                Ok(slice.len())
            })?;
            if let Err(error) = transfer.perform() {
                self.connected.set(false);
                return Err(error.into());
            }
        }
        if received.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_MEMORY.into());
        }
        receive_buffer[..received.len()].copy_from_slice(&received);
        log!(2, "curl.post({:?}) -> {:?}", send_buffer, received);
        self.connected.set(true);
        Ok(&receive_buffer[..received.len()])
    }
    fn refresh(&self) -> Result<(), Error> {
        if !self.connected.get() {
            return Err(CKR_DEVICE_REMOVED.into());
        }
        match self.status(Duration::from_secs(5)) {
            Ok(_) => {
                self.connected.set(true);
                Ok(())
            }
            Err(error) => {
                self.connected.set(false);
                Err(error)
            }
        }
    }
}

impl CurlConnector {
    pub(crate) fn new(url: String) -> Result<Self, Error> {
        let url = url.trim_end_matches('/').to_owned();
        if url.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut curl = curl::easy::Easy::new();
        curl.useragent(concat!("pkcs11rs/", env!("CARGO_PKG_VERSION")))?;
        Ok(Self {
            serial: String::new(),
            url,
            version: (0, 0, 0),
            connected: Cell::new(false),
            curl: RefCell::new(curl),
        })
    }

    fn status(&self, timeout: Duration) -> Result<YubiHsmConnectorStatus, Error> {
        let mut received = Vec::new();
        let mut curl = self.curl.try_borrow_mut()?;
        curl.url(&format!("{}/connector/status", self.url))?;
        curl.timeout(timeout)?;
        curl.fail_on_error(true)?;
        curl.get(true)?;
        {
            let mut transfer = curl.transfer();
            transfer.write_function(|slice| {
                received.extend(slice);
                Ok(slice.len())
            })?;
            transfer.perform()?;
        }
        log!(2, "curl.get() -> {:?}", String::from_utf8_lossy(&received));
        parse_yubihsm_connector_status(&received)
    }

    pub(crate) fn connect(&mut self) -> Result<(), Error> {
        let status = self.status(Duration::from_secs(5))?;
        self.serial = status.serial;
        self.version = status.version;
        let mut curl = self.curl.try_borrow_mut()?;
        curl.url(&format!("{}/connector/api", self.url))?;
        curl.post(true)?;
        self.connected.set(true);
        Ok(())
    }

    pub(crate) fn set_unavailable(&self) {
        self.connected.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        use std::io::Read;

        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        let header_end = loop {
            let length = stream.read(&mut buffer).unwrap();
            assert_ne!(length, 0);
            request.extend_from_slice(&buffer[..length]);
            if let Some(offset) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let length = stream.read(&mut buffer).unwrap();
            assert_ne!(length, 0);
            request.extend_from_slice(&buffer[..length]);
        }
        request
    }

    fn write_http_response(stream: &mut std::net::TcpStream, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }

    #[test]
    fn parses_yubihsm_connector_status() {
        assert_eq!(
            parse_yubihsm_connector_status(b"status=OK\nserial=12345678\nversion=3.0.7\n").unwrap(),
            YubiHsmConnectorStatus {
                serial: "12345678".to_owned(),
                version: (3, 0, 7),
            }
        );
    }

    #[test]
    fn rejects_unavailable_or_malformed_yubihsm_connector_status() {
        assert!(
            parse_yubihsm_connector_status(b"status=NO_DEVICE\nserial=*\nversion=3.0.7\n").is_err()
        );
        assert!(parse_yubihsm_connector_status(b"status=OK\nserial=*\nversion=3.0\n").is_err());
        assert!(parse_yubihsm_connector_status(b"status=OK\nserial=*\n").is_err());
    }

    #[test]
    fn unconnected_curl_connector_has_a_stable_url_identity() {
        let connector = CurlConnector::new("http://127.0.0.1:12345/".to_owned()).unwrap();
        assert_eq!(
            connector.name(),
            "Yubico YubiHSM Connector http://127.0.0.1:12345"
        );
        assert!(!connector.is_present());
    }

    #[test]
    fn curl_connector_uses_status_and_binary_api_endpoints() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut status, _) = listener.accept().unwrap();
            let request = read_http_request(&mut status);
            assert!(request.starts_with(b"GET /connector/status HTTP/1.1\r\n"));
            write_http_response(&mut status, b"status=OK\nserial=12345678\nversion=3.0.7\n");

            let (mut refreshed_status, _) = listener.accept().unwrap();
            let request = read_http_request(&mut refreshed_status);
            assert!(request.starts_with(b"GET /connector/status HTTP/1.1\r\n"));
            write_http_response(
                &mut refreshed_status,
                b"status=OK\nserial=12345678\nversion=3.0.7\n",
            );

            let (mut api, _) = listener.accept().unwrap();
            let request = read_http_request(&mut api);
            assert!(request.starts_with(b"POST /connector/api HTTP/1.1\r\n"));
            let header_end = request
                .windows(4)
                .position(|value| value == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert!(std::str::from_utf8(&request[..header_end])
                .unwrap()
                .lines()
                .any(|line| line.eq_ignore_ascii_case("Content-Type: application/octet-stream")));
            assert_eq!(&request[header_end..], b"\x03\x00\x01\x42");
            write_http_response(&mut api, b"\x83\x00\x01\x42");
        });

        let mut connector = CurlConnector::new(format!("http://{address}")).unwrap();
        connector.connect().unwrap();
        assert!(connector.is_present());
        assert_eq!(connector.serial(), "12345678");
        assert_eq!((connector.major(), connector.minor()), (3, 0));
        connector.refresh().unwrap();
        let mut response = [0; 32];
        assert_eq!(
            connector
                .transmit(b"\x03\x00\x01\x42", &mut response, Duration::from_secs(1))
                .unwrap(),
            b"\x83\x00\x01\x42"
        );
        server.join().unwrap();
    }

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

    #[test]
    fn validated_scp11_keys_survive_selection_but_not_reconnect_or_sd_mutation() {
        let key = (0x13, 1, [0x55; 32]);
        let mut state = SecureChannelState {
            connection_epoch: 7,
            application_aid: vec![1, 2, 3],
            ..SecureChannelState::default()
        };
        state.validated_scp11_keys.insert(key, vec![0x04; 65]);

        state.synchronize_connection(7);
        assert!(state.validated_scp11_keys.contains_key(&key));

        state.invalidate_scp11_certificates();
        assert!(state.validated_scp11_keys.is_empty());
        state.validated_scp11_keys.insert(key, vec![0x04; 65]);

        state.synchronize_connection(8);
        assert!(state.validated_scp11_keys.is_empty());
        assert!(state.application_aid.is_empty());
        assert_eq!(state.connection_epoch, 8);
    }
}
