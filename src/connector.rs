use super::*;
use crate::device::{DeviceContext, DeviceIdentity};

pub(crate) type SharedConnector = Arc<dyn Connector + Send + Sync>;

pub(crate) trait Connector {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        None
    }
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
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
        format!("{} {}", self.manufacturer(), self.product())
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

#[cfg(feature = "native-hardware")]
struct PcscTransportState {
    card: Option<pcsc::Card>,
    apdu_capabilities: ApduCapabilities,
    connection_epoch: u64,
}

#[cfg(feature = "native-hardware")]
impl std::fmt::Debug for PcscTransportState {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("PcscTransportState")
            .field("card", &self.card.as_ref().map(|_| "Card"))
            .field("apdu_capabilities", &self.apdu_capabilities)
            .field("connection_epoch", &self.connection_epoch)
            .finish()
    }
}

#[cfg(feature = "native-hardware")]
impl Default for PcscTransportState {
    fn default() -> Self {
        Self {
            card: None,
            apdu_capabilities: ApduCapabilities::SHORT_ONLY,
            connection_epoch: 0,
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "native-hardware")]
pub(crate) struct PcscReaderState {
    // This is the physical-reader gate. PKCS slot state is protected separately
    // by the applet's SlotContext.
    operation: Mutex<()>,
    transport: Mutex<PcscTransportState>,
    secure_channel: Mutex<SecureChannelState>,
    pub(crate) device: Arc<DeviceContext>,
}

#[cfg(feature = "native-hardware")]
impl Default for PcscReaderState {
    fn default() -> Self {
        Self {
            operation: Mutex::new(()),
            transport: Mutex::new(PcscTransportState::default()),
            secure_channel: Mutex::new(SecureChannelState::default()),
            device: Arc::new(DeviceContext::new(DeviceIdentity::unknown(
                "Yubico", "YubiKey",
            ))),
        }
    }
}

#[cfg(feature = "native-hardware")]
impl PcscReaderState {
    fn with_operation<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let _guard = self.operation.lock().map_err(|_| CKR_MUTEX_BAD)?;
        operation()
    }

    fn secure_channel(&self) -> Result<MutexGuard<'_, SecureChannelState>, Error> {
        self.secure_channel.lock().map_err(|_| CKR_MUTEX_BAD.into())
    }

    pub(crate) fn set_selected_application(&self, application_aid: &[u8]) -> Result<(), Error> {
        self.with_operation(|| {
            let mut state = self.secure_channel()?;
            state.session = None;
            state.application_aid = application_aid.to_vec();
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn with_secure_channel(application_aid: Vec<u8>, session: Scp03Session) -> Self {
        Self {
            operation: Mutex::new(()),
            transport: Mutex::new(PcscTransportState::default()),
            secure_channel: Mutex::new(SecureChannelState {
                application_aid,
                session: Some(session),
                ..SecureChannelState::default()
            }),
            device: Arc::new(DeviceContext::new(DeviceIdentity::unknown(
                "Yubico", "YubiKey",
            ))),
        }
    }
}

#[derive(Debug, Default)]
#[cfg(feature = "native-hardware")]
pub(crate) struct PcscAppletState {
    pub(crate) enabled: std::sync::atomic::AtomicBool,
    pub(crate) applet_present: std::sync::atomic::AtomicBool,
    pub(crate) discovery_error: Mutex<Option<String>>,
}

#[derive(Clone)]
#[cfg(feature = "native-hardware")]
pub(crate) struct PcscAppletConnector {
    pub(crate) base: SharedConnector,
    pub(crate) application_aid: Vec<u8>,
    pub(crate) protocol: Option<SecureChannelProtocol>,
    pub(crate) state: Arc<PcscReaderState>,
    pub(crate) applet: Arc<PcscAppletState>,
    pub(crate) secure_channels: Arc<SecureChannelConfiguration>,
    pub(crate) pinentry: Arc<pinentry::Pinentry>,
}

#[cfg(feature = "native-hardware")]
impl std::fmt::Debug for PcscAppletConnector {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("PcscAppletConnector")
            .field("base", self.base.as_ref().as_debug())
            .field("application_aid", &self.application_aid)
            .field("protocol", &self.protocol)
            .field("state", &self.state)
            .field("applet", &self.applet)
            .finish()
    }
}

#[cfg(feature = "native-hardware")]
impl PcscAppletConnector {
    #[cfg(test)]
    pub(crate) fn discovery_error(&self) -> Option<String> {
        self.applet
            .discovery_error
            .lock()
            .ok()
            .and_then(|error| error.clone())
    }

    fn enabled(&self) -> bool {
        self.applet
            .enabled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.applet
            .enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    fn applet_present(&self) -> bool {
        self.applet
            .applet_present
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_applet_presence(&self, present: bool) {
        self.applet
            .applet_present
            .store(present, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn new(
        base: SharedConnector,
        application_aid: &[u8],
        protocol: Option<SecureChannelProtocol>,
        state: Arc<PcscReaderState>,
    ) -> Self {
        Self::new_configured(
            base,
            application_aid,
            protocol,
            state,
            Arc::new(SecureChannelConfiguration::for_test()),
            Arc::new(pinentry::Pinentry::unconfigured()),
        )
    }

    pub(crate) fn new_configured(
        base: SharedConnector,
        application_aid: &[u8],
        protocol: Option<SecureChannelProtocol>,
        state: Arc<PcscReaderState>,
        secure_channels: Arc<SecureChannelConfiguration>,
        pinentry: Arc<pinentry::Pinentry>,
    ) -> Self {
        let applet_present = base.is_present();
        Self {
            base,
            application_aid: application_aid.to_vec(),
            protocol,
            state,
            applet: Arc::new(PcscAppletState {
                enabled: std::sync::atomic::AtomicBool::new(false),
                applet_present: std::sync::atomic::AtomicBool::new(applet_present),
                discovery_error: Mutex::new(None),
            }),
            secure_channels,
            pinentry,
        }
    }

    fn ensure_selected_locked(&self) -> Result<(), Error> {
        let mut state = self.state.secure_channel()?;
        let connection_epoch = self.base.connection_epoch();
        state.synchronize_connection(connection_epoch);
        if state.application_aid != self.application_aid {
            state.session = None;
            state.application_aid.clear();
            select_application(self.base.as_ref(), &self.application_aid)?;
            state.application_aid = self.application_aid.clone();
        }

        if self.protocol.is_none() || !self.enabled() || state.session.is_some() {
            return Ok(());
        }

        let established = match self.protocol.ok_or(CKR_ARGUMENTS_BAD)? {
            SecureChannelProtocol::Scp03 => (|| {
                let keys = Scp03KeySet::from_configuration(&self.secure_channels.scp03)?;
                Scp03Session::authenticate_selected(
                    self.base.as_ref(),
                    &keys,
                    self.secure_channels.scp03.security_level,
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
        let keys = Scp11KeySet::from_configuration(
            variant,
            &self.secure_channels.scp11,
            self.pinentry.as_ref(),
        )?;
        let cache_key = keys.certificate_cache_key();
        let cached = cache_key
            .as_ref()
            .and_then(|key| state.validated_scp11_keys.get(key))
            .cloned();
        let first = keys.authenticate_application(
            self.base.as_ref(),
            &self.application_aid,
            &self.secure_channels.scp11.issuer_sd_aid,
            cached.as_deref(),
        );
        let (session, validated) = match first {
            Err(_) if cached.is_some() => {
                if let Some(key) = cache_key.as_ref() {
                    state.validated_scp11_keys.remove(key);
                }
                keys.authenticate_application(
                    self.base.as_ref(),
                    &self.application_aid,
                    &self.secure_channels.scp11.issuer_sd_aid,
                    None,
                )?
            }
            result => result?,
        };
        if let (Some(key), Some(point)) = (cache_key, validated) {
            state.validated_scp11_keys.insert(key, point);
        }
        Ok(session)
    }

    fn send_apdu_locked(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.ensure_selected_locked()?;
        if self.protocol.is_none() || !self.enabled() {
            return self.base.send_apdu(command);
        }
        let mut state = self.state.secure_channel()?;
        let channel = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let result = channel.transmit(self.base.as_ref(), command);
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        result
    }

    fn send_short_apdu_locked(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.ensure_selected_locked()?;
        if self.protocol.is_none() || !self.enabled() {
            return crate::iso7816::transmit_short(self.base.as_ref(), command);
        }
        let mut state = self.state.secure_channel()?;
        let channel = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let result = channel.transmit_short(self.base.as_ref(), command);
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        result
    }

    fn clear_secure_channel_locked(&self) -> Result<(), Error> {
        self.set_enabled(false);
        let mut state = self.state.secure_channel()?;
        if state.application_aid == self.application_aid {
            state.session = None;
            state.application_aid.clear();
        }
        Ok(())
    }

    fn record_discovery_error(&self, error: &Error) {
        if let Ok(mut discovery_error) = self.applet.discovery_error.lock() {
            *discovery_error = Some(format!("{error:?}"));
        }
    }

    fn forget_discovery_error(&self) {
        if let Ok(mut discovery_error) = self.applet.discovery_error.lock() {
            *discovery_error = None;
        }
    }
}

#[cfg(feature = "native-hardware")]
impl Connector for PcscAppletConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        Some(self.state.device.clone())
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

    fn is_present(&self) -> bool {
        self.base.is_present() && self.applet_present()
    }

    fn buffer_size(&self) -> usize {
        self.base.buffer_size()
    }

    fn apdu_capabilities(&self) -> ApduCapabilities {
        self.base.apdu_capabilities()
    }

    fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.state.with_operation(|| self.send_apdu_locked(command))
    }

    fn send_short_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        self.state
            .with_operation(|| self.send_short_apdu_locked(command))
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.state.with_operation(|| {
            self.ensure_selected_locked()?;
            if self.protocol.is_none() || !self.enabled() {
                return self.base.transmit(send_buffer, receive_buffer, timeout);
            }
            let command = CommandApdu::decode(send_buffer)?;
            let encoded = self.send_apdu_locked(&command)?.encode();
            if encoded.len() > receive_buffer.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            receive_buffer[..encoded.len()].copy_from_slice(&encoded);
            Ok(&receive_buffer[..encoded.len()])
        })
    }

    fn refresh(&self) -> Result<(), Error> {
        self.state.with_operation(|| {
            let result = self.base.refresh();
            if result.is_err() || !self.base.is_present() {
                self.set_applet_presence(false);
                if let Err(error) = &result {
                    self.record_discovery_error(error);
                } else {
                    self.record_discovery_error(&Error::from(CKR_DEVICE_REMOVED));
                }
                self.clear_secure_channel_locked()?;
                return result;
            }

            self.clear_secure_channel_locked()?;
            match select_application(self.base.as_ref(), &self.application_aid) {
                Ok(()) => {
                    let mut state = self.state.secure_channel()?;
                    state.session = None;
                    state.application_aid = self.application_aid.clone();
                    self.set_applet_presence(true);
                    self.forget_discovery_error();
                    Ok(())
                }
                Err(error) => {
                    self.set_applet_presence(false);
                    self.record_discovery_error(&error);
                    Err(error)
                }
            }
        })
    }

    fn set_applet_present(&self, present: bool) {
        let _ = self.state.with_operation(|| {
            self.set_applet_presence(present);
            if !present {
                self.clear_secure_channel_locked()?;
            }
            Ok(())
        });
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
        self.state.with_operation(|| {
            self.set_enabled(true);
            if let Err(error) = self.ensure_selected_locked() {
                self.set_enabled(false);
                return Err(error);
            }
            Ok(())
        })
    }

    fn clear_secure_channel(&self) {
        let _ = self
            .state
            .with_operation(|| self.clear_secure_channel_locked());
    }

    fn secure_channel_is_active(&self) -> bool {
        if self.protocol.is_none() || !self.enabled() {
            return false;
        }
        self.state
            .with_operation(|| {
                let state = self.state.secure_channel()?;
                Ok(state.application_aid == self.application_aid && state.session.is_some())
            })
            .unwrap_or(false)
    }

    fn security_domain_put_scp03_key_set(
        &self,
        new_kvn: u8,
        replace_kvn: u8,
        keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        self.state.with_operation(|| {
            self.ensure_selected_locked()?;
            if !self.enabled() {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            let mut state = self.state.secure_channel()?;
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
        })
    }

    fn security_domain_delete_scp03_key_set(
        &self,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), Error> {
        self.state.with_operation(|| {
            self.ensure_selected_locked()?;
            if !self.enabled() {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            let mut state = self.state.secure_channel()?;
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
        })
    }

    fn security_domain_scp11_administration(
        &self,
        operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        self.state.with_operation(|| {
            self.ensure_selected_locked()?;
            if !self.enabled() {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            let mut state = self.state.secure_channel()?;
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
        })
    }
}

impl std::fmt::Debug for dyn Connector + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[cfg(feature = "native-hardware")]
#[derive(Clone, Debug)]
pub(crate) struct UsbConnector {
    manufacturer: String,
    product: String,
    serial: String,
    version: (u8, u8),
    state: Arc<Mutex<UsbConnectorState>>,
}

#[cfg(feature = "native-hardware")]
#[derive(Debug)]
struct UsbConnectorState {
    device: pkcs11rs_local_hardware::YubiHsmUsbDevice,
    connection_epoch: u64,
}

#[cfg(feature = "native-hardware")]
impl UsbConnector {
    pub(crate) fn open_blocking(
        candidate: pkcs11rs_local_hardware::YubiHsmUsbCandidate,
    ) -> Result<Self, Error> {
        let device = candidate.open_blocking().map_err(Error::from)?;
        Ok(Self {
            manufacturer: device.manufacturer().to_owned(),
            product: device.product().to_owned(),
            serial: device.serial().to_owned(),
            version: device.version(),
            state: Arc::new(Mutex::new(UsbConnectorState {
                device,
                connection_epoch: 0,
            })),
        })
    }

    pub(crate) fn connect_blocking(&mut self) -> Result<(), Error> {
        self.state
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .device
            .connect_blocking()
            .map_err(Error::from)
    }

    pub(crate) fn mark_discovery_absent(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.device.disconnect();
        }
    }

    pub(crate) fn apply_discovered(
        &self,
        candidate: pkcs11rs_local_hardware::YubiHsmUsbCandidate,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        if state.device.id() == candidate.id() && state.device.is_present() {
            return Ok(());
        }
        state.device.disconnect();
        let mut device = candidate.open_blocking().map_err(Error::from)?;
        device.connect_blocking().map_err(Error::from)?;
        if !self.serial.is_empty() && device.serial() != self.serial {
            return Err(CKR_DEVICE_ERROR.into());
        }
        state.device = device;
        state.connection_epoch = state.connection_epoch.wrapping_add(1);
        Ok(())
    }

    fn refresh_blocking(&self) -> Result<(), Error> {
        let candidates =
            pkcs11rs_local_hardware::yubihsm_candidates_blocking().map_err(Error::from)?;
        let state = self.state.lock().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        let current_id = state.device.id();
        let current_is_present = state.device.is_present();
        let mut exact_candidate = None;
        let mut serial_candidate = None;
        for candidate in candidates {
            if candidate.id() == current_id {
                exact_candidate = Some(candidate);
                break;
            }
            if !self.serial.is_empty()
                && candidate.serial_blocking().ok().flatten().as_deref()
                    == Some(self.serial.as_str())
            {
                serial_candidate = Some(candidate);
            }
        }
        if current_is_present && exact_candidate.is_some() {
            return Ok(());
        }
        let candidate = exact_candidate
            .or(serial_candidate)
            .ok_or(CKR_DEVICE_REMOVED)?;
        drop(state);
        self.apply_discovered(candidate)
    }
}

#[cfg(feature = "native-hardware")]
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
    fn name(&self) -> String {
        format!("{} {} {}", self.manufacturer(), self.product(), self.serial)
    }
    fn major(&self) -> u8 {
        self.version.0
    }
    fn minor(&self) -> u8 {
        self.version.1
    }
    fn hardware_version(&self) -> Option<(u8, u8)> {
        Some(self.version)
    }
    fn connection_epoch(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.connection_epoch)
            .unwrap_or_default()
    }
    fn is_present(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.device.is_present())
            .unwrap_or(false)
    }
    fn buffer_size(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.device.buffer_size())
            .unwrap_or(3136)
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let mut state = self.state.lock().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        match state
            .device
            .transmit_blocking(send_buffer, receive_buffer, timeout)
        {
            Ok(response) => Ok(response),
            Err(error) => {
                state.device.disconnect();
                Err(Error::from(error))
            }
        }
    }
    fn refresh(&self) -> Result<(), Error> {
        self.refresh_blocking()
    }
}

#[cfg(test)]
pub(crate) fn ensure_complete_write(actual: usize, expected: usize) -> Result<(), Error> {
    pkcs11rs_local_hardware::ensure_complete_write(actual, expected).map_err(Error::from)
}

#[cfg(test)]
pub(crate) fn needs_zero_length_packet(length: usize, packet_size: usize) -> bool {
    pkcs11rs_local_hardware::needs_zero_length_packet(length, packet_size)
}

#[cfg(test)]
pub(crate) fn usb_bcd_version(raw: u16) -> (u8, u8) {
    pkcs11rs_local_hardware::usb_bcd_version(raw)
}

#[cfg(feature = "native-hardware")]
pub(crate) struct PcscConnector {
    pub(crate) reader: std::ffi::CString,
    pub(crate) context: pcsc::Context,
    pub(crate) state: Arc<PcscReaderState>,
}

#[cfg(feature = "native-hardware")]
impl std::fmt::Debug for PcscConnector {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("PcscConnector")
            .field("reader", &self.reader)
            .field(
                "card",
                &self
                    .state
                    .transport
                    .lock()
                    .ok()
                    .and_then(|state| state.card.as_ref().map(|_| "Card")),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "native-hardware")]
impl Connector for PcscConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        Some(self.state.device.clone())
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
        self.state
            .device
            .identity(self.connection_epoch())
            .firmware_version
    }
    fn connection_epoch(&self) -> u64 {
        self.state
            .transport
            .lock()
            .map(|state| state.connection_epoch)
            .unwrap_or(0)
    }
    fn is_present(&self) -> bool {
        self.state
            .transport
            .lock()
            .is_ok_and(|state| state.card.is_some())
    }
    fn buffer_size(&self) -> usize {
        pcsc::MAX_BUFFER_SIZE_EXTENDED
    }
    fn apdu_capabilities(&self) -> ApduCapabilities {
        self.state
            .transport
            .lock()
            .map(|state| state.apdu_capabilities)
            .unwrap_or(ApduCapabilities::SHORT_ONLY)
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let state = self
            .state
            .transport
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        match state.card.as_ref() {
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
        let mut state = self
            .state
            .transport
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        if let Some(card) = state.card.as_ref() {
            if card.status2_owned().is_ok() {
                state.apdu_capabilities = detect_pcsc_apdu_capabilities(card);
                return Ok(());
            }
        }
        state.card = None;
        let card = self.context.connect(
            &self.reader,
            pcsc::ShareMode::Exclusive,
            pcsc::Protocols::T0 | pcsc::Protocols::T1,
        )?;
        state.apdu_capabilities = detect_pcsc_apdu_capabilities(&card);
        state.card = Some(card);
        state.connection_epoch = state.connection_epoch.wrapping_add(1);
        Ok(())
    }
}

#[cfg(feature = "native-hardware")]
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

#[cfg(feature = "native-hardware")]
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

#[cfg(feature = "native-hardware")]
impl PcscConnector {
    pub(crate) fn set_yubikey_device_info(&self, info: YubiKeyDeviceInfo) -> Result<(), Error> {
        self.state.device.replace(
            self.connection_epoch(),
            DeviceIdentity {
                manufacturer: String::from("Yubico"),
                product: info.part_number.unwrap_or_else(|| String::from("YubiKey")),
                serial: info.serial.unwrap_or_else(|| String::from("0")),
                hardware_version: None,
                firmware_version: info.version,
            },
        )
    }

    fn _reconnect(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .transport
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        match state.card.as_mut() {
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
        self.state
            .transport
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .card = None;
        Ok(())
    }
}

const YUBIHSM_CONNECTOR_BUFFER_SIZE: usize = 3139;
const YUBIHSM_CONNECTOR_DISCOVERY_LIMIT: u64 = 64 * 1024;
const YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
struct YubiHsmConnectorStatus {
    serial: String,
    version: (u8, u8, u8),
}

#[derive(Clone, Debug, serde::Deserialize)]
struct HttpConnectorDevice {
    serial: String,
    usb_version: String,
    status: String,
}

#[derive(Debug, serde::Deserialize)]
struct HttpConnectorDeviceList {
    devices: Vec<HttpConnectorDevice>,
}

impl HttpConnectorDevice {
    fn identity(&self) -> Result<YubiHsmConnectorStatus, Error> {
        if self.serial.is_empty() || self.status != "available" {
            return Err(CKR_DEVICE_REMOVED.into());
        }
        let components = self
            .usb_version
            .split('.')
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let version = match components.as_slice() {
            [major, minor] => (*major, *minor, 0),
            [major, minor, patch] => (*major, *minor, *patch),
            _ => return Err(CKR_DEVICE_ERROR.into()),
        };
        Ok(YubiHsmConnectorStatus {
            serial: self.serial.clone(),
            version,
        })
    }
}

fn encode_http_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[derive(Clone, Default)]
pub(crate) struct HttpConnectorTlsConfig {
    client_cert: Option<ureq::tls::ClientCert>,
    custom_roots: Option<ureq::tls::RootCerts>,
}

impl std::fmt::Debug for HttpConnectorTlsConfig {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("HttpConnectorTlsConfig")
            .field("client_certificate_configured", &self.client_cert.is_some())
            .field("custom_ca_bundle_configured", &self.custom_roots.is_some())
            .finish()
    }
}

impl HttpConnectorTlsConfig {
    pub(crate) fn from_client_identity(
        certificate_bundle: &[u8],
        private_key_der: &[u8],
    ) -> Result<Self, Error> {
        use der::{Decode, Encode};

        let certificates = http_certificate_bundle(certificate_bundle)?;
        let private_key = pkcs8::PrivateKeyInfoRef::from_der(private_key_der)
            .and_then(|private_key| private_key.to_der())
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        if private_key != private_key_der {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let private_key = http_pkcs8_private_key(&private_key)?;
        validate_http_client_identity(&certificates, &private_key)?;
        Ok(Self {
            client_cert: Some(ureq::tls::ClientCert::new_with_certs(
                &certificates,
                private_key,
            )),
            custom_roots: None,
        })
    }

    pub(crate) fn with_ca_bundle(mut self, certificate_bundle: &[u8]) -> Result<Self, Error> {
        let certificates = http_certificate_bundle(certificate_bundle)?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in &certificates {
            roots
                .add(rustls_pki_types::CertificateDer::from(certificate.der()))
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        }
        self.custom_roots = Some(ureq::tls::RootCerts::new_with_certs(&certificates));
        Ok(self)
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.client_cert.is_some() || self.custom_roots.is_some()
    }

    fn has_client_identity(&self) -> bool {
        self.client_cert.is_some()
    }

    fn for_url(&self, url: &str) -> Option<ureq::tls::TlsConfig> {
        let scheme = url.get(..8)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return None;
        }
        let mut builder = ureq::tls::TlsConfig::builder()
            .client_cert(self.client_cert.clone())
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));
        if let Some(custom_roots) = &self.custom_roots {
            builder = builder.root_certs(custom_roots.clone());
        }
        Some(builder.build())
    }
}

fn http_certificate_bundle(encoded: &[u8]) -> Result<Vec<ureq::tls::Certificate<'static>>, Error> {
    crate::certificate_chain::decode_bundle(encoded).map(|certificates| {
        certificates
            .iter()
            .map(|certificate| ureq::tls::Certificate::from_der(certificate).to_owned())
            .collect()
    })
}

// ureq 3.3 does not re-export the KeyKind argument required by PrivateKey::from_der.
// Keep its PEM-only adapter internal; configured and persisted keys remain PKCS#8 DER.
fn http_pkcs8_private_key(encoded: &[u8]) -> Result<ureq::tls::PrivateKey<'static>, Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let base64 = Zeroizing::new(STANDARD.encode(encoded));
    let mut armored = Zeroizing::new(b"-----BEGIN PRIVATE KEY-----\n".to_vec());
    for line in base64.as_bytes().chunks(64) {
        armored.extend_from_slice(line);
        armored.push(b'\n');
    }
    armored.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    ureq::tls::PrivateKey::from_pem(&armored).map_err(|_| CKR_ARGUMENTS_BAD.into())
}

fn validate_http_client_identity(
    certificates: &[ureq::tls::Certificate<'static>],
    private_key: &ureq::tls::PrivateKey<'static>,
) -> Result<(), Error> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let certificates = certificates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.der().to_vec()))
        .collect();
    let private_key = PrivateKeyDer::try_from(private_key.der().to_vec())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    rustls::sign::CertifiedKey::from_der(
        certificates,
        private_key,
        &rustls::crypto::ring::default_provider(),
    )
    .map(|_| ())
    .map_err(|_| CKR_ARGUMENTS_BAD.into())
}

#[derive(Debug)]
struct HttpConnectorState {
    connected: std::sync::atomic::AtomicBool,
    reconnectable: std::sync::atomic::AtomicBool,
    connection_epoch: std::sync::atomic::AtomicU64,
    status_identity: std::sync::Mutex<Option<YubiHsmConnectorStatus>>,
    agent: std::sync::RwLock<ureq::Agent>,
}

#[derive(Clone, Debug)]
pub(crate) struct HttpConnector {
    url: String,
    serial_path: String,
    state: Arc<HttpConnectorState>,
}

impl Connector for HttpConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "YubiHSM Connector"
    }
    fn major(&self) -> u8 {
        self.state
            .status_identity
            .lock()
            .ok()
            .and_then(|identity| identity.as_ref().map(|identity| identity.version.0))
            .unwrap_or(0)
    }
    fn minor(&self) -> u8 {
        self.state
            .status_identity
            .lock()
            .ok()
            .and_then(|identity| identity.as_ref().map(|identity| identity.version.1))
            .unwrap_or(0)
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.state
            .status_identity
            .lock()
            .ok()
            .and_then(|identity| identity.as_ref().map(|identity| identity.version))
    }
    fn connection_epoch(&self) -> u64 {
        self.state
            .connection_epoch
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    fn is_present(&self) -> bool {
        self.state
            .connected
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    fn name(&self) -> String {
        let serial = self
            .state
            .status_identity
            .lock()
            .ok()
            .and_then(|identity| identity.as_ref().map(|identity| identity.serial.clone()))
            .unwrap_or_else(|| self.serial_path.clone());
        format!("YubiHSM Connector {} #{serial}", self.url)
    }
    fn buffer_size(&self) -> usize {
        YUBIHSM_CONNECTOR_BUFFER_SIZE
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let agent = self.request_agent()?;
        let response = agent
            .post(format!(
                "{}/v1/devices/{}/commands",
                self.url, self.serial_path
            ))
            .content_type("application/octet-stream")
            .config()
            // Once the connector has received the command, its USB transport
            // owns the response deadline. Do not race that deadline here.
            .timeout_recv_response(None)
            .build()
            .send(send_buffer);
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                self.mark_disconnected();
                return Err(error.into());
            }
        };
        let received = response
            .body_mut()
            .with_config()
            .limit((receive_buffer.len() + 1) as u64)
            .read_to_vec();
        let received = match received {
            Ok(received) => received,
            Err(ureq::Error::BodyExceedsLimit(_)) => {
                return Err(CKR_DEVICE_MEMORY.into());
            }
            Err(error) => {
                self.mark_disconnected();
                return Err(error.into());
            }
        };
        if received.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_MEMORY.into());
        }
        receive_buffer[..received.len()].copy_from_slice(&received);
        log!(2, "http.post({:?}) -> {:?}", send_buffer, received);
        if !self
            .state
            .connected
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.state
                .connection_epoch
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(&receive_buffer[..received.len()])
    }
    fn refresh(&self) -> Result<(), Error> {
        if !self
            .state
            .connected
            .load(std::sync::atomic::Ordering::SeqCst)
            && !self
                .state
                .reconnectable
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(CKR_DEVICE_REMOVED.into());
        }
        match self.status() {
            Ok(status) => self.apply_status(status),
            Err(error) => {
                self.mark_disconnected();
                Err(error)
            }
        }
    }
}

impl HttpConnector {
    fn mark_disconnected(&self) {
        self.state
            .connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn request_agent(&self) -> Result<ureq::Agent, Error> {
        self.state
            .agent
            .read()
            .map(|agent| agent.clone())
            .map_err(|_| CKR_MUTEX_BAD.into())
    }

    pub(crate) fn endpoint_identity(&self) -> Result<(String, String), Error> {
        let serial = self
            .state
            .status_identity
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .as_ref()
            .map(|identity| identity.serial.clone())
            .ok_or(CKR_DEVICE_ERROR)?;
        Ok((self.url.clone(), serial))
    }

    pub(crate) fn accept_discovered(&self) {
        self.state
            .connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.state
            .reconnectable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn apply_discovered(&self, discovered: &Self) -> Result<(), Error> {
        let (url, serial) = self.endpoint_identity()?;
        let (discovered_url, discovered_serial) = discovered.endpoint_identity()?;
        if url != discovered_url || serial != discovered_serial {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let status = discovered
            .state
            .status_identity
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .clone()
            .ok_or(CKR_DEVICE_ERROR)?;
        let agent = discovered.request_agent()?;
        *self
            .state
            .agent
            .write()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))? = agent;
        self.apply_status(status)
    }

    fn apply_status(&self, status: YubiHsmConnectorStatus) -> Result<(), Error> {
        let mut current = self
            .state
            .status_identity
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        let identity_changed = current.as_ref() != Some(&status);
        *current = Some(status);
        drop(current);
        let was_connected = self
            .state
            .connected
            .swap(true, std::sync::atomic::Ordering::SeqCst);
        if !was_connected || identity_changed {
            self.state
                .connection_epoch
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.state
            .reconnectable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub(crate) fn mark_discovery_absent(&self) {
        self.mark_disconnected();
    }

    #[cfg(test)]
    pub(crate) fn new(url: String, serial: &str) -> Result<Self, Error> {
        Self::new_with_tls(
            url,
            YubiHsmConnectorStatus {
                serial: serial.to_owned(),
                version: (2, 5, 0),
            },
            &HttpConnectorTlsConfig::default(),
        )
    }

    fn agent(url: &str, tls: &HttpConnectorTlsConfig) -> ureq::Agent {
        let url_tls = tls.for_url(url);
        let config = ureq::Agent::config_builder()
            .user_agent(concat!("pkcs11rs/", env!("CARGO_PKG_VERSION")))
            .timeout_resolve(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .timeout_connect(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .timeout_send_request(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .timeout_send_body(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .timeout_recv_response(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .timeout_recv_body(Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT))
            .tls_config(url_tls.clone().unwrap_or_default())
            .https_only(tls.is_configured() && url_tls.is_some())
            .max_redirects(if tls.has_client_identity() { 0 } else { 10 })
            .build();
        ureq::Agent::new_with_config(config)
    }

    fn new_with_agent(
        url: String,
        identity: YubiHsmConnectorStatus,
        agent: ureq::Agent,
    ) -> Result<Self, Error> {
        let url = url.trim_end_matches('/').to_owned();
        if url.is_empty() || identity.serial.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let serial_path = encode_http_path_segment(&identity.serial);
        Ok(Self {
            url,
            serial_path,
            state: Arc::new(HttpConnectorState {
                connected: std::sync::atomic::AtomicBool::new(false),
                reconnectable: std::sync::atomic::AtomicBool::new(false),
                connection_epoch: std::sync::atomic::AtomicU64::new(0),
                status_identity: std::sync::Mutex::new(Some(identity)),
                agent: std::sync::RwLock::new(agent),
            }),
        })
    }

    #[cfg(test)]
    fn new_with_tls(
        url: String,
        identity: YubiHsmConnectorStatus,
        tls: &HttpConnectorTlsConfig,
    ) -> Result<Self, Error> {
        let normalized_url = url.trim_end_matches('/').to_owned();
        if normalized_url.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let agent = Self::agent(&normalized_url, tls);
        Self::new_with_agent(normalized_url, identity, agent)
    }

    pub(crate) fn discover_with_tls(
        url: String,
        tls: &HttpConnectorTlsConfig,
    ) -> Result<Vec<Self>, Error> {
        use std::collections::HashSet;

        let url = url.trim_end_matches('/').to_owned();
        if url.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let agent = Self::agent(&url, tls);
        let mut response = agent.get(format!("{url}/v1/devices")).call()?;
        let received = response
            .body_mut()
            .with_config()
            .limit(YUBIHSM_CONNECTOR_DISCOVERY_LIMIT)
            .read_to_vec()?;
        log!(
            2,
            "http.get({url}/v1/devices) -> {:?}",
            String::from_utf8_lossy(&received)
        );
        let mut devices: HttpConnectorDeviceList =
            serde_json::from_slice(&received).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        devices
            .devices
            .sort_by(|left, right| left.serial.cmp(&right.serial));
        let mut serials = HashSet::with_capacity(devices.devices.len());
        let mut connectors = Vec::with_capacity(devices.devices.len());
        for device in devices.devices {
            if device.status != "available" {
                continue;
            }
            let identity = device.identity()?;
            if !serials.insert(identity.serial.clone()) {
                return Err(CKR_DEVICE_ERROR.into());
            }
            connectors.push(Self::new_with_agent(url.clone(), identity, agent.clone())?);
        }
        Ok(connectors)
    }

    fn status(&self) -> Result<YubiHsmConnectorStatus, Error> {
        let agent = self.request_agent()?;
        let mut response = agent
            .get(format!("{}/v1/devices/{}", self.url, self.serial_path))
            .call()?;
        let received = response
            .body_mut()
            .with_config()
            .limit(YUBIHSM_CONNECTOR_BUFFER_SIZE as u64)
            .read_to_vec()?;
        log!(2, "http.get() -> {:?}", String::from_utf8_lossy(&received));
        let device: HttpConnectorDevice =
            serde_json::from_slice(&received).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let identity = device.identity()?;
        let expected_serial = self
            .state
            .status_identity
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .as_ref()
            .map(|identity| identity.serial.clone())
            .ok_or(CKR_DEVICE_ERROR)?;
        if identity.serial != expected_serial {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(identity)
    }

    #[cfg(test)]
    pub(crate) fn connect(&self) -> Result<(), Error> {
        let status = self.status()?;
        *self
            .state
            .status_identity
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))? = Some(status);
        self.state
            .connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.state
            .reconnectable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    fn test_http_client_identity() -> (Vec<u8>, zeroize::Zeroizing<Vec<u8>>) {
        let key = crate::certificate_builder::p256_key();
        let certificate = crate::certificate_builder::p256_certificate(
            key.verifying_key(),
            &key,
            "CN=pkcs11rs mTLS client",
            "CN=pkcs11rs mTLS client",
            1,
            false,
        );
        let certificate = crate::certificate_chain::encode_bundle(&[certificate]).unwrap();
        let private_key = key.to_pkcs8_der().unwrap();
        (
            certificate,
            zeroize::Zeroizing::new(private_key.as_bytes().to_vec()),
        )
    }

    fn test_ca_certificate_bundle() -> Vec<u8> {
        let key = crate::certificate_builder::p256_key();
        crate::certificate_chain::encode_bundle(&[crate::certificate_builder::p256_certificate(
            key.verifying_key(),
            &key,
            "CN=pkcs11rs test root",
            "CN=pkcs11rs test root",
            2,
            true,
        )])
        .unwrap()
    }

    fn test_mutual_tls(
        server_ip_address: &[u8],
        trust_server_ca: bool,
    ) -> (HttpConnectorTlsConfig, Arc<rustls::ServerConfig>) {
        let ca_key = crate::certificate_builder::p256_key();
        let ca_name = "CN=pkcs11rs test CA";
        let ca_certificate = crate::certificate_builder::p256_certificate(
            ca_key.verifying_key(),
            &ca_key,
            ca_name,
            ca_name,
            10,
            true,
        );

        let client_key = crate::certificate_builder::p256_key();
        let client_certificate = crate::certificate_builder::p256_certificate(
            client_key.verifying_key(),
            &ca_key,
            "CN=pkcs11rs test client",
            ca_name,
            11,
            false,
        );
        let client_key_der = client_key.to_pkcs8_der().unwrap();
        let client_tls = HttpConnectorTlsConfig::from_client_identity(
            &crate::certificate_chain::encode_bundle(&[client_certificate]).unwrap(),
            client_key_der.as_bytes(),
        )
        .unwrap();
        let client_tls = if trust_server_ca {
            client_tls
                .with_ca_bundle(
                    &crate::certificate_chain::encode_bundle(std::slice::from_ref(&ca_certificate))
                        .unwrap(),
                )
                .unwrap()
        } else {
            let other_ca_key = crate::certificate_builder::p256_key();
            let other_ca = crate::certificate_builder::p256_certificate(
                other_ca_key.verifying_key(),
                &other_ca_key,
                "CN=pkcs11rs other CA",
                "CN=pkcs11rs other CA",
                12,
                true,
            );
            client_tls
                .with_ca_bundle(&crate::certificate_chain::encode_bundle(&[other_ca]).unwrap())
                .unwrap()
        };

        let server_key = crate::certificate_builder::p256_key();
        let server_certificate = crate::certificate_builder::p256_tls_ip_certificate(
            server_key.verifying_key(),
            &ca_key,
            "CN=pkcs11rs test server",
            ca_name,
            13,
            server_ip_address,
        );
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(rustls_pki_types::CertificateDer::from(
                ca_certificate.clone(),
            ))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let server_key = server_key.to_pkcs8_der().unwrap();
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(server_certificate)],
                rustls_pki_types::PrivateKeyDer::try_from(server_key.as_bytes().to_vec()).unwrap(),
            )
            .unwrap();
        (client_tls, Arc::new(server_config))
    }

    fn assert_pcsc_operation_concurrency(
        first: Arc<PcscReaderState>,
        second: Arc<PcscReaderState>,
        concurrent: bool,
    ) {
        use std::sync::mpsc::{sync_channel, RecvTimeoutError};

        let (first_entered_tx, first_entered_rx) = sync_channel(0);
        let (release_first_tx, release_first_rx) = sync_channel(0);
        let first_worker = std::thread::spawn(move || {
            first
                .with_operation(|| {
                    first_entered_tx.send(()).unwrap();
                    release_first_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (second_attempted_tx, second_attempted_rx) = sync_channel(0);
        let (second_entered_tx, second_entered_rx) = sync_channel(0);
        let second_worker = std::thread::spawn(move || {
            second_attempted_tx.send(()).unwrap();
            second
                .with_operation(|| {
                    second_entered_tx.send(()).unwrap();
                    Ok(())
                })
                .unwrap();
        });
        second_attempted_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        if concurrent {
            second_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
        } else {
            assert!(matches!(
                second_entered_rx.recv_timeout(Duration::from_millis(100)),
                Err(RecvTimeoutError::Timeout)
            ));
        }

        release_first_tx.send(()).unwrap();
        if !concurrent {
            second_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
        }
        first_worker.join().unwrap();
        second_worker.join().unwrap();
    }

    #[test]
    fn pcsc_applets_on_one_reader_do_not_execute_concurrently() {
        let reader = Arc::new(PcscReaderState::default());
        assert_pcsc_operation_concurrency(reader.clone(), reader, false);
    }

    #[test]
    fn pcsc_applets_on_different_readers_execute_concurrently() {
        let first_reader = Arc::new(PcscReaderState::default());
        let second_reader = Arc::new(PcscReaderState::default());
        assert_pcsc_operation_concurrency(first_reader, second_reader, true);
    }

    fn read_http_request(stream: &mut impl std::io::Read) -> Vec<u8> {
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

    fn write_http_response(stream: &mut impl std::io::Write, body: &[u8], close: bool) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
            body.len(),
            if close { "close" } else { "keep-alive" }
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }

    fn http_identity(serial: &str, version: (u8, u8, u8)) -> YubiHsmConnectorStatus {
        YubiHsmConnectorStatus {
            serial: serial.to_owned(),
            version,
        }
    }

    #[test]
    fn parses_multi_device_connector_identity() {
        let device: HttpConnectorDevice = serde_json::from_slice(
            br#"{"serial":"12345678","usb_version":"2.5","status":"available"}"#,
        )
        .unwrap();
        assert_eq!(
            device.identity().unwrap(),
            http_identity("12345678", (2, 5, 0))
        );
    }

    #[test]
    fn rejects_unavailable_or_malformed_multi_device_identity() {
        for encoded in [
            br#"{"serial":"12345678","usb_version":"2.5","status":"busy"}"#.as_slice(),
            br#"{"serial":"","usb_version":"2.5","status":"available"}"#.as_slice(),
            br#"{"serial":"12345678","usb_version":"2","status":"available"}"#.as_slice(),
            br#"{"serial":"12345678","usb_version":"2.x","status":"available"}"#.as_slice(),
        ] {
            let device: HttpConnectorDevice = serde_json::from_slice(encoded).unwrap();
            assert!(device.identity().is_err());
        }
    }

    #[test]
    fn discovers_every_device_at_one_connector_url_in_serial_order() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"GET /v1/devices HTTP/1.1\r\n"));
            write_http_response(
                &mut connection,
                br#"{"devices":[{"serial":"87654321","usb_version":"2.5","status":"available"},{"serial":"55555555","usb_version":"2.5","status":"unclaimed"},{"serial":"12345678","usb_version":"2.4","status":"available"}]}"#,
                true,
            );
        });

        let connectors = HttpConnector::discover_with_tls(
            format!("http://{address}"),
            &HttpConnectorTlsConfig::default(),
        )
        .unwrap();
        assert_eq!(connectors.len(), 2);
        assert_eq!(connectors[0].serial_path, "12345678");
        assert_eq!((connectors[0].major(), connectors[0].minor()), (2, 4));
        assert_eq!(connectors[1].serial_path, "87654321");
        assert_eq!((connectors[1].major(), connectors[1].minor()), (2, 5));
        server.join().unwrap();
    }

    #[test]
    fn unconnected_http_connector_has_a_stable_device_identity() {
        let connector =
            HttpConnector::new("http://127.0.0.1:12345/".to_owned(), "12345678").unwrap();
        assert_eq!(
            connector.name(),
            "YubiHSM Connector http://127.0.0.1:12345 #12345678"
        );
        assert!(!connector.is_present());
        assert!(connector.refresh().is_err());
    }

    #[test]
    fn http_connector_bounds_every_http_request_stage() {
        let connector =
            HttpConnector::new("http://127.0.0.1:12345".to_owned(), "12345678").unwrap();
        let agent = connector.request_agent().unwrap();
        let timeouts = agent.config().timeouts();
        assert_eq!(timeouts.global, None);
        assert_eq!(timeouts.resolve, Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT));
        assert_eq!(timeouts.connect, Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT));
        assert_eq!(timeouts.per_call, None);
        assert_eq!(
            timeouts.send_request,
            Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT)
        );
        assert_eq!(
            timeouts.send_body,
            Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT)
        );
        assert_eq!(
            timeouts.recv_response,
            Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT)
        );
        assert_eq!(
            timeouts.recv_body,
            Some(YUBIHSM_CONNECTOR_HTTP_STAGE_TIMEOUT)
        );
    }

    #[test]
    fn rediscovery_replaces_the_shared_http_agent() {
        let url = String::from("http://127.0.0.1:12345");
        let old_agent =
            ureq::Agent::new_with_config(ureq::Agent::config_builder().max_redirects(1).build());
        let connector = HttpConnector::new_with_agent(
            url.clone(),
            http_identity("12345678", (2, 5, 0)),
            old_agent,
        )
        .unwrap();
        let slot_connector = connector.clone();
        connector.accept_discovered();

        let fresh_agent =
            ureq::Agent::new_with_config(ureq::Agent::config_builder().max_redirects(2).build());
        let discovered =
            HttpConnector::new_with_agent(url, http_identity("12345678", (2, 5, 0)), fresh_agent)
                .unwrap();
        connector.apply_discovered(&discovered).unwrap();

        assert_eq!(
            slot_connector
                .request_agent()
                .unwrap()
                .config()
                .max_redirects(),
            2
        );
    }

    #[test]
    fn http_connector_configures_client_auth_only_for_https() {
        let (certificate, private_key) = test_http_client_identity();
        let tls = HttpConnectorTlsConfig::from_client_identity(&certificate, &private_key).unwrap();
        let https = HttpConnector::new_with_tls(
            "https://connector.example".to_owned(),
            http_identity("12345678", (2, 5, 0)),
            &tls,
        )
        .unwrap();
        let https_agent = https.request_agent().unwrap();
        assert!(https_agent.config().tls_config().client_cert().is_some());
        assert!(https_agent.config().https_only());
        assert_eq!(https_agent.config().max_redirects(), 0);

        let http = HttpConnector::new_with_tls(
            "http://connector.example".to_owned(),
            http_identity("12345678", (2, 5, 0)),
            &tls,
        )
        .unwrap();
        let http_agent = http.request_agent().unwrap();
        assert!(http_agent.config().tls_config().client_cert().is_none());
        assert!(!http_agent.config().https_only());
        assert_eq!(http_agent.config().max_redirects(), 0);
    }

    #[test]
    fn http_connector_rejects_malformed_or_mismatched_client_identity() {
        let (certificate, private_key) = test_http_client_identity();
        assert!(
            HttpConnectorTlsConfig::from_client_identity(b"not a certificate", &private_key)
                .is_err()
        );
        assert!(
            HttpConnectorTlsConfig::from_client_identity(&certificate, b"not a private key")
                .is_err()
        );

        let other_key = crate::certificate_builder::p256_key();
        let other_private_key = other_key.to_pkcs8_der().unwrap();
        assert!(HttpConnectorTlsConfig::from_client_identity(
            &certificate,
            other_private_key.as_bytes()
        )
        .is_err());
        assert!(HttpConnectorTlsConfig::default()
            .with_ca_bundle(b"not a CA bundle")
            .is_err());
    }

    #[test]
    fn http_connector_custom_ca_does_not_require_a_client_identity() {
        let tls = HttpConnectorTlsConfig::default()
            .with_ca_bundle(&test_ca_certificate_bundle())
            .unwrap();
        let https = HttpConnector::new_with_tls(
            "https://connector.example".to_owned(),
            http_identity("12345678", (2, 5, 0)),
            &tls,
        )
        .unwrap();
        let https_agent = https.request_agent().unwrap();
        assert!(https_agent.config().tls_config().client_cert().is_none());
        assert!(matches!(
            https_agent.config().tls_config().root_certs(),
            ureq::tls::RootCerts::Specific(certificates) if certificates.len() == 1
        ));
        assert!(https_agent.config().https_only());
        assert_eq!(https_agent.config().max_redirects(), 10);
    }

    #[test]
    fn http_connector_mutual_tls_verifies_both_peers() {
        let (tls, server_config) = test_mutual_tls(&[127, 0, 0, 1], true);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            connection
                .set_write_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let session = rustls::ServerConnection::new(server_config).unwrap();
            let mut connection = rustls::StreamOwned::new(session, connection);
            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"GET /v1/devices HTTP/1.1\r\n"));
            assert_eq!(
                connection
                    .conn
                    .peer_certificates()
                    .map(|certificates| certificates.len()),
                Some(1)
            );
            write_http_response(
                &mut connection,
                br#"{"devices":[{"serial":"12345678","usb_version":"2.5","status":"available"}]}"#,
                true,
            );
        });

        let connectors =
            HttpConnector::discover_with_tls(format!("https://127.0.0.1:{}", address.port()), &tls)
                .unwrap();
        assert_eq!(connectors.len(), 1);
        server.join().unwrap();
    }

    fn assert_tls_server_is_rejected(
        tls: &HttpConnectorTlsConfig,
        server_config: Arc<rustls::ServerConfig>,
    ) {
        use std::io::Read;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            connection
                .set_write_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let session = rustls::ServerConnection::new(server_config).unwrap();
            let mut connection = rustls::StreamOwned::new(session, connection);
            let mut byte = [0];
            assert!(connection.read(&mut byte).is_err());
        });
        assert!(HttpConnector::discover_with_tls(
            format!("https://127.0.0.1:{}", address.port()),
            tls,
        )
        .is_err());
        server.join().unwrap();
    }

    #[test]
    fn http_connector_rejects_an_untrusted_tls_server() {
        let (tls, server_config) = test_mutual_tls(&[127, 0, 0, 1], false);
        assert_tls_server_is_rejected(&tls, server_config);
    }

    #[test]
    fn http_connector_rejects_a_tls_server_with_the_wrong_identity() {
        let (tls, server_config) = test_mutual_tls(&[127, 0, 0, 2], true);
        assert_tls_server_is_rejected(&tls, server_config);
    }

    #[test]
    fn http_connector_discovers_and_routes_a_device_by_serial() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"GET /v1/devices HTTP/1.1\r\n"));
            write_http_response(
                &mut connection,
                br#"{"devices":[{"serial":"12345678","usb_version":"2.5","status":"available"}]}"#,
                false,
            );

            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"GET /v1/devices/12345678 HTTP/1.1\r\n"));
            write_http_response(
                &mut connection,
                br#"{"serial":"12345678","usb_version":"2.5","status":"available"}"#,
                false,
            );

            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"GET /v1/devices/12345678 HTTP/1.1\r\n"));
            write_http_response(
                &mut connection,
                br#"{"serial":"12345678","usb_version":"2.5","status":"available"}"#,
                false,
            );

            let request = read_http_request(&mut connection);
            assert!(request.starts_with(b"POST /v1/devices/12345678/commands HTTP/1.1\r\n"));
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
            write_http_response(&mut connection, b"\x83\x00\x01\x42", true);
        });

        let mut connectors = HttpConnector::discover_with_tls(
            format!("http://{address}"),
            &HttpConnectorTlsConfig::default(),
        )
        .unwrap();
        assert_eq!(connectors.len(), 1);
        let connector = connectors.pop().unwrap();
        connector.connect().unwrap();
        assert!(connector.is_present());
        assert_eq!(
            connector
                .state
                .status_identity
                .lock()
                .unwrap()
                .as_ref()
                .map(|status| status.serial.as_str()),
            Some("12345678")
        );
        assert_eq!((connector.major(), connector.minor()), (2, 5));
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
    fn http_connector_epochs_track_replacement_and_reconnection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            for (index, (path, identity)) in [
                (
                    b"GET /v1/devices HTTP/1.1\r\n".as_slice(),
                    br#"{"devices":[{"serial":"11111111","usb_version":"2.5","status":"available"}]}"#.as_slice(),
                ),
                (
                    b"GET /v1/devices/11111111 HTTP/1.1\r\n".as_slice(),
                    br#"{"serial":"11111111","usb_version":"2.5","status":"available"}"#.as_slice(),
                ),
                (
                    b"GET /v1/devices/11111111 HTTP/1.1\r\n".as_slice(),
                    br#"{"serial":"11111111","usb_version":"2.5","status":"available"}"#.as_slice(),
                ),
                (
                    b"GET /v1/devices/11111111 HTTP/1.1\r\n".as_slice(),
                    br#"{"serial":"11111111","usb_version":"2.6","status":"available"}"#.as_slice(),
                ),
                (
                    b"GET /v1/devices/11111111 HTTP/1.1\r\n".as_slice(),
                    br#"{"serial":"11111111","usb_version":"2.6","status":"available"}"#.as_slice(),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let request = read_http_request(&mut connection);
                assert!(request.starts_with(path));
                write_http_response(&mut connection, identity, index == 4);
            }
        });

        let mut connectors = HttpConnector::discover_with_tls(
            format!("http://{address}"),
            &HttpConnectorTlsConfig::default(),
        )
        .unwrap();
        let connector = connectors.pop().unwrap();
        connector.connect().unwrap();
        assert_eq!(connector.connection_epoch(), 0);
        assert_eq!(
            connector
                .state
                .status_identity
                .lock()
                .unwrap()
                .as_ref()
                .map(|status| status.serial.as_str()),
            Some("11111111")
        );

        connector.refresh().unwrap();
        assert_eq!(connector.connection_epoch(), 0);

        connector.refresh().unwrap();
        assert_eq!(connector.connection_epoch(), 1);
        {
            let status = connector.state.status_identity.lock().unwrap();
            let status = status.as_ref().unwrap();
            assert_eq!(status.serial, "11111111");
            assert_eq!(status.version, (2, 6, 0));
        }

        connector.mark_disconnected();
        assert!(!connector.is_present());
        connector.refresh().unwrap();
        assert!(connector.is_present());
        assert_eq!(connector.connection_epoch(), 2);
        assert_eq!(
            connector
                .state
                .status_identity
                .lock()
                .unwrap()
                .as_ref()
                .map(|status| status.serial.as_str()),
            Some("11111111")
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
