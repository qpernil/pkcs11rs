use futures_util::future::BoxFuture;
use pkcs11rs_local_hardware::{
    UsbDeviceId, YubiHsmHotplugEvent, YubiHsmUsbCandidate, YubiHsmUsbDevice,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SerialAllowlist(HashSet<String>);

impl FromStr for SerialAllowlist {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.trim().is_empty() {
            return Ok(Self(HashSet::new()));
        }
        value
            .split(',')
            .map(|serial| {
                let serial = serial.trim();
                if serial.is_empty() {
                    Err(String::from("serial allowlist contains an empty entry"))
                } else {
                    Ok(serial.to_owned())
                }
            })
            .collect::<Result<HashSet<_>, _>>()
            .map(Self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Claimed,
    Unclaimed,
    Filtered,
    LegacyOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTransportKind {
    Usb,
    #[cfg(any(test, all(embedded_virtual_yubihsm, unix)))]
    Embedded,
    #[cfg(any(test, all(feature = "experimental-i2c", target_os = "linux")))]
    I2c,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceTransportView {
    pub kind: DeviceTransportKind,
    pub connection_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceView {
    pub serial: String,
    pub manufacturer: String,
    pub product: String,
    pub usb_version: String,
    pub status: DeviceStatus,
    pub transport: DeviceTransportView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceMetadata {
    serial: String,
    manufacturer: String,
    product: String,
    usb_version: String,
}

impl DeviceMetadata {
    fn view(&self, status: DeviceStatus, transport: DeviceTransportView) -> DeviceView {
        DeviceView {
            serial: self.serial.clone(),
            manufacturer: self.manufacturer.clone(),
            product: self.product.clone(),
            usb_version: self.usb_version.clone(),
            status,
            transport,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    InvalidCommandFrame,
    CommandTooLarge,
    DeviceTransport,
    #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
    EndpointUnavailable,
}

#[derive(Clone, Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
    pub(crate) fn invalid_frame(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::InvalidCommandFrame,
            message: message.into(),
        }
    }

    #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
    pub(crate) fn too_large(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::CommandTooLarge,
            message: message.into(),
        }
    }

    pub(crate) fn device(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::DeviceTransport,
            message: message.into(),
        }
    }

    #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
    pub(crate) fn endpoint_unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::EndpointUnavailable,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        match self.kind {
            TransportErrorKind::InvalidCommandFrame => "invalid_command_frame",
            TransportErrorKind::CommandTooLarge => "command_too_large",
            TransportErrorKind::DeviceTransport => "device_transport_error",
            #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
            TransportErrorKind::EndpointUnavailable => "endpoint_unavailable",
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

impl From<pkcs11rs_local_hardware::Error> for TransportError {
    fn from(error: pkcs11rs_local_hardware::Error) -> Self {
        let kind = match &error {
            pkcs11rs_local_hardware::Error::InvalidMessageLength { .. } => {
                TransportErrorKind::InvalidCommandFrame
            }
            pkcs11rs_local_hardware::Error::SendBufferTooLarge { .. } => {
                TransportErrorKind::CommandTooLarge
            }
            _ => TransportErrorKind::DeviceTransport,
        };
        Self {
            kind,
            message: error.to_string(),
        }
    }
}

pub(crate) trait CommandTransport: Send {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

trait ConnectedCommandTransport: Send {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

trait CommandTransportFactory: Send {
    fn open(&mut self)
    -> BoxFuture<'_, Result<Box<dyn ConnectedCommandTransport>, TransportError>>;
}

struct RecoverableCommandTransport {
    connected: Option<Box<dyn ConnectedCommandTransport>>,
    factory: Box<dyn CommandTransportFactory>,
}

impl RecoverableCommandTransport {
    fn new(
        connected: Box<dyn ConnectedCommandTransport>,
        factory: Box<dyn CommandTransportFactory>,
    ) -> Self {
        Self {
            connected: Some(connected),
            factory,
        }
    }
}

impl CommandTransport for RecoverableCommandTransport {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            if self.connected.is_none() {
                self.connected = Some(self.factory.open().await?);
            }
            let result = self
                .connected
                .as_mut()
                .expect("transport was opened above")
                .command(request)
                .await;
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == TransportErrorKind::DeviceTransport)
            {
                // The command may already have executed. Discard the uncertain
                // transport, return its error without replay, and reopen only
                // when a later request arrives.
                self.connected = None;
            }
            result
        })
    }
}

struct UsbConnectedTransport {
    device: YubiHsmUsbDevice,
}

impl ConnectedCommandTransport for UsbConnectedTransport {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let response = self
                .device
                .transmit_owned(request, Duration::ZERO)
                .await
                .map_err(TransportError::from)?;
            ensure_single_response_frame(&response)?;
            Ok(response)
        })
    }
}

fn ensure_single_response_frame(response: &[u8]) -> Result<(), TransportError> {
    let Some(header) = response.get(..3) else {
        return Err(TransportError::device(format!(
            "YubiHSM returned an incomplete response header of {} bytes",
            response.len()
        )));
    };
    let payload_len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    let expected = 3 + payload_len;
    if response.len() != expected {
        return Err(TransportError::device(format!(
            "YubiHSM returned {} response bytes, expected one {expected}-byte frame",
            response.len()
        )));
    }
    Ok(())
}

struct UsbTransportFactory {
    id: UsbDeviceId,
    serial: String,
}

impl CommandTransportFactory for UsbTransportFactory {
    fn open(
        &mut self,
    ) -> BoxFuture<'_, Result<Box<dyn ConnectedCommandTransport>, TransportError>> {
        Box::pin(async move {
            tracing::info!(
                serial = %self.serial,
                id = ?self.id,
                "reopening YubiHSM USB transport"
            );
            let result = async {
                let candidate = pkcs11rs_local_hardware::yubihsm_candidates()
                    .await
                    .map_err(TransportError::from)?
                    .into_iter()
                    .find(|candidate| candidate.id() == self.id)
                    .ok_or_else(|| {
                        TransportError::device(format!(
                            "YubiHSM {} is no longer present at USB device {:?}",
                            self.serial, self.id
                        ))
                    })?;
                let mut device = candidate.open().await.map_err(TransportError::from)?;
                if device.serial() != self.serial {
                    return Err(TransportError::device(format!(
                        "USB device {:?} changed serial from {} to {}",
                        self.id,
                        self.serial,
                        device.serial()
                    )));
                }
                device.connect().await.map_err(TransportError::from)?;
                Ok(Box::new(UsbConnectedTransport { device })
                    as Box<dyn ConnectedCommandTransport>)
            }
            .await;
            match &result {
                Ok(_) => tracing::info!(
                    serial = %self.serial,
                    id = ?self.id,
                    outcome = "success",
                    "YubiHSM USB transport reopen completed"
                ),
                Err(error) => tracing::info!(
                    serial = %self.serial,
                    id = ?self.id,
                    outcome = "failed",
                    %error,
                    "YubiHSM USB transport reopen completed"
                ),
            }
            result
        })
    }
}

pub struct DeviceEntry {
    id: Option<UsbDeviceId>,
    legacy_only: bool,
    metadata: DeviceMetadata,
    device_transport: DeviceTransportView,
    command_transport: Mutex<Box<dyn CommandTransport>>,
}

impl DeviceEntry {
    pub fn view(&self) -> DeviceView {
        self.metadata.view(
            if self.legacy_only {
                DeviceStatus::LegacyOnly
            } else {
                DeviceStatus::Claimed
            },
            self.device_transport.clone(),
        )
    }

    pub fn usb_device_id(&self) -> Option<String> {
        self.id.map(|id| format!("{id:?}"))
    }

    pub async fn command(
        self: &Arc<Self>,
        request: &[u8],
    ) -> (Result<Vec<u8>, TransportError>, Duration) {
        let entry = self.clone();
        let request = request.to_vec();
        tokio::spawn(async move {
            let mut transport = entry.command_transport.lock().await;
            let started_at = Instant::now();
            let result = transport.command(request).await;
            (result, started_at.elapsed())
        })
        .await
        .unwrap_or_else(|error| {
            (
                Err(TransportError::device(format!(
                    "YubiHSM command task failed: {error}"
                ))),
                Duration::ZERO,
            )
        })
    }
}

enum DeviceRecord {
    Claimed(Arc<DeviceEntry>),
    Unclaimed {
        metadata: DeviceMetadata,
        transport: DeviceTransportView,
    },
    Filtered {
        metadata: DeviceMetadata,
        transport: DeviceTransportView,
    },
}

impl DeviceRecord {
    fn metadata(&self) -> &DeviceMetadata {
        match self {
            Self::Claimed(entry) => &entry.metadata,
            Self::Unclaimed { metadata, .. } | Self::Filtered { metadata, .. } => metadata,
        }
    }

    fn view(&self) -> DeviceView {
        match self {
            Self::Claimed(entry) => entry.view(),
            Self::Unclaimed {
                metadata,
                transport,
            } => metadata.view(DeviceStatus::Unclaimed, transport.clone()),
            Self::Filtered {
                metadata,
                transport,
            } => metadata.view(DeviceStatus::Filtered, transport.clone()),
        }
    }

    fn claimed(&self) -> Option<&Arc<DeviceEntry>> {
        match self {
            Self::Claimed(entry) => Some(entry),
            Self::Unclaimed { .. } | Self::Filtered { .. } => None,
        }
    }
}

#[derive(Default)]
struct RegistryState {
    records: HashMap<String, DeviceRecord>,
    serial_by_id: HashMap<UsbDeviceId, String>,
    connection_generations: HashMap<String, u64>,
    legacy_serial: Option<String>,
}

#[derive(Clone)]
pub struct DeviceRegistry {
    state: Arc<RwLock<RegistryState>>,
    serials: Option<Arc<SerialAllowlist>>,
    configured_legacy_serial: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySelectionError {
    NoDevice,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(RegistryState::default())),
            serials: None,
            configured_legacy_serial: None,
        }
    }

    pub(crate) fn with_serials(mut self, serials: Option<SerialAllowlist>) -> Self {
        self.serials = serials.map(Arc::new);
        self
    }

    pub(crate) fn allows_serial(&self, serial: &str) -> bool {
        self.serials
            .as_ref()
            .is_none_or(|serials| serials.0.contains(serial))
    }

    pub(crate) fn with_legacy_serial(mut self, serial: Option<String>) -> Self {
        self.configured_legacy_serial = serial.map(Arc::from);
        self
    }

    pub(crate) fn should_claim(&self, serial: &str) -> bool {
        self.allows_serial(serial) || self.configured_legacy_serial.as_deref() == Some(serial)
    }

    #[cfg(any(
        test,
        all(feature = "experimental-i2c", target_os = "linux"),
        all(embedded_virtual_yubihsm, unix)
    ))]
    pub(crate) async fn register_filtered(
        &self,
        serial: String,
        version: Option<[u8; 3]>,
        kind: DeviceTransportKind,
    ) -> Result<(), TransportError> {
        let mut state = self.state.write().await;
        if state.records.contains_key(&serial) {
            return Err(TransportError::device(format!(
                "duplicate YubiHSM serial {serial}"
            )));
        }
        let generation = state
            .connection_generations
            .entry(serial.clone())
            .or_default();
        *generation = generation.saturating_add(1);
        let record = DeviceRecord::Filtered {
            metadata: DeviceMetadata {
                serial: serial.clone(),
                manufacturer: "Yubico".into(),
                product: "YubiHSM".into(),
                usb_version: version
                    .map(|version| format!("{}.{}", version[0], version[1]))
                    .unwrap_or_default(),
            },
            transport: DeviceTransportView {
                kind,
                connection_generation: *generation,
            },
        };
        state.records.insert(serial.clone(), record);
        tracing::info!(%serial, "configured YubiHSM excluded by serial filter");
        Ok(())
    }

    pub async fn list(&self) -> Vec<DeviceView> {
        let mut devices = self
            .state
            .read()
            .await
            .records
            .values()
            .map(DeviceRecord::view)
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| left.serial.cmp(&right.serial));
        devices
    }

    pub async fn view(&self, serial: &str) -> Option<DeviceView> {
        self.state
            .read()
            .await
            .records
            .get(serial)
            .map(DeviceRecord::view)
    }

    pub async fn get(&self, serial: &str) -> Option<Arc<DeviceEntry>> {
        self.state
            .read()
            .await
            .records
            .get(serial)
            .and_then(DeviceRecord::claimed)
            .filter(|entry| !entry.legacy_only)
            .cloned()
    }

    pub async fn select_legacy(
        &self,
        configured_serial: Option<&str>,
    ) -> Result<Arc<DeviceEntry>, LegacySelectionError> {
        let state = self.state.read().await;
        if let Some(serial) = configured_serial {
            return state
                .records
                .get(serial)
                .and_then(DeviceRecord::claimed)
                .cloned()
                .ok_or(LegacySelectionError::NoDevice);
        }
        state
            .legacy_serial
            .as_deref()
            .and_then(|serial| state.records.get(serial))
            .and_then(DeviceRecord::claimed)
            .cloned()
            .ok_or(LegacySelectionError::NoDevice)
    }

    async fn contains_id(&self, id: UsbDeviceId) -> bool {
        self.state.read().await.serial_by_id.contains_key(&id)
    }

    async fn next_connection_generation(&self, serial: &str) -> u64 {
        let mut state = self.state.write().await;
        let generation = state
            .connection_generations
            .entry(serial.to_owned())
            .or_default();
        *generation = generation.saturating_add(1);
        *generation
    }

    async fn register(&self, id: UsbDeviceId, record: DeviceRecord) -> bool {
        let serial = record.metadata().serial.clone();
        let mut state = self.state.write().await;
        if state.records.contains_key(&serial) {
            tracing::error!(%serial, ?id, "duplicate YubiHSM serial");
            return false;
        }
        state.serial_by_id.insert(id, serial.clone());
        if record.claimed().is_some() && state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.clone());
        }
        state.records.insert(serial, record);
        true
    }

    async fn register_unclaimed(&self, id: UsbDeviceId, metadata: DeviceMetadata) {
        let connection_generation = self.next_connection_generation(&metadata.serial).await;
        self.register(
            id,
            DeviceRecord::Unclaimed {
                metadata,
                transport: DeviceTransportView {
                    kind: DeviceTransportKind::Usb,
                    connection_generation,
                },
            },
        )
        .await;
    }

    #[cfg(any(
        test,
        all(feature = "experimental-i2c", target_os = "linux"),
        all(embedded_virtual_yubihsm, unix)
    ))]
    pub(crate) async fn register_configured(
        &self,
        serial: String,
        version: [u8; 3],
        kind: DeviceTransportKind,
        transport: impl FnOnce(u64) -> Box<dyn CommandTransport> + Send,
    ) -> Result<(), TransportError> {
        if !self.should_claim(&serial) {
            return self.register_filtered(serial, Some(version), kind).await;
        }
        let mut state = self.state.write().await;
        if state.records.contains_key(&serial) {
            return Err(TransportError::device(format!(
                "duplicate YubiHSM serial {serial}"
            )));
        }
        let connection_generation = state
            .connection_generations
            .entry(serial.clone())
            .or_default();
        *connection_generation = connection_generation.saturating_add(1);
        let entry = Arc::new(DeviceEntry {
            id: None,
            legacy_only: !self.allows_serial(&serial),
            metadata: DeviceMetadata {
                serial: serial.clone(),
                manufacturer: String::from("Yubico"),
                product: String::from("YubiHSM"),
                usb_version: format!("{}.{}", version[0], version[1]),
            },
            device_transport: DeviceTransportView {
                kind,
                connection_generation: *connection_generation,
            },
            command_transport: Mutex::new(transport(*connection_generation)),
        });
        if state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.clone());
        }
        state.records.insert(serial, DeviceRecord::Claimed(entry));
        Ok(())
    }

    #[cfg(any(test, all(feature = "experimental-i2c", target_os = "linux")))]
    pub(crate) async fn remove_i2c(&self, serial: u32, connection_generation: u64) -> bool {
        let serial = serial.to_string();
        let mut state = self.state.write().await;
        let is_matching_i2c = state
            .records
            .get(&serial)
            .map(DeviceRecord::view)
            .is_some_and(|view| {
                view.transport.kind == DeviceTransportKind::I2c
                    && view.transport.connection_generation == connection_generation
            });
        if !is_matching_i2c {
            return false;
        }
        state.records.remove(&serial);
        if state.legacy_serial.as_deref() == Some(&serial) {
            state.legacy_serial = None;
        }
        true
    }

    fn candidate_metadata(candidate: &YubiHsmUsbCandidate, serial: String) -> DeviceMetadata {
        let version = candidate.version();
        DeviceMetadata {
            serial,
            manufacturer: candidate.manufacturer().to_owned(),
            product: candidate.product().to_owned(),
            usb_version: format!("{}.{}", version.0, version.1),
        }
    }

    async fn attach_candidate(&self, candidate: YubiHsmUsbCandidate) {
        let id = candidate.id();
        if self.contains_id(id).await {
            return;
        }
        let serial = match candidate.serial().await {
            Ok(Some(serial)) if !serial.is_empty() => serial,
            Ok(_) => {
                tracing::warn!(?id, "ignoring YubiHSM without a serial number");
                return;
            }
            Err(error) => {
                tracing::warn!(?id, %error, "could not identify YubiHSM; leaving it unmanaged");
                return;
            }
        };
        let unclaimed_metadata = Self::candidate_metadata(&candidate, serial.clone());
        if self
            .reject_filtered_usb(id, unclaimed_metadata.clone())
            .await
        {
            return;
        }
        let mut device = match candidate.open().await {
            Ok(device) => device,
            Err(error) => {
                tracing::warn!(?id, %error, "could not open YubiHSM; leaving it unmanaged");
                self.register_unclaimed(id, unclaimed_metadata).await;
                return;
            }
        };
        if let Err(error) = device.connect().await {
            tracing::warn!(
                ?id,
                serial = device.serial(),
                %error,
                "could not claim YubiHSM interface; leaving it unmanaged"
            );
            self.register_unclaimed(id, unclaimed_metadata).await;
            return;
        }
        let version = device.version();
        let metadata = DeviceMetadata {
            serial: serial.clone(),
            manufacturer: device.manufacturer().to_owned(),
            product: device.product().to_owned(),
            usb_version: format!("{}.{}", version.0, version.1),
        };
        let connection_generation = self.next_connection_generation(&serial).await;
        let entry = Arc::new(DeviceEntry {
            id: Some(id),
            legacy_only: !self.allows_serial(&serial),
            metadata,
            device_transport: DeviceTransportView {
                kind: DeviceTransportKind::Usb,
                connection_generation,
            },
            command_transport: Mutex::new(Box::new(RecoverableCommandTransport::new(
                Box::new(UsbConnectedTransport { device }),
                Box::new(UsbTransportFactory {
                    id,
                    serial: serial.clone(),
                }),
            ))),
        });
        if self.register(id, DeviceRecord::Claimed(entry)).await {
            tracing::info!(%serial, ?id, "YubiHSM attached");
        }
    }

    async fn reject_filtered_usb(&self, id: UsbDeviceId, metadata: DeviceMetadata) -> bool {
        if self.should_claim(&metadata.serial) {
            return false;
        }
        let connection_generation = self.next_connection_generation(&metadata.serial).await;
        tracing::info!(serial = %metadata.serial, ?id, "USB YubiHSM excluded by serial filter");
        self.register(
            id,
            DeviceRecord::Filtered {
                metadata,
                transport: DeviceTransportView {
                    kind: DeviceTransportKind::Usb,
                    connection_generation,
                },
            },
        )
        .await;
        true
    }

    async fn detach(&self, id: UsbDeviceId) {
        let mut state = self.state.write().await;
        let Some(serial) = state.serial_by_id.remove(&id) else {
            return;
        };
        let managed = state
            .records
            .get(&serial)
            .and_then(DeviceRecord::claimed)
            .is_some_and(|entry| entry.id == Some(id));
        state.records.remove(&serial);
        tracing::info!(%serial, ?id, managed, "YubiHSM detached");
    }

    #[cfg(test)]
    async fn insert_test(&self, serial: &str, transport: Box<dyn CommandTransport>) {
        let connection_generation = self.next_connection_generation(serial).await;
        let entry = Arc::new(DeviceEntry {
            id: None,
            legacy_only: !self.allows_serial(serial),
            metadata: DeviceMetadata {
                serial: serial.to_owned(),
                manufacturer: String::from("Test"),
                product: String::from("YubiHSM"),
                usb_version: String::from("2.0"),
            },
            device_transport: DeviceTransportView {
                kind: DeviceTransportKind::Embedded,
                connection_generation,
            },
            command_transport: Mutex::new(transport),
        });
        let mut state = self.state.write().await;
        if state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.to_owned());
        }
        state
            .records
            .insert(serial.to_owned(), DeviceRecord::Claimed(entry));
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_unclaimed(&self, serial: &str) {
        let connection_generation = self.next_connection_generation(serial).await;
        self.state.write().await.records.insert(
            serial.to_owned(),
            DeviceRecord::Unclaimed {
                metadata: DeviceMetadata {
                    serial: serial.to_owned(),
                    manufacturer: String::from("Test"),
                    product: String::from("YubiHSM"),
                    usb_version: String::from("2.0"),
                },
                transport: DeviceTransportView {
                    kind: DeviceTransportKind::Usb,
                    connection_generation,
                },
            },
        );
    }

    #[cfg(test)]
    async fn remove_test(&self, serial: &str) {
        self.state.write().await.records.remove(serial);
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_echo(&self, serial: &str) {
        self.insert_test(serial, Box::new(EchoTransport)).await;
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_response(&self, serial: &str, response: &'static [u8]) {
        self.insert_test(serial, Box::new(FixedTransport(response)))
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_error(&self, serial: &str, error: TransportError) {
        self.insert_test(serial, Box::new(FixedErrorTransport(error)))
            .await;
    }
}

#[cfg(test)]
struct EchoTransport;

#[cfg(test)]
impl CommandTransport for EchoTransport {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Ok(request) })
    }
}

#[cfg(test)]
struct FixedTransport(&'static [u8]);

#[cfg(test)]
impl CommandTransport for FixedTransport {
    fn command<'a>(
        &'a mut self,
        _request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Ok(self.0.to_vec()) })
    }
}

#[cfg(test)]
struct FixedErrorTransport(TransportError);

#[cfg(test)]
impl CommandTransport for FixedErrorTransport {
    fn command<'a>(
        &'a mut self,
        _request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Err(self.0.clone()) })
    }
}

pub async fn spawn_discovery(
    registry: DeviceRegistry,
) -> Result<tokio::task::JoinHandle<()>, BoxError> {
    Ok(tokio::spawn(async move {
        // Start watching before the initial list so no attachment can be missed
        // in the interval between enumeration and hot-plug subscription.
        let mut watch = match pkcs11rs_local_hardware::watch_yubihsms() {
            Ok(watch) => watch,
            Err(error) => {
                tracing::error!(%error, "USB hot-plug watcher could not start");
                return;
            }
        };
        match pkcs11rs_local_hardware::yubihsm_candidates().await {
            Ok(candidates) => {
                for candidate in candidates {
                    registry.attach_candidate(candidate).await;
                }
            }
            Err(error) => {
                tracing::error!(%error, "initial USB YubiHSM enumeration failed");
            }
        }
        while let Some(event) = watch.next_event().await {
            match event {
                YubiHsmHotplugEvent::Connected(candidate) => {
                    registry.attach_candidate(candidate).await
                }
                YubiHsmHotplugEvent::Disconnected(id) => registry.detach(id).await,
            }
        }
        tracing::error!("USB hot-plug event stream ended");
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::sync::Barrier;

    struct ScriptedConnectedTransport {
        calls: Arc<StdMutex<Vec<Vec<u8>>>>,
        outcomes: VecDeque<Option<TransportError>>,
    }

    impl ConnectedCommandTransport for ScriptedConnectedTransport {
        fn command<'a>(
            &'a mut self,
            request: Vec<u8>,
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(request.clone());
                match self.outcomes.pop_front().flatten() {
                    Some(error) => Err(error),
                    None => Ok(request),
                }
            })
        }
    }

    struct ScriptedFactory {
        calls: Arc<StdMutex<Vec<Vec<u8>>>>,
        opens: Arc<AtomicUsize>,
        failures_remaining: usize,
    }

    impl CommandTransportFactory for ScriptedFactory {
        fn open(
            &mut self,
        ) -> BoxFuture<'_, Result<Box<dyn ConnectedCommandTransport>, TransportError>> {
            Box::pin(async move {
                self.opens.fetch_add(1, Ordering::SeqCst);
                if self.failures_remaining > 0 {
                    self.failures_remaining -= 1;
                    return Err(TransportError::device("scripted reopen failure"));
                }
                Ok(Box::new(ScriptedConnectedTransport {
                    calls: self.calls.clone(),
                    outcomes: VecDeque::new(),
                }) as Box<dyn ConnectedCommandTransport>)
            })
        }
    }

    struct ScriptedTransportHarness {
        transport: RecoverableCommandTransport,
        calls: Arc<StdMutex<Vec<Vec<u8>>>>,
        opens: Arc<AtomicUsize>,
    }

    fn scripted_recoverable_transport(
        outcomes: impl IntoIterator<Item = Option<TransportError>>,
        reopen_failures: usize,
    ) -> ScriptedTransportHarness {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let opens = Arc::new(AtomicUsize::new(0));
        ScriptedTransportHarness {
            transport: RecoverableCommandTransport::new(
                Box::new(ScriptedConnectedTransport {
                    calls: calls.clone(),
                    outcomes: outcomes.into_iter().collect(),
                }),
                Box::new(ScriptedFactory {
                    calls: calls.clone(),
                    opens: opens.clone(),
                    failures_remaining: reopen_failures,
                }),
            ),
            calls,
            opens,
        }
    }

    #[tokio::test]
    async fn transport_error_reopens_only_for_the_next_command_without_replay() {
        let ScriptedTransportHarness {
            mut transport,
            calls,
            opens,
        } = scripted_recoverable_transport(
            [Some(TransportError::device("uncertain command outcome"))],
            0,
        );

        assert!(transport.command(b"uncertain".to_vec()).await.is_err());
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(transport.command(b"next".to_vec()).await.unwrap(), b"next");
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![b"uncertain".to_vec(), b"next".to_vec()]
        );
    }

    #[tokio::test]
    async fn failed_reopen_is_retried_by_a_later_command() {
        let ScriptedTransportHarness {
            mut transport,
            calls,
            opens,
        } = scripted_recoverable_transport(
            [Some(TransportError::device("uncertain command outcome"))],
            1,
        );

        assert!(transport.command(b"uncertain".to_vec()).await.is_err());
        assert!(transport.command(b"reopen fails".to_vec()).await.is_err());
        assert_eq!(
            transport.command(b"later".to_vec()).await.unwrap(),
            b"later"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![b"uncertain".to_vec(), b"later".to_vec()]
        );
    }

    #[tokio::test]
    async fn request_validation_error_keeps_the_connected_transport() {
        let invalid = TransportError {
            kind: TransportErrorKind::InvalidCommandFrame,
            message: String::from("invalid request"),
        };
        let ScriptedTransportHarness {
            mut transport,
            calls,
            opens,
        } = scripted_recoverable_transport([Some(invalid)], 0);

        assert!(transport.command(b"invalid".to_vec()).await.is_err());
        assert_eq!(
            transport.command(b"valid".to_vec()).await.unwrap(),
            b"valid"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![b"invalid".to_vec(), b"valid".to_vec()]
        );
    }

    #[tokio::test]
    async fn legacy_selection_latches_the_first_serial_and_allows_an_override() {
        let registry = DeviceRegistry::new();
        assert!(matches!(
            registry.select_legacy(None).await,
            Err(LegacySelectionError::NoDevice)
        ));
        registry.insert_test_echo("22222222").await;
        let selected = registry.select_legacy(None).await.unwrap();
        assert_eq!(selected.view().serial, "22222222");
        assert_eq!(selected.command(b"hello").await.0.unwrap(), b"hello");

        registry.insert_test_echo("11111111").await;
        assert_eq!(
            registry.select_legacy(None).await.unwrap().view().serial,
            "22222222"
        );
        assert_eq!(
            registry
                .select_legacy(Some("11111111"))
                .await
                .unwrap()
                .view()
                .serial,
            "11111111"
        );
        assert_eq!(
            registry
                .list()
                .await
                .into_iter()
                .map(|device| device.serial)
                .collect::<Vec<_>>(),
            vec![String::from("11111111"), String::from("22222222")]
        );

        registry.remove_test("22222222").await;
        assert!(matches!(
            registry.select_legacy(None).await,
            Err(LegacySelectionError::NoDevice)
        ));

        registry.insert_test_echo("22222222").await;
        assert_eq!(
            registry.select_legacy(None).await.unwrap().view().serial,
            "22222222"
        );
    }

    #[tokio::test]
    async fn connection_generation_increases_when_a_serial_is_registered_again() {
        let registry = DeviceRegistry::new();
        registry.insert_test_unclaimed("12345678").await;
        let first = registry.view("12345678").await.unwrap();
        assert_eq!(first.status, DeviceStatus::Unclaimed);
        assert_eq!(first.transport.kind, DeviceTransportKind::Usb);
        assert_eq!(first.transport.connection_generation, 1);

        registry.remove_test("12345678").await;
        registry.insert_test_echo("12345678").await;
        let second = registry.view("12345678").await.unwrap();
        assert_eq!(second.status, DeviceStatus::Claimed);
        assert_eq!(second.transport.kind, DeviceTransportKind::Embedded);
        assert_eq!(second.transport.connection_generation, 2);
    }

    #[tokio::test]
    async fn stale_i2c_loss_does_not_remove_a_new_connection_generation() {
        let registry = DeviceRegistry::new();
        registry
            .register_configured(
                String::from("12345678"),
                [2, 4, 0],
                DeviceTransportKind::I2c,
                |_| Box::new(EchoTransport),
            )
            .await
            .unwrap();
        let first_generation = registry
            .view("12345678")
            .await
            .unwrap()
            .transport
            .connection_generation;
        assert!(registry.remove_i2c(12345678, first_generation).await);

        registry
            .register_configured(
                String::from("12345678"),
                [2, 4, 0],
                DeviceTransportKind::I2c,
                |_| Box::new(EchoTransport),
            )
            .await
            .unwrap();
        let second_generation = registry
            .view("12345678")
            .await
            .unwrap()
            .transport
            .connection_generation;
        assert!(second_generation > first_generation);

        assert!(!registry.remove_i2c(12345678, first_generation).await);
        assert_eq!(
            registry
                .view("12345678")
                .await
                .unwrap()
                .transport
                .connection_generation,
            second_generation
        );
    }

    struct ConcurrencyProbe {
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }

    impl CommandTransport for ConcurrencyProbe {
        fn command<'a>(
            &'a mut self,
            request: Vec<u8>,
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                Ok(request)
            })
        }
    }

    #[tokio::test]
    async fn one_device_executes_only_one_command_at_a_time() {
        let registry = DeviceRegistry::new();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        registry
            .insert_test(
                "12345678",
                Box::new(ConcurrencyProbe {
                    active: active.clone(),
                    maximum: maximum.clone(),
                }),
            )
            .await;
        let entry = registry.get("12345678").await.unwrap();
        let (left, right) = tokio::join!(entry.command(b"left"), entry.command(b"right"));
        assert_eq!(left.0.unwrap(), b"left");
        assert_eq!(right.0.unwrap(), b"right");
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    struct CancellationProbe {
        executions: Arc<AtomicUsize>,
        first_started: Option<tokio::sync::oneshot::Sender<()>>,
        release_first: Arc<tokio::sync::Notify>,
    }

    impl CommandTransport for CancellationProbe {
        fn command<'a>(
            &'a mut self,
            request: Vec<u8>,
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                self.executions.fetch_add(1, Ordering::SeqCst);
                if request == b"first" {
                    self.first_started.take().unwrap().send(()).unwrap();
                    self.release_first.notified().await;
                }
                Ok(request)
            })
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_cancel_or_overlap_device_command() {
        let registry = DeviceRegistry::new();
        let executions = Arc::new(AtomicUsize::new(0));
        let release_first = Arc::new(tokio::sync::Notify::new());
        let (first_started, started) = tokio::sync::oneshot::channel();
        registry
            .insert_test(
                "12345678",
                Box::new(CancellationProbe {
                    executions: executions.clone(),
                    first_started: Some(first_started),
                    release_first: release_first.clone(),
                }),
            )
            .await;
        let entry = registry.get("12345678").await.unwrap();

        let first_entry = entry.clone();
        let first = tokio::spawn(async move { first_entry.command(b"first").await });
        started.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(entry.command_transport.try_lock().is_err());

        let second_entry = entry.clone();
        let second = tokio::spawn(async move { second_entry.command(b"second").await });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());

        release_first.notify_one();
        assert_eq!(second.await.unwrap().0.unwrap(), b"second");
        assert_eq!(executions.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn usb_response_must_contain_exactly_one_frame() {
        assert!(ensure_single_response_frame(&[0x86, 0x00, 0x01, 0x00]).is_ok());
        assert!(ensure_single_response_frame(&[0x86, 0x00]).is_err());
        assert!(
            ensure_single_response_frame(&[0x86, 0x00, 0x01, 0x00, 0x86, 0x00, 0x01, 0x00])
                .is_err()
        );
    }

    struct StressProbe {
        executions: StdMutex<HashMap<u64, usize>>,
        active: AtomicUsize,
        maximum: AtomicUsize,
        first_command: AtomicBool,
        first_command_barrier: Arc<Barrier>,
        global_active: Arc<AtomicUsize>,
        global_maximum: Arc<AtomicUsize>,
        worker_threads: Arc<StdMutex<HashSet<std::thread::ThreadId>>>,
        opens: AtomicUsize,
    }

    struct StressConnectedTransport {
        probe: Arc<StressProbe>,
    }

    impl ConnectedCommandTransport for StressConnectedTransport {
        fn command<'a>(
            &'a mut self,
            request: Vec<u8>,
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let id = u64::from_be_bytes(request.as_slice().try_into().unwrap());
                let active = self.probe.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.probe.maximum.fetch_max(active, Ordering::SeqCst);
                let global_active = self.probe.global_active.fetch_add(1, Ordering::SeqCst) + 1;
                self.probe
                    .global_maximum
                    .fetch_max(global_active, Ordering::SeqCst);
                self.probe
                    .worker_threads
                    .lock()
                    .unwrap()
                    .insert(std::thread::current().id());
                *self.probe.executions.lock().unwrap().entry(id).or_default() += 1;

                if self.probe.first_command.swap(false, Ordering::SeqCst) {
                    self.probe.first_command_barrier.wait().await;
                }
                tokio::time::sleep(Duration::from_micros(100)).await;

                self.probe.active.fetch_sub(1, Ordering::SeqCst);
                self.probe.global_active.fetch_sub(1, Ordering::SeqCst);
                if id % 29 == 0 {
                    Err(TransportError::device("injected transport failure"))
                } else {
                    Ok(request)
                }
            })
        }
    }

    struct StressFactory {
        probe: Arc<StressProbe>,
    }

    impl CommandTransportFactory for StressFactory {
        fn open(
            &mut self,
        ) -> BoxFuture<'_, Result<Box<dyn ConnectedCommandTransport>, TransportError>> {
            self.probe.opens.fetch_add(1, Ordering::SeqCst);
            let connected = StressConnectedTransport {
                probe: self.probe.clone(),
            };
            Box::pin(async move { Ok(Box::new(connected) as Box<dyn ConnectedCommandTransport>) })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn heavy_multithreaded_access_serializes_each_device_and_recovers_without_replay() {
        const DEVICES: usize = 8;
        const COMMANDS_PER_DEVICE: u64 = 256;

        let registry = DeviceRegistry::new();
        let barrier = Arc::new(Barrier::new(DEVICES));
        let global_active = Arc::new(AtomicUsize::new(0));
        let global_maximum = Arc::new(AtomicUsize::new(0));
        let worker_threads = Arc::new(StdMutex::new(HashSet::new()));
        let mut entries = Vec::new();
        let mut probes = Vec::new();

        for device in 0..DEVICES {
            let probe = Arc::new(StressProbe {
                executions: StdMutex::new(HashMap::new()),
                active: AtomicUsize::new(0),
                maximum: AtomicUsize::new(0),
                first_command: AtomicBool::new(true),
                first_command_barrier: barrier.clone(),
                global_active: global_active.clone(),
                global_maximum: global_maximum.clone(),
                worker_threads: worker_threads.clone(),
                opens: AtomicUsize::new(0),
            });
            let transport = RecoverableCommandTransport::new(
                Box::new(StressConnectedTransport {
                    probe: probe.clone(),
                }),
                Box::new(StressFactory {
                    probe: probe.clone(),
                }),
            );
            let serial = format!("{device:08}");
            registry.insert_test(&serial, Box::new(transport)).await;
            entries.push(registry.get(&serial).await.unwrap());
            probes.push(probe);
        }

        let mut tasks = tokio::task::JoinSet::new();
        for (device, entry) in entries.iter().enumerate() {
            for command in 0..COMMANDS_PER_DEVICE {
                let entry = entry.clone();
                let request_id = (device as u64) << 32 | command;
                tasks.spawn(async move {
                    let request = request_id.to_be_bytes();
                    (request_id, entry.command(&request).await.0)
                });
            }
        }

        let mut failures = [0_usize; DEVICES];
        while let Some(result) = tasks.join_next().await {
            let (request_id, result) = result.unwrap();
            let device = (request_id >> 32) as usize;
            if request_id % 29 == 0 {
                assert!(result.is_err());
                failures[device] += 1;
            } else {
                assert_eq!(result.unwrap(), request_id.to_be_bytes());
            }
        }

        // Ensure a failure that happened to execute last also gets a later
        // request, so every invalidated transport must pass through reopen.
        for (device, entry) in entries.iter().enumerate() {
            let mut sentinel = u64::MAX - device as u64;
            while sentinel.is_multiple_of(29) {
                sentinel -= DEVICES as u64;
            }
            assert_eq!(
                entry.command(&sentinel.to_be_bytes()).await.0.unwrap(),
                sentinel.to_be_bytes()
            );
        }

        assert_eq!(global_active.load(Ordering::SeqCst), 0);
        assert_eq!(global_maximum.load(Ordering::SeqCst), DEVICES);
        assert!(worker_threads.lock().unwrap().len() > 1);
        for (device, probe) in probes.iter().enumerate() {
            assert_eq!(probe.active.load(Ordering::SeqCst), 0);
            assert_eq!(probe.maximum.load(Ordering::SeqCst), 1);
            assert_eq!(probe.opens.load(Ordering::SeqCst), failures[device]);
            let executions = probe.executions.lock().unwrap();
            assert_eq!(executions.len(), COMMANDS_PER_DEVICE as usize + 1);
            assert!(executions.values().all(|count| *count == 1));
        }
    }
}
