use futures_util::future::BoxFuture;
use pkcs11rs_local_hardware::{
    UsbDeviceId, YubiHsmHotplugEvent, YubiHsmUsbCandidate, YubiHsmUsbDevice,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Available,
    Unclaimed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceView {
    pub serial: String,
    pub manufacturer: String,
    pub product: String,
    pub usb_version: String,
    pub status: DeviceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceMetadata {
    serial: String,
    manufacturer: String,
    product: String,
    usb_version: String,
}

impl DeviceMetadata {
    fn view(&self, status: DeviceStatus) -> DeviceView {
        DeviceView {
            serial: self.serial.clone(),
            manufacturer: self.manufacturer.clone(),
            product: self.product.clone(),
            usb_version: self.usb_version.clone(),
            status,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    InvalidCommandFrame,
    CommandTooLarge,
    DeviceTransport,
}

#[derive(Clone, Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        match self.kind {
            TransportErrorKind::InvalidCommandFrame => "invalid_command_frame",
            TransportErrorKind::CommandTooLarge => "command_too_large",
            TransportErrorKind::DeviceTransport => "device_transport_error",
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

trait CommandTransport: Send {
    fn command<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

struct UsbTransport {
    device: YubiHsmUsbDevice,
    timeout: Duration,
}

impl CommandTransport for UsbTransport {
    fn command<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let mut response = vec![0; self.device.buffer_size()];
            let received = self
                .device
                .transmit(request, &mut response, self.timeout)
                .await
                .map_err(TransportError::from)?;
            let length = received.len();
            response.truncate(length);
            Ok(response)
        })
    }
}

pub struct DeviceEntry {
    id: Option<UsbDeviceId>,
    metadata: DeviceMetadata,
    transport: Mutex<Box<dyn CommandTransport>>,
}

impl DeviceEntry {
    pub fn view(&self) -> DeviceView {
        self.metadata.view(DeviceStatus::Available)
    }

    pub fn usb_device_id(&self) -> Option<String> {
        self.id.map(|id| format!("{id:?}"))
    }

    pub async fn command(&self, request: &[u8]) -> (Result<Vec<u8>, TransportError>, Duration) {
        let mut transport = self.transport.lock().await;
        let started_at = Instant::now();
        let result = transport.command(request).await;
        (result, started_at.elapsed())
    }
}

enum DeviceRecord {
    Available(Arc<DeviceEntry>),
    Unclaimed(DeviceMetadata),
}

impl DeviceRecord {
    fn metadata(&self) -> &DeviceMetadata {
        match self {
            Self::Available(entry) => &entry.metadata,
            Self::Unclaimed(metadata) => metadata,
        }
    }

    fn view(&self) -> DeviceView {
        match self {
            Self::Available(entry) => entry.view(),
            Self::Unclaimed(metadata) => metadata.view(DeviceStatus::Unclaimed),
        }
    }

    fn available(&self) -> Option<&Arc<DeviceEntry>> {
        match self {
            Self::Available(entry) => Some(entry),
            Self::Unclaimed(_) => None,
        }
    }
}

#[derive(Default)]
struct RegistryState {
    records: HashMap<String, DeviceRecord>,
    serial_by_id: HashMap<UsbDeviceId, String>,
    legacy_serial: Option<String>,
}

#[derive(Clone)]
pub struct DeviceRegistry {
    state: Arc<RwLock<RegistryState>>,
    command_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySelectionError {
    NoDevice,
}

impl DeviceRegistry {
    pub fn new(command_timeout: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(RegistryState::default())),
            command_timeout,
        }
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
            .and_then(DeviceRecord::available)
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
                .and_then(DeviceRecord::available)
                .cloned()
                .ok_or(LegacySelectionError::NoDevice);
        }
        state
            .legacy_serial
            .as_deref()
            .and_then(|serial| state.records.get(serial))
            .and_then(DeviceRecord::available)
            .cloned()
            .ok_or(LegacySelectionError::NoDevice)
    }

    async fn contains_id(&self, id: UsbDeviceId) -> bool {
        self.state.read().await.serial_by_id.contains_key(&id)
    }

    async fn register(&self, id: UsbDeviceId, record: DeviceRecord) -> bool {
        let serial = record.metadata().serial.clone();
        let mut state = self.state.write().await;
        if state.records.contains_key(&serial) {
            tracing::error!(%serial, ?id, "duplicate YubiHSM serial");
            return false;
        }
        state.serial_by_id.insert(id, serial.clone());
        if record.available().is_some() && state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.clone());
        }
        state.records.insert(serial, record);
        true
    }

    async fn register_unclaimed(&self, id: UsbDeviceId, metadata: DeviceMetadata) {
        self.register(id, DeviceRecord::Unclaimed(metadata)).await;
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
        let entry = Arc::new(DeviceEntry {
            id: Some(id),
            metadata,
            transport: Mutex::new(Box::new(UsbTransport {
                device,
                timeout: self.command_timeout,
            })),
        });
        if self.register(id, DeviceRecord::Available(entry)).await {
            tracing::info!(%serial, ?id, "YubiHSM attached");
        }
    }

    async fn detach(&self, id: UsbDeviceId) {
        let mut state = self.state.write().await;
        let Some(serial) = state.serial_by_id.remove(&id) else {
            return;
        };
        let managed = state
            .records
            .get(&serial)
            .and_then(DeviceRecord::available)
            .is_some_and(|entry| entry.id == Some(id));
        state.records.remove(&serial);
        tracing::info!(%serial, ?id, managed, "YubiHSM detached");
    }

    #[cfg(test)]
    async fn insert_test(&self, serial: &str, transport: Box<dyn CommandTransport>) {
        let entry = Arc::new(DeviceEntry {
            id: None,
            metadata: DeviceMetadata {
                serial: serial.to_owned(),
                manufacturer: String::from("Test"),
                product: String::from("YubiHSM"),
                usb_version: String::from("2.0"),
            },
            transport: Mutex::new(transport),
        });
        let mut state = self.state.write().await;
        if state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.to_owned());
        }
        state
            .records
            .insert(serial.to_owned(), DeviceRecord::Available(entry));
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_unclaimed(&self, serial: &str) {
        self.state.write().await.records.insert(
            serial.to_owned(),
            DeviceRecord::Unclaimed(DeviceMetadata {
                serial: serial.to_owned(),
                manufacturer: String::from("Test"),
                product: String::from("YubiHSM"),
                usb_version: String::from("2.0"),
            }),
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
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Ok(request.to_vec()) })
    }
}

#[cfg(test)]
struct FixedTransport(&'static [u8]);

#[cfg(test)]
impl CommandTransport for FixedTransport {
    fn command<'a>(
        &'a mut self,
        _request: &'a [u8],
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
        _request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Err(self.0.clone()) })
    }
}

pub async fn spawn_discovery(
    registry: DeviceRegistry,
) -> Result<tokio::task::JoinHandle<()>, BoxError> {
    // Start watching before the initial list so no attachment can be missed in
    // the interval between enumeration and hot-plug subscription.
    let mut watch = pkcs11rs_local_hardware::watch_yubihsms()?;
    for candidate in pkcs11rs_local_hardware::yubihsm_candidates().await? {
        registry.attach_candidate(candidate).await;
    }
    Ok(tokio::spawn(async move {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn legacy_selection_latches_the_first_serial_and_allows_an_override() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
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

    struct ConcurrencyProbe {
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }

    impl CommandTransport for ConcurrencyProbe {
        fn command<'a>(
            &'a mut self,
            request: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                Ok(request.to_vec())
            })
        }
    }

    #[tokio::test]
    async fn one_device_executes_only_one_command_at_a_time() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
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
}
