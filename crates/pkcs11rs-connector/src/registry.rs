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
    fn device(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::DeviceTransport,
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

trait ConnectedCommandTransport: Send {
    fn command<'a>(
        &'a mut self,
        request: &'a [u8],
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
        request: &'a [u8],
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
    timeout: Duration,
}

impl ConnectedCommandTransport for UsbConnectedTransport {
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

struct UsbTransportFactory {
    id: UsbDeviceId,
    serial: String,
    timeout: Duration,
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
                Ok(Box::new(UsbConnectedTransport {
                    device,
                    timeout: self.timeout,
                }) as Box<dyn ConnectedCommandTransport>)
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
            transport: Mutex::new(Box::new(RecoverableCommandTransport::new(
                Box::new(UsbConnectedTransport {
                    device,
                    timeout: self.command_timeout,
                }),
                Box::new(UsbTransportFactory {
                    id,
                    serial: serial.clone(),
                    timeout: self.command_timeout,
                }),
            ))),
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
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex as StdMutex,
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
            request: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(request.to_vec());
                match self.outcomes.pop_front().flatten() {
                    Some(error) => Err(error),
                    None => Ok(request.to_vec()),
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

        assert!(transport.command(b"uncertain").await.is_err());
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(transport.command(b"next").await.unwrap(), b"next");
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

        assert!(transport.command(b"uncertain").await.is_err());
        assert!(transport.command(b"reopen fails").await.is_err());
        assert_eq!(transport.command(b"later").await.unwrap(), b"later");
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

        assert!(transport.command(b"invalid").await.is_err());
        assert_eq!(transport.command(b"valid").await.unwrap(), b"valid");
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![b"invalid".to_vec(), b"valid".to_vec()]
        );
    }

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
            request: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let id = u64::from_be_bytes(request.try_into().unwrap());
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
                    Ok(request.to_vec())
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

        let registry = DeviceRegistry::new(Duration::from_secs(1));
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
            while sentinel % 29 == 0 {
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
