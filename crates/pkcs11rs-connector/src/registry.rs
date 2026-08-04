use futures_util::future::BoxFuture;
use pkcs11rs_local_hardware::{
    UsbDeviceId, YubiHsmHotplugEvent, YubiHsmUsbCandidate, YubiHsmUsbDevice,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceView {
    pub serial: String,
    pub manufacturer: String,
    pub product: String,
    pub usb_version: String,
    pub status: &'static str,
}

#[derive(Debug)]
pub struct TransportError(String);

impl std::fmt::Display for TransportError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

trait CommandTransport: Send + Sync {
    fn command<'a>(&'a self, request: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

struct UsbTransport {
    device: Mutex<YubiHsmUsbDevice>,
    timeout: Duration,
}

impl CommandTransport for UsbTransport {
    fn command<'a>(&'a self, request: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            // The transport mutex owns the non-Sync USB handle. The registry
            // entry's access gate has already serialized commands for this HSM.
            let device = self.device.lock().await;
            let mut response = vec![0; device.buffer_size()];
            let received = device
                .transmit(request, &mut response, self.timeout)
                .await
                .map_err(|error| TransportError(error.to_string()))?;
            let length = received.len();
            response.truncate(length);
            Ok(response)
        })
    }
}

pub struct DeviceEntry {
    id: Option<UsbDeviceId>,
    view: DeviceView,
    transport: Box<dyn CommandTransport>,
    access: Mutex<()>,
}

impl DeviceEntry {
    pub fn view(&self) -> DeviceView {
        self.view.clone()
    }

    pub async fn command(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let _access = self.access.lock().await;
        self.transport.command(request).await
    }
}

#[derive(Default)]
struct RegistryState {
    devices: HashMap<String, Arc<DeviceEntry>>,
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
            .devices
            .values()
            .map(|entry| entry.view())
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| left.serial.cmp(&right.serial));
        devices
    }

    pub async fn get(&self, serial: &str) -> Option<Arc<DeviceEntry>> {
        self.state.read().await.devices.get(serial).cloned()
    }

    pub async fn select_legacy(
        &self,
        configured_serial: Option<&str>,
    ) -> Result<Arc<DeviceEntry>, LegacySelectionError> {
        let state = self.state.read().await;
        if let Some(serial) = configured_serial {
            return state
                .devices
                .get(serial)
                .cloned()
                .ok_or(LegacySelectionError::NoDevice);
        }
        state
            .legacy_serial
            .as_deref()
            .and_then(|serial| state.devices.get(serial))
            .cloned()
            .ok_or(LegacySelectionError::NoDevice)
    }

    async fn contains_id(&self, id: UsbDeviceId) -> bool {
        self.state.read().await.serial_by_id.contains_key(&id)
    }

    async fn attach_candidate(&self, candidate: YubiHsmUsbCandidate) {
        let id = candidate.id();
        if self.contains_id(id).await {
            return;
        }
        let mut device = match candidate.open().await {
            Ok(device) => device,
            Err(error) => {
                tracing::warn!(?id, %error, "could not open YubiHSM");
                return;
            }
        };
        if let Err(error) = device.connect().await {
            tracing::warn!(?id, %error, "could not claim YubiHSM interface");
            return;
        }
        let serial = device.serial().to_owned();
        if serial.is_empty() {
            tracing::warn!(?id, "ignoring YubiHSM without a serial number");
            return;
        }
        let version = device.version();
        let view = DeviceView {
            serial: serial.clone(),
            manufacturer: device.manufacturer().to_owned(),
            product: device.product().to_owned(),
            usb_version: format!("{}.{}", version.0, version.1),
            status: "available",
        };
        let entry = Arc::new(DeviceEntry {
            id: Some(id),
            view,
            transport: Box::new(UsbTransport {
                device: Mutex::new(device),
                timeout: self.command_timeout,
            }),
            access: Mutex::new(()),
        });

        let mut state = self.state.write().await;
        if let Some(existing) = state.devices.get(&serial) {
            if existing.id != Some(id) {
                tracing::error!(%serial, ?id, existing_id = ?existing.id, "duplicate YubiHSM serial");
            }
            return;
        }
        state.serial_by_id.insert(id, serial.clone());
        if state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.clone());
        }
        state.devices.insert(serial.clone(), entry);
        tracing::info!(%serial, ?id, "YubiHSM attached");
    }

    async fn detach(&self, id: UsbDeviceId) {
        let mut state = self.state.write().await;
        let Some(serial) = state.serial_by_id.remove(&id) else {
            return;
        };
        if state
            .devices
            .get(&serial)
            .is_some_and(|entry| entry.id == Some(id))
        {
            state.devices.remove(&serial);
            tracing::info!(%serial, ?id, "YubiHSM detached");
        }
    }

    #[cfg(test)]
    async fn insert_test(&self, serial: &str, transport: Box<dyn CommandTransport>) {
        let entry = Arc::new(DeviceEntry {
            id: None,
            view: DeviceView {
                serial: serial.to_owned(),
                manufacturer: String::from("Test"),
                product: String::from("YubiHSM"),
                usb_version: String::from("2.0"),
                status: "available",
            },
            transport,
            access: Mutex::new(()),
        });
        let mut state = self.state.write().await;
        if state.legacy_serial.is_none() {
            state.legacy_serial = Some(serial.to_owned());
        }
        state.devices.insert(serial.to_owned(), entry);
    }

    #[cfg(test)]
    async fn remove_test(&self, serial: &str) {
        let mut state = self.state.write().await;
        state.devices.remove(serial);
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
}

#[cfg(test)]
struct EchoTransport;

#[cfg(test)]
impl CommandTransport for EchoTransport {
    fn command<'a>(&'a self, request: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Ok(request.to_vec()) })
    }
}

#[cfg(test)]
struct FixedTransport(&'static [u8]);

#[cfg(test)]
impl CommandTransport for FixedTransport {
    fn command<'a>(&'a self, _request: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move { Ok(self.0.to_vec()) })
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
        assert_eq!(selected.command(b"hello").await.unwrap(), b"hello");

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
            &'a self,
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
        assert_eq!(left.unwrap(), b"left");
        assert_eq!(right.unwrap(), b"right");
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }
}
