use crate::{
    VirtualPersistence, VirtualYubiHsmSpec,
    registry::{CommandTransport, DeviceRegistry, TransportError},
};
use futures_util::future::BoxFuture;
use std::{
    collections::HashSet,
    fs::{self, DirBuilder},
    io,
    os::unix::fs::DirBuilderExt,
    path::Path,
    thread,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use usb_gadget_worker::{
    PersistenceMode, StateLock, StatePersistence, StatePersistenceHandle, replace_file_atomically,
};
use virtual_yubihsm_core::{Device, DeviceConfig};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ACTOR_CHANNEL_CAPACITY: usize = 1;

enum ActorRequest {
    Command {
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, TransportError>>,
    },
    Shutdown,
}

struct VirtualTransport {
    requests: mpsc::Sender<ActorRequest>,
}

impl CommandTransport for VirtualTransport {
    fn command<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let (reply, response) = oneshot::channel();
            self.requests
                .send(ActorRequest::Command {
                    bytes: request.to_vec(),
                    reply,
                })
                .await
                .map_err(|_| TransportError::device("embedded YubiHSM actor stopped"))?;
            response
                .await
                .map_err(|_| TransportError::device("embedded YubiHSM actor stopped"))?
        })
    }
}

struct ActorController {
    requests: mpsc::Sender<ActorRequest>,
    thread: thread::JoinHandle<io::Result<()>>,
}

impl ActorController {
    async fn start(
        spec: VirtualYubiHsmSpec,
        persistence: PersistenceMode,
    ) -> io::Result<(Self, VirtualTransport, [u8; 3])> {
        let (requests, receiver) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        let transport = VirtualTransport {
            requests: requests.clone(),
        };
        let (ready, readiness) = oneshot::channel();
        let name = format!("virtual-yubihsm-{}", spec.serial);
        let actor_thread = thread::Builder::new()
            .name(name)
            .spawn(move || actor_main(spec, persistence, receiver, ready))?;
        match readiness.await {
            Ok(Ok(version)) => Ok((
                Self {
                    requests,
                    thread: actor_thread,
                },
                transport,
                version,
            )),
            Ok(Err(error)) => {
                let _ = join_actor(actor_thread).await;
                Err(error)
            }
            Err(_) => join_actor(actor_thread).await.and_then(|_| {
                Err(io::Error::other(
                    "embedded YubiHSM actor stopped during startup",
                ))
            }),
        }
    }

    async fn shutdown(self) -> io::Result<()> {
        let _ = self.requests.send(ActorRequest::Shutdown).await;
        join_actor(self.thread).await
    }
}

pub(crate) struct VirtualHsmActors {
    actors: Vec<ActorController>,
}

impl VirtualHsmActors {
    pub(crate) async fn start(
        registry: &DeviceRegistry,
        specs: &[VirtualYubiHsmSpec],
        persistence: VirtualPersistence,
        batch_delay: Duration,
    ) -> Result<Self, BoxError> {
        validate_specs(specs)?;
        let persistence = match persistence {
            VirtualPersistence::Batched => {
                if batch_delay.is_zero() {
                    return Err("--virtual-yubihsm-batch-delay-ms must be greater than zero".into());
                }
                PersistenceMode::Batched(batch_delay)
            }
            VirtualPersistence::Immediate => PersistenceMode::Immediate,
        };
        let mut actors = Self { actors: Vec::new() };
        for spec in specs {
            let (actor, transport, version) =
                match ActorController::start(spec.clone(), persistence).await {
                    Ok(started) => started,
                    Err(error) => {
                        let _ = actors.shutdown().await;
                        return Err(error.into());
                    }
                };
            if let Err(error) = registry
                .register_virtual(spec.serial.to_string(), version, Box::new(transport))
                .await
            {
                let _ = actor.shutdown().await;
                let _ = actors.shutdown().await;
                return Err(error.into());
            }
            tracing::info!(
                serial = spec.serial,
                state_directory = %spec.state_directory.display(),
                ?persistence,
                "embedded virtual YubiHSM started"
            );
            actors.actors.push(actor);
        }
        Ok(actors)
    }

    pub(crate) async fn shutdown(mut self) -> io::Result<()> {
        let mut first_error = None;
        while let Some(actor) = self.actors.pop() {
            if let Err(error) = actor.shutdown().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn validate_specs(specs: &[VirtualYubiHsmSpec]) -> Result<(), BoxError> {
    let mut serials = HashSet::new();
    let mut state_directories = HashSet::new();
    for spec in specs {
        if !spec.state_directory.is_absolute() {
            return Err(format!(
                "embedded YubiHSM {} state directory must be absolute: {}",
                spec.serial,
                spec.state_directory.display()
            )
            .into());
        }
        if !serials.insert(spec.serial) {
            return Err(format!("duplicate embedded YubiHSM serial {}", spec.serial).into());
        }
        if !state_directories.insert(spec.state_directory.clone()) {
            return Err(format!(
                "duplicate embedded YubiHSM state directory {}",
                spec.state_directory.display()
            )
            .into());
        }
    }
    Ok(())
}

fn actor_main(
    spec: VirtualYubiHsmSpec,
    persistence_mode: PersistenceMode,
    mut requests: mpsc::Receiver<ActorRequest>,
    ready: oneshot::Sender<io::Result<[u8; 3]>>,
) -> io::Result<()> {
    let serial = spec.serial;
    match initialize(&spec, persistence_mode) {
        Ok((persistence, state_lock, version)) => {
            let _ = ready.send(Ok(version));
            run_actor(serial, persistence, state_lock, &mut requests)
        }
        Err(error) => {
            let reported = io::Error::new(error.kind(), error.to_string());
            let _ = ready.send(Err(error));
            Err(reported)
        }
    }
}

fn initialize(
    spec: &VirtualYubiHsmSpec,
    persistence_mode: PersistenceMode,
) -> io::Result<(StatePersistence<Device>, StateLock, [u8; 3])> {
    create_state_directory(&spec.state_directory)?;
    let state_path = spec
        .state_directory
        .join(format!("yubihsm-{}.cbor", spec.serial));
    let state_lock = StateLock::acquire(
        spec.state_directory
            .join(format!("yubihsm-{}.lock", spec.serial)),
    )?;
    let config = DeviceConfig {
        serial: spec.serial,
        ..DeviceConfig::default()
    };
    let version = config.version;
    let device = load_or_create_state(config, &state_path)?;
    let serial = spec.serial;
    let persistence = StatePersistence::start(
        device,
        state_path,
        persistence_mode,
        encode_device_state,
        move || tracing::error!(serial, "embedded YubiHSM persistence failed"),
    )?;
    Ok((persistence, state_lock, version))
}

fn run_actor(
    serial: u32,
    persistence: StatePersistence<Device>,
    _state_lock: StateLock,
    requests: &mut mpsc::Receiver<ActorRequest>,
) -> io::Result<()> {
    let handle = persistence.handle();
    while let Some(request) = requests.blocking_recv() {
        match request {
            ActorRequest::Command { bytes, reply } => {
                let result = execute_command(&handle, &bytes);
                let _ = reply.send(result);
            }
            ActorRequest::Shutdown => {
                clear_sessions(&handle);
                let result = persistence.shutdown();
                tracing::info!(serial, "embedded virtual YubiHSM stopped");
                return result;
            }
        }
    }
    clear_sessions(&handle);
    persistence.shutdown()
}

fn execute_command(
    handle: &StatePersistenceHandle<Device>,
    request: &[u8],
) -> Result<Vec<u8>, TransportError> {
    handle
        .check_health()
        .map_err(|error| TransportError::device(error.to_string()))?;
    let (response, mutation) = {
        let mut device = handle
            .state()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let response = device.handle_encoded(request);
        let mutation = if device
            .take_persistent_change()
            .map_err(|error| TransportError::device(error.to_string()))?
        {
            Some(
                handle
                    .record_mutation()
                    .map_err(|error| TransportError::device(error.to_string()))?,
            )
        } else {
            None
        };
        (response, mutation)
    };
    if let Some(mutation) = mutation {
        mutation
            .wait()
            .map_err(|error| TransportError::device(error.to_string()))?;
    }
    Ok(response)
}

fn clear_sessions(handle: &StatePersistenceHandle<Device>) {
    handle
        .state()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear_sessions();
}

fn create_state_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| with_path(error, "create embedded YubiHSM state directory", path))
}

fn load_or_create_state(config: DeviceConfig, path: &Path) -> io::Result<Device> {
    match fs::read(path) {
        Ok(encoded) => Device::from_persistent_state(config, &encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("load persistent YubiHSM state {}: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let device = Device::factory_default(config);
            replace_file_atomically(path, &encode_device_state(&device)?)?;
            Ok(device)
        }
        Err(error) => Err(with_path(error, "read persistent YubiHSM state", path)),
    }
}

fn encode_device_state(device: &Device) -> io::Result<Vec<u8>> {
    device
        .persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent YubiHSM state: {error}")))
}

fn with_path(error: io::Error, operation: &str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

async fn join_actor(thread: thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        thread
            .join()
            .map_err(|_| io::Error::other("embedded YubiHSM actor panicked"))?
    })
    .await
    .map_err(|error| io::Error::other(format!("join embedded YubiHSM actor: {error}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc as std_mpsc,
        },
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pkcs11rs-connector-virtual-hsm-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn cancelled_response_does_not_stop_actor_or_reach_next_request() {
        let (requests, mut receiver) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        let mut transport = VirtualTransport { requests };
        let (first_received, first_observed) = oneshot::channel();
        let (release_first, first_released) = std_mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            let Some(ActorRequest::Command { bytes, reply }) = receiver.blocking_recv() else {
                panic!("expected first command");
            };
            assert_eq!(bytes, b"first");
            first_received.send(()).unwrap();
            first_released.recv().unwrap();
            assert!(reply.send(Ok(b"abandoned response".to_vec())).is_err());

            let Some(ActorRequest::Command { bytes, reply }) = receiver.blocking_recv() else {
                panic!("expected second command");
            };
            assert_eq!(bytes, b"second");
            reply.send(Ok(b"second response".to_vec())).unwrap();
        });

        {
            let first = transport.command(b"first");
            tokio::pin!(first);
            tokio::select! {
                response = &mut first => panic!("first command completed unexpectedly: {response:?}"),
                observed = first_observed => observed.unwrap(),
            }
        }
        release_first.send(()).unwrap();

        assert_eq!(
            transport.command(b"second").await.unwrap(),
            b"second response"
        );
        worker.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn actor_serves_the_core_and_releases_persistent_state_on_shutdown() {
        let directory = temporary_directory();
        let spec = VirtualYubiHsmSpec {
            serial: 12_345_678,
            state_directory: directory.clone(),
        };
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        let actors = VirtualHsmActors::start(
            &registry,
            std::slice::from_ref(&spec),
            VirtualPersistence::Immediate,
            Duration::from_millis(500),
        )
        .await
        .unwrap();

        let view = registry.view("12345678").await.unwrap();
        assert_eq!(view.manufacturer, "Yubico");
        assert_eq!(view.product, "YubiHSM");
        let entry = registry.get("12345678").await.unwrap();
        let response = entry.command(&[0x06, 0x00, 0x00]).await.0.unwrap();
        assert_eq!(response.first(), Some(&0x86));
        assert!(directory.join("yubihsm-12345678.cbor").exists());
        assert!(directory.join("yubihsm-12345678.lock").exists());

        actors.shutdown().await.unwrap();
        let lock = StateLock::acquire(directory.join("yubihsm-12345678.lock")).unwrap();
        drop(lock);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_actor_cannot_open_the_same_persistent_device() {
        let directory = temporary_directory();
        let spec = VirtualYubiHsmSpec {
            serial: 12_345_678,
            state_directory: directory.clone(),
        };
        let first_registry = DeviceRegistry::new(Duration::from_secs(1));
        let first = VirtualHsmActors::start(
            &first_registry,
            std::slice::from_ref(&spec),
            VirtualPersistence::Batched,
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        let second_registry = DeviceRegistry::new(Duration::from_secs(1));
        let error = match VirtualHsmActors::start(
            &second_registry,
            &[spec],
            VirtualPersistence::Batched,
            Duration::from_millis(10),
        )
        .await
        {
            Ok(_) => panic!("second actor unexpectedly acquired persistent state"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("persistent state lock"));

        first.shutdown().await.unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_actors_are_independent_registry_devices() {
        let first_directory = temporary_directory();
        let second_directory = temporary_directory();
        let specs = [
            VirtualYubiHsmSpec {
                serial: 11_111_111,
                state_directory: first_directory.clone(),
            },
            VirtualYubiHsmSpec {
                serial: 22_222_222,
                state_directory: second_directory.clone(),
            },
        ];
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        let actors = VirtualHsmActors::start(
            &registry,
            &specs,
            VirtualPersistence::Batched,
            Duration::from_millis(10),
        )
        .await
        .unwrap();

        assert_eq!(
            registry
                .list()
                .await
                .into_iter()
                .map(|device| device.serial)
                .collect::<Vec<_>>(),
            [String::from("11111111"), String::from("22222222")]
        );
        let first = registry.get("11111111").await.unwrap();
        let second = registry.get("22222222").await.unwrap();
        let (first_response, second_response) = tokio::join!(
            first.command(&[0x06, 0x00, 0x00]),
            second.command(&[0x06, 0x00, 0x00])
        );
        assert_eq!(first_response.0.unwrap().first(), Some(&0x86));
        assert_eq!(second_response.0.unwrap().first(), Some(&0x86));

        actors.shutdown().await.unwrap();
        fs::remove_dir_all(first_directory).unwrap();
        fs::remove_dir_all(second_directory).unwrap();
    }
}
