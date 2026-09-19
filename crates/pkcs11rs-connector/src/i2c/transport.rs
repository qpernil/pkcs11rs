use super::{I2cYubiHsmSpec, device::YubiHsmI2cDevice};
use crate::{
    BoxError,
    registry::{
        CommandTransport, DeviceRegistry, DeviceTransportKind, TransportError, TransportErrorKind,
    },
};
use futures_util::future::BoxFuture;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(8);

struct Connection {
    endpoint: I2cYubiHsmSpec,
    timeout: Duration,
    serial: u32,
    connection_generation: u64,
    device: Option<YubiHsmI2cDevice>,
    events: mpsc::UnboundedSender<super::I2cEvent>,
}

impl Connection {
    fn command(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.device.is_none() {
            self.device = Some(super::reopen_verified(self.serial, || {
                YubiHsmI2cDevice::open(self.endpoint.clone(), self.timeout)
                    .map(|(device, identity)| (device, identity.serial))
            })?);
        }
        let result = self
            .device
            .as_mut()
            .expect("device was opened above")
            .transmit(request);
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.kind(),
                TransportErrorKind::DeviceTransport | TransportErrorKind::EndpointUnavailable
            )
        }) {
            // The request may have executed. Close uncertain handles and reopen
            // only for a later command; never replay this request.
            self.device = None;
        }
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == TransportErrorKind::EndpointUnavailable)
        {
            let _ = self.events.send(super::I2cEvent::EndpointLost {
                spec: self.endpoint.clone(),
                serial: self.serial,
                connection_generation: self.connection_generation,
            });
        }
        result
    }
}

struct I2cTransport(Arc<Mutex<Connection>>);

impl CommandTransport for I2cTransport {
    fn command<'a>(
        &'a mut self,
        request: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        let state = self.0.clone();
        Box::pin(super::with_device(state, move |state| {
            state.command(&request)
        }))
    }
}

pub(super) async fn register(
    registry: &DeviceRegistry,
    specs: &[I2cYubiHsmSpec],
    timeout: Duration,
) -> Result<Option<tokio::task::JoinHandle<()>>, BoxError> {
    if specs.is_empty() {
        return Ok(None);
    }
    let (events, mut event_rx) = mpsc::unbounded_channel();
    let registry = registry.clone();
    let specs = specs.to_vec();
    let coordinator = tokio::spawn(async move {
        let mut pending = specs;
        let mut retry_delay = INITIAL_RETRY_DELAY;
        loop {
            let results = futures_util::future::join_all(pending.into_iter().map(|spec| {
                let events = events.clone();
                let registry = registry.clone();
                async move {
                    let result = register_one(&registry, spec.clone(), timeout, events).await;
                    (spec, result)
                }
            }))
            .await;
            pending = results
                .into_iter()
                .filter_map(|(spec, result)| match result {
                    Ok(()) => None,
                    Err(error) => {
                        tracing::warn!(bus = %spec.bus.display(), address = spec.address, %error,
                            "I2C YubiHSM registration failed; scheduling retry");
                        Some(spec)
                    }
                })
                .collect();
            while let Ok(event) = event_rx.try_recv() {
                handle_event(&registry, &mut pending, event).await;
                retry_delay = INITIAL_RETRY_DELAY;
            }
            if pending.is_empty() {
                match event_rx.recv().await {
                    Some(event) => {
                        handle_event(&registry, &mut pending, event).await;
                        retry_delay = INITIAL_RETRY_DELAY;
                        continue;
                    }
                    None => return,
                }
            }
            tokio::select! {
                event = event_rx.recv() => {
                    if let Some(event) = event {
                        handle_event(&registry, &mut pending, event).await;
                        retry_delay = INITIAL_RETRY_DELAY;
                    } else {
                        return;
                    }
                }
                _ = tokio::time::sleep(retry_delay) => {
                    retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                }
            }
        }
    });
    Ok(Some(coordinator))
}

async fn handle_event(
    registry: &DeviceRegistry,
    pending: &mut Vec<I2cYubiHsmSpec>,
    event: super::I2cEvent,
) {
    match event {
        super::I2cEvent::EndpointLost {
            spec,
            serial,
            connection_generation,
        } => {
            if registry.remove_i2c(serial, connection_generation).await && !pending.contains(&spec)
            {
                pending.push(spec);
            }
        }
    }
}

async fn register_one(
    registry: &DeviceRegistry,
    spec: I2cYubiHsmSpec,
    timeout: Duration,
    events: mpsc::UnboundedSender<super::I2cEvent>,
) -> Result<(), BoxError> {
    let endpoint = spec.clone();
    let (device, identity) =
        tokio::task::spawn_blocking(move || YubiHsmI2cDevice::open(endpoint, timeout)).await??;
    if !registry.should_claim(&identity.serial.to_string()) {
        drop(device);
        registry
            .register_filtered(
                identity.serial.to_string(),
                Some(identity.version),
                DeviceTransportKind::I2c,
            )
            .await?;
        return Ok(());
    }
    let connection_spec = spec.clone();
    registry
        .register_configured(
            identity.serial.to_string(),
            identity.version,
            DeviceTransportKind::I2c,
            move |connection_generation| {
                Box::new(I2cTransport(Arc::new(Mutex::new(Connection {
                    endpoint: connection_spec,
                    timeout,
                    serial: identity.serial,
                    connection_generation,
                    device: Some(device),
                    events,
                }))))
            },
        )
        .await?;
    tracing::info!(serial = identity.serial, bus = %spec.bus.display(), address = spec.address,
        "experimental I2C YubiHSM registered");
    Ok(())
}
