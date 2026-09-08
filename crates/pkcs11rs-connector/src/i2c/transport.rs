use super::{I2cYubiHsmSpec, device::YubiHsmI2cDevice};
use crate::{
    BoxError,
    registry::{
        CommandTransport, DeviceRegistry, DeviceTransportKind, TransportError, TransportErrorKind,
    },
};
use futures_util::future::BoxFuture;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

struct Connection {
    endpoint: I2cYubiHsmSpec,
    timeout: Duration,
    serial: u32,
    device: Option<YubiHsmI2cDevice>,
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
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == TransportErrorKind::DeviceTransport)
        {
            // The request may have executed. Close uncertain handles and reopen
            // only for a later command; never replay this request.
            self.device = None;
        }
        result
    }
}

struct I2cTransport(Arc<Mutex<Connection>>);

impl CommandTransport for I2cTransport {
    fn command<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        let state = self.0.clone();
        let request = request.to_vec();
        Box::pin(super::with_device(state, move |state| {
            state.command(&request)
        }))
    }
}

pub(super) async fn register(
    registry: &DeviceRegistry,
    specs: &[I2cYubiHsmSpec],
    timeout: Duration,
) -> Result<(), BoxError> {
    for spec in specs {
        let endpoint = spec.clone();
        let (device, identity) =
            tokio::task::spawn_blocking(move || YubiHsmI2cDevice::open(endpoint, timeout))
                .await??;
        if !registry.should_claim(&identity.serial.to_string()) {
            drop(device);
            registry
                .register_filtered(
                    identity.serial.to_string(),
                    Some(identity.version),
                    DeviceTransportKind::I2c,
                )
                .await?;
            continue;
        }
        registry
            .register_configured(
                identity.serial.to_string(),
                identity.version,
                DeviceTransportKind::I2c,
                Box::new(I2cTransport(Arc::new(Mutex::new(Connection {
                    endpoint: spec.clone(),
                    timeout,
                    serial: identity.serial,
                    device: Some(device),
                })))),
            )
            .await?;
        tracing::info!(serial = identity.serial, bus = %spec.bus.display(), address = spec.address,
            "experimental I2C YubiHSM registered");
    }
    Ok(())
}
