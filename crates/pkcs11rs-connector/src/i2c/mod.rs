#[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
mod device;
#[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
mod transport;

use crate::{BoxError, registry::DeviceRegistry};
use std::time::Duration;
use std::{collections::HashSet, path::PathBuf, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReadyGpioSpec {
    pub(crate) chip: PathBuf,
    pub(crate) offset: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct I2cYubiHsmSpec {
    pub(crate) bus: PathBuf,
    pub(crate) address: u16,
    pub(crate) ready: ReadyGpioSpec,
}

impl FromStr for I2cYubiHsmSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (bus, endpoint) = value.rsplit_once('@').ok_or_else(|| {
            String::from("expected BUS@ADDRESS=GPIOCHIP:OFFSET for an I2C YubiHSM")
        })?;
        if bus.is_empty() {
            return Err(String::from("I2C bus path must not be empty"));
        }
        let (address, ready) = endpoint.split_once('=').ok_or_else(|| {
            String::from("I2C YubiHSM requires READY: BUS@ADDRESS=GPIOCHIP:OFFSET")
        })?;
        let address = address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
            .map_or_else(
                || address.parse::<u16>(),
                |hexadecimal| u16::from_str_radix(hexadecimal, 16),
            )
            .map_err(|_| format!("invalid I2C address {address:?}"))?;
        if !(0x08..=0x77).contains(&address) {
            return Err(format!(
                "I2C address 0x{address:02x} is outside the non-reserved 7-bit range 0x08..=0x77"
            ));
        }
        let (chip, offset) = ready.rsplit_once(':').ok_or_else(|| {
            String::from("expected GPIOCHIP:OFFSET after the I2C READY separator")
        })?;
        if chip.is_empty() {
            return Err(String::from("READY GPIO chip path must not be empty"));
        }
        let ready = ReadyGpioSpec {
            chip: PathBuf::from(chip),
            offset: offset
                .parse::<u32>()
                .map_err(|_| format!("invalid READY GPIO offset {offset:?}"))?,
        };
        Ok(Self {
            bus: PathBuf::from(bus),
            address,
            ready,
        })
    }
}

pub(crate) async fn register(
    registry: &DeviceRegistry,
    specs: &[I2cYubiHsmSpec],
    timeout: Duration,
) -> Result<(), BoxError> {
    #[cfg(all(feature = "experimental-i2c", target_os = "linux"))]
    {
        transport::register(registry, specs, timeout).await
    }
    #[cfg(not(all(feature = "experimental-i2c", target_os = "linux")))]
    {
        let _ = (registry, timeout);
        if !specs.is_empty() {
            return Err(
                "I2C YubiHSM transport requires a Linux build with --features experimental-i2c"
                    .into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn validate(specs: &[I2cYubiHsmSpec]) -> Result<(), BoxError> {
    let mut endpoint_ids = HashSet::<(PathBuf, u16)>::new();
    let mut ready_lines = HashSet::<(PathBuf, u32)>::new();
    for spec in specs {
        if !spec.bus.is_absolute() || !spec.ready.chip.is_absolute() {
            return Err("I2C bus and READY GPIO chip paths must be absolute".into());
        }
        if !endpoint_ids.insert((spec.bus.clone(), spec.address)) {
            return Err(format!(
                "duplicate I2C YubiHSM endpoint {}@0x{:02x}",
                spec.bus.display(),
                spec.address
            )
            .into());
        }
        let ready = &spec.ready;
        if !ready_lines.insert((ready.chip.clone(), ready.offset)) {
            return Err(format!(
                "duplicate I2C READY line {}:{}",
                ready.chip.display(),
                ready.offset
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(any(test, all(feature = "experimental-i2c", target_os = "linux")))]
fn reopen_verified<D>(
    serial: u32,
    open: impl FnOnce() -> Result<(D, u32), crate::registry::TransportError>,
) -> Result<D, crate::registry::TransportError> {
    let (device, discovered_serial) = open()?;
    if discovered_serial != serial {
        return Err(crate::registry::TransportError::device(format!(
            "I2C endpoint changed serial from {serial} to {}",
            discovered_serial
        )));
    }
    Ok(device)
}

#[cfg(any(test, all(feature = "experimental-i2c", target_os = "linux")))]
async fn with_device<T: Send + 'static, R: Send + 'static>(
    device: std::sync::Arc<tokio::sync::Mutex<T>>,
    command: impl FnOnce(&mut T) -> Result<R, crate::registry::TransportError> + Send + 'static,
) -> Result<R, crate::registry::TransportError> {
    let mut device = device.lock_owned().await;
    // The blocking task owns the guard even if its HTTP waiter is cancelled.
    tokio::task::spawn_blocking(move || command(&mut device))
        .await
        .map_err(|error| {
            crate::registry::TransportError::device(format!("I2C blocking task: {error}"))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Args, hardware_discovery_enabled,
        registry::{TransportError, TransportErrorKind},
        validate_args,
    };
    use clap::Parser;

    #[tokio::test]
    async fn cancelled_waiter_does_not_overlap_or_replay_device_work() {
        use std::sync::{Arc, mpsc};
        use tokio::sync::Mutex;
        let device = Arc::new(Mutex::new(0));
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, wait) = mpsc::channel();
        let first = tokio::spawn(with_device(device.clone(), move |count| {
            *count += 1;
            started.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(())
        }));
        start.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(
            device.try_lock().is_err(),
            "the cancelled HTTP waiter must not release the device"
        );
        let second = tokio::spawn(with_device(device.clone(), |count| {
            assert_eq!(*count, 1, "the first request must execute exactly once");
            *count += 1;
            Ok(())
        }));
        release.send(()).unwrap();
        second.await.unwrap().unwrap();
        assert_eq!(*device.lock().await, 2);
    }

    #[test]
    fn reconnect_releases_replacement_and_accepts_returning_device() {
        use std::{cell::Cell, rc::Rc};

        struct Device(Rc<Cell<bool>>);
        impl Drop for Device {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let released = Rc::new(Cell::new(false));
        let result = reopen_verified(24, || Ok((Device(released.clone()), 25)));
        assert!(
            released.get(),
            "a rejected device must release its bus and READY handles"
        );
        let error = result
            .err()
            .expect("a replacement must not receive routed commands");
        assert_eq!(error.kind(), TransportErrorKind::DeviceTransport);
        assert!(error.to_string().contains("changed serial from 24 to 25"));

        released.set(false);
        let device = reopen_verified(24, || Ok((Device(released.clone()), 24)))
            .expect("the original serial may return after a rejected replacement");
        assert!(!released.get());
        drop(device);
        assert!(released.get());
    }

    #[test]
    fn reconnect_propagates_identity_probe_failure() {
        let result = reopen_verified::<()>(24, || {
            Err(TransportError::device(String::from("invalid DeviceInfo")))
        });
        let error = result.unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::DeviceTransport);
        assert_eq!(error.to_string(), "invalid DeviceInfo");
    }
    #[test]
    fn rejects_duplicate_endpoints_and_ready_lines() {
        let endpoint = I2cYubiHsmSpec {
            bus: PathBuf::from("/dev/i2c-1"),
            address: 0x24,
            ready: ReadyGpioSpec {
                chip: PathBuf::from("/dev/gpiochip0"),
                offset: 23,
            },
        };
        assert!(validate(&[endpoint.clone(), endpoint]).is_err());

        let second_endpoint = I2cYubiHsmSpec {
            bus: PathBuf::from("/dev/i2c-1"),
            address: 0x25,
            ready: ReadyGpioSpec {
                chip: PathBuf::from("/dev/gpiochip0"),
                offset: 23,
            },
        };
        let first_endpoint = I2cYubiHsmSpec {
            bus: PathBuf::from("/dev/i2c-1"),
            address: 0x24,
            ready: second_endpoint.ready.clone(),
        };
        assert!(validate(&[first_endpoint, second_endpoint]).is_err());
    }
    #[test]
    fn rejects_endpoints_without_ready() {
        assert!("/dev/i2c-1@0x24".parse::<I2cYubiHsmSpec>().is_err());
    }

    #[test]
    fn parses_manually_configured_i2c_hsms() {
        let bus = if cfg!(windows) {
            r"C:\dev\i2c-1"
        } else {
            "/dev/i2c-1"
        };
        let ready_chip = if cfg!(windows) {
            r"C:\dev\gpiochip0"
        } else {
            "/dev/gpiochip0"
        };
        let args = Args::try_parse_from([
            String::from("pkcs11rs-connector"),
            String::from("--hardware-discovery"),
            String::from("false"),
            String::from("--i2c-yubihsm"),
            format!("{bus}@0x24={ready_chip}:23"),
            String::from("--i2c-yubihsm"),
            format!("{bus}@37={ready_chip}:22"),
        ])
        .unwrap();
        assert!(!args.hardware_discovery);
        assert_eq!(
            args.i2c_yubihsms,
            vec![
                I2cYubiHsmSpec {
                    bus: PathBuf::from(bus),
                    address: 0x24,
                    ready: ReadyGpioSpec {
                        chip: PathBuf::from(ready_chip),
                        offset: 23,
                    },
                },
                I2cYubiHsmSpec {
                    bus: PathBuf::from(bus),
                    address: 0x25,
                    ready: ReadyGpioSpec {
                        chip: PathBuf::from(ready_chip),
                        offset: 22
                    },
                },
            ]
        );
        validate_args(&args).unwrap();
        assert!(!hardware_discovery_enabled(&args));
    }

    #[cfg(not(all(feature = "experimental-i2c", target_os = "linux")))]
    #[tokio::test]
    async fn unavailable_i2c_requires_explicit_build_support() {
        let args = Args::try_parse_from([
            "pkcs11rs-connector",
            "--i2c-yubihsm",
            "/dev/i2c-1@0x24=/dev/gpiochip0:23",
        ])
        .unwrap();
        let registry = DeviceRegistry::new(Duration::from_secs(60));
        let error = register(&registry, &args.i2c_yubihsms, Duration::from_secs(60))
            .await
            .expect_err("an unavailable experimental transport must fail at startup");
        assert!(error.to_string().contains("experimental-i2c"));
    }
}
