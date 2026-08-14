#[cfg(test)]
use crate::connector::Connector;
use crate::{CKR_MUTEX_BAD, Error};
use std::sync::{Arc, Mutex, RwLock};

pub(crate) trait DeviceOperationLifecycle: Send + Sync + std::fmt::Debug {
    fn enter(&self, kind: DeviceOperationKind, message: &str) -> Result<(), Error>;
    fn exit(&self, kind: DeviceOperationKind);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceIdentity {
    pub(crate) manufacturer: String,
    pub(crate) product: String,
    pub(crate) serial: String,
    pub(crate) hardware_version: Option<(u8, u8)>,
    pub(crate) firmware_version: Option<(u8, u8, u8)>,
}

impl DeviceIdentity {
    pub(crate) fn unknown(manufacturer: impl Into<String>, product: impl Into<String>) -> Self {
        Self {
            manufacturer: manufacturer.into(),
            product: product.into(),
            serial: String::from("0"),
            hardware_version: None,
            firmware_version: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_endpoint(connector: &dyn Connector) -> Self {
        Self {
            manufacturer: connector.manufacturer().to_owned(),
            product: connector.product().to_owned(),
            serial: String::from("0"),
            hardware_version: connector.hardware_version(),
            firmware_version: connector.firmware_version(),
        }
    }

    pub(crate) fn physical_key(&self) -> Option<PhysicalDeviceKey> {
        let serial = self.serial.trim_start_matches('0');
        (self.manufacturer == "Yubico" && !serial.is_empty())
            .then(|| PhysicalDeviceKey::YubicoSerial(serial.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PhysicalDeviceKey {
    YubicoSerial(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceOperationKind {
    Hid,
    Ccid,
}

#[derive(Debug)]
pub(crate) struct DeviceContext {
    fallback: DeviceIdentity,
    discovered: Mutex<Option<(u64, DeviceIdentity)>>,
    operation: RwLock<()>,
    lifecycle: Option<Arc<dyn DeviceOperationLifecycle>>,
}

impl DeviceContext {
    pub(crate) fn new(fallback: DeviceIdentity) -> Self {
        Self {
            fallback,
            discovered: Mutex::new(None),
            operation: RwLock::new(()),
            lifecycle: None,
        }
    }

    pub(crate) fn with_lifecycle(
        fallback: DeviceIdentity,
        lifecycle: Arc<dyn DeviceOperationLifecycle>,
    ) -> Self {
        Self {
            fallback,
            discovered: Mutex::new(None),
            operation: RwLock::new(()),
            lifecycle: Some(lifecycle),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_endpoint(connector: &dyn Connector) -> Self {
        Self::new(DeviceIdentity::from_endpoint(connector))
    }

    pub(crate) fn identity(&self, connection_epoch: u64) -> DeviceIdentity {
        self.discovered
            .lock()
            .ok()
            .and_then(|identity| {
                identity
                    .as_ref()
                    .filter(|(epoch, _)| *epoch == connection_epoch)
                    .map(|(_, identity)| identity.clone())
            })
            .unwrap_or_else(|| self.fallback.clone())
    }

    pub(crate) fn replace(
        &self,
        connection_epoch: u64,
        identity: DeviceIdentity,
    ) -> Result<(), Error> {
        *self.discovered.lock().map_err(|_| CKR_MUTEX_BAD)? = Some((connection_epoch, identity));
        Ok(())
    }

    pub(crate) fn lock_operation(
        &self,
        kind: DeviceOperationKind,
    ) -> Result<DeviceOperationGuard<'_>, Error> {
        self.lock_operation_with_message(kind, crate::logging::current_operation_message())
    }

    pub(crate) fn lock_operation_with_message(
        &self,
        kind: DeviceOperationKind,
        message: &str,
    ) -> Result<DeviceOperationGuard<'_>, Error> {
        let guard = match kind {
            DeviceOperationKind::Hid => self
                .operation
                .read()
                .map(|guard| DeviceLockGuard::Hid { _guard: guard })
                .map_err(|_| Error::from(CKR_MUTEX_BAD)),
            DeviceOperationKind::Ccid => self
                .operation
                .write()
                .map(|guard| DeviceLockGuard::Ccid { _guard: guard })
                .map_err(|_| Error::from(CKR_MUTEX_BAD)),
        }?;
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.enter(kind, message)?;
        }
        Ok(DeviceOperationGuard {
            _guard: guard,
            lifecycle: self.lifecycle.as_deref(),
            kind,
        })
    }

    #[cfg(test)]
    pub(crate) fn test() -> Self {
        Self::new(DeviceIdentity::unknown("Test", "Test"))
    }
}

enum DeviceLockGuard<'a> {
    Hid {
        _guard: std::sync::RwLockReadGuard<'a, ()>,
    },
    Ccid {
        _guard: std::sync::RwLockWriteGuard<'a, ()>,
    },
}

pub(crate) struct DeviceOperationGuard<'a> {
    _guard: DeviceLockGuard<'a>,
    lifecycle: Option<&'a dyn DeviceOperationLifecycle>,
    kind: DeviceOperationKind,
}

impl Drop for DeviceOperationGuard<'_> {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle {
            lifecycle.exit(self.kind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(serial: &str) -> DeviceIdentity {
        DeviceIdentity {
            manufacturer: String::from("Yubico"),
            product: String::from("YubiKey"),
            serial: serial.to_owned(),
            hardware_version: None,
            firmware_version: None,
        }
    }

    #[test]
    fn discovered_identity_is_scoped_to_connection_epoch() {
        let context = DeviceContext::new(identity("0"));
        context.replace(7, identity("12345678")).unwrap();
        assert_eq!(context.identity(7).serial, "12345678");
        assert_eq!(context.identity(8).serial, "0");
    }

    #[test]
    fn physical_key_requires_a_real_yubico_serial() {
        assert_eq!(
            identity("001234").physical_key(),
            Some(PhysicalDeviceKey::YubicoSerial(String::from("1234")))
        );
        assert_eq!(identity("0").physical_key(), None);
        assert_eq!(identity("0000").physical_key(), None);
        let mut generic = identity("1234");
        generic.manufacturer = String::from("Other");
        assert_eq!(generic.physical_key(), None);
    }
}
