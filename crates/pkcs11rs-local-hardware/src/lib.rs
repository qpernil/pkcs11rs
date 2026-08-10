//! Host-local hardware transports shared by the PKCS #11 module and companion tools.
//!
//! This crate deliberately contains device access rather than PKCS #11 slot or
//! token policy. The PKCS #11 module uses the blocking API, while the connector
//! daemon can opt into the asynchronous API without pulling a runtime into the
//! module or its iOS build.

mod yubihsm_usb;

pub use yubihsm_usb::{
    Error, UsbDeviceId, YUBICO_VENDOR_ID, YUBIHSM_PRODUCT_ID, YubiHsmUsbCandidate,
    YubiHsmUsbDevice, ensure_complete_write, needs_zero_length_packet, usb_bcd_version,
};

#[cfg(feature = "blocking")]
pub use yubihsm_usb::yubihsm_candidates_blocking;

#[cfg(feature = "async-tokio")]
pub use yubihsm_usb::{
    YubiHsmHotplugEvent, YubiHsmHotplugWatch, watch_yubihsms, yubihsm_candidates,
};
