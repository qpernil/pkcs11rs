use std::cell::BorrowMutError;

use crate::{
    CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_MUTEX_BAD, CKR_OK, CK_RV,
};

#[derive(Debug)]
pub enum Error {
    Generic(CK_RV),
    #[cfg(feature = "native-hardware")]
    Hid(hidapi::HidError),
    #[cfg(feature = "native-hardware")]
    LocalHardware(pkcs11rs_local_hardware::Error),
    #[cfg(feature = "native-hardware")]
    Pcsc(pcsc::Error),
    Http(ureq::Error),
    Io(std::io::Error),
}

#[cfg(feature = "native-hardware")]
impl From<hidapi::HidError> for Error {
    fn from(e: hidapi::HidError) -> Self {
        Self::Hid(e)
    }
}

#[cfg(feature = "native-hardware")]
impl From<pkcs11rs_local_hardware::Error> for Error {
    fn from(e: pkcs11rs_local_hardware::Error) -> Self {
        Self::LocalHardware(e)
    }
}

#[cfg(feature = "native-hardware")]
impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Self::Http(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BorrowMutError> for Error {
    fn from(_e: BorrowMutError) -> Self {
        Self::Generic(CKR_MUTEX_BAD as CK_RV)
    }
}

impl From<CK_RV> for Error {
    fn from(e: CK_RV) -> Self {
        Self::Generic(e)
    }
}

#[cfg(all(not(windows), target_pointer_width = "64"))]
impl From<u32> for Error {
    fn from(e: u32) -> Self {
        Self::Generic(e as CK_RV)
    }
}

impl From<Error> for CK_RV {
    fn from(error: Error) -> Self {
        log!(2, "{:?}", error);
        match error {
            Error::Generic(rv) => rv,
            #[cfg(feature = "native-hardware")]
            Error::Hid(_) => CKR_DEVICE_ERROR as CK_RV,
            #[cfg(feature = "native-hardware")]
            Error::LocalHardware(pkcs11rs_local_hardware::Error::DeviceRemoved) => {
                CKR_DEVICE_REMOVED as CK_RV
            }
            #[cfg(feature = "native-hardware")]
            Error::LocalHardware(pkcs11rs_local_hardware::Error::SendBufferTooLarge { .. }) => {
                crate::CKR_DATA_LEN_RANGE as CK_RV
            }
            #[cfg(feature = "native-hardware")]
            Error::LocalHardware(pkcs11rs_local_hardware::Error::InvalidMessageLength {
                ..
            }) => crate::CKR_DATA_LEN_RANGE as CK_RV,
            #[cfg(feature = "native-hardware")]
            Error::LocalHardware(pkcs11rs_local_hardware::Error::ReceiveBufferTooLarge) => {
                crate::CKR_DEVICE_MEMORY as CK_RV
            }
            #[cfg(feature = "native-hardware")]
            Error::LocalHardware(_) => CKR_DEVICE_ERROR as CK_RV,
            #[cfg(feature = "native-hardware")]
            Error::Pcsc(_) => CKR_DEVICE_ERROR as CK_RV,
            Error::Http(_) => CKR_DEVICE_REMOVED as CK_RV,
            Error::Io(_) => CKR_FUNCTION_FAILED as CK_RV,
        }
    }
}

pub fn map<T, E>(r: Result<T, E>) -> CK_RV
where
    E: Into<CK_RV>,
{
    match r {
        Ok(_) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}
