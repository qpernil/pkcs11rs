use std::cell::BorrowMutError;

use crate::{
    CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_MUTEX_BAD, CKR_OK, CK_RV,
};

#[derive(Debug)]
pub enum Error {
    Generic(CK_RV),
    Usb(rusb::Error),
    Pcsc(pcsc::Error),
    Curl(curl::Error),
    OpenSsl(openssl::error::ErrorStack),
}

impl From<rusb::Error> for Error {
    fn from(e: rusb::Error) -> Self {
        Self::Usb(e)
    }
}

impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Self::Pcsc(e)
    }
}

impl From<curl::Error> for Error {
    fn from(e: curl::Error) -> Self {
        Self::Curl(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSsl(e)
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

impl Into<CK_RV> for Error {
    fn into(self) -> CK_RV {
        eprintln!("{:?}", self);
        match self {
            Self::Generic(rv) => rv,
            Self::Usb(_) => CKR_DEVICE_ERROR as CK_RV,
            Self::Pcsc(_) => CKR_DEVICE_ERROR as CK_RV,
            Self::Curl(_) => CKR_DEVICE_REMOVED as CK_RV,
            Self::OpenSsl(_) => CKR_FUNCTION_FAILED as CK_RV,
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
