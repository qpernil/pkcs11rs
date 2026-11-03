use std::cell::BorrowMutError;

use crate::{
    CK_RV, CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_MUTEX_BAD, CKR_OK,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginStage {
    CredentialLookup,
    CardCertificate,
    SecureChannel,
    Authentication,
}

impl Error {
    /// Translate failures of internal key operations to the login API's error
    /// domain, retaining the phase and original code in secret-free diagnostics.
    pub(crate) fn login_failure(self, stage: LoginStage) -> Self {
        use crate::*;
        let original: CK_RV = self.into();
        let internal_key_failure = [
            CKR_KEY_HANDLE_INVALID,
            CKR_OBJECT_HANDLE_INVALID,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_PUBLIC_KEY_INVALID,
            CKR_TEMPLATE_INCOMPLETE,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_MECHANISM_PARAM_INVALID,
        ]
        .into_iter()
        .any(|code| original == code as CK_RV);
        // Channel credentials are not the target applet's PIN. Parsing caller
        // arguments happens before prerequisite lookup or channel establishment.
        let prerequisite_failure = stage != LoginStage::Authentication
            && [
                CKR_ARGUMENTS_BAD,
                CKR_PIN_INCORRECT,
                CKR_PIN_LOCKED,
                CKR_USER_PIN_NOT_INITIALIZED,
                CKR_USER_NOT_LOGGED_IN,
                CKR_FUNCTION_NOT_SUPPORTED,
            ]
            .into_iter()
            .any(|code| original == code as CK_RV);
        let result = if original == CKR_SIGNATURE_INVALID as CK_RV
            || original == CKR_SIGNATURE_LEN_RANGE as CK_RV
        {
            CKR_DEVICE_ERROR as CK_RV
        } else if internal_key_failure || prerequisite_failure {
            CKR_FUNCTION_FAILED as CK_RV
        } else {
            original
        };
        tracing::warn!(
            target: "pkcs11rs::auth",
            stage = ?stage,
            original_rv = original,
            returned_rv = result,
            "Login failed"
        );
        Self::Generic(result)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn login_codes_distinguish_prerequisites_from_applet_authentication() {
        for stage in [
            LoginStage::CredentialLookup,
            LoginStage::CardCertificate,
            LoginStage::SecureChannel,
        ] {
            for code in [
                CKR_KEY_HANDLE_INVALID,
                CKR_TEMPLATE_INCOMPLETE,
                CKR_PUBLIC_KEY_INVALID,
                CKR_USER_NOT_LOGGED_IN,
                CKR_PIN_INCORRECT,
            ] {
                assert_eq!(
                    CK_RV::from(Error::from(code).login_failure(stage)),
                    CKR_FUNCTION_FAILED as CK_RV,
                    "{stage:?}: {code:x}"
                );
            }
        }
        for code in [
            CKR_ARGUMENTS_BAD,
            CKR_PIN_INCORRECT,
            CKR_PIN_LOCKED,
            CKR_USER_PIN_NOT_INITIALIZED,
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_USER_TYPE_INVALID,
            CKR_SESSION_HANDLE_INVALID,
        ] {
            assert_eq!(
                CK_RV::from(Error::from(code).login_failure(LoginStage::Authentication)),
                code as CK_RV
            );
        }
        assert_eq!(
            CK_RV::from(
                Error::from(CKR_KEY_HANDLE_INVALID).login_failure(LoginStage::Authentication)
            ),
            CKR_FUNCTION_FAILED as CK_RV
        );
    }

    #[test]
    fn login_errors_preserve_device_and_resource_failures() {
        for stage in [
            LoginStage::CredentialLookup,
            LoginStage::CardCertificate,
            LoginStage::SecureChannel,
            LoginStage::Authentication,
        ] {
            for code in [
                CKR_DEVICE_ERROR,
                CKR_DEVICE_REMOVED,
                CKR_HOST_MEMORY,
                CKR_DEVICE_MEMORY,
                CKR_GENERAL_ERROR,
                CKR_FUNCTION_CANCELED,
            ] {
                assert_eq!(
                    CK_RV::from(Error::from(code).login_failure(stage)),
                    code as CK_RV
                );
            }
            assert_eq!(
                CK_RV::from(Error::from(CKR_SIGNATURE_INVALID).login_failure(stage)),
                CKR_DEVICE_ERROR as CK_RV
            );
        }
    }
}
