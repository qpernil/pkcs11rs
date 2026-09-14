use crate::{CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, Error};
#[cfg(not(target_os = "ios"))]
use crate::{CKR_CANCEL, CKR_FUNCTION_FAILED, CKR_PIN_INVALID};
use std::{ffi::OsString, sync::Mutex};
use zeroize::Zeroizing;

#[cfg(not(target_os = "ios"))]
pub(crate) use crate::pinentry_client::Prompt;

#[cfg(target_os = "ios")]
pub(crate) struct Prompt<'a> {
    pub(crate) title: &'a str,
    pub(crate) description: &'a str,
    pub(crate) label: &'a str,
}

pub(crate) struct Pinentry {
    program: Mutex<Option<OsString>>,
    prompt: Mutex<()>,
}

impl std::fmt::Debug for Pinentry {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Pinentry")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl Pinentry {
    pub(crate) fn unconfigured() -> Self {
        Self {
            program: Mutex::new(None),
            prompt: Mutex::new(()),
        }
    }

    pub(crate) fn from_configuration(value: Option<OsString>) -> Result<Self, Error> {
        let pinentry = Self::unconfigured();
        pinentry.configure(value)?;
        Ok(pinentry)
    }

    fn configure(&self, value: Option<OsString>) -> Result<(), Error> {
        let value = parse_configuration(value)?;
        match value.as_deref() {
            Some(program) => log!(2, "Pinentry configured with executable {:?}", program),
            None => log!(2, "Pinentry is not configured"),
        }
        *self.program.lock().map_err(|_| CKR_CANT_LOCK)? = value;
        Ok(())
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.program
            .lock()
            .map(|program| program.is_some())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "ios"))]
    pub(crate) fn request(&self, prompt: Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let program = self
            .program
            .lock()
            .map_err(|_| CKR_CANT_LOCK)?
            .clone()
            .ok_or(CKR_ARGUMENTS_BAD)?;
        let _prompt = self.prompt.lock().map_err(|_| CKR_CANT_LOCK)?;
        log!(
            2,
            "Starting pinentry executable {:?} for prompt {:?}",
            program,
            prompt.label
        );
        let result = crate::pinentry_client::request(&program, prompt, std::env::var_os("GPG_TTY"))
            .map_err(|error| match error {
                crate::pinentry_client::Error::Io(error) => Error::from(error),
                crate::pinentry_client::Error::Cancelled => Error::from(CKR_CANCEL),
                crate::pinentry_client::Error::InvalidSecret => Error::from(CKR_PIN_INVALID),
                crate::pinentry_client::Error::Protocol => Error::from(CKR_FUNCTION_FAILED),
            });
        match &result {
            Ok(_) => log!(2, "Pinentry returned a password"),
            Err(Error::Generic(rv)) if *rv == CKR_CANCEL as crate::CK_RV => {
                log!(2, "Pinentry prompt was cancelled")
            }
            Err(error) => log!(2, "Pinentry prompt failed: {:?}", error),
        }
        result
    }

    // A native application callback will implement the protected path on iOS.
    // Until it is installed, a null PIN has no usable protected path.
    #[cfg(target_os = "ios")]
    pub(crate) fn request(&self, _prompt: Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(CKR_ARGUMENTS_BAD.into())
    }
}

#[cfg(all(test, unix))]
pub(crate) fn configure_for_test(value: Option<OsString>) -> Result<(), Error> {
    let module = crate::lock_context_read()?;
    match module.as_ref() {
        Some(context) => context.pinentry.configure(value),
        None => Ok(()),
    }
}

fn parse_configuration(value: Option<OsString>) -> Result<Option<OsString>, Error> {
    if value.as_ref().is_some_and(|value| value.is_empty()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    #[cfg(target_os = "ios")]
    if value.is_some() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinentry_configuration_is_explicit() {
        assert_eq!(parse_configuration(None).unwrap(), None);
        assert_eq!(
            parse_configuration(Some(OsString::from("pinentry-mac"))).unwrap(),
            Some(OsString::from("pinentry-mac"))
        );
        assert!(parse_configuration(Some(OsString::new())).is_err());
    }
}
