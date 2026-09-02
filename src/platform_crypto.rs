#[cfg(test)]
pub(crate) use platform_credential::prefixed_x963_kdf;
pub(crate) use platform_credential::{
    PlatformAuthenticationCredential, PlatformCryptoError, PrefixedX963Credential,
    resolve_platform_credential, validate_platform_credential_name,
};
