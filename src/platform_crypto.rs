#[cfg(test)]
pub(crate) use platform_credential::prefixed_x963_kdf;
pub(crate) use platform_credential::{
    PLATFORM_CREDENTIAL_NAME_CAPACITY, PlatformAuthenticationCredential,
    PlatformCredentialAlgorithm, PlatformCryptoError, PrefixedX963Credential,
    delete_platform_credential, generate_platform_credential, list_platform_credentials,
    platform_credential_public_key, resolve_platform_credential, validate_platform_credential_name,
};
