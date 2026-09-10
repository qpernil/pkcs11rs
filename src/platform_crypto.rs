pub(crate) use platform_credential::{
    EcdhCredential, PLATFORM_CREDENTIAL_NAME_CAPACITY, PlatformAuthenticationCredential,
    PlatformCredentialAlgorithm, PlatformCryptoError, delete_platform_credential,
    generate_platform_credential, list_platform_credentials, platform_credential_public_key,
    resolve_platform_credential, validate_platform_credential_name,
};
