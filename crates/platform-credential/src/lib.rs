//! Platform-protected authentication credentials.
//!
//! The public boundary is deliberately independent of Apple Security,
//! Windows CNG, TPMs, or any other storage mechanism. Backends expose only
//! the cryptographic operations the authentication protocol needs and a small
//! lifecycle API used by management tools.

use software_key_core::{
    digest::{HashAlgorithm, HashContext},
    software_signing::SoftwarePublicKey,
};
use std::{fmt, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use apple::ApplePlatformCryptoProvider;

/// Failure reported by a platform credential provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformCryptoError {
    InvalidName,
    AlreadyExists,
    NotFound,
    Ambiguous,
    Unsupported,
    InvalidPublicKey,
    OutputTooLong,
    Backend(String),
}

impl fmt::Display for PlatformCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str("invalid platform credential name"),
            Self::AlreadyExists => formatter.write_str("platform credential already exists"),
            Self::NotFound => formatter.write_str("platform credential not found"),
            Self::Ambiguous => formatter.write_str("platform credential name is ambiguous"),
            Self::Unsupported => formatter.write_str("operation is not supported by this provider"),
            Self::InvalidPublicKey => formatter.write_str("invalid peer public key"),
            Self::OutputTooLong => formatter.write_str("derived output is too long"),
            Self::Backend(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PlatformCryptoError {}

/// An asymmetric credential capable of the exact construction needed by
/// YubiHSM asymmetric authentication and SCP11-style handshakes.
pub trait PrefixedX963Credential: Send + Sync {
    fn public_key(&self) -> Result<SoftwarePublicKey, PlatformCryptoError>;

    fn derive_prefixed_x963(
        &self,
        peer_public_key: &SoftwarePublicKey,
        hash: HashAlgorithm,
        prefix: &[u8],
        shared_info: &[u8],
        output_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, PlatformCryptoError>;
}

/// The two independent AES-CMAC keys used by symmetric HSM authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmacKeyRole {
    Encryption,
    Mac,
}

/// A symmetric credential whose raw AES keys need not be exportable.
pub trait CmacPairCredential: Send + Sync {
    fn cmac(&self, role: CmacKeyRole, message: &[u8]) -> Result<[u8; 16], PlatformCryptoError>;
}

/// The primitive kind determines how the common authentication layer drives
/// the credential; it is metadata, not credential-string syntax.
#[derive(Clone)]
pub enum PlatformAuthenticationCredential {
    Asymmetric(Arc<dyn PrefixedX963Credential>),
    Symmetric(Arc<dyn CmacPairCredential>),
}

/// Algorithm of a managed platform credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlatformCredentialAlgorithm {
    P256,
}

/// Non-secret information returned while enumerating managed credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformCredentialInfo {
    pub name: String,
    pub algorithm: PlatformCredentialAlgorithm,
}

/// Resolves credentials for authentication without changing persistent state.
pub trait AuthenticationCredentialProvider: Send + Sync {
    fn resolve(&self, name: &str) -> Result<PlatformAuthenticationCredential, PlatformCryptoError>;
}

/// Explicit lifecycle operations used by administration tools and host apps.
pub trait AuthenticationCredentialStore: Send + Sync {
    fn generate(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError>;
    fn list(&self) -> Result<Vec<PlatformCredentialInfo>, PlatformCryptoError>;
    fn public_key(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError>;
    fn delete(&self, name: &str) -> Result<(), PlatformCryptoError>;
}

/// Resolve the provider selected by the current build target. Platform names
/// intentionally do not encode whether the implementation is Apple, CNG, TPM,
/// or some future backend.
pub fn resolve_platform_credential(
    name: &str,
) -> Result<PlatformAuthenticationCredential, PlatformCryptoError> {
    current_provider().resolve(name)
}

pub fn generate_platform_credential(name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
    current_provider().generate(name)
}

pub fn list_platform_credentials() -> Result<Vec<PlatformCredentialInfo>, PlatformCryptoError> {
    current_provider().list()
}

pub fn platform_credential_public_key(
    name: &str,
) -> Result<SoftwarePublicKey, PlatformCryptoError> {
    current_provider().public_key(name)
}

pub fn delete_platform_credential(name: &str) -> Result<(), PlatformCryptoError> {
    current_provider().delete(name)
}

fn current_provider() -> impl AuthenticationCredentialProvider + AuthenticationCredentialStore {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        ApplePlatformCryptoProvider
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        UnsupportedPlatformCryptoProvider
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Default)]
struct UnsupportedPlatformCryptoProvider;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
impl AuthenticationCredentialProvider for UnsupportedPlatformCryptoProvider {
    fn resolve(&self, name: &str) -> Result<PlatformAuthenticationCredential, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        Err(PlatformCryptoError::Unsupported)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
impl AuthenticationCredentialStore for UnsupportedPlatformCryptoProvider {
    fn generate(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        Err(PlatformCryptoError::Unsupported)
    }

    fn list(&self) -> Result<Vec<PlatformCredentialInfo>, PlatformCryptoError> {
        Err(PlatformCryptoError::Unsupported)
    }

    fn public_key(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        Err(PlatformCryptoError::Unsupported)
    }

    fn delete(&self, name: &str) -> Result<(), PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        Err(PlatformCryptoError::Unsupported)
    }
}

/// X9.63 KDF with a caller-supplied prefix before the ECDH secret.
pub fn prefixed_x963_kdf(
    hash: HashAlgorithm,
    prefix: &[u8],
    shared_secret: &[u8],
    shared_info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, PlatformCryptoError> {
    if output_length == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }

    let block_count = output_length.div_ceil(hash.output_length());
    if block_count > u32::MAX as usize {
        return Err(PlatformCryptoError::OutputTooLong);
    }

    let mut output = Zeroizing::new(Vec::with_capacity(output_length));
    for counter in 1..=block_count as u32 {
        let mut context = HashContext::new(hash);
        context.update(prefix);
        context.update(shared_secret);
        context.update(&counter.to_be_bytes());
        context.update(shared_info);
        let mut block = context.finalize();
        let remaining = output_length - output.len();
        output.extend_from_slice(&block[..remaining.min(block.len())]);
        block.zeroize();
    }
    Ok(output)
}

pub fn validate_platform_credential_name(name: &str) -> Result<(), PlatformCryptoError> {
    if name.is_empty()
        || name.bytes().all(|byte| byte.is_ascii_digit())
        || name.bytes().any(|byte| byte == b'@' || byte == b':')
    {
        return Err(PlatformCryptoError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_x963_kdf_has_stable_counter_and_field_order() {
        let derived = prefixed_x963_kdf(
            HashAlgorithm::Sha256,
            b"prefix",
            b"secret",
            b"shared-info",
            48,
        )
        .expect("valid KDF request");

        let mut first = Vec::new();
        first.extend_from_slice(b"prefixsecret");
        first.extend_from_slice(&1_u32.to_be_bytes());
        first.extend_from_slice(b"shared-info");
        let mut second = Vec::new();
        second.extend_from_slice(b"prefixsecret");
        second.extend_from_slice(&2_u32.to_be_bytes());
        second.extend_from_slice(b"shared-info");
        let expected = [
            HashAlgorithm::Sha256.digest(&first),
            HashAlgorithm::Sha256.digest(&second),
        ]
        .concat();
        assert_eq!(&derived[..], &expected[..48]);
    }

    #[test]
    fn platform_names_are_unambiguous_with_existing_selector_syntax() {
        assert!(validate_platform_credential_name("reserve").is_ok());
        assert!(validate_platform_credential_name("phone-key").is_ok());
        for invalid in ["", "1234", "name@host", ":direct"] {
            assert_eq!(
                validate_platform_credential_name(invalid),
                Err(PlatformCryptoError::InvalidName)
            );
        }
    }
}
