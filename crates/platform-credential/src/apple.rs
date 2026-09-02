//! Apple Keychain/Secure Enclave backend.

use super::{
    AuthenticationCredentialProvider, AuthenticationCredentialStore,
    PlatformAuthenticationCredential, PlatformCredentialAlgorithm, PlatformCredentialInfo,
    PlatformCryptoError, PrefixedX963Credential, prefixed_x963_kdf,
    validate_platform_credential_name,
};
use core_foundation::{
    array::CFArray,
    base::{CFGetTypeID, CFType, CFTypeRef, TCFType, ToVoid},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFMutableDictionary},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    key::{Algorithm, SecKey},
};
use security_framework_sys::{
    access_control::kSecAccessControlPrivateKeyUsage,
    base::errSecItemNotFound,
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchLimit, kSecMatchLimitAll,
        kSecPrivateKeyAttrs, kSecReturnAttributes, kSecReturnRef,
    },
    key::{SecKeyCreateRandomKey, SecKeyCreateWithData, SecKeyGetTypeID},
    keychain_item::SecItemCopyMatching,
};
use software_key_core::{
    digest::HashAlgorithm,
    software_signing::{EcCurve, SoftwarePublicKey},
};
use std::{ffi::c_void, ptr, sync::Arc};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use security_framework_sys::item::kSecUseDataProtectionKeychain;

const APPLICATION_TAG_PREFIX: &[u8] = b"pkcs11rs.yubihsm-auth.";

// security-framework-sys does not currently expose this public
// Security.framework constant.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ApplePlatformCryptoProvider;

impl AuthenticationCredentialProvider for ApplePlatformCryptoProvider {
    fn resolve(&self, name: &str) -> Result<PlatformAuthenticationCredential, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let key = find_secure_enclave_key(name)?;
        Ok(PlatformAuthenticationCredential::Asymmetric(Arc::new(
            ApplePrefixedX963Credential { key },
        )))
    }
}

impl AuthenticationCredentialStore for ApplePlatformCryptoProvider {
    fn generate(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        match find_secure_enclave_key(name) {
            Err(PlatformCryptoError::NotFound) => {}
            Ok(_) | Err(PlatformCryptoError::Ambiguous) => {
                return Err(PlatformCryptoError::AlreadyExists);
            }
            Err(error) => return Err(error),
        }

        let key = generate_secure_enclave_key(name)?;
        public_key(&key)
    }

    fn list(&self) -> Result<Vec<PlatformCredentialInfo>, PlatformCryptoError> {
        let mut credentials = secure_enclave_key_names()?
            .into_iter()
            .map(|name| PlatformCredentialInfo {
                name,
                algorithm: PlatformCredentialAlgorithm::P256,
            })
            .collect::<Vec<_>>();
        credentials.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(credentials)
    }

    fn public_key(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        public_key(&find_secure_enclave_key(name)?)
    }

    fn delete(&self, name: &str) -> Result<(), PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let keys = matching_secure_enclave_keys(name)?;
        if keys.is_empty() {
            return Err(PlatformCryptoError::NotFound);
        }
        for key in keys {
            key.delete()
                .map_err(|error| backend_error(format!("Keychain deletion failed: {error}")))?;
        }
        Ok(())
    }
}

struct ApplePrefixedX963Credential {
    key: SecKey,
}

impl PrefixedX963Credential for ApplePrefixedX963Credential {
    fn public_key(&self) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        public_key(&self.key)
    }

    fn derive_prefixed_x963(
        &self,
        peer_public_key: &SoftwarePublicKey,
        hash: HashAlgorithm,
        prefix: &[u8],
        shared_info: &[u8],
        output_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, PlatformCryptoError> {
        let SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed,
        } = peer_public_key
        else {
            return Err(PlatformCryptoError::InvalidPublicKey);
        };
        peer_public_key
            .validate()
            .map_err(|_| PlatformCryptoError::InvalidPublicKey)?;
        let peer = sec_key_from_p256_public(uncompressed)?;
        let shared_secret = Zeroizing::new(
            self.key
                .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
                .map_err(|error| backend_error(format!("Secure Enclave ECDH failed: {error}")))?,
        );
        prefixed_x963_kdf(hash, prefix, &shared_secret, shared_info, output_length)
    }
}

fn generate_secure_enclave_key(name: &str) -> Result<SecKey, PlatformCryptoError> {
    let tag = application_tag(name);
    let key_size = CFNumber::from(256_i32);
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|error| backend_error(format!("create key access control: {error}")))?;
    let private_attributes = unsafe {
        CFMutableDictionary::from_CFType_pairs(&[
            (
                kSecAttrIsPermanent.to_void(),
                CFBoolean::true_value().to_void(),
            ),
            (kSecAttrApplicationTag.to_void(), tag.to_void()),
            (kSecAttrAccessControl.to_void(), access.to_void()),
        ])
    };
    let mut attributes = unsafe {
        CFMutableDictionary::from_CFType_pairs(&[
            (
                kSecAttrKeyType.to_void(),
                kSecAttrKeyTypeECSECPrimeRandom.to_void(),
            ),
            (kSecAttrKeySizeInBits.to_void(), key_size.to_void()),
            (
                kSecAttrTokenID.to_void(),
                kSecAttrTokenIDSecureEnclave.to_void(),
            ),
            (kSecPrivateKeyAttrs.to_void(), private_attributes.to_void()),
        ])
    };
    use_data_protection_keychain(&mut attributes);
    let mut error = ptr::null_mut();
    let key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error) };
    if key.is_null() {
        if error.is_null() {
            return Err(backend_error("Secure Enclave key generation failed"));
        }
        let error = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
        return Err(backend_error(format!(
            "Secure Enclave key generation failed: {error}"
        )));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

fn application_tag(name: &str) -> CFData {
    let mut tag = Vec::with_capacity(APPLICATION_TAG_PREFIX.len() + name.len());
    tag.extend_from_slice(APPLICATION_TAG_PREFIX);
    tag.extend_from_slice(name.as_bytes());
    CFData::from_buffer(&tag)
}

fn application_name(attributes: &CFDictionary) -> Option<String> {
    let value = attributes.find(unsafe { kSecAttrApplicationTag.to_void() })?;
    if unsafe { CFGetTypeID((*value).cast()) } != CFData::type_id() {
        return None;
    }
    let tag = unsafe { CFData::wrap_under_get_rule((*value).cast_mut().cast()) };
    let name = tag.bytes().strip_prefix(APPLICATION_TAG_PREFIX)?;
    let name = std::str::from_utf8(name).ok()?;
    validate_platform_credential_name(name).ok()?;
    Some(name.to_owned())
}

fn find_secure_enclave_key(name: &str) -> Result<SecKey, PlatformCryptoError> {
    let mut matches = matching_secure_enclave_keys(name)?.into_iter();
    let key = matches.next().ok_or(PlatformCryptoError::NotFound)?;
    if matches.next().is_some() {
        return Err(PlatformCryptoError::Ambiguous);
    }
    Ok(key)
}

fn matching_secure_enclave_keys(name: &str) -> Result<Vec<SecKey>, PlatformCryptoError> {
    let tag = application_tag(name);
    secure_enclave_keys(Some(&tag))
}

fn secure_enclave_key_names() -> Result<Vec<String>, PlatformCryptoError> {
    let mut query = unsafe {
        CFMutableDictionary::from_CFType_pairs(&[
            (kSecClass.to_void(), kSecClassKey.to_void()),
            (
                kSecAttrKeyClass.to_void(),
                kSecAttrKeyClassPrivate.to_void(),
            ),
            (
                kSecAttrKeyType.to_void(),
                kSecAttrKeyTypeECSECPrimeRandom.to_void(),
            ),
            (
                kSecAttrTokenID.to_void(),
                kSecAttrTokenIDSecureEnclave.to_void(),
            ),
            (
                kSecReturnAttributes.to_void(),
                CFBoolean::true_value().to_void(),
            ),
            (kSecMatchLimit.to_void(), kSecMatchLimitAll.to_void()),
        ])
    };
    use_data_protection_keychain(&mut query);

    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == errSecItemNotFound {
        return Ok(Vec::new());
    }
    if status != 0 {
        return Err(backend_error(format!(
            "Keychain lookup failed with OSStatus {status}"
        )));
    }
    if result.is_null() {
        return Ok(Vec::new());
    }

    unsafe {
        if CFGetTypeID(result) == CFArray::<CFType>::type_id() {
            let attributes = CFArray::<CFType>::wrap_under_create_rule(result.cast_mut().cast());
            attributes
                .iter()
                .map(|attributes| application_name_from_cf_type(&attributes))
                .collect()
        } else {
            let attributes = CFType::wrap_under_create_rule(result.cast_mut());
            Ok(vec![application_name_from_cf_type(&attributes)?])
        }
    }
}

fn application_name_from_cf_type(attributes: &CFType) -> Result<String, PlatformCryptoError> {
    if unsafe { CFGetTypeID(attributes.as_CFTypeRef()) }
        != CFDictionary::<*const c_void, *const c_void>::type_id()
    {
        return Err(backend_error("Keychain returned non-dictionary attributes"));
    }
    let attributes: CFDictionary =
        unsafe { CFDictionary::wrap_under_get_rule(attributes.as_CFTypeRef().cast_mut().cast()) };
    application_name(&attributes)
        .ok_or_else(|| backend_error("Keychain key has an invalid application tag"))
}

fn secure_enclave_keys(
    application_tag: Option<&CFData>,
) -> Result<Vec<SecKey>, PlatformCryptoError> {
    let mut query = unsafe {
        CFMutableDictionary::from_CFType_pairs(&[
            (kSecClass.to_void(), kSecClassKey.to_void()),
            (
                kSecAttrKeyClass.to_void(),
                kSecAttrKeyClassPrivate.to_void(),
            ),
            (
                kSecAttrKeyType.to_void(),
                kSecAttrKeyTypeECSECPrimeRandom.to_void(),
            ),
            (
                kSecAttrTokenID.to_void(),
                kSecAttrTokenIDSecureEnclave.to_void(),
            ),
            (kSecReturnRef.to_void(), CFBoolean::true_value().to_void()),
            (kSecMatchLimit.to_void(), kSecMatchLimitAll.to_void()),
        ])
    };
    if let Some(application_tag) = application_tag {
        unsafe {
            query.set(kSecAttrApplicationTag.to_void(), application_tag.to_void());
        }
    }
    use_data_protection_keychain(&mut query);

    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == errSecItemNotFound {
        return Ok(Vec::new());
    }
    if status != 0 {
        return Err(backend_error(format!(
            "Keychain lookup failed with OSStatus {status}"
        )));
    }
    if result.is_null() {
        return Ok(Vec::new());
    }

    unsafe {
        if CFGetTypeID(result) == CFArray::<CFType>::type_id() {
            let keys = CFArray::<CFType>::wrap_under_create_rule(result.cast_mut().cast());
            keys.iter().map(|key| sec_key_from_cf_type(&key)).collect()
        } else if CFGetTypeID(result) == SecKeyGetTypeID() {
            Ok(vec![SecKey::wrap_under_create_rule(
                result.cast_mut().cast(),
            )])
        } else {
            let _owned = CFType::wrap_under_create_rule(result.cast_mut());
            Err(backend_error("Keychain returned an unexpected reference"))
        }
    }
}

fn sec_key_from_cf_type(value: &CFType) -> Result<SecKey, PlatformCryptoError> {
    if unsafe { CFGetTypeID(value.as_CFTypeRef()) } != unsafe { SecKeyGetTypeID() } {
        return Err(backend_error("Keychain returned a non-key reference"));
    }
    Ok(unsafe { SecKey::wrap_under_get_rule(value.as_CFTypeRef().cast_mut().cast()) })
}

fn use_data_protection_keychain(_dictionary: &mut CFMutableDictionary) {
    #[cfg(target_os = "macos")]
    unsafe {
        _dictionary.set(
            kSecUseDataProtectionKeychain.to_void(),
            CFBoolean::true_value().to_void(),
        );
    }
}

fn public_key(key: &SecKey) -> Result<SoftwarePublicKey, PlatformCryptoError> {
    let public = key
        .public_key()
        .ok_or_else(|| backend_error("Secure Enclave did not return a public key"))?;
    let encoded = public
        .external_representation()
        .ok_or_else(|| backend_error("Secure Enclave public key is not exportable"))?
        .to_vec();
    let public = SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: encoded,
    };
    public
        .validate()
        .map_err(|_| PlatformCryptoError::InvalidPublicKey)?;
    Ok(public)
}

fn sec_key_from_p256_public(encoded: &[u8]) -> Result<SecKey, PlatformCryptoError> {
    let encoded = CFData::from_buffer(encoded);
    let key_size = CFNumber::from(256_i32);
    let attributes = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(security_framework_sys::item::kSecAttrKeyClassPublic)
                    .into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                key_size.into_CFType(),
            ),
        ])
    };
    let mut error = ptr::null_mut();
    let key = unsafe {
        SecKeyCreateWithData(
            encoded.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key.is_null() {
        if error.is_null() {
            return Err(PlatformCryptoError::InvalidPublicKey);
        }
        let error = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
        return Err(backend_error(format!(
            "failed to import peer P-256 public key: {error}"
        )));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

fn backend_error(message: impl Into<String>) -> PlatformCryptoError {
    PlatformCryptoError::Backend(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_framework::key::{GenerateKeyOptions, KeyType, Token};
    use software_key_core::{
        software_key_agreement::derive_with_signing_key,
        software_signing::{KeyKind, SoftwareSigningKey},
    };

    #[test]
    #[ignore = "requires unsandboxed access to the host Secure Enclave"]
    fn secure_enclave_ecdh_matches_software_peer_and_prefixed_kdf() {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave);
        let credential = ApplePrefixedX963Credential {
            key: SecKey::new(&options).expect("generate ephemeral Secure Enclave key"),
        };

        let enclave_public = credential.public_key().expect("read public key");
        let peer = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
            .expect("generate peer key");
        let peer_public = peer.public_key();
        let derived = credential
            .derive_prefixed_x963(
                &peer_public,
                HashAlgorithm::Sha256,
                b"ephemeral-secret-prefix",
                b"shared-info",
                64,
            )
            .expect("derive in Secure Enclave");
        let SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed,
        } = enclave_public
        else {
            panic!("Secure Enclave returned a non-P256 public key");
        };
        let software_secret = derive_with_signing_key(&peer, &uncompressed).expect("software ECDH");
        let expected = prefixed_x963_kdf(
            HashAlgorithm::Sha256,
            b"ephemeral-secret-prefix",
            &software_secret,
            b"shared-info",
            64,
        )
        .expect("software KDF");
        assert_eq!(derived, expected);
    }
}
