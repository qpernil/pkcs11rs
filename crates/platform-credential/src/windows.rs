//! Current-user, non-exportable P-256 ECDH keys in the Windows TPM KSP.
//! No software fallback or password cache. Private-key access requests silent UI policy.

use super::{
    AuthenticationCredentialProvider, AuthenticationCredentialStore, EcdhCredential,
    PlatformAuthenticationCredential, PlatformCredentialAlgorithm, PlatformCredentialInfo,
    PlatformCryptoError, validate_platform_credential_name,
};
use software_key_core::software_signing::{EcCurve, SoftwarePublicKey};
use std::{ffi::c_void, ptr, sync::Arc};
use windows_sys::Win32::{Foundation::*, Security::Cryptography::*};
use zeroize::Zeroizing;

const KEY_PREFIX: &str = "pkcs11rs.yubihsm-auth.";
const SILENT: u32 = NCRYPT_SILENT_FLAG;

#[derive(Clone, Copy)]
pub(super) struct WindowsPlatformCryptoProvider {
    name: &'static str,
    require_hardware: bool,
}

impl WindowsPlatformCryptoProvider {
    pub(super) fn tpm() -> Self {
        Self {
            name: "Microsoft Platform Crypto Provider",
            require_hardware: true,
        }
    }

    fn provider(&self) -> Result<Handle, PlatformCryptoError> {
        let name = wide(self.name);
        let mut handle = Handle(0);
        check(
            unsafe { NCryptOpenStorageProvider(&mut handle.0, name.as_ptr(), 0) },
            "open provider",
        )?;
        if self.require_hardware {
            let implementation =
                property_u32(&handle, NCRYPT_IMPL_TYPE_PROPERTY, "implementation type")?;
            if implementation & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
                return Err(unsupported(format!(
                    "{} reports implementation type 0x{implementation:08x}; hardware flag required",
                    self.name,
                )));
            }
        }
        Ok(handle)
    }

    fn key_usage_policy(&self) -> (*const u16, u32, &'static str) {
        if self.require_hardware {
            // PCP uses TPM object attributes, rather than the software KSP's
            // generic usage setter. TPM's decrypt attribute permits ECDH;
            // exclude the signature attribute and require an ECDH public blob.
            (
                NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                NCRYPT_PCP_ENCRYPTION_KEY,
                "TPM key usage policy",
            )
        } else {
            (
                NCRYPT_KEY_USAGE_PROPERTY,
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG,
                "key usage",
            )
        }
    }

    fn validate_key_policy(&self, key: &Handle) -> Result<(), PlatformCryptoError> {
        let export = property_u32(key, NCRYPT_EXPORT_POLICY_PROPERTY, "export policy")?;
        let (property, required, description) = self.key_usage_policy();
        let usage = property_u32(key, property, description)?;
        // PCP may include its documented provider marker in the usage value.
        // It is metadata, not permission to sign/decrypt with another algorithm.
        let metadata = if self.require_hardware {
            NCRYPT_TPM12_PROVIDER
        } else {
            0
        };
        validate_policy_values(export, usage, required, metadata, description)
    }

    fn open_named(&self, provider: &Handle, name: &str) -> Result<Handle, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let name = wide(&format!("{KEY_PREFIX}{name}"));
        let mut key = Handle(0);
        check(
            unsafe { NCryptOpenKey(provider.0, &mut key.0, name.as_ptr(), 0, SILENT) },
            "open key",
        )?;
        Ok(key)
    }

    fn open(&self, provider: &Handle, name: &str) -> Result<Handle, PlatformCryptoError> {
        let key = self.open_named(provider, name)?;
        self.validate_key_policy(&key)?;
        public_key(&key)?;
        Ok(key)
    }

    fn delete_key(&self, key: &mut Handle) -> Result<(), PlatformCryptoError> {
        // PCP rejects NCRYPT_SILENT_FLAG for deletion on some Windows versions.
        // This is destruction of a named key, not private-key use. Keep silent
        // flags on open/agreement and use PCP's zero-flags deletion contract.
        let flags = if self.require_hardware { 0 } else { SILENT };
        check(unsafe { NCryptDeleteKey(key.0, flags) }, "delete key")?;
        key.0 = 0; // Successful deletion also frees the native handle.
        Ok(())
    }
}

impl AuthenticationCredentialProvider for WindowsPlatformCryptoProvider {
    fn resolve(&self, name: &str) -> Result<PlatformAuthenticationCredential, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let provider = self.provider()?;
        let key = self.open(&provider, name)?;
        Ok(PlatformAuthenticationCredential::Asymmetric(Arc::new(
            WindowsEcdhCredential {
                store: *self,
                name: name.to_owned(),
                public: public_key(&key)?,
            },
        )))
    }
}

impl AuthenticationCredentialStore for WindowsPlatformCryptoProvider {
    fn generate(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let provider = self.provider()?;
        let native_name = wide(&format!("{KEY_PREFIX}{name}"));
        let mut key = Handle(0);
        // No overwrite flag: creation must never replace an existing identity.
        check(
            unsafe {
                NCryptCreatePersistedKey(
                    provider.0,
                    &mut key.0,
                    NCRYPT_ECDH_P256_ALGORITHM,
                    native_name.as_ptr(),
                    0,
                    SILENT,
                )
            },
            "create key",
        )?;
        set_u32(&key, NCRYPT_EXPORT_POLICY_PROPERTY, 0, "export policy")?;
        let (usage_property, usage_value, description) = self.key_usage_policy();
        set_u32(&key, usage_property, usage_value, description)?;
        check(unsafe { NCryptFinalizeKey(key.0, SILENT) }, "finalize key")?;
        let result = (|| {
            self.validate_key_policy(&key)?;
            public_key(&key)
        })();
        match result {
            Ok(public) => Ok(public),
            Err(original) => {
                // Preserve the provisioning failure even if rollback also fails.
                match self.delete_key(&mut key) {
                    Ok(()) => Err(original),
                    Err(cleanup) => Err(rollback_error(&original, &cleanup, name)),
                }
            }
        }
    }

    fn list(&self) -> Result<Vec<PlatformCredentialInfo>, PlatformCryptoError> {
        let provider = self.provider()?;
        let mut state = Buffer(ptr::null_mut());
        let mut result = Vec::new();
        loop {
            let mut entry = ptr::null_mut();
            let status = unsafe {
                NCryptEnumKeys(provider.0, ptr::null(), &mut entry, &mut state.0, SILENT)
            };
            let _entry = Buffer(entry.cast());
            if status == NTE_NO_MORE_ITEMS {
                break;
            }
            check(status, "enumerate keys")?;
            if entry.is_null() {
                return Err(backend_error("enumeration returned no key"));
            }
            // NCrypt owns both terminated UTF-16 strings until the entry is freed.
            let native_name = unsafe { read_wide((*entry).pszName) }?;
            let algorithm = unsafe { read_wide((*entry).pszAlgid) }?;
            let Some(name) = native_name.strip_prefix(KEY_PREFIX) else {
                continue;
            };
            // Some KSPs enumerate the generic ECC algorithm name. The public
            // blob and policies below establish the actual P-256 capability.
            if !matches!(algorithm.as_str(), "ECDH_P256" | "ECDH")
                || validate_platform_credential_name(name).is_err()
            {
                continue;
            }
            self.open(&provider, name)?;
            result.push(PlatformCredentialInfo {
                name: name.to_owned(),
                algorithm: PlatformCredentialAlgorithm::P256,
            });
        }
        result.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        result.dedup_by(|a, b| a.name == b.name);
        Ok(result)
    }

    fn public_key(&self, name: &str) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let provider = self.provider()?;
        public_key(&self.open(&provider, name)?)
    }

    fn delete(&self, name: &str) -> Result<(), PlatformCryptoError> {
        validate_platform_credential_name(name)?;
        let provider = self.provider()?;
        // Explicit management deletion also recovers managed keys rejected by
        // current policy/projection checks after incomplete provisioning.
        self.delete_key(&mut self.open_named(&provider, name)?)
    }
}

struct WindowsEcdhCredential {
    store: WindowsPlatformCryptoProvider,
    name: String,
    public: SoftwarePublicKey,
}

impl EcdhCredential for WindowsEcdhCredential {
    fn public_key(&self) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        Ok(self.public.clone())
    }

    fn certificates(&self) -> Result<Vec<Vec<u8>>, PlatformCryptoError> {
        matching_certificates(&self.public)
    }

    fn ecdh(&self, peer: &SoftwarePublicKey) -> Result<Zeroizing<Vec<u8>>, PlatformCryptoError> {
        let blob = peer_blob(peer)?;
        let provider = self.store.provider()?;
        let key = self.store.open(&provider, &self.name)?;
        // Reopen and use the same checked handle; a replacement cannot rebind it.
        if public_key(&key)? != self.public {
            return Err(PlatformCryptoError::NotFound);
        }
        let mut public = Handle(0);
        check(
            unsafe {
                NCryptImportKey(
                    provider.0,
                    0,
                    BCRYPT_ECCPUBLIC_BLOB,
                    ptr::null(),
                    &mut public.0,
                    blob.as_ptr(),
                    blob.len() as u32,
                    SILENT,
                )
            },
            "import peer public key",
        )?;
        let mut agreed = Handle(0);
        check(
            unsafe { NCryptSecretAgreement(key.0, public.0, &mut agreed.0, SILENT) },
            "ECDH agreement",
        )?;
        let mut size = 0;
        check(
            unsafe {
                NCryptDeriveKey(
                    agreed.0,
                    BCRYPT_KDF_RAW_SECRET,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut size,
                    0,
                )
            },
            "query ECDH secret length",
        )?;
        if size != 32 {
            return Err(backend_error("unexpected P-256 secret length"));
        }
        let mut secret = Zeroizing::new(vec![0; 32]);
        check(
            unsafe {
                NCryptDeriveKey(
                    agreed.0,
                    BCRYPT_KDF_RAW_SECRET,
                    ptr::null(),
                    secret.as_mut_ptr(),
                    32,
                    &mut size,
                    0,
                )
            },
            "read ECDH secret",
        )?;
        if size != 32 {
            return Err(backend_error("unexpected P-256 secret length"));
        }
        // CNG RAW_SECRET is little-endian. The common PKCS #11/KDF contract is
        // the fixed-width, big-endian x coordinate (including leading zeros).
        secret.reverse();
        Ok(secret)
    }
}

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
struct Buffer(*mut c_void);
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                NCryptFreeBuffer(self.0);
            }
        }
    }
}
fn rollback_error(
    original: &PlatformCryptoError,
    cleanup: &PlatformCryptoError,
    name: &str,
) -> PlatformCryptoError {
    backend_error(format!(
        "{original}; rollback also failed: {cleanup}; managed key {KEY_PREFIX}{name} may remain"
    ))
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
unsafe fn read_wide(value: *const u16) -> Result<String, PlatformCryptoError> {
    if value.is_null() {
        return Err(backend_error("missing key metadata"));
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| backend_error("invalid UTF-16 key metadata"))
}
fn check(status: i32, operation: &str) -> Result<(), PlatformCryptoError> {
    match status {
        0 => Ok(()),
        NTE_EXISTS => Err(PlatformCryptoError::AlreadyExists),
        NTE_BAD_KEYSET | NTE_NOT_FOUND => Err(PlatformCryptoError::NotFound),
        NTE_NOT_SUPPORTED => Err(unsupported(format!(
            "CNG {operation} failed: NTE_NOT_SUPPORTED (0x{:08x})",
            status as u32
        ))),
        _ => Err(backend_error(format!(
            "CNG {operation} failed: 0x{:08x}",
            status as u32
        ))),
    }
}
fn backend_error(message: impl Into<String>) -> PlatformCryptoError {
    PlatformCryptoError::Backend(message.into())
}
fn unsupported(context: impl Into<String>) -> PlatformCryptoError {
    PlatformCryptoError::UnsupportedWithContext(context.into())
}
fn validate_policy_values(
    export: u32,
    usage: u32,
    required: u32,
    metadata: u32,
    description: &str,
) -> Result<(), PlatformCryptoError> {
    if export != 0 {
        return Err(unsupported(format!(
            "key export policy is 0x{export:08x}; non-exportable policy 0 required"
        )));
    }
    if usage & !metadata != required {
        return Err(unsupported(format!(
            "{description} is 0x{usage:08x}; required usage is 0x{required:08x} with optional metadata 0x{metadata:08x}"
        )));
    }
    Ok(())
}
fn property_u32(
    handle: &Handle,
    name: *const u16,
    description: &str,
) -> Result<u32, PlatformCryptoError> {
    let mut value = [0u8; 4];
    let mut size = 0;
    check(
        unsafe { NCryptGetProperty(handle.0, name, value.as_mut_ptr(), 4, &mut size, SILENT) },
        &format!("read {description}"),
    )?;
    if size != 4 {
        return Err(backend_error(format!(
            "CNG {description} returned {size} bytes; expected 4"
        )));
    }
    Ok(u32::from_le_bytes(value))
}
fn set_u32(
    handle: &Handle,
    name: *const u16,
    value: u32,
    description: &str,
) -> Result<(), PlatformCryptoError> {
    check(
        unsafe { NCryptSetProperty(handle.0, name, value.to_le_bytes().as_ptr(), 4, SILENT) },
        &format!("set {description}"),
    )
}
fn public_key(key: &Handle) -> Result<SoftwarePublicKey, PlatformCryptoError> {
    let mut blob = [0u8; 72];
    let mut size = 0;
    check(
        unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                blob.as_mut_ptr(),
                72,
                &mut size,
                SILENT,
            )
        },
        "export public key",
    )?;
    if size != 72
        || u32::from_le_bytes(blob[..4].try_into().unwrap()) != BCRYPT_ECDH_PUBLIC_P256_MAGIC
    {
        let magic = u32::from_le_bytes(blob[..4].try_into().unwrap());
        return Err(unsupported(format!(
            "public key blob has length {size} and magic 0x{magic:08x}; ECDH P-256 blob required"
        )));
    }
    decode_public_blob(&blob)
}
fn decode_public_blob(blob: &[u8]) -> Result<SoftwarePublicKey, PlatformCryptoError> {
    if blob.len() != 72 || u32::from_le_bytes(blob[4..8].try_into().unwrap()) != 32 {
        return Err(PlatformCryptoError::InvalidPublicKey);
    }
    let magic = u32::from_le_bytes(blob[..4].try_into().unwrap());
    if magic != BCRYPT_ECDH_PUBLIC_P256_MAGIC && magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
        return Err(PlatformCryptoError::InvalidPublicKey);
    }
    let mut uncompressed = vec![4];
    uncompressed.extend_from_slice(&blob[8..]);
    let public = SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    };
    public
        .validate()
        .map_err(|_| PlatformCryptoError::InvalidPublicKey)?;
    Ok(public)
}
fn peer_blob(peer: &SoftwarePublicKey) -> Result<Vec<u8>, PlatformCryptoError> {
    let SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    } = peer
    else {
        return Err(PlatformCryptoError::InvalidPublicKey);
    };
    peer.validate()
        .map_err(|_| PlatformCryptoError::InvalidPublicKey)?;
    let mut blob = Vec::with_capacity(72);
    blob.extend_from_slice(&BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32u32.to_le_bytes());
    blob.extend_from_slice(&uncompressed[1..]);
    Ok(blob)
}

struct CertificateStore(HCERTSTORE);
impl Drop for CertificateStore {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}
struct CertificateContext(*const CERT_CONTEXT);
impl Drop for CertificateContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertFreeCertificateContext(self.0);
            }
        }
    }
}
struct BCryptKey(BCRYPT_KEY_HANDLE);
impl Drop for BCryptKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyKey(self.0);
            }
        }
    }
}
fn matching_certificates(
    expected: &SoftwarePublicKey,
) -> Result<Vec<Vec<u8>>, PlatformCryptoError> {
    let name = wide("MY");
    let store = CertificateStore(unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_READONLY_FLAG
                | CERT_STORE_OPEN_EXISTING_FLAG,
            name.as_ptr().cast(),
        )
    });
    if store.0.is_null() {
        return Err(backend_error(format!(
            "open certificate store failed: {}",
            unsafe { GetLastError() }
        )));
    }
    matching_certificates_in_store(&store, expected)
}

fn matching_certificates_in_store(
    store: &CertificateStore,
    expected: &SoftwarePublicKey,
) -> Result<Vec<Vec<u8>>, PlatformCryptoError> {
    let mut context = CertificateContext(ptr::null());
    let mut certificates = Vec::new();
    loop {
        // Enumeration consumes the previous context, including on failure.
        let previous = std::mem::replace(&mut context.0, ptr::null());
        context.0 = unsafe { CertEnumCertificatesInStore(store.0, previous) };
        if context.0.is_null() {
            let status = unsafe { GetLastError() };
            if status != CRYPT_E_NOT_FOUND as u32 {
                return Err(backend_error(format!(
                    "enumerate certificates failed: 0x{status:08x}"
                )));
            }
            break;
        }
        let cert = unsafe { &*context.0 };
        let mut key = BCryptKey(ptr::null_mut());
        if unsafe {
            CryptImportPublicKeyInfoEx2(
                X509_ASN_ENCODING,
                &(*cert.pCertInfo).SubjectPublicKeyInfo,
                0,
                ptr::null(),
                &mut key.0,
            )
        } == 0
        {
            continue;
        }
        let mut blob = [0u8; 72];
        let mut size = 0;
        if unsafe {
            BCryptExportKey(
                key.0,
                ptr::null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                blob.as_mut_ptr(),
                72,
                &mut size,
                0,
            )
        } != 0
        {
            continue;
        }
        if size == 72 && decode_public_blob(&blob).as_ref() == Ok(expected) {
            certificates.push(
                unsafe {
                    std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize)
                }
                .to_vec(),
            );
        }
    }
    certificates.sort();
    certificates.dedup();
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use software_key_core::{
        digest::HashAlgorithm,
        software_key_agreement::derive_with_signing_key,
        software_signing::{KeyKind, SoftwareSigningKey},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Cleanup {
        store: WindowsPlatformCryptoProvider,
        name: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.name);
        }
    }
    fn unique_name() -> String {
        format!(
            "cng-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
    fn exercise_store(store: WindowsPlatformCryptoProvider) {
        let name = unique_name();
        let _cleanup = Cleanup {
            store,
            name: name.clone(),
        };
        let public = store.generate(&name).expect("generate persisted P-256 key");
        assert_eq!(
            store.generate(&name),
            Err(PlatformCryptoError::AlreadyExists)
        );
        assert_eq!(store.public_key(&name).unwrap(), public);
        assert!(store.list().unwrap().iter().any(|info| info.name == name));
        let PlatformAuthenticationCredential::Asymmetric(credential) =
            store.resolve(&name).unwrap()
        else {
            panic!()
        };
        let provider = store.provider().unwrap();
        let key = store.open(&provider, &name).unwrap();
        // Verify actual private export denial, beyond the policy property.
        let mut size = 0;
        assert_ne!(
            unsafe {
                NCryptExportKey(
                    key.0,
                    0,
                    BCRYPT_ECCPRIVATE_BLOB,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut size,
                    SILENT,
                )
            },
            0
        );
        drop(key);
        drop(provider);
        let peer = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let peer_public = peer.public_key();
        let SoftwarePublicKey::Ec { uncompressed, .. } = &public else {
            panic!()
        };
        let expected = derive_with_signing_key(&peer, uncompressed).unwrap();
        assert_eq!(
            credential.ecdh(&peer_public).unwrap().as_slice(),
            expected.as_slice()
        );
        assert_eq!(
            credential
                .derive_prefixed_x963(
                    &peer_public,
                    HashAlgorithm::Sha256,
                    b"prefix",
                    b"context",
                    64
                )
                .unwrap(),
            crate::prefixed_x963_kdf(HashAlgorithm::Sha256, b"prefix", &expected, b"context", 64)
                .unwrap()
        );
        let invalid = SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: vec![4; 65],
        };
        assert_eq!(
            credential.ecdh(&invalid),
            Err(PlatformCryptoError::InvalidPublicKey)
        );
        store.delete(&name).unwrap();
        assert_eq!(
            credential.ecdh(&peer_public),
            Err(PlatformCryptoError::NotFound)
        );
        assert_eq!(store.public_key(&name), Err(PlatformCryptoError::NotFound));
        let replacement = store.generate(&name).unwrap();
        assert_ne!(replacement, public);
        assert_eq!(
            credential.ecdh(&peer_public),
            Err(PlatformCryptoError::NotFound)
        );
        store.delete(&name).unwrap();
        assert!(!store.list().unwrap().iter().any(|info| info.name == name));
    }

    #[test]
    fn software_ksp_lifecycle_and_ecdh_interoperate() {
        // Only tests select the software KSP. Production always requires TPM.
        exercise_store(WindowsPlatformCryptoProvider {
            name: "Microsoft Software Key Storage Provider",
            require_hardware: false,
        });
    }

    #[test]
    #[ignore = "requires a Windows TPM supporting P-256 ECDH and raw-secret derivation"]
    fn tpm_ksp_lifecycle_and_ecdh_interoperate() {
        exercise_store(WindowsPlatformCryptoProvider::tpm());
    }

    #[test]
    fn public_blob_rejects_wrong_curve_length_and_invalid_points() {
        let peer = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
            .unwrap()
            .public_key();
        let blob = peer_blob(&peer).unwrap();
        assert_eq!(decode_public_blob(&blob).unwrap(), peer);
        let mut wrong = blob.clone();
        wrong[..4].copy_from_slice(&BCRYPT_ECDH_PUBLIC_P384_MAGIC.to_le_bytes());
        assert_eq!(
            decode_public_blob(&wrong),
            Err(PlatformCryptoError::InvalidPublicKey)
        );
        assert_eq!(
            decode_public_blob(&blob[..71]),
            Err(PlatformCryptoError::InvalidPublicKey)
        );
        wrong = blob;
        wrong[8..].fill(0);
        assert_eq!(
            decode_public_blob(&wrong),
            Err(PlatformCryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn certificate_lookup_matches_public_key_and_deduplicates() {
        // In-memory store: this test does not write the user's certificate store.
        let store = CertificateStore(unsafe {
            CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, ptr::null())
        });
        assert!(!store.0.is_null());
        let expected = SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: vec![
                0x04, 0x16, 0x64, 0xaa, 0x26, 0x33, 0xd6, 0xc7, 0x20, 0x71, 0x30, 0xb8, 0xeb, 0xb2,
                0xa1, 0xc0, 0x59, 0x95, 0xd8, 0x9b, 0x42, 0x1f, 0xbd, 0xba, 0xb0, 0x42, 0xce, 0x9c,
                0xa4, 0xe8, 0x86, 0xbe, 0xa3, 0x35, 0x53, 0xac, 0xd6, 0x34, 0x5d, 0xc9, 0xce, 0x9f,
                0xa4, 0x80, 0x62, 0xaa, 0x06, 0xd1, 0x6a, 0x85, 0x7d, 0xfa, 0x0d, 0x6e, 0x0c, 0x5c,
                0x39, 0xe4, 0x56, 0xa0, 0x9f, 0x28, 0xf6, 0xea, 0xaa,
            ],
        };
        assert!(
            matching_certificates_in_store(&store, &expected)
                .unwrap()
                .is_empty()
        );
        let certificate = include_bytes!("fixtures/cng-p256-certificate.der");
        let unrelated =
            include_bytes!("../../../certificates/yubihsm/yubihsm2-attestation-root.der");
        for encoded in [
            certificate.as_slice(),
            certificate.as_slice(),
            unrelated.as_slice(),
        ] {
            assert_ne!(
                unsafe {
                    CertAddEncodedCertificateToStore(
                        store.0,
                        X509_ASN_ENCODING,
                        encoded.as_ptr(),
                        encoded.len() as u32,
                        CERT_STORE_ADD_ALWAYS,
                        ptr::null_mut(),
                    )
                },
                0
            );
        }
        assert_eq!(
            matching_certificates_in_store(&store, &expected).unwrap(),
            vec![certificate.to_vec()]
        );
        let other = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
            .unwrap()
            .public_key();
        assert!(
            matching_certificates_in_store(&store, &other)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn software_provider_cannot_satisfy_hardware_requirement() {
        let store = WindowsPlatformCryptoProvider {
            name: "Microsoft Software Key Storage Provider",
            require_hardware: true,
        };
        assert!(matches!(
            store.provider(),
            Err(PlatformCryptoError::UnsupportedWithContext(_))
        ));
    }

    #[test]
    fn rollback_failure_reports_primary_error_and_remaining_key_name() {
        let original = unsupported("TPM key usage policy mismatch");
        let cleanup = backend_error("CNG delete key failed: 0x80090009");
        let message = rollback_error(&original, &cleanup, "cleanup-test").to_string();
        assert!(message.contains("TPM key usage policy mismatch"));
        assert!(message.contains("rollback also failed"));
        assert!(message.contains("0x80090009"));
        assert!(message.contains("pkcs11rs.yubihsm-auth.cleanup-test"));
    }

    #[test]
    fn tpm_policy_accepts_provider_metadata_but_rejects_other_permissions() {
        for metadata in [0, NCRYPT_TPM12_PROVIDER] {
            assert!(
                validate_policy_values(
                    0,
                    metadata | NCRYPT_PCP_ENCRYPTION_KEY,
                    NCRYPT_PCP_ENCRYPTION_KEY,
                    NCRYPT_TPM12_PROVIDER,
                    "TPM key usage policy"
                )
                .is_ok()
            );
            for usage in [
                0,
                NCRYPT_PCP_SIGNATURE_KEY,
                NCRYPT_PCP_SIGNATURE_KEY | NCRYPT_PCP_ENCRYPTION_KEY,
                NCRYPT_PCP_STORAGE_KEY | NCRYPT_PCP_ENCRYPTION_KEY,
                0x00100000 | NCRYPT_PCP_ENCRYPTION_KEY,
            ] {
                assert!(matches!(
                    validate_policy_values(
                        0,
                        metadata | usage,
                        NCRYPT_PCP_ENCRYPTION_KEY,
                        NCRYPT_TPM12_PROVIDER,
                        "TPM key usage policy"
                    ),
                    Err(PlatformCryptoError::UnsupportedWithContext(_))
                ));
            }
            assert!(matches!(
                validate_policy_values(
                    NCRYPT_ALLOW_EXPORT_FLAG,
                    metadata | NCRYPT_PCP_ENCRYPTION_KEY,
                    NCRYPT_PCP_ENCRYPTION_KEY,
                    NCRYPT_TPM12_PROVIDER,
                    "TPM key usage policy"
                ),
                Err(PlatformCryptoError::UnsupportedWithContext(_))
            ));
        }
        // Software policies have no such provider metadata exemption.
        assert!(matches!(
            validate_policy_values(
                0,
                NCRYPT_TPM12_PROVIDER | NCRYPT_ALLOW_KEY_AGREEMENT_FLAG,
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG,
                0,
                "software key usage"
            ),
            Err(PlatformCryptoError::UnsupportedWithContext(_))
        ));
    }

    #[test]
    fn unsupported_native_operation_preserves_error_code_and_operation() {
        let error = check(NTE_NOT_SUPPORTED, "read export policy").unwrap_err();
        assert!(matches!(
            error,
            PlatformCryptoError::UnsupportedWithContext(_)
        ));
        let message = error.to_string();
        assert!(message.contains("read export policy"));
        assert!(message.contains("0x80090029"));
    }

    #[test]
    fn invalid_names_fail_before_provider_access() {
        let store = WindowsPlatformCryptoProvider {
            name: "nonexistent provider",
            require_hardware: true,
        };
        for name in ["", "123", "bad:name", "bad\0name"] {
            assert_eq!(store.generate(name), Err(PlatformCryptoError::InvalidName));
            assert_eq!(
                store.public_key(name),
                Err(PlatformCryptoError::InvalidName)
            );
            assert_eq!(store.delete(name), Err(PlatformCryptoError::InvalidName));
            assert!(matches!(
                store.resolve(name),
                Err(PlatformCryptoError::InvalidName)
            ));
        }
    }
}
