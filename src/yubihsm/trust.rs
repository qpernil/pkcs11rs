use crate::{Error, CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT};
use minicbor::{Decoder, Encoder};
use p256::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    PublicKey,
};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use subtle::ConstantTimeEq;

pub(crate) const TRUST_PREFIX_ENV: &str = "PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX";
const TRUST_RECORD_SCHEMA: &str = "pkcs11rs.yubihsm-device-trust";
const TRUST_RECORD_VERSION: u64 = 1;
const TRUST_RECORD_PUBLIC_KEY: u8 = 1;
const TRUST_RECORD_ATTESTATION_CERTIFICATE: u8 = 2;
const YUBICO_ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certificates/yubihsm/yubihsm2-attestation-root.pem"
));
const YUBICO_INTERMEDIATE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certificates/yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem"
));
pub(crate) struct TrustStore {
    next_temporary_file: AtomicU64,
}

impl TrustStore {
    pub(crate) fn new() -> Self {
        Self {
            next_temporary_file: AtomicU64::new(1),
        }
    }

    pub(crate) fn install_public_key(
        &self,
        encoded_public_point: &[u8],
        prefix: Option<&OsStr>,
    ) -> Result<[u8; 32], Error> {
        let spki = device_spki(encoded_public_point)?;
        self.install_record(
            encoded_public_point,
            TRUST_RECORD_PUBLIC_KEY,
            &spki,
            prefix,
            false,
        )
    }

    pub(crate) fn install_attestation(
        &self,
        encoded_public_point: &[u8],
        attestation: &[u8],
        device_certificate: &[u8],
        validation: AttestationValidation,
        prefix: Option<&OsStr>,
    ) -> Result<[u8; 32], Error> {
        let attestation = crate::certificate_chain::decode(attestation)?;
        let device_certificate = crate::certificate_chain::decode(device_certificate)?;
        match validation {
            AttestationValidation::ExplicitSigner => {
                crate::certificate_chain::verify_signed_by(&attestation, &device_certificate)
                    .map_err(|_| Error::from(CKR_PIN_INCORRECT))?;
            }
            AttestationValidation::Yubico => {
                let intermediate = crate::certificate_chain::decode(YUBICO_INTERMEDIATE)?;
                let root = crate::certificate_chain::decode(YUBICO_ROOT)?;
                crate::certificate_chain::validate_p256_public_point(
                    &[intermediate, device_certificate, attestation.clone()],
                    &[root],
                )?;
            }
        }
        if !bool::from(
            device_spki(encoded_public_point)?
                .ct_eq(&crate::certificate_chain::public_key_info(&attestation)?),
        ) {
            return Err(CKR_PIN_INCORRECT.into());
        }
        self.install_record(
            encoded_public_point,
            TRUST_RECORD_ATTESTATION_CERTIFICATE,
            &attestation,
            prefix,
            true,
        )
    }

    fn install_record(
        &self,
        encoded_public_point: &[u8],
        kind: u8,
        payload: &[u8],
        prefix: Option<&OsStr>,
        replace_matching_entry: bool,
    ) -> Result<[u8; 32], Error> {
        let fingerprint = fingerprint_bytes(encoded_public_point)?;
        let encoded = encode_trust_record(kind, &fingerprint, payload)?;
        let path = entry_path(encoded_public_point, prefix)?;
        let current_metadata = fs::symlink_metadata(&path).ok();
        if current_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if current_metadata.is_some() {
            validate_device_public_key(encoded_public_point, prefix)?;
            if !replace_matching_entry {
                return Ok(fingerprint);
            }
        }

        let id = self.next_temporary_file.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = path.as_os_str().to_os_string();
        temporary_name.push(format!(".tmp-{}-{id}", std::process::id()));
        let temporary = PathBuf::from(temporary_name);
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            file.write_all(&encoded)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            fs::rename(&temporary, &path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            Ok(fingerprint)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttestationValidation {
    ExplicitSigner,
    Yubico,
}

pub(crate) fn configured_prefix() -> OsString {
    env::var_os(TRUST_PREFIX_ENV).unwrap_or_default()
}

pub(crate) fn fingerprint(encoded_public_point: &[u8]) -> Result<String, Error> {
    Ok(fingerprint_bytes(encoded_public_point)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn fingerprint_bytes(encoded_public_point: &[u8]) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(device_spki(encoded_public_point)?).into())
}

pub(crate) fn entry_path(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<PathBuf, Error> {
    let mut name = prefix
        .map(OsStr::to_os_string)
        .unwrap_or_else(configured_prefix);
    if name.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    name.push(fingerprint(encoded_public_point)?);
    name.push(".cbor");
    Ok(PathBuf::from(name))
}

fn encode_trust_record(kind: u8, fingerprint: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .array(5)
        .and_then(|encoder| encoder.str(TRUST_RECORD_SCHEMA))
        .and_then(|encoder| encoder.u64(TRUST_RECORD_VERSION))
        .and_then(|encoder| encoder.u8(kind))
        .and_then(|encoder| encoder.bytes(fingerprint))
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    Ok(encoded)
}

pub(crate) fn decode_trust_record(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = Decoder::new(encoded);
    if decoder.array().map_err(|_| CKR_ARGUMENTS_BAD)? != Some(5)
        || decoder.str().map_err(|_| CKR_ARGUMENTS_BAD)? != TRUST_RECORD_SCHEMA
        || decoder.u64().map_err(|_| CKR_ARGUMENTS_BAD)? != TRUST_RECORD_VERSION
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let kind = decoder.u8().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let fingerprint: [u8; 32] = decoder
        .bytes()
        .map_err(|_| CKR_ARGUMENTS_BAD)?
        .try_into()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let payload = decoder.bytes().map_err(|_| CKR_ARGUMENTS_BAD)?;
    if decoder.position() != encoded.len()
        || encode_trust_record(kind, &fingerprint, payload)? != encoded
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let pinned = match kind {
        TRUST_RECORD_PUBLIC_KEY => {
            let key = PublicKey::from_public_key_der(payload)
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            let canonical = key
                .to_public_key_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            if canonical.as_bytes() != payload {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            canonical.as_bytes().to_vec()
        }
        TRUST_RECORD_ATTESTATION_CERTIFICATE => {
            let certificate = crate::certificate_chain::decode(payload)?;
            if certificate != payload {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            let pinned = crate::certificate_chain::public_key_info(&certificate)?;
            PublicKey::from_public_key_der(&pinned).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            pinned
        }
        _ => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    let actual: [u8; 32] = Sha256::digest(&pinned).into();
    if !bool::from(actual.ct_eq(&fingerprint)) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(pinned)
}

pub(crate) fn validate_device_public_key(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<(), Error> {
    let prefix = prefix
        .map(OsStr::to_os_string)
        .unwrap_or_else(configured_prefix);
    if prefix.is_empty() {
        log!(
            2,
            "YubiHSM device trust is not configured; accepting an unpinned device key"
        );
        return Ok(());
    }
    let expected = device_spki(encoded_public_point)?;
    let path = entry_path(encoded_public_point, Some(prefix.as_os_str()))?;
    let encoded = fs::read(&path).map_err(|_| Error::from(CKR_PIN_INCORRECT))?;
    let pinned = decode_trust_record(&encoded)?;
    if bool::from(expected.ct_eq(&pinned)) {
        Ok(())
    } else {
        Err(CKR_PIN_INCORRECT.into())
    }
}

#[cfg(test)]
pub(crate) fn install_public_key(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<[u8; 32], Error> {
    TrustStore::new().install_public_key(encoded_public_point, prefix)
}

#[cfg(test)]
pub(crate) fn install_attestation(
    encoded_public_point: &[u8],
    attestation: &[u8],
    device_certificate: &[u8],
    validation: AttestationValidation,
    prefix: Option<&OsStr>,
) -> Result<[u8; 32], Error> {
    TrustStore::new().install_attestation(
        encoded_public_point,
        attestation,
        device_certificate,
        validation,
        prefix,
    )
}

pub(crate) fn device_spki(encoded_public_point: &[u8]) -> Result<Vec<u8>, Error> {
    let key = PublicKey::from_sec1_bytes(encoded_public_point)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    key.to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use spki::SubjectPublicKeyInfoOwned;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

    fn test_key() -> (VerifyingKey, Vec<u8>) {
        let private = crate::certificate_builder::p256_key();
        let public = *private.verifying_key();
        let point = crate::certificate_builder::p256_public_point(&public);
        (public, point)
    }

    fn signed_certificate(key: &VerifyingKey, signer: &SigningKey, serial: u32) -> Vec<u8> {
        crate::certificate_builder::p256_certificate(
            key,
            signer,
            "CN=pkcs11rs YubiHSM attestation",
            "CN=pkcs11rs YubiHSM attestation",
            serial,
            false,
        )
    }

    fn private_key() -> SigningKey {
        crate::certificate_builder::p256_key()
    }

    fn public_point(key: &SigningKey) -> Vec<u8> {
        crate::certificate_builder::p256_public_point(key.verifying_key())
    }

    fn public_key(key: &SigningKey) -> VerifyingKey {
        *key.verifying_key()
    }

    fn unused_prefix() -> PathBuf {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("pkcs11rs-enroll-{id}-"))
    }

    #[test]
    fn installed_public_key_is_a_canonical_cbor_record() {
        let (_, point) = test_key();
        let prefix = unused_prefix();
        let path = entry_path(&point, Some(prefix.as_os_str())).unwrap();

        install_public_key(&point, Some(prefix.as_os_str())).unwrap();
        let encoded = fs::read(&path).unwrap();

        assert_eq!(path.extension(), Some(OsStr::new("cbor")));
        assert_eq!(
            decode_trust_record(&encoded).unwrap(),
            device_spki(&point).unwrap()
        );
        assert_eq!(
            encode_trust_record(
                TRUST_RECORD_PUBLIC_KEY,
                &fingerprint_bytes(&point).unwrap(),
                &device_spki(&point).unwrap(),
            )
            .unwrap(),
            encoded
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_cbor_fails_closed() {
        let (_, point) = test_key();
        let prefix = unused_prefix();
        let path = entry_path(&point, Some(prefix.as_os_str())).unwrap();
        fs::write(&path, [0x81, 0x01]).unwrap();

        assert!(matches!(
            validate_device_public_key(&point, Some(prefix.as_os_str())),
            Err(Error::Generic(rv)) if rv == CKR_ARGUMENTS_BAD as _
        ));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trust_record_rejects_unknown_kinds_tampering_and_trailing_data() {
        let (_, point) = test_key();
        let spki = device_spki(&point).unwrap();
        let fingerprint = fingerprint_bytes(&point).unwrap();

        let unknown = encode_trust_record(0xff, &fingerprint, &spki).unwrap();
        assert!(decode_trust_record(&unknown).is_err());

        let mut wrong_fingerprint = fingerprint;
        wrong_fingerprint[0] ^= 1;
        let tampered =
            encode_trust_record(TRUST_RECORD_PUBLIC_KEY, &wrong_fingerprint, &spki).unwrap();
        assert!(decode_trust_record(&tampered).is_err());

        let mut trailing =
            encode_trust_record(TRUST_RECORD_PUBLIC_KEY, &fingerprint, &spki).unwrap();
        trailing.push(0);
        assert!(decode_trust_record(&trailing).is_err());
    }

    #[test]
    fn accepts_an_unpinned_device_when_trust_is_not_configured() {
        let (_, point) = test_key();
        validate_device_public_key(&point, Some(OsStr::new(""))).unwrap();
    }

    #[test]
    fn configured_trust_requires_the_exact_device_entry() {
        let (_, point) = test_key();
        let prefix = unused_prefix();
        assert!(matches!(
            validate_device_public_key(&point, Some(prefix.as_os_str())),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
    }

    #[test]
    fn enrollment_requires_a_configured_trust_prefix() {
        let (_, point) = test_key();
        assert!(matches!(
            install_public_key(&point, Some(OsStr::new(""))),
            Err(Error::Generic(rv)) if rv == CKR_ARGUMENTS_BAD as _
        ));
    }

    #[test]
    fn fingerprint_is_sha256_of_canonical_spki() {
        let (key, point) = test_key();
        let expected: String = Sha256::digest(
            SubjectPublicKeyInfoOwned::from_key(&key)
                .unwrap()
                .to_der()
                .unwrap(),
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
        assert_eq!(fingerprint(&point).unwrap(), expected);
    }

    #[test]
    fn installs_device_attestation_certificate() {
        let device_key = private_key();
        let device_point = public_point(&device_key);
        let signer = private_key();
        let signer_certificate = signed_certificate(&public_key(&signer), &signer, 1);
        let attestation = signed_certificate(&public_key(&device_key), &signer, 2);
        let prefix = unused_prefix();

        let digest = install_attestation(
            &device_point,
            &attestation,
            &signer_certificate,
            AttestationValidation::ExplicitSigner,
            Some(prefix.as_os_str()),
        )
        .unwrap();

        assert_eq!(digest, fingerprint_bytes(&device_point).unwrap());
        validate_device_public_key(&device_point, Some(prefix.as_os_str())).unwrap();
        fs::remove_file(entry_path(&device_point, Some(prefix.as_os_str())).unwrap()).unwrap();
    }

    #[test]
    fn attestation_replaces_existing_public_key_entry() {
        let device_key = private_key();
        let device_point = public_point(&device_key);
        let signer = private_key();
        let signer_certificate = signed_certificate(&public_key(&signer), &signer, 1);
        let attestation = signed_certificate(&public_key(&device_key), &signer, 2);
        let prefix = unused_prefix();
        let path = entry_path(&device_point, Some(prefix.as_os_str())).unwrap();

        install_public_key(&device_point, Some(prefix.as_os_str())).unwrap();
        let public_key_record = fs::read(&path).unwrap();
        install_attestation(
            &device_point,
            &attestation,
            &signer_certificate,
            AttestationValidation::ExplicitSigner,
            Some(prefix.as_os_str()),
        )
        .unwrap();

        let attestation_record = fs::read(&path).unwrap();
        assert_ne!(attestation_record, public_key_record);
        assert_eq!(
            decode_trust_record(&attestation_record).unwrap(),
            device_spki(&device_point).unwrap()
        );
        validate_device_public_key(&device_point, Some(prefix.as_os_str())).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_attestation_signed_by_another_key() {
        let device_key = private_key();
        let device_point = public_point(&device_key);
        let signer = private_key();
        let wrong_signer = private_key();
        let wrong_certificate = signed_certificate(&public_key(&wrong_signer), &wrong_signer, 1);
        let attestation = signed_certificate(&public_key(&device_key), &signer, 2);

        assert!(matches!(
            install_attestation(
                &device_point,
                &attestation,
                &wrong_certificate,
                AttestationValidation::ExplicitSigner,
                Some(unused_prefix().as_os_str()),
            ),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
    }

    #[test]
    fn embedded_yubico_intermediate_is_signed_by_embedded_root() {
        crate::certificate_chain::verify_signed_by(YUBICO_INTERMEDIATE, YUBICO_ROOT).unwrap();
    }
}
