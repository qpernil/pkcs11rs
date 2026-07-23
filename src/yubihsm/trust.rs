use crate::{Error, CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT};
use p256::{
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
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
const YUBICO_ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certificates/yubihsm/yubihsm2-attestation-root.pem"
));
const YUBICO_INTERMEDIATE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certificates/yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem"
));
static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

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
    name.push(".pem");
    Ok(PathBuf::from(name))
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
    let pem = fs::read(path).map_err(|_| Error::from(CKR_PIN_INCORRECT))?;
    let pinned = public_key_from_pem(&pem)?;
    if bool::from(expected.ct_eq(&pinned)) {
        Ok(())
    } else {
        Err(CKR_PIN_INCORRECT.into())
    }
}

pub(crate) fn public_key_from_pem(pem: &[u8]) -> Result<Vec<u8>, Error> {
    if let Ok(public_key_info) = crate::certificate_chain::public_key_info(pem) {
        PublicKey::from_public_key_der(&public_key_info)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        return Ok(public_key_info);
    }
    let pem = std::str::from_utf8(pem).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    PublicKey::from_public_key_pem(pem)
        .and_then(|key| key.to_public_key_der())
        .map(|document| document.as_bytes().to_vec())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn install_public_key(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<[u8; 32], Error> {
    let key = PublicKey::from_sec1_bytes(encoded_public_point)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    install_pem(encoded_public_point, pem.as_bytes(), prefix, false)
}

pub(crate) fn install_attestation(
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
    let pem = crate::certificate_chain::encode_pem(&attestation)?;
    install_pem(encoded_public_point, pem.as_bytes(), prefix, true)
}

fn install_pem(
    encoded_public_point: &[u8],
    pem: &[u8],
    prefix: Option<&OsStr>,
    replace_matching_entry: bool,
) -> Result<[u8; 32], Error> {
    let path = entry_path(encoded_public_point, prefix)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        validate_device_public_key(encoded_public_point, prefix)?;
        if !replace_matching_entry {
            return fingerprint_bytes(encoded_public_point);
        }
    }

    let id = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
    let mut temporary_name = path.as_os_str().to_os_string();
    temporary_name.push(format!(".tmp-{}-{id}", std::process::id()));
    let temporary = PathBuf::from(temporary_name);
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        file.write_all(pem)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        fs::rename(&temporary, &path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        fingerprint_bytes(encoded_public_point)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
    use crate::yubihsm::parse_p256_public_key;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey, PointConversionForm},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private, Public},
        x509::{X509NameBuilder, X509},
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

    fn test_key() -> (PKey<Public>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let private = EcKey::generate(&group).unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        let point = private
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap();
        let public = parse_p256_public_key(&point).unwrap();
        (PKey::from_ec_key(public).unwrap(), point)
    }

    fn certificate_pem(key: &PKey<Public>) -> Vec<u8> {
        let signing =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
        let signing = PKey::from_ec_key(signing).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "pkcs11rs YubiHSM pin")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(key).unwrap();
        certificate
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        certificate
            .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        certificate.sign(&signing, MessageDigest::sha256()).unwrap();
        certificate.build().to_pem().unwrap()
    }

    fn signed_certificate(key: &PKey<Public>, signer: &PKey<Private>, serial: u32) -> X509 {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "pkcs11rs YubiHSM attestation")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(key).unwrap();
        certificate
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        certificate
            .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        certificate.sign(signer, MessageDigest::sha256()).unwrap();
        certificate.build()
    }

    fn private_key() -> PKey<Private> {
        PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap()
    }

    fn public_point(key: &PKey<Private>) -> Vec<u8> {
        let ec = key.ec_key().unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        ec.public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap()
    }

    fn public_key(key: &PKey<Private>) -> PKey<Public> {
        PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap()
    }

    fn unused_prefix() -> PathBuf {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("pkcs11rs-enroll-{id}-"))
    }

    fn with_entry(pem: &[u8], point: &[u8], test: impl FnOnce(&OsStr)) {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let prefix = std::env::temp_dir().join(format!("pkcs11rs-trust-{id}-"));
        let path = entry_path(point, Some(prefix.as_os_str())).unwrap();
        fs::write(&path, pem).unwrap();
        test(prefix.as_os_str());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn accepts_public_key_and_certificate_pem_entries() {
        let (key, point) = test_key();
        with_entry(&key.public_key_to_pem().unwrap(), &point, |prefix| {
            validate_device_public_key(&point, Some(prefix)).unwrap();
        });
        with_entry(&certificate_pem(&key), &point, |prefix| {
            validate_device_public_key(&point, Some(prefix)).unwrap();
        });
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
        let expected: String = Sha256::digest(key.public_key_to_der().unwrap())
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
            &attestation.to_der().unwrap(),
            &signer_certificate.to_der().unwrap(),
            AttestationValidation::ExplicitSigner,
            Some(prefix.as_os_str()),
        )
        .unwrap();

        assert_eq!(digest, fingerprint_bytes(&device_point).unwrap());
        validate_device_public_key(&device_point, Some(prefix.as_os_str())).unwrap();
        fs::remove_file(entry_path(&device_point, Some(prefix.as_os_str())).unwrap()).unwrap();
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
                &attestation.to_der().unwrap(),
                &wrong_certificate.to_der().unwrap(),
                AttestationValidation::ExplicitSigner,
                Some(unused_prefix().as_os_str()),
            ),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
    }

    #[test]
    fn embedded_yubico_intermediate_is_signed_by_embedded_root() {
        let intermediate = X509::from_pem(YUBICO_INTERMEDIATE).unwrap();
        let root = X509::from_pem(YUBICO_ROOT).unwrap();
        assert!(intermediate.verify(&root.public_key().unwrap()).unwrap());
    }
}
