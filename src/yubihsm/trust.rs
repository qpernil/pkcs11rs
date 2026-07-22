use super::parse_p256_public_key;
use crate::{Error, CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT};
use openssl::{
    memcmp,
    nid::Nid,
    pkey::{PKey, Public},
    sha::sha256,
    x509::X509,
};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::PathBuf,
};

pub(crate) const TRUST_PREFIX_ENV: &str = "PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX";

pub(crate) fn configured_prefix() -> OsString {
    env::var_os(TRUST_PREFIX_ENV).unwrap_or_default()
}

pub(crate) fn fingerprint(encoded_public_point: &[u8]) -> Result<String, Error> {
    let spki = device_spki(encoded_public_point)?;
    Ok(sha256(&spki)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn entry_path(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<PathBuf, Error> {
    let mut name = prefix
        .map(OsStr::to_os_string)
        .unwrap_or_else(configured_prefix);
    name.push(fingerprint(encoded_public_point)?);
    name.push(".pem");
    Ok(PathBuf::from(name))
}

pub(crate) fn validate_device_public_key(
    encoded_public_point: &[u8],
    prefix: Option<&OsStr>,
) -> Result<(), Error> {
    let expected = device_spki(encoded_public_point)?;
    let path = entry_path(encoded_public_point, prefix)?;
    let pem = fs::read(path).map_err(|_| Error::from(CKR_PIN_INCORRECT))?;
    let pinned = public_key_from_pem(&pem)?;
    let pinned = pinned.public_key_to_der().map_err(Error::from)?;
    if memcmp::eq(&expected, &pinned) {
        Ok(())
    } else {
        Err(CKR_PIN_INCORRECT.into())
    }
}

pub(crate) fn public_key_from_pem(pem: &[u8]) -> Result<PKey<Public>, Error> {
    let key = match X509::from_pem(pem) {
        Ok(certificate) => certificate.public_key().map_err(Error::from)?,
        Err(_) => PKey::public_key_from_pem(pem)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
    };
    let ec = key
        .ec_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    ec.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    PKey::from_ec_key(ec).map_err(Error::from)
}

fn device_spki(encoded_public_point: &[u8]) -> Result<Vec<u8>, Error> {
    let key = parse_p256_public_key(encoded_public_point)?;
    PKey::from_ec_key(key)?
        .public_key_to_der()
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey, PointConversionForm},
        hash::MessageDigest,
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
        let signing = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())
            .unwrap();
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
    fn fingerprint_is_sha256_of_canonical_spki() {
        let (key, point) = test_key();
        let expected: String = sha256(&key.public_key_to_der().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(fingerprint(&point).unwrap(), expected);
    }
}
