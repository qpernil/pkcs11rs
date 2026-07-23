use der::Encode;
#[cfg(test)]
use der::{pem::LineEnding, EncodePem};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
#[cfg(any(test, feature = "abi-tests"))]
use rand_core::OsRng;
#[cfg(feature = "abi-tests")]
use rsa::RsaPublicKey;
#[cfg(any(test, feature = "abi-tests"))]
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use spki::SubjectPublicKeyInfoOwned;
#[cfg(any(test, feature = "abi-tests"))]
use std::sync::OnceLock;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn p256_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn rsa_key() -> RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::from_pkcs8_pem(include_str!("fixtures/test-rsa-private-key.pem"))
            .expect("valid RSA test fixture")
    })
    .clone()
}

pub(crate) fn p256_public_point(key: &VerifyingKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

#[cfg(test)]
pub(crate) fn p256_public_key_pem(key: &VerifyingKey) -> Vec<u8> {
    SubjectPublicKeyInfoOwned::from_key(*key)
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap()
        .into_bytes()
}

pub(crate) fn p256_certificate(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
    is_ca: bool,
) -> Vec<u8> {
    let profile = if is_ca {
        if subject == issuer {
            Profile::Root
        } else {
            Profile::SubCA {
                issuer: Name::from_str(issuer).unwrap(),
                path_len_constraint: None,
            }
        }
    } else {
        Profile::Leaf {
            issuer: Name::from_str(issuer).unwrap(),
            enable_key_agreement: true,
            enable_key_encipherment: false,
        }
    };
    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(86_400 * 3_650)).unwrap(),
        Name::from_str(subject).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(*subject_key).unwrap(),
        signer,
    )
    .unwrap();
    builder.build::<DerSignature>().unwrap().to_der().unwrap()
}

#[cfg(feature = "abi-tests")]
pub(crate) fn p256_certificate_for_rsa(
    public_key: &RsaPublicKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
) -> Vec<u8> {
    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: Name::from_str(issuer).unwrap(),
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(86_400 * 3_650)).unwrap(),
        Name::from_str(subject).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(public_key.clone()).unwrap(),
        signer,
    )
    .unwrap();
    builder.build::<DerSignature>().unwrap().to_der().unwrap()
}
