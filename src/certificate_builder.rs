use der::Encode;
#[cfg(test)]
use der::{pem::LineEnding, EncodePem};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
#[cfg(test)]
use rand_core::OsRng;
use rsa::{
    pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey},
    RsaPrivateKey,
};
use sha2::Sha256;
use signature::Keypair;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

#[cfg(test)]
pub(crate) fn p256_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
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

pub(crate) fn rsa_certificate(
    private_key: &RsaPrivateKey,
    subject: &str,
    serial: &[u8],
) -> Vec<u8> {
    let signer = RsaSigningKey::<Sha256>::new(private_key.clone());
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::new(serial).unwrap(),
        Validity::from_now(Duration::from_secs(86_400 * 3_650)).unwrap(),
        Name::from_str(subject).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap(),
        &signer,
    )
    .unwrap();
    builder.build::<RsaSignature>().unwrap().to_der().unwrap()
}
