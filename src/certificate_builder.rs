#[cfg(feature = "abi-tests")]
use der::Decode;
use der::Encode;
#[cfg(test)]
use der::{pem::LineEnding, EncodePem};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
#[cfg(any(test, feature = "abi-tests"))]
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
#[cfg(feature = "abi-tests")]
use rsa::{pkcs8::EncodePublicKey, RsaPublicKey};
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
#[cfg(any(test, feature = "abi-tests"))]
use std::sync::OnceLock;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    certificate::TbsCertificate,
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Extension, ToExtension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) fn p256_key() -> SigningKey {
    SigningKey::generate()
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
    key.to_sec1_point(false).as_bytes().to_vec()
}

#[cfg(test)]
pub(crate) fn p256_public_key_pem(key: &VerifyingKey) -> Vec<u8> {
    SubjectPublicKeyInfoOwned::from_key(key)
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap()
        .into_bytes()
}

struct TestProfile {
    subject: Name,
    issuer: Name,
    is_ca: bool,
    enable_key_agreement: bool,
    enable_key_encipherment: bool,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _subject_key: SubjectPublicKeyInfoRef<'_>,
        _issuer_key: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = Vec::new();
        extensions.push(
            BasicConstraints {
                ca: self.is_ca,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        let mut usages = KeyUsages::DigitalSignature.into();
        if self.is_ca {
            usages |= KeyUsages::KeyCertSign | KeyUsages::CRLSign;
        }
        if self.enable_key_agreement {
            usages |= KeyUsages::KeyAgreement;
        }
        if self.enable_key_encipherment {
            usages |= KeyUsages::KeyEncipherment;
        }
        extensions.push(KeyUsage(usages).to_extension(tbs.subject(), &extensions)?);
        Ok(extensions)
    }
}

pub(crate) fn p256_certificate(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
    is_ca: bool,
) -> Vec<u8> {
    let profile = TestProfile {
        subject: Name::from_str(subject).unwrap(),
        issuer: Name::from_str(issuer).unwrap(),
        is_ca,
        enable_key_agreement: !is_ca,
        enable_key_encipherment: false,
    };
    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(86_400 * 3_650)).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(subject_key).unwrap(),
    )
    .unwrap();
    builder
        .build::<_, DerSignature>(signer)
        .unwrap()
        .to_der()
        .unwrap()
}

#[cfg(feature = "abi-tests")]
pub(crate) fn p256_certificate_for_rsa(
    public_key: &RsaPublicKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
) -> Vec<u8> {
    let public_key_der = public_key.to_public_key_der().unwrap();
    let builder = CertificateBuilder::new(
        TestProfile {
            subject: Name::from_str(subject).unwrap(),
            issuer: Name::from_str(issuer).unwrap(),
            is_ca: false,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(86_400 * 3_650)).unwrap(),
        SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes()).unwrap(),
    )
    .unwrap();
    builder
        .build::<_, DerSignature>(signer)
        .unwrap()
        .to_der()
        .unwrap()
}
