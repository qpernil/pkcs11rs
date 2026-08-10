#[cfg(feature = "abi-tests")]
use der::Decode;
use der::Encode;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
#[cfg(any(test, feature = "abi-tests"))]
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
#[cfg(feature = "abi-tests")]
use rsa::{RsaPublicKey, pkcs8::EncodePublicKey};
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
#[cfg(any(test, feature = "abi-tests"))]
use std::sync::OnceLock;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName, name::GeneralName},
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
        let encoded = crate::private_key::decrypt(
            include_bytes!("fixtures/test-rsa-private-key.der"),
            b"test fixture",
        )
        .expect("decrypt RSA test fixture");
        RsaPrivateKey::from_pkcs8_der(&encoded).expect("valid RSA test fixture")
    })
    .clone()
}

pub(crate) fn p256_public_point(key: &VerifyingKey) -> Vec<u8> {
    key.to_sec1_point(false).as_bytes().to_vec()
}

struct TestProfile {
    subject: Name,
    issuer: Name,
    is_ca: bool,
    enable_key_agreement: bool,
    enable_key_encipherment: bool,
    subject_alt_ip_address: Option<Vec<u8>>,
    fido_aaguid: Option<[u8; 16]>,
}

#[derive(Default)]
struct TestExtensions<'a> {
    ip_address: Option<&'a [u8]>,
    fido_aaguid: Option<[u8; 16]>,
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
        if let Some(ip_address) = &self.subject_alt_ip_address {
            extensions.push(
                SubjectAltName(vec![GeneralName::IpAddress(der::asn1::OctetString::new(
                    ip_address.clone(),
                )?)])
                .to_extension(tbs.subject(), &extensions)?,
            );
        }
        if let Some(aaguid) = self.fido_aaguid {
            let value = der::asn1::OctetString::new(aaguid.to_vec())?.to_der()?;
            extensions.push(Extension {
                extn_id: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4"),
                critical: false,
                extn_value: der::asn1::OctetString::new(value)?,
            });
        }
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
    p256_certificate_with_extensions(
        subject_key,
        signer,
        subject,
        issuer,
        serial,
        is_ca,
        TestExtensions::default(),
    )
}

#[cfg(test)]
pub(crate) fn p256_tls_ip_certificate(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
    ip_address: &[u8],
) -> Vec<u8> {
    p256_certificate_with_extensions(
        subject_key,
        signer,
        subject,
        issuer,
        serial,
        false,
        TestExtensions {
            ip_address: Some(ip_address),
            ..TestExtensions::default()
        },
    )
}

#[cfg(test)]
pub(crate) fn p256_fido_attestation_certificate(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
    aaguid: [u8; 16],
) -> Vec<u8> {
    p256_certificate_with_extensions(
        subject_key,
        signer,
        subject,
        issuer,
        serial,
        false,
        TestExtensions {
            fido_aaguid: Some(aaguid),
            ..TestExtensions::default()
        },
    )
}

fn p256_certificate_with_extensions(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
    is_ca: bool,
    extensions: TestExtensions<'_>,
) -> Vec<u8> {
    let profile = TestProfile {
        subject: Name::from_str(subject).unwrap(),
        issuer: Name::from_str(issuer).unwrap(),
        is_ca,
        enable_key_agreement: !is_ca,
        enable_key_encipherment: false,
        subject_alt_ip_address: extensions.ip_address.map(ToOwned::to_owned),
        fido_aaguid: extensions.fido_aaguid,
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
            subject_alt_ip_address: None,
            fido_aaguid: None,
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
