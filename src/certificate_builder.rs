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

#[cfg(test)]
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
    scp_oce: bool,
}

#[derive(Default)]
struct TestExtensions<'a> {
    ip_address: Option<&'a [u8]>,
    fido_aaguid: Option<[u8; 16]>,
    scp_oce: bool,
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
        subject_key: SubjectPublicKeyInfoRef<'_>,
        issuer_key: SubjectPublicKeyInfoRef<'_>,
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
        let mut usages = if self.scp_oce {
            KeyUsages::KeyAgreement.into()
        } else {
            KeyUsages::DigitalSignature.into()
        };
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
        if self.scp_oce {
            use der::asn1::OctetString;
            use software_key_core::digest::HashAlgorithm;
            use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
            let subject_id = SubjectKeyIdentifier(OctetString::new(
                HashAlgorithm::Sha1.digest(
                    subject_key
                        .subject_public_key
                        .as_bytes()
                        .expect("aligned public key"),
                ),
            )?);
            let issuer_id = AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(
                    HashAlgorithm::Sha1.digest(
                        issuer_key
                            .subject_public_key
                            .as_bytes()
                            .expect("aligned issuer key"),
                    ),
                )?),
                ..AuthorityKeyIdentifier::default()
            };
            extensions.push(subject_id.to_extension(tbs.subject(), &extensions)?);
            extensions.push(issuer_id.to_extension(tbs.subject(), &extensions)?);
            use x509_cert::ext::pkix::{CertificatePolicies, certpolicy::PolicyInformation};
            let policies = CertificatePolicies(vec![PolicyInformation {
                policy_identifier: const_oid::ObjectIdentifier::new_unwrap(
                    "1.2.840.114283.100.0.10.2.1.0",
                ),
                policy_qualifiers: None,
            }]);
            let mut extension = policies.to_extension(tbs.subject(), &extensions)?;
            extension.critical = true;
            extensions.push(extension);
        }
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

/// GlobalPlatform OCE key-agreement certificate, matching Yubico's SCP11 fixture policy.
#[cfg(all(test, not(feature = "abi-tests")))]
pub(crate) fn p256_scp11_oce_certificate(
    subject_key: &VerifyingKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    serial: u32,
) -> Vec<u8> {
    p256_certificate_with_extensions(
        subject_key,
        signer,
        subject,
        issuer,
        serial,
        false,
        TestExtensions {
            scp_oce: true,
            ..TestExtensions::default()
        },
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
        scp_oce: extensions.scp_oce,
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
            scp_oce: false,
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
