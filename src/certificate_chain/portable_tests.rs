use super::*;
use p256::ecdsa::{DerSignature, SigningKey};
use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
    },
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
};

struct Profile {
    subject: Name,
    issuer: Name,
    extensions: Vec<Extension>,
}
impl BuilderProfile for Profile {
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn get_issuer(&self, _: &Name) -> Name {
        self.issuer.clone()
    }
    fn build_extensions(
        &self,
        _: spki::SubjectPublicKeyInfoRef<'_>,
        _: spki::SubjectPublicKeyInfoRef<'_>,
        _: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(self.extensions.clone())
    }
}

fn extensions(ca: bool, path_len: Option<u8>, signing: bool) -> Vec<Extension> {
    let subject = Name::from_str("CN=Test").unwrap();
    vec![
        BasicConstraints {
            ca,
            path_len_constraint: path_len,
        }
        .to_extension(&subject, &[])
        .unwrap(),
        KeyUsage(if signing {
            KeyUsages::KeyCertSign.into()
        } else {
            KeyUsages::DigitalSignature.into()
        })
        .to_extension(&subject, &[])
        .unwrap(),
    ]
}
fn critical(oid: &str, value: &[u8]) -> Extension {
    Extension {
        extn_id: ObjectIdentifier::new(oid).unwrap(),
        critical: true,
        extn_value: der::asn1::OctetString::new(value).unwrap(),
    }
}
fn certificate(
    key: &SigningKey,
    signer: &SigningKey,
    subject: &str,
    issuer: &str,
    extensions: Vec<Extension>,
    expired: bool,
) -> Vec<u8> {
    let now = SystemTime::now();
    let validity = Validity::new(
        Time::try_from(now - Duration::from_secs(3600)).unwrap(),
        Time::try_from(if expired {
            now - Duration::from_secs(60)
        } else {
            now + Duration::from_secs(86400)
        })
        .unwrap(),
    );
    CertificateBuilder::new(
        Profile {
            subject: Name::from_str(subject).unwrap(),
            issuer: Name::from_str(issuer).unwrap(),
            extensions,
        },
        SerialNumber::from(1u32),
        validity,
        spki::SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap(),
    )
    .unwrap()
    .build::<_, DerSignature>(signer)
    .unwrap()
    .to_der()
    .unwrap()
}

#[test]
fn intermediate_bundle_cannot_supply_roots_or_leaf_certificates() {
    let issuer = include_bytes!("../fixtures/yubikey-scp11b-issuer.der").to_vec();
    assert_eq!(
        decode_intermediate_bundle(&encode_bundle(std::slice::from_ref(&issuer)).unwrap()).unwrap(),
        vec![issuer]
    );
    for certificate in [
        include_bytes!("../fixtures/yubikey-scp11b-leaf.der").to_vec(),
        include_bytes!("../../certificates/yubikey/yubico-attestation-root-1.der").to_vec(),
    ] {
        assert!(decode_intermediate_bundle(&encode_bundle(&[certificate]).unwrap()).is_err());
    }
}

#[test]
fn portable_validation_enforces_ca_usage_and_anchor_path_length() {
    let root_key = crate::certificate_builder::p256_key();
    let issuer_key = crate::certificate_builder::p256_key();
    let leaf_key = crate::certificate_builder::p256_key();
    let root = certificate(
        &root_key,
        &root_key,
        "CN=Root",
        "CN=Root",
        extensions(true, None, true),
        false,
    );
    let trust = CertificateTrust::new(&[root]).unwrap();
    let leaf = certificate(
        &leaf_key,
        &issuer_key,
        "CN=Leaf",
        "CN=Issuer",
        extensions(false, None, false),
        false,
    );
    for (ca, signing, expected) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
    ] {
        let issuer = certificate(
            &issuer_key,
            &root_key,
            "CN=Issuer",
            "CN=Root",
            extensions(ca, None, signing),
            false,
        );
        assert_eq!(
            trust
                .validate_p256_public_point(&[issuer, leaf.clone()])
                .is_ok(),
            expected
        );
    }
    let constrained_root = certificate(
        &root_key,
        &root_key,
        "CN=Root",
        "CN=Root",
        extensions(true, Some(0), true),
        false,
    );
    let issuer = certificate(
        &issuer_key,
        &root_key,
        "CN=Issuer",
        "CN=Root",
        extensions(true, None, true),
        false,
    );
    assert!(
        CertificateTrust::new(&[constrained_root])
            .unwrap()
            .validate_p256_public_point(&[issuer.clone(), leaf])
            .is_err()
    );
    assert!(trust.validate_p256_public_point(&[issuer]).is_err());
}

#[test]
fn portable_validation_processes_critical_policy_constraints() {
    let root_key = crate::certificate_builder::p256_key();
    let issuer_key = crate::certificate_builder::p256_key();
    let leaf_key = crate::certificate_builder::p256_key();
    let root = certificate(
        &root_key,
        &root_key,
        "CN=Root",
        "CN=Root",
        extensions(true, None, true),
        false,
    );
    let trust = CertificateTrust::new(&[root]).unwrap();
    let policy = critical("2.5.29.32", &[0x30, 7, 0x30, 5, 6, 3, 0x2a, 3, 4]);
    let mut issuer_extensions = extensions(true, None, true);
    issuer_extensions.extend([
        policy.clone(),
        critical("2.5.29.36", &[0x30, 3, 0x80, 1, 0]),
    ]);
    let issuer = certificate(
        &issuer_key,
        &root_key,
        "CN=Issuer",
        "CN=Root",
        issuer_extensions,
        false,
    );
    for (extra, expected) in [
        (vec![], false),
        (vec![policy], true),
        (vec![critical("2.5.29.32", &[0x30, 1, 0xff])], false),
    ] {
        let mut leaf_extensions = extensions(false, None, false);
        leaf_extensions.extend(extra);
        let leaf = certificate(
            &leaf_key,
            &issuer_key,
            "CN=Leaf",
            "CN=Issuer",
            leaf_extensions,
            false,
        );
        assert_eq!(
            trust
                .validate_p256_public_point(&[issuer.clone(), leaf])
                .is_ok(),
            expected
        );
    }
}

#[test]
fn bare_ca_key_accepts_critical_oce_policy_without_trusting_presented_keys() {
    use software_key_core::certificate_chain::CertificateTrust as CoreTrust;
    let ca = crate::certificate_builder::p256_key();
    let other_ca = crate::certificate_builder::p256_key();
    let host = crate::certificate_builder::p256_key();
    let point = ca.verifying_key().to_sec1_point(false);
    let leaf = crate::certificate_builder::p256_scp11_oce_certificate(
        host.verifying_key(),
        &ca,
        "CN=Host",
        "CN=CA",
        10,
    );
    assert_eq!(
        CoreTrust::validate_with_p256_ca_key(point.as_bytes(), std::slice::from_ref(&leaf))
            .unwrap(),
        host.verifying_key().to_sec1_point(false).as_bytes(),
    );
    let other_point = other_ca.verifying_key().to_sec1_point(false);
    assert!(
        CoreTrust::validate_with_p256_ca_key(other_point.as_bytes(), std::slice::from_ref(&leaf))
            .is_err()
    );
    assert!(
        CoreTrust::validate_with_p256_ca_key(&point.as_bytes()[1..], std::slice::from_ref(&leaf))
            .is_err()
    );
    let mut tampered = leaf.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(CoreTrust::validate_with_p256_ca_key(point.as_bytes(), &[tampered]).is_err());
    let unrelated_root = crate::certificate_builder::p256_certificate(
        other_ca.verifying_key(),
        &other_ca,
        "CN=CA",
        "CN=CA",
        11,
        true,
    );
    assert!(
        CoreTrust::validate_with_p256_ca_key(other_point.as_bytes(), &[unrelated_root, leaf])
            .is_err()
    );
}

#[test]
fn bare_ca_key_enforces_validity_usage_and_critical_extensions() {
    use software_key_core::certificate_chain::CertificateTrust as CoreTrust;
    let ca = crate::certificate_builder::p256_key();
    let host = crate::certificate_builder::p256_key();
    let point = ca.verifying_key().to_sec1_point(false);
    let name = Name::from_str("CN=Host").unwrap();
    let agreement = KeyUsage(KeyUsages::KeyAgreement.into())
        .to_extension(&name, &[])
        .unwrap();
    for (case, (expired, usage, extra, expected)) in [
        (false, agreement.clone(), vec![], true),
        (true, agreement.clone(), vec![], false),
        (
            false,
            extensions(false, None, false)[1].clone(),
            vec![],
            false,
        ),
        (
            false,
            agreement.clone(),
            vec![critical("1.2.3.4", &[0x05, 0])],
            false,
        ),
        (
            false,
            agreement,
            vec![critical("2.5.29.32", &[0x30, 1, 0xff])],
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut ext = vec![extensions(false, None, false)[0].clone(), usage];
        ext.extend(extra);
        let leaf = certificate(&host, &ca, "CN=Host", "CN=CA", ext, expired);
        assert_eq!(
            CoreTrust::validate_with_p256_ca_key(point.as_bytes(), &[leaf]).is_ok(),
            expected,
            "case={case}"
        );
    }
}

#[test]
fn portable_validation_rejects_expiry_and_unknown_critical_extensions() {
    let root_key = crate::certificate_builder::p256_key();
    let leaf_key = crate::certificate_builder::p256_key();
    let root = certificate(
        &root_key,
        &root_key,
        "CN=Root",
        "CN=Root",
        extensions(true, None, true),
        false,
    );
    let trust = CertificateTrust::new(&[root]).unwrap();
    let expired = certificate(
        &leaf_key,
        &root_key,
        "CN=Leaf",
        "CN=Root",
        extensions(false, None, false),
        true,
    );
    assert!(trust.validate_p256_public_point(&[expired]).is_err());
    let mut leaf_extensions = extensions(false, None, false);
    leaf_extensions.push(critical("1.2.3.9", &[5, 0]));
    let unknown = certificate(
        &leaf_key,
        &root_key,
        "CN=Leaf",
        "CN=Root",
        leaf_extensions,
        false,
    );
    assert!(trust.validate_p256_public_point(&[unknown]).is_err());
}
