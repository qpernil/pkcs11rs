use crate::{Error, CKR_ARGUMENTS_BAD};
use const_oid::ObjectIdentifier;
use der::{
    asn1::ObjectIdentifier as DerObjectIdentifier, pem::LineEnding, Decode, DecodePem, Encode,
    EncodePem,
};
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, fs};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_cert::{
    ext::pkix::{BasicConstraints, KeyUsage},
    Certificate,
};

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const AUTHORITY_INFORMATION_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

type Fingerprint = [u8; 32];

fn supported_signature_algorithms(
) -> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] {
    webpki::ALL_VERIFICATION_ALGS
}

#[derive(Clone, Copy)]
struct AttestationUsage;

impl ExtendedKeyUsageValidator for AttestationUsage {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in purposes {
            purpose?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ParsedCertificate {
    certificate: Certificate,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    fingerprint: Fingerprint,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
    can_sign_certificates: bool,
}

impl ParsedCertificate {
    fn parse(encoded: &[u8]) -> Result<Self, Error> {
        let certificate =
            Certificate::from_der(encoded).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        if certificate.signature_algorithm != certificate.tbs_certificate.signature {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        validate_critical_extensions(&certificate)?;
        let basic_constraints = certificate
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?
            .map(|(_, constraints)| constraints);
        let key_usage = certificate
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?
            .map(|(_, usage)| usage);
        let encoded = certificate
            .to_der()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;

        Ok(Self {
            subject: certificate
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
            issuer: certificate
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
            fingerprint: Sha256::digest(&encoded).into(),
            not_before: certificate
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
            not_after: certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
            is_ca: basic_constraints
                .as_ref()
                .is_some_and(|constraints| constraints.ca),
            can_sign_certificates: key_usage.as_ref().is_none_or(KeyUsage::key_cert_sign),
            certificate,
        })
    }

    fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    fn is_valid_at(&self, timestamp: u64) -> bool {
        self.not_before <= timestamp && timestamp <= self.not_after
    }

    fn verify_signature(&self, issuer: &Self) -> Result<(), Error> {
        verify_certificate_signature(&self.certificate, &issuer.certificate)
    }

    fn p256_public_point(&self) -> Result<Vec<u8>, Error> {
        let spki = &self.certificate.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != EC_PUBLIC_KEY || algorithm_parameter_oid(spki)? != P256_CURVE {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CKR_ARGUMENTS_BAD)?;
        P256VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        Ok(point.to_vec())
    }
}

#[derive(Clone)]
pub(crate) struct CertificateTrust {
    trust_anchors: Vec<TrustAnchor<'static>>,
    local_intermediates: Vec<CertificateDer<'static>>,
    root_fingerprints: HashSet<Fingerprint>,
    fingerprint: Fingerprint,
}

impl CertificateTrust {
    pub(crate) fn new(certificates: &[Vec<u8>]) -> Result<Self, Error> {
        if certificates.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let local = parse_unique(certificates)?;
        let now = UnixTime::now().as_secs();
        let mut trust_anchors = Vec::new();
        let mut local_intermediates = Vec::new();
        let mut root_fingerprints = HashSet::new();

        for certificate in &local {
            if certificate.is_self_issued() {
                if !certificate.is_ca
                    || !certificate.can_sign_certificates
                    || !certificate.is_valid_at(now)
                    || certificate.verify_signature(certificate).is_err()
                {
                    return Err(CKR_ARGUMENTS_BAD.into());
                }
                let encoded = CertificateDer::from(
                    certificate
                        .certificate
                        .to_der()
                        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
                );
                let anchor = webpki::anchor_from_trusted_cert(&encoded)
                    .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?
                    .to_owned();
                trust_anchors.push(anchor);
                root_fingerprints.insert(certificate.fingerprint);
            } else {
                local_intermediates.push(CertificateDer::from(
                    certificate
                        .certificate
                        .to_der()
                        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
                ));
            }
        }
        if trust_anchors.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        let mut fingerprints = local
            .iter()
            .map(|certificate| certificate.fingerprint)
            .collect::<Vec<_>>();
        fingerprints.sort_unstable();
        let fingerprint = Sha256::digest(fingerprints.concat()).into();
        Ok(Self {
            trust_anchors,
            local_intermediates,
            root_fingerprints,
            fingerprint,
        })
    }

    pub(crate) fn validate_p256_public_point(
        &self,
        certificates: &[Vec<u8>],
    ) -> Result<Vec<u8>, Error> {
        self.validate(certificates)?.p256_public_point()
    }

    pub(crate) fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    fn validate(&self, certificates: &[Vec<u8>]) -> Result<ParsedCertificate, Error> {
        let leaf = certificates.last().ok_or(CKR_ARGUMENTS_BAD)?;
        let leaf_der = CertificateDer::from(leaf.as_slice());
        let end_entity =
            EndEntityCert::try_from(&leaf_der).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let mut fingerprints = self.root_fingerprints.clone();
        let mut intermediates = Vec::new();
        for certificate in &self.local_intermediates {
            let fingerprint: Fingerprint = Sha256::digest(certificate.as_ref()).into();
            if fingerprints.insert(fingerprint) {
                intermediates.push(certificate.clone());
            }
        }
        for certificate in &certificates[..certificates.len() - 1] {
            let fingerprint: Fingerprint = Sha256::digest(certificate).into();
            if fingerprints.insert(fingerprint) {
                intermediates.push(CertificateDer::from(certificate.clone()));
            }
        }
        end_entity
            .verify_for_usage(
                supported_signature_algorithms(),
                &self.trust_anchors,
                &intermediates,
                UnixTime::now(),
                AttestationUsage,
                None,
                None,
            )
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        ParsedCertificate::parse(leaf)
    }
}

fn parse_unique(certificates: &[Vec<u8>]) -> Result<Vec<ParsedCertificate>, Error> {
    let mut fingerprints = HashSet::new();
    certificates
        .iter()
        .map(|encoded| ParsedCertificate::parse(encoded))
        .filter_map(|result| match result {
            Ok(certificate) if fingerprints.insert(certificate.fingerprint) => {
                Some(Ok(certificate))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn validate_critical_extensions(certificate: &Certificate) -> Result<(), Error> {
    const SUPPORTED: &[ObjectIdentifier] = &[
        SUBJECT_KEY_IDENTIFIER,
        KEY_USAGE,
        SUBJECT_ALT_NAME,
        BASIC_CONSTRAINTS,
        CERTIFICATE_POLICIES,
        EXTENDED_KEY_USAGE,
        AUTHORITY_KEY_IDENTIFIER,
        CRL_DISTRIBUTION_POINTS,
        AUTHORITY_INFORMATION_ACCESS,
    ];
    if certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|extension| extension.critical && !SUPPORTED.contains(&extension.extn_id))
    {
        Err(CKR_ARGUMENTS_BAD.into())
    } else {
        Ok(())
    }
}

fn algorithm_parameter_oid(
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<DerObjectIdentifier, Error> {
    spki.algorithm
        .parameters
        .as_ref()
        .ok_or(CKR_ARGUMENTS_BAD)?
        .decode_as::<DerObjectIdentifier>()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

fn algorithm_identifier_contents(
    algorithm: &spki::AlgorithmIdentifierOwned,
) -> Result<Vec<u8>, Error> {
    let mut encoded = algorithm
        .oid
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    if let Some(parameters) = &algorithm.parameters {
        encoded.extend(
            parameters
                .to_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
        );
    }
    Ok(encoded)
}

fn verify_certificate_signature(
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<(), Error> {
    if certificate.signature_algorithm != certificate.tbs_certificate.signature {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_algorithm = algorithm_identifier_contents(&certificate.signature_algorithm)?;
    let public_key_algorithm = algorithm_identifier_contents(
        &issuer.tbs_certificate.subject_public_key_info.algorithm,
    )?;
    let algorithm = supported_signature_algorithms()
        .iter()
        .copied()
        .find(|algorithm| {
            algorithm.signature_alg_id().as_ref() == signature_algorithm
                && algorithm.public_key_alg_id().as_ref() == public_key_algorithm
        })
        .ok_or(CKR_ARGUMENTS_BAD)?;
    let issuer_der = CertificateDer::from(
        issuer
            .to_der()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
    );
    let issuer =
        EndEntityCert::try_from(&issuer_der).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let message = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(CKR_ARGUMENTS_BAD)?;
    issuer
        .verify_signature(algorithm, &message, signature)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn load(paths: &str) -> Result<Vec<Vec<u8>>, Error> {
    let mut certificates = Vec::new();
    for path in env::split_paths(paths) {
        let encoded = fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let parsed = Certificate::load_pem_chain(&encoded)
            .or_else(|_| Certificate::from_der(&encoded).map(|certificate| vec![certificate]))
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        for certificate in parsed {
            certificates.push(
                certificate
                    .to_der()
                    .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
            );
        }
    }
    if certificates.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(certificates)
}

pub(crate) fn decode(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    Certificate::from_der(encoded)
        .or_else(|_| Certificate::from_pem(encoded))
        .and_then(|certificate| certificate.to_der())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn encode_pem(encoded: &[u8]) -> Result<String, Error> {
    Certificate::from_der(encoded)
        .and_then(|certificate| certificate.to_pem(LineEnding::LF))
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn public_key_info(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    ParsedCertificate::parse(&decode(encoded)?)?
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn verify_signed_by(certificate: &[u8], signer: &[u8]) -> Result<(), Error> {
    ParsedCertificate::parse(&decode(certificate)?)?
        .verify_signature(&ParsedCertificate::parse(&decode(signer)?)?)
}

pub(crate) fn validate_p256_public_point(
    certificates: &[Vec<u8>],
    trust_anchors: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    CertificateTrust::new(trust_anchors)?.validate_p256_public_point(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        nid::Nid,
        stack::Stack,
        x509::{store::X509StoreBuilder, X509StoreContext, X509},
    };
    use std::{cmp::Ordering, collections::HashSet};

    const YUBICO_ATTESTATION_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-attestation-root-1.pem"
    ));
    const YUBICO_PIV_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-piv-ca-1.pem"
    ));
    const YUBICO_INTERMEDIATES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-intermediate.pem"
    ));
    const YUBIHSM_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubihsm/yubihsm2-attestation-root.pem"
    ));
    const YUBIHSM_INTERMEDIATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem"
    ));

    fn sha256(certificate: &X509) -> Vec<u8> {
        certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .to_vec()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn assert_current(certificate: &X509) {
        let now = Asn1Time::days_from_now(0).unwrap();
        assert_ne!(
            certificate.not_before().compare(&now).unwrap(),
            Ordering::Greater
        );
        assert_ne!(
            certificate.not_after().compare(&now).unwrap(),
            Ordering::Less
        );
    }

    fn assert_self_signed(certificate: &X509) {
        assert_eq!(
            certificate.subject_name().to_der().unwrap(),
            certificate.issuer_name().to_der().unwrap()
        );
        assert!(certificate
            .verify(&certificate.public_key().unwrap())
            .unwrap());
    }

    #[test]
    fn yubico_public_roots_are_current_self_signed_and_fingerprint_pinned() {
        let fixtures = [
            (
                YUBICO_ATTESTATION_ROOT,
                "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8",
            ),
            (
                YUBICO_PIV_ROOT,
                "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546",
            ),
            (
                YUBIHSM_ROOT,
                "094a3ac493c2bdcd65a54bdf40190f52bb03f7156397a3fc69d8aa9a392fb724",
            ),
        ];

        for (encoded, expected_fingerprint) in fixtures {
            let certificate = X509::from_pem(encoded).unwrap();
            assert_current(&certificate);
            assert_self_signed(&certificate);
            assert_eq!(encode_hex(&sha256(&certificate)), expected_fingerprint);
        }
    }

    #[test]
    fn every_published_yubico_intermediate_has_an_exact_der_path_to_the_root() {
        let root = X509::from_pem(YUBICO_ATTESTATION_ROOT).unwrap();
        let intermediates = X509::stack_from_pem(YUBICO_INTERMEDIATES).unwrap();
        assert_eq!(intermediates.len(), 15);

        let expected_subjects = [
            "Yubico Attestation Intermediate A 1",
            "Yubico Attestation Intermediate B 1",
            "Yubico FIDO Attestation A 1",
            "Yubico FIDO Attestation B 1",
            "Yubico FIDO Attestation B2 1",
            "Yubico OPGP Attestation A 1",
            "Yubico OPGP Attestation B 1",
            "Yubico OPGP Attestation B2 1",
            "Yubico PIV Attestation A 1",
            "Yubico PIV Attestation B 1",
            "Yubico PIV Attestation B2 1",
            "Yubico SD Attestation A 1",
            "Yubico SD Attestation B 1",
            "Yubico SD Attestation B2 1",
            "YubiHSM Attestation B2 1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<HashSet<_>>();
        let subjects = intermediates
            .iter()
            .map(|certificate| {
                certificate
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .unwrap()
                    .data()
                    .to_string()
                    .unwrap()
            })
            .collect::<HashSet<_>>();
        assert_eq!(subjects, expected_subjects);

        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(root.clone()).unwrap();
        let store = store.build();
        for certificate in &intermediates {
            assert_current(certificate);

            let issuer_der = certificate.issuer_name().to_der().unwrap();
            let issuer = std::iter::once(&root)
                .chain(intermediates.iter())
                .find(|candidate| candidate.subject_name().to_der().unwrap() == issuer_der)
                .expect("published intermediate has no exact-DER issuer");
            assert!(certificate.verify(&issuer.public_key().unwrap()).unwrap());

            let mut untrusted = Stack::new().unwrap();
            for candidate in &intermediates {
                if candidate.digest(MessageDigest::sha256()).unwrap().as_ref()
                    != certificate
                        .digest(MessageDigest::sha256())
                        .unwrap()
                        .as_ref()
                {
                    untrusted.push(candidate.clone()).unwrap();
                }
            }
            let mut context = X509StoreContext::new().unwrap();
            assert!(context
                .init(&store, certificate, &untrusted, |context| {
                    context.verify_cert()
                })
                .unwrap());
        }
    }

    #[test]
    fn published_yubihsm_intermediate_matches_its_public_root() {
        let root = X509::from_pem(YUBIHSM_ROOT).unwrap();
        let intermediate = X509::from_pem(YUBIHSM_INTERMEDIATE).unwrap();
        assert_current(&intermediate);
        assert_eq!(
            intermediate.issuer_name().to_der().unwrap(),
            root.subject_name().to_der().unwrap()
        );
        assert!(intermediate.verify(&root.public_key().unwrap()).unwrap());
        assert_eq!(
            encode_hex(&sha256(&intermediate)),
            "d7c6d8f45208e2a53996fb5a8f4d631b33ebabb64956b37b2ac151fbdbaf4ae9"
        );
    }

    fn rustcrypto_der_chain(encoded: &[u8]) -> Vec<Vec<u8>> {
        Certificate::load_pem_chain(encoded)
            .unwrap()
            .into_iter()
            .map(|certificate| certificate.to_der().unwrap())
            .collect()
    }

    #[test]
    fn webpki_trust_store_loads_every_published_yubico_ca() {
        let mut certificates = rustcrypto_der_chain(YUBICO_ATTESTATION_ROOT);
        certificates.extend(rustcrypto_der_chain(YUBICO_INTERMEDIATES));
        let trust = CertificateTrust::new(&certificates).unwrap();

        assert_eq!(trust.trust_anchors.len(), 1);
        assert_eq!(trust.local_intermediates.len(), 15);
        assert_eq!(trust.root_fingerprints.len(), 1);
    }

    #[test]
    fn webpki_trust_store_loads_yubico_legacy_and_yubihsm_roots() {
        let legacy = rustcrypto_der_chain(YUBICO_PIV_ROOT);
        let legacy_trust = CertificateTrust::new(&legacy).unwrap();
        assert_eq!(legacy_trust.trust_anchors.len(), 1);
        assert!(legacy_trust.local_intermediates.is_empty());

        let mut yubihsm = rustcrypto_der_chain(YUBIHSM_ROOT);
        yubihsm.extend(rustcrypto_der_chain(YUBIHSM_INTERMEDIATE));
        let yubihsm_trust = CertificateTrust::new(&yubihsm).unwrap();
        assert_eq!(yubihsm_trust.trust_anchors.len(), 1);
        assert_eq!(yubihsm_trust.local_intermediates.len(), 1);
    }

    #[test]
    fn device_supplied_self_signed_certificate_never_becomes_a_root() {
        let trusted = rustcrypto_der_chain(YUBICO_ATTESTATION_ROOT);
        let untrusted = rustcrypto_der_chain(YUBICO_PIV_ROOT);
        let forest = CertificateTrust::new(&trusted).unwrap();

        assert!(forest.validate(&untrusted).is_err());
    }

    #[test]
    fn duplicate_configured_certificates_are_deduplicated() {
        let mut roots = rustcrypto_der_chain(YUBICO_ATTESTATION_ROOT);
        roots.push(roots[0].clone());
        let forest = CertificateTrust::new(&roots).unwrap();

        assert_eq!(forest.trust_anchors.len(), 1);
        assert_eq!(forest.root_fingerprints.len(), 1);
        assert!(forest.local_intermediates.is_empty());
    }

}
