use crate::{CKR_ARGUMENTS_BAD, Error};
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode,
    asn1::{ObjectIdentifier as DerObjectIdentifier, OctetStringRef},
};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use software_key_core::software_signing::{EcCurve, SoftwarePublicKey};
use std::collections::HashSet;
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, KeyUsage},
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
const FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

type Fingerprint = [u8; 32];

fn supported_signature_algorithms()
-> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] {
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
        if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        validate_critical_extensions(&certificate)?;
        let basic_constraints = certificate
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?
            .map(|(_, constraints)| constraints);
        let key_usage = certificate
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?
            .map(|(_, usage)| usage);
        let canonical = certificate
            .to_der()
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        if canonical != encoded {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        Ok(Self {
            subject: certificate
                .tbs_certificate()
                .subject()
                .to_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
            issuer: certificate
                .tbs_certificate()
                .issuer()
                .to_der()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
            fingerprint: sha256_fingerprint(&canonical),
            not_before: certificate
                .tbs_certificate()
                .validity()
                .not_before
                .to_unix_duration()
                .as_secs(),
            not_after: certificate
                .tbs_certificate()
                .validity()
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
        let spki = &self.certificate.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid != EC_PUBLIC_KEY || algorithm_parameter_oid(spki)? != P256_CURVE {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CKR_ARGUMENTS_BAD)?;
        SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: point.to_vec(),
        }
        .validate()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
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
        let fingerprint = sha256_fingerprint(&fingerprints.concat());
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
            let fingerprint = sha256_fingerprint(certificate.as_ref());
            if fingerprints.insert(fingerprint) {
                intermediates.push(certificate.clone());
            }
        }
        for certificate in &certificates[..certificates.len() - 1] {
            let fingerprint = sha256_fingerprint(certificate);
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
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
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
    if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_algorithm = algorithm_identifier_contents(certificate.signature_algorithm())?;
    let public_key_algorithm = algorithm_identifier_contents(
        &issuer.tbs_certificate().subject_public_key_info().algorithm,
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
        .tbs_certificate()
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let signature = certificate
        .signature()
        .as_bytes()
        .ok_or(CKR_ARGUMENTS_BAD)?;
    issuer
        .verify_signature(algorithm, &message, signature)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn decode(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    crate::certificate_bundle::decode_certificate(encoded)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

#[cfg(test)]
pub(crate) fn encode_bundle(certificates: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    crate::certificate_bundle::encode(certificates).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn decode_bundle(encoded: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    crate::certificate_bundle::decode(encoded).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn public_key_info(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    ParsedCertificate::parse(&decode(encoded)?)?
        .certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn p256_public_point(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    ParsedCertificate::parse(&decode(encoded)?)?.p256_public_point()
}

pub(crate) fn public_key_parts(
    encoded: &[u8],
) -> Result<(ObjectIdentifier, Option<ObjectIdentifier>, Vec<u8>), Error> {
    let certificate = Certificate::from_der(encoded).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let spki = certificate.tbs_certificate().subject_public_key_info();
    let parameters = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    Ok((
        spki.algorithm.oid,
        parameters,
        spki.subject_public_key
            .as_bytes()
            .ok_or(CKR_ARGUMENTS_BAD)?
            .to_vec(),
    ))
}

pub(crate) fn fido_aaguid(encoded: &[u8]) -> Result<Option<[u8; 16]>, Error> {
    let certificate = Certificate::from_der(encoded).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let mut result = None;
    for extension in certificate
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
    {
        if extension.extn_id != FIDO_AAGUID {
            continue;
        }
        if result.is_some() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let value = <&OctetStringRef>::from_der(extension.extn_value.as_bytes())
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        result = Some(
            value
                .as_bytes()
                .try_into()
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?,
        );
    }
    Ok(result)
}

pub(crate) fn subject(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    Certificate::from_der(encoded)
        .and_then(|certificate| certificate.tbs_certificate().subject().to_der())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn issuer(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    Certificate::from_der(encoded)
        .and_then(|certificate| certificate.tbs_certificate().issuer().to_der())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn serial_number(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    Certificate::from_der(encoded)
        .map(|certificate| {
            certificate
                .tbs_certificate()
                .serial_number()
                .as_bytes()
                .to_vec()
        })
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn validate(encoded: &[u8]) -> Result<(), Error> {
    Certificate::from_der(encoded)
        .map(|_| ())
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
    use std::{
        collections::HashSet,
        time::{SystemTime, UNIX_EPOCH},
    };

    const YUBICO_ATTESTATION_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-attestation-root-1.der"
    ));
    const YUBICO_FIDO_ROOT_ONE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-fido-ca-1.der"
    ));
    const YUBICO_FIDO_ROOT_TWO: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-fido-ca-2.der"
    ));
    const YUBICO_PIV_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-piv-ca-1.der"
    ));
    const YUBICO_INTERMEDIATES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubikey/yubico-intermediate.cbor"
    ));
    const YUBIHSM_ROOT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubihsm/yubihsm2-attestation-root.der"
    ));
    const YUBIHSM_INTERMEDIATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certificates/yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.der"
    ));

    fn der_certificate(encoded: &[u8]) -> Certificate {
        Certificate::from_der(encoded).unwrap()
    }

    fn sha256(certificate: &Certificate) -> Vec<u8> {
        sha256_fingerprint(&certificate.to_der().unwrap()).to_vec()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn assert_current(certificate: &Certificate) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let parsed = ParsedCertificate::parse(&certificate.to_der().unwrap()).unwrap();
        assert!(parsed.is_valid_at(now));
    }

    fn assert_self_signed(certificate: &Certificate) {
        let parsed = ParsedCertificate::parse(&certificate.to_der().unwrap()).unwrap();
        assert!(parsed.is_self_issued());
        parsed.verify_signature(&parsed).unwrap();
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
                YUBICO_FIDO_ROOT_ONE,
                "0fa1386f80eb8713263ae5c1d84deb455bdf08aea50ab05503cefee82b092d42",
            ),
            (
                YUBICO_FIDO_ROOT_TWO,
                "35f1a54b353bfb711e6d42adbeb76c0e9dead095018e6a94783ba2192fd6faad",
            ),
            (
                YUBIHSM_ROOT,
                "094a3ac493c2bdcd65a54bdf40190f52bb03f7156397a3fc69d8aa9a392fb724",
            ),
        ];

        for (encoded, expected_fingerprint) in fixtures {
            let certificate = der_certificate(encoded);
            assert_current(&certificate);
            assert_self_signed(&certificate);
            assert_eq!(encode_hex(&sha256(&certificate)), expected_fingerprint);
        }
    }

    #[test]
    fn certificate_bundle_is_canonical_and_strict() {
        let certificates = vec![
            YUBICO_ATTESTATION_ROOT.to_vec(),
            YUBICO_FIDO_ROOT_ONE.to_vec(),
        ];
        let encoded = encode_bundle(&certificates).unwrap();
        assert_eq!(decode_bundle(&encoded).unwrap(), certificates);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_bundle(&trailing).is_err());

        let mut decoder = minicbor::Decoder::new(&encoded);
        assert_eq!(decoder.array().unwrap(), Some(3));
        assert_eq!(decoder.str().unwrap(), "pkcs11rs.x509-certificate-bundle");
        let version = decoder.position();
        let mut noncanonical = encoded.clone();
        noncanonical.splice(version..=version, [0x18, 0x01]);
        assert!(decode_bundle(&noncanonical).is_err());
        assert!(encode_bundle(&[]).is_err());

        let mut invalid_certificate = certificates;
        invalid_certificate[0].push(0);
        assert!(encode_bundle(&invalid_certificate).is_err());
    }

    #[test]
    fn embedded_intermediate_bundle_uses_the_shared_schema() {
        let certificates = decode_bundle(YUBICO_INTERMEDIATES).unwrap();
        assert_eq!(certificates.len(), 15);
        assert_eq!(encode_bundle(&certificates).unwrap(), YUBICO_INTERMEDIATES);
    }

    #[test]
    fn every_published_yubico_intermediate_has_an_exact_der_path_to_the_root() {
        let root = der_certificate(YUBICO_ATTESTATION_ROOT);
        let intermediate_der = decode_bundle(YUBICO_INTERMEDIATES).unwrap();
        let intermediates = intermediate_der
            .iter()
            .map(|encoded| der_certificate(encoded))
            .collect::<Vec<_>>();
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
                    .tbs_certificate()
                    .subject()
                    .to_string()
                    .strip_prefix("CN=")
                    .unwrap()
                    .to_owned()
            })
            .collect::<HashSet<_>>();
        assert_eq!(subjects, expected_subjects);

        let mut all = vec![root.to_der().unwrap()];
        all.extend(
            intermediates
                .iter()
                .map(|certificate| certificate.to_der().unwrap()),
        );
        CertificateTrust::new(&all).unwrap();
        for certificate in &intermediates {
            assert_current(certificate);

            let issuer_der = certificate.tbs_certificate().issuer().to_der().unwrap();
            let issuer = std::iter::once(&root)
                .chain(intermediates.iter())
                .find(|candidate| {
                    candidate.tbs_certificate().subject().to_der().unwrap() == issuer_der
                })
                .expect("published intermediate has no exact-DER issuer");
            ParsedCertificate::parse(&certificate.to_der().unwrap())
                .unwrap()
                .verify_signature(&ParsedCertificate::parse(&issuer.to_der().unwrap()).unwrap())
                .unwrap();
        }
    }

    #[test]
    fn published_yubihsm_intermediate_matches_its_public_root() {
        let root = der_certificate(YUBIHSM_ROOT);
        let intermediate = der_certificate(YUBIHSM_INTERMEDIATE);
        assert_current(&intermediate);
        assert_eq!(
            intermediate.tbs_certificate().issuer().to_der().unwrap(),
            root.tbs_certificate().subject().to_der().unwrap()
        );
        ParsedCertificate::parse(&intermediate.to_der().unwrap())
            .unwrap()
            .verify_signature(&ParsedCertificate::parse(&root.to_der().unwrap()).unwrap())
            .unwrap();
        assert_eq!(
            encode_hex(&sha256(&intermediate)),
            "d7c6d8f45208e2a53996fb5a8f4d631b33ebabb64956b37b2ac151fbdbaf4ae9"
        );
    }

    fn der_chain(encoded: &[u8]) -> Vec<Vec<u8>> {
        vec![decode(encoded).unwrap()]
    }

    #[test]
    fn webpki_trust_store_loads_every_published_yubico_ca() {
        let mut certificates = der_chain(YUBICO_ATTESTATION_ROOT);
        certificates.extend(der_chain(YUBICO_FIDO_ROOT_ONE));
        certificates.extend(der_chain(YUBICO_FIDO_ROOT_TWO));
        certificates.extend(decode_bundle(YUBICO_INTERMEDIATES).unwrap());
        let trust = CertificateTrust::new(&certificates).unwrap();

        assert_eq!(trust.trust_anchors.len(), 3);
        assert_eq!(trust.local_intermediates.len(), 15);
        assert_eq!(trust.root_fingerprints.len(), 3);
    }

    #[test]
    fn webpki_trust_store_loads_yubico_legacy_and_yubihsm_roots() {
        let legacy = der_chain(YUBICO_PIV_ROOT);
        let legacy_trust = CertificateTrust::new(&legacy).unwrap();
        assert_eq!(legacy_trust.trust_anchors.len(), 1);
        assert!(legacy_trust.local_intermediates.is_empty());

        let mut yubihsm = der_chain(YUBIHSM_ROOT);
        yubihsm.extend(der_chain(YUBIHSM_INTERMEDIATE));
        let yubihsm_trust = CertificateTrust::new(&yubihsm).unwrap();
        assert_eq!(yubihsm_trust.trust_anchors.len(), 1);
        assert_eq!(yubihsm_trust.local_intermediates.len(), 1);
    }

    #[test]
    fn device_supplied_self_signed_certificate_never_becomes_a_root() {
        let trusted = der_chain(YUBICO_ATTESTATION_ROOT);
        let untrusted = der_chain(YUBICO_PIV_ROOT);
        let forest = CertificateTrust::new(&trusted).unwrap();

        assert!(forest.validate(&untrusted).is_err());
    }

    #[test]
    fn duplicate_configured_certificates_are_deduplicated() {
        let mut roots = der_chain(YUBICO_ATTESTATION_ROOT);
        roots.push(roots[0].clone());
        let forest = CertificateTrust::new(&roots).unwrap();

        assert_eq!(forest.trust_anchors.len(), 1);
        assert_eq!(forest.root_fingerprints.len(), 1);
        assert!(forest.local_intermediates.is_empty());
    }

    #[test]
    fn webpki_uses_configured_intermediate_to_validate_presented_leaf() {
        let root_key = crate::certificate_builder::p256_key();
        let intermediate_key = crate::certificate_builder::p256_key();
        let leaf_key = crate::certificate_builder::p256_key();
        let root = crate::certificate_builder::p256_certificate(
            root_key.verifying_key(),
            &root_key,
            "CN=Root",
            "CN=Root",
            1,
            true,
        );
        let intermediate = crate::certificate_builder::p256_certificate(
            intermediate_key.verifying_key(),
            &root_key,
            "CN=Intermediate",
            "CN=Root",
            2,
            true,
        );
        let leaf = crate::certificate_builder::p256_certificate(
            leaf_key.verifying_key(),
            &intermediate_key,
            "CN=Leaf",
            "CN=Intermediate",
            3,
            false,
        );
        let trust = CertificateTrust::new(&[root, intermediate]).unwrap();

        assert_eq!(
            trust.validate_p256_public_point(&[leaf]).unwrap(),
            crate::certificate_builder::p256_public_point(leaf_key.verifying_key())
        );
    }
}
fn sha256_fingerprint(data: &[u8]) -> Fingerprint {
    software_key_core::digest::HashAlgorithm::Sha256
        .digest(data)
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}
