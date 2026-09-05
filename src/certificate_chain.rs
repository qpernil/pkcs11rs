use crate::{CKR_ARGUMENTS_BAD, Error};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode, asn1::OctetStringRef};
use software_key_core::certificate_chain::{CertificateError, ParsedCertificate};
use x509_cert::Certificate;

const FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

impl From<CertificateError> for Error {
    fn from(_: CertificateError) -> Self {
        CKR_ARGUMENTS_BAD.into()
    }
}

#[derive(Clone)]
pub(crate) struct CertificateTrust(software_key_core::certificate_chain::CertificateTrust);

impl CertificateTrust {
    pub(crate) fn new(certificates: &[Vec<u8>]) -> Result<Self, Error> {
        Ok(Self(
            software_key_core::certificate_chain::CertificateTrust::new(certificates)?,
        ))
    }

    pub(crate) fn validate_p256_public_point(
        &self,
        certificates: &[Vec<u8>],
    ) -> Result<Vec<u8>, Error> {
        self.0
            .validate_p256_public_point(certificates)
            .map_err(Into::into)
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.0.fingerprint()
    }
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
        .certificate()
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

pub(crate) fn p256_public_point(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    ParsedCertificate::parse(&decode(encoded)?)?
        .p256_public_point()
        .map_err(Into::into)
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
        .map_err(Into::into)
}

pub(crate) fn validate_p256_public_point(
    certificates: &[Vec<u8>],
    trust_anchors: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    CertificateTrust::new(trust_anchors)?.validate_p256_public_point(certificates)
}

#[cfg(test)]
fn sha256_fingerprint(data: &[u8]) -> [u8; 32] {
    let digest = software_key_core::digest::HashAlgorithm::Sha256.digest(data);
    let mut fingerprint = [0; 32];
    fingerprint.copy_from_slice(&digest);
    fingerprint
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
        let _trust = CertificateTrust::new(&certificates).unwrap();
    }

    #[test]
    fn webpki_trust_store_loads_yubico_legacy_and_yubihsm_roots() {
        let legacy = der_chain(YUBICO_PIV_ROOT);
        let _legacy_trust = CertificateTrust::new(&legacy).unwrap();

        let mut yubihsm = der_chain(YUBIHSM_ROOT);
        yubihsm.extend(der_chain(YUBIHSM_INTERMEDIATE));
        let _yubihsm_trust = CertificateTrust::new(&yubihsm).unwrap();
    }

    #[test]
    fn device_supplied_self_signed_certificate_never_becomes_a_root() {
        let trusted = der_chain(YUBICO_ATTESTATION_ROOT);
        let untrusted = der_chain(YUBICO_PIV_ROOT);
        let forest = CertificateTrust::new(&trusted).unwrap();

        assert!(forest.validate_p256_public_point(&untrusted).is_err());
    }

    #[test]
    fn duplicate_configured_certificates_are_deduplicated() {
        let mut roots = der_chain(YUBICO_ATTESTATION_ROOT);
        roots.push(roots[0].clone());
        let forest = CertificateTrust::new(&roots).unwrap();
        assert_eq!(
            forest.fingerprint(),
            CertificateTrust::new(&roots[..1]).unwrap().fingerprint()
        );
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
