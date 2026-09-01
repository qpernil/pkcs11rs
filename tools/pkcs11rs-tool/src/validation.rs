use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use rustls::{
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, TrustAnchor, UnixTime},
    sign::CertifiedKey,
};
use software_key_core::software_signing::{
    EcCurve, SignatureScheme, SoftwarePublicKey, SoftwareSigningKey,
};
use std::{collections::HashSet, path::Path};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
};

const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Purpose {
    CertificateCollection,
    YubiHsmTlsClient,
    YubiHsmTlsCa,
    Scp11Oce,
}

impl Purpose {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "certificate-collection" => Ok(Self::CertificateCollection),
            "yubihsm-tls-client" => Ok(Self::YubiHsmTlsClient),
            "yubihsm-tls-ca" => Ok(Self::YubiHsmTlsCa),
            "scp11-oce" => Ok(Self::Scp11Oce),
            _ => Err(format!("unknown certificate-bundle purpose {value:?}")),
        }
    }

    pub(crate) fn requires_key(self) -> bool {
        matches!(self, Self::YubiHsmTlsClient | Self::Scp11Oce)
    }

    pub(crate) fn accepts_trust(self) -> bool {
        matches!(self, Self::YubiHsmTlsClient | Self::Scp11Oce)
    }
}

struct ParsedCertificate {
    certificate: Certificate,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    is_ca: bool,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<ExtendedKeyUsage>,
    not_before: u64,
    not_after: u64,
}

impl ParsedCertificate {
    fn parse(encoded: &[u8]) -> Result<Self, String> {
        let certificate = Certificate::from_der(encoded)
            .map_err(|error| format!("parse X.509 certificate: {error}"))?;
        if certificate
            .to_der()
            .map_err(|error| format!("encode X.509 certificate: {error}"))?
            != encoded
        {
            return Err("certificate is not canonical DER".to_owned());
        }
        if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
            return Err("certificate signature algorithms disagree".to_owned());
        }
        let basic_constraints = certificate
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(|error| format!("decode Basic Constraints: {error}"))?
            .map(|(_, constraints)| constraints);
        let key_usage = certificate
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|error| format!("decode Key Usage: {error}"))?
            .map(|(_, usage)| usage);
        let extended_key_usage = certificate
            .tbs_certificate()
            .get_extension::<ExtendedKeyUsage>()
            .map_err(|error| format!("decode Extended Key Usage: {error}"))?
            .map(|(_, usage)| usage);
        Ok(Self {
            subject: certificate
                .tbs_certificate()
                .subject()
                .to_der()
                .map_err(|error| format!("encode certificate subject: {error}"))?,
            issuer: certificate
                .tbs_certificate()
                .issuer()
                .to_der()
                .map_err(|error| format!("encode certificate issuer: {error}"))?,
            is_ca: basic_constraints
                .as_ref()
                .is_some_and(|constraints| constraints.ca),
            key_usage,
            extended_key_usage,
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
            certificate,
        })
    }

    fn require_valid_now(&self) -> Result<(), String> {
        let now = UnixTime::now().as_secs();
        if self.not_before <= now && now <= self.not_after {
            Ok(())
        } else {
            Err("certificate is not currently valid".to_owned())
        }
    }

    fn require_ca(&self) -> Result<(), String> {
        if !self.is_ca {
            return Err("issuer certificate is not a CA".to_owned());
        }
        if self
            .key_usage
            .as_ref()
            .is_some_and(|usage| !usage.key_cert_sign())
        {
            return Err("issuer certificate does not permit certificate signing".to_owned());
        }
        Ok(())
    }
}

pub(crate) fn validate(
    purpose: Purpose,
    certificates: &[Vec<u8>],
    key_path: Option<&Path>,
    trust: Option<&[Vec<u8>]>,
) -> Result<(), String> {
    if certificates.is_empty() {
        return Err("certificate bundle is empty".to_owned());
    }
    reject_duplicates(certificates)?;
    let parsed = certificates
        .iter()
        .enumerate()
        .map(|(index, certificate)| {
            ParsedCertificate::parse(certificate)
                .map_err(|error| format!("certificate {}: {error}", index + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;

    match purpose {
        Purpose::CertificateCollection => Ok(()),
        Purpose::YubiHsmTlsCa => validate_tls_ca(&parsed),
        Purpose::YubiHsmTlsClient => {
            validate_ordered_chain(&parsed)?;
            validate_tls_client_leaf(&parsed[0])?;
            validate_key(certificates, key_path, false)?;
            validate_path(certificates, trust, PathUsage::TlsClient)
        }
        Purpose::Scp11Oce => {
            validate_ordered_chain(&parsed)?;
            validate_scp11_leaf(&parsed[0])?;
            validate_key(certificates, key_path, true)?;
            validate_path(certificates, trust, PathUsage::Any)
        }
    }
}

fn reject_duplicates(certificates: &[Vec<u8>]) -> Result<(), String> {
    let mut fingerprints = HashSet::new();
    for (index, certificate) in certificates.iter().enumerate() {
        let fingerprint: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
            .digest(certificate)
            .try_into()
            .expect("SHA-256 has a 32-byte output");
        if !fingerprints.insert(fingerprint) {
            return Err(format!("certificate {} is a duplicate", index + 1));
        }
    }
    Ok(())
}

fn validate_tls_ca(certificates: &[ParsedCertificate]) -> Result<(), String> {
    for (index, certificate) in certificates.iter().enumerate() {
        certificate
            .require_valid_now()
            .and_then(|_| certificate.require_ca())
            .map_err(|error| format!("trust anchor {}: {error}", index + 1))?;
        let encoded = certificate
            .certificate
            .to_der()
            .map_err(|error| format!("encode trust anchor {}: {error}", index + 1))?;
        webpki::anchor_from_trusted_cert(&CertificateDer::from(encoded))
            .map_err(|error| format!("trust anchor {} is unusable: {error}", index + 1))?;
    }
    Ok(())
}

fn validate_ordered_chain(certificates: &[ParsedCertificate]) -> Result<(), String> {
    for (index, certificate) in certificates.iter().enumerate() {
        certificate
            .require_valid_now()
            .map_err(|error| format!("certificate {}: {error}", index + 1))?;
    }
    for (index, pair) in certificates.windows(2).enumerate() {
        let [certificate, issuer] = pair else {
            unreachable!()
        };
        if certificate.issuer != issuer.subject {
            return Err(format!(
                "certificate {} is not issued by certificate {}",
                index + 1,
                index + 2
            ));
        }
        issuer
            .require_ca()
            .map_err(|error| format!("certificate {}: {error}", index + 2))?;
        verify_signature(&certificate.certificate, &issuer.certificate).map_err(|error| {
            format!(
                "certificate {} signature is not valid under certificate {}: {error}",
                index + 1,
                index + 2
            )
        })?;
    }
    Ok(())
}

fn validate_tls_client_leaf(certificate: &ParsedCertificate) -> Result<(), String> {
    if certificate.is_ca {
        return Err("TLS client leaf certificate is a CA".to_owned());
    }
    if certificate
        .key_usage
        .as_ref()
        .is_some_and(|usage| !usage.digital_signature())
    {
        return Err("TLS client leaf does not permit digital signatures".to_owned());
    }
    if certificate
        .extended_key_usage
        .as_ref()
        .is_some_and(|usage| !usage.0.contains(&CLIENT_AUTH))
    {
        return Err("TLS client leaf does not permit TLS client authentication".to_owned());
    }
    Ok(())
}

fn validate_scp11_leaf(certificate: &ParsedCertificate) -> Result<(), String> {
    if certificate.is_ca {
        return Err("SCP11 OCE leaf certificate is a CA".to_owned());
    }
    if certificate
        .key_usage
        .as_ref()
        .is_some_and(|usage| !usage.key_agreement())
    {
        return Err("SCP11 OCE leaf does not permit key agreement".to_owned());
    }
    p256_public_point(&certificate.certificate)?;
    Ok(())
}

fn validate_key(
    certificates: &[Vec<u8>],
    key_path: Option<&Path>,
    require_p256: bool,
) -> Result<(), String> {
    let key_path = key_path.ok_or_else(|| "this purpose requires --key".to_owned())?;
    let encrypted = std::fs::read(key_path)
        .map_err(|error| format!("read private key {}: {error}", key_path.display()))?;
    let password = crate::pinentry::request("Unlock the identity private key")?;
    let decrypted = crate::encrypted_private_key::decrypt(&encrypted, &password)
        .map_err(|error| error.to_string())?;
    validate_decrypted_key(certificates, &decrypted, require_p256)
}

fn validate_decrypted_key(
    certificates: &[Vec<u8>],
    decrypted: &[u8],
    require_p256: bool,
) -> Result<(), String> {
    if require_p256 {
        let private_key =
            SoftwareSigningKey::from_pkcs8_der(SignatureScheme::EcdsaP256Sha256, decrypted)
                .map_err(|_| "SCP11 OCE private key is not a P-256 PKCS #8 key".to_owned())?;
        let certificate = Certificate::from_der(&certificates[0])
            .map_err(|error| format!("parse leaf certificate: {error}"))?;
        let certificate_key = p256_public_point(&certificate)?;
        let SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: private_key,
        } = private_key.public_key()
        else {
            return Err("SCP11 OCE private key is not P-256".to_owned());
        };
        if private_key != certificate_key {
            return Err("private key does not match the leaf certificate".to_owned());
        }
        return Ok(());
    }

    let certificate_chain = certificates
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decrypted.to_vec()));
    let certified_key = CertifiedKey::from_der(certificate_chain, private_key, &default_provider())
        .map_err(|error| format!("load TLS client identity: {error}"))?;
    certified_key
        .keys_match()
        .map_err(|_| "private key does not match the leaf certificate".to_owned())
}

fn p256_public_point(certificate: &Certificate) -> Result<Vec<u8>, String> {
    let spki = certificate.tbs_certificate().subject_public_key_info();
    let parameters = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != EC_PUBLIC_KEY || parameters != Some(P256_CURVE) {
        return Err("certificate does not contain a P-256 public key".to_owned());
    }
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "certificate P-256 public key is not byte-aligned".to_owned())?
        .to_vec();
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: point.clone(),
    }
    .validate()
    .map_err(|_| "certificate contains an invalid P-256 public key".to_owned())?;
    Ok(point)
}

enum PathUsage {
    TlsClient,
    Any,
}

#[derive(Clone, Copy)]
struct AnyUsage;

impl ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in purposes {
            purpose?;
        }
        Ok(())
    }
}

fn validate_path(
    certificates: &[Vec<u8>],
    trust: Option<&[Vec<u8>]>,
    usage: PathUsage,
) -> Result<(), String> {
    let implicit_terminal;
    let (anchors, intermediates) = if let Some(trust) = trust {
        if trust.is_empty() {
            return Err("trust bundle is empty".to_owned());
        }
        reject_duplicates(trust)?;
        let parsed_trust = trust
            .iter()
            .enumerate()
            .map(|(index, certificate)| {
                ParsedCertificate::parse(certificate)
                    .map_err(|error| format!("trust certificate {}: {error}", index + 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_tls_ca(&parsed_trust)?;
        let trusted = trust.iter().map(Vec::as_slice).collect::<HashSet<_>>();
        (
            trust,
            certificates[1..]
                .iter()
                .filter(|certificate| !trusted.contains(certificate.as_slice()))
                .cloned()
                .collect::<Vec<_>>(),
        )
    } else if certificates.len() > 1 {
        implicit_terminal = vec![certificates.last().expect("nonempty").clone()];
        (
            implicit_terminal.as_slice(),
            certificates[1..certificates.len() - 1].to_vec(),
        )
    } else {
        return Ok(());
    };

    let anchors = trust_anchors(anchors)?;
    let intermediates = intermediates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect::<Vec<_>>();
    let leaf_der = CertificateDer::from(certificates[0].as_slice());
    let leaf =
        EndEntityCert::try_from(&leaf_der).map_err(|error| format!("parse chain leaf: {error}"))?;
    let result = match usage {
        PathUsage::TlsClient => leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::now(),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        ),
        PathUsage::Any => leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::now(),
            AnyUsage,
            None,
            None,
        ),
    };
    result
        .map(|_| ())
        .map_err(|error| format!("certificate path validation failed: {error}"))
}

fn trust_anchors(certificates: &[Vec<u8>]) -> Result<Vec<TrustAnchor<'static>>, String> {
    certificates
        .iter()
        .enumerate()
        .map(|(index, certificate)| {
            let certificate = CertificateDer::from(certificate.clone());
            webpki::anchor_from_trusted_cert(&certificate)
                .map(|anchor| anchor.to_owned())
                .map_err(|error| format!("trust certificate {} is unusable: {error}", index + 1))
        })
        .collect()
}

fn verify_signature(certificate: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let signature_algorithm = algorithm_identifier_contents(certificate.signature_algorithm())?;
    let public_key_algorithm = algorithm_identifier_contents(
        &issuer.tbs_certificate().subject_public_key_info().algorithm,
    )?;
    let algorithm = webpki::ALL_VERIFICATION_ALGS
        .iter()
        .copied()
        .find(|algorithm| {
            algorithm.signature_alg_id().as_ref() == signature_algorithm
                && algorithm.public_key_alg_id().as_ref() == public_key_algorithm
        })
        .ok_or_else(|| "unsupported certificate signature algorithm".to_owned())?;
    let issuer_der = CertificateDer::from(
        issuer
            .to_der()
            .map_err(|error| format!("encode issuer: {error}"))?,
    );
    let issuer = EndEntityCert::try_from(&issuer_der)
        .map_err(|error| format!("parse issuer public key: {error}"))?;
    let message = certificate
        .tbs_certificate()
        .to_der()
        .map_err(|error| format!("encode signed certificate body: {error}"))?;
    let signature = certificate
        .signature()
        .as_bytes()
        .ok_or_else(|| "certificate signature is not byte-aligned".to_owned())?;
    issuer
        .verify_signature(algorithm, &message, signature)
        .map_err(|error| error.to_string())
}

fn algorithm_identifier_contents(
    algorithm: &spki::AlgorithmIdentifierOwned,
) -> Result<Vec<u8>, String> {
    let mut encoded = algorithm
        .oid
        .to_der()
        .map_err(|error| format!("encode algorithm OID: {error}"))?;
    if let Some(parameters) = &algorithm.parameters {
        encoded.extend(
            parameters
                .to_der()
                .map_err(|error| format!("encode algorithm parameters: {error}"))?,
        );
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{DerSignature, SigningKey},
        elliptic_curve::Generate,
        pkcs8::EncodePrivateKey,
    };
    use std::{str::FromStr, time::Duration};
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile::BuilderProfile},
        certificate::TbsCertificate,
        ext::{
            Extension, ToExtension,
            pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages},
        },
        name::Name,
        serial_number::SerialNumber,
        time::Validity,
    };

    struct Profile {
        subject: Name,
        issuer: Name,
        is_ca: bool,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            _subject_key: spki::SubjectPublicKeyInfoRef<'_>,
            _issuer_key: spki::SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let mut extensions = vec![
                BasicConstraints {
                    ca: self.is_ca,
                    path_len_constraint: None,
                }
                .to_extension(tbs.subject(), &[])?,
            ];
            let usages = if self.is_ca {
                KeyUsages::DigitalSignature | KeyUsages::KeyCertSign | KeyUsages::CRLSign
            } else {
                KeyUsages::DigitalSignature | KeyUsages::KeyAgreement
            };
            extensions.push(KeyUsage(usages).to_extension(tbs.subject(), &extensions)?);
            if !self.is_ca {
                extensions.push(
                    ExtendedKeyUsage(vec![CLIENT_AUTH]).to_extension(tbs.subject(), &extensions)?,
                );
            }
            Ok(extensions)
        }
    }

    fn certificate(
        subject_key: &SigningKey,
        signer: &SigningKey,
        subject: &str,
        issuer: &str,
        serial: u32,
        is_ca: bool,
    ) -> Vec<u8> {
        let builder = CertificateBuilder::new(
            Profile {
                subject: Name::from_str(subject).unwrap(),
                issuer: Name::from_str(issuer).unwrap(),
                is_ca,
            },
            SerialNumber::from(serial),
            Validity::from_now(Duration::from_secs(86_400 * 365)).unwrap(),
            spki::SubjectPublicKeyInfoOwned::from_key(subject_key.verifying_key()).unwrap(),
        )
        .unwrap();
        builder
            .build::<_, DerSignature>(signer)
            .unwrap()
            .to_der()
            .unwrap()
    }

    fn client_chain() -> (SigningKey, Vec<Vec<u8>>) {
        let root_key = SigningKey::generate();
        let root_name = "CN=pkcs11rs tool test root";
        let root = certificate(&root_key, &root_key, root_name, root_name, 1, true);
        let leaf_key = SigningKey::generate();
        let leaf = certificate(
            &leaf_key,
            &root_key,
            "CN=pkcs11rs tool test client",
            root_name,
            2,
            false,
        );
        (leaf_key, vec![leaf, root])
    }

    #[test]
    fn purpose_names_are_explicit() {
        assert_eq!(
            Purpose::parse("yubihsm-tls-client"),
            Ok(Purpose::YubiHsmTlsClient)
        );
        assert!(Purpose::parse("tls").is_err());
    }

    #[test]
    fn certificate_collection_rejects_duplicates() {
        let certificate =
            include_bytes!("../../../certificates/yubikey/yubico-attestation-root-1.der").to_vec();
        assert!(
            validate(
                Purpose::CertificateCollection,
                &[certificate.clone(), certificate],
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn yubihsm_tls_ca_accepts_factory_root() {
        let certificate =
            include_bytes!("../../../certificates/yubihsm/yubihsm2-attestation-root.der").to_vec();
        validate(Purpose::YubiHsmTlsCa, &[certificate], None, None).unwrap();
    }

    #[test]
    fn tls_client_profile_validates_chain_usage_and_matching_key() {
        let (key, chain) = client_chain();
        let parsed = chain
            .iter()
            .map(|certificate| ParsedCertificate::parse(certificate).unwrap())
            .collect::<Vec<_>>();
        validate_ordered_chain(&parsed).unwrap();
        validate_tls_client_leaf(&parsed[0]).unwrap();
        validate_path(&chain, None, PathUsage::TlsClient).unwrap();
        let encoded_key = key.to_pkcs8_der().unwrap();
        validate_decrypted_key(&chain, encoded_key.as_bytes(), false).unwrap();
        validate_decrypted_key(&chain, encoded_key.as_bytes(), true).unwrap();

        let other_key = SigningKey::generate().to_pkcs8_der().unwrap();
        assert!(validate_decrypted_key(&chain, other_key.as_bytes(), false).is_err());
        assert!(validate_decrypted_key(&chain, other_key.as_bytes(), true).is_err());
    }

    #[test]
    fn explicit_trust_must_complete_the_chain() {
        let (_, chain) = client_chain();
        validate_path(&chain[..1], Some(&chain[1..]), PathUsage::TlsClient).unwrap();

        let other_key = SigningKey::generate();
        let other_root = certificate(
            &other_key,
            &other_key,
            "CN=other root",
            "CN=other root",
            3,
            true,
        );
        assert!(validate_path(&chain[..1], Some(&[other_root]), PathUsage::TlsClient).is_err());
    }

    #[test]
    fn encrypted_private_keys_are_canonical_and_password_protected() {
        let encrypted = include_bytes!("../../../src/fixtures/test-rsa-private-key.der");
        let decrypted = crate::encrypted_private_key::decrypt(encrypted, b"test fixture").unwrap();
        pkcs8::PrivateKeyInfoRef::from_der(&decrypted).unwrap();
        assert!(crate::encrypted_private_key::decrypt(encrypted, b"wrong").is_err());
        let mut trailing = encrypted.to_vec();
        trailing.push(0);
        assert!(crate::encrypted_private_key::decrypt(&trailing, b"test fixture").is_err());
    }
}
