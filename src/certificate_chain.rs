use crate::{Error, CKR_ARGUMENTS_BAD};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    nid::Nid,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use std::{env, fs};

pub(crate) fn load(paths: &str) -> Result<Vec<Vec<u8>>, Error> {
    let mut certificates = Vec::new();
    for path in env::split_paths(paths) {
        let encoded = fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let parsed = X509::stack_from_pem(&encoded)
            .or_else(|_| X509::from_der(&encoded).map(|certificate| vec![certificate]))
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        for certificate in parsed {
            certificates.push(certificate.to_der().map_err(Error::from)?);
        }
    }
    if certificates.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(certificates)
}

pub(crate) fn validate_p256_public_point(
    certificates: &[Vec<u8>],
    trust_anchors: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let parsed: Vec<X509> = certificates
        .iter()
        .map(|certificate| X509::from_der(certificate).map_err(Error::from))
        .collect::<Result<_, _>>()?;
    let leaf = parsed.last().ok_or(CKR_ARGUMENTS_BAD)?;
    if trust_anchors.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let mut store = X509StoreBuilder::new()?;
    for trust_anchor in trust_anchors {
        store.add_cert(X509::from_der(trust_anchor).map_err(Error::from)?)?;
    }
    let store = store.build();
    let mut intermediates = Stack::new()?;
    for (certificate, encoded) in parsed.iter().zip(certificates).take(parsed.len() - 1) {
        if !trust_anchors.contains(encoded) {
            intermediates.push(certificate.clone())?;
        }
    }
    let mut context = X509StoreContext::new()?;
    if !context.init(&store, leaf, &intermediates, |context| {
        context.verify_cert()
    })? {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let key = leaf
        .public_key()
        .and_then(|key| key.ec_key())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let mut context = BigNumContext::new()?;
    key.public_key()
        .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        stack::Stack,
        x509::{store::X509StoreBuilder, X509StoreContext},
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
}
