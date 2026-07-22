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
