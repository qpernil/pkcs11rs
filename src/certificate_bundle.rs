use der::{Decode, Encode};
use minicbor::{Decoder, Encoder};
use std::{error, fmt};
use x509_cert::Certificate;

const SCHEMA: &str = "pkcs11rs.x509-certificate-bundle";
const VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid canonical certificate encoding")
    }
}

impl error::Error for FormatError {}

pub(crate) fn decode_certificate(encoded: &[u8]) -> Result<Vec<u8>, FormatError> {
    let certificate = Certificate::from_der(encoded).map_err(|_| FormatError)?;
    let canonical = certificate.to_der().map_err(|_| FormatError)?;
    if canonical != encoded {
        return Err(FormatError);
    }
    Ok(canonical)
}

pub(crate) fn encode(certificates: &[Vec<u8>]) -> Result<Vec<u8>, FormatError> {
    if certificates.is_empty() {
        return Err(FormatError);
    }
    let mut encoded = Vec::new();
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .array(3)
        .and_then(|encoder| encoder.str(SCHEMA))
        .and_then(|encoder| encoder.u64(VERSION))
        .and_then(|encoder| encoder.array(certificates.len() as u64))
        .map_err(|_| FormatError)?;
    for certificate in certificates {
        encoder
            .bytes(&decode_certificate(certificate)?)
            .map_err(|_| FormatError)?;
    }
    Ok(encoded)
}

pub(crate) fn decode(encoded: &[u8]) -> Result<Vec<Vec<u8>>, FormatError> {
    let mut decoder = Decoder::new(encoded);
    if decoder.array().map_err(|_| FormatError)? != Some(3)
        || decoder.str().map_err(|_| FormatError)? != SCHEMA
        || decoder.u64().map_err(|_| FormatError)? != VERSION
    {
        return Err(FormatError);
    }
    let count = decoder
        .array()
        .map_err(|_| FormatError)?
        .ok_or(FormatError)?;
    if count == 0 || count > encoded.len() as u64 {
        return Err(FormatError);
    }
    let count = usize::try_from(count).map_err(|_| FormatError)?;
    let mut certificates = Vec::with_capacity(count);
    for _ in 0..count {
        certificates.push(decode_certificate(
            decoder.bytes().map_err(|_| FormatError)?,
        )?);
    }
    if decoder.position() != encoded.len() || encode(&certificates)? != encoded {
        return Err(FormatError);
    }
    Ok(certificates)
}
