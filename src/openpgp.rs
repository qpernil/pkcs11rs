#![allow(dead_code)]

use crate::{
    error::Error,
    scp03::{select_application, transmit, CommandApdu},
    Connector, CKR_DATA_INVALID, CKR_DEVICE_ERROR, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
    CKR_USER_NOT_LOGGED_IN,
};
use openssl::{bn::BigNum, rsa::Rsa};
use std::time::Duration;

pub(crate) const OPENPGP_AID: [u8; 6] = [0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];

const INS_VERIFY: u8 = 0x20;
const INS_PSO: u8 = 0x2a;
const INS_GET_DATA: u8 = 0xca;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_GET_CHALLENGE: u8 = 0x84;
const STATUS_SUCCESS: u16 = 0x9000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum KeyRef {
    Signature = 1,
    Decipher = 2,
    Authentication = 3,
}

impl KeyRef {
    pub(crate) const ALL: [Self; 3] = [Self::Signature, Self::Decipher, Self::Authentication];

    fn crt(self) -> &'static [u8] {
        match self {
            Self::Signature => &[0xb6, 0x00],
            Self::Decipher => &[0xb8, 0x00],
            Self::Authentication => &[0xa4, 0x00],
        }
    }

    fn algorithm_tag(self) -> u32 {
        match self {
            Self::Signature => 0xc1,
            Self::Decipher => 0xc2,
            Self::Authentication => 0xc3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
    Secp256k1,
    Ed25519,
    X25519,
}

impl Curve {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        [
            (
                Self::P256,
                &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..],
            ),
            (Self::P384, &[0x2b, 0x81, 0x04, 0x00, 0x22][..]),
            (Self::P521, &[0x2b, 0x81, 0x04, 0x00, 0x23][..]),
            (
                Self::BrainpoolP256,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07][..],
            ),
            (
                Self::BrainpoolP384,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b][..],
            ),
            (
                Self::BrainpoolP512,
                &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d][..],
            ),
            (Self::Secp256k1, &[0x2b, 0x81, 0x04, 0x00, 0x0a][..]),
            (
                Self::Ed25519,
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01][..],
            ),
            (
                Self::X25519,
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01][..],
            ),
        ]
        .into_iter()
        .find_map(|(curve, value)| (oid == value).then_some(curve))
    }

    pub(crate) fn oid(self) -> &'static [u8] {
        match self {
            Self::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            Self::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            Self::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
            Self::BrainpoolP256 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
            ],
            Self::BrainpoolP384 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
            ],
            Self::BrainpoolP512 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
            ],
            Self::Secp256k1 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
            Self::Ed25519 => &[
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
            ],
            Self::X25519 => &[
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
            ],
        }
    }

    pub(crate) fn coordinate_length(self) -> Option<usize> {
        match self {
            Self::P256 | Self::BrainpoolP256 | Self::Secp256k1 => Some(32),
            Self::P384 | Self::BrainpoolP384 => Some(48),
            Self::P521 => Some(66),
            Self::BrainpoolP512 => Some(64),
            Self::Ed25519 | Self::X25519 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Algorithm {
    Rsa { bits: usize },
    Ecdsa(Curve),
    Ecdh(Curve),
    Ed25519,
}

impl Algorithm {
    pub(crate) fn key_type(self) -> u64 {
        match self {
            Self::Rsa { .. } => crate::CKK_RSA as u64,
            Self::Ecdsa(_) | Self::Ecdh(_) => crate::CKK_EC as u64,
            Self::Ed25519 => crate::CKK_EC_EDWARDS as u64,
        }
    }

    pub(crate) fn is_rsa(self) -> bool {
        matches!(self, Self::Rsa { .. })
    }

    pub(crate) fn is_ec_signature(self) -> bool {
        matches!(self, Self::Ecdsa(_) | Self::Ed25519)
    }

    pub(crate) fn is_decryption(self) -> bool {
        matches!(self, Self::Rsa { .. } | Self::Ecdh(Curve::X25519))
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PublicKey {
    Rsa(Rsa<openssl::pkey::Public>),
    Ec { curve: Curve, point: Vec<u8> },
    Raw { curve: Curve, key: Vec<u8> },
}

#[derive(Clone, Debug)]
pub(crate) struct KeyInfo {
    pub(crate) key_ref: KeyRef,
    pub(crate) algorithm: Algorithm,
    pub(crate) public_key: PublicKey,
    pub(crate) pin_policy: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct ApplicationInfo {
    pub(crate) version: (u8, u8),
    pub(crate) serial: String,
    pub(crate) pin_policy: u8,
    pub(crate) pin_min: u8,
    pub(crate) pin_max: u8,
    algorithms: Vec<(KeyRef, Algorithm)>,
}

impl ApplicationInfo {
    pub(crate) fn algorithm(&self, key_ref: KeyRef) -> Option<Algorithm> {
        self.algorithms
            .iter()
            .find_map(|(reference, algorithm)| (*reference == key_ref).then_some(*algorithm))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Client;

impl Client {
    pub(crate) fn select(&self, connector: &dyn Connector) -> Result<ApplicationInfo, Error> {
        select_application(connector, &OPENPGP_AID)?;
        let data = self.get_data(connector, 0x006e)?;
        parse_application_info(&data)
    }

    pub(crate) fn public_key(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        algorithm: Algorithm,
    ) -> Result<PublicKey, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GENERATE_ASYMMETRIC,
                p1: 0x81,
                p2: 0,
                data: key_ref.crt().to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        let body = tlv_value(0x7f49, &response)?;
        let fields = parse_tlvs(&body)?;
        match algorithm {
            Algorithm::Rsa { bits } => {
                let modulus = field_value(&fields, 0x81).ok_or(CKR_DATA_INVALID)?;
                let exponent = field_value(&fields, 0x82).ok_or(CKR_DATA_INVALID)?;
                if modulus.len() * 8 != bits {
                    return Err(CKR_DATA_INVALID.into());
                }
                let modulus = BigNum::from_slice(modulus).map_err(Error::from)?;
                let exponent = BigNum::from_slice(exponent).map_err(Error::from)?;
                Ok(PublicKey::Rsa(
                    Rsa::from_public_components(modulus, exponent).map_err(Error::from)?,
                ))
            }
            Algorithm::Ecdsa(curve) | Algorithm::Ecdh(curve)
                if curve.coordinate_length().is_some() =>
            {
                let point = field_value(&fields, 0x86).ok_or(CKR_DATA_INVALID)?;
                let expected = curve.coordinate_length().unwrap() * 2 + 1;
                if point.len() != expected || point[0] != 0x04 {
                    return Err(CKR_DATA_INVALID.into());
                }
                Ok(PublicKey::Ec {
                    curve,
                    point: point[1..].to_vec(),
                })
            }
            Algorithm::Ed25519 | Algorithm::Ecdh(Curve::X25519) => {
                let key = field_value(&fields, 0x86).ok_or(CKR_DATA_INVALID)?;
                if key.len() != 32 {
                    return Err(CKR_DATA_INVALID.into());
                }
                let curve = if matches!(algorithm, Algorithm::Ed25519) {
                    Curve::Ed25519
                } else {
                    Curve::X25519
                };
                Ok(PublicKey::Raw {
                    curve,
                    key: key.to_vec(),
                })
            }
            _ => Err(CKR_DATA_INVALID.into()),
        }
    }

    pub(crate) fn verify_pin(
        &self,
        connector: &dyn Connector,
        pin: &[u8],
        extended: bool,
    ) -> Result<(), Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0,
                p2: if extended { 0x82 } else { 0x81 },
                data: pin.to_vec(),
                le: None,
                extended: false,
            },
        )?;
        Ok(())
    }

    pub(crate) fn unverify(&self, connector: &dyn Connector, extended: bool) {
        let _ = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0xff,
                p2: if extended { 0x82 } else { 0x81 },
                data: Vec::new(),
                le: None,
                extended: false,
            },
        );
    }

    pub(crate) fn sign(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (ins, p1, p2) = match key_ref {
            KeyRef::Authentication => (INS_INTERNAL_AUTHENTICATE, 0, 0),
            KeyRef::Signature => (INS_PSO, 0x9e, 0x9a),
            KeyRef::Decipher => return Err(crate::CKR_KEY_FUNCTION_NOT_PERMITTED.into()),
        };
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins,
                p1,
                p2,
                data: input.to_vec(),
                le: Some(256),
                extended: input.len() > 255,
            },
        )?;
        Ok(response)
    }

    pub(crate) fn decipher(
        &self,
        connector: &dyn Connector,
        input: &[u8],
        raw: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(input.len() + 1);
        data.push(if raw { 0x00 } else { 0x02 });
        data.extend_from_slice(input);
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_PSO,
                p1: 0x80,
                p2: 0x86,
                data,
                le: Some(256),
                extended: input.len() >= 255,
            },
        )?;
        Ok(response)
    }

    pub(crate) fn challenge(
        &self,
        connector: &dyn Connector,
        length: usize,
    ) -> Result<Vec<u8>, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_CHALLENGE,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(length as u32),
                extended: length > 256,
            },
        )?;
        if response.len() != length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(response)
    }

    fn get_data(&self, connector: &dyn Connector, tag: u16) -> Result<Vec<u8>, Error> {
        self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_GET_DATA,
                p1: (tag >> 8) as u8,
                p2: tag as u8,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            },
        )
    }

    fn transmit(&self, connector: &dyn Connector, command: CommandApdu) -> Result<Vec<u8>, Error> {
        let response = transmit(connector, &command)?;
        require_success(response.status)?;
        Ok(response.data)
    }
}

fn require_success(status: u16) -> Result<(), Error> {
    match status {
        STATUS_SUCCESS => Ok(()),
        0x6983 => Err(CKR_PIN_LOCKED.into()),
        0x6982 | 0x6985 => Err(CKR_USER_NOT_LOGGED_IN.into()),
        0x63c0..=0x63cf => Err(CKR_PIN_INCORRECT.into()),
        _ => Err(CKR_DEVICE_ERROR.into()),
    }
}

fn parse_application_info(encoded: &[u8]) -> Result<ApplicationInfo, Error> {
    let body = tlv_value(0x6e, encoded)?;
    let fields = parse_tlvs(&body)?;
    let aid = field_value(&fields, 0x4f).ok_or(CKR_DATA_INVALID)?;
    if aid.len() < 14 || aid[..6] != OPENPGP_AID {
        return Err(CKR_DATA_INVALID.into());
    }
    let version = (bcd(aid[6]), bcd(aid[7]));
    let serial = if aid[10..14]
        .iter()
        .all(|value| value >> 4 < 10 && value & 0x0f < 10)
    {
        aid[10..14]
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect()
    } else {
        u32::from_be_bytes(aid[10..14].try_into().unwrap()).to_string()
    };
    let discretionary = field_value(&fields, 0x73)
        .map(|value| parse_tlvs(value))
        .transpose()?
        .unwrap_or_else(|| fields.clone());
    let pin_status = field_value(&discretionary, 0xc4).ok_or(CKR_DATA_INVALID)?;
    if pin_status.len() < 4 {
        return Err(CKR_DATA_INVALID.into());
    }
    let mut algorithms = Vec::new();
    for key_ref in KeyRef::ALL {
        if let Some(value) = field_value(&discretionary, key_ref.algorithm_tag()) {
            algorithms.push((key_ref, parse_algorithm(value)?));
        }
    }
    Ok(ApplicationInfo {
        version,
        serial,
        pin_policy: pin_status[0],
        pin_min: 6,
        pin_max: pin_status[1],
        algorithms,
    })
}

fn parse_algorithm(value: &[u8]) -> Result<Algorithm, Error> {
    let algorithm = *value.first().ok_or(CKR_DATA_INVALID)?;
    match algorithm {
        0x01 => {
            if value.len() < 6 {
                return Err(CKR_DATA_INVALID.into());
            }
            let bits = u16::from_be_bytes([value[1], value[2]]) as usize;
            if !matches!(bits, 1024 | 2048 | 3072 | 4096) {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(Algorithm::Rsa { bits })
        }
        0x12 | 0x13 | 0x16 => {
            let oid = value[1..].strip_suffix(&[0xff]).unwrap_or(&value[1..]);
            let curve = Curve::from_oid(oid).ok_or(CKR_DATA_INVALID)?;
            match algorithm {
                0x12 => Ok(Algorithm::Ecdh(curve)),
                0x13 => Ok(Algorithm::Ecdsa(curve)),
                0x16 => Ok(Algorithm::Ed25519),
                _ => unreachable!(),
            }
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn bcd(value: u8) -> u8 {
    (value >> 4) * 10 + (value & 0x0f)
}

fn field_value<'a>(fields: &'a [(u32, Vec<u8>)], tag: u32) -> Option<&'a [u8]> {
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == tag).then_some(value.as_slice()))
}

fn tlv_value(tag: u32, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let fields = parse_tlvs(encoded)?;
    field_value(&fields, tag)
        .map(<[u8]>::to_vec)
        .ok_or(CKR_DATA_INVALID.into())
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, Error> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        let (tag, tag_len) = parse_tag(encoded)?;
        encoded = &encoded[tag_len..];
        let (length, length_len) = parse_length(encoded)?;
        encoded = &encoded[length_len..];
        if encoded.len() < length {
            return Err(CKR_DATA_INVALID.into());
        }
        fields.push((tag, encoded[..length].to_vec()));
        encoded = &encoded[length..];
    }
    Ok(fields)
}

fn parse_tag(encoded: &[u8]) -> Result<(u32, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x1f != 0x1f {
        return Ok((first as u32, 1));
    }
    let second = *encoded.get(1).ok_or(CKR_DATA_INVALID)?;
    if second & 0x80 == 0 {
        Ok((((first as u32) << 8) | second as u32, 2))
    } else {
        Err(CKR_DATA_INVALID.into())
    }
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    match first {
        0..=0x7f => Ok((first as usize, 1)),
        0x81 => Ok((*encoded.get(1).ok_or(CKR_DATA_INVALID)? as usize, 2)),
        0x82 => {
            let bytes = encoded.get(1..3).ok_or(CKR_DATA_INVALID)?;
            Ok((u16::from_be_bytes([bytes[0], bytes[1]]) as usize, 3))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_data() -> Vec<u8> {
        vec![
            0x6e, 0x2b, 0x4f, 0x0e, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06,
            0x12, 0x34, 0x56, 0x78, 0x73, 0x19, 0xc1, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00,
            0xc2, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc4, 0x07, 0x01, 0x20,
            0x08, 0x03, 0x03, 0x03, 0x03,
        ]
    }

    #[test]
    fn parses_application_related_data() {
        let info = parse_application_info(&app_data()).unwrap();
        assert_eq!(info.version, (3, 4));
        assert_eq!(info.serial, "12345678");
        assert_eq!(info.algorithms.len(), 2);
        assert_eq!(
            info.algorithm(KeyRef::Signature),
            Some(Algorithm::Rsa { bits: 2048 })
        );
        assert_eq!(info.pin_policy, 1);
    }

    #[test]
    fn parses_lengths_and_tags() {
        assert_eq!(
            parse_tlvs(&[0x7f, 0x49, 0x81, 0x01, 0xaa]).unwrap(),
            vec![(0x7f49, vec![0xaa])]
        );
        let mut encoded = vec![0x01, 0x82, 0x01, 0x00];
        encoded.extend(std::iter::repeat_n(0, 256));
        assert_eq!(parse_tlvs(&encoded).unwrap()[0].1.len(), 256);
    }
}
