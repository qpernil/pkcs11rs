#![allow(dead_code)]

use crate::{
    error::Error, CommandApdu, Connector, ResponseApdu, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_REJECTED, CKR_KEY_SIZE_RANGE,
    CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_USER_NOT_LOGGED_IN,
};
use flate2::{read::GzDecoder, read::ZlibDecoder, write::GzEncoder, Compression};
use openssl::{
    memcmp,
    symm::{Cipher, Crypter, Mode},
};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub(crate) const PIV_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];
pub(crate) const ORIGIN_GENERATED: u8 = 1;
pub(crate) const ORIGIN_IMPORTED: u8 = 2;

const INS_SELECT: u8 = 0xa4;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2c;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_GET_DATA: u8 = 0xcb;
const INS_PUT_DATA: u8 = 0xdb;
const INS_IMPORT_KEY: u8 = 0xfe;
const INS_GET_VERSION: u8 = 0xfd;
const INS_GET_SERIAL: u8 = 0xf8;
const INS_GET_METADATA: u8 = 0xf7;
const INS_MOVE_KEY: u8 = 0xf6;
const INS_ATTEST: u8 = 0xf9;
const INS_SET_MANAGEMENT_KEY: u8 = 0xff;
const INS_SET_PIN_RETRIES: u8 = 0xfa;
const MANAGEMENT_KEY_REFERENCE: u8 = 0x9b;
const STATUS_SUCCESS: u16 = 0x9000;
const CERTIFICATE_UNCOMPRESSED: u8 = 0;
const CERTIFICATE_GZIP: u8 = 1;
const MAX_DECOMPRESSED_CERTIFICATE_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Version {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceInfo {
    pub(crate) version: Version,
    pub(crate) serial: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Algorithm {
    Rsa1024 = 0x06,
    Rsa2048 = 0x07,
    Rsa3072 = 0x05,
    Rsa4096 = 0x16,
    EccP256 = 0x11,
    EccP384 = 0x14,
    Ed25519 = 0xe0,
    X25519 = 0xe1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagementAlgorithm {
    TripleDes = 0x03,
    Aes128 = 0x08,
    Aes192 = 0x0a,
    Aes256 = 0x0c,
}

impl ManagementAlgorithm {
    fn from_id(id: u8) -> Option<Self> {
        match id {
            0x03 => Some(Self::TripleDes),
            0x08 => Some(Self::Aes128),
            0x0a => Some(Self::Aes192),
            0x0c => Some(Self::Aes256),
            _ => None,
        }
    }

    fn cipher(self) -> Cipher {
        match self {
            Self::TripleDes => Cipher::des_ede3_ecb(),
            Self::Aes128 => Cipher::aes_128_ecb(),
            Self::Aes192 => Cipher::aes_192_ecb(),
            Self::Aes256 => Cipher::aes_256_ecb(),
        }
    }

    fn key_length(self) -> usize {
        match self {
            Self::TripleDes | Self::Aes192 => 24,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }
}

impl Algorithm {
    pub(crate) fn from_id(id: u8) -> Option<Self> {
        match id {
            0x06 => Some(Self::Rsa1024),
            0x07 => Some(Self::Rsa2048),
            0x05 => Some(Self::Rsa3072),
            0x16 => Some(Self::Rsa4096),
            0x11 => Some(Self::EccP256),
            0x14 => Some(Self::EccP384),
            0xe0 => Some(Self::Ed25519),
            0xe1 => Some(Self::X25519),
            _ => None,
        }
    }

    pub(crate) fn rsa_input_length(self) -> Option<usize> {
        match self {
            Self::Rsa1024 => Some(128),
            Self::Rsa2048 => Some(256),
            Self::Rsa3072 => Some(384),
            Self::Rsa4096 => Some(512),
            _ => None,
        }
    }

    fn ec_input_length(self) -> Option<usize> {
        match self {
            Self::EccP256 => Some(32),
            Self::EccP384 => Some(48),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Slot {
    Authentication = 0x9a,
    Signature = 0x9c,
    KeyManagement = 0x9d,
    CardAuthentication = 0x9e,
    Retired1 = 0x82,
    Retired2 = 0x83,
    Retired3 = 0x84,
    Retired4 = 0x85,
    Retired5 = 0x86,
    Retired6 = 0x87,
    Retired7 = 0x88,
    Retired8 = 0x89,
    Retired9 = 0x8a,
    Retired10 = 0x8b,
    Retired11 = 0x8c,
    Retired12 = 0x8d,
    Retired13 = 0x8e,
    Retired14 = 0x8f,
    Retired15 = 0x90,
    Retired16 = 0x91,
    Retired17 = 0x92,
    Retired18 = 0x93,
    Retired19 = 0x94,
    Retired20 = 0x95,
    Attestation = 0xf9,
}

impl Slot {
    pub(crate) const ALL: [Self; 25] = [
        Self::Authentication,
        Self::Signature,
        Self::KeyManagement,
        Self::CardAuthentication,
        Self::Retired1,
        Self::Retired2,
        Self::Retired3,
        Self::Retired4,
        Self::Retired5,
        Self::Retired6,
        Self::Retired7,
        Self::Retired8,
        Self::Retired9,
        Self::Retired10,
        Self::Retired11,
        Self::Retired12,
        Self::Retired13,
        Self::Retired14,
        Self::Retired15,
        Self::Retired16,
        Self::Retired17,
        Self::Retired18,
        Self::Retired19,
        Self::Retired20,
        Self::Attestation,
    ];

    pub(crate) fn all() -> &'static [Self] {
        &Self::ALL
    }

    pub(crate) fn from_id(id: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|slot| *slot as u8 == id)
    }

    pub(crate) fn cka_id(self) -> u8 {
        match self {
            Self::Authentication => 1,
            Self::Signature => 2,
            Self::KeyManagement => 3,
            Self::CardAuthentication => 4,
            Self::Retired1
            | Self::Retired2
            | Self::Retired3
            | Self::Retired4
            | Self::Retired5
            | Self::Retired6
            | Self::Retired7
            | Self::Retired8
            | Self::Retired9
            | Self::Retired10
            | Self::Retired11
            | Self::Retired12
            | Self::Retired13
            | Self::Retired14
            | Self::Retired15
            | Self::Retired16
            | Self::Retired17
            | Self::Retired18
            | Self::Retired19
            | Self::Retired20 => 5 + (self as u8 - Self::Retired1 as u8),
            Self::Attestation => 25,
        }
    }

    pub(crate) fn from_cka_id(id: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|slot| slot.cka_id() == id)
    }

    pub(crate) fn is_retired(self) -> bool {
        (Self::Retired1 as u8..=Self::Retired20 as u8).contains(&(self as u8))
    }

    pub(crate) fn certificate_object(self) -> u32 {
        match self {
            Self::Authentication => 0x5f_c105,
            Self::Signature => 0x5f_c10a,
            Self::KeyManagement => 0x5f_c10b,
            Self::CardAuthentication => 0x5f_c101,
            Self::Retired1
            | Self::Retired2
            | Self::Retired3
            | Self::Retired4
            | Self::Retired5
            | Self::Retired6
            | Self::Retired7
            | Self::Retired8
            | Self::Retired9
            | Self::Retired10
            | Self::Retired11
            | Self::Retired12
            | Self::Retired13
            | Self::Retired14
            | Self::Retired15
            | Self::Retired16
            | Self::Retired17
            | Self::Retired18
            | Self::Retired19
            | Self::Retired20 => 0x5f_c10d + (self as u32 - Self::Retired1 as u32),
            Self::Attestation => 0x5f_ff01,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataObjectMapping {
    pub(crate) object_id: u32,
    pub(crate) cka_id: u8,
    pub(crate) name: &'static str,
    pub(crate) slot: Option<Slot>,
}

pub(crate) const DATA_OBJECTS: &[DataObjectMapping] = &[
    DataObjectMapping {
        object_id: 0x5f_c105,
        cka_id: 1,
        name: "X.509 Certificate for PIV Authentication",
        slot: Some(Slot::Authentication),
    },
    DataObjectMapping {
        object_id: 0x5f_c10a,
        cka_id: 2,
        name: "X.509 Certificate for Digital Signature",
        slot: Some(Slot::Signature),
    },
    DataObjectMapping {
        object_id: 0x5f_c10b,
        cka_id: 3,
        name: "X.509 Certificate for Key Management",
        slot: Some(Slot::KeyManagement),
    },
    DataObjectMapping {
        object_id: 0x5f_c101,
        cka_id: 4,
        name: "X.509 Certificate for Card Authentication",
        slot: Some(Slot::CardAuthentication),
    },
    DataObjectMapping {
        object_id: 0x5f_c10d,
        cka_id: 5,
        name: "X.509 Certificate for Retired Key 1",
        slot: Some(Slot::Retired1),
    },
    DataObjectMapping {
        object_id: 0x5f_c10e,
        cka_id: 6,
        name: "X.509 Certificate for Retired Key 2",
        slot: Some(Slot::Retired2),
    },
    DataObjectMapping {
        object_id: 0x5f_c10f,
        cka_id: 7,
        name: "X.509 Certificate for Retired Key 3",
        slot: Some(Slot::Retired3),
    },
    DataObjectMapping {
        object_id: 0x5f_c110,
        cka_id: 8,
        name: "X.509 Certificate for Retired Key 4",
        slot: Some(Slot::Retired4),
    },
    DataObjectMapping {
        object_id: 0x5f_c111,
        cka_id: 9,
        name: "X.509 Certificate for Retired Key 5",
        slot: Some(Slot::Retired5),
    },
    DataObjectMapping {
        object_id: 0x5f_c112,
        cka_id: 10,
        name: "X.509 Certificate for Retired Key 6",
        slot: Some(Slot::Retired6),
    },
    DataObjectMapping {
        object_id: 0x5f_c113,
        cka_id: 11,
        name: "X.509 Certificate for Retired Key 7",
        slot: Some(Slot::Retired7),
    },
    DataObjectMapping {
        object_id: 0x5f_c114,
        cka_id: 12,
        name: "X.509 Certificate for Retired Key 8",
        slot: Some(Slot::Retired8),
    },
    DataObjectMapping {
        object_id: 0x5f_c115,
        cka_id: 13,
        name: "X.509 Certificate for Retired Key 9",
        slot: Some(Slot::Retired9),
    },
    DataObjectMapping {
        object_id: 0x5f_c116,
        cka_id: 14,
        name: "X.509 Certificate for Retired Key 10",
        slot: Some(Slot::Retired10),
    },
    DataObjectMapping {
        object_id: 0x5f_c117,
        cka_id: 15,
        name: "X.509 Certificate for Retired Key 11",
        slot: Some(Slot::Retired11),
    },
    DataObjectMapping {
        object_id: 0x5f_c118,
        cka_id: 16,
        name: "X.509 Certificate for Retired Key 12",
        slot: Some(Slot::Retired12),
    },
    DataObjectMapping {
        object_id: 0x5f_c119,
        cka_id: 17,
        name: "X.509 Certificate for Retired Key 13",
        slot: Some(Slot::Retired13),
    },
    DataObjectMapping {
        object_id: 0x5f_c11a,
        cka_id: 18,
        name: "X.509 Certificate for Retired Key 14",
        slot: Some(Slot::Retired14),
    },
    DataObjectMapping {
        object_id: 0x5f_c11b,
        cka_id: 19,
        name: "X.509 Certificate for Retired Key 15",
        slot: Some(Slot::Retired15),
    },
    DataObjectMapping {
        object_id: 0x5f_c11c,
        cka_id: 20,
        name: "X.509 Certificate for Retired Key 16",
        slot: Some(Slot::Retired16),
    },
    DataObjectMapping {
        object_id: 0x5f_c11d,
        cka_id: 21,
        name: "X.509 Certificate for Retired Key 17",
        slot: Some(Slot::Retired17),
    },
    DataObjectMapping {
        object_id: 0x5f_c11e,
        cka_id: 22,
        name: "X.509 Certificate for Retired Key 18",
        slot: Some(Slot::Retired18),
    },
    DataObjectMapping {
        object_id: 0x5f_c11f,
        cka_id: 23,
        name: "X.509 Certificate for Retired Key 19",
        slot: Some(Slot::Retired19),
    },
    DataObjectMapping {
        object_id: 0x5f_c120,
        cka_id: 24,
        name: "X.509 Certificate for Retired Key 20",
        slot: Some(Slot::Retired20),
    },
    DataObjectMapping {
        object_id: 0x5f_ff01,
        cka_id: 25,
        name: "X.509 Certificate for PIV Attestation",
        slot: Some(Slot::Attestation),
    },
    DataObjectMapping {
        object_id: 0x5f_c107,
        cka_id: 26,
        name: "Card Capability Container",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c102,
        cka_id: 27,
        name: "Cardholder Unique Identifier",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c103,
        cka_id: 28,
        name: "Cardholder Fingerprints",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c106,
        cka_id: 29,
        name: "Security Object",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c108,
        cka_id: 30,
        name: "Cardholder Facial Images",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c109,
        cka_id: 31,
        name: "Printed Information",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x7e,
        cka_id: 32,
        name: "Discovery Object",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c10c,
        cka_id: 33,
        name: "Key History Object",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c121,
        cka_id: 34,
        name: "Cardholder Iris Images",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x7f61,
        cka_id: 35,
        name: "Biometric Information Templates Group Template",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c122,
        cka_id: 36,
        name: "Secure Messaging Certificate Signer",
        slot: None,
    },
    DataObjectMapping {
        object_id: 0x5f_c123,
        cka_id: 37,
        name: "Pairing Code Reference Data Container",
        slot: None,
    },
];

pub(crate) fn data_object_mapping(object_id: u32) -> Option<&'static DataObjectMapping> {
    DATA_OBJECTS
        .iter()
        .find(|mapping| mapping.object_id == object_id)
}

pub(crate) fn data_object_mapping_by_cka_id(cka_id: u8) -> Option<&'static DataObjectMapping> {
    DATA_OBJECTS.iter().find(|mapping| mapping.cka_id == cka_id)
}

pub(crate) fn data_object_oid(mapping: &DataObjectMapping) -> Vec<u8> {
    match mapping.cka_id {
        1 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x01],
        2 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x00],
        3 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x02],
        4 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x05, 0x00],
        5..=24 => vec![
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x07,
            0x02,
            0x10,
            mapping.cka_id - 4,
        ],
        25 => vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03],
        26 => vec![
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x01, 0x81, 0x5b, 0x00,
        ],
        27 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00],
        28 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x10],
        29 => vec![
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x81, 0x10, 0x00,
        ],
        30 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x30],
        31 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x01],
        32 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x50],
        33 => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x60],
        34..=37 => vec![
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x07,
            0x02,
            0x10,
            mapping.cka_id - 13,
        ],
        _ => unreachable!("PIV data object mapping has an invalid CKA_ID"),
    }
}

pub(crate) fn data_object_mapping_by_oid(oid: &[u8]) -> Option<&'static DataObjectMapping> {
    DATA_OBJECTS
        .iter()
        .find(|mapping| data_object_oid(mapping) == oid)
}

pub(crate) fn data_object_allowed(object_id: u32) -> bool {
    data_object_mapping(object_id).is_some()
        || ((0x5f_ff00..=0x5f_ffff).contains(&object_id) && object_id != 0x5f_ff01)
}

pub(crate) fn data_object_name(object_id: u32) -> String {
    data_object_mapping(object_id)
        .map(|mapping| mapping.name.to_owned())
        .unwrap_or_else(|| format!("PIV data {object_id:06X}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Metadata {
    pub(crate) algorithm: Option<u8>,
    pub(crate) pin_policy: Option<u8>,
    pub(crate) touch_policy: Option<u8>,
    pub(crate) origin: Option<u8>,
    pub(crate) public_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MetadataPublicKey {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    Ec(Vec<u8>),
    Raw(Vec<u8>),
}

pub(crate) struct PrivateKeyImport {
    pub(crate) algorithm: Algorithm,
    pub(crate) components: Vec<(u32, Zeroizing<Vec<u8>>)>,
    pub(crate) public_key: MetadataPublicKey,
}

impl std::fmt::Debug for PrivateKeyImport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateKeyImport")
            .field("algorithm", &self.algorithm)
            .field(
                "components",
                &self
                    .components
                    .iter()
                    .map(|(tag, value)| (*tag, value.len()))
                    .collect::<Vec<_>>(),
            )
            .field("public_key", &self.public_key)
            .finish()
    }
}

pub(crate) fn parse_metadata_public_key(
    algorithm: Algorithm,
    encoded: &[u8],
) -> Result<MetadataPublicKey, Error> {
    let fields = parse_tlvs(encoded)?;
    match algorithm {
        Algorithm::Rsa1024 | Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
            let modulus = field(&fields, 0x81)
                .filter(|value| !value.is_empty())
                .ok_or(CKR_DATA_INVALID)?;
            let exponent = field(&fields, 0x82)
                .filter(|value| !value.is_empty())
                .ok_or(CKR_DATA_INVALID)?;
            Ok(MetadataPublicKey::Rsa {
                modulus: modulus.to_vec(),
                exponent: exponent.to_vec(),
            })
        }
        Algorithm::EccP256 | Algorithm::EccP384 => field(&fields, 0x86)
            .filter(|value| !value.is_empty())
            .map(<[u8]>::to_vec)
            .map(MetadataPublicKey::Ec)
            .ok_or_else(|| CKR_DATA_INVALID.into()),
        Algorithm::Ed25519 | Algorithm::X25519 => field(&fields, 0x86)
            .filter(|value| !value.is_empty())
            .map(<[u8]>::to_vec)
            .map(MetadataPublicKey::Raw)
            .ok_or_else(|| CKR_DATA_INVALID.into()),
    }
}

const YUBICO_PIV_USAGE_POLICY_OID: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x44, 0x0a, 0x03, 0x08];

fn der_tlv(input: &[u8], offset: usize) -> Result<(u8, usize, usize), Error> {
    let tag = *input.get(offset).ok_or(CKR_DATA_INVALID)?;
    let length_offset = offset.checked_add(1).ok_or(CKR_DATA_INVALID)?;
    let first_length = *input.get(length_offset).ok_or(CKR_DATA_INVALID)?;
    let (length, content_offset) = if first_length & 0x80 == 0 {
        (first_length as usize, length_offset + 1)
    } else {
        let length_bytes = (first_length & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > 4 {
            return Err(CKR_DATA_INVALID.into());
        }
        let end = length_offset
            .checked_add(1 + length_bytes)
            .ok_or(CKR_DATA_INVALID)?;
        let bytes = input.get(length_offset + 1..end).ok_or(CKR_DATA_INVALID)?;
        if bytes.first() == Some(&0) {
            return Err(CKR_DATA_INVALID.into());
        }
        (
            bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | *byte as usize),
            end,
        )
    };
    let end = content_offset.checked_add(length).ok_or(CKR_DATA_INVALID)?;
    if end > input.len() {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok((tag, content_offset, end))
}

fn find_der_extension(input: &[u8], oid: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    fn scan(input: &[u8], start: usize, end: usize, oid: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut offset = start;
        while offset < end {
            let (tag, content, next) = der_tlv(input, offset)?;
            if next > end {
                return Err(CKR_DATA_INVALID.into());
            }
            if tag == 0x30 {
                let (first_tag, first_content, first_next) = der_tlv(input, content)?;
                if first_tag == 0x06 && input.get(first_content..first_next) == Some(oid) {
                    let mut child = first_next;
                    while child < next {
                        let (child_tag, child_content, child_next) = der_tlv(input, child)?;
                        if child_tag == 0x04 {
                            return Ok(Some(input[child_content..child_next].to_vec()));
                        }
                        child = child_next;
                    }
                }
                if let Some(value) = scan(input, content, next, oid)? {
                    return Ok(Some(value));
                }
            } else if tag & 0x20 != 0 {
                if let Some(value) = scan(input, content, next, oid)? {
                    return Ok(Some(value));
                }
            }
            offset = next;
        }
        Ok(None)
    }

    let (tag, content, end) = der_tlv(input, 0)?;
    if tag != 0x30 || end != input.len() {
        return Err(CKR_DATA_INVALID.into());
    }
    scan(input, content, end, oid)
}

pub(crate) fn parse_attestation_metadata(certificate: &[u8]) -> Result<Metadata, Error> {
    let policy = find_der_extension(certificate, YUBICO_PIV_USAGE_POLICY_OID)?;
    let (pin_policy, touch_policy) = match policy {
        Some(policy) => {
            let [pin_policy, touch_policy] = policy.as_slice() else {
                return Err(CKR_DATA_INVALID.into());
            };
            (Some(*pin_policy), Some(*touch_policy))
        }
        None => (None, None),
    };
    Ok(Metadata {
        algorithm: None,
        pin_policy,
        touch_policy,
        origin: Some(1),
        public_key: None,
    })
}

#[derive(Debug, Default)]
pub(crate) struct Client;

impl Client {
    pub(crate) fn select(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
    ) -> Result<DeviceInfo, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_SELECT,
                p1: 0x04,
                p2: 0,
                data: application_aid.to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        require_success(response.status)?;

        let version_data = self.command(connector, INS_GET_VERSION, 0, 0, &[])?;
        if version_data.len() != 3 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let version = Version {
            major: version_data[0],
            minor: version_data[1],
            patch: version_data[2],
        };
        let serial = match self.command(connector, INS_GET_SERIAL, 0, 0, &[]) {
            Ok(serial) if serial.len() == 4 => Some(u32::from_be_bytes(
                serial.try_into().map_err(|_| CKR_DEVICE_ERROR)?,
            )),
            Ok(_) => return Err(CKR_DEVICE_ERROR.into()),
            Err(Error::Generic(rv)) if rv == CKR_FUNCTION_NOT_SUPPORTED as _ => None,
            Err(error) => return Err(error),
        };
        Ok(DeviceInfo { version, serial })
    }

    pub(crate) fn verify_pin(&self, connector: &dyn Connector, pin: &[u8]) -> Result<(), Error> {
        if !(6..=8).contains(&pin.len()) {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let mut padded = [0xff; 8];
        padded[..pin.len()].copy_from_slice(pin);
        self.command(connector, INS_VERIFY, 0, 0x80, &padded)
            .map(|_| ())
    }

    pub(crate) fn change_pin(
        &self,
        connector: &dyn Connector,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        self.change_reference(connector, INS_CHANGE_REFERENCE, 0x80, old_pin, new_pin)
    }

    pub(crate) fn change_puk(
        &self,
        connector: &dyn Connector,
        old_puk: &[u8],
        new_puk: &[u8],
    ) -> Result<(), Error> {
        self.change_reference(connector, INS_CHANGE_REFERENCE, 0x81, old_puk, new_puk)
    }

    pub(crate) fn unblock_pin(
        &self,
        connector: &dyn Connector,
        puk: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        self.change_reference(connector, INS_RESET_RETRY, 0x80, puk, new_pin)
    }

    fn change_reference(
        &self,
        connector: &dyn Connector,
        instruction: u8,
        reference: u8,
        old_value: &[u8],
        new_value: &[u8],
    ) -> Result<(), Error> {
        if !(6..=8).contains(&old_value.len()) || !(6..=8).contains(&new_value.len()) {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let mut request = Zeroizing::new(vec![0xff; 16]);
        request[..old_value.len()].copy_from_slice(old_value);
        request[8..8 + new_value.len()].copy_from_slice(new_value);
        self.command(connector, instruction, 0, reference, &request)?;
        Ok(())
    }

    pub(crate) fn set_pin_retries(
        &self,
        connector: &dyn Connector,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<(), Error> {
        if pin_retries == 0 || puk_retries == 0 {
            return Err(CKR_DATA_INVALID.into());
        }
        self.command(
            connector,
            INS_SET_PIN_RETRIES,
            pin_retries,
            puk_retries,
            &[],
        )?;
        Ok(())
    }

    pub(crate) fn pin_retries(&self, connector: &dyn Connector) -> Result<u8, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins: INS_VERIFY,
                p1: 0,
                p2: 0x80,
                data: Vec::new(),
                le: None,
                extended: false,
            },
        )?;
        match response.status {
            status if status & 0xfff0 == 0x63c0 => Ok((status & 0xf) as u8),
            0x6983 => Ok(0),
            STATUS_SUCCESS => Ok(u8::MAX),
            status => Err(map_status(status)),
        }
    }

    pub(crate) fn metadata(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<Metadata, Error> {
        self.metadata_for_reference(connector, slot as u8)
    }

    fn metadata_for_reference(
        &self,
        connector: &dyn Connector,
        reference: u8,
    ) -> Result<Metadata, Error> {
        let data = self.command(connector, INS_GET_METADATA, 0, reference, &[])?;
        let fields = parse_tlvs(&data)?;
        let policy = field(&fields, 0x02);
        Ok(Metadata {
            algorithm: field(&fields, 0x01).and_then(|value| value.first().copied()),
            pin_policy: policy.and_then(|value| value.first().copied()),
            touch_policy: policy.and_then(|value| value.get(1).copied()),
            origin: field(&fields, 0x03).and_then(|value| value.first().copied()),
            public_key: field(&fields, 0x04).map(<[u8]>::to_vec),
        })
    }

    pub(crate) fn authenticate_management_key(
        &self,
        connector: &dyn Connector,
        key: &[u8],
    ) -> Result<(), Error> {
        let algorithm = self
            .metadata_for_reference(connector, MANAGEMENT_KEY_REFERENCE)
            .ok()
            .and_then(|metadata| metadata.algorithm)
            .and_then(ManagementAlgorithm::from_id)
            .unwrap_or(ManagementAlgorithm::TripleDes);
        if key.len() != algorithm.key_length() {
            return Err(CKR_PIN_LEN_RANGE.into());
        }

        let request = encode_tlv(0x7c, &encode_tlv(0x80, &[])?)?;
        let response = self.command(
            connector,
            INS_AUTHENTICATE,
            algorithm as u8,
            MANAGEMENT_KEY_REFERENCE,
            &request,
        )?;
        let outer = parse_tlvs(&response)?;
        let dynamic = field(&outer, 0x7c).ok_or(CKR_DATA_INVALID)?;
        let fields = parse_tlvs(dynamic)?;
        let card_challenge = field(&fields, 0x80).ok_or(CKR_DATA_INVALID)?;
        if card_challenge.len() != algorithm.cipher().block_size() {
            return Err(CKR_DATA_INVALID.into());
        }

        let card_response = crypt_management_block(algorithm, key, card_challenge, Mode::Decrypt)?;
        let mut host_challenge = Zeroizing::new(vec![0; algorithm.cipher().block_size()]);
        openssl::rand::rand_bytes(&mut host_challenge)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let mut dynamic = encode_tlv(0x80, &card_response)?;
        dynamic.extend_from_slice(&encode_tlv(0x81, &host_challenge)?);
        let request = encode_tlv(0x7c, &dynamic)?;
        let response = self.command(
            connector,
            INS_AUTHENTICATE,
            algorithm as u8,
            MANAGEMENT_KEY_REFERENCE,
            &request,
        )?;
        let outer = parse_tlvs(&response)?;
        let dynamic = field(&outer, 0x7c).ok_or(CKR_DATA_INVALID)?;
        let fields = parse_tlvs(dynamic)?;
        let card_cryptogram = field(&fields, 0x82).ok_or(CKR_DATA_INVALID)?;
        let expected = crypt_management_block(algorithm, key, &host_challenge, Mode::Encrypt)?;
        if !memcmp::eq(card_cryptogram, &expected) {
            return Err(CKR_PIN_INCORRECT.into());
        }
        Ok(())
    }

    pub(crate) fn set_management_key(
        &self,
        connector: &dyn Connector,
        new_key: &[u8],
    ) -> Result<(), Error> {
        let metadata = self.metadata_for_reference(connector, MANAGEMENT_KEY_REFERENCE)?;
        let algorithm = metadata
            .algorithm
            .and_then(ManagementAlgorithm::from_id)
            .ok_or(CKR_DATA_INVALID)?;
        if new_key.len() != algorithm.key_length() {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let touch_policy = metadata.touch_policy.unwrap_or(0);
        let p2 = match touch_policy {
            0 | 1 => 0xff,
            2 => 0xfe,
            _ => return Err(CKR_DATA_INVALID.into()),
        };
        let mut request = Zeroizing::new(vec![algorithm as u8, MANAGEMENT_KEY_REFERENCE]);
        request.push(new_key.len() as u8);
        request.extend_from_slice(new_key);
        self.command(connector, INS_SET_MANAGEMENT_KEY, 0xff, p2, &request)?;
        Ok(())
    }

    pub(crate) fn generate_key_pair(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        algorithm: Algorithm,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<MetadataPublicKey, Error> {
        if slot == Slot::Attestation {
            return Err(CKR_FUNCTION_REJECTED.into());
        }
        if pin_policy > 5 || touch_policy > 3 {
            return Err(CKR_DATA_INVALID.into());
        }
        let mut attributes = encode_tlv(0x80, &[algorithm as u8])?;
        if pin_policy != 0 {
            attributes.extend_from_slice(&encode_tlv(0xaa, &[pin_policy])?);
        }
        if touch_policy != 0 {
            attributes.extend_from_slice(&encode_tlv(0xab, &[touch_policy])?);
        }
        let request = encode_tlv(0xac, &attributes)?;
        let response = self.command(connector, INS_GENERATE_ASYMMETRIC, 0, slot as u8, &request)?;
        let fields = parse_tlvs(&response)?;
        let public_key = field(&fields, 0x7f49).ok_or(CKR_DATA_INVALID)?;
        parse_metadata_public_key(algorithm, public_key)
    }

    pub(crate) fn import_private_key(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        key: &PrivateKeyImport,
        pin_policy: u8,
        touch_policy: u8,
    ) -> Result<(), Error> {
        if slot == Slot::Attestation || pin_policy > 5 || touch_policy > 3 {
            return Err(CKR_DATA_INVALID.into());
        }
        let element_length = match key.algorithm {
            Algorithm::Rsa1024 => 64,
            Algorithm::Rsa2048 => 128,
            Algorithm::Rsa3072 => 192,
            Algorithm::Rsa4096 => 256,
            Algorithm::EccP256 | Algorithm::Ed25519 | Algorithm::X25519 => 32,
            Algorithm::EccP384 => 48,
        };
        let mut request = Zeroizing::new(Vec::new());
        for (tag, component) in &key.components {
            if component.is_empty() || component.len() > element_length {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let mut padded = Zeroizing::new(vec![0; element_length]);
            padded[element_length - component.len()..].copy_from_slice(component);
            request.extend_from_slice(&encode_tlv(*tag, &padded)?);
        }
        if pin_policy != 0 {
            request.extend_from_slice(&encode_tlv(0xaa, &[pin_policy])?);
        }
        if touch_policy != 0 {
            request.extend_from_slice(&encode_tlv(0xab, &[touch_policy])?);
        }
        self.command(
            connector,
            INS_IMPORT_KEY,
            key.algorithm as u8,
            slot as u8,
            &request,
        )?;
        Ok(())
    }

    pub(crate) fn put_data(
        &self,
        connector: &dyn Connector,
        object_id: u32,
        value: &[u8],
    ) -> Result<(), Error> {
        if object_id > 0x00ff_ffff {
            return Err(CKR_DATA_INVALID.into());
        }
        let bytes = object_id.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        let mut request = encode_tlv(0x5c, &bytes[first..])?;
        request.extend_from_slice(&encode_tlv(0x53, value)?);
        self.command(connector, INS_PUT_DATA, 0x3f, 0xff, &request)?;
        Ok(())
    }

    pub(crate) fn put_certificate(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        certificate: &[u8],
    ) -> Result<Vec<u8>, Error> {
        openssl::x509::X509::from_der(certificate).map_err(|_| Error::from(CKR_DATA_INVALID))?;
        let object = encode_certificate_object(certificate)?;
        self.put_data(connector, slot.certificate_object(), &object)?;
        Ok(object)
    }

    pub(crate) fn delete_certificate(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<(), Error> {
        self.put_data(connector, slot.certificate_object(), &[])
    }

    pub(crate) fn delete_key(&self, connector: &dyn Connector, slot: Slot) -> Result<(), Error> {
        if slot == Slot::Attestation {
            return Err(CKR_FUNCTION_REJECTED.into());
        }
        self.command(connector, INS_MOVE_KEY, 0xff, slot as u8, &[])?;
        Ok(())
    }

    pub(crate) fn move_key(
        &self,
        connector: &dyn Connector,
        from: Slot,
        to: Slot,
    ) -> Result<(), Error> {
        if from == Slot::Attestation || to == Slot::Attestation {
            return Err(CKR_FUNCTION_REJECTED.into());
        }
        if from == to {
            return Ok(());
        }
        self.command(connector, INS_MOVE_KEY, to as u8, from as u8, &[])?;
        Ok(())
    }

    pub(crate) fn certificate(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<Vec<u8>, Error> {
        self.certificate_and_data(connector, slot)
            .map(|(certificate, _)| certificate)
    }

    pub(crate) fn certificate_and_data(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let object = self.get_data(connector, slot.certificate_object())?;
        let certificate = decode_certificate_object(&object)?;
        Ok((certificate, object))
    }

    pub(crate) fn attestation(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<Vec<u8>, Error> {
        self.command(connector, INS_ATTEST, slot as u8, 0, &[])
    }

    pub(crate) fn get_data(
        &self,
        connector: &dyn Connector,
        object_id: u32,
    ) -> Result<Vec<u8>, Error> {
        if object_id > 0x00ff_ffff {
            return Err(CKR_DATA_INVALID.into());
        }
        let bytes = object_id.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        let request = encode_tlv(0x5c, &bytes[first..])?;
        let response = self.command(connector, INS_GET_DATA, 0x3f, 0xff, &request)?;
        let fields = parse_tlvs(&response)?;
        field(&fields, 0x53)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| CKR_DATA_INVALID.into())
    }

    pub(crate) fn sign(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        algorithm: Algorithm,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if let Some(length) = algorithm.rsa_input_length() {
            if input.len() != length {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        } else if let Some(length) = algorithm.ec_input_length() {
            if input.len() > length {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        } else if algorithm != Algorithm::Ed25519 {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        self.general_authenticate(connector, slot, algorithm, 0x81, input)
    }

    pub(crate) fn decipher(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        algorithm: Algorithm,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let tag = if let Some(length) = algorithm.rsa_input_length() {
            if input.len() != length {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            0x81
        } else if let Some(length) = algorithm.ec_input_length() {
            if input.len() != length * 2 + 1 {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            0x85
        } else if algorithm == Algorithm::X25519 && input.len() == 32 {
            0x85
        } else {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        };
        self.general_authenticate(connector, slot, algorithm, tag, input)
    }

    fn general_authenticate(
        &self,
        connector: &dyn Connector,
        slot: Slot,
        algorithm: Algorithm,
        input_tag: u32,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut dynamic = encode_tlv(0x82, &[])?;
        dynamic.extend_from_slice(&encode_tlv(input_tag, input)?);
        let request = encode_tlv(0x7c, &dynamic)?;
        let response = self.command(
            connector,
            INS_AUTHENTICATE,
            algorithm as u8,
            slot as u8,
            &request,
        )?;
        let outer = parse_tlvs(&response)?;
        let dynamic = field(&outer, 0x7c).ok_or(CKR_DATA_INVALID)?;
        let fields = parse_tlvs(dynamic)?;
        field(&fields, 0x82)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| CKR_DATA_INVALID.into())
    }

    fn command(
        &self,
        connector: &dyn Connector,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let response = self.transmit(
            connector,
            CommandApdu {
                cla: 0,
                ins,
                p1,
                p2,
                data: data.to_vec(),
                le: Some(256),
                extended: false,
            },
        )?;
        require_success(response.status)?;
        Ok(response.data)
    }

    fn transmit(
        &self,
        connector: &dyn Connector,
        command: CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        connector.send_apdu(&command)
    }
}

fn crypt_management_block(
    algorithm: ManagementAlgorithm,
    key: &[u8],
    input: &[u8],
    mode: Mode,
) -> Result<Vec<u8>, Error> {
    let cipher = algorithm.cipher();
    if key.len() != algorithm.key_length() || input.len() != cipher.block_size() {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut crypter = Crypter::new(cipher, mode, key, None).map_err(Error::from)?;
    crypter.pad(false);
    let mut output = vec![0; input.len() + cipher.block_size()];
    let mut length = crypter.update(input, &mut output).map_err(Error::from)?;
    length += crypter
        .finalize(&mut output[length..])
        .map_err(Error::from)?;
    output.truncate(length);
    Ok(output)
}

fn require_success(status: u16) -> Result<(), Error> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(map_status(status))
    }
}

fn map_status(status: u16) -> Error {
    match status {
        status if status & 0xfff0 == 0x63c0 => CKR_PIN_INCORRECT.into(),
        0x6982 => CKR_USER_NOT_LOGGED_IN.into(),
        0x6983 => CKR_PIN_LOCKED.into(),
        0x6985 => CKR_FUNCTION_REJECTED.into(),
        0x6d00 => CKR_FUNCTION_NOT_SUPPORTED.into(),
        _ => CKR_DEVICE_ERROR.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Tlv<'a> {
    tag: u32,
    value: &'a [u8],
}

fn field<'a>(fields: &'a [Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|field| field.tag == tag)
        .map(|field| field.value)
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<Tlv<'_>>, Error> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        let (tag, tag_length) = parse_tag(encoded)?;
        encoded = &encoded[tag_length..];
        let (length, length_length) = parse_length(encoded)?;
        encoded = &encoded[length_length..];
        if length > encoded.len() {
            return Err(CKR_DATA_INVALID.into());
        }
        let (value, remaining) = encoded.split_at(length);
        fields.push(Tlv { tag, value });
        encoded = remaining;
    }
    Ok(fields)
}

fn parse_tag(encoded: &[u8]) -> Result<(u32, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x1f != 0x1f {
        return Ok((first as u32, 1));
    }
    let mut tag = first as u32;
    for (index, byte) in encoded.iter().copied().enumerate().skip(1).take(3) {
        if index == 1 && byte & 0x7f == 0 {
            return Err(CKR_DATA_INVALID.into());
        }
        tag = (tag << 8) | byte as u32;
        if byte & 0x80 == 0 {
            return Ok((tag, index + 1));
        }
    }
    Err(CKR_DATA_INVALID.into())
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || encoded.len() <= count || encoded[1] == 0 {
        return Err(CKR_DATA_INVALID.into());
    }
    let length = encoded[1..=count]
        .iter()
        .fold(0usize, |length, byte| (length << 8) | *byte as usize);
    if length < 0x80 {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok((length, count + 1))
}

fn encode_tlv(tag: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    if tag > 0x00ff_ffff || value.len() > u16::MAX as usize {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = Vec::with_capacity(4 + value.len());
    let tag_bytes = tag.to_be_bytes();
    let first = tag_bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    encoded.extend_from_slice(&tag_bytes[first..]);
    if value.len() < 0x80 {
        encoded.push(value.len() as u8);
    } else if value.len() <= 0xff {
        encoded.extend([0x81, value.len() as u8]);
    } else {
        encoded.push(0x82);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

pub(crate) fn encode_certificate_object(certificate: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(certificate)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let compressed = encoder
        .finish()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let (stored, cert_info) = if compressed.len() < certificate.len() {
        (compressed.as_slice(), CERTIFICATE_GZIP)
    } else {
        (certificate, CERTIFICATE_UNCOMPRESSED)
    };

    let mut object = encode_tlv(0x70, stored)?;
    object.extend_from_slice(&encode_tlv(0x71, &[cert_info])?);
    object.extend_from_slice(&encode_tlv(0xfe, &[])?);
    Ok(object)
}

pub(crate) fn decode_certificate_object(object: &[u8]) -> Result<Vec<u8>, Error> {
    let fields = parse_tlvs(object)?;
    if fields.len() != 3
        || fields
            .iter()
            .any(|field| !matches!(field.tag, 0x70 | 0x71 | 0xfe))
    {
        return Err(CKR_DATA_INVALID.into());
    }
    for tag in [0x70, 0x71, 0xfe] {
        if fields.iter().filter(|field| field.tag == tag).count() != 1 {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    if field(&fields, 0xfe) != Some(&[]) {
        return Err(CKR_DATA_INVALID.into());
    }

    let certificate = field(&fields, 0x70)
        .filter(|value| !value.is_empty())
        .ok_or(CKR_DATA_INVALID)?;
    match field(&fields, 0x71) {
        Some([CERTIFICATE_UNCOMPRESSED]) => Ok(certificate.to_vec()),
        Some([CERTIFICATE_GZIP]) => decode_compressed_certificate(certificate),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn decode_compressed_certificate(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    // Some deployed NET iD cards prefix a zlib stream with a marker and the
    // expected uncompressed size. Yubico's middleware accepts this format.
    let (compressed, expected_length) = if let [0x01, 0x00, low, high, rest @ ..] = compressed {
        (rest, Some(u16::from_le_bytes([*low, *high]) as usize))
    } else {
        (compressed, None)
    };
    let mut decoded = Vec::new();
    let limit = (MAX_DECOMPRESSED_CERTIFICATE_SIZE + 1) as u64;
    if compressed.starts_with(&[0x1f, 0x8b]) {
        GzDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut decoded)
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    } else {
        ZlibDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut decoded)
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    }
    if decoded.len() > MAX_DECOMPRESSED_CERTIFICATE_SIZE
        || expected_length.is_some_and(|expected| expected != decoded.len())
    {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests;
