#![allow(dead_code)]

use crate::{
    error::Error, CommandApdu, Connector, ResponseApdu, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_REJECTED, CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_USER_NOT_LOGGED_IN,
};
use std::time::Duration;

pub(crate) const PIV_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

const INS_SELECT: u8 = 0xa4;
const INS_VERIFY: u8 = 0x20;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xcb;
const INS_GET_RESPONSE: u8 = 0xc0;
const INS_GET_VERSION: u8 = 0xfd;
const INS_GET_SERIAL: u8 = 0xf8;
const INS_GET_METADATA: u8 = 0xf7;
const INS_ATTEST: u8 = 0xf9;
const STATUS_SUCCESS: u16 = 0x9000;
const MAX_COMMAND_CHUNK: usize = 0xff;
const MAX_RESPONSE_SEGMENTS: usize = 256;
const MAX_OBJECT_SIZE: usize = 3072;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

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
        let data = self.command(connector, INS_GET_METADATA, 0, slot as u8, &[])?;
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

    pub(crate) fn certificate(
        &self,
        connector: &dyn Connector,
        slot: Slot,
    ) -> Result<Vec<u8>, Error> {
        let object = self.get_data(connector, slot.certificate_object())?;
        let fields = parse_tlvs(&object)?;
        if field(&fields, 0x71).is_some_and(|compressed| compressed != [0]) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        field(&fields, 0x70)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| CKR_DATA_INVALID.into())
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
        if command.data.len() <= MAX_COMMAND_CHUNK || command.extended {
            return self.transmit_one(connector, command);
        }

        let mut chunks = command.data.chunks(MAX_COMMAND_CHUNK).peekable();
        while let Some(chunk) = chunks.next() {
            let final_chunk = chunks.peek().is_none();
            let response = self.transmit_one(
                connector,
                CommandApdu {
                    cla: if final_chunk {
                        command.cla
                    } else {
                        command.cla | 0x10
                    },
                    ins: command.ins,
                    p1: command.p1,
                    p2: command.p2,
                    data: chunk.to_vec(),
                    le: final_chunk.then_some(command.le).flatten(),
                    extended: false,
                },
            )?;
            if final_chunk {
                return Ok(response);
            }
            require_success(response.status)?;
            if !response.data.is_empty() {
                return Err(CKR_DEVICE_ERROR.into());
            }
        }
        Err(CKR_DEVICE_ERROR.into())
    }

    fn transmit_one(
        &self,
        connector: &dyn Connector,
        mut command: CommandApdu,
    ) -> Result<ResponseApdu, Error> {
        let mut response =
            ResponseApdu::parse(&connector.send(&command.encode()?, DEFAULT_TIMEOUT)?)?;
        if response.status & 0xff00 == 0x6c00 {
            command.le = Some(match response.status as u8 {
                0 => 256,
                length => length as u32,
            });
            response = ResponseApdu::parse(&connector.send(&command.encode()?, DEFAULT_TIMEOUT)?)?;
        }

        let mut segments = 0;
        while response.status & 0xff00 == 0x6100 {
            if segments == MAX_RESPONSE_SEGMENTS {
                return Err(CKR_DEVICE_ERROR.into());
            }
            segments += 1;
            let expected = match response.status as u8 {
                0 => 256,
                length => length as u32,
            };
            let continuation = ResponseApdu::parse(
                &connector.send(
                    &CommandApdu {
                        cla: 0,
                        ins: INS_GET_RESPONSE,
                        p1: 0,
                        p2: 0,
                        data: Vec::new(),
                        le: Some(expected),
                        extended: false,
                    }
                    .encode()?,
                    DEFAULT_TIMEOUT,
                )?,
            )?;
            response.data.extend_from_slice(&continuation.data);
            response.status = continuation.status;
            if response.data.len() > MAX_OBJECT_SIZE + 1024 {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        }
        Ok(response)
    }
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
    if tag > 0xff || value.len() > u16::MAX as usize {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.push(tag as u8);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<Vec<u8>>>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiKey"
        }
        fn serial(&self) -> &str {
            "0"
        }
        fn major(&self) -> u8 {
            5
        }
        fn minor(&self) -> u8 {
            7
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn transmit<'a>(
            &self,
            command: &[u8],
            receive: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(command.to_vec());
            let response = self
                .responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR)?;
            receive[..response.len()].copy_from_slice(&response);
            Ok(&receive[..response.len()])
        }
    }

    fn response(data: &[u8], status: u16) -> Vec<u8> {
        let mut response = data.to_vec();
        response.extend_from_slice(&status.to_be_bytes());
        response
    }

    #[test]
    fn selects_piv_and_reads_version_and_serial() {
        let connector = ScriptedConnector::new(vec![
            response(&[], STATUS_SUCCESS),
            response(&[5, 7, 2], STATUS_SUCCESS),
            response(&0x01020304u32.to_be_bytes(), STATUS_SUCCESS),
        ]);
        let info = Client.select(&connector, &PIV_AID).unwrap();
        assert_eq!(
            info.version,
            Version {
                major: 5,
                minor: 7,
                patch: 2
            }
        );
        assert_eq!(info.serial, Some(0x01020304));
        assert_eq!(
            connector.commands.borrow()[0],
            [0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0]
        );
    }

    #[test]
    fn pads_pin_and_reports_retry_failures() {
        let connector = ScriptedConnector::new(vec![response(&[], 0x63c2)]);
        let error = Client.verify_pin(&connector, b"123456").unwrap_err();
        assert!(matches!(error, Error::Generic(rv) if rv == CKR_PIN_INCORRECT as _));
        assert_eq!(
            connector.commands.borrow()[0],
            [0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff, 0]
        );
    }

    #[test]
    fn follows_response_chaining_and_retries_wrong_le() {
        let connector = ScriptedConnector::new(vec![
            response(&[], 0x6c03),
            response(&[1, 2], 0x6102),
            response(&[3, 4], STATUS_SUCCESS),
        ]);
        let data = Client
            .command(&connector, INS_GET_VERSION, 0, 0, &[])
            .unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
        assert_eq!(
            connector.commands.borrow()[1],
            [0, INS_GET_VERSION, 0, 0, 3]
        );
        assert_eq!(
            connector.commands.borrow()[2],
            [0, INS_GET_RESPONSE, 0, 0, 2]
        );
    }

    #[test]
    fn chains_large_general_authenticate_commands() {
        let connector = ScriptedConnector::new(vec![
            response(&[], STATUS_SUCCESS),
            response(
                &encode_tlv(0x7c, &encode_tlv(0x82, &[0x5a; 16]).unwrap()).unwrap(),
                STATUS_SUCCESS,
            ),
        ]);
        let output = Client
            .sign(
                &connector,
                Slot::Signature,
                Algorithm::Rsa2048,
                &[0x33; 256],
            )
            .unwrap();
        assert_eq!(output, [0x5a; 16]);
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], 0x10);
        assert_eq!(commands[0][1], INS_AUTHENTICATE);
        assert_eq!(commands[1][0], 0);
    }

    #[test]
    fn parses_metadata_and_certificate_objects() {
        let metadata = [0x01, 0x01, 0x11, 0x02, 0x02, 0x02, 0x03, 0x03, 0x01, 0x01];
        let certificate_object = encode_tlv(
            0x53,
            &[
                encode_tlv(0x70, &[0x30, 0x01, 0x00]).unwrap(),
                encode_tlv(0x71, &[0]).unwrap(),
                encode_tlv(0xfe, &[]).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let connector = ScriptedConnector::new(vec![
            response(&metadata, STATUS_SUCCESS),
            response(&certificate_object, STATUS_SUCCESS),
        ]);
        let parsed = Client.metadata(&connector, Slot::Authentication).unwrap();
        assert_eq!(parsed.algorithm, Some(0x11));
        assert_eq!(parsed.pin_policy, Some(2));
        assert_eq!(parsed.touch_policy, Some(3));
        assert_eq!(parsed.origin, Some(1));
        assert_eq!(
            Client
                .certificate(&connector, Slot::Authentication)
                .unwrap(),
            [0x30, 0x01, 0x00]
        );
    }

    #[test]
    fn parses_metadata_public_key_by_algorithm() {
        let rsa = parse_metadata_public_key(
            Algorithm::Rsa2048,
            &[0x81, 0x03, 0x01, 0x02, 0x03, 0x82, 0x03, 0x01, 0x00, 0x01],
        )
        .unwrap();
        assert_eq!(
            rsa,
            MetadataPublicKey::Rsa {
                modulus: vec![1, 2, 3],
                exponent: vec![1, 0, 1],
            }
        );
        assert_eq!(
            parse_metadata_public_key(Algorithm::EccP256, &[0x86, 0x03, 0x04, 1, 2]).unwrap(),
            MetadataPublicKey::Ec(vec![0x04, 1, 2])
        );
        assert_eq!(
            parse_metadata_public_key(Algorithm::X25519, &[0x86, 0x02, 1, 2]).unwrap(),
            MetadataPublicKey::Raw(vec![1, 2])
        );
    }

    #[test]
    fn enumerates_all_piv_slots_and_certificate_objects() {
        assert_eq!(Slot::all().len(), 25);
        assert_eq!(Slot::Authentication.certificate_object(), 0x5f_c105);
        assert_eq!(Slot::Retired1.certificate_object(), 0x5f_c10d);
        assert_eq!(Slot::Retired20.certificate_object(), 0x5f_c120);
        assert_eq!(Slot::Attestation.certificate_object(), 0x5f_ff01);
        assert!(Slot::Retired10.is_retired());
        assert!(!Slot::Attestation.is_retired());
    }

    #[test]
    fn requests_dynamic_attestation_certificate() {
        let connector = ScriptedConnector::new(vec![response(&[0x30, 0x00], STATUS_SUCCESS)]);
        assert_eq!(
            Client.attestation(&connector, Slot::Signature).unwrap(),
            [0x30, 0x00]
        );
        assert_eq!(
            connector.commands.borrow()[0],
            [0, INS_ATTEST, Slot::Signature as u8, 0, 0]
        );
    }

    #[test]
    fn performs_x25519_key_agreement_with_general_authenticate() {
        let response_data = encode_tlv(0x7c, &encode_tlv(0x82, &[0xa5; 32]).unwrap()).unwrap();
        let connector = ScriptedConnector::new(vec![response(&response_data, STATUS_SUCCESS)]);
        assert_eq!(
            Client
                .decipher(
                    &connector,
                    Slot::CardAuthentication,
                    Algorithm::X25519,
                    &[0x11; 32],
                )
                .unwrap(),
            [0xa5; 32]
        );
        let command = &connector.commands.borrow()[0];
        assert_eq!(&command[..4], &[0, INS_AUTHENTICATE, 0xe1, 0x9e]);
        assert!(command.windows(2).any(|window| window == [0x85, 0x20]));
    }

    #[test]
    fn rejects_noncanonical_and_truncated_tlvs() {
        assert!(parse_tlvs(&[0x53, 0x81, 0x01, 0]).is_err());
        assert!(parse_tlvs(&[0x53, 2, 0]).is_err());
        assert!(parse_tlvs(&[0x5f, 0x80, 0]).is_err());
    }
}
