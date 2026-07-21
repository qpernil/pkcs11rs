use crate::{CommandApdu, Connector, Error, ResponseApdu, CKR_DATA_INVALID, CKR_DEVICE_ERROR};

const INS_GET_DATA: u8 = 0xca;
const TAG_KEY_INFORMATION: u32 = 0xe0;
const TAG_CARD_RECOGNITION_DATA: u32 = 0x66;
const TAG_CA_KLOC_IDENTIFIERS: u32 = 0xff33;
const TAG_CA_KLCC_IDENTIFIERS: u32 = 0xff34;
const TAG_CERTIFICATE_STORE: u32 = 0xbf21;
const TAG_CPLC: u32 = 0x9f7f;
const STATUS_SUCCESS: u16 = 0x9000;
const STATUS_REFERENCE_DATA_NOT_FOUND: u16 = 0x6a88;

pub(crate) const KID_SCP03: u8 = 0x01;
pub(crate) const KID_SCP11A: u8 = 0x11;
pub(crate) const KID_SCP11B: u8 = 0x13;
pub(crate) const KID_SCP11C: u8 = 0x15;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct KeyRef {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
}

impl KeyRef {
    fn encoded(self) -> [u8; 2] {
        [self.kid, self.kvn]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyComponent {
    pub(crate) key_type: u8,
    pub(crate) length: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyInfo {
    pub(crate) key_ref: KeyRef,
    pub(crate) components: Vec<KeyComponent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaIdentifierKind {
    Kloc,
    Klcc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaIdentifier {
    pub(crate) kind: CaIdentifierKind,
    pub(crate) key_ref: KeyRef,
    pub(crate) subject_key_identifier: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateBundle {
    pub(crate) key_ref: KeyRef,
    pub(crate) certificates: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SecurityDomainInfo {
    pub(crate) keys: Vec<KeyInfo>,
    pub(crate) card_recognition_data: Option<Vec<u8>>,
    pub(crate) cplc: Option<Vec<u8>>,
    pub(crate) ca_identifiers: Vec<CaIdentifier>,
    pub(crate) certificate_bundles: Vec<CertificateBundle>,
}

pub(crate) struct Client;

impl Client {
    pub(crate) fn discover(&self, connector: &dyn Connector) -> Result<SecurityDomainInfo, Error> {
        let keys = self.get_key_information(connector)?;
        let card_recognition_data = self.get_card_recognition_data(connector)?;
        let cplc = self.get_cplc(connector)?;
        let ca_identifiers = self.get_supported_ca_identifiers(connector)?;

        let mut certificate_bundles = Vec::new();
        for key in &keys {
            if !matches!(key.key_ref.kid, KID_SCP11A | KID_SCP11B | KID_SCP11C) {
                continue;
            }
            let certificates = self.get_certificate_bundle(connector, key.key_ref)?;
            if !certificates.is_empty() {
                certificate_bundles.push(CertificateBundle {
                    key_ref: key.key_ref,
                    certificates,
                });
            }
        }

        Ok(SecurityDomainInfo {
            keys,
            card_recognition_data,
            cplc,
            ca_identifiers,
            certificate_bundles,
        })
    }

    pub(crate) fn get_key_information(
        &self,
        connector: &dyn Connector,
    ) -> Result<Vec<KeyInfo>, Error> {
        let encoded = self.get_data(connector, TAG_KEY_INFORMATION, Vec::new())?;
        parse_key_information(&encoded)
    }

    pub(crate) fn get_card_recognition_data(
        &self,
        connector: &dyn Connector,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_data_optional(connector, TAG_CARD_RECOGNITION_DATA, Vec::new())?
            .map(|encoded| tlv_value(0x73, &encoded))
            .transpose()
    }

    pub(crate) fn get_cplc(&self, connector: &dyn Connector) -> Result<Option<Vec<u8>>, Error> {
        let cplc = self.get_data_optional(connector, TAG_CPLC, Vec::new())?;
        if cplc.as_ref().is_some_and(|value| value.len() != 42) {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(cplc)
    }

    pub(crate) fn get_supported_ca_identifiers(
        &self,
        connector: &dyn Connector,
    ) -> Result<Vec<CaIdentifier>, Error> {
        let mut identifiers = Vec::new();
        for (tag, kind) in [
            (TAG_CA_KLOC_IDENTIFIERS, CaIdentifierKind::Kloc),
            (TAG_CA_KLCC_IDENTIFIERS, CaIdentifierKind::Klcc),
        ] {
            if let Some(encoded) = self.get_data_optional(connector, tag, Vec::new())? {
                identifiers.extend(parse_ca_identifiers(&encoded, kind)?);
            }
        }
        Ok(identifiers)
    }

    pub(crate) fn get_certificate_bundle(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let key_ref = encode_tlv(0x83, &key_ref.encoded())?;
        let request = encode_tlv(0xa6, &key_ref)?;
        let Some(encoded) = self.get_data_optional(connector, TAG_CERTIFICATE_STORE, request)?
        else {
            return Ok(Vec::new());
        };
        parse_certificate_bundle(&encoded)
    }

    fn get_data(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let response = self.send_get_data(connector, tag, data)?;
        if response.status != STATUS_SUCCESS {
            return Err(apdu_status_error(response.status));
        }
        Ok(response.data)
    }

    fn get_data_optional(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let response = self.send_get_data(connector, tag, data)?;
        match response.status {
            STATUS_SUCCESS => Ok(Some(response.data)),
            STATUS_REFERENCE_DATA_NOT_FOUND => Ok(None),
            status => Err(apdu_status_error(status)),
        }
    }

    fn send_get_data(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<ResponseApdu, Error> {
        if tag > u16::MAX as u32 {
            return Err(CKR_DATA_INVALID.into());
        }
        let le = data.is_empty().then_some(256);
        connector.send_apdu(&CommandApdu {
            cla: 0,
            ins: INS_GET_DATA,
            p1: (tag >> 8) as u8,
            p2: tag as u8,
            data,
            le,
            extended: false,
        })
    }
}

fn apdu_status_error(status: u16) -> Error {
    log!(1, "Security Domain command failed with status {status:04x}");
    match status {
        0x6982 | 0x6985 => crate::CKR_USER_NOT_LOGGED_IN.into(),
        0x6700 => crate::CKR_DATA_LEN_RANGE.into(),
        0x6a80 | 0x6a88 => CKR_DATA_INVALID.into(),
        0x6a86 | 0x6b00 => crate::CKR_ARGUMENTS_BAD.into(),
        0x6d00 => crate::CKR_FUNCTION_NOT_SUPPORTED.into(),
        _ => CKR_DEVICE_ERROR.into(),
    }
}

fn parse_key_information(encoded: &[u8]) -> Result<Vec<KeyInfo>, Error> {
    parse_tlvs(encoded)?
        .into_iter()
        .map(|tlv| {
            if tlv.tag != 0xc0 || tlv.value.len() < 2 || tlv.value.len() % 2 != 0 {
                return Err(CKR_DATA_INVALID.into());
            }
            let components = tlv.value[2..]
                .chunks_exact(2)
                .map(|component| KeyComponent {
                    key_type: component[0],
                    length: component[1],
                })
                .collect();
            Ok(KeyInfo {
                key_ref: KeyRef {
                    kid: tlv.value[0],
                    kvn: tlv.value[1],
                },
                components,
            })
        })
        .collect()
}

fn parse_ca_identifiers(
    encoded: &[u8],
    kind: CaIdentifierKind,
) -> Result<Vec<CaIdentifier>, Error> {
    let tlvs = parse_tlvs(encoded)?;
    if tlvs.len() % 2 != 0 {
        return Err(CKR_DATA_INVALID.into());
    }
    tlvs.chunks_exact(2)
        .map(|pair| {
            let key_ref = &pair[1];
            if key_ref.tag != 0x83 || key_ref.value.len() != 2 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(CaIdentifier {
                kind,
                key_ref: KeyRef {
                    kid: key_ref.value[0],
                    kvn: key_ref.value[1],
                },
                subject_key_identifier: pair[0].value.to_vec(),
            })
        })
        .collect()
}

fn parse_certificate_bundle(encoded: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    parse_tlvs(encoded)?
        .into_iter()
        .map(|tlv| {
            if tlv.tag != 0x30 {
                return Err(CKR_DATA_INVALID.into());
            }
            openssl::x509::X509::from_der(tlv.encoded)?;
            Ok(tlv.encoded.to_vec())
        })
        .collect()
}

fn tlv_value(tag: u32, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let tlvs = parse_tlvs(encoded)?;
    if tlvs.len() != 1 || tlvs[0].tag != tag {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(tlvs[0].value.to_vec())
}

fn encode_tlv(tag: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::with_capacity(value.len() + 5);
    match tag {
        0..=0xff => encoded.push(tag as u8),
        0x100..=0xffff => encoded.extend_from_slice(&(tag as u16).to_be_bytes()),
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    match value.len() {
        0..=0x7f => encoded.push(value.len() as u8),
        0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u32,
    value: &'a [u8],
    encoded: &'a [u8],
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<Tlv<'_>>, Error> {
    let mut tlvs = Vec::new();
    while !encoded.is_empty() {
        let complete = encoded;
        let (tag, tag_length) = parse_tag(encoded)?;
        encoded = &encoded[tag_length..];
        let (length, length_length) = parse_length(encoded)?;
        encoded = &encoded[length_length..];
        let value = encoded.get(..length).ok_or(CKR_DATA_INVALID)?;
        let encoded_length = tag_length
            .checked_add(length_length)
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(CKR_DATA_INVALID)?;
        tlvs.push(Tlv {
            tag,
            value,
            encoded: &complete[..encoded_length],
        });
        encoded = &encoded[length..];
    }
    Ok(tlvs)
}

fn parse_tag(encoded: &[u8]) -> Result<(u32, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x1f != 0x1f {
        return Ok((first as u32, 1));
    }
    let second = *encoded.get(1).ok_or(CKR_DATA_INVALID)?;
    if second & 0x80 != 0 {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok((((first as u32) << 8) | second as u32, 2))
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    match *encoded.first().ok_or(CKR_DATA_INVALID)? {
        length @ 0..=0x7f => Ok((length as usize, 1)),
        0x81 => {
            let length = *encoded.get(1).ok_or(CKR_DATA_INVALID)? as usize;
            if length < 0x80 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 2))
        }
        0x82 => {
            let length = encoded.get(1..3).ok_or(CKR_DATA_INVALID)?;
            let length = u16::from_be_bytes([length[0], length[1]]) as usize;
            if length <= 0xff {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 3))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApduCapabilities;
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<ResponseApdu>>,
        commands: RefCell<Vec<CommandApdu>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<ResponseApdu>) -> Self {
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
            "1"
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
        fn apdu_capabilities(&self) -> ApduCapabilities {
            ApduCapabilities::EXTENDED
        }
        fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
            self.commands.borrow_mut().push(command.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR.into())
        }
        fn transmit<'a>(
            &self,
            _send_buffer: &[u8],
            _receive_buffer: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            Err(CKR_DEVICE_ERROR.into())
        }
    }

    fn response(data: Vec<u8>, status: u16) -> ResponseApdu {
        ResponseApdu { data, status }
    }

    fn certificate() -> Vec<u8> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let key = openssl::pkey::PKey::from_ec_key(key).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Security Domain test")
            .unwrap();
        let name = name.build();
        let mut certificate = openssl::x509::X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        certificate
            .set_not_after(openssl::asn1::Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        certificate
            .sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        certificate.build().to_der().unwrap()
    }

    #[test]
    fn discovers_security_domain_metadata_and_certificates() {
        let key_info = [
            encode_tlv(0xc0, &[KID_SCP03, 0xff, 0x88, 0x10]).unwrap(),
            encode_tlv(0xc0, &[KID_SCP11B, 0x01, 0xb1, 0x20, 0xf0, 0x00]).unwrap(),
        ]
        .concat();
        let card_recognition = encode_tlv(0x73, &[0x01, 0x02]).unwrap();
        let ca_identifiers = [
            encode_tlv(0x42, &[0xaa, 0xbb]).unwrap(),
            encode_tlv(0x83, &[KID_SCP11B, 0x01]).unwrap(),
        ]
        .concat();
        let certificate = certificate();
        let mut cplc = vec![0; 42];
        cplc[..2].copy_from_slice(&[0x40, 0x90]);
        let connector = ScriptedConnector::new(vec![
            response(key_info, STATUS_SUCCESS),
            response(card_recognition, STATUS_SUCCESS),
            response(cplc.clone(), STATUS_SUCCESS),
            response(Vec::new(), STATUS_REFERENCE_DATA_NOT_FOUND),
            response(ca_identifiers, STATUS_SUCCESS),
            response(certificate.clone(), STATUS_SUCCESS),
        ]);

        let info = Client.discover(&connector).unwrap();
        assert_eq!(info.keys.len(), 2);
        assert_eq!(info.keys[0].key_ref, KeyRef { kid: 1, kvn: 0xff });
        assert_eq!(info.keys[1].components.len(), 2);
        assert_eq!(info.card_recognition_data, Some(vec![1, 2]));
        assert_eq!(info.cplc, Some(cplc));
        assert_eq!(info.ca_identifiers.len(), 1);
        assert_eq!(info.certificate_bundles[0].certificates, vec![certificate]);

        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 6);
        assert_eq!(
            (commands[0].ins, commands[0].p1, commands[0].p2),
            (0xca, 0, 0xe0)
        );
        assert_eq!((commands[2].p1, commands[2].p2), (0x9f, 0x7f));
        assert_eq!((commands[5].p1, commands[5].p2), (0xbf, 0x21));
        assert_eq!(commands[5].data, vec![0xa6, 4, 0x83, 2, 0x13, 1]);
        assert_eq!(commands[5].le, None);
    }

    #[test]
    fn rejects_malformed_security_domain_tlvs() {
        assert!(parse_key_information(&[0xc0, 3, 1, 2, 0x88]).is_err());
        assert!(parse_ca_identifiers(&[0x42, 1, 1], CaIdentifierKind::Kloc).is_err());
        assert!(parse_certificate_bundle(&[0x31, 0]).is_err());
        assert!(parse_certificate_bundle(&[0x30, 0]).is_err());
        assert!(parse_tlvs(&[0x42, 0x81, 0x01, 0]).is_err());
    }
}
