use super::*;
use crate::ApduCapabilities;
use std::{cell::RefCell, collections::VecDeque, time::Duration};

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
    fn apdu_capabilities(&self) -> ApduCapabilities {
        ApduCapabilities::SHORT_ONLY
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

#[derive(Debug)]
struct ManagementConnector {
    commands: RefCell<Vec<Vec<u8>>>,
}

impl Connector for ManagementConnector {
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
    fn transmit<'a>(
        &self,
        command: &[u8],
        receive: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.commands.borrow_mut().push(command.to_vec());
        let key = [1u8; 24];
        let response = match (command[1], command[4]) {
            (INS_GET_METADATA, _) => response(&[0x01, 0x01, 0x03], STATUS_SUCCESS),
            (INS_AUTHENTICATE, 4) => {
                let challenge = crypt_management_block(
                    ManagementAlgorithm::TripleDes,
                    &key,
                    &[0x5a; 8],
                    Mode::Encrypt,
                )?;
                response(
                    &encode_tlv(0x7c, &encode_tlv(0x80, &challenge)?)?,
                    STATUS_SUCCESS,
                )
            }
            (INS_AUTHENTICATE, _) => {
                let host_tag = command
                    .windows(2)
                    .position(|window| window == [0x81, 0x08])
                    .ok_or(CKR_DATA_INVALID)?;
                let host = command
                    .get(host_tag + 2..host_tag + 10)
                    .ok_or(CKR_DATA_INVALID)?;
                let cryptogram = crypt_management_block(
                    ManagementAlgorithm::TripleDes,
                    &key,
                    host,
                    Mode::Encrypt,
                )?;
                response(
                    &encode_tlv(0x7c, &encode_tlv(0x82, &cryptogram)?)?,
                    STATUS_SUCCESS,
                )
            }
            _ => response(&[], 0x6d00),
        };
        receive[..response.len()].copy_from_slice(&response);
        Ok(&receive[..response.len()])
    }
}

#[test]
fn authenticates_the_piv_management_key_mutually() {
    let connector = ManagementConnector {
        commands: RefCell::new(Vec::new()),
    };
    Client
        .authenticate_management_key(&connector, &[1; 24])
        .unwrap();
    let commands = connector.commands.borrow();
    assert_eq!(&commands[0][..4], &[0, INS_GET_METADATA, 0, 0x9b]);
    assert_eq!(
        commands[1],
        [
            0,
            INS_AUTHENTICATE,
            ManagementAlgorithm::TripleDes as u8,
            0x9b,
            4,
            0x7c,
            2,
            0x80,
            0,
            0
        ]
    );
    assert_eq!(&commands[2][..4], &[0, INS_AUTHENTICATE, 0x03, 0x9b]);
    assert!(commands[2]
        .windows(4)
        .any(|window| window == [0x80, 8, 0x5a, 0x5a]));
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
    assert_eq!(connector.commands.borrow()[2], [0, 0xc0, 0, 0, 2]);
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
fn parses_attestation_usage_policy_metadata() {
    let oid = encode_tlv(0x06, YUBICO_PIV_USAGE_POLICY_OID).unwrap();
    let policy = encode_tlv(0x04, &[2, 3]).unwrap();
    let extension = encode_tlv(0x30, &[oid, policy].concat()).unwrap();
    let certificate = encode_tlv(0x30, &extension).unwrap();

    let metadata = parse_attestation_metadata(&certificate).unwrap();
    assert_eq!(metadata.pin_policy, Some(2));
    assert_eq!(metadata.touch_policy, Some(3));
    assert_eq!(metadata.origin, Some(1));
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
fn generates_a_piv_key_pair_with_requested_policies() {
    let public_key = encode_tlv(0x86, &[0x04; 65]).unwrap();
    let response_data = encode_tlv(0x7f49, &public_key).unwrap();
    let connector = ScriptedConnector::new(vec![response(&response_data, STATUS_SUCCESS)]);
    assert_eq!(
        Client
            .generate_key_pair(&connector, Slot::Signature, Algorithm::EccP256, 3, 2,)
            .unwrap(),
        MetadataPublicKey::Ec(vec![0x04; 65])
    );
    assert_eq!(
        connector.commands.borrow()[0],
        [
            0,
            INS_GENERATE_ASYMMETRIC,
            0,
            Slot::Signature as u8,
            11,
            0xac,
            9,
            0x80,
            1,
            Algorithm::EccP256 as u8,
            0xaa,
            1,
            3,
            0xab,
            1,
            2,
            0
        ]
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
