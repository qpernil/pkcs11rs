use super::*;
use crate::ApduCapabilities;
use std::{cell::RefCell, collections::VecDeque, time::Duration};

#[derive(Debug)]
struct ScriptedConnector {
    responses: RefCell<VecDeque<Vec<u8>>>,
    commands: RefCell<Vec<Vec<u8>>>,
    firmware: Option<(u8, u8, u8)>,
    capabilities: ApduCapabilities,
}

impl ScriptedConnector {
    fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            commands: RefCell::new(Vec::new()),
            firmware: None,
            capabilities: ApduCapabilities::EXTENDED,
        }
    }

    fn with_firmware(responses: Vec<Vec<u8>>, firmware: (u8, u8, u8)) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            commands: RefCell::new(Vec::new()),
            firmware: Some(firmware),
            capabilities: ApduCapabilities::EXTENDED,
        }
    }

    fn with_capabilities(responses: Vec<Vec<u8>>, capabilities: ApduCapabilities) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            commands: RefCell::new(Vec::new()),
            firmware: None,
            capabilities,
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
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.firmware
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn apdu_capabilities(&self) -> ApduCapabilities {
        self.capabilities
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

fn app_data() -> Vec<u8> {
    vec![
        0x6e, 0x2b, 0x4f, 0x0e, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12,
        0x34, 0x56, 0x78, 0x73, 0x19, 0xc1, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc2, 0x06,
        0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc4, 0x07, 0x01, 0x20, 0x08, 0x20, 0x03, 0x03, 0x03,
    ]
}

fn app_data_with_attestation() -> Vec<u8> {
    let mut data = app_data();
    data[1] = 0x3d;
    data[19] = 0x2b;
    data.splice(36..36, [0xda, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00]);
    data.splice(
        44..44,
        [0xde, 0x08, 0x01, 0x01, 0x02, 0x02, 0x03, 0x00, 0x81, 0x02],
    );
    data
}

fn app_data_with_empty_keys() -> Vec<u8> {
    let mut data = app_data_with_attestation();
    let key_information = data
        .windows(2)
        .position(|window| window == [0xde, 0x08])
        .unwrap();
    for status in [3, 5, 7, 9] {
        data[key_information + status] = 0;
    }
    data
}

fn app_data_with_generated_attestation_only() -> Vec<u8> {
    vec![
        0x6e, 0x27, 0x4f, 0x0e, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12,
        0x34, 0x56, 0x78, 0x73, 0x15, 0xda, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc4, 0x07,
        0x01, 0x20, 0x08, 0x20, 0x03, 0x03, 0x03, 0xde, 0x02, 0x81, 0x01,
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
    assert!(info.kdf.is_none());
}

#[test]
fn parses_optional_attestation_algorithm() {
    let info = parse_application_info(&app_data_with_attestation()).unwrap();

    assert_eq!(
        info.algorithm(KeyRef::Attestation),
        Some(Algorithm::Rsa { bits: 2048 })
    );
    assert_eq!(
        info.key_status(KeyRef::Signature),
        Some(KeyStatus::Generated)
    );
    assert_eq!(info.key_status(KeyRef::Decipher), Some(KeyStatus::Imported));
    assert_eq!(
        info.key_status(KeyRef::Authentication),
        Some(KeyStatus::None)
    );
    assert_eq!(
        info.key_status(KeyRef::Attestation),
        Some(KeyStatus::Imported)
    );
    assert!(info.key_is_local(KeyRef::Signature));
    assert!(!info.key_is_local(KeyRef::Attestation));
}

#[test]
fn rejects_malformed_key_information() {
    assert!(parse_key_information(&[0x81]).is_err());
    assert!(parse_key_information(&[0x81, 0x03]).is_err());
}

#[test]
fn generated_attestation_status_sets_discovered_key_provenance() {
    let mut public_key = encode_tlv(0x81, &[0x11; 256]).unwrap();
    public_key.extend_from_slice(&encode_tlv(0x82, &[0x01, 0x00, 0x01]).unwrap());
    let public_key = encode_tlv(0x7f49, &public_key).unwrap();
    let connector = std::rc::Rc::new(ScriptedConnector::new(vec![
        response(&[], STATUS_SUCCESS),
        response(&app_data_with_generated_attestation_only(), STATUS_SUCCESS),
        response(&[], 0x6a88),
        response(&public_key, STATUS_SUCCESS),
        response(&[0x30, 0], STATUS_SUCCESS),
    ]));
    let connector_trait: std::rc::Rc<dyn Connector> = connector.clone();
    let mut slot = crate::OpenPgpSlot::new(connector_trait, OPENPGP_AID.to_vec());

    crate::Slot::init_slot(&mut slot).unwrap();
    let objects = crate::Slot::token_objects(&slot, 7).unwrap();
    for id in ["openpgp-81-public", "openpgp-81-private"] {
        let object = objects
            .iter()
            .find(|object| object.unique_id == id)
            .unwrap();
        assert!(object.local);
        assert_eq!(
            object.key_gen_mechanism,
            Some(crate::CKM_RSA_PKCS_KEY_PAIR_GEN as crate::CK_MECHANISM_TYPE)
        );
    }
    assert!(objects
        .iter()
        .any(|object| object.unique_id == "openpgp-81-certificate"));
    assert_eq!(
        connector.commands.borrow()[3],
        [0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0]
    );
}

#[test]
fn empty_key_information_skips_public_key_discovery() {
    let connector = std::rc::Rc::new(ScriptedConnector::new(vec![
        response(&[], STATUS_SUCCESS),
        response(&app_data_with_empty_keys(), STATUS_SUCCESS),
        response(&[], 0x6a88),
        response(&[], STATUS_SUCCESS),
    ]));
    let connector_trait: std::rc::Rc<dyn Connector> = connector.clone();
    let mut slot = crate::OpenPgpSlot::new(connector_trait, OPENPGP_AID.to_vec());

    crate::Slot::init_slot(&mut slot).unwrap();
    assert!(crate::Slot::token_objects(&slot, 7).unwrap().is_empty());
    assert!(connector
        .commands
        .borrow()
        .iter()
        .all(|command| command.get(1) != Some(&INS_GENERATE_ASYMMETRIC)));
}

#[test]
fn openpgp_so_operations_use_pw3_and_reset_pw1() {
    let connector = std::rc::Rc::new(ScriptedConnector::new(vec![
        response(&[], STATUS_SUCCESS),
        response(&app_data(), STATUS_SUCCESS),
        response(&[], 0x6a88),
        response(&[], STATUS_SUCCESS),
        response(&[], STATUS_SUCCESS),
        response(&[], STATUS_SUCCESS),
        response(&app_data(), STATUS_SUCCESS),
        response(&[], 0x6a88),
        response(&[], STATUS_SUCCESS),
    ]));
    let connector_trait: std::rc::Rc<dyn Connector> = connector.clone();
    let mut slot = crate::OpenPgpSlot::new(connector_trait, OPENPGP_AID.to_vec());

    crate::Slot::login_so(&mut slot, b"12345678").unwrap();
    assert!(crate::Slot::login_is_active(&slot));
    crate::Slot::init_user_pin(&mut slot, b"654321").unwrap();
    assert!(crate::Slot::login_is_active(&slot));
    crate::Slot::set_so_pin(&mut slot, b"12345678", b"87654321").unwrap();
    assert!(!crate::Slot::login_is_active(&slot));

    let commands = connector.commands.borrow();
    assert_eq!(
        commands[3],
        [&[0, 0x20, 0, 0x83, 8][..], &b"12345678"[..]].concat()
    );
    assert_eq!(
        commands[4],
        [&[0, 0x2c, 2, 0x81, 6][..], &b"654321"[..]].concat()
    );
    assert_eq!(
        commands[8],
        [
            &[0, 0x24, 0, 0x83, 16][..],
            &b"12345678"[..],
            &b"87654321"[..],
        ]
        .concat()
    );
}

#[test]
fn selects_openpgp_and_reads_application_metadata() {
    let connector = ScriptedConnector::new(vec![
        response(&[], STATUS_SUCCESS),
        response(&app_data(), STATUS_SUCCESS),
        response(&[], 0x6a88),
    ]);
    let info = Client.select(&connector, &OPENPGP_AID).unwrap();
    assert_eq!(info.version, (3, 4));
    assert_eq!(info.serial, "12345678");
    let commands = connector.commands.borrow();
    assert_eq!(
        commands[0],
        [0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0]
    );
    assert_eq!(commands[1], [0, 0xca, 0, 0x6e, 0]);
    assert_eq!(commands[2], [0, 0xca, 0, 0xf9, 0]);
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

#[test]
fn encodes_ecdh_cipher_do() {
    let point = vec![0x04, 1, 2, 3, 4, 5, 6, 7, 8];
    assert!(matches!(
        ecdh_cipher_do(Curve::P256, &point),
        Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as _
    ));

    let point = vec![0x04; 65];
    assert_eq!(ecdh_cipher_do(Curve::P256, &point).unwrap(), {
        let mut expected = vec![0xa6, 0x46, 0x7f, 0x49, 0x43, 0x86, 0x41];
        expected.extend_from_slice(&point);
        expected
    });

    let point = vec![0x55; 32];
    assert_eq!(ecdh_cipher_do(Curve::X25519, &point).unwrap(), {
        let mut expected = vec![0xa6, 0x25, 0x7f, 0x49, 0x22, 0x86, 0x20];
        expected.extend_from_slice(&point);
        expected
    });
}

#[test]
fn selects_certificate_data_object_with_required_reference() {
    let command = CommandApdu {
        cla: 0,
        ins: 0xa5,
        p1: KeyRef::Signature.certificate_occurrence().unwrap(),
        p2: 0x04,
        data: SELECT_CERTIFICATE_DATA.to_vec(),
        le: Some(256),
        extended: false,
    };
    assert_eq!(
        command.encode().unwrap(),
        [0x00, 0xa5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00]
    );
}

#[test]
fn certificate_selection_handles_yubikey_firmware_variants() {
    let legacy = ScriptedConnector::with_firmware(vec![response(&[], STATUS_SUCCESS)], (5, 4, 3));
    Client
        .select_data(&legacy, 2, DataObject::CardholderCertificate)
        .unwrap();
    assert_eq!(
        legacy.commands.borrow()[0],
        [0, 0xa5, 2, 4, 7, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0,]
    );

    let old =
        ScriptedConnector::with_firmware(vec![response(&[0x30, 0], STATUS_SUCCESS)], (4, 3, 7));
    assert_eq!(
        Client.certificate(&old, KeyRef::Authentication).unwrap(),
        [0x30, 0]
    );
    assert!(matches!(
        Client.certificate(&old, KeyRef::Signature),
        Err(Error::Generic(rv)) if rv == CKR_FUNCTION_NOT_SUPPORTED as _
    ));
    assert_eq!(old.commands.borrow()[0], [0, 0xca, 0x7f, 0x21, 0]);
}

#[test]
fn derives_iterated_salted_s2k_user_pin() {
    let kdf = KdfParams {
        hash_algorithm: 0x08,
        iteration_count: 100_000,
        user_salt: b"01234567".to_vec(),
        reset_salt: None,
        admin_salt: None,
    };
    assert_eq!(
        kdf.derive_user_pin(b"123456").unwrap(),
        [
            0x77, 0x37, 0x84, 0xa6, 0x02, 0xb6, 0xc8, 0x1e, 0x3f, 0x09, 0x2f, 0x4d, 0x7d, 0x00,
            0xe1, 0x7c, 0xc8, 0x22, 0xd8, 0x8f, 0x73, 0x60, 0xfc, 0xf2, 0xd2, 0xef, 0x2d, 0x9d,
            0x90, 0x1f, 0x44, 0xb6,
        ]
    );
}

#[test]
fn derives_each_openpgp_secret_with_its_configured_kdf_salt() {
    let kdf = KdfParams {
        hash_algorithm: 0x08,
        iteration_count: 64,
        user_salt: b"user-slt".to_vec(),
        reset_salt: Some(b"reset-sl".to_vec()),
        admin_salt: Some(b"admin-sl".to_vec()),
    };
    let user = kdf
        .derive_pin(PasswordRef::UserOperations, b"123456")
        .unwrap();
    let reset = kdf.derive_reset_code(b"12345678").unwrap();
    let admin = kdf.derive_pin(PasswordRef::Admin, b"12345678").unwrap();
    assert_ne!(user, reset);
    assert_ne!(user, admin);
    assert_ne!(reset, admin);
}

#[test]
fn parses_wrapped_and_unwrapped_kdf_data_objects() {
    let inner = vec![
        0x81, 0x01, 0x03, 0x82, 0x01, 0x08, 0x83, 0x04, 0x00, 0x01, 0x86, 0xa0, 0x84, 0x08, b'0',
        b'1', b'2', b'3', b'4', b'5', b'6', b'7',
    ];
    let mut wrapped = vec![0xf9, inner.len() as u8];
    wrapped.extend_from_slice(&inner);

    for encoded in [inner, wrapped] {
        let kdf = parse_kdf(&encoded).unwrap().unwrap();
        assert_eq!(kdf.hash_algorithm, 0x08);
        assert_eq!(kdf.iteration_count, 100_000);
        assert_eq!(kdf.user_salt, b"01234567");
        assert!(kdf.reset_salt.is_none());
        assert!(kdf.admin_salt.is_none());
    }
}

#[test]
fn standard_password_commands_match_openpgp_card_encodings() {
    let connector = ScriptedConnector::new(vec![response(&[], STATUS_SUCCESS); 7]);

    Client
        .verify_password(&connector, PasswordRef::Admin, b"12345678")
        .unwrap();
    Client
        .verification_status(&connector, PasswordRef::UserSignature)
        .unwrap();
    Client
        .change_admin_pin(&connector, b"12345678", b"87654321")
        .unwrap();
    Client
        .reset_user_pin(&connector, b"654321", Some(b"reset123"))
        .unwrap();
    Client.reset_user_pin(&connector, b"123456", None).unwrap();
    Client
        .unverify_password(&connector, PasswordRef::UserOperations)
        .unwrap();
    Client.verify_pin(&connector, b"123456", false).unwrap();

    let commands = connector.commands.borrow();
    assert_eq!(
        commands[0],
        [&[0, 0x20, 0, 0x83, 8][..], &b"12345678"[..]].concat()
    );
    assert_eq!(commands[1], [0, 0x20, 0, 0x81]);
    assert_eq!(
        commands[2],
        [
            &[0, 0x24, 0, 0x83, 16][..],
            &b"12345678"[..],
            &b"87654321"[..],
        ]
        .concat()
    );
    assert_eq!(
        commands[3],
        [
            &[0, 0x2c, 0, 0x81, 14][..],
            &b"reset123"[..],
            &b"654321"[..],
        ]
        .concat()
    );
    assert_eq!(
        commands[4],
        [&[0, 0x2c, 2, 0x81, 6][..], &b"123456"[..]].concat()
    );
    assert_eq!(commands[5], [0, 0x20, 0xff, 0x82]);
    assert_eq!(
        commands[6],
        [&[0, 0x20, 0, 0x81, 6][..], &b"123456"[..]].concat()
    );
}

#[test]
fn data_object_commands_cover_even_odd_and_repeated_objects() {
    let connector = ScriptedConnector::new(vec![response(&[0xaa], STATUS_SUCCESS); 6]);

    assert_eq!(
        Client
            .get_data(&connector, DataObject::PasswordStatus.tag())
            .unwrap(),
        [0xaa]
    );
    assert_eq!(
        Client
            .get_next_data(&connector, DataObject::CardholderCertificate.tag())
            .unwrap(),
        [0xaa]
    );
    assert_eq!(
        Client
            .get_data_odd(&connector, 0x2f, 0x00, &[0x4f])
            .unwrap(),
        [0xaa]
    );
    Client
        .put_data(&connector, DataObject::UifSignature.tag(), &[1, 0x20])
        .unwrap();
    assert!(matches!(
        Client.put_data_odd(&connector, 0x3f, 0xff, &[0x4d, 0x01, 0x00]),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    Client
        .select_data(&connector, 1, DataObject::CardholderCertificate)
        .unwrap();
    Client
        .put_certificate(&connector, KeyRef::Attestation, &[0x30, 0x00])
        .unwrap();

    let commands = connector.commands.borrow();
    assert_eq!(commands[0], [0, 0xca, 0, 0xc4, 0]);
    assert_eq!(commands[1], [0, 0xcc, 0x7f, 0x21, 0]);
    assert_eq!(commands[2], [0, 0xcb, 0x2f, 0, 3, 0x5c, 1, 0x4f, 0]);
    assert_eq!(commands[3], [0, 0xda, 0, 0xd6, 2, 1, 0x20]);
    assert_eq!(
        commands[4],
        [0, 0xa5, 1, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0]
    );
    assert_eq!(commands[5], [0, 0xda, 0, 0xfc, 2, 0x30, 0]);
}

#[test]
fn cryptographic_commands_cover_all_openpgp_security_operations() {
    let connector = ScriptedConnector::new(vec![response(&[0xaa], STATUS_SUCCESS); 8]);

    assert_eq!(
        Client
            .sign(&connector, KeyRef::Signature, &[1, 2, 3])
            .unwrap(),
        [0xaa]
    );
    assert_eq!(
        Client
            .sign(&connector, KeyRef::Authentication, &[4, 5])
            .unwrap(),
        [0xaa]
    );
    assert_eq!(Client.decipher(&connector, &[6, 7], true).unwrap(), [0xaa]);
    assert_eq!(Client.decipher(&connector, &[8], false).unwrap(), [0xaa]);
    assert_eq!(Client.encipher(&connector, &[0x11; 16]).unwrap(), [0xaa]);
    Client
        .manage_security_environment(
            &connector,
            KeyRef::Decipher,
            SecurityOperation::Authenticate,
        )
        .unwrap();
    Client
        .manage_security_environment(
            &connector,
            KeyRef::Authentication,
            SecurityOperation::Decipher,
        )
        .unwrap();
    assert_eq!(
        Client.ecdh(&connector, Curve::X25519, &[0x55; 32]).unwrap(),
        [0xaa]
    );

    let commands = connector.commands.borrow();
    assert_eq!(commands[0], [0, 0x2a, 0x9e, 0x9a, 3, 1, 2, 3, 0]);
    assert_eq!(commands[1], [0, 0x88, 0, 0, 2, 4, 5, 0]);
    assert_eq!(commands[2], [0, 0x2a, 0x80, 0x86, 3, 0, 6, 7, 0]);
    assert_eq!(commands[3], [0, 0x2a, 0x80, 0x86, 2, 2, 8, 0]);
    assert_eq!(
        commands[4],
        [&[0, 0x2a, 0x86, 0x80, 16][..], &[0x11; 16][..], &[0][..],].concat()
    );
    assert_eq!(commands[5], [0, 0x22, 0x41, 0xa4, 3, 0x83, 1, 2]);
    assert_eq!(commands[6], [0, 0x22, 0x41, 0xb8, 3, 0x83, 1, 3]);
    let mut ecdh = vec![0, 0x2a, 0x80, 0x86, 39, 0xa6, 37, 0x7f, 0x49, 34, 0x86, 32];
    ecdh.extend_from_slice(&[0x55; 32]);
    ecdh.push(0);
    assert_eq!(commands[7], ecdh);
}

#[test]
fn yubikey_commands_refuse_key_destructive_lifecycle_operations() {
    let connector = ScriptedConnector::new(vec![
        response(&[0x05, 0x07, 0x02], STATUS_SUCCESS),
        response(&[], STATUS_SUCCESS),
        response(&[1, 2, 3, 4], STATUS_SUCCESS),
    ]);

    assert_eq!(Client.firmware_version(&connector).unwrap(), (5, 7, 2));
    assert!(matches!(
        Client.set_pin_attempts(&connector, 3, 4, 5),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    Client.attest_key(&connector, KeyRef::Signature).unwrap();
    assert!(matches!(
        Client.terminate(&connector),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    assert!(matches!(
        Client.put_data(&connector, 0x00c1, &[1, 8, 0, 32, 0, 0]),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    assert!(matches!(
        Client.activate(&connector),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    assert_eq!(Client.challenge(&connector, 4).unwrap(), [1, 2, 3, 4]);

    let commands = connector.commands.borrow();
    assert_eq!(commands[0], [0, 0xf1, 0, 0, 0]);
    assert_eq!(commands[1], [0x80, 0xfb, 1, 0]);
    assert_eq!(commands[2], [0, 0x84, 0, 0, 4]);
}

#[test]
fn key_destructive_apdus_are_classified_before_transport() {
    for (ins, p1, p2) in [
        (INS_TERMINATE_DF, 0, 0),
        (INS_ACTIVATE_FILE, 0, 0),
        (INS_SET_PIN_RETRIES, 0, 0),
        (INS_GENERATE_ASYMMETRIC, 0x80, 0),
        (INS_PUT_DATA_ODD, 0x3f, 0xff),
        (INS_PUT_DATA, 0, 0xc1),
        (INS_PUT_DATA, 0, 0xc2),
        (INS_PUT_DATA, 0, 0xc3),
        (INS_PUT_DATA, 0, 0xda),
    ] {
        assert!(command_may_delete_keys(&CommandApdu {
            cla: 0,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
            extended: false,
        }));
    }
    assert!(!command_may_delete_keys(&CommandApdu {
        cla: 0,
        ins: INS_GENERATE_ASYMMETRIC,
        p1: 0x81,
        p2: 0,
        data: Vec::new(),
        le: Some(256),
        extended: false,
    }));
}

#[test]
fn public_key_reads_work_but_key_generation_and_import_are_prohibited() {
    let mut public_key = encode_tlv(0x81, &[0x11; 128]).unwrap();
    public_key.extend_from_slice(&encode_tlv(0x82, &[0x01, 0x00, 0x01]).unwrap());
    let public_key = encode_tlv(0x7f49, &public_key).unwrap();
    let connector = ScriptedConnector::new(vec![
        response(&public_key, STATUS_SUCCESS),
        response(&public_key, STATUS_SUCCESS),
    ]);

    Client
        .public_key(&connector, KeyRef::Signature, Algorithm::Rsa { bits: 1024 })
        .unwrap();
    Client
        .public_key(
            &connector,
            KeyRef::Attestation,
            Algorithm::Rsa { bits: 1024 },
        )
        .unwrap();
    assert!(matches!(
        Client.generate_key_pair(
            &connector,
            KeyRef::Attestation,
            Algorithm::Rsa { bits: 1024 },
        ),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));
    assert!(matches!(
        Client.import_private_key(&connector, &[0x4d, 0x01, 0x00]),
        Err(Error::Generic(rv)) if rv == CKR_ACTION_PROHIBITED as _
    ));

    let commands = connector.commands.borrow();
    assert_eq!(commands[0], [0, 0x47, 0x81, 0, 2, 0xb6, 0, 0]);
    assert_eq!(
        commands[1],
        [0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0]
    );
    assert_eq!(commands.len(), 2);
}

#[test]
fn command_and_response_chaining_follow_iso_7816() {
    let connector = ScriptedConnector::with_capabilities(
        vec![
            response(&[], STATUS_SUCCESS),
            response(&[1, 2], 0x6102),
            response(&[3, 4], STATUS_SUCCESS),
        ],
        ApduCapabilities::SHORT_ONLY,
    );
    let data = vec![0x5a; 300];
    let output = Client
        .transmit(
            &connector,
            CommandApdu {
                cla: 0,
                ins: INS_PUT_DATA,
                p1: 0,
                p2: 0x5b,
                data,
                le: Some(256),
                extended: false,
            },
        )
        .unwrap();
    assert_eq!(output, [1, 2, 3, 4]);

    let commands = connector.commands.borrow();
    assert_eq!(&commands[0][..5], &[0x10, 0xda, 0, 0x5b, 255]);
    assert_eq!(commands[0].len(), 260);
    assert_eq!(&commands[1][..5], &[0, 0xda, 0, 0x5b, 45]);
    assert_eq!(commands[1].len(), 51);
    assert_eq!(commands[2], [0, 0xc0, 0, 0, 2]);
}

#[test]
fn command_statuses_map_to_specific_pkcs11_errors() {
    for (status, expected) in [
        (0x6700, CKR_DATA_LEN_RANGE),
        (0x6983, CKR_PIN_LOCKED),
        (0x6985, CKR_USER_NOT_LOGGED_IN),
        (0x6a80, CKR_DATA_INVALID),
        (0x6a86, CKR_ARGUMENTS_BAD),
        (0x6d00, CKR_FUNCTION_NOT_SUPPORTED),
    ] {
        let connector = ScriptedConnector::new(vec![response(&[], status)]);
        let error = Client
            .get_data(&connector, DataObject::Aid.tag())
            .unwrap_err();
        assert!(matches!(error, Error::Generic(rv) if rv == expected as _));
    }
}
