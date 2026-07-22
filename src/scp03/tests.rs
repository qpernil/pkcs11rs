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
        "Test"
    }
    fn product(&self) -> &str {
        "SCP03"
    }
    fn serial(&self) -> &str {
        "1"
    }
    fn major(&self) -> u8 {
        1
    }
    fn minor(&self) -> u8 {
        0
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.commands.borrow_mut().push(send_buffer.to_vec());
        let response = self
            .responses
            .borrow_mut()
            .pop_front()
            .ok_or(CKR_DEVICE_ERROR)?;
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

fn hex(value: &str) -> Vec<u8> {
    parse_hex(value).unwrap()
}

fn test_session(security_level: u8) -> Scp03Session {
    let key = hex("404142434445464748494a4b4c4d4e4f");
    Scp03Session {
        s_enc: Zeroizing::new(key.clone()),
        s_mac: Zeroizing::new(key.clone()),
        s_rmac: Zeroizing::new(key),
        static_dek: None,
        oce_authenticated: true,
        mac_chaining_value: [0; 16],
        encryption_counter: 0,
        security_level,
    }
}

#[test]
fn encodes_short_apdu_cases() {
    assert_eq!(
        CommandApdu {
            cla: 0,
            ins: 0x84,
            p1: 0,
            p2: 0,
            data: vec![],
            le: Some(8),
            extended: false,
        }
        .encode()
        .unwrap(),
        hex("00 84 00 00 08")
    );
    assert_eq!(
        CommandApdu {
            cla: 0,
            ins: 0xa4,
            p1: 4,
            p2: 0,
            data: DEFAULT_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
            le: Some(256),
            extended: false,
        }
        .encode()
        .unwrap(),
        hex("00 A4 04 00 08 A0 00 00 01 51 00 00 00 00")
    );
}

#[test]
fn encodes_extended_apdu_cases() {
    assert_eq!(
        CommandApdu {
            cla: 0,
            ins: 0xca,
            p1: 0,
            p2: 0,
            data: vec![],
            le: Some(65_536),
            extended: false,
        }
        .encode()
        .unwrap(),
        hex("00 CA 00 00 00 00 00")
    );
    assert_eq!(
        CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![1, 2, 3],
            le: None,
            extended: true,
        }
        .encode()
        .unwrap(),
        hex("80 E2 00 00 00 00 03 01 02 03")
    );

    let data = vec![0x5a; 256];
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xe2,
        p1: 0,
        p2: 0,
        data: data.clone(),
        le: Some(65_536),
        extended: false,
    };
    let encoded = command.encode().unwrap();
    assert_eq!(&encoded[..7], &hex("80 E2 00 00 00 01 00"));
    assert_eq!(&encoded[7..263], data);
    assert_eq!(&encoded[263..], &[0, 0]);
}

#[test]
fn rejects_unencodable_apdu_lengths() {
    let command = |data, le| CommandApdu {
        cla: 0,
        ins: 0,
        p1: 0,
        p2: 0,
        data,
        le,
        extended: false,
    };
    assert!(command(vec![0; 65_536], None).encode().is_err());
    assert!(command(vec![], Some(0)).encode().is_err());
    assert!(command(vec![], Some(65_537)).encode().is_err());
}

#[test]
fn parses_response_status() {
    assert_eq!(
        ResponseApdu::parse(&hex("01 02 90 00")).unwrap(),
        ResponseApdu {
            data: vec![1, 2],
            status: 0x9000,
        }
    );
    assert!(ResponseApdu::parse(&[0x90]).is_err());
}

#[test]
fn aes_cmac_matches_nist_vectors() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    assert_eq!(
        aes_cmac(&key, &[]).unwrap().as_slice(),
        hex("bb1d6929e95937287fa37d129b756746")
    );
    assert_eq!(
        aes_cmac(&key, &hex("6bc1bee22e409f96e93d7e117393172a"))
            .unwrap()
            .as_slice(),
        hex("070a16b46b4d4144f79bdd9dd04a287c")
    );
}

#[test]
fn decodes_apdu_forms_used_by_secure_channel_transport() {
    let commands = [
        CommandApdu {
            cla: 0,
            ins: 0x84,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(256),
            extended: false,
        },
        CommandApdu {
            cla: 0,
            ins: 0xda,
            p1: 0x01,
            p2: 0x02,
            data: vec![0xaa; 255],
            le: Some(256),
            extended: false,
        },
        CommandApdu {
            cla: 0,
            ins: 0xda,
            p1: 0x01,
            p2: 0x02,
            data: vec![0xaa; 256],
            le: Some(65_536),
            extended: true,
        },
    ];
    for command in commands {
        let encoded = command.encode().unwrap();
        assert_eq!(CommandApdu::decode(&encoded).unwrap(), command);
    }
}

#[test]
fn secure_channel_connector_wraps_encoded_apdus() {
    let base = std::rc::Rc::new(ScriptedConnector::new(vec![hex("90 00")]))
        as std::rc::Rc<dyn crate::Connector>;
    let application_aid = vec![1, 2, 3, 4, 5];
    let connector = crate::PcscAppletConnector {
        base,
        application_aid: application_aid.clone(),
        protocol: Some(crate::SecureChannelProtocol::Scp03),
        state: std::rc::Rc::new(RefCell::new(crate::SecureChannelState {
            application_aid,
            session: Some(test_session(0x01)),
            validated_scp11_keys: std::collections::HashMap::new(),
            connection_epoch: 0,
        })),
        enabled: std::cell::Cell::new(true),
        applet_present: std::cell::Cell::new(true),
        discovery_error: RefCell::new(None),
    };
    let command = CommandApdu {
        cla: 0,
        ins: 0x84,
        p1: 0,
        p2: 0,
        data: Vec::new(),
        le: Some(8),
        extended: false,
    };
    let encoded = command.encode().unwrap();
    let mut received = vec![0; 256];
    let response = connector
        .transmit(&encoded, &mut received, Duration::from_secs(1))
        .unwrap();
    assert_eq!(response, hex("90 00"));
}

#[test]
fn kdf_uses_gp_counter_layout_and_requested_length() {
    let key = hex("404142434445464748494a4b4c4d4e4f");
    let context = hex("0102030405060708 1112131415161718");
    assert_eq!(
        derive(&key, DERIVATION_S_ENC, &context, 128).unwrap(),
        hex("d99675d4a95c58de629225730cddb758")
    );
    assert_eq!(
        derive(&key, DERIVATION_S_ENC, &context, 192).unwrap().len(),
        24
    );
    assert_eq!(
        derive(&key, DERIVATION_S_ENC, &context, 256).unwrap().len(),
        32
    );
}

#[test]
fn yubikey_factory_key_set_uses_documented_defaults() {
    let keys = Scp03KeySet::yubikey_factory();
    assert_eq!(keys.key_version, YUBIKEY_FACTORY_KEY_VERSION);
    assert_eq!(keys.key_id, YUBIKEY_FACTORY_KEY_ID);
    assert_eq!(keys.enc.as_slice(), YUBIKEY_FACTORY_KEY);
    assert_eq!(keys.mac.as_slice(), YUBIKEY_FACTORY_KEY);
    assert_eq!(
        keys.dek.as_ref().map(|key| key.as_slice()),
        Some(YUBIKEY_FACTORY_KEY.as_slice())
    );
    assert_eq!(YUBIKEY_SECURITY_LEVEL, 0x33);
}

#[test]
fn non_default_key_selectors_require_custom_key_material() {
    assert!(validate_factory_key_selector(
        YUBIKEY_FACTORY_KEY_VERSION,
        YUBIKEY_FACTORY_KEY_ID,
        false,
    )
    .is_ok());
    assert!(validate_factory_key_selector(1, YUBIKEY_FACTORY_KEY_ID, false).is_err());
    assert!(validate_factory_key_selector(YUBIKEY_FACTORY_KEY_VERSION, 1, false).is_err());
    assert!(validate_factory_key_selector(1, 1, true).is_ok());
}

#[test]
fn accepts_explicit_generic_scp03_key_sizes_and_security_levels() {
    for key_size in [16, 24, 32] {
        assert!(Scp03KeySet::new(
            1,
            0,
            vec![1; key_size],
            vec![2; key_size],
            vec![3; key_size],
        )
        .is_ok());
    }
    assert!(Scp03KeySet::new(1, 0, vec![1; 16], vec![2; 24], vec![3; 16]).is_err());
    assert!(Scp03KeySet::new(1, 0, vec![1; 16], vec![2; 16], vec![3; 32]).is_err());
    for security_level in [0x00, 0x01, 0x03, 0x11, 0x13, 0x33] {
        assert!(validate_security_level(security_level).is_ok());
    }
}

#[test]
fn yubico_diversification_matches_sp800_108_cmac_vectors() {
    let bmk = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let issuer_context: [u8; 10] = hex("00010203040506070809").try_into().unwrap();
    assert_eq!(
        yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_ENC_LABEL, &issuer_context).unwrap(),
        hex("6D8EF504CDFCA3D667DE72F24C4C82AF")
    );
    assert_eq!(
        yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_MAC_LABEL, &issuer_context).unwrap(),
        hex("90753AB6FD71D3BB9618DBEA179E0A56")
    );
    assert_eq!(
        yubico_diversify_key(&bmk, YUBICO_DIVERSIFICATION_DEK_LABEL, &issuer_context).unwrap(),
        hex("53A68B700A229B4314315BFCB162A650")
    );
    assert!(yubico_diversify_key(
        &bmk[..AES_BLOCK_SIZE],
        YUBICO_DIVERSIFICATION_ENC_LABEL,
        &issuer_context,
    )
    .is_err());
}

#[test]
fn resolves_all_three_keys_from_the_initialize_update_context() {
    let keys = Scp03KeySet {
        key_version: 7,
        key_id: 0,
        enc: Zeroizing::new(Vec::new()),
        mac: Zeroizing::new(Vec::new()),
        dek: None,
        diversification_bmk: Some(Zeroizing::new(hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ))),
    };
    keys.validate().unwrap();
    let resolved = keys
        .resolve(&hex("00010203040506070809").try_into().unwrap())
        .unwrap();
    assert_eq!(
        resolved.enc.as_slice(),
        hex("6D8EF504CDFCA3D667DE72F24C4C82AF")
    );
    assert_eq!(
        resolved.mac.as_slice(),
        hex("90753AB6FD71D3BB9618DBEA179E0A56")
    );
    assert_eq!(
        resolved.dek.as_ref().map(|key| key.as_slice()),
        Some(hex("53A68B700A229B4314315BFCB162A650").as_slice())
    );
}

#[test]
fn selects_configured_security_domain() {
    let connector = ScriptedConnector::new(vec![hex("6f 00 90 00")]);
    select_application(&connector, &DEFAULT_ISSUER_SECURITY_DOMAIN_AID).unwrap();
    assert_eq!(
        connector.commands.into_inner(),
        vec![hex("00 A4 04 00 08 A0 00 00 01 51 00 00 00 00")]
    );
    assert!(select_application(&ScriptedConnector::new(Vec::new()), &[1, 2, 3, 4]).is_err());
}

#[test]
fn rejects_invalid_padding_and_response_mac() {
    assert!(unpad(vec![0; 16]).is_err());
    assert!(unpad(vec![0x80, 1]).is_err());
    let session = Scp03Session {
        s_enc: Zeroizing::new(vec![0; 16]),
        s_mac: Zeroizing::new(vec![0; 16]),
        s_rmac: Zeroizing::new(vec![0; 16]),
        static_dek: None,
        oce_authenticated: true,
        mac_chaining_value: [0; 16],
        encryption_counter: 1,
        security_level: 0x11,
    };
    assert!(session
        .unprotect_response(ResponseApdu {
            data: vec![0; 8],
            status: 0x9000,
        })
        .is_err());
}

#[test]
fn encrypts_and_macs_commands() {
    let key = hex("404142434445464748494a4b4c4d4e4f");
    let mut session = Scp03Session {
        s_enc: Zeroizing::new(key.clone()),
        s_mac: Zeroizing::new(key.clone()),
        s_rmac: Zeroizing::new(key),
        static_dek: None,
        oce_authenticated: true,
        mac_chaining_value: [0; 16],
        encryption_counter: 0,
        security_level: 0x03,
    };
    let connector = ScriptedConnector::new(vec![hex("90 00")]);
    let response = session
        .transmit(
            &connector,
            &CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1: 0,
                p2: 0,
                data: vec![1, 2, 3],
                le: Some(256),
                extended: false,
            },
        )
        .unwrap();
    assert_eq!(response.status, 0x9000);
    assert_eq!(
        connector.commands.into_inner(),
        vec![hex(
            "84 E2 00 00 18 0F EF 8F BF 4E 4F 9A 76 8B 7A 07 C7 D0 89 88 \
                 BA E5 EF 16 EB C5 06 98 9B 00"
        )]
    );
}

#[test]
fn macs_extended_commands_with_extended_lc() {
    let key = hex("404142434445464748494a4b4c4d4e4f");
    let mut session = Scp03Session {
        s_enc: Zeroizing::new(key.clone()),
        s_mac: Zeroizing::new(key.clone()),
        s_rmac: Zeroizing::new(key),
        static_dek: None,
        oce_authenticated: true,
        mac_chaining_value: [0; 16],
        encryption_counter: 0,
        security_level: 0x01,
    };
    let protected = session
        .protect_command(&CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![1, 2, 3],
            le: Some(256),
            extended: true,
        })
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        protected,
        hex("84 E2 00 00 00 00 0B 01 02 03 1D 53 BC 91 9D 15 44 FF 01 00")
    );
}

#[test]
fn secure_messaging_promotes_short_commands_when_required() {
    let key = hex("404142434445464748494a4b4c4d4e4f");
    let mut session = Scp03Session {
        s_enc: Zeroizing::new(key.clone()),
        s_mac: Zeroizing::new(key.clone()),
        s_rmac: Zeroizing::new(key),
        static_dek: None,
        oce_authenticated: true,
        mac_chaining_value: [0; 16],
        encryption_counter: 0,
        security_level: 0x03,
    };
    let protected = session
        .protect_command(&CommandApdu {
            cla: 0x80,
            ins: 0xe2,
            p1: 0,
            p2: 0,
            data: vec![0x5a; 250],
            le: Some(256),
            extended: false,
        })
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(&protected[..7], &hex("84 E2 00 00 00 01 08"));
    assert_eq!(protected.len(), 273);
    assert_eq!(&protected[protected.len() - 2..], &[1, 0]);
}

#[test]
fn secure_messaging_normalizes_cla_and_rejects_other_logical_channels() {
    for (cla, expected) in [(0x08, 0x04), (0x88, 0x84)] {
        let protected = test_session(0x01)
            .protect_command(&CommandApdu {
                cla,
                ins: 0xca,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(256),
                extended: false,
            })
            .unwrap();
        assert_eq!(protected.cla, expected);
    }

    for cla in [0x01, 0x40, 0x81, 0xc0] {
        let mut session = test_session(0x01);
        assert!(session
            .protect_command(&CommandApdu {
                cla,
                ins: 0xca,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(256),
                extended: false,
            })
            .is_err());
        assert_eq!(session.encryption_counter, 0);
    }
}

#[test]
fn chains_after_protecting_the_complete_command() {
    let data: Vec<u8> = (0..300).map(|value| value as u8).collect();
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xe2,
        p1: 0x02,
        p2: 0x03,
        data: data.clone(),
        le: Some(256),
        extended: false,
    };
    let connector = ScriptedConnector::new(vec![hex("90 00"), hex("90 00")]);
    let response = test_session(0x01)
        .transmit_chained(&connector, &command)
        .unwrap();
    assert_eq!(response.status, RESPONSE_OK);

    let commands = connector.commands.into_inner();
    assert_eq!(commands.len(), 2);
    assert_eq!(&commands[0][..5], &[0x84, 0xe2, 0x82, 0x03, 0xff]);
    assert_eq!(&commands[1][..5], &[0x84, 0xe2, 0x02, 0x03, 0x35]);
    assert_eq!(commands[1].last(), Some(&0));

    let mut protected_data = commands[0][5..].to_vec();
    protected_data.extend_from_slice(&commands[1][5..commands[1].len() - 1]);
    assert_eq!(&protected_data[..data.len()], data);
    assert_eq!(
        &protected_data[data.len()..],
        &hex("6F CD 3B 5E DE 1D 71 78")
    );
}

#[test]
fn encrypts_the_complete_command_before_chaining() {
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xe2,
        p1: 0,
        p2: 0,
        data: vec![0x5a; 300],
        le: None,
        extended: false,
    };
    let connector = ScriptedConnector::new(vec![hex("90 00"), hex("90 00")]);
    test_session(0x03)
        .transmit_chained(&connector, &command)
        .unwrap();

    let commands = connector.commands.into_inner();
    let mut protected_data = commands[0][5..].to_vec();
    protected_data.extend_from_slice(&commands[1][5..]);
    assert_eq!(protected_data.len(), 312);
    assert_eq!(
        &protected_data[..16],
        &hex("1E C7 81 53 83 11 08 31 66 3C CC E3 A5 DE 45 06")
    );
    assert_eq!(
        &protected_data[protected_data.len() - MAC_LENGTH..],
        &hex("EE CC BD 4C 2A 82 50 C9")
    );
}

#[test]
fn chained_intermediate_responses_omit_rmac() {
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xe2,
        p1: 0,
        p2: 0,
        data: vec![0x5a; 300],
        le: None,
        extended: false,
    };
    let mut preview = test_session(0x11);
    preview.protect_command(&command).unwrap();
    let mut rmac_input = preview.mac_chaining_value.to_vec();
    rmac_input.extend_from_slice(&RESPONSE_OK.to_be_bytes());
    let rmac = aes_cmac(&preview.s_rmac, &rmac_input).unwrap();
    let mut final_response = rmac[..MAC_LENGTH].to_vec();
    final_response.extend_from_slice(&RESPONSE_OK.to_be_bytes());
    let connector = ScriptedConnector::new(vec![hex("90 00"), final_response]);

    let response = test_session(0x11)
        .transmit_chained(&connector, &command)
        .unwrap();
    assert_eq!(
        response,
        ResponseApdu {
            data: vec![],
            status: RESPONSE_OK,
        }
    );
}

#[test]
fn collects_iso_response_chains() {
    let connector = ScriptedConnector::new(vec![hex("AA 61 02"), hex("BB CC 90 00")]);
    let response = test_session(0x01)
        .transmit(
            &connector,
            &CommandApdu {
                cla: 0x80,
                ins: 0xca,
                p1: 0,
                p2: 0,
                data: vec![],
                le: Some(256),
                extended: false,
            },
        )
        .unwrap();
    assert_eq!(
        response,
        ResponseApdu {
            data: hex("AA BB CC"),
            status: RESPONSE_OK,
        }
    );
    let commands = connector.commands.into_inner();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[1], hex("00 C0 00 00 02"));
}

#[test]
fn collects_unprotected_iso_response_chains() {
    let connector = ScriptedConnector::new(vec![hex("BB CC 90 00")]);
    let response = Scp03Session::collect_response_chain(
        &connector,
        ResponseApdu {
            data: hex("AA"),
            status: 0x6102,
        },
    )
    .unwrap();
    assert_eq!(
        response,
        ResponseApdu {
            data: hex("AA BB CC"),
            status: RESPONSE_OK,
        }
    );
    assert_eq!(connector.commands.into_inner(), vec![hex("00 C0 00 00 02")]);
}

#[test]
fn response_chain_requires_progress_after_initial_continuation() {
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xca,
        p1: 0,
        p2: 0,
        data: vec![],
        le: Some(256),
        extended: false,
    };

    let connector = ScriptedConnector::new(vec![hex("61 01"), hex("61 01")]);
    assert!(test_session(0x01).transmit(&connector, &command).is_err());
    assert_eq!(connector.commands.into_inner().len(), 2);

    let connector = ScriptedConnector::new(vec![hex("61 01"), hex("AA 90 00")]);
    assert_eq!(
        test_session(0x01)
            .transmit(&connector, &command)
            .unwrap()
            .data,
        hex("AA")
    );

    let connector = ScriptedConnector::new(vec![hex("AA 61 01"); MAX_RESPONSE_CHAIN_SEGMENTS + 1]);
    assert!(test_session(0x01).transmit(&connector, &command).is_err());
    assert_eq!(
        connector.commands.into_inner().len(),
        MAX_RESPONSE_CHAIN_SEGMENTS + 1
    );
}

#[test]
fn response_chain_is_verified_and_decrypted_as_one_response() {
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xca,
        p1: 0,
        p2: 0,
        data: vec![],
        le: Some(256),
        extended: false,
    };
    let mut preview = test_session(0x33);
    preview.protect_command(&command).unwrap();
    let plaintext: Vec<u8> = (0..300).map(|value| value as u8).collect();
    let iv = preview.command_iv(true).unwrap();
    let ciphertext = aes_cbc(&preview.s_enc, &iv, &pad(&plaintext), Mode::Encrypt).unwrap();
    let mut rmac_input = preview.mac_chaining_value.to_vec();
    rmac_input.extend_from_slice(&ciphertext);
    rmac_input.extend_from_slice(&RESPONSE_OK.to_be_bytes());
    let rmac = aes_cmac(&preview.s_rmac, &rmac_input).unwrap();
    let mut protected_response = ciphertext;
    protected_response.extend_from_slice(&rmac[..MAC_LENGTH]);

    let mut first_response = protected_response[..256].to_vec();
    first_response.extend([0x61, 0x00]);
    let mut final_response = protected_response[256..].to_vec();
    final_response.extend_from_slice(&RESPONSE_OK.to_be_bytes());
    let connector = ScriptedConnector::new(vec![first_response, final_response]);

    let response = test_session(0x33).transmit(&connector, &command).unwrap();
    assert_eq!(
        response,
        ResponseApdu {
            data: plaintext,
            status: RESPONSE_OK,
        }
    );
    assert_eq!(connector.commands.into_inner()[1], hex("00 C0 00 00 00"));
}

#[test]
fn chained_transfer_stops_on_invalid_intermediate_response() {
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xe2,
        p1: 0,
        p2: 0,
        data: vec![0x5a; 300],
        le: None,
        extended: false,
    };
    for response in [hex("6A 80"), hex("01 90 00")] {
        let connector = ScriptedConnector::new(vec![response]);
        assert!(test_session(0x01)
            .transmit_chained(&connector, &command)
            .is_err());
        assert_eq!(connector.commands.into_inner().len(), 1);
    }
}

#[test]
fn chained_transfer_rejects_ambiguous_header_inputs() {
    let connector = ScriptedConnector::new(vec![]);
    for (p1, le) in [(MORE_COMMANDS, None), (0, Some(65_536))] {
        let mut session = test_session(0x01);
        let result = session.transmit_chained(
            &connector,
            &CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1,
                p2: 0,
                data: vec![0; 300],
                le,
                extended: false,
            },
        );
        assert!(result.is_err());
        assert_eq!(session.encryption_counter, 0);
    }
}

#[test]
fn error_responses_do_not_require_rmac() {
    let connector = ScriptedConnector::new(vec![hex("6A 80")]);
    let response = test_session(0x11)
        .transmit(
            &connector,
            &CommandApdu {
                cla: 0x80,
                ins: 0xe2,
                p1: 0,
                p2: 0,
                data: vec![1],
                le: None,
                extended: false,
            },
        )
        .unwrap();
    assert_eq!(response.status, 0x6a80);
    assert!(response.data.is_empty());
}

#[test]
fn yubikey_sessions_share_and_require_the_authenticated_channel() {
    let connector = std::rc::Rc::new(ScriptedConnector::new(vec![hex("90 00")]));
    let shared = std::rc::Rc::new(RefCell::new(Some(test_session(0x01))));
    let session = crate::IssuerSecurityDomainSession {
        slotID: 1,
        flags: 0,
        connector: connector.clone(),
        session: shared.clone(),
    };
    let response = session
        .send_apdu(
            &CommandApdu {
                cla: 0x80,
                ins: 0xca,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            },
            false,
        )
        .unwrap();
    assert_eq!(response.status, RESPONSE_OK);
    assert_eq!(connector.commands.borrow().len(), 1);
    assert_eq!(connector.commands.borrow()[0][0], 0x84);
    assert_eq!(shared.borrow().as_ref().unwrap().encryption_counter, 1);

    *shared.borrow_mut() = None;
    assert!(session
        .send_apdu(
            &CommandApdu {
                cla: 0,
                ins: 0x84,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(8),
                extended: false,
            },
            false,
        )
        .is_err());
    assert_eq!(connector.commands.borrow().len(), 1);
}

#[test]
fn yubikey_sessions_discard_desynchronized_channels() {
    let connector = std::rc::Rc::new(ScriptedConnector::new(vec![]));
    let shared = std::rc::Rc::new(RefCell::new(Some(test_session(0x01))));
    let session = crate::IssuerSecurityDomainSession {
        slotID: 1,
        flags: 0,
        connector,
        session: shared.clone(),
    };
    assert!(session
        .send_apdu(
            &CommandApdu {
                cla: 0,
                ins: 0x84,
                p1: 0,
                p2: 0,
                data: Vec::new(),
                le: Some(8),
                extended: false,
            },
            false,
        )
        .is_err());
    assert!(shared.borrow().is_none());
}

#[test]
fn authenticates_with_yubico_diversified_transport_keys() {
    let keys = Scp03KeySet {
        key_version: 7,
        key_id: 0,
        enc: Zeroizing::new(Vec::new()),
        mac: Zeroizing::new(Vec::new()),
        dek: None,
        diversification_bmk: Some(Zeroizing::new(hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ))),
    };
    keys.validate().unwrap();
    let issuer_context: [u8; 10] = hex("00010203040506070809").try_into().unwrap();
    let resolved = keys.resolve(&issuer_context).unwrap();
    let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
    let card = hex("1112131415161718");
    let mut session_context = host.to_vec();
    session_context.extend_from_slice(&card);
    let s_mac = derive(&resolved.mac, DERIVATION_S_MAC, &session_context, 128).unwrap();
    let card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &session_context, 64).unwrap();
    let mut initialize_response = issuer_context.to_vec();
    initialize_response.extend([7, 3, 0x60]);
    initialize_response.extend_from_slice(&card);
    initialize_response.extend_from_slice(&card_cryptogram);
    initialize_response.extend([0x90, 0x00]);
    let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

    Scp03Session::establish_with_challenge(
        &connector,
        &keys,
        YUBIKEY_SECURITY_LEVEL,
        host,
        &DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
    )
    .unwrap();
    let commands = connector.commands.into_inner();
    assert_eq!(&commands[0][..5], &hex("80 50 07 00 08"));
    assert_eq!(&commands[1][..5], &hex("84 82 33 00 10"));
}

#[test]
fn matches_kaoh_globalplatform_scp03_authentication_vector() {
    // Published by the GlobalPlatform open-source implementation:
    // https://github.com/kaoh/globalplatform/blob/master/globalplatform/src/scp03Test.c
    let keys = Scp03KeySet::new(
        0,
        0,
        hex("F995D0A069335C7DF42E590317FFEA6D"),
        hex("58563362EC5A4541ABCD32B34B1EAE7D"),
        hex("0A02A6D687406DCFA09DC70B3EDB7E38"),
    )
    .unwrap();
    let host: [u8; 8] = hex("9BD6BF878FB8E991").try_into().unwrap();
    let connector = ScriptedConnector::new(vec![
        hex("00000000000000000000 300370 3C80C2CC87EB3A35 \
                 E4EDBA35E629C336 00001E 9000"),
        hex("9000"),
    ]);

    let session = Scp03Session::establish_with_challenge(
        &connector,
        &keys,
        0x03,
        host,
        &DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
    )
    .unwrap();

    assert_eq!(
        session.s_enc.as_slice(),
        hex("D83EE38C9954C8078987A5E9EE6AB13C")
    );
    assert_eq!(
        session.s_mac.as_slice(),
        hex("6FF37716E0413065E8DFD08BF1E9EC5E")
    );
    assert_eq!(
        session.s_rmac.as_slice(),
        hex("0254C786E57ACA8982670C1C1A05FF12")
    );
    assert_eq!(
        connector.commands.into_inner(),
        vec![
            hex("8050000008 9BD6BF878FB8E991 00"),
            hex("8482030010 23EBFEDC579D22CD CDB6A25A5FF7891F"),
        ]
    );
}

#[test]
fn matches_samsung_openscp_s8_exchange_vectors() {
    // Samsung OpenSCP publishes complete S8 exchanges for all AES key sizes:
    // https://github.com/Samsung/OpenSCP-Java/tree/main/src/test/java/com/samsung/openscp/testdata
    struct Vector<'a> {
        enc: &'a str,
        mac: &'a str,
        dek: &'a str,
        initialize_response: &'a str,
        external_authenticate: &'a str,
        protected_commands: [&'a str; 3],
        protected_responses: [&'a str; 3],
    }

    let vectors = [
        Vector {
            enc: "1D72CD9283FD55162722C6BEAA4DC187",
            mac: "F4932BA02FFC3098D172790099D28382",
            dek: "B4BDC610C3F6793708FF1132E2C5BF60",
            initialize_response: concat!(
                "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                "DC2DBE8974C8B0DE 00082A 9000"
            ),
            external_authenticate: "8482330010 B08D6CE26B6CB3CC B411CF0296EB7B1D",
            protected_commands: [
                "84F2200018 5230BA64388B4A40E0B4DA5CC1DF51C2 85E4020D99D5AED1",
                "84F2400018 1819D47B42BBE6B9449BBC2BD43A090D AC1F2F0A52D9F34B",
                "84F2800018 09F07C3DF47956B1052951FA28211BA7 BABC05C321D9B3BF",
            ],
            protected_responses: [
                concat!(
                    "BD3292BFB1A23C4478E37292BA1EDF43",
                    "8770CE472FB7611FBDBD1C981A27FA47",
                    "80A81A95D93C05F9C4C94839DED0363C",
                    "FEA57CE2ECFB572B26F3474DAEEBBABC",
                    "202942381F9755F5 9000"
                ),
                concat!(
                    "BB82442BB5CC8C839620615D1F163D3D",
                    "DBC9357D68EF4BAD997CFBB79A24C224",
                    "A89488C44B25C3B23D489E4E58A309D4",
                    "38FDD6E453D0E07216541FB142B977A3",
                    "A7D4C4048BBE2BA068F04A0A4A9C50B",
                    "AD232F8CA8EA1F40E 9000"
                ),
                concat!(
                    "31EB08363026463BAD10AF29F24301F1",
                    "D9B8532067F9313D97FDA39BBE6B6099",
                    "BEFD623E1F79FB5D 9000"
                ),
            ],
        },
        Vector {
            enc: "1D72CD9283FD55162722C6BEAA4DC1877F4C0CD0ECC15E05",
            mac: "F4932BA02FFC3098D172790099D2838236F2E61068D56F44",
            dek: "B4BDC610C3F6793708FF1132E2C5BF60523AEAC06B32F204",
            initialize_response: concat!(
                "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                "6E7C64F962A822A4 00082A 9000"
            ),
            external_authenticate: "8482330010 63B6CEFAC0EC0983 33860788C65220BA",
            protected_commands: [
                "84F2200018 D9EDCBCB7F69CB1EF0508E6EDE933A6D 80091E7D99CB3E51",
                "84F2400018 CDC4B0480CF151C1132655133115A8CA 1A89964F2554551C",
                "84F2800018 96800333FA638A32DBCCBF4C7E52FBD5 DA469A954E1D58F6",
            ],
            protected_responses: [
                concat!(
                    "99077B167D43A4F313B59B63CC23EFD3",
                    "B5158BDEF8F24D85E250570A4AAB8186",
                    "9A92307350267F0FBC2278FA3D34D2FD",
                    "5D2B4E8C0362C01D082C76A17B80AEA4",
                    "BA5FB9D7DA3BB368 9000"
                ),
                concat!(
                    "AB7A97B6C673DF3D95378D06B7B42E25",
                    "D7C3B22D6D1A42299FFED17F5973950E",
                    "C68C77700FC01947067470178A1D0615",
                    "2ED648E95E8C3510B61CF0036DFD8C9F",
                    "6FA167D32FDEB3F81A0E6B2BB35BCD4C",
                    "D104692D131D7776 9000"
                ),
                concat!(
                    "E5E5761FEFF5C0C078ADBC4E77B72900",
                    "94C99183AC73CAB99A7412D0194DEFFD",
                    "D0895DCCE662D945 9000"
                ),
            ],
        },
        Vector {
            enc: concat!(
                "1D72CD9283FD55162722C6BEAA4DC187",
                "7F4C0CD0ECC15E052AAC39A99AF9AD72"
            ),
            mac: concat!(
                "F4932BA02FFC3098D172790099D28382",
                "36F2E61068D56F4401CC0374C25AF8CB"
            ),
            dek: concat!(
                "B4BDC610C3F6793708FF1132E2C5BF60",
                "523AEAC06B32F204B851B6CC007C8D3C"
            ),
            initialize_response: concat!(
                "A1A01243058551312085 300370 9CE033FA78E6B10D ",
                "8AFA7267CB63740E 00082A 9000"
            ),
            external_authenticate: "8482330010 50E003735F922282 69A094FFC07429FD",
            protected_commands: [
                "84F2200018 BD57D1382AE8F66F7EB5F5991B92D139 9044157C7DFD2761",
                "84F2400018 45D2B475C3EFF8BBB254D0B6A8E6CA97 CF5265D907A76070",
                "84F2800018 7083CA3ADA0F76CF7B3FFAC60ABE1359 9D521EE7B9224C49",
            ],
            protected_responses: [
                concat!(
                    "47D81041004B7E9208E3BEF1372E7CDE",
                    "8CD995AEF207F138C80D45156F2D36F2",
                    "B15BDC9C4D6FDB9774344495CCC83AE7",
                    "BA0B39C734BF9CEBD07204AA5A67DF2D",
                    "7E663D55FC4944C0 9000"
                ),
                concat!(
                    "59E8DCFDC22D436336552128F790E1B3",
                    "83D6942ED4025F30FE8D95541E634E23",
                    "8BFD963D88DF822D8EBCC1272A9D56C7",
                    "D1CBC306039647FC4977EFF562C0B8C0",
                    "1314B1C8B2D168A581A98C65B676B3EE",
                    "4032E91A9C0858EC 9000"
                ),
                concat!("E58CB33A46F76909ADDDFF0C2821F4F2", "5F22B5553C534DC6 9000"),
            ],
        },
    ];
    let host: [u8; 8] = hex("06F85B77251BF794").try_into().unwrap();
    let plain_responses = [
        concat!(
            "08A00000015141434C010010A00000022020030101010000000000060100",
            "10A0000002202003010101000000000011010005A0000002480100"
        ),
        concat!(
            "0AA9A8A7A6A5A4A3A2A1A00F800AA0A1A2A3A4A5A6A7A8A9070009",
            "A00000015141434C00070010A00000022020030103010000000000110700",
            "07A00000024804000700"
        ),
        "08A0000001510000000F9E",
    ];

    for vector in vectors {
        // These traces reuse one externally supplied card challenge for all key sizes even
        // though i=70 marks it as pseudo-random. The kaoh vector above covers verification
        // of a key-derived challenge; these vectors start at card-cryptogram verification.
        let mut responses = vec![hex("9000")];
        responses.extend(vector.protected_responses.map(hex));
        let connector = ScriptedConnector::new(responses);
        let keys =
            Scp03KeySet::new(0x30, 0, hex(vector.enc), hex(vector.mac), hex(vector.dek)).unwrap();
        let initialize_response = ResponseApdu::parse(&hex(vector.initialize_response)).unwrap();
        let update = InitializeUpdate::parse(&initialize_response.data).unwrap();
        let static_keys = keys.resolve(&update.issuer_context).unwrap();
        let (mut session, host_cryptogram) = Scp03Session::from_initialize_update(
            &static_keys,
            0x33,
            host,
            &update,
            &initialize_response.data[21..29],
        )
        .unwrap();
        assert_eq!(session.s_enc.len(), keys.enc.len());
        assert_eq!(session.s_mac.len(), keys.mac.len());
        assert_eq!(session.s_rmac.len(), keys.mac.len());
        let authenticate = session.external_authenticate(&host_cryptogram).unwrap();
        transmit(&connector, &authenticate)
            .unwrap()
            .require_success(&authenticate)
            .unwrap();

        for (p1, expected) in [0x20, 0x40, 0x80].into_iter().zip(plain_responses) {
            let response = session
                .transmit(
                    &connector,
                    &CommandApdu {
                        cla: 0x80,
                        ins: 0xf2,
                        p1,
                        p2: 0,
                        data: hex("4F00"),
                        le: None,
                        extended: false,
                    },
                )
                .unwrap();
            assert_eq!(
                response,
                ResponseApdu {
                    data: hex(expected),
                    status: RESPONSE_OK
                }
            );
        }

        let mut expected_commands = vec![hex(vector.external_authenticate)];
        expected_commands.extend(vector.protected_commands.map(hex));
        assert_eq!(connector.commands.into_inner(), expected_commands);
    }
}

#[test]
fn authenticates_with_deterministic_challenges() {
    let keys = Scp03KeySet::new(
        0,
        0,
        hex("404142434445464748494a4b4c4d4e4f"),
        hex("404142434445464748494a4b4c4d4e4f"),
        hex("404142434445464748494a4b4c4d4e4f"),
    )
    .unwrap();
    let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
    let card = hex("1112131415161718");
    let mut context = host.to_vec();
    context.extend_from_slice(&card);
    let s_mac = derive(&keys.mac, DERIVATION_S_MAC, &context, 128).unwrap();
    let card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &context, 64).unwrap();
    let mut initialize_response = vec![0; 10];
    initialize_response.extend([0, 3, 0]);
    initialize_response.extend_from_slice(&card);
    initialize_response.extend_from_slice(&card_cryptogram);
    initialize_response.extend([0x90, 0x00]);
    let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

    Scp03Session::establish_with_challenge(
        &connector,
        &keys,
        0x03,
        host,
        &DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
    )
    .unwrap();
    let commands = connector.commands.into_inner();
    assert_eq!(
        commands[0],
        hex("80 50 00 00 08 01 02 03 04 05 06 07 08 00")
    );
    assert_eq!(
        commands[1],
        hex("84 82 03 00 10 00 B1 1D 00 F7 5C 45 6B 08 28 91 E5 45 EC 80 79")
    );
}

#[test]
fn verifies_pseudo_random_card_challenge() {
    let keys = Scp03KeySet::new(
        0,
        0,
        hex("404142434445464748494a4b4c4d4e4f"),
        hex("404142434445464748494a4b4c4d4e4f"),
        hex("404142434445464748494a4b4c4d4e4f"),
    )
    .unwrap();
    let host: [u8; 8] = hex("0102030405060708").try_into().unwrap();
    let sequence = hex("000001");
    let mut challenge_context = sequence.clone();
    challenge_context.extend_from_slice(&DEFAULT_ISSUER_SECURITY_DOMAIN_AID);
    let card = derive(&keys.enc, DERIVATION_CARD_CHALLENGE, &challenge_context, 64).unwrap();
    assert_eq!(card, hex("86 C8 BD 65 FA 10 44 EE"));
    let mut session_context = host.to_vec();
    session_context.extend_from_slice(&card);
    let s_mac = derive(&keys.mac, DERIVATION_S_MAC, &session_context, 128).unwrap();
    let card_cryptogram = derive(&s_mac, DERIVATION_CARD_CRYPTOGRAM, &session_context, 64).unwrap();
    let mut initialize_response = vec![0; 10];
    initialize_response.extend([0, 3, 0x10]);
    initialize_response.extend_from_slice(&card);
    initialize_response.extend_from_slice(&card_cryptogram);
    initialize_response.extend_from_slice(&sequence);
    initialize_response.extend([0x90, 0x00]);
    let connector = ScriptedConnector::new(vec![initialize_response, hex("90 00")]);

    Scp03Session::establish_with_challenge(
        &connector,
        &keys,
        0x03,
        host,
        &DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
    )
    .unwrap();
}

#[test]
fn rejects_unsupported_response_security_and_s16() {
    assert!(validate_card_capabilities(0x00, 0x11).is_err());
    assert!(validate_card_capabilities(0x20, 0x33).is_err());
    assert!(validate_card_capabilities(0x60, 0x33).is_ok());
    assert!(validate_implementation(0x01).is_err());
    assert!(validate_implementation(0x40).is_err());
}
