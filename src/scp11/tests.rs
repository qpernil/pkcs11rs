use super::*;
use openssl::bn::BigNum;
use std::{cell::RefCell, time::Duration};

#[derive(Debug)]
struct ScriptedConnector {
    response: Vec<u8>,
    commands: RefCell<Vec<Vec<u8>>>,
}

impl Connector for ScriptedConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Test"
    }
    fn product(&self) -> &str {
        "SCP11"
    }
    fn serial(&self) -> &str {
        "1"
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        72
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
        receive_buffer[..self.response.len()].copy_from_slice(&self.response);
        Ok(&receive_buffer[..self.response.len()])
    }
}

fn private_key(scalar: u32) -> EcKey<Private> {
    let group = p256_group().unwrap();
    let scalar = BigNum::from_u32(scalar).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut public = EcPoint::new(&group).unwrap();
    public
        .mul_generator2(&group, &scalar, &mut context)
        .unwrap();
    EcKey::from_private_components(&group, &scalar, &public).unwrap()
}

#[test]
fn encodes_scp11b_authentication_parameters() {
    let mut point = vec![0x04];
    point.extend(1u8..=64);
    let data = authentication_data(&point, 0).unwrap();
    assert_eq!(
        &data[..15],
        &[
            0xa6, 0x0d, 0x90, 0x02, 0x11, 0x00, 0x95, 0x01, 0x3c, 0x80, 0x01, 0x88, 0x81, 0x01,
            0x10
        ]
    );
    assert_eq!(&data[15..18], &[0x5f, 0x49, 0x41]);
    assert_eq!(&data[18..], point);
}

#[test]
fn scp11_variants_use_globalplatform_parameters_and_instructions() {
    assert_eq!(Scp11Variant::A.parameter(), 0x01);
    assert_eq!(Scp11Variant::A.key_id(), 0x11);
    assert_eq!(Scp11Variant::A.instruction(), 0x82);
    assert_eq!(Scp11Variant::B.parameter(), 0x00);
    assert_eq!(Scp11Variant::B.key_id(), 0x13);
    assert_eq!(Scp11Variant::B.instruction(), 0x88);
    assert_eq!(Scp11Variant::C.parameter(), 0x03);
    assert_eq!(Scp11Variant::C.key_id(), 0x15);
    assert_eq!(Scp11Variant::C.instruction(), 0x82);
}

#[test]
fn key_derivation_uses_x963_sha256_counter_layout() {
    let agreement: Vec<u8> = (0u8..64).collect();
    assert_eq!(
        derive_key_material(&agreement).unwrap().as_slice(),
        parse_hex(
            "78e6afba798e338b0b6104dfc18e5b9e \
                 faabdf39c991de6879d9c7a0c21ff022 \
                 40998ce38b6d3dd3fd3fa9c7d956b673 \
                 23d069af6457586600431b7ec83d38c7 \
                 183f299ddc90b91643d6d2e137eefcff"
        )
        .unwrap()
    );
}

#[test]
fn authenticates_scp11b_against_fixed_p256_vector() {
    // Independent vector generated with Python cryptography's P-256 ECDH and AES-CMAC.
    let static_public = parse_hex(
        "047cf27b188d034f7e8a52380304b51a \
             c3c08969e277f21b35a60b48fc476699 \
             7807775510db8ed040293d9ac69f7430 \
             dbba7dade63ce982299e04b79d227873d1",
    )
    .unwrap();
    let response = parse_hex(
        "5f4941045ecbe4d1a6330a44c8f7ef951d4bf165 \
             e6c6b721efada985fb41661bc6e7fd6c8734640 \
             c4998ff7e374b06ce1a64a2ecd82ab036384fb83 \
             d9a79b127a27d50328610f0ddff3231c0eae541 \
             9bbcd9536d5a829000",
    )
    .unwrap();
    let connector = ScriptedConnector {
        response: response.clone(),
        commands: RefCell::new(Vec::new()),
    };
    let keys = Scp11KeySet {
        variant: Scp11Variant::B,
        key_version: 1,
        card_public_key: parse_public_point(&static_public).unwrap(),
        host: None,
    };
    let session = keys
        .establish_with_ephemeral(&connector, private_key(1))
        .unwrap();
    assert!(session.require_oce_authentication().is_err());
    assert_eq!(
        connector.commands.borrow().as_slice(),
        &[parse_hex(
            "8088011353a60d9002110095013c8001888101105f \
                 4941046b17d1f2e12c4247f8bce6e563a440f277 \
                 037d812deb33a0f4a13945d898c2964fe342e2fe1 \
                 a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb \
                 6406837bf51f500"
        )
        .unwrap()]
    );

    let receipt_offset = response.len() - 3;
    let mut bad_response = response;
    bad_response[receipt_offset] ^= 1;
    let connector = ScriptedConnector {
        response: bad_response,
        commands: RefCell::new(Vec::new()),
    };
    assert!(matches!(
        keys.establish_with_ephemeral(&connector, private_key(1)),
        Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
    ));
}

#[test]
fn authenticates_scp11a_with_oce_certificate_upload_and_static_ecdh() {
    let static_public = parse_hex(
        "047cf27b188d034f7e8a52380304b51a \
             c3c08969e277f21b35a60b48fc476699 \
             7807775510db8ed040293d9ac69f7430 \
             dbba7dade63ce982299e04b79d227873d1",
    )
    .unwrap();
    let response = parse_hex(
        "5f4941045ecbe4d1a6330a44c8f7ef951d4bf165 \
             e6c6b721efada985fb41661bc6e7fd6c8734640 \
             c4998ff7e374b06ce1a64a2ecd82ab036384fb83 \
             d9a79b127a27d503286105d612b371134aeda05d \
             d9e9b933fa4449000",
    )
    .unwrap();
    let connector = ScriptedConnector {
        response,
        commands: RefCell::new(Vec::new()),
    };
    let keys = Scp11KeySet {
        variant: Scp11Variant::A,
        key_version: 1,
        card_public_key: parse_public_point(&static_public).unwrap(),
        host: Some(Scp11aHostCredentials {
            key_version: 0,
            key_id: 0,
            private_key: private_key(4),
            certificates: vec![vec![0x30, 0x01, 0x00]],
        }),
    };
    let session = keys
        .establish_with_ephemeral(&connector, private_key(1))
        .unwrap();
    session.require_oce_authentication().unwrap();
    assert_eq!(
        connector.commands.borrow().as_slice(),
        &[
            parse_hex("802a000003300100").unwrap(),
            parse_hex(
                "8082011153a60d9002110195013c8001888101105f \
                     4941046b17d1f2e12c4247f8bce6e563a440f277 \
                     037d812deb33a0f4a13945d898c2964fe342e2fe1 \
                     a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb \
                     6406837bf51f500"
            )
            .unwrap(),
        ]
    );
}

#[test]
fn rejects_noncanonical_or_trailing_response_tlvs() {
    let mut point = vec![0x04; 65];
    point[0] = 0x04;
    let valid = [
        encode_tlv(&[0x5f, 0x49], &point).unwrap(),
        encode_tlv(&[0x86], &[0; 16]).unwrap(),
    ]
    .concat();
    assert!(parse_authentication_response(&valid).is_ok());

    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(parse_authentication_response(&trailing).is_err());

    let mut noncanonical = vec![0x5f, 0x49, 0x81, 65];
    noncanonical.extend_from_slice(&point);
    noncanonical.extend_from_slice(&encode_tlv(&[0x86], &[0; 16]).unwrap());
    assert!(parse_authentication_response(&noncanonical).is_err());
}
