use super::*;

fn app_data() -> Vec<u8> {
    vec![
        0x6e, 0x2b, 0x4f, 0x0e, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12,
        0x34, 0x56, 0x78, 0x73, 0x19, 0xc1, 0x06, 0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc2, 0x06,
        0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0xc4, 0x07, 0x01, 0x20, 0x08, 0x03, 0x03, 0x03, 0x03,
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
        p1: KeyRef::Signature.certificate_occurrence(),
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
fn derives_iterated_salted_s2k_user_pin() {
    let kdf = KdfParams {
        hash_algorithm: 0x08,
        iteration_count: 100_000,
        user_salt: b"01234567".to_vec(),
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
    }
}
