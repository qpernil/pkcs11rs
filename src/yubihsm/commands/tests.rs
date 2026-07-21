use super::*;
use std::collections::BTreeSet;

fn object(label: &str) -> ObjectParameters<'_> {
    ObjectParameters {
        id: 0x1234,
        label,
        domains: 0x5678,
        capabilities: [0x11; 8],
        algorithm: 0x22,
    }
}

fn object_with_algorithm(label: &str, algorithm: u8) -> ObjectParameters<'_> {
    ObjectParameters {
        algorithm,
        ..object(label)
    }
}

fn delegated(label: &str) -> DelegatedObjectParameters<'_> {
    DelegatedObjectParameters {
        object: object(label),
        delegated_capabilities: [0x33; 8],
    }
}

fn all_sample_commands() -> Vec<Command> {
    let aead = [0x44; 36];
    let otp = [0x55; 16];
    let private_id = [0x66; 6];
    let iv = [0x77; 16];
    let mut commands = vec![
        Command::echo(b"echo").unwrap(),
        Command::raw(CommandCode::CreateSession, b"session").unwrap(),
        Command::raw(CommandCode::AuthenticateSession, b"auth").unwrap(),
        Command::raw(CommandCode::SessionMessage, b"message").unwrap(),
        Command::get_device_info(None),
        Command::reset_device(),
        Command::get_device_public_key(),
        Command::close_session(),
        Command::get_storage_info(),
        Command::put_object(CommandCode::PutOpaque, &object("opaque"), b"value").unwrap(),
        Command::get_object(CommandCode::GetOpaque, 1).unwrap(),
        Command::put_delegated_object(
            CommandCode::PutAuthenticationKey,
            &delegated("auth"),
            &[0; 32],
        )
        .unwrap(),
        Command::put_object(
            CommandCode::PutAsymmetricKey,
            &object("asymmetric"),
            &[0; 32],
        )
        .unwrap(),
        Command::generate_object(CommandCode::GenerateAsymmetricKey, &object("asym-gen")).unwrap(),
        Command::key_data(CommandCode::SignPkcs1, 1, b"digest").unwrap(),
        Command::list_objects(&[
            ObjectFilter::Id(1),
            ObjectFilter::Type(2),
            ObjectFilter::Domains(3),
            ObjectFilter::Capabilities([4; 8]),
            ObjectFilter::Algorithm(5),
            ObjectFilter::Label(b"label"),
        ])
        .unwrap(),
        Command::key_data(CommandCode::DecryptPkcs1, 1, b"ciphertext").unwrap(),
        Command::export_wrapped(1, 2, 3, None),
        Command::import_wrapped(1, b"wrapped").unwrap(),
        Command::put_delegated_object(CommandCode::PutWrapKey, &delegated("wrap"), &[0; 16])
            .unwrap(),
        Command::get_log_entries(),
        Command::get_object_info(1, 2),
        Command::set_option(1, &[2]).unwrap(),
        Command::get_option(1),
        Command::get_pseudo_random(32),
        Command::put_object(CommandCode::PutHmacKey, &object("hmac"), &[0; 32]).unwrap(),
        Command::key_data(CommandCode::SignHmac, 1, b"data").unwrap(),
        Command::get_public_key(1, None),
        Command::sign_pss(1, 32, 32, &[0; 32]).unwrap(),
        Command::key_data(CommandCode::SignEcdsa, 1, &[0; 32]).unwrap(),
        Command::key_data(CommandCode::DeriveEcdh, 1, &[0; 65]).unwrap(),
        Command::delete_object(1, 2),
        Command::decrypt_oaep(1, 32, &[0; 256], &[0; 32]).unwrap(),
        Command::generate_object(CommandCode::GenerateHmacKey, &object("hmac-gen")).unwrap(),
        Command::generate_wrap_key(&delegated("wrap-gen")).unwrap(),
        Command::verify_hmac(1, &[0; 32], b"data").unwrap(),
        Command::sign_ssh_certificate(1, 2, 3, b"request").unwrap(),
        Command::put_object(CommandCode::PutTemplate, &object("template"), b"template").unwrap(),
        Command::get_object(CommandCode::GetTemplate, 1).unwrap(),
        Command::decrypt_otp(1, &aead, &otp),
        Command::create_otp_aead(1, &otp, &private_id),
        Command::randomize_otp_aead(1),
        Command::rewrap_otp_aead(1, 2, &aead),
        Command::sign_attestation_certificate(1, 2),
        Command::otp_aead_key(
            CommandCode::PutOtpAeadKey,
            &object_with_algorithm("otp", ALGORITHM_AES128_YUBICO_OTP),
            4,
            &[0; 16],
        )
        .unwrap(),
        Command::otp_aead_key(
            CommandCode::GenerateOtpAeadKey,
            &object_with_algorithm("otp-gen", ALGORITHM_AES128_YUBICO_OTP),
            4,
            &[],
        )
        .unwrap(),
        Command::set_log_index(1),
        Command::key_data(CommandCode::WrapData, 1, b"data").unwrap(),
        Command::key_data(CommandCode::UnwrapData, 1, b"wrapped").unwrap(),
        Command::key_data(CommandCode::SignEddsa, 1, b"data").unwrap(),
        Command::blink_device(10),
        Command::change_authentication_key(1, 38, &[0; 32]).unwrap(),
        Command::put_object(CommandCode::PutSymmetricKey, &object("symmetric"), &[0; 16]).unwrap(),
        Command::generate_object(CommandCode::GenerateSymmetricKey, &object("symmetric-gen"))
            .unwrap(),
        Command::key_data(CommandCode::DecryptEcb, 1, &[0; 16]).unwrap(),
        Command::key_data(CommandCode::EncryptEcb, 1, &[0; 16]).unwrap(),
        Command::crypt_cbc(CommandCode::DecryptCbc, 1, &iv, &[0; 16]).unwrap(),
        Command::crypt_cbc(CommandCode::EncryptCbc, 1, &iv, &[0; 16]).unwrap(),
        Command::put_delegated_object(
            CommandCode::PutPublicWrapKey,
            &delegated("public-wrap"),
            &[0; 256],
        )
        .unwrap(),
        Command::rsa_wrap(
            CommandCode::GetRsaWrappedKey,
            &RsaWrapParameters {
                wrapping_key_id: 1,
                object_type: 3,
                object_id: 2,
                aes_algorithm: 50,
                hash_algorithm: 26,
                mgf1_algorithm: 33,
                label_digest: &[0; 32],
            },
        )
        .unwrap(),
        Command::put_rsa_wrapped_key(1, 3, &object("rsa-wrapped"), 26, 33, b"key", &[0; 32])
            .unwrap(),
        Command::rsa_wrap(
            CommandCode::ExportRsaWrapped,
            &RsaWrapParameters {
                wrapping_key_id: 1,
                object_type: 3,
                object_id: 2,
                aes_algorithm: 50,
                hash_algorithm: 26,
                mgf1_algorithm: 33,
                label_digest: &[0; 32],
            },
        )
        .unwrap(),
        Command::import_rsa_wrapped(1, 26, 33, b"object", &[0; 32]).unwrap(),
    ];
    commands.sort_by_key(|command| command.code() as u8);
    commands
}

#[test]
fn every_official_command_code_has_a_sample_request() {
    let commands = all_sample_commands();
    assert_eq!(commands.len(), 63);
    assert_eq!(commands.len(), ALL_COMMAND_CODES.len());
    assert_eq!(
        commands
            .iter()
            .map(|command| command.code() as u8)
            .collect::<BTreeSet<_>>(),
        ALL_COMMAND_CODES
            .iter()
            .map(|command| *command as u8)
            .collect()
    );
    assert_eq!(
        ALL_COMMAND_CODES
            .iter()
            .filter(|command| (**command as u8) >= 0x40)
            .map(|command| *command as u8)
            .collect::<Vec<_>>(),
        (0x40..=0x77).collect::<Vec<_>>()
    );
}

#[test]
fn object_parameters_match_the_documented_wire_layout() {
    let encoded = object("abc").encode().unwrap();
    assert_eq!(encoded.len(), 53);
    assert_eq!(&encoded[0..2], &[0x12, 0x34]);
    assert_eq!(&encoded[2..5], b"abc");
    assert!(encoded[5..42].iter().all(|byte| *byte == 0));
    assert_eq!(&encoded[42..44], &[0x56, 0x78]);
    assert_eq!(&encoded[44..52], &[0x11; 8]);
    assert_eq!(encoded[52], 0x22);
    assert!(object(&"x".repeat(41)).encode().is_err());
}

#[test]
fn optional_fields_use_the_canonical_wire_layout() {
    for object_type in [None, Some(0x03), Some(0x83)] {
        assert_eq!(
            Command::get_public_key(0x1234, object_type).data(),
            [0x12, 0x34]
        );
    }
    assert_eq!(
        Command::get_public_key(0x1234, Some(0x04)).data(),
        [0x12, 0x34, 0x04]
    );

    for format in [None, Some(0)] {
        assert_eq!(
            Command::export_wrapped(0x1234, 3, 0x5678, format).data(),
            [0x12, 0x34, 3, 0x56, 0x78]
        );
    }
    assert_eq!(
        Command::export_wrapped(0x1234, 3, 0x5678, Some(1)).data(),
        [0x12, 0x34, 3, 0x56, 0x78, 1]
    );
}

#[test]
fn crypto_commands_match_wire_vectors() {
    assert_eq!(
        Command::key_data(CommandCode::SignPkcs1, 0x1234, &[0xaa, 0xbb])
            .unwrap()
            .data(),
        [0x12, 0x34, 0xaa, 0xbb]
    );
    assert_eq!(
        Command::sign_pss(0x1234, 0x21, 32, &[0xaa; 20])
            .unwrap()
            .data(),
        [&[0x12, 0x34, 0x21, 0x00, 0x20][..], &[0xaa; 20]].concat()
    );
    assert_eq!(
        Command::crypt_cbc(CommandCode::EncryptCbc, 0x1234, &[0x11; 16], &[0x22; 16])
            .unwrap()
            .data(),
        [&[0x12, 0x34][..], &[0x11; 16], &[0x22; 16],].concat()
    );
    assert_eq!(
        Command::sign_ssh_certificate(0x1234, 0x5678, 0x09, &[0xaa, 0xbb])
            .unwrap()
            .data(),
        [0x12, 0x34, 0x56, 0x78, 0x09, 0xaa, 0xbb]
    );
}

#[test]
fn crypto_commands_reject_non_block_aligned_input() {
    assert!(Command::key_data(CommandCode::EncryptEcb, 1, &[0; 15]).is_err());
    assert!(Command::crypt_cbc(CommandCode::DecryptCbc, 1, &[0; 16], &[0; 15]).is_err());
}

#[test]
fn set_option_command_matches_wire_vector() {
    assert_eq!(
        Command::set_option(3, &[0x47, 1, 0x48, 0]).unwrap().data(),
        [3, 0, 4, 0x47, 1, 0x48, 0]
    );
}

#[test]
fn otp_aead_key_commands_use_little_endian_nonce_and_validate_key_lengths() {
    let otp = Command::otp_aead_key(
        CommandCode::PutOtpAeadKey,
        &object_with_algorithm("otp", ALGORITHM_AES128_YUBICO_OTP),
        0x0102_0304,
        &[0x55; 16],
    )
    .unwrap();
    assert_eq!(&otp.data()[53..57], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&otp.data()[57..], &[0x55; 16]);

    for (algorithm, key_length) in [
        (ALGORITHM_AES128_YUBICO_OTP, 16),
        (ALGORITHM_AES192_YUBICO_OTP, 24),
        (ALGORITHM_AES256_YUBICO_OTP, 32),
    ] {
        let parameters = object_with_algorithm("otp", algorithm);
        assert!(Command::otp_aead_key(
            CommandCode::PutOtpAeadKey,
            &parameters,
            0,
            &vec![0; key_length],
        )
        .is_ok());
        assert!(Command::otp_aead_key(
            CommandCode::PutOtpAeadKey,
            &parameters,
            0,
            &vec![0; key_length + 1],
        )
        .is_err());
    }
    assert!(Command::otp_aead_key(
        CommandCode::GenerateOtpAeadKey,
        &object_with_algorithm("otp", 0xff),
        0,
        &[],
    )
    .is_err());
}

#[test]
fn change_authentication_key_validates_algorithm_and_key_length() {
    assert!(Command::change_authentication_key(
        1,
        ALGORITHM_AES128_YUBICO_AUTHENTICATION,
        &[0; 64],
    )
    .is_err());
    assert!(Command::change_authentication_key(
        1,
        ALGORITHM_EC_P256_YUBICO_AUTHENTICATION,
        &[0; 64],
    )
    .is_ok());
    assert!(Command::change_authentication_key(1, 0xff, &[0; 32]).is_err());
}

#[test]
fn rsa_wrap_commands_match_wire_vectors_and_validate_digest_lengths() {
    let rsa = Command::rsa_wrap(
        CommandCode::ExportRsaWrapped,
        &RsaWrapParameters {
            wrapping_key_id: 0x1234,
            object_type: 3,
            object_id: 0x5678,
            aes_algorithm: 50,
            hash_algorithm: 26,
            mgf1_algorithm: 33,
            label_digest: &[0xaa; 20],
        },
    )
    .unwrap();
    assert_eq!(
        rsa.data(),
        [&[0x12, 0x34, 3, 0x56, 0x78, 50, 26, 33][..], &[0xaa; 20],].concat()
    );
    assert!(Command::rsa_wrap(
        CommandCode::ExportRsaWrapped,
        &RsaWrapParameters {
            wrapping_key_id: 1,
            object_type: 3,
            object_id: 2,
            aes_algorithm: 50,
            hash_algorithm: 26,
            mgf1_algorithm: 33,
            label_digest: &[0; 31],
        },
    )
    .is_err());
}

#[test]
fn list_filters_and_delegated_objects_match_wire_vectors() {
    let filters = Command::list_objects(&[
        ObjectFilter::Id(0x1234),
        ObjectFilter::Type(3),
        ObjectFilter::Domains(0x5678),
        ObjectFilter::Algorithm(12),
        ObjectFilter::Capabilities([0xaa; 8]),
    ])
    .unwrap();
    assert_eq!(
        filters.data(),
        [
            1, 0x12, 0x34, 2, 3, 3, 0x56, 0x78, 5, 12, 4, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa,
        ]
    );

    let encoded = delegated("key").encode().unwrap();
    assert_eq!(encoded.len(), 61);
    assert_eq!(&encoded[..53], object("key").encode().unwrap());
    assert_eq!(&encoded[53..], &[0x33; 8]);
}

#[test]
fn command_data_is_bounded_and_debug_output_is_redacted() {
    assert!(Command::raw(CommandCode::Echo, &[0; MAX_COMMAND_DATA_LENGTH]).is_ok());
    assert!(Command::raw(CommandCode::Echo, &[0; MAX_COMMAND_DATA_LENGTH + 1]).is_err());
    let command = Command::raw(CommandCode::PutSymmetricKey, b"secret-key-material").unwrap();
    let debug = format!("{command:?}");
    assert!(debug.contains("data_length"));
    assert!(!debug.contains("secret-key-material"));
}

#[test]
fn structured_response_parsers_reject_malformed_responses() {
    assert!(StorageInfo::parse(&[0; 9]).is_err());
    assert!(parse_object_list(&[0; 3]).is_err());
    assert!(parse_object_list(&vec![0; (MAX_OBJECT_COUNT + 1) * 4]).is_err());
    assert!(LogEntries::parse(&[0, 0, 0, 0, 1]).is_err());
    let mut excess_logs = vec![0; 5 + (MAX_LOG_ENTRY_COUNT + 1) * 32];
    excess_logs[4] = (MAX_LOG_ENTRY_COUNT + 1) as u8;
    assert!(LogEntries::parse(&excess_logs).is_err());
    assert!(require_empty(&[1]).is_err());
}

#[test]
fn structured_response_parsers_decode_success_vectors() {
    assert_eq!(
        StorageInfo::parse(&[0, 1, 0, 2, 0, 3, 0, 4, 0, 5]).unwrap(),
        StorageInfo {
            total_records: 1,
            free_records: 2,
            total_pages: 3,
            free_pages: 4,
            page_size: 5,
        }
    );
    assert_eq!(parse_object_id(&[0x12, 0x34]).unwrap(), 0x1234);

    let mut object = vec![0x11; 8];
    object.extend_from_slice(&[0x12, 0x34, 0x00, 0x20, 0x56, 0x78, 3, 12, 4, 2]);
    object.extend_from_slice(&[0x41; 40]);
    object.extend_from_slice(&[0x22; 8]);
    let parsed = ObjectInfo::parse(&object).unwrap();
    assert_eq!(parsed.id, 0x1234);
    assert_eq!(parsed.length, 32);
    assert_eq!(parsed.domains, 0x5678);
    assert_eq!(parsed.label, "A".repeat(40));

    assert_eq!(
        parse_object_list(&[0x12, 0x34, 3, 4, 0x56, 0x78, 5, 6]).unwrap(),
        [
            ObjectEntry {
                id: 0x1234,
                object_type: 3,
                sequence: 4,
            },
            ObjectEntry {
                id: 0x5678,
                object_type: 5,
                sequence: 6,
            },
        ]
    );
    assert_eq!(
        ImportedObject::parse(&[3, 0x12, 0x34]).unwrap(),
        ImportedObject {
            object_type: 3,
            id: 0x1234,
        }
    );
    assert_eq!(
        PublicKey::parse(&[12, 1, 2, 3]).unwrap(),
        PublicKey {
            algorithm: 12,
            key: vec![1, 2, 3],
        }
    );
    assert_eq!(
        OtpDecryption::parse(&[0x34, 0x12, 5, 6, 0x78, 0x56]).unwrap(),
        OtpDecryption {
            use_counter: 0x1234,
            session_counter: 5,
            timestamp_high: 6,
            timestamp_low: 0x5678,
        }
    );

    let mut logs = vec![0, 1, 0, 2, 1, 0, 3, 0x47, 0, 4, 0, 5, 0, 6, 0, 7, 0x00];
    logs.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    logs.extend_from_slice(&[0xaa; 16]);
    let logs = LogEntries::parse(&logs).unwrap();
    assert_eq!(logs.unlogged_boot, 1);
    assert_eq!(logs.unlogged_authentication, 2);
    assert_eq!(logs.entries[0].number, 3);
    assert_eq!(logs.entries[0].command, 0x47);
    assert_eq!(logs.entries[0].systick, 0x0102_0304);
}
