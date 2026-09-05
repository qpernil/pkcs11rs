use super::*;
#[cfg(feature = "mock-yubikey")]
#[path = "virtual_admin_tests.rs"]
mod virtual_administration;
use p256::ecdsa::SigningKey;
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

fn private_key(scalar: u32) -> SoftwareSigningKey {
    let mut encoded = [0; 32];
    encoded[28..].copy_from_slice(&scalar.to_be_bytes());
    SoftwareSigningKey::from_serialized_for_kind(
        KeyKind::Ec(software_key_core::software_signing::EcCurve::P256),
        &encoded,
    )
    .unwrap()
}

fn signing_key(scalar: u32) -> SigningKey {
    let serialized = private_key(scalar).serialized().unwrap();
    SigningKey::from(p256::SecretKey::from_slice(&serialized).unwrap())
}

fn certificate_chain(leaf_signer: &SigningKey) -> Vec<Vec<u8>> {
    let ca_key = signing_key(4);
    let ca_name = "CN=pkcs11rs SCP11 test CA";
    let ca = crate::certificate_builder::p256_certificate(
        ca_key.verifying_key(),
        &ca_key,
        ca_name,
        ca_name,
        1,
        true,
    );
    let leaf_key = signing_key(5);
    let leaf = crate::certificate_builder::p256_certificate(
        leaf_key.verifying_key(),
        leaf_signer,
        "CN=pkcs11rs SCP11B card",
        ca_name,
        2,
        false,
    );
    vec![ca, leaf]
}

#[test]
fn scp11b_card_key_requires_a_valid_certificate_chain() {
    let certificates = certificate_chain(&signing_key(4));
    assert!(
        Scp11KeySet::scp11b_from_certificates(1, &certificates[1..], &certificates[..1]).is_ok()
    );

    let invalid = certificate_chain(&signing_key(6));
    assert!(Scp11KeySet::scp11b_from_certificates(1, &invalid[1..], &invalid[..1]).is_err());
}

#[test]
fn embedded_yubico_attestation_root_is_self_signed() {
    crate::certificate_chain::verify_signed_by(YUBICO_ATTESTATION_ROOT, YUBICO_ATTESTATION_ROOT)
        .unwrap();
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
        card_public_key: Some(parse_public_point(&static_public).unwrap()),
        certificate_trust: None,
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
        Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
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
        card_public_key: Some(parse_public_point(&static_public).unwrap()),
        certificate_trust: None,
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

#[cfg(feature = "mock-yubikey")]
mod virtual_card {
    use super::*;
    use crate::{mock_yubikey::MockYubiKeyConnector, select_application};
    use virtual_yubikey_core::{
        DeviceProfile, FIDO2_AID, HSMAUTH_AID, ISSUER_SECURITY_DOMAIN_AID, MANAGEMENT_AID,
        OPENPGP_AID, PIV_AID, VirtualYubiKey,
    };

    fn fixture(variant: Scp11Variant) -> (MockYubiKeyConnector, Scp11KeySet) {
        let mut profile = DeviceProfile::yubikey_5_8_ccid(42);
        profile.applets.openpgp = true;
        let mut device = VirtualYubiKey::new(profile.clone());
        // The fixture's leaf key is scalar 5, issued by CA scalar 4.
        let chain = certificate_chain(&signing_key(4));
        let card = private_key(8);
        device
            .provision_scp11(
                variant.key_id(),
                1,
                &card.serialized().unwrap(),
                0x10,
                1,
                &chain[..1],
            )
            .unwrap();
        assert!(device.take_security_domain_persistent_change());
        assert!(!device.take_security_domain_persistent_change());
        let sd = device.security_domain_persistent_state().unwrap();
        let device = VirtualYubiKey::from_persistent_states(
            profile,
            &device.piv_persistent_state().unwrap(),
            &device.hsmauth_persistent_state().unwrap(),
            &sd,
        )
        .unwrap();
        let keys = Scp11KeySet {
            variant,
            key_version: 1,
            card_public_key: Some(encode_private_public_point(&card).unwrap()),
            certificate_trust: None,
            host: Some(Scp11aHostCredentials {
                key_version: 1,
                key_id: 0x10,
                private_key: private_key(5),
                certificates: chain.into_iter().rev().collect(),
            }),
        };
        (MockYubiKeyConnector::from_device(device), keys)
    }

    fn command(ins: u8, p2: u8, data: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0,
            ins,
            p1: 0,
            p2,
            data: data.to_vec(),
            le: Some(256),
            extended: false,
        }
    }

    fn authenticate_command(keys: &Scp11KeySet) -> CommandApdu {
        CommandApdu {
            cla: 0x80,
            ins: keys.variant.instruction(),
            p1: keys.key_version,
            p2: keys.variant.key_id(),
            data: authentication_data(
                &encode_private_public_point(&private_key(7)).unwrap(),
                keys.variant.parameter(),
            )
            .unwrap(),
            le: Some(256),
            extended: false,
        }
    }

    #[test]
    fn scp11a_and_c_protect_every_ccid_applet_after_persistence_roundtrip() {
        let cases: &[(&[u8], u8, u8, &[u8])] = &[
            (&MANAGEMENT_AID, 0x1d, 0, &[]),
            (&HSMAUTH_AID, 0x07, 0, &[]),
            (&OPENPGP_AID, 0x84, 0, &[]),
            (&PIV_AID, 0xfd, 0, &[]),
            (&FIDO2_AID, 0x10, 0, &[0x04]),
            (&ISSUER_SECURITY_DOMAIN_AID, 0xca, 0xe0, &[]),
        ];
        for variant in [Scp11Variant::A, Scp11Variant::C] {
            let (connector, mut keys) = fixture(variant);
            // Both explicit and automatic host CA selection are supported.
            for automatic in [false, true] {
                if automatic {
                    let host = keys.host.as_mut().unwrap();
                    host.key_id = 0;
                    host.key_version = 0;
                }
                for &(aid, ins, p2, data) in cases {
                    select_application(&connector, aid).unwrap();
                    // Mock transport is SHORT_ONLY, so certificates use ISO chaining.
                    let mut session = keys.authenticate_selected(&connector).unwrap();
                    session.require_oce_authentication().unwrap();
                    let response = session
                        .transmit(&connector, &command(ins, p2, data))
                        .unwrap();
                    assert!(!response.data.is_empty(), "{variant:?} {aid:x?}");
                }
            }
        }
    }

    #[test]
    fn scp11a_and_c_reject_untrusted_hosts_wrong_private_keys_and_ca_selectors() {
        for variant in [Scp11Variant::A, Scp11Variant::C] {
            for failure in 0..4 {
                let (connector, mut keys) = fixture(variant);
                select_application(&connector, &PIV_AID).unwrap();
                let host = keys.host.as_mut().unwrap();
                match failure {
                    0 => host.private_key = private_key(6),
                    1 => {
                        host.certificates = certificate_chain(&signing_key(6))
                            .into_iter()
                            .rev()
                            .collect()
                    }
                    2 => host.key_id = 0x20,
                    3 => {
                        // A self-signed certificate delivered by the host is not a trust anchor.
                        let key = signing_key(6);
                        host.certificates = vec![crate::certificate_builder::p256_certificate(
                            key.verifying_key(),
                            &key,
                            "CN=Untrusted",
                            "CN=Untrusted",
                            9,
                            true,
                        )];
                    }
                    _ => unreachable!(),
                }
                assert!(
                    keys.authenticate_selected(&connector).is_err(),
                    "{variant:?} case {failure}"
                );
                // No host authentication attempt permits an unauthenticated protected APDU.
                let mut invalid = command(0xfd, 0, &[0; 8]);
                invalid.cla = 4;
                assert!(
                    connector
                        .send_apdu(&invalid)
                        .unwrap()
                        .require_success(&invalid)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn scp11a_and_c_consume_uploads_and_select_clears_credentials_and_sessions() {
        for variant in [Scp11Variant::A, Scp11Variant::C] {
            let (connector, keys) = fixture(variant);
            select_application(&connector, &PIV_AID).unwrap();
            let auth = authenticate_command(&keys);
            assert!(
                connector
                    .send_apdu(&auth)
                    .unwrap()
                    .require_success(&auth)
                    .is_err()
            );
            keys.upload_host_certificates(&connector).unwrap();
            select_application(&connector, &PIV_AID).unwrap();
            assert!(
                connector
                    .send_apdu(&auth)
                    .unwrap()
                    .require_success(&auth)
                    .is_err()
            );
            keys.upload_host_certificates(&connector).unwrap();
            let mut wrong_variant = auth.clone();
            wrong_variant.data[5] = 0; // SCP11b parameters cannot be used with an A/C key.
            assert!(
                connector
                    .send_apdu(&wrong_variant)
                    .unwrap()
                    .require_success(&wrong_variant)
                    .is_err()
            );
            assert!(
                connector
                    .send_apdu(&auth)
                    .unwrap()
                    .require_success(&auth)
                    .is_err()
            );
            let mut session = keys.authenticate_selected(&connector).unwrap();
            select_application(&connector, &PIV_AID).unwrap();
            let version = command(0xfd, 0, &[]);
            assert!(
                session
                    .transmit(&connector, &version)
                    .unwrap()
                    .require_success(&version)
                    .is_err()
            );
            // Recovery requires a fresh upload and handshake.
            let mut session = keys.authenticate_selected(&connector).unwrap();
            assert_eq!(
                session
                    .transmit(&connector, &command(0xfd, 0, &[]))
                    .unwrap()
                    .data,
                [5, 8, 0]
            );
        }
    }

    #[test]
    fn scp11a_and_c_reject_incomplete_malformed_and_mismatched_uploads() {
        for variant in [Scp11Variant::A, Scp11Variant::C] {
            let (connector, keys) = fixture(variant);
            select_application(&connector, &PIV_AID).unwrap();
            let root = keys.host.as_ref().unwrap().certificates.last().unwrap();
            let upload = CommandApdu {
                cla: 0x80,
                ins: 0x2a,
                p1: 1,
                p2: 0x90,
                data: root.clone(),
                le: None,
                extended: true,
            };
            connector
                .send_apdu(&upload)
                .unwrap()
                .require_success(&upload)
                .unwrap();
            let auth = authenticate_command(&keys);
            assert!(
                connector
                    .send_apdu(&auth)
                    .unwrap()
                    .require_success(&auth)
                    .is_err()
            );
            connector
                .send_apdu(&upload)
                .unwrap()
                .require_success(&upload)
                .unwrap();
            let mut final_upload = upload.clone();
            final_upload.p2 = 0x20;
            final_upload.data = keys.host.as_ref().unwrap().certificates[0].clone();
            assert!(
                connector
                    .send_apdu(&final_upload)
                    .unwrap()
                    .require_success(&final_upload)
                    .is_err()
            );
            keys.upload_host_certificates(&connector).unwrap();
            final_upload.p2 = 0x10;
            final_upload.data = vec![0x30, 0];
            assert!(
                connector
                    .send_apdu(&final_upload)
                    .unwrap()
                    .require_success(&final_upload)
                    .is_err()
            );
            assert!(
                connector
                    .send_apdu(&auth)
                    .unwrap()
                    .require_success(&auth)
                    .is_err()
            );
        }
    }

    #[test]
    fn scp11a_and_c_accept_leaf_only_upload_with_configured_issuer() {
        for variant in [Scp11Variant::A, Scp11Variant::C] {
            let (connector, mut keys) = fixture(variant);
            keys.host.as_mut().unwrap().certificates.truncate(1);
            select_application(&connector, &PIV_AID).unwrap();
            let mut session = keys.authenticate_selected(&connector).unwrap();
            assert_eq!(
                session
                    .transmit(&connector, &command(0xfd, 0, &[]))
                    .unwrap()
                    .data,
                [5, 8, 0]
            );
        }
    }
}
