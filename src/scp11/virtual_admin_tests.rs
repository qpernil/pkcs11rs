use super::*;
use crate::security_domain::{KeyRef, Scp11Administration as Op};
use crate::{SecurityDomainClient, mock_yubikey::MockYubiKeyConnector, select_application};
use spki::EncodePublicKey;
use virtual_yubikey_core::{
    DeviceProfile, ISSUER_SECURITY_DOMAIN_AID as SD, PIV_AID, VirtualYubiKey,
};

fn factory_session(connector: &MockYubiKeyConnector) -> Scp03Session {
    select_application(connector, &SD).unwrap();
    Scp03Session::authenticate_selected(
        connector,
        &crate::Scp03KeySet::yubikey_factory(),
        0x33,
        &SD,
    )
    .unwrap()
}

fn administer(
    connector: &MockYubiKeyConnector,
    session: &mut Scp03Session,
    operation: Op,
) -> Result<Vec<u8>, Error> {
    let prepared = SecurityDomainClient.prepare_scp11_administration(session, &operation)?;
    SecurityDomainClient.execute_scp11_administration(connector, session, prepared)
}

fn version_command() -> CommandApdu {
    CommandApdu {
        cla: 0,
        ins: 0xfd,
        p1: 0,
        p2: 0,
        data: vec![],
        le: Some(256),
        extended: false,
    }
}

#[test]
fn commands_provision_scp11a_and_c_with_discovery_and_persistent_policy() {
    for variant in [Scp11Variant::A, Scp11Variant::C] {
        let profile = DeviceProfile::yubikey_5_8_ccid(42);
        let connector = MockYubiKeyConnector::from_device(VirtualYubiKey::new(profile.clone()));
        let mut session = factory_session(&connector);
        let key_ref = KeyRef {
            kid: variant.key_id(),
            kvn: 2,
        };
        let public = administer(
            &connector,
            &mut session,
            Op::GenerateKey {
                key_ref,
                replace_kvn: 0,
                curve: 0,
            },
        )
        .unwrap();
        let ca_ref = KeyRef { kid: 0x10, kvn: 1 };
        administer(
            &connector,
            &mut session,
            Op::PutPublicKey {
                key_ref: ca_ref,
                replace_kvn: 0,
                encoded: signing_key(4)
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        )
        .unwrap();
        administer(
            &connector,
            &mut session,
            Op::StoreCaIssuer {
                key_ref: ca_ref,
                subject_key_identifier: vec![0x55; 20],
            },
        )
        .unwrap();
        let card_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).unwrap();
        let ca = signing_key(4);
        let root = certificate_chain(&ca)[0].clone();
        let leaf = crate::certificate_builder::p256_certificate(
            &card_key,
            &ca,
            "CN=Card",
            "CN=pkcs11rs SCP11 test CA",
            20,
            false,
        );
        // STORE DATA crosses the short-APDU boundary under encryption.
        administer(
            &connector,
            &mut session,
            Op::StoreCertificateChain {
                key_ref,
                certificates: vec![root.clone(), leaf.clone()],
            },
        )
        .unwrap();
        administer(
            &connector,
            &mut session,
            Op::SetAllowlist {
                key_ref,
                serials: vec![vec![2]],
            },
        )
        .unwrap();
        let keys = Scp11KeySet {
            variant,
            key_version: 2,
            card_public_key: None,
            certificate_trust: Some(
                crate::certificate_chain::CertificateTrust::new(&[root]).unwrap(),
            ),
            host: Some(Scp11aHostCredentials {
                key_id: 0x10,
                key_version: 1,
                private_key: private_key(5),
                certificates: certificate_chain(&ca).into_iter().rev().collect(),
            }),
        };
        connector.restore_persistent_state(profile);
        select_application(&connector, &SD).unwrap();
        assert_eq!(
            SecurityDomainClient
                .get_certificate_bundle(&connector, key_ref)
                .unwrap()
                .last(),
            Some(&leaf)
        );
        assert!(
            SecurityDomainClient
                .get_supported_ca_identifiers(&connector)
                .unwrap()
                .iter()
                .any(|entry| entry.key_ref == ca_ref
                    && entry.subject_key_identifier == vec![0x55; 20])
        );
        let (mut channel, _) = keys
            .authenticate_application(&connector, &SD, &SD, None)
            .unwrap();
        // SCP11 itself can administer policy after host key confirmation.
        administer(
            &connector,
            &mut channel,
            Op::SetAllowlist {
                key_ref,
                serials: vec![vec![3]],
            },
        )
        .unwrap();
        select_application(&connector, &SD).unwrap();
        assert!(
            keys.authenticate_application(&connector, &SD, &SD, None)
                .is_err()
        );
        let mut session = factory_session(&connector);
        administer(
            &connector,
            &mut session,
            Op::SetAllowlist {
                key_ref,
                serials: vec![],
            },
        )
        .unwrap();
        select_application(&connector, &SD).unwrap();
        let (mut channel, _) = keys
            .authenticate_application(&connector, &SD, &SD, None)
            .unwrap();
        // SCP11's fifth derived key is the DEK for private-key imports.
        let imported_ref = KeyRef { kid: 0x13, kvn: 3 };
        administer(
            &connector,
            &mut channel,
            Op::PutPrivateKey {
                key_ref: imported_ref,
                replace_kvn: 0,
                encoded: private_key(9).to_pkcs8_der().unwrap(),
            },
        )
        .unwrap();
        let imported = Scp11KeySet {
            variant: Scp11Variant::B,
            key_version: 3,
            card_public_key: Some(encode_private_public_point(&private_key(9)).unwrap()),
            certificate_trust: None,
            host: None,
        };
        select_application(&connector, &PIV_AID).unwrap();
        let mut channel = imported.authenticate_selected(&connector).unwrap();
        assert_eq!(
            channel
                .transmit(&connector, &version_command())
                .unwrap()
                .data,
            [5, 8, 0]
        );
        let mut session = factory_session(&connector);
        administer(
            &connector,
            &mut session,
            Op::DeleteKey {
                key_ref: imported_ref,
                delete_last: false,
            },
        )
        .unwrap();
        select_application(&connector, &PIV_AID).unwrap();
        assert!(imported.authenticate_selected(&connector).is_err());
    }
}

#[test]
fn administration_rejects_plain_and_scp11b_commands() {
    let connector = MockYubiKeyConnector::new().unwrap();
    select_application(&connector, &SD).unwrap();
    let chain = SecurityDomainClient
        .get_certificate_bundle(&connector, KeyRef { kid: 0x13, kvn: 1 })
        .unwrap();
    let keys = Scp11KeySet::scp11b_from_certificates(1, &chain[1..], &chain[..1]).unwrap();
    let mut session = keys.authenticate_selected(&connector).unwrap();
    for (cla, ins, p1, p2, data) in [
        (0x80, 0xf1, 0, 0x11, vec![2, 0xf0, 1, 0]),
        (0x80, 0xd8, 0, 0x10, vec![1]),
        (0, 0xe2, 0x90, 0, vec![]),
        (0x80, 0xe4, 0, 1, vec![0xd2, 1, 1]),
    ] {
        let command = CommandApdu {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
            extended: false,
        };
        assert_eq!(connector.send_apdu(&command).unwrap().status, 0x6982);
        assert_eq!(
            session.transmit(&connector, &command).unwrap().status,
            0x6982
        );
    }
    assert_eq!(
        SecurityDomainClient
            .get_key_information(&connector)
            .unwrap()
            .len(),
        4
    );
    let _session = factory_session(&connector);
    let command = CommandApdu {
        cla: 0x80,
        ins: 0xf1,
        p1: 0,
        p2: 0x11,
        data: vec![2, 0xf0, 1, 0],
        le: None,
        extended: false,
    };
    assert_eq!(connector.send_apdu(&command).unwrap().status, 0x6982);
}

#[test]
fn scp03_rotation_removes_factory_keys_and_validates_kcv_atomically() {
    use crate::configuration::{Scp03Configuration, Scp03KeyMaterialConfiguration};
    use crate::security_domain::Scp03ProvisioningKeys;
    let profile = DeviceProfile::yubikey_5_8_ccid(42);
    let connector = MockYubiKeyConnector::from_device(VirtualYubiKey::new(profile.clone()));
    let mut session = factory_session(&connector);
    let material = Scp03ProvisioningKeys {
        enc: &[0x11; 16],
        mac: &[0x22; 16],
        dek: &[0x33; 16],
    };
    SecurityDomainClient
        .put_scp03_key_set(&connector, &mut session, 2, 0, &material)
        .unwrap();
    connector.restore_persistent_state(profile);
    select_application(&connector, &SD).unwrap();
    assert!(
        Scp03Session::authenticate_selected(
            &connector,
            &crate::Scp03KeySet::yubikey_factory(),
            0x33,
            &SD
        )
        .is_err()
    );
    let keys = crate::Scp03KeySet::from_configuration(&Scp03Configuration {
        key_version: 2,
        key_id: 0,
        security_level: 0x33,
        key_material: Scp03KeyMaterialConfiguration::Direct {
            enc: Zeroizing::new(material.enc.to_vec()),
            mac: Zeroizing::new(material.mac.to_vec()),
            dek: Some(Zeroizing::new(material.dek.to_vec())),
        },
    })
    .unwrap();
    let mut session = Scp03Session::authenticate_selected(&connector, &keys, 0x33, &SD).unwrap();
    let bad = CommandApdu {
        cla: 0x80,
        ins: 0xd8,
        p1: 2,
        p2: 0x81,
        data: [vec![3, 0x88, 16], vec![0; 16], vec![3, 0, 0, 0]].concat(),
        le: None,
        extended: false,
    };
    assert_eq!(session.transmit(&connector, &bad).unwrap().status, 0x6a80);
    select_application(&connector, &SD).unwrap();
    Scp03Session::authenticate_selected(&connector, &keys, 0x33, &SD).unwrap();
}
