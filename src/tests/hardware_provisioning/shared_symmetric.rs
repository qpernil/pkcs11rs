//! Explicitly selected, additive provisioning; never replaces existing objects.
use super::*;

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn provider(connector: Rc<dyn crate::Connector>, label: &str) -> crate::NativeHsmAuth {
    let info = with_ccid_operation(connector.as_ref(), || {
        crate::HsmAuthClient.discover(connector.as_ref())
    })
    .expect("failed to discover HSM Auth credentials");
    let credential = info
        .credentials
        .into_iter()
        .find(|c| c.label == label)
        .unwrap_or_else(|| panic!("credential {label:?} missing on {}", connector.name()));
    crate::NativeHsmAuth {
        connector,
        credential,
        version: info.version,
        trust_prefix: None,
        source: String::new(),
    }
}

#[test]
#[ignore = "persistent hardware provisioning; explicit targets and secrets required"]
fn provisions_shared_symmetric_hsmauth() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let sources: Vec<String> = required("PKCS11RS_SHARED_SOURCES")
        .split(',')
        .map(str::to_owned)
        .collect();
    assert!(!sources.is_empty());
    let mut unique = sources.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(sources.len(), unique.len(), "duplicate sources");
    let mut serials: Vec<u32> = required("PKCS11RS_SHARED_HSMS")
        .split(',')
        .map(|s| s.parse().expect("invalid HSM serial"))
        .collect();
    serials.sort();
    assert!(!serials.is_empty());
    let label = required("PKCS11RS_SHARED_LABEL");
    assert!(!label.is_empty() && label.len() <= 40);
    let id = hex_u16("PKCS11RS_SHARED_ID", &required("PKCS11RS_SHARED_ID"));
    assert_ne!(id, 0);
    let admin_id = hex_u16(
        "PKCS11RS_SHARED_ADMIN_ID",
        &required("PKCS11RS_SHARED_ADMIN_ID"),
    );
    assert_ne!(id, admin_id);
    let password = crate::Zeroizing::new(required("PKCS11RS_SHARED_PASSWORD"));
    assert!(password.len() <= 16);
    let admin_password = crate::Zeroizing::new(required("PKCS11RS_SHARED_ADMIN_PASSWORD"));
    let management_hex = crate::Zeroizing::new(required("PKCS11RS_SHARED_MANAGEMENT_KEY"));
    let management_key =
        crate::Zeroizing::new(crate::parse_hex(&management_hex).expect("invalid management key"));
    assert_eq!(management_key.len(), 16);
    let context =
        crate::ModuleContext::new_with_configuration(direct_hardware_configuration()).unwrap();
    context.init().unwrap();
    context.refresh_discovery().unwrap();
    let (connectors, hsms) = {
        let slots = context.slot_contexts.read().unwrap();
        (
            slots
                .values()
                .filter_map(|s| s.lock().ok()?.slot.hsmauth_provisioning_connector())
                .collect::<Vec<_>>(),
            slots
                .values()
                .filter_map(|s| s.lock().ok()?.slot.yubihsm_provisioning_connector())
                .collect::<Vec<_>>(),
        )
    };
    let mut devices = Vec::new();
    for source in &sources {
        let matches: Vec<_> = connectors
            .iter()
            .filter(|c| c.name() == *source)
            .cloned()
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "source {source:?} missing or ambiguous; available: {:?}",
            connectors.iter().map(|c| c.name()).collect::<Vec<_>>()
        );
        let connector = matches[0].clone();
        let info = with_ccid_operation(connector.as_ref(), || {
            crate::HsmAuthClient.discover(connector.as_ref())
        })
        .unwrap();
        assert!(
            !info.credentials.iter().any(|c| c.label == label),
            "refusing to replace {label:?} on {source}"
        );
        eprintln!("preflight YubiKey {source}: new label {label:?}, touch disabled");
        devices.push((connector, info.credentials));
    }
    let admin_source = required("PKCS11RS_SHARED_ADMIN_SOURCE");
    let admin_connector = devices
        .iter()
        .find(|(c, _)| c.name() == admin_source)
        .expect("admin source must be a selected YubiKey")
        .0
        .clone();
    let admin = provider(admin_connector, &required("PKCS11RS_SHARED_ADMIN_LABEL"));
    let mut found_serials = hsms
        .iter()
        .map(|h| crate::yubihsm::get_device_info(h.as_ref()).unwrap().serial)
        .collect::<Vec<_>>();
    found_serials.sort();
    assert_eq!(
        found_serials, serials,
        "local HSM inventory must match explicit target serials"
    );
    let mut targets = Vec::new();
    for hsm in hsms {
        let mut session = admin
            .authenticate(hsm.as_ref(), admin_id, admin_password.as_bytes())
            .expect("admin authentication failed");
        let before = crate::parse_yubihsm_object_list(
            &session
                .send_command(
                    hsm.as_ref(),
                    &crate::YubiHsmCommand::list_objects(&[]).unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(
            !before
                .iter()
                .any(|o| o.id == id && o.object_type == crate::YUBIHSM_AUTHENTICATION_KEY),
            "refusing to replace authentication key {id:04x}"
        );
        let info = crate::YubiHsmObjectInfo::parse(
            &session
                .send_command(
                    hsm.as_ref(),
                    &crate::YubiHsmCommand::get_object_info(
                        admin_id,
                        crate::YUBIHSM_AUTHENTICATION_KEY,
                    ),
                )
                .unwrap(),
        )
        .unwrap();
        eprintln!(
            "preflight {}: auth key {id:04x}, domains {:04x}, capabilities {:02x?}, delegated {:02x?}",
            hsm.name(),
            info.domains,
            info.capabilities,
            info.delegated_capabilities
        );
        targets.push((hsm, session, info, before));
    }
    if std::env::var("PKCS11RS_SHARED_APPLY").as_deref() != Ok("1") {
        for (hsm, mut session, _, _) in targets {
            session
                .send_command(hsm.as_ref(), &crate::YubiHsmCommand::close_session())
                .unwrap();
        }
        eprintln!("preflight complete; no credentials written (PKCS11RS_SHARED_APPLY is not 1)");
        return;
    }
    let mut keys = crate::Zeroizing::new([0u8; 32]);
    getrandom::fill(keys.as_mut()).expect("random generation failed");
    // No persistent host copy. On a partial failure, stop and inspect the printed
    // completed additions; never rerun blindly or replace an existing credential.
    for (connector, before) in &devices {
        with_ccid_operation(connector.as_ref(), || {
            crate::HsmAuthClient.put_symmetric_credential(
                connector.as_ref(),
                &management_key,
                &label,
                crate::hsmauth::SymmetricCredentialKeys {
                    enc: &keys[..16],
                    mac: &keys[16..],
                },
                password.as_bytes(),
                false,
            )
        })
        .expect("YubiKey import failed; inspect completed additions before recovery");
        eprintln!("installed {label:?} on {}", connector.name());
        let after = with_ccid_operation(connector.as_ref(), || {
            crate::HsmAuthClient
                .discover(connector.as_ref())
                .map(|info| info.credentials)
        })
        .unwrap();
        assert_eq!(after.len(), before.len() + 1);
        for old in before {
            assert!(after.contains(old), "existing credential metadata changed");
        }
        let added = after.iter().find(|c| c.label == label).unwrap();
        assert_eq!(
            added.algorithm,
            crate::HsmAuthAlgorithm::Aes128YubicoAuthentication
        );
        assert!(!added.touch_required);
    }
    for (hsm, session, info, before) in &mut targets {
        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id,
                label: &label,
                domains: info.domains,
                capabilities: info.capabilities,
                algorithm: crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: info.delegated_capabilities,
        };
        let command = crate::YubiHsmCommand::put_delegated_object(
            crate::YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            keys.as_ref(),
        )
        .unwrap();
        let installed = crate::parse_yubihsm_object_id(
            &session
                .send_command(hsm.as_ref(), &command)
                .expect("HSM import failed; inspect completed additions before recovery"),
        )
        .unwrap();
        assert_eq!(installed, id);
        eprintln!("installed auth key {id:04x} on {}", hsm.name());
        let added = crate::YubiHsmObjectInfo::parse(
            &session
                .send_command(
                    hsm.as_ref(),
                    &crate::YubiHsmCommand::get_object_info(id, crate::YUBIHSM_AUTHENTICATION_KEY),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(added.label, label);
        assert_eq!(added.domains, info.domains);
        assert_eq!(added.capabilities, info.capabilities);
        assert_eq!(added.delegated_capabilities, info.delegated_capabilities);
        assert_eq!(
            added.algorithm,
            crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION
        );
        let after = crate::parse_yubihsm_object_list(
            &session
                .send_command(
                    hsm.as_ref(),
                    &crate::YubiHsmCommand::list_objects(&[]).unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after.len(), before.len() + 1);
        for old in before {
            assert!(after.contains(old), "existing HSM object inventory changed");
        }
        session
            .send_command(hsm.as_ref(), &crate::YubiHsmCommand::close_session())
            .unwrap();
    }
    drop(keys);
    for (connector, _) in devices {
        let shared = provider(connector.clone(), &label);
        for (hsm, _, _, _) in &targets {
            let mut session = shared
                .authenticate(hsm.as_ref(), id, password.as_bytes())
                .expect("new shared credential login failed");
            let response = session
                .send_command(
                    hsm.as_ref(),
                    &crate::YubiHsmCommand::echo(b"shared credential verification").unwrap(),
                )
                .unwrap();
            assert_eq!(response, b"shared credential verification");
            session
                .send_command(hsm.as_ref(), &crate::YubiHsmCommand::close_session())
                .unwrap();
            eprintln!(
                "verified {} -> {} using {label:?}/{id:04x}",
                connector.name(),
                hsm.name()
            );
        }
    }
}
