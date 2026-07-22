#[cfg(not(feature = "abi-tests"))]
mod hardware_provisioning {
    use super::*;
    use std::rc::Rc;

    const ENABLE_ENV: &str = "PKCS11RS_TEST_PROVISION_ASYMMETRIC_HSMAUTH";
    const AUTHKEY_ID_ENV: &str = "PKCS11RS_TEST_YUBIHSM_AUTHKEY_ID";
    const DEFAULT_MANAGEMENT_KEY: &str = "00000000000000000000000000000000";
    const DEFAULT_LABEL: &str = "pkcs11rs-asymmetric";
    const DEFAULT_CREDENTIAL_PASSWORD: &str = "password";
    const DEFAULT_ADMIN_ID: &str = "0001";
    const DEFAULT_ADMIN_PASSWORD: &str = "password";
    const DEFAULT_DOMAINS: &str = "0001";

    fn environment(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_owned())
    }

    fn hex_u16(name: &str, value: &str) -> u16 {
        assert_eq!(
            value.len(),
            4,
            "{name} must contain exactly four hexadecimal characters"
        );
        u16::from_str_radix(value, 16)
            .unwrap_or_else(|_| panic!("{name} must contain exactly four hexadecimal characters"))
    }

    fn select_connector(
        connectors: Vec<Rc<dyn crate::Connector>>,
        selector_name: &str,
        kind: &str,
    ) -> Rc<dyn crate::Connector> {
        let selector = std::env::var(selector_name).ok();
        let mut matches = connectors.into_iter().filter(|connector| {
            selector.as_ref().is_none_or(|selector| {
                connector.serial() == selector || connector.name() == *selector
            })
        });
        let connector = matches.next().unwrap_or_else(|| {
            panic!("no {kind} matched {selector_name}={selector:?}")
        });
        assert!(
            matches.next().is_none(),
            "multiple {kind} devices matched; set {selector_name} to a serial number or full device name"
        );
        connector
    }

    #[test]
    fn provisioning_connectors_are_exposed_by_the_matching_slots() {
        let connector = || -> Rc<dyn crate::Connector> {
            Rc::new(SelectableConnector {
                present: std::cell::Cell::new(true),
                select_ok: std::cell::Cell::new(true),
                serial: "PROVISION",
            })
        };
        let hsmauth_aid = crate::hsmauth::AID.to_vec();
        let hsmauth = crate::HsmAuthSlot::new(connector(), hsmauth_aid);
        assert!(crate::Slot::hsmauth_provisioning_connector(&hsmauth).is_some());

        let issuer_sd = crate::GlobalPlatformSlot::new(
            connector(),
            crate::YUBIKEY_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
        );
        assert!(crate::Slot::hsmauth_provisioning_connector(&issuer_sd).is_none());

        let yubihsm = crate::YubiHsmSlot::new(connector(), (2, 4, 0), Vec::new());
        assert!(crate::Slot::yubihsm_provisioning_connector(&yubihsm).is_some());
    }

    #[test]
    #[ignore = "provisions persistent keys on a live YubiKey and YubiHSM"]
    fn provisions_asymmetric_hsmauth_credential_on_yubihsm() {
        if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
            eprintln!("skipped persistent provisioning; set {ENABLE_ENV}=1 to enable it");
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        crate::initialize_debug_logging().expect("invalid PKCS11RS_DEBUG level");

        let authkey_id = hex_u16(
            AUTHKEY_ID_ENV,
            &std::env::var(AUTHKEY_ID_ENV)
                .unwrap_or_else(|_| panic!("{AUTHKEY_ID_ENV} is required when provisioning")),
        );
        assert_ne!(authkey_id, 0, "{AUTHKEY_ID_ENV} must not be zero");
        let admin_id = hex_u16(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_ID",
            &environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
        );
        let domains = hex_u16(
            "PKCS11RS_TEST_YUBIHSM_DOMAINS",
            &environment("PKCS11RS_TEST_YUBIHSM_DOMAINS", DEFAULT_DOMAINS),
        );
        assert_ne!(domains, 0, "PKCS11RS_TEST_YUBIHSM_DOMAINS must not be zero");

        let label = environment("PKCS11RS_TEST_HSMAUTH_LABEL", DEFAULT_LABEL);
        assert!(!label.is_empty() && label.len() <= 40, "label must be 1..=40 bytes");
        let credential_password = crate::Zeroizing::new(environment(
            "PKCS11RS_TEST_HSMAUTH_CREDENTIAL_PASSWORD",
            DEFAULT_CREDENTIAL_PASSWORD,
        ));
        assert!(
            credential_password.len() <= 16,
            "YubiHSM Auth credential password must not exceed 16 bytes"
        );
        let management_key = crate::Zeroizing::new(
            crate::parse_hex(&environment(
                "PKCS11RS_TEST_HSMAUTH_MANAGEMENT_KEY",
                DEFAULT_MANAGEMENT_KEY,
            ))
            .expect("invalid YubiHSM Auth management key encoding"),
        );
        assert_eq!(management_key.len(), 16, "management key must be 16 bytes");
        let admin_password = crate::Zeroizing::new(environment(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
            DEFAULT_ADMIN_PASSWORD,
        ));
        assert!(
            (8..=64).contains(&admin_password.len()),
            "YubiHSM admin password must be 8..=64 bytes"
        );

        let mut context = crate::Context::new().expect("failed to create hardware context");
        context.init();
        let hsmauth = select_connector(
            context
                .slots
                .values()
                .filter_map(|slot| slot.hsmauth_provisioning_connector())
                .collect(),
            "PKCS11RS_TEST_HSMAUTH_SOURCE",
            "YubiHSM Auth applet",
        );
        let yubihsm = select_connector(
            context
                .slots
                .values()
                .filter_map(|slot| slot.yubihsm_provisioning_connector())
                .collect(),
            "PKCS11RS_TEST_YUBIHSM_SOURCE",
            "YubiHSM",
        );

        let credentials = crate::HsmAuthClient
            .list_credentials(hsmauth.as_ref())
            .expect("failed to list YubiHSM Auth credentials");
        let existing_credential = credentials
            .into_iter()
            .find(|credential| credential.label == label);
        if let Some(credential) = &existing_credential {
            assert_eq!(
                credential.algorithm,
                crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
                "existing YubiHSM Auth credential {label:?} is not asymmetric P-256"
            );
        }

        let mut admin_session = crate::YubiHsmSecureSession::authenticate(
            yubihsm.as_ref(),
            admin_id,
            admin_password.as_bytes(),
        )
        .expect("failed to authenticate to the YubiHSM provisioning key");
        let existing_key = (|| -> Result<Option<crate::YubiHsmObjectInfo>, crate::Error> {
            let response = admin_session.send_command(
                yubihsm.as_ref(),
                &crate::YubiHsmCommand::list_objects(&[
                    crate::yubihsm::ObjectFilter::Id(authkey_id),
                    crate::yubihsm::ObjectFilter::Type(crate::YUBIHSM_AUTHENTICATION_KEY),
                ])?,
            )?;
            let entries = crate::parse_yubihsm_object_list(&response)?;
            match entries.as_slice() {
                [] => Ok(None),
                [entry] => crate::YubiHsmObjectInfo::parse(&admin_session.send_command(
                    yubihsm.as_ref(),
                    &crate::YubiHsmCommand::get_object_info(entry.id, entry.object_type),
                )?)
                .map(Some),
                _ => Err(crate::CKR_DEVICE_ERROR.into()),
            }
        })();
        let preflight_close = admin_session.send_command(
            yubihsm.as_ref(),
            &crate::YubiHsmCommand::close_session(),
        );
        let existing_key = existing_key
            .expect("failed to query the target YubiHSM authentication-key ID and metadata");
        preflight_close.expect("failed to close the YubiHSM preflight session");
        if let Some(info) = &existing_key {
            assert_eq!(info.label, label, "target YubiHSM object ID has another label");
            assert_eq!(
                info.algorithm,
                crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
                "target YubiHSM object is not an asymmetric P-256 authentication key"
            );
        }

        if existing_key.is_some() {
            let mut admin_session = crate::YubiHsmSecureSession::authenticate(
                yubihsm.as_ref(),
                admin_id,
                admin_password.as_bytes(),
            )
            .expect("failed to reopen the YubiHSM provisioning session for cleanup");
            let deletion = admin_session
                .send_command(
                    yubihsm.as_ref(),
                    &crate::YubiHsmCommand::delete_object(
                        authkey_id,
                        crate::YUBIHSM_AUTHENTICATION_KEY,
                    ),
                )
                .and_then(|response| {
                    if response.is_empty() {
                        Ok(())
                    } else {
                        Err(crate::CKR_DEVICE_ERROR.into())
                    }
                });
            let cleanup_close = admin_session.send_command(
                yubihsm.as_ref(),
                &crate::YubiHsmCommand::close_session(),
            );
            deletion.expect("failed to delete the prior YubiHSM authentication key");
            cleanup_close.expect("failed to close the YubiHSM cleanup session");
            eprintln!("deleted prior YubiHSM authentication key {authkey_id:04x}");
        }

        if existing_credential.is_some() {
            crate::HsmAuthClient
                .delete_credential(hsmauth.as_ref(), management_key.as_slice(), &label)
                .expect("failed to delete the prior YubiHSM Auth credential");
            eprintln!("deleted prior YubiHSM Auth credential {label:?}");
        }

        crate::HsmAuthClient
            .put_asymmetric_credential(
                hsmauth.as_ref(),
                management_key.as_slice(),
                &label,
                None,
                credential_password.as_bytes(),
                false,
            )
            .expect("failed to generate the YubiHSM Auth asymmetric credential");
        let public_key = crate::HsmAuthClient
            .get_public_key(hsmauth.as_ref(), &label)
            .expect("failed to read the generated YubiHSM Auth public key");
        let public_key = public_key
            .strip_prefix(&[0x04])
            .expect("YubiHSM Auth returned a non-SEC1 P-256 public key");
        assert_eq!(public_key.len(), 64);

        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id: authkey_id,
                label: &label,
                domains,
                capabilities: [0; 8],
                algorithm: crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: [0; 8],
        };
        let command = crate::YubiHsmCommand::put_delegated_object(
            crate::YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            public_key,
        )
        .expect("failed to encode the asymmetric authentication key");
        let mut admin_session = crate::YubiHsmSecureSession::authenticate(
            yubihsm.as_ref(),
            admin_id,
            admin_password.as_bytes(),
        )
        .expect("failed to reopen the YubiHSM provisioning session");
        let installed_id = admin_session
            .send_command(yubihsm.as_ref(), &command)
            .and_then(|response| crate::parse_yubihsm_object_id(&response));
        let provisioning_close = admin_session.send_command(
            yubihsm.as_ref(),
            &crate::YubiHsmCommand::close_session(),
        );
        let installed_id =
            installed_id.expect("failed to install the asymmetric authentication key in the YubiHSM");
        provisioning_close.expect("failed to close the YubiHSM provisioning session");
        assert_eq!(installed_id, authkey_id);

        let info = crate::HsmAuthClient
            .discover(hsmauth.as_ref())
            .expect("failed to rediscover the generated YubiHSM Auth credential");
        let credential = info
            .credentials
            .into_iter()
            .find(|credential| credential.label == label)
            .expect("generated YubiHSM Auth credential was not rediscovered");
        let mut session = crate::HsmAuthProvider {
            connector: hsmauth,
            credential,
            version: info.version,
        }
        .authenticate(
            yubihsm.as_ref(),
            authkey_id,
            credential_password.as_bytes(),
        )
        .expect("the provisioned asymmetric YubiHSM Auth pair could not authenticate");
        session
            .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session())
            .expect("failed to close the verification session");

        eprintln!(
            "provisioned persistent YubiHSM Auth credential {label:?} and YubiHSM authentication key {authkey_id:04x}"
        );
    }
}
