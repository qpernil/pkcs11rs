//! Read-only qualification using a card's existing secure-channel credentials.
use super::*;

#[test]
#[ignore = "requires an explicit YubiKey serial and configured SCP credentials"]
fn card_scp_protected_reads_across_transactions() {
    let _guard = TEST_LOCK.lock().unwrap();
    let serial = std::env::var("PKCS11RS_TEST_ISSUER_SD_SOURCE")
        .expect("PKCS11RS_TEST_ISSUER_SD_SOURCE must select one serial");
    let protocol = std::env::var("PKCS11RS_CCID_SECURE_CHANNEL")
        .expect("PKCS11RS_CCID_SECURE_CHANNEL must select an SCP protocol");
    assert!(matches!(
        protocol.as_str(),
        "scp03" | "scp11a" | "scp11b" | "scp11c"
    ));
    finalize_for_test();
    assert_eq!(
        initialize_with_configuration(serde_json::json!({
            "version": 1, "hardware": {"discovery": true},
            "slots": {"serials": [serial]},
            "ccid": {"applications": ["issuer-sd"], "secure_channel": protocol},
            "software": {"slots": []}, "platform": {"enabled": false},
            "yubihsm": {"urls": [], "public_discovery": null}
        })),
        CKR_OK as CK_RV
    );
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as _, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let slot = crate::with_context(|ctx| {
        let slots = ctx.slot_contexts.read().unwrap();
        let matches: Vec<_> = slots
            .iter()
            .filter_map(|(id, child)| {
                let child = child.lock().unwrap();
                (child.slot.serial() == serial
                    && child.slot.is_present()
                    && child
                        .slot
                        .security_domain_provisioning_connector()
                        .is_some())
                .then_some(*id)
            })
            .collect();
        assert_eq!(matches.len(), 1, "expected the selected physical Issuer SD");
        Ok(matches[0])
    })
    .unwrap();
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            CKF_SERIAL_SESSION as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    let result = std::panic::catch_unwind(|| {
        let mut baseline = None;
        for _ in 0..3 {
            let information = crate::with_session_context(session, |ctx| {
                let connector = ctx.slot.security_domain_provisioning_connector().unwrap();
                connector
                    .establish_secure_channel(&crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID)?;
                // Each closure owns a separate device transaction. Both GET DATA
                // responses must pass channel MAC verification and decryption.
                let keys = crate::SecurityDomainClient.get_key_information(connector.as_ref())?;
                let cplc = crate::SecurityDomainClient.get_cplc(connector.as_ref())?;
                Ok((keys, cplc))
            })
            .expect("secure-channel authentication and protected GET DATA failed");
            assert!(!information.0.is_empty());
            assert!(information.1.as_ref().is_some_and(|cplc| !cplc.is_empty()));
            if let Some(before) = &baseline {
                assert_eq!(before, &information);
            } else {
                baseline = Some(information);
            }
        }
        eprintln!(
            "{serial}: {protocol} authenticated and verified protected reads in three separate transactions"
        );
    });
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    finalize_for_test();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
