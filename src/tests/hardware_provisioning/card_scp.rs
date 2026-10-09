//! Read-only qualification using a card's existing secure-channel credentials.
use super::*;

#[test]
#[ignore = "requires an explicit YubiKey serial and configured SCP credentials"]
fn card_scp_protected_reads_across_operations() {
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
    let result = std::panic::catch_unwind(|| {
        let mut baseline = None;
        for _ in 0..3 {
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
            let operations = std::panic::catch_unwind(|| {
                assert_eq!(
                    crate::api::C_Login(session, CKU_USER as _, std::ptr::null_mut(), 0),
                    CKR_OK as CK_RV,
                    "Issuer SD login must establish the configured secure channel without a PIN"
                );
                let mut information = None;
                for _ in 0..3 {
                    let current = crate::with_session_context(session, |ctx| {
                        let connector = ctx.slot.security_domain_provisioning_connector().unwrap();
                        // Both responses must pass MAC verification and decryption.
                        let keys =
                            crate::SecurityDomainClient.get_key_information(connector.as_ref())?;
                        let cplc = crate::SecurityDomainClient.get_cplc(connector.as_ref())?;
                        Ok((keys, cplc))
                    })
                    .expect("protected GET DATA failed");
                    assert!(!current.0.is_empty());
                    let cplc = current
                        .1
                        .as_ref()
                        .expect("qualification requires CPLC metadata");
                    assert_eq!(cplc.len(), 42);
                    if let Some(before) = &information {
                        assert_eq!(before, &current);
                    }
                    information = Some(current);
                }
                if let Some(before) = &baseline {
                    assert_eq!(Some(before), information.as_ref());
                }
                information.unwrap()
            });
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
            match operations {
                Ok(information) => baseline = Some(information),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        eprintln!(
            "{serial}: {protocol} authenticated three fresh sessions and verified nine protected read pairs"
        );
    });
    finalize_for_test();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
