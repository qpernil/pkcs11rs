//! Opt-in authentication between two explicitly selected physical YubiHSMs.
use super::*;

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn command(
    session: CK_SESSION_HANDLE,
    command: &crate::YubiHsmCommand,
) -> Result<Vec<u8>, crate::Error> {
    crate::with_session_context(session, |ctx| {
        ctx._get_session(session)?.1.yubihsm_command(command)
    })
}

fn inventory(session: CK_SESSION_HANDLE) -> Vec<(u16, u8, u8)> {
    let response = command(session, &crate::YubiHsmCommand::list_objects(&[]).unwrap()).unwrap();
    let mut objects: Vec<_> = crate::parse_yubihsm_object_list(&response)
        .unwrap()
        .into_iter()
        .map(|object| (object.id, object.object_type, object.sequence))
        .collect();
    objects.sort_unstable();
    objects
}

fn open(serial: &str) -> CK_SESSION_HANDLE {
    let slot = crate::with_context(|context| {
        let slots = context
            .slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        let matches: Vec<_> = slots
            .iter()
            .filter_map(|(id, child)| {
                let child = child.lock().ok()?;
                (child.slot.serial() == serial
                    && child.slot.is_present()
                    && child.slot.supports_yubihsm_management())
                .then_some(*id)
            })
            .collect();
        if matches.len() != 1 {
            return Err(CKR_SLOT_ID_INVALID.into());
        }
        Ok(matches[0])
    })
    .unwrap_or_else(|e| panic!("expected one local HSM with serial {serial}: {e:?}"));
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    session
}

fn login(session: CK_SESSION_HANDLE, pin: &str) {
    let mut pin = crate::Zeroizing::new(pin.as_bytes().to_vec());
    assert_eq!(
        crate::api::C_Login(session, CKU_USER as _, pin.as_mut_ptr(), pin.len() as _),
        CKR_OK as CK_RV,
        "bootstrap source/target login failed"
    );
}

#[test]
#[ignore = "creates and removes temporary HSM keys; requires two explicit local serials and bootstrap PINs"]
fn yubihsm_to_yubihsm_asymmetric_authentication() {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_CROSS_HSM_SOURCE");
    let target = required("PKCS11RS_CROSS_HSM_TARGET");
    assert_ne!(source, target, "source and target must differ");
    let source_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_SOURCE_PIN"));
    let target_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_TARGET_PIN"));
    let mut serials = vec![source.clone(), target.clone()];
    if let Ok(helpers) = std::env::var("PKCS11RS_CROSS_HSM_HELPERS") {
        serials.extend(
            helpers
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
    }
    finalize_for_test();
    assert_eq!(
        initialize_with_configuration(serde_json::json!({
            "version": 1, "hardware": {"discovery": true},
            "slots": {"serials": serials}, "ccid": {"applications": ["hsmauth"]},
            "software": {"slots": []}, "platform": {"enabled": false},
            "yubihsm": {"urls": [], "public_discovery": null, "recreate_sessions": false}
        })),
        CKR_OK as CK_RV
    );
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as _, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let source_session = open(&source);
    let target_session = open(&target);
    login(source_session, &source_pin);
    login(target_session, &target_pin);
    let source_before = inventory(source_session);
    let target_before = inventory(target_session);
    eprintln!(
        "source {source}: {} native objects; target {target}: {} native objects",
        source_before.len(),
        target_before.len()
    );
    let label = format!(
        "p11-cross-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut auth_id = None;
    // Always attempt cleanup after an assertion failure as well as success.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as _,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut yes = CK_TRUE as CK_BBOOL;
        let mut no = CK_FALSE as CK_BBOOL;
        let mut parameters = crate::ec_curve_parameters(crate::EcCurve::P256).to_vec();
        let mut public_label = label.as_bytes().to_vec();
        let mut private_label = public_label.clone();
        let mut public_template = [
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            bytes_attribute(CKA_LABEL as _, &mut public_label),
            bytes_attribute(CKA_EC_PARAMS as _, &mut parameters),
        ];
        let mut private_template = [
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            scalar_attribute(CKA_PRIVATE as _, &mut yes),
            scalar_attribute(CKA_SENSITIVE as _, &mut yes),
            scalar_attribute(CKA_EXTRACTABLE as _, &mut no),
            scalar_attribute(CKA_DERIVE as _, &mut yes),
            scalar_attribute(CKA_SIGN as _, &mut no),
            bytes_attribute(CKA_LABEL as _, &mut private_label),
        ];
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                source_session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as _,
                private_template.as_mut_ptr(),
                private_template.len() as _,
                &mut public,
                &mut private
            ),
            CKR_OK as CK_RV,
            "source token key generation failed"
        );
        let point = read_hardware_attribute(source_session, public, CKA_EC_POINT as _);
        assert_eq!(
            &point[..3],
            &[4, 65, 4],
            "expected DER-wrapped uncompressed P-256 public point"
        );
        assert_eq!(point.len(), 67);
        let mut hidden = CK_ATTRIBUTE {
            type_: CKA_VALUE as _,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(source_session, private, &mut hidden, 1),
            CKR_ATTRIBUTE_SENSITIVE as CK_RV,
            "source private scalar must stay unreadable"
        );
        let source_id = read_hardware_attribute(source_session, private, CKA_ID as _);
        assert_eq!(
            source_id,
            read_hardware_attribute(source_session, public, CKA_ID as _)
        );
        let allowed = read_hardware_attribute(source_session, private, CKA_ALLOWED_MECHANISMS as _);
        let allowed: Vec<_> = allowed
            .as_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>()
            .0
            .iter()
            .map(|bytes| CK_MECHANISM_TYPE::from_ne_bytes(*bytes))
            .collect();
        assert!(allowed.contains(&(CKM_ECDH1_DERIVE as _)));
        assert!(allowed.contains(&crate::CKM_PKCS11RS_PREFIXED_ECDH_DERIVE));
        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id: 0,
                label: &label,
                domains: 1,
                capabilities: crate::yubihsm_capabilities(&[0x00, 0x13]), // get-opaque, get-pseudo-random
                algorithm: crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: [0; 8],
        };
        let put = crate::YubiHsmCommand::put_delegated_object(
            crate::YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            &point[3..],
        )
        .unwrap();
        let id = crate::parse_yubihsm_object_id(&command(target_session, &put).unwrap()).unwrap();
        auth_id = Some(id);
        eprintln!("created temporary source key {label:?} and target Authentication Key {id:04x}");
        assert!(
            !target_before
                .iter()
                .any(|(old, kind, _)| *old == id && *kind == crate::YUBIHSM_AUTHENTICATION_KEY)
        );
        assert_eq!(crate::api::C_Logout(target_session), CKR_OK as CK_RV);
        let mut selector = format!(":{id:04x}{label}@{source}").into_bytes();
        // The source's existing USER session supplies authorization. No source
        // password or private scalar is passed to the target login.
        assert_eq!(
            crate::api::C_LoginUser(
                target_session,
                CKU_USER as _,
                std::ptr::null_mut(),
                0,
                selector.as_mut_ptr(),
                selector.len() as _
            ),
            CKR_OK as CK_RV,
            "cross-HSM login through the PKCS #11 source slot failed"
        );
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        assert_eq!(
            crate::api::C_GenerateRandom(target_session, first.as_mut_ptr(), first.len() as _),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_GenerateRandom(target_session, second.as_mut_ptr(), second.len() as _),
            CKR_OK as CK_RV
        );
        assert_ne!(first, second);
        let echo = b"pkcs11rs physical HSM source authentication";
        assert_eq!(
            command(target_session, &crate::YubiHsmCommand::echo(echo).unwrap()).unwrap(),
            echo
        );
        eprintln!(
            "verified {source} -> {target}: protected source P-256, PKCS #11 login, two random requests and encrypted echo"
        );
    }));
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rv = crate::api::C_Logout(target_session);
        assert!(rv == CKR_OK as CK_RV || rv == CKR_USER_NOT_LOGGED_IN as CK_RV);
        login(target_session, &target_pin);
        if let Some(id) = auth_id {
            let response = command(
                target_session,
                &crate::YubiHsmCommand::delete_object(id, crate::YUBIHSM_AUTHENTICATION_KEY),
            )
            .unwrap();
            assert!(response.is_empty());
        }
        if public != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            assert_eq!(
                crate::api::C_DestroyObject(source_session, public),
                CKR_OK as CK_RV
            );
        }
        if private != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            assert_eq!(
                crate::api::C_DestroyObject(source_session, private),
                CKR_OK as CK_RV
            );
        }
        assert_eq!(
            inventory(source_session),
            source_before,
            "source inventory differs after cleanup"
        );
        assert_eq!(
            inventory(target_session),
            target_before,
            "target inventory differs after cleanup"
        );
        eprintln!(
            "temporary objects removed; both native inventories match their pre-test snapshots"
        );
    }));
    finalize_for_test();
    if let Err(error) = cleanup {
        std::panic::resume_unwind(error);
    }
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
