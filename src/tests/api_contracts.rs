use super::*;

#[test]
fn data_session_objects_share_visibility_and_follow_creator_and_login_lifetimes() {
    let _guard = TEST_LOCK.lock().unwrap();
    for kind in [
        crate::SlotKind::Software,
        crate::SlotKind::Host,
        crate::SlotKind::YubiHsm,
        crate::SlotKind::Fido2,
        crate::SlotKind::Ccid(crate::CcidApplication::Piv),
        crate::SlotKind::Ccid(crate::CcidApplication::OpenPgp),
    ] {
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let mut slot = test_slot(true);
        slot.kind = kind;
        install_test_slot_with_backend(82, Box::new(slot));
        install_test_session(82, 8201);
        install_test_session(82, 8202);
        install_test_session(83, 8301);
        let create = |private: bool| {
            let mut class = CKO_DATA as CK_OBJECT_CLASS;
            let mut private = private as CK_BBOOL;
            let mut value = *b"session payload";
            let mut application = *b"test application";
            let mut object_id = [6, 2, 42, 3];
            let mut template = [
                scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
                scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
                bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
                bytes_attribute(CKA_APPLICATION as CK_ATTRIBUTE_TYPE, &mut application),
                bytes_attribute(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE, &mut object_id),
            ];
            let mut object = 0;
            assert_eq!(
                crate::api::C_CreateObject(
                    8201,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut object
                ),
                CKR_OK as CK_RV,
                "{kind:?}"
            );
            object
        };
        let public = create(false);
        let private = create(true);
        assert_eq!(
            read_bytes_attribute(8202, public, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            b"session payload"
        );
        assert_eq!(
            read_bytes_attribute(8202, private, CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
            b"test application"
        );
        assert_eq!(
            read_bytes_attribute(8202, public, CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
            [6, 2, 42, 3]
        );
        assert_eq!(
            find_by_bytes_attribute(
                8202,
                CKO_DATA as CK_OBJECT_CLASS,
                CKA_VALUE as CK_ATTRIBUTE_TYPE,
                b"session payload"
            )
            .len(),
            2
        );
        let mut size = 0;
        assert_eq!(
            crate::api::C_GetObjectSize(8301, public, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );

        let mut copy = 0;
        assert_eq!(
            crate::api::C_CopyObject(8202, public, std::ptr::null_mut(), 0, &mut copy),
            CKR_OK as CK_RV
        );
        let mut changed = *b"copy content";
        let mut attribute = bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut changed);
        assert_eq!(
            crate::api::C_SetAttributeValue(8202, copy, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            read_bytes_attribute(8201, public, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            b"session payload"
        );
        assert_eq!(
            read_bytes_attribute(8201, copy, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            b"copy content"
        );

        // An impossible input length must not alter the object.
        attribute.ulValueLen = CK_ULONG::MAX;
        assert_eq!(
            crate::api::C_SetAttributeValue(8202, copy, &mut attribute, 1),
            CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
        );
        assert_eq!(crate::api::C_Logout(8201), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_GetObjectSize(8202, private, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
        assert_eq!(
            crate::api::C_GetObjectSize(8202, public, &mut size),
            CKR_OK as CK_RV
        );
        let mut pin = *b"1234";
        assert_eq!(
            crate::api::C_Login(
                8202,
                CKU_USER as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_GetObjectSize(8202, private, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
        assert_eq!(crate::api::C_CloseSession(8201), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_GetObjectSize(8202, public, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
        assert_eq!(
            read_bytes_attribute(8202, copy, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            b"copy content"
        );
        assert_eq!(crate::api::C_DestroyObject(8202, copy), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_GetObjectSize(8202, copy, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
    }
    finalize_for_test();
}

fn initialize_contract_slot() {
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let mechanisms = crate::HASHED_RSA_PSS_MECHANISMS
        .into_iter()
        .chain([CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE])
        .map(|mechanism| (mechanism, (CKF_SIGN | CKF_VERIFY) as CK_FLAGS))
        .chain([(CKM_SHA256 as CK_MECHANISM_TYPE, CKF_DIGEST as CK_FLAGS)])
        .collect::<Vec<_>>();
    install_test_slot_with_backend(
        TEST_SLOT_ID,
        Box::new(test_slot_with_mechanisms(true, &mechanisms)),
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
}

#[test]
fn rsa_pss_init_validates_parameters_for_raw_and_composite_mechanisms() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize_contract_slot();
    for mechanism_type in crate::HASHED_RSA_PSS_MECHANISMS
        .into_iter()
        .chain([CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE])
    {
        let hash =
            crate::pss_hash_mechanism(mechanism_type).unwrap_or(CKM_SHA256 as CK_MECHANISM_TYPE);
        let mut parameters = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: hash,
            mgf: CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE,
            sLen: 17,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: (&mut parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast(),
            ulParameterLen: std::mem::size_of_val(&parameters) as CK_ULONG,
        };
        let check_invalid = |mechanism: &mut CK_MECHANISM| {
            assert_eq!(
                crate::api::C_SignInit(TEST_SESSION_HANDLE, mechanism, 2),
                CKR_MECHANISM_PARAM_INVALID as CK_RV
            );
            assert_eq!(
                crate::api::C_VerifyInit(TEST_SESSION_HANDLE, mechanism, 1),
                CKR_MECHANISM_PARAM_INVALID as CK_RV
            );
        };
        mechanism.pParameter = std::ptr::null_mut();
        check_invalid(&mut mechanism);
        mechanism.pParameter = (&mut parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast();
        mechanism.ulParameterLen -= 1;
        check_invalid(&mut mechanism);
        mechanism.ulParameterLen += 1;
        let check_parameters = |parameters: &mut CK_RSA_PKCS_PSS_PARAMS| {
            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: (parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast(),
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
            };
            check_invalid(&mut mechanism);
        };
        parameters.hashAlg = CKM_AES_ECB as CK_MECHANISM_TYPE;
        check_parameters(&mut parameters);
        if mechanism_type != CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            parameters.hashAlg = if hash == CKM_SHA256 as CK_MECHANISM_TYPE {
                CKM_SHA384 as CK_MECHANISM_TYPE
            } else {
                CKM_SHA256 as CK_MECHANISM_TYPE
            };
            check_parameters(&mut parameters);
        }
        parameters.hashAlg = hash;
        parameters.mgf = 0;
        check_parameters(&mut parameters);
        parameters.mgf = CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE;
        parameters.sLen = CK_ULONG::MAX;
        check_parameters(&mut parameters);
        parameters.sLen = 17;
        mechanism.pParameter = (&mut parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast();
        assert_eq!(
            crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
            CKR_OK as CK_RV
        );
        with_test_slot_context(TEST_SLOT_ID, |context| {
            let session = context.sessions.get(&TEST_SESSION_HANDLE).unwrap();
            assert_eq!(
                session.sign_operation.as_ref().unwrap().pss,
                Some((34, 17, hash))
            );
            assert_eq!(
                session.verify_operation.as_ref().unwrap().pss,
                Some((34, 17, hash))
            );
        });
        assert_eq!(
            crate::api::C_SessionCancel(TEST_SESSION_HANDLE, (CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
            CKR_OK as CK_RV
        );
    }
    finalize_for_test();
}

#[test]
fn null_mechanism_cancels_only_the_requested_operation_and_allows_restart() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize_contract_slot();
    let mut rsa = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut digest = CK_MECHANISM {
        mechanism: CKM_SHA256 as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    for _ in 0..2 {
        assert_eq!(
            crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut rsa, 2),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_VerifyInit(TEST_SESSION_HANDLE, &mut rsa, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_DigestInit(TEST_SESSION_HANDLE, &mut digest),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_SignInit(
                TEST_SESSION_HANDLE,
                std::ptr::null_mut(),
                CK_INVALID_HANDLE as CK_OBJECT_HANDLE
            ),
            CKR_OK as CK_RV
        );
        with_test_slot_context(TEST_SLOT_ID, |context| {
            let session = context.sessions.get(&TEST_SESSION_HANDLE).unwrap();
            assert!(session.sign_operation.is_none());
            assert!(session.verify_operation.is_some());
            assert!(session.digest_operation.is_some());
        });
        assert_eq!(
            crate::api::C_VerifyInit(
                TEST_SESSION_HANDLE,
                std::ptr::null_mut(),
                CK_INVALID_HANDLE as CK_OBJECT_HANDLE
            ),
            CKR_OK as CK_RV
        );
        with_test_slot_context(TEST_SLOT_ID, |context| {
            let session = context.sessions.get(&TEST_SESSION_HANDLE).unwrap();
            assert!(session.verify_operation.is_none());
            assert!(session.digest_operation.is_some());
        });
        assert_eq!(
            crate::api::C_DigestInit(TEST_SESSION_HANDLE, std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_SignInit(TEST_SESSION_HANDLE, std::ptr::null_mut(), 0),
            CKR_OPERATION_NOT_INITIALIZED as CK_RV
        );
        assert_eq!(
            crate::api::C_VerifyInit(TEST_SESSION_HANDLE, std::ptr::null_mut(), 0),
            CKR_OPERATION_NOT_INITIALIZED as CK_RV
        );
        assert_eq!(
            crate::api::C_DigestInit(TEST_SESSION_HANDLE, std::ptr::null_mut()),
            CKR_OPERATION_NOT_INITIALIZED as CK_RV
        );
    }
    finalize_for_test();
}

#[test]
fn copy_object_enforces_reported_immutable_material_policy() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize_contract_slot();
    let base = with_test_slot_context(TEST_SLOT_ID, |context| {
        context.memory_objects.get(&2).unwrap().clone()
    });
    let materials = [
        crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Authentication,
            algorithm: crate::piv::Algorithm::EccP256,
            pin_policy: 0,
            touch_policy: 0,
        },
        crate::KeyMaterial::OpenPgpPrivate {
            key_ref: crate::OpenPgpKeyRef::Authentication,
            algorithm: crate::OpenPgpAlgorithm::Ed25519,
            pin_policy: 0,
            touch_policy: 0,
        },
        crate::KeyMaterial::OpenPgpCertificate { value: Vec::new() },
        crate::KeyMaterial::FidoResidentPrivate {
            credential_id: vec![1, 2, 3],
        },
    ];
    for material in materials {
        let handle = with_test_slot_context(TEST_SLOT_ID, |context| {
            let mut object = base.clone();
            object.material = material;
            context.insert_object(object).unwrap()
        });
        let mut copyable = CK_TRUE as CK_BBOOL;
        let mut attribute = scalar_attribute(CKA_COPYABLE as CK_ATTRIBUTE_TYPE, &mut copyable);
        assert_eq!(
            crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, handle, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(copyable, CK_FALSE as CK_BBOOL);
        let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let count_before =
            with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len());
        assert_eq!(
            crate::api::C_CopyObject(
                TEST_SESSION_HANDLE,
                handle,
                std::ptr::null_mut(),
                0,
                &mut copied
            ),
            CKR_ACTION_PROHIBITED as CK_RV
        );
        let mut private = CK_FALSE as CK_BBOOL;
        let mut template = scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private);
        assert_eq!(
            crate::api::C_CopyObject(TEST_SESSION_HANDLE, handle, &mut template, 1, &mut copied),
            CKR_ACTION_PROHIBITED as CK_RV
        );
        assert_eq!(copied, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
        assert_eq!(
            with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
            count_before
        );
    }
    finalize_for_test();
}

fn data_test_certificate() -> Vec<u8> {
    let key = crate::certificate_builder::p256_key();
    crate::certificate_builder::p256_certificate(
        key.verifying_key(),
        &key,
        "CN=Data test",
        "CN=Data test",
        128,
        false,
    )
}

fn create_test_data(
    session: CK_SESSION_HANDLE,
    certificate: bool,
    token: bool,
    private: bool,
    value: &[u8],
    label: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut class = if certificate {
        CKO_CERTIFICATE
    } else {
        CKO_DATA
    } as CK_OBJECT_CLASS;
    let mut token = token as CK_BBOOL;
    let mut private = private as CK_BBOOL;
    let mut value = value.to_vec();
    let mut label = label.to_vec();
    let mut certificate_type = CKC_X_509 as CK_CERTIFICATE_TYPE;
    let mut id = b"certificate identifier".to_vec();
    let mut template = vec![
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ];
    if certificate {
        template.push(scalar_attribute(
            CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE,
            &mut certificate_type,
        ));
        template.push(bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id));
    }
    let mut handle = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut handle
        ),
        CKR_OK as CK_RV
    );
    handle
}

#[test]
fn yubihsm_create_native_data_and_certificates_preserves_payload_and_identity() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(92, slot);
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            92,
            (CKF_RW_SESSION | CKF_SERIAL_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let certificate = data_test_certificate();
    for (is_certificate, value, algorithm) in [
        (
            false,
            b"raw opaque data\x00\xff".as_slice(),
            crate::YUBIHSM_ALGO_OPAQUE_DATA,
        ),
        (
            true,
            certificate.as_slice(),
            crate::YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
        ),
    ] {
        let label = b"native opaque object with an identity longer than forty bytes";
        let handle = create_test_data(session, is_certificate, true, false, value, label);
        assert_eq!(
            read_bytes_attribute(session, handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            value
        );
        assert_eq!(
            read_bytes_attribute(session, handle, CKA_LABEL as CK_ATTRIBUTE_TYPE),
            label
        );
        with_test_slot_context(92, |ctx| {
            let object = ctx.resolve_object(handle).unwrap().unwrap();
            assert!(
                matches!(object.material, crate::KeyMaterial::YubiHsm { object_type: crate::YUBIHSM_OPAQUE, algorithm: actual, .. } if actual == algorithm)
            );
            ctx.refresh_slot_token_objects(92).unwrap();
        });
        assert!(commands.borrow().iter().any(|(command, data)| *command
            == crate::YubiHsmCommandCode::PutOpaque as u8
            && data.len() >= 53
            && data[52] == algorithm
            && &data[53..] == value));
        assert_eq!(
            read_bytes_attribute(session, handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            value
        );
        if is_certificate {
            assert_eq!(
                read_bytes_attribute(session, handle, CKA_ID as CK_ATTRIBUTE_TYPE),
                b"certificate identifier"
            );
            assert_eq!(
                read_bytes_attribute(session, handle, CKA_SUBJECT as CK_ATTRIBUTE_TYPE),
                crate::certificate_chain::subject(value).unwrap()
            );
        }
        assert_eq!(
            crate::api::C_DestroyObject(session, handle),
            CKR_OK as CK_RV
        );
        let mut size = 0;
        assert_eq!(
            crate::api::C_GetObjectSize(session, handle, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
    }
    finalize_for_test();
}

#[test]
fn software_token_data_and_certificates_persist_in_the_correct_login_realm() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let root = std::env::temp_dir().join(format!("pkcs11rs-data-test-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let discovery = b"data discovery password".to_vec();
    let store = crate::software_storage::SoftwareTokenStore::open(
        "data test".into(),
        root.clone(),
        Some(discovery.clone()),
    )
    .unwrap();
    let public = store
        .init_token(b"data officer password", [b' '; 32])
        .unwrap();
    store.init_user_pin(b"data user password", &public).unwrap();
    let certificate = data_test_certificate();
    for round in 0..2 {
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot = crate::SoftwareSlot::new_with_storage(
            "data test".into(),
            0,
            Some(root.clone()),
            Some(discovery.clone()),
        )
        .unwrap();
        install_test_slot_with_backend(93, Box::new(slot));
        let mut session = 0;
        assert_eq!(
            crate::api::C_OpenSession(
                93,
                (CKF_RW_SESSION | CKF_SERIAL_SESSION) as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_OK as CK_RV
        );
        if round == 1 {
            assert_eq!(
                find_by_bytes_attribute(
                    session,
                    CKO_DATA as CK_OBJECT_CLASS,
                    CKA_LABEL as CK_ATTRIBUTE_TYPE,
                    b"public data"
                )
                .len(),
                1
            );
            assert!(
                find_by_bytes_attribute(
                    session,
                    CKO_DATA as CK_OBJECT_CLASS,
                    CKA_LABEL as CK_ATTRIBUTE_TYPE,
                    b"private data"
                )
                .is_empty()
            );
        }
        let mut pin = *b"data user password";
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG
            ),
            CKR_OK as CK_RV
        );
        for (is_certificate, private, label) in [
            (false, false, b"public data".as_slice()),
            (false, true, b"private data".as_slice()),
            (true, false, b"public certificate".as_slice()),
            (true, true, b"private certificate".as_slice()),
        ] {
            let value = if is_certificate {
                certificate.as_slice()
            } else {
                b"persistent data"
            };
            let class = if is_certificate {
                CKO_CERTIFICATE
            } else {
                CKO_DATA
            } as CK_OBJECT_CLASS;
            let handle = if round == 0 {
                create_test_data(session, is_certificate, true, private, value, label)
            } else {
                let found =
                    find_by_bytes_attribute(session, class, CKA_LABEL as CK_ATTRIBUTE_TYPE, label);
                assert_eq!(found.len(), 1);
                found[0]
            };
            assert_eq!(
                read_bytes_attribute(session, handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                value
            );
            if round == 0 {
                let mut copy = 0;
                assert_eq!(
                    crate::api::C_CopyObject(session, handle, std::ptr::null_mut(), 0, &mut copy),
                    CKR_OK as CK_RV
                );
                assert_ne!(copy, handle);
                assert_eq!(
                    find_by_bytes_attribute(session, class, CKA_LABEL as CK_ATTRIBUTE_TYPE, label)
                        .len(),
                    2
                );
                assert_eq!(crate::api::C_DestroyObject(session, copy), CKR_OK as CK_RV);
                assert_eq!(
                    read_bytes_attribute(session, handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                    value
                );
            }
            if round == 1 {
                let mut new_label = b"updated identity".to_vec();
                let mut attr = bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut new_label);
                assert_eq!(
                    crate::api::C_SetAttributeValue(session, handle, &mut attr, 1),
                    CKR_OK as CK_RV
                );
                assert_eq!(
                    read_bytes_attribute(session, handle, CKA_LABEL as CK_ATTRIBUTE_TYPE),
                    new_label
                );
                let mut session_token = CK_FALSE as CK_BBOOL;
                let mut attr = scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_token);
                let mut copy = 0;
                assert_eq!(
                    crate::api::C_CopyObject(session, handle, &mut attr, 1, &mut copy),
                    CKR_OK as CK_RV
                );
                assert_eq!(
                    read_bytes_attribute(session, copy, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                    value
                );
                assert_eq!(
                    crate::api::C_DestroyObject(session, handle),
                    CKR_OK as CK_RV
                );
                assert!(
                    find_by_bytes_attribute(session, class, CKA_LABEL as CK_ATTRIBUTE_TYPE, label)
                        .is_empty()
                );
            }
        }
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert!(
            find_by_bytes_attribute(
                session,
                CKO_CERTIFICATE as CK_OBJECT_CLASS,
                CKA_LABEL as CK_ATTRIBUTE_TYPE,
                b"private certificate"
            )
            .is_empty()
        );
        finalize_for_test();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn certificate_session_objects_are_shared_on_all_slots_and_validate_der() {
    let _guard = TEST_LOCK.lock().unwrap();
    let certificate = data_test_certificate();
    for kind in [
        crate::SlotKind::Software,
        crate::SlotKind::Host,
        crate::SlotKind::YubiHsm,
        crate::SlotKind::Fido2,
        crate::SlotKind::Ccid(crate::CcidApplication::Piv),
        crate::SlotKind::Ccid(crate::CcidApplication::OpenPgp),
    ] {
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let mut slot = test_slot(true);
        slot.kind = kind;
        install_test_slot_with_backend(94, Box::new(slot));
        install_test_session(94, 9401);
        install_test_session(94, 9402);
        let handle = create_test_data(
            9401,
            true,
            false,
            false,
            &certificate,
            b"session certificate",
        );
        assert_eq!(
            read_bytes_attribute(9402, handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            certificate
        );
        assert_eq!(
            read_bytes_attribute(9402, handle, CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE),
            [2, 2, 0, 128]
        );
        let mut copy = 0;
        assert_eq!(
            crate::api::C_CopyObject(9402, handle, std::ptr::null_mut(), 0, &mut copy),
            CKR_OK as CK_RV
        );
        let mut value = b"invalid DER".to_vec();
        let mut class = CKO_CERTIFICATE as CK_OBJECT_CLASS;
        let mut cert_type = CKC_X_509 as CK_CERTIFICATE_TYPE;
        let mut template = [
            scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
            scalar_attribute(CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE, &mut cert_type),
            bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
        ];
        let mut rejected = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_CreateObject(
                9401,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut rejected
            ),
            CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
        );
        assert_eq!(rejected, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
        assert_eq!(crate::api::C_CloseSession(9401), CKR_OK as CK_RV);
        let mut size = 0;
        assert_eq!(
            crate::api::C_GetObjectSize(9402, handle, &mut size),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
        assert_eq!(
            read_bytes_attribute(9402, copy, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            certificate
        );
        finalize_for_test();
    }
}
