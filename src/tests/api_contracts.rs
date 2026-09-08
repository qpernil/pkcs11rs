use super::*;

#[test]
fn data_session_objects_share_visibility_and_follow_creator_and_login_lifetimes() {
    let _guard = TEST_LOCK.lock().unwrap();
    for kind in [
        crate::SlotKind::Software,
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

        // Neither an impossible input length nor unsupported persistence can publish an object.
        attribute.ulValueLen = CK_ULONG::MAX;
        assert_eq!(
            crate::api::C_SetAttributeValue(8202, copy, &mut attribute, 1),
            CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
        );
        let mut token = CK_TRUE as CK_BBOOL;
        let mut attribute = scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token);
        let mut rejected = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_CopyObject(8202, public, &mut attribute, 1, &mut rejected),
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV
        );
        assert_eq!(rejected, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

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
