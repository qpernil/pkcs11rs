#[test]
pub fn find_objects_filters_by_attribute_template() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut templ = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_matches_empty_attributes_exactly() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut value = [0x33u8; 16];
    let mut create_template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut empty_label_object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            create_template.as_mut_ptr(),
            create_template.len() as CK_ULONG,
            &mut empty_label_object
        ),
        CKR_OK as CK_RV
    );

    let mut empty_label_template = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            empty_label_template.as_mut_ptr(),
            empty_label_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 3];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], empty_label_object);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    empty_label_template[0].ulValueLen = 1;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            empty_label_template.as_mut_ptr(),
            empty_label_template.len() as CK_ULONG
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_validates_sessions_and_cleans_up_on_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(999, ::std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(999, ::std::ptr::null_mut(), 0, &mut count),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(999),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_removes_object_from_store_and_search() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_yubihsm_pseudo_public_objects_is_a_noop() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let handles: Vec<_> = [crate::YUBIHSM_PUBLIC_KEY, crate::YUBIHSM_WRAP_KEY_PUBLIC]
        .into_iter()
        .map(|object_type| {
            let object = crate::TokenObject {
                slot_id: Some(TEST_SLOT_ID),
                unique_id: format!("pseudo-public-{object_type:02x}"),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_EC as CK_KEY_TYPE,
                label: "YubiHSM pseudo-public key".to_owned(),
                id: vec![0, object_type],
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: true,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: None,
                owner_session: None,
                material: crate::KeyMaterial::YubiHsm {
                    id: object_type as u16,
                    object_type,
                    algorithm: crate::YUBIHSM_ALGO_EC_P256,
                    length: 32,
                    domains: 1,
                    capabilities: [0; 8],
                    delegated_capabilities: [0; 8],
                    public_key: vec![0x04; 65],
                    value: std::rc::Rc::new(std::cell::RefCell::new(None)),
                },
            };
            let mut context = crate::lock_context().unwrap();
            context.as_mut().unwrap().insert_object(object)
        })
        .collect();

    for handle in handles {
        assert_eq!(
            crate::C_DestroyObject(TEST_SESSION_HANDLE, handle),
            CKR_OK as CK_RV
        );
        let mut class = 0 as CK_OBJECT_CLASS;
        let mut attribute = CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        };
        assert_eq!(
            crate::C_GetAttributeValue(TEST_SESSION_HANDLE, handle, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_openpgp_objects_is_prohibited() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let base = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: "openpgp-01-certificate".to_owned(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "OpenPGP Signature certificate".to_owned(),
        id: vec![1],
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: crate::KeyMaterial::OpenPgpCertificate {
            value: vec![0x30, 0],
        },
    };
    let mut public = base.clone();
    public.unique_id = "openpgp-01-public".to_owned();
    public.class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    public.material = crate::KeyMaterial::OpenPgpPublic {
        algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
        public_key: vec![0x11; 256],
    };
    let mut private = base.clone();
    private.unique_id = "openpgp-01-private".to_owned();
    private.class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    private.private = true;
    private.sensitive = true;
    private.extractable = false;
    private.material = crate::KeyMaterial::OpenPgpPrivate {
        key_ref: crate::OpenPgpKeyRef::Signature,
        algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
        modulus: vec![0x11; 256],
        public_exponent: vec![1, 0, 1],
        public_key: Vec::new(),
        pin_policy: 0,
    };
    let handles = {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        [base, public, private]
            .into_iter()
            .map(|object| context.insert_object(object))
            .collect::<Vec<_>>()
    };

    for handle in handles {
        assert_eq!(
            crate::C_DestroyObject(TEST_SESSION_HANDLE, handle),
            CKR_ACTION_PROHIBITED as CK_RV
        );
        let context = crate::lock_context().unwrap();
        assert!(context
            .as_ref()
            .unwrap()
            .memory_objects
            .contains_key(&handle));
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_updates_active_search_results() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 1);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 2),
        CKR_OK as CK_RV
    );
    count = 999;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_adds_readable_findable_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Created public key";
    let mut id = [4u8, 5, 6];
    let mut value = [0xabu8; 16];
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(object, 3);

    let mut read_label = [0u8; 18];
    let mut read_verify = CK_FALSE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Created public key");
    assert_eq!(read_verify, CK_TRUE as CK_BBOOL);

    let mut search_label = *b"Created public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], object);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, object),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, read_attrs.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_preserves_all_supported_template_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Created private key";
    let mut id = [7u8, 8, 9, 10];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_FALSE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_FALSE as CK_BBOOL;
    let mut value = [0xcdu8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut read_class = 0 as CK_OBJECT_CLASS;
    let mut read_key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 19];
    let mut read_id = [0u8; 4];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_private = CK_FALSE as CK_BBOOL;
    let mut read_encrypt = CK_TRUE as CK_BBOOL;
    let mut read_decrypt = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_verify = CK_TRUE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(read_class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(read_key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Created private key");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_private, CK_TRUE as CK_BBOOL);
    assert_eq!(read_encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(read_decrypt, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);
    assert_eq!(read_verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_defaults_optional_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut value = [0x11u8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    let mut id_attr = CK_ATTRIBUTE {
        type_: CKA_ID as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(label_attr.ulValueLen, 0);
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut id_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(id_attr.ulValueLen, 0);

    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut bool_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            bool_attrs.as_mut_ptr(),
            bool_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(token, CK_FALSE as CK_BBOOL);
    assert_eq!(private, CK_FALSE as CK_BBOOL);
    assert_eq!(encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(decrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);
    assert_eq!(verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_reports_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0, &mut object),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1, &mut object),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut incomplete = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            incomplete.as_mut_ptr(),
            incomplete.len() as CK_ULONG,
            &mut object
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    let mut bad_class = [0u8; 1];
    let mut invalid_class_len = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: bad_class.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: bad_class.len() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_class_len.as_mut_ptr(),
            invalid_class_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut invalid_utf8 = [0xff];
    let mut invalid_label = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: invalid_utf8.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: invalid_utf8.len() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_label.as_mut_ptr(),
            invalid_label.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut invalid_bool_len = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool_len.as_mut_ptr(),
            invalid_bool_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut null_class_value = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            null_class_value.as_mut_ptr(),
            null_class_value.len() as CK_ULONG,
            &mut object
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            999,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn object_templates_reject_duplicates_and_updates_are_atomic() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut duplicate_class = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
    ];
    let mut handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            duplicate_class.as_mut_ptr(),
            duplicate_class.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut label = *b"not committed";
    let mut update = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            update.as_mut_ptr(),
            update.len() as CK_ULONG
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );
    let mut original_label = [0u8; 19];
    let mut read_label = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: original_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut read_label, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&original_label, b"Test RSA public key");

    let duplicate_label = [update[0], update[0]];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            duplicate_label.as_ptr() as CK_ATTRIBUTE_PTR,
            duplicate_label.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut generate_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        update[0],
        update[0],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            generate_template.as_mut_ptr(),
            generate_template.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_requires_and_imports_real_key_material() {
    let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
    let mut public_class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut private_class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut modulus = rsa.n().to_vec();
    let mut public_exponent = rsa.e().to_vec();
    let mut private_exponent = rsa.d().to_vec();
    let class_attribute = |class: &mut CK_OBJECT_CLASS| CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    let key_type_attribute = CK_ATTRIBUTE {
        type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
        pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
    };
    let modulus_attribute = CK_ATTRIBUTE {
        type_: CKA_MODULUS as CK_ATTRIBUTE_TYPE,
        pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: modulus.len() as CK_ULONG,
    };
    let public_exponent_attribute = CK_ATTRIBUTE {
        type_: CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
        pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: public_exponent.len() as CK_ULONG,
    };

    let public_template = [
        class_attribute(&mut public_class),
        key_type_attribute,
        modulus_attribute,
        public_exponent_attribute,
    ];
    assert!(matches!(
        crate::parse_create_object_template(&public_template)
            .unwrap()
            .material,
        crate::KeyMaterial::RsaPublic(_)
    ));

    let incomplete = [class_attribute(&mut public_class), key_type_attribute];
    assert!(matches!(
        crate::parse_create_object_template(&incomplete),
        Err(crate::error::Error::Generic(rv)) if rv == CKR_TEMPLATE_INCOMPLETE as CK_RV
    ));

    let private_template = [
        class_attribute(&mut private_class),
        key_type_attribute,
        modulus_attribute,
        public_exponent_attribute,
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE,
            pValue: private_exponent.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: private_exponent.len() as CK_ULONG,
        },
    ];
    let imported = crate::parse_create_object_template(&private_template).unwrap();
    assert!(matches!(
        imported.material,
        crate::KeyMaterial::RsaPrivate(_)
    ));
    assert!(!imported.local);
    assert_eq!(imported.key_gen_mechanism, None);
    assert_eq!(
        imported.attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
    assert_eq!(
        imported.attribute_value(CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );

    let extractable_private_template = crate::TokenObjectTemplate {
        class: Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS),
        extractable: Some(true),
        ..crate::TokenObjectTemplate::default()
    };
    assert!(matches!(
        extractable_private_template.into_object(),
        Err(rv) if rv == CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    ));
}

#[test]
pub fn copy_object_clones_and_overrides_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Copied public key";
    let mut id = [8u8, 6, 4, 2];
    let mut token = CK_FALSE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut copied
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied, 3);

    let mut copied_class = 0 as CK_OBJECT_CLASS;
    let mut copied_key_type = 999 as CK_KEY_TYPE;
    let mut copied_label = [0u8; 17];
    let mut copied_id = [0u8; 4];
    let mut copied_verify = CK_FALSE as CK_BBOOL;
    let mut copied_token = CK_TRUE as CK_BBOOL;
    let mut copied_private = CK_FALSE as CK_BBOOL;
    let mut copied_unique_id = [0u8; 8];
    let mut copied_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: copied_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: copied_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            pValue: copied_unique_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_unique_id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            copied,
            copied_attrs.as_mut_ptr(),
            copied_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied_class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(copied_key_type, CKK_RSA as CK_KEY_TYPE);
    assert_eq!(&copied_label, b"Copied public key");
    assert_eq!(copied_id, id);
    assert_eq!(copied_verify, CK_TRUE as CK_BBOOL);
    assert_eq!(copied_token, CK_FALSE as CK_BBOOL);
    assert_eq!(copied_private, CK_TRUE as CK_BBOOL);
    let copied_unique_id_len = copied_attrs[7].ulValueLen as usize;

    let mut original_label = [0u8; 19];
    let mut original_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: original_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut original_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&original_label, b"Test RSA public key");
    let mut original_unique_id = [0u8; 8];
    let mut original_unique_id_attr = CK_ATTRIBUTE {
        type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
        pValue: original_unique_id.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_unique_id.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut original_unique_id_attr, 1),
        CKR_OK as CK_RV
    );
    assert_ne!(
        &copied_unique_id[..copied_unique_id_len],
        &original_unique_id[..original_unique_id_attr.ulValueLen as usize]
    );

    let mut search_label = *b"Copied public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], copied);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn copy_object_reports_template_and_handle_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            999,
            ::std::ptr::null_mut(),
            0,
            &mut copied
        ),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            1,
            &mut copied
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            readonly_attr.as_mut_ptr(),
            readonly_attr.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            999,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, unknown.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_attribute_storage_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>()
            + b"Test RSA public key".len()
            + 2
            + 7
            + 256
            + 3
            + 1
            + 8) as CK_ULONG
    );

    let mut label = *b"Short";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 1 + 7 + 256 + 3 + 1 + 8)
            as CK_ULONG
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_created_object_size_and_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Sized key";
    let mut id = [1u8, 2, 3, 4, 5];
    let mut value = [0x44u8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 1 + 11 + 1 + 16)
            as CK_ULONG
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 999, &mut size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(999, object, &mut size),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_sizes_and_values() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        label_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut label = [0u8; 19];
    label_attr.pValue = label.as_mut_ptr() as CK_VOID_PTR;
    label_attr.ulValueLen = label.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&label, b"Test RSA public key");

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);

    let mut wrap = CK_FALSE as CK_BBOOL;
    let mut unwrap = CK_FALSE as CK_BBOOL;
    let mut sign_recover = CK_FALSE as CK_BBOOL;
    let mut verify_recover = CK_FALSE as CK_BBOOL;
    let mut wrap_with_trusted = CK_FALSE as CK_BBOOL;
    let mut operation_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_WRAP as CK_ATTRIBUTE_TYPE,
            pValue: &mut wrap as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
            pValue: &mut unwrap as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign_recover as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify_recover as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            pValue: &mut wrap_with_trusted as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            operation_attrs.as_mut_ptr(),
            operation_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        (
            wrap,
            unwrap,
            sign_recover,
            verify_recover,
            wrap_with_trusted
        ),
        (
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL
        )
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reads_certificate_values() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let certificate = b"synthetic certificate".to_vec();
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: "openpgp-certificate".to_owned(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "OpenPGP certificate".to_owned(),
        id: vec![1],
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: crate::KeyMaterial::OpenPgpCertificate {
            value: certificate.clone(),
        },
    };
    let object_handle = {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().insert_object(object)
    };

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object_handle, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value_attribute.ulValueLen, certificate.len() as CK_ULONG);

    let mut value = vec![0; certificate.len()];
    value_attribute.pValue = value.as_mut_ptr() as CK_VOID_PTR;
    value_attribute.ulValueLen = value.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object_handle, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value, certificate);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn issuer_sd_objects_expose_values_but_cannot_be_copied_or_destroyed() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let value = vec![0xb1, 32];
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: "issuer-sd-key-13-01".to_owned(),
        class: CKO_DATA as CK_OBJECT_CLASS,
        key_type: 0,
        label: "Issuer SD SCP11b KVN 1".to_owned(),
        id: vec![0x13, 1],
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: crate::KeyMaterial::IssuerSecurityDomainData {
            value: value.clone(),
            application: "Issuer SD".to_owned(),
            object_id: Vec::new(),
        },
    };
    let object_handle = {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().insert_object(object)
    };

    let mut returned = [0u8; 2];
    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: returned.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: returned.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object_handle, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(returned.as_slice(), value);

    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            object_handle,
            ::std::ptr::null_mut(),
            0,
            &mut copied,
        ),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, object_handle),
        CKR_ACTION_PROHIBITED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut small_label = [0u8; 4];
    let mut small_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: small_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: small_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut small_attr, 1),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(
        small_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut unknown_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut unknown_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        unknown_attr.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 999, &mut unknown_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(999, 1, &mut unknown_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_updates_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Renamed public key";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );

    let mut read_label = [0u8; 18];
    let mut read_id = [0u8; 3];
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Renamed public key");
    assert_eq!(read_id, id);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut readonly_attr, 1),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut invalid_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut invalid_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );

    let mut bad_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 1,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut bad_attr, 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 999, &mut invalid_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(999, 1, &mut invalid_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}
