#[test]
pub fn generate_key_creates_secret_key_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut label = *b"Generated secret";
    let mut id = [3u8, 1, 4];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut value_len = 32 as CK_ULONG;
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
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(key, 3);

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 16];
    let mut read_id = [0u8; 3];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_value_len = 0 as CK_ULONG;
    let mut read_sensitive = CK_FALSE as CK_BBOOL;
    let mut read_extractable = CK_TRUE as CK_BBOOL;
    let mut read_always_sensitive = CK_FALSE as CK_BBOOL;
    let mut read_never_extractable = CK_FALSE as CK_BBOOL;
    let mut read_unique_id = [0u8; 8];
    let mut read_local = CK_FALSE as CK_BBOOL;
    let mut read_key_gen_mechanism = CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE;
    let mut read_attrs = [
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
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_always_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_never_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_unique_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_unique_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_local as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_key_gen_mechanism as *mut CK_MECHANISM_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_MECHANISM_TYPE>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Generated secret");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);
    assert_eq!(read_value_len, value_len);
    assert_eq!(read_sensitive, CK_TRUE as CK_BBOOL);
    assert_eq!(read_extractable, CK_FALSE as CK_BBOOL);
    assert_eq!(read_always_sensitive, CK_TRUE as CK_BBOOL);
    assert_eq!(read_never_extractable, CK_TRUE as CK_BBOOL);
    assert_eq!(&read_unique_id[..read_attrs[11].ulValueLen as usize], b"3");
    assert_eq!(read_local, CK_TRUE as CK_BBOOL);
    assert_eq!(
        read_key_gen_mechanism,
        CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE
    );
    {
        let context = crate::lock_context().unwrap();
        let object = context
            .as_ref()
            .unwrap()
            .memory_objects
            .get(&key)
            .unwrap();
        match &object.material {
            crate::KeyMaterial::Secret(value) => {
                assert_eq!(value.len(), value_len as usize);
                assert!(value.iter().any(|byte| *byte != 0));
            }
            material => panic!("expected generated secret material, got {material:?}"),
        }
    }

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    assert_eq!(
        value_attribute.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    let mut rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut rsa_mechanism, key),
        CKR_KEY_TYPE_INCONSISTENT as CK_RV
    );

    let mut search_label = *b"Generated secret";
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
    assert_eq!(objects[0], key);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generated_secret_key_enforces_sensitivity_policy() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 24 as CK_ULONG;
    let mut sensitive = CK_FALSE as CK_BBOOL;
    let mut extractable = CK_FALSE as CK_BBOOL;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    assert_eq!(
        value_attribute.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    sensitive = CK_TRUE as CK_BBOOL;
    extractable = CK_FALSE as CK_BBOOL;
    let mut harden = [
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            harden.as_mut_ptr(),
            harden.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );

    let mut make_non_sensitive = CK_FALSE as CK_BBOOL;
    let mut make_non_sensitive_attribute = CK_ATTRIBUTE {
        type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
        pValue: &mut make_non_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            &mut make_non_sensitive_attribute,
            1
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );
    let mut make_extractable = CK_TRUE as CK_BBOOL;
    let mut make_extractable_attribute = CK_ATTRIBUTE {
        type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
        pValue: &mut make_extractable as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, key, &mut make_extractable_attribute, 1),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut always_sensitive = CK_TRUE as CK_BBOOL;
    let mut never_extractable = CK_TRUE as CK_BBOOL;
    let mut history = [
        CK_ATTRIBUTE {
            type_: CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut always_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut never_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            history.as_mut_ptr(),
            history.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(always_sensitive, CK_FALSE as CK_BBOOL);
    assert_eq!(never_extractable, CK_TRUE as CK_BBOOL);

    value_attribute.pValue = ::std::ptr::null_mut();
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn session_objects_are_private_to_their_owner_and_removed_on_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut class_attribute = CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut class_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE + 1, key, &mut class_attribute, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    let context = crate::lock_context().unwrap();
    assert!(!context
        .as_ref()
        .unwrap()
        .memory_objects
        .contains_key(&key));
    drop(context);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn removing_a_dynamic_slot_clears_its_runtime_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.dynamic_slots.insert(TEST_SLOT_ID);
        let mut session_object = context.memory_objects.get(&1).unwrap().clone();
        session_object.unique_id.clear();
        session_object.token = false;
        session_object.owner_session = Some(TEST_SESSION_HANDLE);
        let object_handle = context.insert_object(session_object);
        context.find_operations.insert(
            TEST_SESSION_HANDLE,
            crate::FindOperation {
                objects: vec![object_handle],
                next: 0,
            },
        );

        context.close_slot_state(TEST_SLOT_ID, true);
        context.slots.remove(&TEST_SLOT_ID);
        context.dynamic_slots.remove(&TEST_SLOT_ID);
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
        assert!(!context.find_operations.contains_key(&TEST_SESSION_HANDLE));
        assert!(!context.logged_in_slots.contains_key(&TEST_SLOT_ID));
        assert!(context
            .memory_objects
            .values()
            .all(|object| object.slot_id != Some(TEST_SLOT_ID)));
    }
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn slot_info_does_not_rescan_dynamic_slots() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(false)));
        context.dynamic_slots.insert(TEST_SLOT_ID);
    }

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert_eq!(
        crate::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_key_reports_mechanism_and_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(999, &mut mechanism, ::std::ptr::null_mut(), 0, &mut key),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            1,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut unsupported,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut inconsistent = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            inconsistent.as_mut_ptr(),
            inconsistent.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut key
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut zero_len = 0 as CK_ULONG;
    let mut zero_len_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut zero_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            zero_len_template.as_mut_ptr(),
            zero_len_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );

    let mut oversized_len = 513 as CK_ULONG;
    let mut oversized_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut oversized_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            oversized_template.as_mut_ptr(),
            oversized_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );

    let mut duplicate_len = 16 as CK_ULONG;
    let duplicate_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut duplicate_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let mut duplicate_template = [duplicate_attribute, duplicate_attribute];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            duplicate_template.as_mut_ptr(),
            duplicate_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, invalid_bool.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn yubihsm_key_pair_generation_requires_token_objects() {
    let mut modulus_bits = 2048 as CK_ULONG;
    let mut session_object = CK_FALSE as CK_BBOOL;
    let mut token_object = CK_TRUE as CK_BBOOL;
    let modulus_attribute = CK_ATTRIBUTE {
        type_: CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
        pValue: (&mut modulus_bits as *mut CK_ULONG).cast(),
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let session_attribute = CK_ATTRIBUTE {
        type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        pValue: (&mut session_object as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    let token_attribute = CK_ATTRIBUTE {
        type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        pValue: (&mut token_object as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    let session_public_template = [modulus_attribute, session_attribute];
    let token_public_template = [modulus_attribute, token_attribute];
    let session_private_template = [session_attribute];
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    for (public_template, private_template) in [
        (&session_public_template[..], &[][..]),
        (&token_public_template[..], &session_private_template[..]),
    ] {
        let rv: CK_RV = crate::yubihsm_generate_key_pair_command(
            &mechanism,
            public_template,
            private_template,
        )
        .unwrap_err()
        .into();
        assert_eq!(rv, CKR_TEMPLATE_INCONSISTENT as CK_RV);
    }
}

#[test]
pub fn yubihsm_key_pair_generation_requires_matching_ids() {
    let mut modulus_bits = 2048 as CK_ULONG;
    let mut public_id = [0, 1];
    let mut private_id = [0, 2];
    let modulus_attribute = CK_ATTRIBUTE {
        type_: CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
        pValue: (&mut modulus_bits as *mut CK_ULONG).cast(),
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let public_id_attribute = CK_ATTRIBUTE {
        type_: CKA_ID as CK_ATTRIBUTE_TYPE,
        pValue: public_id.as_mut_ptr().cast(),
        ulValueLen: public_id.len() as CK_ULONG,
    };
    let private_id_attribute = CK_ATTRIBUTE {
        type_: CKA_ID as CK_ATTRIBUTE_TYPE,
        pValue: private_id.as_mut_ptr().cast(),
        ulValueLen: private_id.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let public_template = [modulus_attribute, public_id_attribute];

    for private_template in [&[][..], &[private_id_attribute][..]] {
        let rv: CK_RV = crate::yubihsm_generate_key_pair_command(
            &mechanism,
            &public_template,
            private_template,
        )
        .unwrap_err()
        .into();
        assert_eq!(rv, CKR_TEMPLATE_INCONSISTENT as CK_RV);
    }

    private_id.copy_from_slice(&public_id);
    let (object, _) = crate::yubihsm_generate_key_pair_command(
        &mechanism,
        &public_template,
        &[private_id_attribute],
    )
    .unwrap();
    assert_eq!(object.id, public_id);

    let (object, _) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &[modulus_attribute], &[]).unwrap();
    assert!(object.id.is_empty());
}

#[test]
pub fn generate_random_validates_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut random_data = [0u8; 16];

    assert_eq!(
        crate::C_GenerateRandom(1, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GenerateRandom(999, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}
