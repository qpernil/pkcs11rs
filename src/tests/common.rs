#[cfg(test)]
use crate::pkcs11::*;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TEST_SLOT_LOGGED_IN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static TEST_SLOT_LOGIN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_CONTEXT_LOGIN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_SLOT_LOGOUT_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_SLOT_FAIL_LOGOUT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
const PKCS11_2_40_FUNCTION_COUNT: usize = 68;
const PKCS11_3_0_FUNCTION_COUNT: usize = 24;
const PKCS11_3_2_FUNCTION_COUNT: usize = 12;
const TEST_SLOT_ID: CK_SLOT_ID = 77;
const TEST_SESSION_HANDLE: CK_SESSION_HANDLE = 88;

#[test]
fn debug_level_configuration_has_three_modes() {
    assert_eq!(crate::parse_debug_level(None), Ok(0));
    assert_eq!(crate::parse_debug_level(Some("0")), Ok(0));
    assert_eq!(crate::parse_debug_level(Some("1")), Ok(1));
    assert_eq!(crate::parse_debug_level(Some("2")), Ok(2));
    assert_eq!(
        crate::parse_debug_level(Some("enabled")),
        Err(CKR_ARGUMENTS_BAD as CK_RV)
    );
    assert_eq!(
        crate::parse_debug_level(Some("")),
        Err(CKR_ARGUMENTS_BAD as CK_RV)
    );
}

fn finalize_for_test() {
    let _ = crate::C_Finalize(::std::ptr::null_mut());
    crate::reset_object_handles();
}

#[test]
fn yubihsm_abi_operations_emit_authenticated_device_commands() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, corrupt_response_mac, _trust) =
        crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut public_info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::C_GetSessionInfo(session, &mut public_info),
        CKR_OK as CK_RV
    );
    assert_eq!(public_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert!(commands.borrow().is_empty());
    let mut mechanism_count = 0;
    assert_eq!(
        crate::C_GetMechanismList(SLOT_ID, ::std::ptr::null_mut(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    let mut mechanisms = vec![0; mechanism_count as usize];
    assert_eq!(
        crate::C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    assert!(mechanisms.contains(&(CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE)));
    assert!(mechanisms.contains(&(CKM_AES_CBC as CK_MECHANISM_TYPE)));
    assert!(mechanisms.contains(&(CKM_AES_GCM as CK_MECHANISM_TYPE)));
    let mut mechanism_info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(
            SLOT_ID,
            CKM_AES_CBC as CK_MECHANISM_TYPE,
            &mut mechanism_info
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        (mechanism_info.ulMinKeySize, mechanism_info.ulMaxKeySize),
        (16, 32)
    );
    assert_ne!(mechanism_info.flags & CKF_HW as CK_FLAGS, 0);
    let mut pin = *b"0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut find_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_FindObjectsInit(session, find_template.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    let mut private_key = 0;
    let mut found = 0;
    assert_eq!(
        crate::C_FindObjects(session, &mut private_key, 1, &mut found),
        CKR_OK as CK_RV
    );
    assert_eq!(found, 1);
    assert_eq!(crate::C_FindObjectsFinal(session), CKR_OK as CK_RV);

    let mut public_class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    find_template[0].pValue = (&mut public_class as *mut CK_OBJECT_CLASS).cast();
    assert_eq!(
        crate::C_FindObjectsInit(session, find_template.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    let mut public_key = 0;
    assert_eq!(
        crate::C_FindObjects(session, &mut public_key, 1, &mut found),
        CKR_OK as CK_RV
    );
    assert_eq!(found, 1);
    assert_eq!(crate::C_FindObjectsFinal(session), CKR_OK as CK_RV);

    let mut raw_rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_X_509 as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(session, &mut raw_rsa_mechanism, private_key),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut plaintext = *b"secret";
    let mut ciphertext = [0u8; 256];
    let mut ciphertext_len = ciphertext.len() as CK_ULONG;
    assert_eq!(
        crate::C_EncryptInit(session, &mut rsa_mechanism, public_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(ciphertext_len, 256);
    let mut too_small = [0u8; 1];
    let mut decrypted_len = too_small.len() as CK_ULONG;
    assert_eq!(
        crate::C_DecryptInit(session, &mut rsa_mechanism, private_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            too_small.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(decrypted_len, b"plaintext".len() as CK_ULONG);
    let decrypt_commands = || {
        commands
            .borrow()
            .iter()
            .filter(|(code, _)| *code == crate::YubiHsmCommandCode::DecryptPkcs1 as u8)
            .count()
    };
    assert_eq!(decrypt_commands(), 1);
    {
        let context = crate::lock_context().unwrap();
        let debug = format!(
            "{:?}",
            context
                .as_ref()
                .unwrap()
                .decrypt_operations
                .get(&session)
                .unwrap()
        );
        assert!(debug.contains("result_length"));
        assert!(!debug.contains("plaintext"));
    }

    let mut decrypted = [0u8; 32];
    decrypted_len = decrypted.len() as CK_ULONG;
    assert_eq!(
        crate::C_Decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&decrypted[..decrypted_len as usize], b"plaintext");
    assert_eq!(decrypt_commands(), 1);

    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(session, &mut sign_mechanism, private_key),
        CKR_OK as CK_RV
    );
    let mut message = *b"message";
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);
    assert!(signature.iter().all(|byte| *byte == 0x5a));

    let mut modulus_bits = 2048 as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        CK_ATTRIBUTE {
            type_: CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            pValue: (&mut modulus_bits as *mut CK_ULONG).cast(),
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut token as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: (&mut verify as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut private_template = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut token as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sign as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sensitive as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut generate_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut generated_public = 0;
    let mut generated_private = 0;
    assert_eq!(
        crate::C_GenerateKeyPair(
            session,
            &mut generate_mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut generated_public,
            &mut generated_private,
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(generated_public, generated_private);
    assert_eq!(
        crate::C_DestroyObject(session, generated_private),
        CKR_OK as CK_RV
    );

    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(crate::C_GetSessionInfo(session, &mut info), CKR_OK as CK_RV);
    let command_codes: Vec<u8> = commands
        .borrow()
        .iter()
        .map(|(command, _)| *command)
        .collect();
    for command in [
        crate::yubihsm::CommandCode::ListObjects as u8,
        crate::yubihsm::CommandCode::GetObjectInfo as u8,
        crate::yubihsm::CommandCode::GetPublicKey as u8,
        crate::yubihsm::CommandCode::SignPkcs1 as u8,
        crate::yubihsm::CommandCode::DecryptPkcs1 as u8,
        crate::yubihsm::CommandCode::GenerateAsymmetricKey as u8,
        crate::yubihsm::CommandCode::DeleteObject as u8,
        crate::yubihsm::CommandCode::GetStorageInfo as u8,
    ] {
        assert!(
            command_codes.contains(&command),
            "missing command {command:#04x}"
        );
    }

    corrupt_response_mac.set(true);
    assert_eq!(
        crate::C_GetSessionInfo(session, &mut info),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert_eq!(crate::C_Logout(session), CKR_USER_NOT_LOGGED_IN as CK_RV);
    finalize_for_test();
}

#[test]
fn yubihsm_abi_login_accepts_asymmetric_authentication_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"@0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert!(commands
        .borrow()
        .iter()
        .any(|(command, _)| *command == crate::yubihsm::CommandCode::ListObjects as u8));
    assert_eq!(crate::C_Logout(session), CKR_OK as CK_RV);
    finalize_for_test();
}

#[test]
fn yubihsm_ec_discovery_exposes_named_curve_and_der_encoded_point() {
    let label = "p521-key".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x07]),
        id: 0x1234,
        length: 66,
        domains: 1,
        object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
        algorithm: crate::YUBIHSM_ALGO_EC_P521,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let public_key = crate::yubihsm::PublicKey {
        algorithm: crate::YUBIHSM_ALGO_EC_P521,
        key: vec![0x5a; 132],
    };
    let objects = crate::yubihsm_token_objects(99, info, Some(public_key)).unwrap();
    let public = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        public.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
        Some(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23])
    );
    let point = public
        .attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(&point[..4], &[0x04, 0x81, 0x85, 0x04]);
    assert_eq!(point.len(), 136);
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        private.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
}

#[test]
fn yubihsm_unknown_algorithms_use_vendor_defined_key_types() {
    let unknown_algorithm = 0xfe;
    let label = "unknown-algo".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x05]),
        id: 0x1234,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
        algorithm: unknown_algorithm,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let public_key = crate::yubihsm::PublicKey {
        algorithm: unknown_algorithm,
        key: vec![0x5a; 32],
    };
    let objects = crate::yubihsm_token_objects(99, info, Some(public_key)).unwrap();
    let vendor_key_type = CKK_VENDOR_DEFINED as CK_KEY_TYPE + unknown_algorithm as CK_KEY_TYPE;

    assert_eq!(objects.len(), 2);
    for object in &objects {
        assert_eq!(object.key_type, vendor_key_type);
        assert_eq!(
            object.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
            Some(crate::ulong_attribute(
                CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE,
            ))
        );
        assert!(!object.sign);
        assert!(!object.encrypt);
        assert!(!object.decrypt);
        assert!(!object.verify);
    }
    assert!(objects
        .iter()
        .all(|object| object.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE));
}

#[test]
fn yubihsm_authentication_keys_are_non_operational_generic_secrets() {
    let capabilities =
        crate::yubihsm_capabilities(&[0x05, 0x09, 0x0b, 0x16, 0x32, 0x33, 0x34, 0x35]);
    let delegated_capabilities = crate::yubihsm_capabilities(&[0x04, 0x32]);
    for (algorithm, length) in [
        (crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION, 32),
        (crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION, 64),
    ] {
        let label = "session-auth".to_owned();
        let info = crate::yubihsm::ObjectInfo {
            capabilities,
            id: 1,
            length,
            domains: 0x0003,
            object_type: crate::YUBIHSM_AUTHENTICATION_KEY,
            algorithm,
            sequence: 1,
            origin: 1,
            label,
            delegated_capabilities,
        };

        let objects = crate::yubihsm_token_objects(99, info, None).unwrap();
        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert_eq!(object.class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
        assert_eq!(object.key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
        assert!(!object.encrypt);
        assert!(!object.decrypt);
        assert!(!object.sign);
        assert!(!object.verify);
        assert!(!object.derive);
        assert_eq!(
            object.attribute_value(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE),
            Some(crate::ulong_attribute(length as CK_ULONG))
        );
        assert_eq!(
            object.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
            Some(crate::ulong_attribute(
                CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE,
            ))
        );
        match &object.material {
            crate::KeyMaterial::YubiHsm {
                algorithm: stored_algorithm,
                domains,
                capabilities: stored_capabilities,
                delegated_capabilities: stored_delegated_capabilities,
                ..
            } => {
                assert_eq!(*stored_algorithm, algorithm);
                assert_eq!(*domains, 0x0003);
                assert_eq!(*stored_capabilities, capabilities);
                assert_eq!(*stored_delegated_capabilities, delegated_capabilities);
            }
            _ => panic!("expected YubiHSM key material"),
        }
    }
}

#[test]
fn yubihsm_wrap_key_object_types_match_the_reference_module() {
    let info = |id, object_type, algorithm, length, capabilities, name: &[u8]| {
        let label = std::str::from_utf8(name).unwrap().to_owned();
        crate::yubihsm::ObjectInfo {
            capabilities: crate::yubihsm_capabilities(capabilities),
            id,
            length,
            domains: 1,
            object_type,
            algorithm,
            sequence: 1,
            origin: 1,
            label,
            delegated_capabilities: [0; 8],
        }
    };

    let ccm_info = info(
        8,
        crate::YUBIHSM_WRAP_KEY,
        crate::YUBIHSM_ALGO_AES128_CCM_WRAP,
        16,
        &[0x0c, 0x0d, 0x25, 0x26],
        b"ccm-wrap",
    );
    assert!(!crate::yubihsm_object_has_public_key(&ccm_info));
    let ccm = crate::yubihsm_token_objects(99, ccm_info, None).unwrap();
    assert_eq!(ccm.len(), 1);
    assert_eq!(ccm[0].class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(ccm[0].key_type, crate::CKK_YUBICO_AES128_CCM_WRAP);
    assert!(ccm[0].encrypt);
    assert!(ccm[0].decrypt);
    assert_eq!(
        ccm[0].attribute_value(CKA_WRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert_eq!(
        ccm[0].attribute_value(CKA_UNWRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );

    let rsa_public = crate::yubihsm::PublicKey {
        algorithm: crate::YUBIHSM_ALGO_RSA_2048,
        key: vec![0xa5; 256],
    };
    let rsa_info = info(
        9,
        crate::YUBIHSM_WRAP_KEY,
        crate::YUBIHSM_ALGO_RSA_2048,
        256,
        &[0x0c, 0x0d],
        b"rsa-wrap",
    );
    assert!(crate::yubihsm_object_has_public_key(&rsa_info));
    let rsa = crate::yubihsm_token_objects(99, rsa_info, Some(rsa_public.clone())).unwrap();
    assert_eq!(rsa.len(), 2);
    let private = rsa
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let public = rsa
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.key_type, CKK_RSA as CK_KEY_TYPE);
    assert!(!private.sign && !private.decrypt);
    assert_eq!(
        private.attribute_value(CKA_WRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert_eq!(
        private.attribute_value(CKA_UNWRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert!(!public.encrypt && !public.verify);
    assert_eq!(
        public.attribute_value(CKA_WRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
    assert!(matches!(
        public.material,
        crate::KeyMaterial::YubiHsm {
            object_type: crate::YUBIHSM_WRAP_KEY_PUBLIC,
            ..
        }
    ));

    let public_wrap = crate::yubihsm_token_objects(
        99,
        info(
            10,
            crate::YUBIHSM_PUBLIC_WRAP_KEY,
            crate::YUBIHSM_ALGO_RSA_2048,
            256,
            &[0x0c],
            b"public-wrap",
        ),
        Some(rsa_public),
    )
    .unwrap();
    assert_eq!(public_wrap.len(), 1);
    assert_eq!(public_wrap[0].class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(public_wrap[0].key_type, CKK_RSA as CK_KEY_TYPE);
    assert_eq!(
        public_wrap[0].attribute_value(CKA_WRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert_eq!(
        public_wrap[0].attribute_value(CKA_UNWRAP as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
    assert_eq!(
        public_wrap[0].attribute_value(CKA_MODULUS as CK_ATTRIBUTE_TYPE),
        Some(vec![0xa5; 256])
    );
}

#[test]
fn yubihsm_opaque_objects_match_reference_pkcs11_classes() {
    let opaque = |id, algorithm, name: &[u8]| {
        let label = std::str::from_utf8(name).unwrap().to_owned();
        crate::yubihsm::ObjectInfo {
            capabilities: [0; 8],
            id,
            length: 12,
            domains: 1,
            object_type: crate::YUBIHSM_OPAQUE,
            algorithm,
            sequence: 1,
            origin: 1,
            label,
            delegated_capabilities: [0; 8],
        }
    };

    let data = crate::yubihsm_token_objects(
        99,
        opaque(5, crate::YUBIHSM_ALGO_OPAQUE_DATA, b"opaque-data"),
        None,
    )
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(data.class, CKO_DATA as CK_OBJECT_CLASS);
    assert_eq!(
        data.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
        Some(b"Opaque object".to_vec())
    );
    assert_eq!(
        data.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(Vec::new())
    );
    assert_eq!(
        data.attribute_value(CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE),
        Some(crate::bool_attribute(true))
    );
    assert_eq!(
        data.attribute_value(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE),
        Some(crate::bool_attribute(false))
    );
    assert!(data
        .attribute_value(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
        .is_none());
    assert!(data
        .attribute_value(CKA_ENCRYPT as CK_ATTRIBUTE_TYPE)
        .is_none());

    let certificate = crate::yubihsm_token_objects(
        99,
        opaque(
            6,
            crate::YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            b"opaque-cert",
        ),
        None,
    )
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(certificate.class, CKO_CERTIFICATE as CK_OBJECT_CLASS);
    assert_eq!(
        certificate.attribute_value(CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE),
        Some(crate::ulong_attribute(CKC_X_509 as CK_ULONG))
    );
    for attribute in [CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER] {
        assert!(certificate
            .attribute_value(attribute as CK_ATTRIBUTE_TYPE)
            .is_none());
    }
}

#[test]
fn certificate_serial_numbers_are_der_integers() {
    assert_eq!(crate::der_integer(&[]).unwrap(), [0x02, 0x01, 0x00]);
    assert_eq!(
        crate::der_integer(&[0, 0x7f]).unwrap(),
        [0x02, 0x01, 0x7f]
    );
    assert_eq!(
        crate::der_integer(&[0x80]).unwrap(),
        [0x02, 0x02, 0x00, 0x80]
    );
}

#[test]
fn yubihsm_internal_metadata_opaque_objects_are_hidden() {
    let label = "Meta object 0001".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: [0; 8],
        id: 7,
        length: 12,
        domains: 1,
        object_type: crate::YUBIHSM_OPAQUE,
        algorithm: crate::YUBIHSM_ALGO_OPAQUE_DATA,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    assert!(crate::yubihsm_token_objects(99, info, None)
        .unwrap()
        .is_empty());
}

#[test]
fn yubihsm_secret_key_sign_capability_matches_key_type() {
    let label = "hmac-secret".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x16]),
        id: 0x1234,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_HMAC_KEY,
        algorithm: crate::YUBIHSM_ALGO_HMAC_SHA256,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let objects = crate::yubihsm_token_objects(99, info, None).unwrap();

    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert!(objects[0].sign);

    let label = "aes-secret".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x16]),
        id: 0x1235,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_SYMMETRIC_KEY,
        algorithm: crate::YUBIHSM_ALGO_AES256,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let objects = crate::yubihsm_token_objects(99, info.clone(), None).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert!(!objects[0].sign);

    let mut gcm_info = info;
    gcm_info.capabilities = crate::yubihsm_capabilities(&[0x33]);
    let objects = crate::yubihsm_token_objects(99, gcm_info.clone(), None).unwrap();
    assert!(objects[0].encrypt);
    assert!(!objects[0].decrypt);
    gcm_info.capabilities = crate::yubihsm_capabilities(&[0x32, 0x33]);
    let objects = crate::yubihsm_token_objects(99, gcm_info, None).unwrap();
    assert!(objects[0].decrypt);
}

fn test_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn test_aes_ecb(key: &[u8], input: &[u8]) -> Result<Vec<u8>, crate::error::Error> {
    let cipher = match key.len() {
        16 => openssl::symm::Cipher::aes_128_ecb(),
        24 => openssl::symm::Cipher::aes_192_ecb(),
        32 => openssl::symm::Cipher::aes_256_ecb(),
        _ => return Err(CKR_KEY_SIZE_RANGE.into()),
    };
    let mut crypter = openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None)?;
    crypter.pad(false);
    let mut output = vec![0; input.len() + 16];
    let written = crypter.update(input, &mut output)?;
    let final_written = crypter.finalize(&mut output[written..])?;
    output.truncate(written + final_written);
    Ok(output)
}

fn insert_yubihsm_aes_test_object(slot_id: CK_SLOT_ID, key_id: u16) -> CK_OBJECT_HANDLE {
    let object = crate::TokenObject {
        slot_id: Some(slot_id),
        unique_id: format!("test-aes-{key_id}"),
        class: CKO_SECRET_KEY as CK_OBJECT_CLASS,
        key_type: CKK_AES as CK_KEY_TYPE,
        label: "Test AES key".to_owned(),
        id: key_id.to_be_bytes().to_vec(),
        token: true,
        private: true,
        encrypt: true,
        decrypt: true,
        sign: false,
        verify: false,
        derive: false,
        sensitive: true,
        extractable: false,
        always_sensitive: true,
        never_extractable: true,
        local: true,
        key_gen_mechanism: Some(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE),
        owner_session: None,
        material: crate::KeyMaterial::YubiHsm {
            id: key_id,
            object_type: crate::YUBIHSM_SYMMETRIC_KEY,
            algorithm: crate::YUBIHSM_ALGO_AES128,
            length: 16,
            domains: 0xffff,
            capabilities: crate::yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]),
            delegated_capabilities: [0; 8],
            public_key: Vec::new(),
            value: std::rc::Rc::new(std::cell::RefCell::new(None)),
        },
    };
    let mut context = crate::lock_context().unwrap();
    context.as_mut().unwrap().insert_object(object)
}

fn assert_pkcs11_aes_vector(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    iv: Option<&mut [u8; 16]>,
    plaintext: &[u8],
    ciphertext: &[u8],
) {
    let (parameter, parameter_len) = match iv {
        Some(iv) => (iv.as_mut_ptr().cast(), iv.len() as CK_ULONG),
        None => (std::ptr::null_mut(), 0),
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: parameter,
        ulParameterLen: parameter_len,
    };
    let mut input = plaintext.to_vec();
    let mut output = vec![0; ciphertext.len()];
    let mut output_len = output.len() as CK_ULONG;
    assert_eq!(
        crate::C_EncryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Encrypt(
            session,
            input.as_mut_ptr(),
            input.len() as CK_ULONG,
            output.as_mut_ptr(),
            &mut output_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&output[..output_len as usize], ciphertext);

    let mut input = ciphertext.to_vec();
    let mut output = vec![0; plaintext.len()];
    let mut output_len = output.len() as CK_ULONG;
    assert_eq!(
        crate::C_DecryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Decrypt(
            session,
            input.as_mut_ptr(),
            input.len() as CK_ULONG,
            output.as_mut_ptr(),
            &mut output_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&output[..output_len as usize], plaintext);
}

#[test]
fn aes_gcm_matches_nist_vectors_and_rejects_modified_tags() {
    let zero_key = [0; 16];
    let zero_parameters = crate::GcmParameters {
        iv: vec![0; 12],
        aad: Vec::new(),
        tag_bits: 128,
    };
    let encrypted = crate::aes_gcm(&zero_parameters, &[0; 16], true, |blocks| {
        test_aes_ecb(&zero_key, blocks)
    })
    .unwrap();
    assert_eq!(
        encrypted,
        test_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    );
    assert_eq!(
        crate::aes_gcm(&zero_parameters, &encrypted, false, |blocks| {
            test_aes_ecb(&zero_key, blocks)
        })
        .unwrap(),
        [0; 16]
    );
    let mut modified = encrypted;
    *modified.last_mut().unwrap() ^= 1;
    assert_eq!(
        CK_RV::from(
            crate::aes_gcm(&zero_parameters, &modified, false, |blocks| {
                test_aes_ecb(&zero_key, blocks)
            })
            .unwrap_err()
        ),
        CKR_ENCRYPTED_DATA_INVALID as CK_RV
    );

    let key = test_hex("feffe9928665731c6d6a8f9467308308");
    let plaintext = test_hex(concat!(
        "d9313225f88406e5a55909c5aff5269a",
        "86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525",
        "b16aedf5aa0de657ba637b39"
    ));
    let parameters = crate::GcmParameters {
        iv: test_hex("cafebabefacedbad"),
        aad: test_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        tag_bits: 128,
    };
    let encrypted = crate::aes_gcm(&parameters, &plaintext, true, |blocks| {
        test_aes_ecb(&key, blocks)
    })
    .unwrap();
    assert_eq!(
        encrypted,
        test_hex(concat!(
            "61353b4c2806934a777ff51fa22a4755",
            "699b2a714fcdc6f83766e5f97b6c7423",
            "73806900e49f24b22b097544d4896b42",
            "4989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb"
        ))
    );
    assert_eq!(
        crate::aes_gcm(&parameters, &encrypted, false, |blocks| {
            test_aes_ecb(&key, blocks)
        })
        .unwrap(),
        plaintext
    );

    let short_tag_parameters = crate::GcmParameters {
        tag_bits: 96,
        ..zero_parameters
    };
    let encrypted = crate::aes_gcm(&short_tag_parameters, &[0; 16], true, |blocks| {
        test_aes_ecb(&zero_key, blocks)
    })
    .unwrap();
    assert_eq!(encrypted.len(), 16 + 12);
    assert_eq!(
        crate::aes_gcm(&short_tag_parameters, &encrypted, false, |blocks| {
            test_aes_ecb(&zero_key, blocks)
        })
        .unwrap(),
        [0; 16]
    );
}

#[test]
fn aes_gcm_matches_rfc_9180_vector() {
    // RFC 9180, Appendix A.1.3.1, sequence number 0 (AEAD_AES_128_GCM).
    let key = test_hex("b062cb2c4dd4bca0ad7c7a12bbc341e6");
    let plaintext = test_hex("4265617574792069732074727574682c20747275746820626561757479");
    let parameters = crate::GcmParameters {
        iv: test_hex("a1bc314c1942ade7051ffed0"),
        aad: test_hex("436f756e742d30"),
        tag_bits: 128,
    };
    let expected = test_hex(concat!(
        "5fd92cc9d46dbf8943e72a07e42f363e",
        "d5f721212cd90bcfd072bfd9f44e06b8",
        "0fd17824947496e21b680c141b"
    ));

    let encrypted = crate::aes_gcm(&parameters, &plaintext, true, |blocks| {
        test_aes_ecb(&key, blocks)
    })
    .unwrap();
    assert_eq!(encrypted, expected);
    assert_eq!(
        crate::aes_gcm(&parameters, &encrypted, false, |blocks| {
            test_aes_ecb(&key, blocks)
        })
        .unwrap(),
        plaintext
    );
}

#[test]
fn aes_gcm_parameters_are_validated_and_copied_at_init() {
    let mut iv = [0x11; 12];
    let mut aad = [0x22; 7];
    let mut parameters = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 1,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 96,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM as CK_MECHANISM_TYPE,
        pParameter: (&mut parameters as *mut CK_GCM_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let parsed = crate::parse_gcm_parameters(&mechanism).unwrap();
    iv.fill(0);
    aad.fill(0);
    assert_eq!(parsed.iv, [0x11; 12]);
    assert_eq!(parsed.aad, [0x22; 7]);
    assert_eq!(parsed.tag_bits, 96);

    let mut invalid_parameters = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 129,
    };
    let invalid_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM as CK_MECHANISM_TYPE,
        pParameter: (&mut invalid_parameters as *mut CK_GCM_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        CK_RV::from(crate::parse_gcm_parameters(&invalid_mechanism).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    let missing = CK_MECHANISM {
        mechanism: CKM_AES_GCM as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        CK_RV::from(crate::parse_gcm_parameters(&missing).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
}

#[test]
fn yubihsm_aes_ecb_and_cbc_match_nist_sp800_38a_vectors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, _, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let key = insert_yubihsm_aes_test_object(SLOT_ID, crate::yubihsm::tests::NIST_AES_KEY_ID);

    // NIST SP 800-38A, Appendices F.1.1/F.1.2 and F.2.1/F.2.2.
    let plaintext = test_hex(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ));
    let ecb_ciphertext = test_hex(concat!(
        "3ad77bb40d7a3660a89ecaf32466ef97",
        "f5d3d58503b9699de785895a96fdbaaf",
        "43b1cd7f598ece23881b00e3ed030688",
        "7b0c785e27e8ad3f8223207104725dd4"
    ));
    assert_pkcs11_aes_vector(
        session,
        key,
        CKM_AES_ECB as CK_MECHANISM_TYPE,
        None,
        &plaintext,
        &ecb_ciphertext,
    );

    let mut iv = test_hex("000102030405060708090a0b0c0d0e0f")
        .try_into()
        .unwrap();
    let cbc_ciphertext = test_hex(concat!(
        "7649abac8119b246cee98e9b12e9197d",
        "5086cb9b507219ee95db113a917678b2",
        "73bed6b8e3c1743b7116e69e22229516",
        "3ff1caa1681fac09120eca307586e1a7"
    ));
    assert_pkcs11_aes_vector(
        session,
        key,
        CKM_AES_CBC as CK_MECHANISM_TYPE,
        Some(&mut iv),
        &plaintext,
        &cbc_ciphertext,
    );

    assert_eq!(crate::C_Finalize(std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn yubihsm_aes_gcm_round_trip_uses_hardware_ecb() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    const KEY_ID: u16 = 0x1235;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let key = insert_yubihsm_aes_test_object(SLOT_ID, KEY_ID);

    let mut iv = [0; 12];
    let mut aad = *b"authenticated data";
    let mut parameters = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: (iv.len() * 8) as CK_ULONG,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM as CK_MECHANISM_TYPE,
        pParameter: (&mut parameters as *mut CK_GCM_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let mut plaintext: Vec<u8> = (0..5003).map(|index| index as u8).collect();
    let mut encrypted_len = 0;
    assert_eq!(
        crate::C_EncryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut encrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(encrypted_len as usize, plaintext.len() + 16);
    let mut encrypted = vec![0; encrypted_len as usize];
    assert_eq!(
        crate::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            encrypted.as_mut_ptr(),
            &mut encrypted_len,
        ),
        CKR_OK as CK_RV
    );
    encrypted.truncate(encrypted_len as usize);
    assert_eq!(encrypted.len(), plaintext.len() + 16);

    let mut decrypted_len = 0;
    assert_eq!(
        crate::C_DecryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Decrypt(
            session,
            encrypted.as_mut_ptr(),
            encrypted.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(decrypted_len as usize, plaintext.len());
    let mut decrypted = vec![0; decrypted_len as usize];
    assert_eq!(
        crate::C_Decrypt(
            session,
            encrypted.as_mut_ptr(),
            encrypted.len() as CK_ULONG,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&decrypted[..decrypted_len as usize], plaintext);

    *encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(
        crate::C_DecryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Decrypt(
            session,
            encrypted.as_mut_ptr(),
            encrypted.len() as CK_ULONG,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_ENCRYPTED_DATA_INVALID as CK_RV
    );
    let commands = commands.borrow();
    let ecb_commands: Vec<&Vec<u8>> = commands
        .iter()
        .filter_map(|(command, data)| {
            (*command == crate::yubihsm::CommandCode::EncryptEcb as u8).then_some(data)
        })
        .collect();
    assert!(ecb_commands.len() > 3);
    assert!(ecb_commands
        .iter()
        .all(|data| data.len() <= 2018 && (data.len() - 2).is_multiple_of(16)));
    drop(ecb_commands);
    drop(commands);

    assert_eq!(crate::C_Finalize(std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn yubihsm_x25519_objects_use_montgomery_key_type() {
    assert_eq!(
        crate::yubihsm_ec_algorithm(&[
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ])
        .unwrap(),
        crate::YUBIHSM_ALGO_X25519
    );
    assert_eq!(
        crate::yubihsm_ec_algorithm(&[0x06, 0x03, 0x2b, 0x65, 0x6e]).unwrap(),
        crate::YUBIHSM_ALGO_X25519
    );
    assert_eq!(
        crate::yubihsm_ec_algorithm(&[0x06, 0x03, 0x2b, 0x65, 0x70]).unwrap(),
        crate::YUBIHSM_ALGO_ED25519
    );
    assert_eq!(
        crate::yubihsm_ec_algorithm(&[0x13, 0x07, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39])
            .unwrap(),
        crate::YUBIHSM_ALGO_ED25519
    );
    let label = "x25519".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x05, 0x07, 0x0b, 0x17]),
        id: 0x1234,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
        algorithm: crate::YUBIHSM_ALGO_X25519,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let public_key = crate::yubihsm::PublicKey {
        algorithm: crate::YUBIHSM_ALGO_X25519,
        key: vec![0x5a; 32],
    };
    let objects = crate::yubihsm_token_objects(99, info, Some(public_key)).unwrap();

    assert_eq!(objects.len(), 2);
    for object in &objects {
        assert_eq!(object.key_type, CKK_EC_MONTGOMERY as CK_KEY_TYPE);
        assert_eq!(
            object.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
            Some(vec![
                0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
            ])
        );
        assert_eq!(
            object.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
            Some(crate::ulong_attribute(
                CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE
            ))
        );
    }
    let public = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        public.attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE),
        Some([0x04, 0x20].into_iter().chain([0x5a; 32]).collect())
    );
    assert!(!public.encrypt);
    assert!(!public.decrypt);
    assert!(!public.sign);
    assert!(!public.verify);
    assert!(!public.derive);
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert!(!private.encrypt);
    assert!(!private.decrypt);
    assert!(!private.sign);
    assert!(!private.verify);
    assert!(private.derive);
}

#[test]
fn yubihsm_x25519_derive_returns_readable_session_object() {
    yubihsm_x25519_two_way_derive(
        7,
        8,
        Some(&crate::yubihsm::tests::RFC7748_ALICE_PUBLIC_KEY),
        Some(&crate::yubihsm::tests::RFC7748_BOB_PUBLIC_KEY),
        Some(&crate::yubihsm::tests::RFC7748_SHARED_SECRET),
    );
}

#[test]
fn yubihsm_ed25519_objects_use_edwards_key_type() {
    let label = "ed25519".to_owned();
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x08]),
        id: 0x1236,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
        algorithm: crate::YUBIHSM_ALGO_ED25519,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let public_key = crate::yubihsm::PublicKey {
        algorithm: crate::YUBIHSM_ALGO_ED25519,
        key: vec![0x5a; 32],
    };
    let objects = crate::yubihsm_token_objects(99, info, Some(public_key)).unwrap();
    assert_eq!(objects.len(), 2);
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.key_type, CKK_EC_EDWARDS as CK_KEY_TYPE);
    assert!(private.sign);
    assert!(!private.verify);
    assert!(!private.derive);
    assert_eq!(
        private.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
        Some(vec![0x06, 0x03, 0x2b, 0x65, 0x70])
    );
    assert_eq!(
        private.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
        Some(crate::ulong_attribute(
            CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
        ))
    );
    let public = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert!(public.verify);
    assert_eq!(
        public.attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE),
        Some([0x04, 0x20].into_iter().chain([0x5a; 32]).collect())
    );
}

#[test]
fn yubihsm_object_identity_survives_device_sequence_wraps() {
    let info = crate::yubihsm::ObjectInfo {
        capabilities: [0; 8],
        id: 0x1234,
        length: 32,
        domains: 1,
        object_type: crate::YUBIHSM_AUTHENTICATION_KEY,
        algorithm: crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
        sequence: 7,
        origin: 1,
        label: "authentication".to_owned(),
        delegated_capabilities: [0; 8],
    };
    let first = crate::yubihsm_token_objects_with_generation(99, info.clone(), None, 1).unwrap();
    let wrapped = crate::yubihsm_token_objects_with_generation(99, info, None, 257).unwrap();
    assert_ne!(first[0].unique_id, wrapped[0].unique_id);
}

#[test]
fn piv_native_identity_changes_with_object_contents() {
    assert_ne!(
        crate::piv_object_fingerprint(b"first").unwrap(),
        crate::piv_object_fingerprint(b"second").unwrap()
    );
}

#[test]
fn yubihsm_x25519_random_keys_derive_both_directions() {
    yubihsm_x25519_two_way_derive(9, 10, None, None, None);
}

fn yubihsm_x25519_two_way_derive(
    first_id: u8,
    second_id: u8,
    expected_first_public: Option<&[u8; 32]>,
    expected_second_public: Option<&[u8; 32]>,
    expected_shared: Option<&[u8; 32]>,
) {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let generate_x25519 = |id: u8| {
        let mut ec_params: [u8; 12] = [
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ];
        let mut key_id = [0, id];
        let mut token = CK_TRUE as CK_BBOOL;
        let mut derive = CK_TRUE as CK_BBOOL;
        let mut public_template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
                pValue: ec_params.as_mut_ptr().cast(),
                ulValueLen: ec_params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: key_id.as_mut_ptr().cast(),
                ulValueLen: key_id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let mut private_template = [
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: key_id.as_mut_ptr().cast(),
                ulValueLen: key_id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE as CK_ATTRIBUTE_TYPE,
                pValue: (&mut derive as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let mut public_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut private_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: ::std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = crate::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut public_key,
            &mut private_key,
        );
        assert_eq!(rv, CKR_OK as CK_RV);
        (public_key, private_key)
    };
    let _ = generate_x25519(first_id);
    let _ = generate_x25519(second_id);

    let find_key = |id: u8, class: CK_OBJECT_CLASS| {
        let mut key_id = [0, id];
        let mut class_value = class;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: key_id.as_mut_ptr().cast(),
                ulValueLen: key_id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
                pValue: (&mut class_value as *mut CK_OBJECT_CLASS).cast(),
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
        ];
        assert_eq!(
            crate::C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG,),
            CKR_OK as CK_RV
        );
        let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut count = 0;
        assert_eq!(
            crate::C_FindObjects(session, &mut object, 1, &mut count),
            CKR_OK as CK_RV
        );
        assert_eq!(count, 1);
        assert_eq!(crate::C_FindObjectsFinal(session), CKR_OK as CK_RV);
        object
    };
    let public_key_one = find_key(first_id, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    let private_handle = find_key(first_id, CKO_PRIVATE_KEY as CK_OBJECT_CLASS);
    let public_key_two = find_key(second_id, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    let other_private_handle = find_key(second_id, CKO_PRIVATE_KEY as CK_OBJECT_CLASS);

    let read_ec_point = |object| {
        let mut point = vec![0u8; 34];
        let mut attribute = CK_ATTRIBUTE {
            type_: CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
            pValue: point.as_mut_ptr().cast(),
            ulValueLen: point.len() as CK_ULONG,
        };
        assert_eq!(
            crate::C_GetAttributeValue(session, object, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        point.truncate(attribute.ulValueLen as usize);
        point
    };
    let mut public_data = read_ec_point(public_key_two);
    if let Some(expected) = expected_second_public {
        assert_eq!(&public_data[2..], expected);
    }
    let mut parameters = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL as CK_EC_KDF_TYPE,
        pSharedData: ::std::ptr::null_mut(),
        ulSharedDataLen: 0,
        pPublicData: public_data.as_mut_ptr(),
        ulPublicDataLen: public_data.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        pParameter: (&mut parameters as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let mut token_object = CK_TRUE as CK_BBOOL;
    let mut token_template = CK_ATTRIBUTE {
        type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        pValue: (&mut token_object as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    let command_count = commands.borrow().len();
    let mut invalid_derived_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_DeriveKey(
            session,
            &mut mechanism,
            private_handle,
            &mut token_template,
            1,
            &mut invalid_derived_key,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(commands.borrow().len(), command_count);

    let mut derived_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_DeriveKey(
            session,
            &mut mechanism,
            private_handle,
            ::std::ptr::null_mut(),
            0,
            &mut derived_key,
        ),
        CKR_OK as CK_RV
    );

    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_FALSE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut derive = CK_TRUE as CK_BBOOL;
    let mut value = [0u8; 32];
    let mut attributes = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut token as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut private as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sensitive as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut extractable as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: (&mut encrypt as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: (&mut decrypt as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sign as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: (&mut verify as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DERIVE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut derive as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr().cast(),
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            session,
            derived_key,
            attributes.as_mut_ptr(),
            attributes.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(token, CK_FALSE as CK_BBOOL);
    assert_eq!(private, CK_FALSE as CK_BBOOL);
    assert_eq!(sensitive, CK_FALSE as CK_BBOOL);
    assert_eq!(extractable, CK_TRUE as CK_BBOOL);
    assert_eq!(encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(decrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);
    assert_eq!(verify, CK_FALSE as CK_BBOOL);
    assert_eq!(derive, CK_FALSE as CK_BBOOL);

    let mut reverse_public_data = read_ec_point(public_key_one);
    if let Some(expected) = expected_first_public {
        assert_eq!(&reverse_public_data[2..], expected);
    }
    let mut reverse_parameters = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL as CK_EC_KDF_TYPE,
        pSharedData: ::std::ptr::null_mut(),
        ulSharedDataLen: 0,
        pPublicData: reverse_public_data.as_mut_ptr(),
        ulPublicDataLen: reverse_public_data.len() as CK_ULONG,
    };
    let mut reverse_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        pParameter: (&mut reverse_parameters as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let mut reverse_derived_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_DeriveKey(
            session,
            &mut reverse_mechanism,
            other_private_handle,
            ::std::ptr::null_mut(),
            0,
            &mut reverse_derived_key,
        ),
        CKR_OK as CK_RV
    );
    let mut reverse_value = [0u8; 32];
    let mut reverse_value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: reverse_value.as_mut_ptr().cast(),
        ulValueLen: reverse_value.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(
            session,
            reverse_derived_key,
            &mut reverse_value_attribute,
            1,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(value, reverse_value);
    if let Some(expected) = expected_shared {
        assert_eq!(&value, expected);
    }
    assert!(commands
        .borrow()
        .iter()
        .any(|(command, _)| { *command == crate::yubihsm::CommandCode::DeriveEcdh as u8 }));

    finalize_for_test();
}

#[test]
fn piv_ec_objects_expose_named_curve_and_der_encoded_point() {
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: "piv-9c-public".to_owned(),
        class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: "PIV slot 9C".to_owned(),
        id: vec![2],
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
        key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
        owner_session: None,
        material: crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::EccP256,
            public_key: vec![0x11; 64],
        },
    };
    assert_eq!(
        object.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
        Some(vec![
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        ])
    );
    let point = object
        .attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(point[0], 0x04);
    assert_eq!(point[1], 65);
    assert_eq!(point[2], 0x04);
    assert_eq!(point.len(), 67);
}

#[test]
fn piv_edwards_and_montgomery_parameters_match_ykcs11() {
    assert_eq!(
        crate::piv_ec_parameters(crate::piv::Algorithm::Ed25519),
        Some(
            [0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,]
                .as_slice()
        )
    );
    assert_eq!(
        crate::piv_ec_parameters(crate::piv::Algorithm::X25519),
        Some([0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39].as_slice())
    );
    assert_eq!(
        crate::piv_effective_pin_policy(crate::piv::Slot::CardAuthentication, 0),
        1
    );
    assert_eq!(
        crate::piv_effective_pin_policy(crate::piv::Slot::Signature, 0),
        3
    );
    for slot in crate::piv::Slot::all() {
        assert!(!crate::piv_policy_requires_login(*slot, 1));
        assert!(crate::piv_policy_requires_login(*slot, 2));
    }
}

#[test]
fn piv_and_openpgp_edwards_and_montgomery_mechanisms_report_field_sizes() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let piv = crate::PivSlot {
        connector: connector.clone(),
        application_aid: crate::piv::PIV_AID.to_vec(),
        slot_description: None,
        authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        management_authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        version: crate::piv::Version {
            major: 5,
            minor: 7,
            patch: 0,
        },
        serial: String::from("TEST0001"),
        keys: Vec::new(),
        certificates: Vec::new(),
        data_objects: Vec::new(),
    };
    let mechanism = |mechanisms: Vec<crate::MechanismDetails>, type_: CK_MECHANISM_TYPE| {
        mechanisms
            .into_iter()
            .find(|mechanism| mechanism.type_ == type_)
            .unwrap()
    };
    let piv_eddsa = mechanism(
        crate::Slot::mechanisms(&piv),
        CKM_EDDSA as CK_MECHANISM_TYPE,
    );
    assert_eq!((piv_eddsa.min_key_size, piv_eddsa.max_key_size), (255, 255));
    let piv_ecdh = mechanism(
        crate::Slot::mechanisms(&piv),
        CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
    );
    assert_eq!((piv_ecdh.min_key_size, piv_ecdh.max_key_size), (255, 384));

    let openpgp = crate::OpenPgpSlot {
        connector,
        application_aid: Vec::new(),
        authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        version: (0, 0),
        serial: String::from("TEST0001"),
        pin_min: 6,
        pin_max: 127,
        admin_pin_min: 8,
        admin_pin_max: 127,
        kdf: None,
        keys: vec![crate::openpgp::KeyInfo {
            key_ref: crate::openpgp::KeyRef::Decipher,
            algorithm: crate::openpgp::Algorithm::Ecdh(crate::openpgp::Curve::X25519),
            public_key: crate::openpgp::PublicKey::Raw {
                curve: crate::openpgp::Curve::X25519,
                key: vec![0; 32],
            },
            pin_policy: 0,
            local: true,
        }],
        certificates: Vec::new(),
    };
    let openpgp_eddsa = mechanism(
        crate::Slot::mechanisms(&openpgp),
        CKM_EDDSA as CK_MECHANISM_TYPE,
    );
    assert_eq!(
        (openpgp_eddsa.min_key_size, openpgp_eddsa.max_key_size),
        (255, 255)
    );
    let openpgp_ecdh = mechanism(
        crate::Slot::mechanisms(&openpgp),
        CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
    );
    assert_eq!(
        (openpgp_ecdh.min_key_size, openpgp_ecdh.max_key_size),
        (255, 521)
    );
}

#[test]
fn piv_general_data_objects_expose_pkcs11_data_attributes() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let piv = crate::PivSlot {
        connector,
        application_aid: crate::piv::PIV_AID.to_vec(),
        slot_description: None,
        authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        management_authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        version: crate::piv::Version {
            major: 5,
            minor: 7,
            patch: 0,
        },
        serial: String::from("TEST0001"),
        keys: Vec::new(),
        certificates: Vec::new(),
        data_objects: vec![crate::PivDataObject {
            object_id: 0x5f_c102,
            value: vec![1, 2, 3],
        }, crate::PivDataObject {
            object_id: 0x5f_ff10,
            value: vec![4, 5, 6],
        }],
    };
    let objects = crate::Slot::token_objects(&piv, 7).unwrap();
    let object = objects
        .iter()
        .find(|object| object.class == CKO_DATA as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        object.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
        Some(b"PIV".to_vec())
    );
    assert_eq!(
        object.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00])
    );
    assert_eq!(
        object.attribute_value(CKA_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![27])
    );
    assert_eq!(
        object.attribute_value(crate::CKA_PKCS11RS_PIV_OBJECT_TAG),
        Some(vec![0x5f, 0xc1, 0x02])
    );
    assert_eq!(
        object.attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        object.attribute_value(CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );

    let vendor = objects
        .iter()
        .find(|object| matches!(object.material, crate::KeyMaterial::PivData { object_id: 0x5f_ff10, .. }))
        .unwrap();
    assert_eq!(vendor.attribute_value(CKA_ID as CK_ATTRIBUTE_TYPE), None);
    assert_eq!(
        vendor.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        None
    );
    assert_eq!(
        vendor.attribute_value(crate::CKA_PKCS11RS_PIV_OBJECT_TAG),
        Some(vec![0x5f, 0xff, 0x10])
    );
}

#[cfg(feature = "abi-tests")]
#[test]
fn piv_key_related_objects_share_ykcs11_id_and_keep_raw_certificate_data() {
    let slot = crate::abi_test_piv_slot().unwrap();
    let objects = crate::Slot::token_objects(&slot, 7).unwrap();
    let related = objects
        .iter()
        .filter(|object| object.token && object.id == [2])
        .collect::<Vec<_>>();
    assert_eq!(related.len(), 4);
    for class in [CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKO_DATA] {
        assert_eq!(
            related
                .iter()
                .filter(|object| object.class == class as CK_OBJECT_CLASS)
                .count(),
            1
        );
    }

    let certificate = related
        .iter()
        .find(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .unwrap();
    let certificate_value = certificate
        .attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(certificate_value.first(), Some(&0x30));

    let data = related
        .iter()
        .find(|object| object.class == CKO_DATA as CK_OBJECT_CLASS)
        .unwrap();
    let raw_value = data
        .attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(raw_value.first(), Some(&0x70));
    assert_ne!(raw_value, certificate_value);
    assert_eq!(
        data.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x00,
        ])
    );
    assert_eq!(
        crate::piv::decode_certificate_object(&raw_value).unwrap(),
        certificate_value
    );
}

#[cfg(feature = "abi-tests")]
#[test]
fn piv_key_metadata_controls_provenance_policy_and_firmware_mechanisms() {
    let mut slot = crate::abi_test_piv_slot().unwrap();
    let objects = crate::Slot::token_objects(&slot, 7).unwrap();
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        private.attribute_value(CKA_PRIVATE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert_eq!(
        private.attribute_value(CKA_LOCAL as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    assert_eq!(
        private.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
        Some((CKM_RSA_PKCS_KEY_PAIR_GEN as CK_ULONG).to_ne_bytes().to_vec())
    );
    assert_eq!(
        private.attribute_value(crate::CKA_YUBICO_PIN_POLICY),
        Some(2u64.to_ne_bytes().to_vec())
    );
    assert_eq!(
        private.attribute_value(crate::CKA_YUBICO_TOUCH_POLICY),
        Some(1u64.to_ne_bytes().to_vec())
    );

    slot.keys[0].origin = crate::piv::ORIGIN_IMPORTED;
    let imported = crate::Slot::token_objects(&slot, 7)
        .unwrap()
        .into_iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        imported.attribute_value(CKA_LOCAL as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
    assert_eq!(
        imported.attribute_value(CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE),
        Some((CK_UNAVAILABLE_INFORMATION as CK_ULONG).to_ne_bytes().to_vec())
    );

    slot.version = crate::piv::Version {
        major: 5,
        minor: 6,
        patch: 0,
    };
    let mechanisms = crate::Slot::mechanisms(&slot);
    assert!(!mechanisms
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_EDDSA as CK_MECHANISM_TYPE));
    let rsa_generation = mechanisms
        .iter()
        .find(|mechanism| {
            mechanism.type_ == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
        })
        .unwrap();
    assert_eq!((rsa_generation.min_key_size, rsa_generation.max_key_size), (1024, 2048));
}

#[test]
fn piv_ecdsa_signatures_are_converted_to_fixed_width_values() {
    let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let signature = crate::piv_ecdsa_signature(&der, 32).unwrap();
    assert_eq!(signature.len(), 64);
    assert_eq!(&signature[31..32], &[1]);
    assert_eq!(&signature[63..64], &[2]);
}

#[test]
fn yubihsm_mechanisms_follow_enabled_device_algorithms() {
    let mechanisms = crate::yubihsm_mechanisms(&[
        crate::YUBIHSM_ALGO_RSA_2048,
        crate::YUBIHSM_ALGO_AES128,
        crate::YUBIHSM_ALGO_HMAC_SHA1,
        crate::YUBIHSM_ALGO_HMAC_SHA512,
        crate::YUBIHSM_ALGO_ED25519,
        crate::YUBIHSM_ALGO_X25519,
        crate::YUBIHSM_ALGO_AES_ECB,
    ]);
    let mechanism = |type_| {
        mechanisms
            .iter()
            .find(|mechanism| mechanism.type_ == type_)
            .copied()
    };
    let rsa = mechanism(CKM_RSA_PKCS as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((rsa.min_key_size, rsa.max_key_size), (2048, 2048));
    assert_ne!(rsa.flags & CKF_ENCRYPT as CK_FLAGS, 0);
    assert_eq!(rsa.flags & (CKF_SIGN | CKF_DECRYPT) as CK_FLAGS, 0);
    let aes = mechanism(CKM_AES_ECB as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((aes.min_key_size, aes.max_key_size), (16, 16));
    let gcm = mechanism(CKM_AES_GCM as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((gcm.min_key_size, gcm.max_key_size), (16, 16));
    assert_eq!(
        gcm.flags & (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
        (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS
    );
    let hmac = mechanism(CKM_SHA_1_HMAC as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((hmac.min_key_size, hmac.max_key_size), (1, 64));
    let hmac = mechanism(CKM_SHA512_HMAC as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((hmac.min_key_size, hmac.max_key_size), (1, 128));
    let generated = mechanism(CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((generated.min_key_size, generated.max_key_size), (20, 64));
    let montgomery = mechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE).unwrap();
    assert_eq!(
        (montgomery.min_key_size, montgomery.max_key_size),
        (255, 255)
    );
    assert_ne!(montgomery.flags & CKF_EC_CURVENAME as CK_FLAGS, 0);
    let ecdh = mechanism(CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((ecdh.min_key_size, ecdh.max_key_size), (255, 255));
    let edwards = mechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((edwards.min_key_size, edwards.max_key_size), (255, 255));
    assert_eq!(edwards.flags, montgomery.flags);
    let eddsa = mechanism(CKM_EDDSA as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((eddsa.min_key_size, eddsa.max_key_size), (255, 255));
    assert!(mechanism(CKM_AES_CBC as CK_MECHANISM_TYPE).is_none());
    assert!(mechanism(CKM_ECDSA as CK_MECHANISM_TYPE).is_none());

    let public_operations = crate::yubihsm_mechanisms(&[
        crate::YUBIHSM_ALGO_RSA_2048,
        crate::YUBIHSM_ALGO_RSA_PSS_SHA256,
        crate::YUBIHSM_ALGO_RSA_OAEP_SHA256,
        crate::YUBIHSM_ALGO_EC_P256,
        crate::YUBIHSM_ALGO_EC_ECDSA_SHA256,
    ]);
    let flags = |type_| {
        public_operations
            .iter()
            .find(|mechanism| mechanism.type_ == type_)
            .unwrap()
            .flags
    };
    assert_ne!(
        flags(CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE) & CKF_VERIFY as CK_FLAGS,
        0
    );
    assert_ne!(
        flags(CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE) & CKF_ENCRYPT as CK_FLAGS,
        0
    );
    assert_ne!(
        flags(CKM_ECDSA as CK_MECHANISM_TYPE) & CKF_VERIFY as CK_FLAGS,
        0
    );

    let without_ecb =
        crate::yubihsm_mechanisms(&[crate::YUBIHSM_ALGO_AES128, crate::YUBIHSM_ALGO_AES_CBC]);
    assert!(without_ecb
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_AES_CBC as CK_MECHANISM_TYPE));
    assert!(!without_ecb
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_AES_GCM as CK_MECHANISM_TYPE));

    let without_x25519 = crate::yubihsm_mechanisms(&[crate::YUBIHSM_ALGO_EC_P256]);
    assert!(!without_x25519
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE));
    assert!(!without_x25519
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE));
    assert!(!without_x25519
        .iter()
        .any(|mechanism| mechanism.type_ == CKM_EDDSA as CK_MECHANISM_TYPE));
}

#[derive(Debug)]
struct TestSlot {
    present: std::cell::Cell<bool>,
    remove_on_refresh: bool,
    login_active: Option<std::rc::Rc<std::cell::Cell<bool>>>,
}

#[derive(Debug)]
struct TestSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

#[derive(Debug)]
struct PivSigningTestSession {
    slot_id: CK_SLOT_ID,
    captured: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
}

#[derive(Debug)]
struct FailingConnector;

impl crate::Connector for FailingConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Failing connector"
    }

    fn serial(&self) -> &str {
        "FAIL0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        false
    }

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        Err(rusb::Error::NoDevice.into())
    }
}

#[derive(Debug)]
struct SelectableConnector {
    present: std::cell::Cell<bool>,
    select_ok: std::cell::Cell<bool>,
    serial: &'static str,
}

impl crate::Connector for SelectableConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Selectable connector"
    }

    fn serial(&self) -> &str {
        self.serial
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        Some((5, 7, 0))
    }

    fn is_present(&self) -> bool {
        self.present.get()
    }

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        if !self.present.get() {
            return Err(rusb::Error::NoDevice.into());
        }
        if send_buffer.get(1) == Some(&0xa4) && !self.select_ok.get() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..2].copy_from_slice(&[0x90, 0x00]);
        Ok(&receive_buffer[..2])
    }
}

#[derive(Debug)]
struct CountingConnector {
    transmissions: std::rc::Rc<std::cell::Cell<usize>>,
}

impl crate::Connector for CountingConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Counting connector"
    }

    fn serial(&self) -> &str {
        "COUNT0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        self.transmissions.set(self.transmissions.get() + 1);
        Err(CKR_DEVICE_ERROR.into())
    }
}

unsafe extern "C" fn test_create_mutex(_mutex: CK_VOID_PTR_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_destroy_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_lock_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_unlock_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

impl crate::Session for TestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }
}

impl crate::Session for PivSigningTestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        CKF_SERIAL_SESSION as CK_FLAGS
    }

    fn get_session_info(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn piv_sign(
        &self,
        slot: crate::piv::Slot,
        algorithm: crate::piv::Algorithm,
        input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, crate::error::Error> {
        assert_eq!(slot, crate::piv::Slot::Signature);
        assert_eq!(algorithm, crate::piv::Algorithm::Rsa1024);
        *self.captured.borrow_mut() = input.to_vec();
        Ok(vec![0x5a; 128])
    }
}

impl crate::Slot for TestSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        String::from("Test Slot")
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Test Token"
    }

    fn serial(&self) -> &str {
        "TEST0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        self.present.get()
    }

    fn refresh(&self) -> Result<(), crate::error::Error> {
        if self.remove_on_refresh {
            self.present.set(false);
        }
        Ok(())
    }

    fn login_is_active(&self) -> bool {
        self.login_active.as_ref().is_none_or(|active| active.get())
    }

    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn crate::Session> {
        Box::new(TestSession {
            slot_id: slotID,
            flags,
        })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), crate::error::Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        TEST_SLOT_LOGGED_IN.store(true, std::sync::atomic::Ordering::SeqCst);
        TEST_SLOT_LOGIN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn login_so(&mut self, pin: &[u8]) -> Result<(), crate::error::Error> {
        if pin != b"12345678" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        TEST_SLOT_LOGGED_IN.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), crate::error::Error> {
        if old_pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        if new_pin.len() < 4 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn set_so_pin(
        &mut self,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), crate::error::Error> {
        if old_pin != b"12345678" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        if new_pin.len() < 8 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn init_user_pin(&mut self, new_pin: &[u8]) -> Result<(), crate::error::Error> {
        if new_pin.len() < 4 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn login_context_specific(
        &mut self,
        pin: &[u8],
        _extended: bool,
    ) -> Result<(), crate::error::Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        TEST_CONTEXT_LOGIN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn logout(&mut self) -> Result<(), crate::error::Error> {
        TEST_SLOT_LOGOUT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if TEST_SLOT_FAIL_LOGOUT.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        TEST_SLOT_LOGGED_IN.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), crate::error::Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), crate::error::Error> {
        self.format_token_info(info);
        Ok(())
    }
}

fn test_slot(present: bool) -> TestSlot {
    TestSlot {
        present: std::cell::Cell::new(present),
        remove_on_refresh: false,
        login_active: None,
    }
}

fn install_test_slot(slot_id: CK_SLOT_ID) {
    let mut context = crate::lock_context().unwrap();
    context
        .as_mut()
        .unwrap()
        .slots
        .insert(slot_id, Box::new(test_slot(true)));
}

fn install_test_session(slot_id: CK_SLOT_ID, session_handle: CK_SESSION_HANDLE) {
    install_test_session_with_state(
        slot_id,
        session_handle,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
        true,
    );
}

fn install_public_test_session(slot_id: CK_SLOT_ID, session_handle: CK_SESSION_HANDLE) {
    install_test_session_with_state(
        slot_id,
        session_handle,
        CKF_SERIAL_SESSION as CK_FLAGS,
        false,
    );
}

fn install_test_session_with_state(
    slot_id: CK_SLOT_ID,
    session_handle: CK_SESSION_HANDLE,
    flags: CK_FLAGS,
    logged_in: bool,
) {
    let mut context = crate::lock_context().unwrap();
    let context = context.as_mut().unwrap();
    context.slots.insert(slot_id, Box::new(test_slot(true)));
    context
        .sessions
        .insert(session_handle, Box::new(TestSession { slot_id, flags }));
    if logged_in {
        context.logged_in_slots.insert(slot_id, crate::LoginRole::User);
    }
}

fn assert_function_slots_present<T>(function_list: *const T, function_count: usize) {
    assert!(!function_list.is_null());
    let first_function_offset = ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize);
    let pointer_size = ::std::mem::size_of::<*const ::std::os::raw::c_void>();

    for index in 0..function_count {
        let slot = unsafe {
            (function_list as *const u8).add(first_function_offset + index * pointer_size)
                as *const *const ::std::os::raw::c_void
        };
        assert!(
            !unsafe { *slot }.is_null(),
            "function slot {index} should be present"
        );
    }
}

fn assert_session_entry_points_return(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let mut data = [0u8; 8];
    let mut data_len = data.len() as CK_ULONG;
    let mut object = 0;
    let mut second_object = 0;
    let mut flags = 0;
    let mut async_data = CK_ASYNC_DATA {
        ulVersion: 0,
        pValue: ::std::ptr::null_mut(),
        ulValue: 0,
        hObject: 0,
        hAdditionalObject: 0,
    };

    macro_rules! assert_stub {
        ($name:literal, $call:expr) => {
            assert_eq!($call, expected, "{} should validate session state", $name);
        };
    }

    assert_stub!(
        "C_InitPIN",
        crate::C_InitPIN(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_SetPIN",
        crate::C_SetPIN(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_GetOperationState",
        crate::C_GetOperationState(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SetOperationState",
        crate::C_SetOperationState(session, data.as_mut_ptr(), data.len() as CK_ULONG, 0, 0)
    );
    assert_stub!(
        "C_CreateObject",
        crate::C_CreateObject(session, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!(
        "C_CopyObject",
        crate::C_CopyObject(session, 0, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!("C_DestroyObject", crate::C_DestroyObject(session, 0));
    assert_stub!(
        "C_GetObjectSize",
        crate::C_GetObjectSize(session, 0, &mut data_len)
    );
    assert_stub!(
        "C_GetAttributeValue",
        crate::C_GetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SetAttributeValue",
        crate::C_SetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptInit",
        crate::C_EncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Encrypt",
        crate::C_Encrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptUpdate",
        crate::C_EncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptFinal",
        crate::C_EncryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DecryptInit",
        crate::C_DecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Decrypt",
        crate::C_Decrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptUpdate",
        crate::C_DecryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptFinal",
        crate::C_DecryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DigestInit",
        crate::C_DigestInit(session, ::std::ptr::null_mut())
    );
    assert_stub!(
        "C_Digest",
        crate::C_Digest(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestUpdate",
        crate::C_DigestUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!("C_DigestKey", crate::C_DigestKey(session, 0));
    assert_stub!(
        "C_DigestFinal",
        crate::C_DigestFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SignInit",
        crate::C_SignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Sign",
        crate::C_Sign(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignRecoverInit",
        crate::C_SignRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignRecover",
        crate::C_SignRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_VerifyInit",
        crate::C_VerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Verify",
        crate::C_Verify(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyRecoverInit",
        crate::C_VerifyRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyRecover",
        crate::C_VerifyRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestEncryptUpdate",
        crate::C_DigestEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptDigestUpdate",
        crate::C_DecryptDigestUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignEncryptUpdate",
        crate::C_SignEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptVerifyUpdate",
        crate::C_DecryptVerifyUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_GenerateKeyPair",
        crate::C_GenerateKeyPair(
            session,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object,
            &mut second_object
        )
    );
    assert_stub!(
        "C_WrapKey",
        crate::C_WrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKey",
        crate::C_UnwrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            &mut object
        )
    );
    assert_eq!(
        crate::C_DeriveKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object
        ),
        CKR_ARGUMENTS_BAD as CK_RV,
        "C_DeriveKey validates its mechanism arguments"
    );
    assert_stub!("C_GetFunctionStatus", crate::C_GetFunctionStatus(session));
    assert_stub!("C_CancelFunction", crate::C_CancelFunction(session));
    assert_stub!(
        "C_LoginUser",
        crate::C_LoginUser(
            session,
            CKU_USER as CK_USER_TYPE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_SessionCancel", crate::C_SessionCancel(session, 0));
    assert_stub!(
        "C_MessageEncryptInit",
        crate::C_MessageEncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptMessage",
        crate::C_EncryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptMessageBegin",
        crate::C_EncryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_EncryptMessageNext",
        crate::C_EncryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageEncryptFinal",
        crate::C_MessageEncryptFinal(session)
    );
    assert_stub!(
        "C_MessageDecryptInit",
        crate::C_MessageDecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_DecryptMessage",
        crate::C_DecryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptMessageBegin",
        crate::C_DecryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_DecryptMessageNext",
        crate::C_DecryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageDecryptFinal",
        crate::C_MessageDecryptFinal(session)
    );
    assert_stub!(
        "C_MessageSignInit",
        crate::C_MessageSignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessage",
        crate::C_SignMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignMessageBegin",
        crate::C_SignMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessageNext",
        crate::C_SignMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!("C_MessageSignFinal", crate::C_MessageSignFinal(session));
    assert_stub!(
        "C_MessageVerifyInit",
        crate::C_MessageVerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessage",
        crate::C_VerifyMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyMessageBegin",
        crate::C_VerifyMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessageNext",
        crate::C_VerifyMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_MessageVerifyFinal", crate::C_MessageVerifyFinal(session));
    assert_stub!(
        "C_EncapsulateKey",
        crate::C_EncapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            &mut data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_DecapsulateKey",
        crate::C_DecapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_VerifySignatureInit",
        crate::C_VerifySignatureInit(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifySignature",
        crate::C_VerifySignature(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureUpdate",
        crate::C_VerifySignatureUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureFinal",
        crate::C_VerifySignatureFinal(session)
    );
    assert_stub!(
        "C_GetSessionValidationFlags",
        crate::C_GetSessionValidationFlags(session, 0, &mut flags)
    );
    assert_stub!(
        "C_AsyncComplete",
        crate::C_AsyncComplete(session, data.as_mut_ptr(), &mut async_data)
    );
    assert_stub!(
        "C_AsyncGetID",
        crate::C_AsyncGetID(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_AsyncJoin",
        crate::C_AsyncJoin(
            session,
            data.as_mut_ptr(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_WrapKeyAuthenticated",
        crate::C_WrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKeyAuthenticated",
        crate::C_UnwrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            &mut object
        )
    );
}
