use super::*;

#[cfg(feature = "embedded-virtual-yubikey")]
#[test]
fn piv_so_manages_native_keys_and_logout_revokes_management_authorization() {
    let guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let base = std::sync::Arc::new(crate::EmbeddedVirtualYubiKeyConnector::new().unwrap());
    let reader = std::sync::Arc::new(crate::PcscReaderState::default());
    let connector = std::rc::Rc::new(crate::PcscAppletConnector::new(
        base.clone(),
        &crate::piv::PIV_AID,
        None,
        reader.clone(),
    ));
    let mut piv = crate::PivSlot::new_with_device(
        connector,
        crate::piv::PIV_AID.to_vec(),
        std::sync::Arc::new(crate::device::DeviceContext::test()),
    );
    crate::Slot::init_slot(&mut piv).unwrap();
    install_test_slot_with_backend(TEST_SLOT_ID, Box::new(piv));
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        ctx.memory_objects.clear();
        let backend = ctx
            .slot
            .open_session(TEST_SLOT_ID, (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _);
        ctx.sessions
            .insert(TEST_SESSION_HANDLE, crate::SessionContext::new(backend));
    });
    crate::register_session_slot(TEST_SESSION_HANDLE, TEST_SLOT_ID).unwrap();
    let login = |role, secret: &mut [u8]| {
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            role,
            secret.as_mut_ptr(),
            secret.len() as _,
        )
    };
    let mut pin = *b"123456";
    let mut management = *b"010203040506070801020304050607080102030405060708";
    let mut token = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut id = [crate::piv::Slot::Retired1.cka_id()];
    let mut params = crate::pkcs11_auth::P256_PARAMS.to_vec();
    let mut bits = 2048 as CK_ULONG;
    let mut public_template = [
        scalar_attribute(CKA_TOKEN as _, &mut token),
        scalar_attribute(CKA_MODULUS_BITS as _, &mut bits),
    ];
    let mut private_template = [
        scalar_attribute(CKA_TOKEN as _, &mut token),
        scalar_attribute(CKA_SIGN as _, &mut sign),
        scalar_attribute(CKA_DECRYPT as _, &mut sign),
        bytes_attribute(CKA_ID as _, &mut id),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = 0;
    let mut private = 0;
    {
        let mut generate = || {
            crate::api::C_GenerateKeyPair(
                TEST_SESSION_HANDLE,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as _,
                private_template.as_mut_ptr(),
                private_template.len() as _,
                &mut public,
                &mut private,
            )
        };

        assert_eq!(login(CKU_USER as _, &mut pin), CKR_OK as CK_RV);
        assert_eq!(
            generate(),
            CKR_USER_NOT_LOGGED_IN as CK_RV,
            "PIN alone must not authorize management"
        );
        assert_eq!(crate::api::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
        assert_eq!(login(CKU_SO as _, &mut management), CKR_OK as CK_RV);
        assert_eq!(
            login(CKU_USER as _, &mut pin),
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV
        );
        assert_eq!(generate(), CKR_OK as CK_RV);
    }
    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::api::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
    let mut signature_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let find_private = || {
        find_by_bytes_attribute(
            TEST_SESSION_HANDLE,
            CKO_PRIVATE_KEY as _,
            CKA_ID as _,
            &[crate::piv::Slot::Retired1.cka_id()],
        )
    };
    assert_eq!(find_private(), vec![private]);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, private, CKA_PRIVATE as _),
        [CK_TRUE as u8]
    );
    let mut secret = CK_ATTRIBUTE {
        type_: CKA_PRIVATE_EXPONENT as _,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, private, &mut secret, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut signature_mechanism, private),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_DecryptInit(TEST_SESSION_HANDLE, &mut signature_mechanism, private),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(crate::api::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::PivClient
            .management_authentication_probe_status(base.as_ref())
            .unwrap(),
        0x6982,
        "SO logout must revoke card management authorization"
    );
    assert!(find_private().is_empty());
    assert_eq!(login(CKU_USER as _, &mut pin), CKR_OK as CK_RV);
    private = find_private()[0];
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut signature_mechanism, private),
        CKR_OK as CK_RV
    );
    let mut digest = [0x31; 32];
    let mut signature = [0u8; 256];
    let mut length = signature.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_Sign(
            TEST_SESSION_HANDLE,
            digest.as_mut_ptr(),
            digest.len() as _,
            signature.as_mut_ptr(),
            &mut length
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DecryptInit(TEST_SESSION_HANDLE, &mut signature_mechanism, private),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(TEST_SESSION_HANDLE, private),
        CKR_USER_NOT_LOGGED_IN as CK_RV,
        "PIN login must not regain management authorization after SO logout"
    );
    assert_eq!(crate::api::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(login(CKU_SO as _, &mut management), CKR_OK as CK_RV);
    private = find_private()[0];
    assert_eq!(
        crate::api::C_DestroyObject(TEST_SESSION_HANDLE, private),
        CKR_OK as CK_RV
    );
    assert!(find_private().is_empty());

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_EC as CK_KEY_TYPE;
    let mut scalar = [1u8; 32];
    let mut import_template = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        scalar_attribute(CKA_TOKEN as _, &mut token),
        scalar_attribute(CKA_SIGN as _, &mut sign),
        bytes_attribute(CKA_ID as _, &mut id),
        bytes_attribute(CKA_EC_PARAMS as _, &mut params),
        bytes_attribute(CKA_VALUE as _, &mut scalar),
    ];
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            import_template.as_mut_ptr(),
            import_template.len() as _,
            &mut private,
        ),
        CKR_OK as CK_RV
    );
    let mut local = CK_TRUE as CK_BBOOL;
    let mut never_extractable = CK_TRUE as CK_BBOOL;
    let mut history = [
        scalar_attribute(CKA_LOCAL as _, &mut local),
        scalar_attribute(CKA_NEVER_EXTRACTABLE as _, &mut never_extractable),
    ];
    assert_eq!(
        crate::api::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            private,
            history.as_mut_ptr(),
            history.len() as _,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(local, CK_FALSE as CK_BBOOL);
    assert_eq!(never_extractable, CK_FALSE as CK_BBOOL);
    assert_eq!(
        crate::api::C_DestroyObject(TEST_SESSION_HANDLE, private),
        CKR_OK as CK_RV
    );

    let other = crate::PcscAppletConnector::new(base, &crate::openpgp::OPENPGP_AID, None, reader);
    crate::Connector::establish_secure_channel(&other, &crate::openpgp::OPENPGP_AID).unwrap();
    assert_eq!(login(CKU_USER as _, &mut pin), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as _,
            private_template.as_mut_ptr(),
            private_template.len() as _,
            &mut public,
            &mut private
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV,
        "management authorization must not be replayed after applet selection changes"
    );
    finalize_for_test();
    drop(guard);
}

#[test]
fn immutable_piv_key_rejects_attribute_moves_without_changing_identity() {
    let guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let original_id = with_test_slot_context(TEST_SLOT_ID, |ctx| {
        let object = ctx.memory_objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            pin_policy: 2,
            touch_policy: 1,
        };
        object.private = true;
        object.unique_id.clone()
    });
    let mut destination = [0x82];
    let mut attr = bytes_attribute(CKA_ID as _, &mut destination);
    let rv = crate::api::C_SetAttributeValue(TEST_SESSION_HANDLE, 2, &mut attr, 1);
    let after = with_test_slot_context(TEST_SLOT_ID, |ctx| ctx.resolve_object(2).unwrap().unwrap());
    finalize_for_test();
    drop(guard);
    assert_eq!(rv, CKR_ACTION_PROHIBITED as CK_RV);
    assert_eq!(after.unique_id, original_id);
    assert!(matches!(
        after.material,
        crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            ..
        }
    ));
}

#[test]
fn destroyable_false_is_enforced() {
    let guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        let object = ctx.memory_objects.get_mut(&1).unwrap();
        object.material = crate::KeyMaterial::FidoCredential {
            rp_id_hash: [0; 32],
            response_cbor: vec![0xa0],
        };
        object.class = CKO_DATA as _;
        object.token = true;
        object.private = true;
    });
    let mut flag = CK_TRUE as CK_BBOOL;
    let mut attr = scalar_attribute(CKA_DESTROYABLE as _, &mut flag);
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(flag, CK_FALSE as CK_BBOOL);
    let rv = crate::api::C_DestroyObject(TEST_SESSION_HANDLE, 1);
    finalize_for_test();
    drop(guard);
    assert_eq!(
        rv, CKR_ACTION_PROHIBITED as CK_RV,
        "destroy=false must prohibit deletion"
    );
}

#[test]
fn unique_id_create_is_readonly() {
    let guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let mut class = CKO_DATA as CK_OBJECT_CLASS;
    let mut id = *b"caller-id";
    let mut attrs = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        bytes_attribute(CKA_UNIQUE_ID as _, &mut id),
    ];
    let mut handle = 0;
    let rv = crate::api::C_CreateObject(
        TEST_SESSION_HANDLE,
        attrs.as_mut_ptr(),
        attrs.len() as _,
        &mut handle,
    );
    finalize_for_test();
    drop(guard);
    assert_eq!(
        rv, CKR_ATTRIBUTE_READ_ONLY as CK_RV,
        "supplied unique ID must fail as read-only"
    );
}

#[test]
fn imported_piv_history() {
    let mut slot = crate::abi_test_piv_slot().unwrap();
    slot.keys[0].origin = crate::piv::ORIGIN_IMPORTED;
    let object = crate::Slot::token_objects(&slot, 7)
        .unwrap()
        .into_iter()
        .find(|o| o.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let actual = (
        object.attribute_value(CKA_ALWAYS_SENSITIVE as _),
        object.attribute_value(CKA_NEVER_EXTRACTABLE as _),
    );
    assert_eq!(
        actual,
        (Some(vec![0]), Some(vec![0])),
        "imported keys must not claim generated history"
    );
}

#[test]
fn openpgp_replacement_gets_new_identity() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let mut slot = crate::OpenPgpSlot::new(connector, Vec::new());
    slot.keys.push(crate::openpgp::KeyInfo {
        key_ref: crate::openpgp::KeyRef::Decipher,
        algorithm: crate::openpgp::Algorithm::Ecdh(crate::openpgp::Curve::X25519),
        public_key: crate::openpgp::PublicKey::Raw {
            curve: crate::openpgp::Curve::X25519,
            key: vec![1; 32],
        },
        pin_policy: 0,
        touch_policy: 1,
        local: false,
    });
    let get_id = |slot: &crate::OpenPgpSlot| {
        crate::Slot::token_objects(slot, 7)
            .unwrap()
            .into_iter()
            .find(|o| o.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            .unwrap()
            .unique_id
    };
    let original = get_id(&slot);
    slot.keys[0].public_key = crate::openpgp::PublicKey::Raw {
        curve: crate::openpgp::Curve::X25519,
        key: vec![2; 32],
    };
    let replacement = get_id(&slot);
    assert_ne!(
        original, replacement,
        "different native key should not reuse its predecessor's identity"
    );
}

#[test]
fn derived_generation_attribute() {
    let mut object = crate::default_objects().unwrap().remove(&2).unwrap();
    let base = object.clone();
    object.set_derived_history(&base, CKM_ECDH1_DERIVE as _);
    assert!(!object.local);
    assert_eq!(
        object.attribute_value(CKA_KEY_GEN_MECHANISM as _),
        Some(
            (CK_UNAVAILABLE_INFORMATION as CK_ULONG)
                .to_ne_bytes()
                .to_vec()
        )
    );
}

#[test]
fn context_specific_requires_always_authenticate() {
    let guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        let object = ctx.memory_objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            pin_policy: 2,
            touch_policy: 1,
        };
        object.private = true;
        object.sign = true;
        object.decrypt = false;
        object.sensitive = true;
        object.extractable = false;
        assert_eq!(
            object.attribute_value(CKA_ALWAYS_AUTHENTICATE as _),
            Some(vec![0])
        );
    });
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    let mut pin = *b"1234";
    let rv = crate::api::C_Login(
        TEST_SESSION_HANDLE,
        CKU_CONTEXT_SPECIFIC as _,
        pin.as_mut_ptr(),
        pin.len() as _,
    );
    finalize_for_test();
    drop(guard);
    assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED as CK_RV);
}

#[cfg(feature = "embedded-virtual-yubikey")]
#[test]
fn openpgp_so_provisions_and_inspects_keys_without_private_crypto_or_replacement() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let base = std::sync::Arc::new(crate::EmbeddedVirtualYubiKeyConnector::new().unwrap());
    let connector = std::rc::Rc::new(crate::PcscAppletConnector::new(
        base,
        &crate::openpgp::OPENPGP_AID,
        None,
        std::sync::Arc::new(crate::PcscReaderState::default()),
    ));
    let mut slot = crate::OpenPgpSlot::new_with_device(
        connector,
        crate::openpgp::OPENPGP_AID.to_vec(),
        std::sync::Arc::new(crate::device::DeviceContext::test()),
    );
    crate::Slot::init_slot(&mut slot).unwrap();
    install_test_slot_with_backend(TEST_SLOT_ID, Box::new(slot));
    with_test_slot_context(TEST_SLOT_ID, |ctx| ctx.memory_objects.clear());
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_RW_SESSION | CKF_SERIAL_SESSION) as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    let login = |role, password: &mut [u8]| {
        crate::api::C_Login(session, role, password.as_mut_ptr(), password.len() as _)
    };
    let mut user = *b"123456";
    let mut admin = *b"12345678";
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut id = [1u8];
    let mut bits = 2048 as CK_ULONG;
    let mut public_template = [
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        scalar_attribute(CKA_MODULUS_BITS as _, &mut bits),
        bytes_attribute(CKA_ID as _, &mut id),
    ];
    let mut private_template = [
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        scalar_attribute(CKA_SIGN as _, &mut yes),
        bytes_attribute(CKA_ID as _, &mut id),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = 0;
    let mut private = 0;
    let mut generate = |public: &mut CK_OBJECT_HANDLE, private: &mut CK_OBJECT_HANDLE| {
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as _,
            private_template.as_mut_ptr(),
            private_template.len() as _,
            public,
            private,
        )
    };
    assert_eq!(login(CKU_USER as _, &mut user), CKR_OK as CK_RV);
    assert_eq!(
        generate(&mut public, &mut private),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
    assert_eq!(login(CKU_SO as _, &mut admin), CKR_OK as CK_RV);
    assert_eq!(generate(&mut public, &mut private), CKR_OK as CK_RV);
    assert_eq!(
        find_by_bytes_attribute(session, CKO_PRIVATE_KEY as _, CKA_ID as _, &[1]),
        vec![private]
    );
    let identity = read_bytes_attribute(session, private, CKA_UNIQUE_ID as _);
    let mut policy = 1 as CK_ULONG;
    let mut attribute = scalar_attribute(crate::CKA_YUBICO_TOUCH_POLICY, &mut policy);
    assert_eq!(
        crate::api::C_SetAttributeValue(session, private, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        read_bytes_attribute(session, private, CKA_UNIQUE_ID as _),
        identity
    );
    let mut signature = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut signature, private),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, private),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    let mut rejected_public = 0;
    let mut rejected_private = 0;
    assert_eq!(
        generate(&mut rejected_public, &mut rejected_private),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(
        read_bytes_attribute(session, private, CKA_UNIQUE_ID as _),
        identity
    );

    let key = crate::SoftwareSigningKey::generate_rsa(2048).unwrap();
    let crate::SoftwarePublicKey::Rsa {
        mut modulus,
        mut exponent,
    } = key.public_key()
    else {
        unreachable!()
    };
    let mut components = key.rsa_private_components().unwrap();
    let [d, p, q, _, _, _] = &mut components;
    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut kind = CKK_RSA as CK_KEY_TYPE;
    let mut imported_id = [2u8];
    let mut import = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut kind),
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        bytes_attribute(CKA_ID as _, &mut imported_id),
        bytes_attribute(CKA_MODULUS as _, &mut modulus),
        bytes_attribute(CKA_PUBLIC_EXPONENT as _, &mut exponent),
        bytes_attribute(CKA_PRIVATE_EXPONENT as _, d),
        bytes_attribute(CKA_PRIME_1 as _, p),
        bytes_attribute(CKA_PRIME_2 as _, q),
    ];
    let mut imported = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            import.as_mut_ptr(),
            import.len() as _,
            &mut imported
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        find_by_bytes_attribute(session, CKO_PRIVATE_KEY as _, CKA_ID as _, &[2]),
        vec![imported]
    );
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            import.as_mut_ptr(),
            import.len() as _,
            &mut imported
        ),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
    assert!(find_by_bytes_attribute(session, CKO_PRIVATE_KEY as _, CKA_ID as _, &[1]).is_empty());
    assert_eq!(login(CKU_USER as _, &mut user), CKR_OK as CK_RV);
    private = find_by_bytes_attribute(session, CKO_PRIVATE_KEY as _, CKA_ID as _, &[1])[0];
    assert_eq!(
        crate::api::C_SignInit(session, &mut signature, private),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SetAttributeValue(session, private, &mut attribute, 1),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    finalize_for_test();
}
