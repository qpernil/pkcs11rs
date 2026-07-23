#[test]
pub fn mechanism_list_reports_supported_mechanisms() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let expected = [
        CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_ECDSA as CK_MECHANISM_TYPE,
        CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
    ];
    let mut count = 0;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut too_small = [0; 1];
    count = too_small.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, too_small.as_mut_ptr(), &mut count),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut mechanisms = [0; 5];
    count = mechanisms.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, mechanisms.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);
    assert_eq!(mechanisms, expected);

    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn mechanism_info_reports_supported_mechanism_details() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(TEST_SLOT_ID, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1024);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & CKF_GENERATE as CK_FLAGS,
        CKF_GENERATE as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_VENDOR_DEFINED as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_tracks_empty_search_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 999;

    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OPERATION_ACTIVE as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 2);
    assert_eq!(objects, [1, 2]);

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);

    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_tracks_single_part_operation_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature_len = 0;

    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);

    let mut small_signature = [0u8; 4];
    signature_len = small_signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            small_signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(signature_len, 256);

    let mut signature = [0u8; 256];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);
    assert!(signature.iter().any(|byte| *byte != 0));
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_and_verify_update_final_buffer_multipart_data() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut first = *b"ab";
    let mut second = *b"cd";
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignUpdate(
            TEST_SESSION_HANDLE,
            first.as_mut_ptr(),
            first.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignUpdate(
            TEST_SESSION_HANDLE,
            second.as_mut_ptr(),
            second.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut signature_len = 0;
    assert_eq!(
        crate::C_SignFinal(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    let mut signature = vec![0; signature_len as usize];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_SignFinal(
            TEST_SESSION_HANDLE,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            first.as_mut_ptr(),
            first.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            second.as_mut_ptr(),
            second.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyFinal(TEST_SESSION_HANDLE, signature.as_mut_ptr(), signature_len,),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn piv_rsa_signing_encodes_ckm_rsa_pkcs_input() {
    let encoded = crate::encode_pkcs1_v1_5_signature_input(b"abc", 16).unwrap();
    assert_eq!(
        encoded,
        [0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, b'a', b'b', b'c']
    );
    assert!(crate::encode_pkcs1_v1_5_signature_input(&[0; 6], 16).is_err());
}

#[test]
pub fn piv_rsa_pss_hash_mapping_preserves_sha3_variants() {
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA224 as CK_MECHANISM_TYPE
    );
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA3_224 as CK_MECHANISM_TYPE
    );
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA3_512 as CK_MECHANISM_TYPE
    );
}

#[test]
pub fn piv_rsa_padding_round_trips_through_raw_rsa() {
    let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let data = b"padding test";
    let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
    let pss = crate::encode_rsa_pss(
        &digest,
        private.size() as usize,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        33,
        32,
    )
    .unwrap();
    let signature = crate::rsa_private_operation(&private, &pss).unwrap();
    let recovered = crate::rsa_public_operation(&public, &signature).unwrap();
    assert!(crate::verify_rsa_pss(
        &recovered,
        &digest,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        33,
        32,
    )
    .unwrap());

    let label = <sha2::Sha256 as sha2::Digest>::digest(b"");
    let encoded = crate::rsa_oaep_pad(
        data,
        private.size() as usize,
        33,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        &label,
    )
    .unwrap();
    assert_eq!(
        crate::rsa_oaep_unpad(
            &encoded,
            33,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            &label,
        )
        .unwrap(),
        data
    );
    let ciphertext = crate::rsa_public_operation(&public, &encoded).unwrap();
    let plaintext = crate::rsa_private_operation(&private, &ciphertext).unwrap();
    assert_eq!(
        crate::rsa_oaep_unpad(
            &plaintext,
            33,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            &label,
        )
        .unwrap(),
        data
    );
}

#[test]
pub fn piv_private_objects_route_rsa_signing_to_the_card_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(true)));
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(PivSigningTestSession {
                slot_id: TEST_SLOT_ID,
                captured: captured.clone(),
            }),
        );
        context
            .logged_in_slots
            .insert(TEST_SLOT_ID, crate::LoginRole::User);
        context.memory_objects.insert(
            42,
            crate::TokenObject {
                slot_id: Some(TEST_SLOT_ID),
                unique_id: "piv-9c-private".to_owned(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: "PIV slot 9C".to_owned(),
                id: vec![2],
                token: true,
                private: true,
                encrypt: false,
                decrypt: false,
                sign: true,
                verify: false,
                derive: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: crate::KeyMaterial::PivPrivate {
                    slot: crate::piv::Slot::Signature,
                    algorithm: crate::piv::Algorithm::Rsa1024,
                    modulus: vec![0x80; 128],
                    public_exponent: vec![1, 0, 1],
                    pin_policy: 0,
                    touch_policy: 0,
                },
            },
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 42),
        CKR_OK as CK_RV
    );
    let mut data = *b"abc";
    let mut signature = [0u8; 128];
    let mut signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature, [0x5a; 128]);
    assert_eq!(
        *captured.borrow(),
        crate::encode_pkcs1_v1_5_signature_input(b"abc", 128).unwrap()
    );

    mechanism.mechanism = CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE;
    let mut long_message = vec![0x42; 512];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 42),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            long_message.as_mut_ptr(),
            long_message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &long_message).unwrap();
    let digest_info = crate::piv_digest_info(mechanism.mechanism, digest.as_ref()).unwrap();
    assert_eq!(
        *captured.borrow(),
        crate::encode_pkcs1_v1_5_signature_input(&digest_info, 128).unwrap()
    );

    mechanism.mechanism = CKM_RSA_X_509 as CK_MECHANISM_TYPE;
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 42),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    let mut raw_input = vec![0; 125];
    raw_input.extend_from_slice(b"abc");
    assert_eq!(*captured.borrow(), raw_input);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_accepts_raw_rsa_and_pss_signatures() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let private_key = {
        let context = crate::lock_context().unwrap();
        match &context
            .as_ref()
            .unwrap()
            .memory_objects
            .get(&2)
            .unwrap()
            .material
        {
            crate::KeyMaterial::RsaPrivate(key) => key.clone(),
            _ => panic!("test private key is not RSA"),
        }
    };
    let key_size = private_key.size() as usize;

    let mut raw_data = b"raw RSA input".to_vec();
    let mut encoded = vec![0; key_size - raw_data.len()];
    encoded.extend_from_slice(&raw_data);
    let mut raw_signature = crate::rsa_private_operation(&private_key, &encoded).unwrap();
    let mut raw_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_X_509 as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut raw_mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            raw_data.as_mut_ptr(),
            raw_data.len() as CK_ULONG,
            raw_signature.as_mut_ptr(),
            raw_signature.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut digest =
        <sha2::Sha256 as sha2::Digest>::digest(b"RSA-PSS verification").to_vec();
    let pss = crate::encode_rsa_pss(
        &digest,
        key_size,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        33,
        32,
    )
    .unwrap();
    let mut pss_signature = crate::rsa_private_operation(&private_key, &pss).unwrap();
    let mut parameters = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        sLen: 32,
    };
    let mut pss_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        pParameter: (&mut parameters as *mut CK_RSA_PKCS_PSS_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut pss_mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            digest.as_mut_ptr(),
            digest.len() as CK_ULONG,
            pss_signature.as_mut_ptr(),
            pss_signature.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_terminal_errors_clear_the_operation() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut oversized_data = [0u8; 246];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            oversized_data.as_mut_ptr(),
            oversized_data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_DATA_LEN_RANGE as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            oversized_data.as_mut_ptr(),
            oversized_data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    let mut data = [1u8];
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_init_reports_key_and_mechanism_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_SignInit(999, &mut mechanism, 2),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 2),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut unsupported, 2),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 999),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OPERATION_ACTIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_operation_is_cleared_when_session_closes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_accepts_matching_rsa_signature() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            1,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_accepts_piv_and_openpgp_ecdsa_public_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = openssl::ec::EcKey::generate(&group).unwrap();
    let mut context = openssl::bn::BigNumContext::new().unwrap();
    let point = signing_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .unwrap();
    let public_key = point[1..].to_vec();
    let data = b"hardware-backed signature";
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();
    let signature = openssl::ecdsa::EcdsaSig::sign(&digest, &signing_key)
        .unwrap()
        .to_der()
        .unwrap();
    let signature = crate::piv_ecdsa_signature(&signature, 32).unwrap();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = data.to_vec();
    let mut signature = signature;

    for material in [
        crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::EccP256,
            public_key: public_key.clone(),
        },
        crate::KeyMaterial::YubiHsm {
            id: 1,
            object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
            algorithm: crate::YUBIHSM_ALGO_EC_P256,
            length: 32,
            domains: 0xffff,
            capabilities: crate::yubihsm_capabilities(&[0x07]),
            delegated_capabilities: [0; 8],
            public_key: public_key.clone(),
            value: std::rc::Rc::new(std::cell::RefCell::new(None)),
        },
        crate::KeyMaterial::OpenPgpPublic {
            algorithm: crate::OpenPgpAlgorithm::Ecdsa(crate::openpgp::Curve::P256),
            public_key,
        },
    ] {
        {
            let mut context = crate::lock_context().unwrap();
            let object = context
                .as_mut()
                .unwrap()
                .memory_objects
                .get_mut(&1)
                .unwrap();
            object.key_type = CKK_EC as CK_KEY_TYPE;
            object.verify = true;
            object.material = material;
        }
        assert_eq!(
            crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_Verify(
                TEST_SESSION_HANDLE,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
    }

    let signing_key =
        openssl::pkey::PKey::private_key_from_raw_bytes(&[0x42; 32], openssl::pkey::Id::ED25519)
            .unwrap();
    let mut signer = openssl::sign::Signer::new_without_digest(&signing_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&data).unwrap();
    let public_key = signing_key.raw_public_key().unwrap();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    for material in [
        crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::Ed25519,
            public_key: public_key.clone(),
        },
        crate::KeyMaterial::YubiHsm {
            id: 1,
            object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
            algorithm: crate::YUBIHSM_ALGO_ED25519,
            length: 32,
            domains: 0xffff,
            capabilities: crate::yubihsm_capabilities(&[0x16]),
            delegated_capabilities: [0; 8],
            public_key: public_key.clone(),
            value: std::rc::Rc::new(std::cell::RefCell::new(None)),
        },
        crate::KeyMaterial::OpenPgpPublic {
            algorithm: crate::OpenPgpAlgorithm::Ed25519,
            public_key,
        },
    ] {
        {
            let mut context = crate::lock_context().unwrap();
            let object = context
                .as_mut()
                .unwrap()
                .memory_objects
                .get_mut(&1)
                .unwrap();
            object.key_type = CKK_EC_EDWARDS as CK_KEY_TYPE;
            object.verify = true;
            object.material = material;
        }
        assert_eq!(
            crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_Verify(
                TEST_SESSION_HANDLE,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                signature.as_ptr() as *mut u8,
                signature.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn piv_attestation_certificate_supplies_public_key_for_metadata_fallback() {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = openssl::ec::EcKey::generate(&group).unwrap();
    let signing_key = openssl::pkey::PKey::from_ec_key(signing_key).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "PIV attestation test")
        .unwrap();
    let name = name.build();
    let mut builder = openssl::x509::X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&signing_key).unwrap();
    builder
        .set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(openssl::asn1::Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();
    builder
        .sign(&signing_key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let attestation = builder.build().to_der().unwrap();

    let parsed =
        crate::piv_public_key_from_certificate(crate::piv::Algorithm::EccP256, &attestation)
            .unwrap();
    let crate::PivPublicKey::Ec(parsed) = parsed else {
        panic!("expected an EC public key");
    };
    let mut context = openssl::bn::BigNumContext::new().unwrap();
    let expected = signing_key
        .ec_key()
        .unwrap()
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .unwrap();
    assert_eq!(parsed, expected[1..]);
}

#[test]
fn piv_dynamic_attestation_objects_fetch_only_deferred_attributes() {
    let transmissions = std::rc::Rc::new(std::cell::Cell::new(0));
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(CountingConnector {
        transmissions: transmissions.clone(),
    });
    let object = crate::TokenObject {
        slot_id: Some(1),
        unique_id: "piv-attestation".to_owned(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: "PIV attestation".to_owned(),
        id: vec![2],
        token: false,
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
        local: true,
        key_gen_mechanism: None,
        owner_session: Some(2),
        material: crate::KeyMaterial::PivAttestation {
            connector,
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::EccP256,
            value: std::rc::Rc::new(std::cell::RefCell::new(None)),
            attempted: std::rc::Rc::new(std::cell::Cell::new(false)),
        },
    };

    assert!(object
        .attribute_value(CKA_LABEL as CK_ATTRIBUTE_TYPE)
        .is_some());
    assert_eq!(
        object.attribute_value(CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE),
        Some(crate::ulong_attribute(CKC_X_509 as CK_ULONG))
    );
    assert_eq!(transmissions.get(), 0);
    let _ = object.size();
    assert_eq!(transmissions.get(), 0);
    assert!(object
        .attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE)
        .is_none());
    assert_eq!(transmissions.get(), 1);
    assert!(object
        .attribute_value(CKA_SUBJECT as CK_ATTRIBUTE_TYPE)
        .is_none());
    assert_eq!(transmissions.get(), 1);
}

#[test]
fn piv_attestation_slot_is_not_exposed_as_a_dynamic_key() {
    let private_key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let slot = crate::PivSlot {
        connector: std::rc::Rc::new(FailingConnector),
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
        keys: vec![crate::PivKey {
            slot: crate::piv::Slot::Attestation,
            algorithm: crate::piv::Algorithm::Rsa2048,
            public_key: crate::PivPublicKey::Rsa(public_key),
            attestation: std::rc::Rc::new(std::cell::RefCell::new(None)),
            attestation_attempted: std::rc::Rc::new(std::cell::Cell::new(false)),
            pin_policy: 0,
            touch_policy: 0,
            origin: crate::piv::ORIGIN_GENERATED,
        }],
        certificates: Vec::new(),
        data_objects: Vec::new(),
    };

    assert!(crate::Slot::token_objects(&slot, 1)
        .unwrap()
        .iter()
        .all(|object| object.token));
}

#[test]
pub fn verify_reports_signature_mismatches() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );

    let mut short_signature = [0u8; 4];
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            short_signature.as_mut_ptr(),
            short_signature.len() as CK_ULONG
        ),
        CKR_SIGNATURE_LEN_RANGE as CK_RV
    );

    signature[0] ^= 0xff;
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_SIGNATURE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_init_reports_key_and_mechanism_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_VerifyInit(999, &mut mechanism, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut unsupported, 1),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 999),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OPERATION_ACTIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_operation_is_cleared_when_session_closes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);

    let mut data = [1u8];
    let mut signature = [0u8; 32];
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}
