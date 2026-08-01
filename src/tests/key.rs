use super::*;

fn generate_software_key_pair(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    parameters: Option<&mut [u8]>,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut public_template = Vec::new();
    let mut modulus_bits = 1024 as CK_ULONG;
    if mechanism_type == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        public_template.push(scalar_attribute(
            CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            &mut modulus_bits,
        ));
    }
    if let Some(parameters) = parameters {
        public_template.push(bytes_attribute(
            CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            parameters,
        ));
    }
    let mut public_verify = CK_TRUE as CK_BBOOL;
    let mut public_encrypt = CK_TRUE as CK_BBOOL;
    if mechanism_type != CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        public_template.push(scalar_attribute(
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            &mut public_verify,
        ));
    }
    if mechanism_type == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        public_template.push(scalar_attribute(
            CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            &mut public_encrypt,
        ));
    }

    let mut private_template = Vec::new();
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut derive = CK_TRUE as CK_BBOOL;
    if mechanism_type != CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        private_template.push(scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign));
    }
    if mechanism_type == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        private_template.push(scalar_attribute(
            CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            &mut decrypt,
        ));
    }
    if matches!(
        mechanism_type,
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE
            || x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE
    ) {
        private_template.push(scalar_attribute(
            CKA_DERIVE as CK_ATTRIBUTE_TYPE,
            &mut derive,
        ));
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut public,
            &mut private,
        ),
        CKR_OK as CK_RV
    );
    (public, private)
}

fn sign_and_verify(
    session: CK_SESSION_HANDLE,
    public: CK_OBJECT_HANDLE,
    private: CK_OBJECT_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
) {
    let message = b"software session private key";
    let mut mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, private),
        CKR_OK as CK_RV
    );
    let mut signature_length = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            message.as_ptr().cast_mut(),
            message.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    let mut signature = vec![0; signature_length as usize];
    assert_eq!(
        crate::api::C_Sign(
            session,
            message.as_ptr().cast_mut(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_VerifyInit(session, &mut mechanism, public),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            session,
            message.as_ptr().cast_mut(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_length,
        ),
        CKR_OK as CK_RV
    );
}

#[test]
fn software_hmac_session_keys_generate_import_sign_and_verify() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    for (key_type, mechanism_type, length) in [
        (CKK_GENERIC_SECRET, CKM_SHA256_HMAC, 32),
        (CKK_SHA_1_HMAC, CKM_SHA_1_HMAC, 20),
        (CKK_SHA256_HMAC, CKM_SHA256_HMAC, 32),
        (CKK_SHA384_HMAC, CKM_SHA384_HMAC, 48),
        (CKK_SHA512_HMAC, CKM_SHA512_HMAC, 64),
    ] {
        let mut key_type = key_type as CK_KEY_TYPE;
        let mut length = length as CK_ULONG;
        let mut sign = CK_TRUE as CK_BBOOL;
        let mut verify = CK_TRUE as CK_BBOOL;
        let mut template = [
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
            scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
            scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
            scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
        ];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_GenerateKey(
                TEST_SESSION_HANDLE,
                &mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut key,
            ),
            CKR_OK as CK_RV
        );
        with_test_slot_context(TEST_SLOT_ID, |context| {
            assert!(matches!(
                context.resolve_object(key).unwrap().unwrap().material,
                crate::KeyMaterial::SoftwareSecret(_)
            ));
        });
        sign_and_verify(
            TEST_SESSION_HANDLE,
            key,
            key,
            mechanism_type as CK_MECHANISM_TYPE,
        );
    }

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_FALSE as CK_BBOOL;
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut value = [0x0bu8; 20];
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
        scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut sensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ];
    let mut imported = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, imported, &mut value_attribute, 1,),
        CKR_OK as CK_RV
    );
    assert_eq!(value_attribute.ulValueLen, value.len() as CK_ULONG);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, imported),
        CKR_OK as CK_RV
    );
    let first = b"Hi ";
    let second = b"There";
    assert_eq!(
        crate::api::C_SignUpdate(
            TEST_SESSION_HANDLE,
            first.as_ptr().cast_mut(),
            first.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SignUpdate(
            TEST_SESSION_HANDLE,
            second.as_ptr().cast_mut(),
            second.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut signature = [0u8; 32];
    let mut signature_length = signature.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_SignFinal(
            TEST_SESSION_HANDLE,
            signature.as_mut_ptr(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        signature,
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ]
    );

    assert_eq!(
        crate::api::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, imported),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            first.as_ptr().cast_mut(),
            first.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            second.as_ptr().cast_mut(),
            second.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_VerifyFinal(
            TEST_SESSION_HANDLE,
            signature.as_mut_ptr(),
            signature_length,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, imported),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            TEST_SESSION_HANDLE,
            b"Hi There".as_ptr().cast_mut(),
            8,
            signature.as_mut_ptr(),
            signature_length - 1,
        ),
        CKR_SIGNATURE_LEN_RANGE as CK_RV
    );
    signature[0] ^= 1;
    assert_eq!(
        crate::api::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, imported),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            TEST_SESSION_HANDLE,
            b"Hi There".as_ptr().cast_mut(),
            8,
            signature.as_mut_ptr(),
            signature_length,
        ),
        CKR_SIGNATURE_INVALID as CK_RV
    );

    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut token_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ];
    let mut rejected = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            token_template.as_mut_ptr(),
            token_template.len() as CK_ULONG,
            &mut rejected,
        ),
        CKR_TOKEN_WRITE_PROTECTED as CK_RV
    );
    assert_eq!(rejected, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

fn object_ec_point(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut attribute = CK_ATTRIBUTE {
        type_: CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    let mut point = vec![0; attribute.ulValueLen as usize];
    attribute.pValue = point.as_mut_ptr().cast();
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    point
}

fn derive_secret(
    session: CK_SESSION_HANDLE,
    private: CK_OBJECT_HANDLE,
    peer: &mut [u8],
) -> Vec<u8> {
    let object = derive_key_object(session, private, peer, &mut []);
    let mut attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    let mut value = vec![0; attribute.ulValueLen as usize];
    attribute.pValue = value.as_mut_ptr().cast();
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    value
}

fn derive_key_object(
    session: CK_SESSION_HANDLE,
    private: CK_OBJECT_HANDLE,
    peer: &mut [u8],
    templ: &mut [CK_ATTRIBUTE],
) -> CK_OBJECT_HANDLE {
    let mut parameters = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL as CK_EC_KDF_TYPE,
        pSharedData: std::ptr::null_mut(),
        ulSharedDataLen: 0,
        pPublicData: peer.as_mut_ptr(),
        ulPublicDataLen: peer.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        pParameter: (&mut parameters as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut mechanism,
            private,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object,
        ),
        CKR_OK as CK_RV
    );
    object
}

#[test]
fn software_ecdh_materializes_typed_session_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let (public, private) = generate_software_key_pair(
        TEST_SESSION_HANDLE,
        CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        Some(
            &mut crate::piv_ec_parameters(crate::piv::Algorithm::EccP256)
                .unwrap()
                .to_vec(),
        ),
    );
    let mut peer = object_ec_point(TEST_SESSION_HANDLE, public);
    let mut aes_type = CKK_AES as CK_KEY_TYPE;
    let mut aes_length = 16 as CK_ULONG;
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_FALSE as CK_BBOOL;
    let mut aes_template = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes_type),
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut aes_length),
        scalar_attribute(CKA_ENCRYPT as CK_ATTRIBUTE_TYPE, &mut enabled),
        scalar_attribute(CKA_DECRYPT as CK_ATTRIBUTE_TYPE, &mut enabled),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut sensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
    ];
    let aes = derive_key_object(TEST_SESSION_HANDLE, private, &mut peer, &mut aes_template);
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.resolve_object(aes).unwrap().unwrap();
        assert_eq!(object.key_type, CKK_AES as CK_KEY_TYPE);
        assert!(object.encrypt && object.decrypt);
        assert!(object.sensitive && !object.extractable);
        assert!(object.always_sensitive && object.never_extractable);
        assert!(!object.local);
        assert_eq!(
            object.key_gen_mechanism,
            Some(CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE)
        );
        assert!(
            matches!(object.material, crate::KeyMaterial::SoftwareSecret(ref value) if value.len() == 16)
        );
    });
    let mut ecb = CK_MECHANISM {
        mechanism: CKM_AES_ECB as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut plaintext = *b"derived AES key!";
    let mut ciphertext = [0; 16];
    let mut ciphertext_length = ciphertext.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_EncryptInit(TEST_SESSION_HANDLE, &mut ecb, aes),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Encrypt(
            TEST_SESSION_HANDLE,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_length,
        ),
        CKR_OK as CK_RV
    );
    let mut recovered = [0; 16];
    let mut recovered_length = recovered.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_DecryptInit(TEST_SESSION_HANDLE, &mut ecb, aes),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Decrypt(
            TEST_SESSION_HANDLE,
            ciphertext.as_mut_ptr(),
            ciphertext_length,
            recovered.as_mut_ptr(),
            &mut recovered_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(recovered, plaintext);

    let mut hmac_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut hmac_length = 32 as CK_ULONG;
    let mut nonsensitive = CK_FALSE as CK_BBOOL;
    let mut hmac_extractable = CK_TRUE as CK_BBOOL;
    let mut hmac_template = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut hmac_type),
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut hmac_length),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut enabled),
        scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut enabled),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut nonsensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut hmac_extractable),
    ];
    let hmac = derive_key_object(TEST_SESSION_HANDLE, private, &mut peer, &mut hmac_template);
    sign_and_verify(
        TEST_SESSION_HANDLE,
        hmac,
        hmac,
        CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.resolve_object(hmac).unwrap().unwrap();
        assert!(!object.always_sensitive);
        assert!(!object.never_extractable);
    });
    finalize_for_test();
}

#[test]
fn software_session_key_pairs_cover_every_supported_curve() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let (rsa_public, rsa_private) = generate_software_key_pair(
        TEST_SESSION_HANDLE,
        CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        None,
    );
    sign_and_verify(
        TEST_SESSION_HANDLE,
        rsa_public,
        rsa_private,
        CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE,
    );
    sign_and_verify(
        TEST_SESSION_HANDLE,
        rsa_public,
        rsa_private,
        CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
    );
    let plaintext = b"software RSA decryption";
    let mut rsa = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_EncryptInit(TEST_SESSION_HANDLE, &mut rsa, rsa_public),
        CKR_OK as CK_RV
    );
    let mut encrypted_length = 0;
    assert_eq!(
        crate::api::C_Encrypt(
            TEST_SESSION_HANDLE,
            plaintext.as_ptr().cast_mut(),
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut encrypted_length,
        ),
        CKR_OK as CK_RV
    );
    let mut encrypted = vec![0; encrypted_length as usize];
    assert_eq!(
        crate::api::C_Encrypt(
            TEST_SESSION_HANDLE,
            plaintext.as_ptr().cast_mut(),
            plaintext.len() as CK_ULONG,
            encrypted.as_mut_ptr(),
            &mut encrypted_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DecryptInit(TEST_SESSION_HANDLE, &mut rsa, rsa_private),
        CKR_OK as CK_RV
    );
    let mut recovered_length = 0;
    assert_eq!(
        crate::api::C_Decrypt(
            TEST_SESSION_HANDLE,
            encrypted.as_mut_ptr(),
            encrypted_length,
            std::ptr::null_mut(),
            &mut recovered_length,
        ),
        CKR_OK as CK_RV
    );
    let mut recovered = vec![0; recovered_length as usize];
    assert_eq!(
        crate::api::C_Decrypt(
            TEST_SESSION_HANDLE,
            encrypted.as_mut_ptr(),
            encrypted_length,
            recovered.as_mut_ptr(),
            &mut recovered_length,
        ),
        CKR_OK as CK_RV
    );
    recovered.truncate(recovered_length as usize);
    assert_eq!(recovered, plaintext);

    let mut oaep_parameters = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };
    let mut oaep = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        pParameter: (&mut oaep_parameters as *mut CK_RSA_PKCS_OAEP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        crate::api::C_EncryptInit(TEST_SESSION_HANDLE, &mut oaep, rsa_public),
        CKR_OK as CK_RV
    );
    encrypted_length = 0;
    assert_eq!(
        crate::api::C_Encrypt(
            TEST_SESSION_HANDLE,
            plaintext.as_ptr().cast_mut(),
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut encrypted_length,
        ),
        CKR_OK as CK_RV
    );
    encrypted.resize(encrypted_length as usize, 0);
    assert_eq!(
        crate::api::C_Encrypt(
            TEST_SESSION_HANDLE,
            plaintext.as_ptr().cast_mut(),
            plaintext.len() as CK_ULONG,
            encrypted.as_mut_ptr(),
            &mut encrypted_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DecryptInit(TEST_SESSION_HANDLE, &mut oaep, rsa_private),
        CKR_OK as CK_RV
    );
    recovered_length = 0;
    assert_eq!(
        crate::api::C_Decrypt(
            TEST_SESSION_HANDLE,
            encrypted.as_mut_ptr(),
            encrypted_length,
            std::ptr::null_mut(),
            &mut recovered_length,
        ),
        CKR_OK as CK_RV
    );
    recovered.resize(recovered_length as usize, 0);
    assert_eq!(
        crate::api::C_Decrypt(
            TEST_SESSION_HANDLE,
            encrypted.as_mut_ptr(),
            encrypted_length,
            recovered.as_mut_ptr(),
            &mut recovered_length,
        ),
        CKR_OK as CK_RV
    );
    recovered.truncate(recovered_length as usize);
    assert_eq!(recovered, plaintext);

    for (algorithm, mut parameters, sign_mechanism) in [
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P224).to_vec(),
            CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P256).to_vec(),
            CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P384).to_vec(),
            CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P521).to_vec(),
            CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::K256).to_vec(),
            CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP256).to_vec(),
            CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP384).to_vec(),
            CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP512).to_vec(),
            CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
        ),
        (
            CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::piv_ec_parameters(crate::piv::Algorithm::Ed25519)
                .unwrap()
                .to_vec(),
            CKM_EDDSA as CK_MECHANISM_TYPE,
        ),
    ] {
        let (public, private) =
            generate_software_key_pair(TEST_SESSION_HANDLE, algorithm, Some(&mut parameters));
        sign_and_verify(TEST_SESSION_HANDLE, public, private, sign_mechanism);
    }
    finalize_for_test();
}

#[test]
fn software_session_ecdh_covers_every_supported_curve() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    for (algorithm, mut parameters) in [
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P224).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P256).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P384).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::P521).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::K256).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP256).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP384).to_vec(),
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::ec_curve_parameters(crate::EcCurve::BrainpoolP512).to_vec(),
        ),
        (
            CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            crate::piv_ec_parameters(crate::piv::Algorithm::X25519)
                .unwrap()
                .to_vec(),
        ),
    ] {
        let (first_public, first_private) =
            generate_software_key_pair(TEST_SESSION_HANDLE, algorithm, Some(&mut parameters));
        let (second_public, second_private) =
            generate_software_key_pair(TEST_SESSION_HANDLE, algorithm, Some(&mut parameters));
        let mut first_point = object_ec_point(TEST_SESSION_HANDLE, first_public);
        let mut second_point = object_ec_point(TEST_SESSION_HANDLE, second_public);
        let first = derive_secret(TEST_SESSION_HANDLE, first_private, &mut second_point);
        let second = derive_secret(TEST_SESSION_HANDLE, second_private, &mut first_point);
        assert_eq!(first, second);
        assert!(first.iter().any(|byte| *byte != 0));
    }
    finalize_for_test();
}

#[test]
fn software_private_token_keys_require_the_dedicated_encrypted_store() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    with_test_slot_context(TEST_SLOT_ID, |context| {
        context
            .set_token_storage_provider(Box::new(crate::storage::MemoryStorageProvider::new()))
            .unwrap();
    });

    let mut modulus_bits = 1024 as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
    ];
    let mut private_template = [scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token)];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut public,
            &mut private,
        ),
        CKR_TOKEN_WRITE_PROTECTED as CK_RV
    );
    assert_eq!(public, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(private, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_EC as CK_KEY_TYPE;
    let mut parameters = crate::ec_curve_parameters(crate::EcCurve::P256).to_vec();
    let mut value = [0u8; 32];
    value[31] = 1;
    let mut import_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bytes_attribute(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE, &mut parameters),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ];
    let mut imported = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            import_template.as_mut_ptr(),
            import_template.len() as CK_ULONG,
            &mut imported,
        ),
        CKR_TOKEN_WRITE_PROTECTED as CK_RV
    );
    assert_eq!(imported, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    let mut session_token = CK_FALSE as CK_BBOOL;
    import_template[2] = scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_token);
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            import_template.as_mut_ptr(),
            import_template.len() as CK_ULONG,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let imported_object = context.resolve_object(imported).unwrap().unwrap();
        assert!(!imported_object.token);
        assert!(matches!(
            imported_object.material,
            crate::KeyMaterial::SoftwarePrivate(_)
        ));
    });

    assert_eq!(
        crate::api::C_GenerateKeyPair(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut public,
            &mut private,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let public_object = context.resolve_object(public).unwrap().unwrap();
        assert!(public_object.token);
        assert!(matches!(
            public_object.material,
            crate::KeyMaterial::Public(_)
        ));
        let private_object = context.resolve_object(private).unwrap().unwrap();
        assert!(!private_object.token);
        assert!(matches!(
            private_object.material,
            crate::KeyMaterial::SoftwarePrivate(_)
        ));
    });
    finalize_for_test();
}

#[test]
fn hardware_slots_do_not_fallback_to_generic_software_private_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism_count = 0;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, std::ptr::null_mut(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    let mut mechanisms = vec![0; mechanism_count as usize];
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, mechanisms.as_mut_ptr(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    assert!(!mechanisms.contains(&(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)));
    assert!(!mechanisms.contains(&(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE)));

    let mut modulus_bits = 1024 as CK_ULONG;
    let mut public_template = [scalar_attribute(
        CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
        &mut modulus_bits,
    )];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut public,
            &mut private,
        ),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(public, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(private, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_EC as CK_KEY_TYPE;
    let mut parameters = crate::ec_curve_parameters(crate::EcCurve::P256).to_vec();
    let mut value = [0u8; 32];
    value[31] = 1;
    let mut import_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        bytes_attribute(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE, &mut parameters),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            import_template.as_mut_ptr(),
            import_template.len() as CK_ULONG,
            &mut object,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(object, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    finalize_for_test();
}

#[test]
pub fn openpgp_generation_templates_select_reference_algorithm_and_touch_policy() {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut token = CK_TRUE as CK_BBOOL;
    let mut key_type = CKK_EC_EDWARDS as CK_KEY_TYPE;
    let mut id = [3u8];
    let mut params = crate::openpgp::Curve::Ed25519.oid().to_vec();
    let mut touch_policy = 2 as CK_ULONG;
    let public = [
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            pValue: params.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: params.len() as CK_ULONG,
        },
    ];
    let private = [
        public[0],
        public[1],
        public[2],
        CK_ATTRIBUTE {
            type_: crate::CKA_YUBICO_TOUCH_POLICY,
            pValue: &mut touch_policy as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];

    let generation =
        crate::openpgp_generate_key_pair_parameters(&mechanism, &public, &private).unwrap();
    assert_eq!(generation.key_ref, crate::OpenPgpKeyRef::Authentication);
    assert_eq!(generation.algorithm, crate::OpenPgpAlgorithm::Ed25519);
    assert_eq!(generation.touch_policy, 2);
}

#[test]
pub fn generate_key_creates_secret_key_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GetAttributeValue(
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
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.memory_objects.get(&key).unwrap();
        match &object.material {
            crate::KeyMaterial::Secret(value) => {
                assert_eq!(value.len(), value_len as usize);
                assert!(value.iter().any(|byte| *byte != 0));
            }
            material => panic!("expected generated secret material, got {material:?}"),
        }
    });

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
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
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut rsa_mechanism, key),
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
        crate::api::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], key);
    assert_eq!(
        crate::api::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn generated_secret_key_enforces_sensitivity_policy() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value_attribute.ulValueLen, value_len);

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
        crate::api::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            harden.as_mut_ptr(),
            harden.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    assert_eq!(
        value_attribute.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    let mut make_non_sensitive = CK_FALSE as CK_BBOOL;
    let mut make_non_sensitive_attribute = CK_ATTRIBUTE {
        type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
        pValue: &mut make_non_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        crate::api::C_SetAttributeValue(
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
        crate::api::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            &mut make_extractable_attribute,
            1
        ),
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
        crate::api::C_GetAttributeValue(
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
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn session_objects_are_shared_on_the_slot_and_removed_with_the_creator() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);
    install_test_session(TEST_SLOT_ID + 1, TEST_SESSION_HANDLE + 2);

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
        crate::api::C_GenerateKey(
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
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut class_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE + 1, key, &mut class_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE + 2, key, &mut class_attribute, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut secret_class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut find_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut secret_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::api::C_FindObjectsInit(
            TEST_SESSION_HANDLE + 1,
            find_template.as_mut_ptr(),
            find_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert!(!with_test_slot_context(TEST_SLOT_ID, |context| {
        context.memory_objects.contains_key(&key)
    }));
    let mut found = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut found_count = 0;
    assert_eq!(
        crate::api::C_FindObjects(
            TEST_SESSION_HANDLE + 1,
            found.as_mut_ptr(),
            found.len() as CK_ULONG,
            &mut found_count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(found_count, 0);
    assert_eq!(
        crate::api::C_FindObjectsFinal(TEST_SESSION_HANDLE + 1),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn removing_a_slot_clears_its_runtime_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    {
        let child = test_slot_context(TEST_SLOT_ID);
        let mut context = child.lock().unwrap();
        let mut session_object = context.memory_objects.get(&1).unwrap().clone();
        session_object.unique_id.clear();
        session_object.token = false;
        session_object.creator_session = Some(TEST_SESSION_HANDLE);
        let object_handle = context.insert_object(session_object).unwrap();
        context
            .sessions
            .get_mut(&TEST_SESSION_HANDLE)
            .unwrap()
            .find_operation = Some(crate::FindOperation {
            objects: vec![object_handle],
            next: 0,
        });

        context.close_slot_state(TEST_SLOT_ID, true);
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
        assert!(context.login_role.is_none());
        assert!(context.memory_objects.is_empty());
    }
    crate::lock_context()
        .unwrap()
        .as_mut()
        .unwrap()
        .slot_contexts
        .get_mut()
        .unwrap()
        .remove(&TEST_SLOT_ID);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn slot_info_does_not_trigger_slot_discovery() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot_with_backend(TEST_SLOT_ID, Box::new(test_slot(false)));

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert_eq!(
        crate::api::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
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
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    assert_eq!(
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::api::C_GenerateKey(999, &mut mechanism, ::std::ptr::null_mut(), 0, &mut key),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            duplicate_template.as_mut_ptr(),
            duplicate_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, invalid_bool.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn yubihsm_key_pair_generation_requires_a_token_private_key() {
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

    let (private, public, _) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &session_public_template, &[])
            .unwrap();
    assert!(private.token);
    assert!(!public.token);

    let rv: CK_RV = crate::yubihsm_generate_key_pair_command(
        &mechanism,
        &token_public_template,
        &session_private_template,
    )
    .unwrap_err()
    .into();
    assert_eq!(rv, CKR_TEMPLATE_INCONSISTENT as CK_RV);
}

#[test]
pub fn yubihsm_key_pair_generation_requires_matching_ids() {
    let mut modulus_bits = 2048 as CK_ULONG;
    let mut token_object = CK_TRUE as CK_BBOOL;
    let mut session_object = CK_FALSE as CK_BBOOL;
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
    let token_attribute = CK_ATTRIBUTE {
        type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        pValue: (&mut token_object as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    let session_attribute = CK_ATTRIBUTE {
        type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        pValue: (&mut session_object as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let public_template = [modulus_attribute, token_attribute, public_id_attribute];

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
    let (object, _, _) = crate::yubihsm_generate_key_pair_command(
        &mechanism,
        &public_template,
        &[private_id_attribute],
    )
    .unwrap();
    assert_eq!(object.id, public_id);

    let (object, public, _) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &[modulus_attribute], &[]).unwrap();
    assert!(object.id.is_empty());
    assert!(!public.token);

    private_id.copy_from_slice(&[0, 2]);
    let (private, public, _) = crate::yubihsm_generate_key_pair_command(
        &mechanism,
        &[modulus_attribute, session_attribute, public_id_attribute],
        &[private_id_attribute],
    )
    .unwrap();
    assert_eq!(private.id, private_id);
    assert_eq!(public.id, public_id);
    assert!(!public.token);
}

#[test]
pub fn generate_random_validates_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut random_data = [0u8; 16];

    assert_eq!(
        crate::api::C_GenerateRandom(1, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GenerateRandom(999, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}
