use super::*;
use crate::{KeyMaterial, TokenObject};

fn create_software_wrap_test_key(
    session: CK_SESSION_HANDLE,
    key_type: CK_KEY_TYPE,
    value: &mut [u8],
    wrap: bool,
    unwrap: bool,
    extractable: bool,
) -> CK_OBJECT_HANDLE {
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = key_type;
    let mut wrap = CK_BBOOL::from(wrap);
    let mut unwrap = CK_BBOOL::from(unwrap);
    let mut extractable = CK_BBOOL::from(extractable);
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, value),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut unwrap),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
    ];
    let mut handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut handle,
        ),
        CKR_OK as CK_RV
    );
    handle
}

fn software_unwrap_test_template(
    key_type: &mut CK_KEY_TYPE,
    sign: &mut CK_BBOOL,
    verify: &mut CK_BBOOL,
) -> [CK_ATTRIBUTE; 3] {
    [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, key_type),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, sign),
        scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, verify),
    ]
}

#[test]
fn software_aes_wrap_and_unwrap_secret_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut wrapping_value = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let wrapper = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_AES as CK_KEY_TYPE,
        &mut wrapping_value,
        true,
        true,
        true,
    );
    let mut target_value = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let target = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_SHA256_HMAC as CK_KEY_TYPE,
        &mut target_value,
        false,
        false,
        true,
    );
    let mut kw = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            target,
            std::ptr::null_mut(),
            &mut wrapped_length,
        ),
        CKR_OK as CK_RV
    );

    let mut no_wrap_value = [0x22; 16];
    let no_wrap = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_AES as CK_KEY_TYPE,
        &mut no_wrap_value,
        false,
        true,
        true,
    );
    let mut denied_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            no_wrap,
            target,
            std::ptr::null_mut(),
            &mut denied_length,
        ),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );
    let mut nonextractable_value = [0x33; 16];
    let nonextractable = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_GENERIC_SECRET as CK_KEY_TYPE,
        &mut nonextractable_value,
        false,
        false,
        false,
    );
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            nonextractable,
            std::ptr::null_mut(),
            &mut denied_length,
        ),
        CKR_KEY_UNEXTRACTABLE as CK_RV
    );
    assert_eq!(wrapped_length, 24);
    let mut short = [0; 23];
    let mut short_length = short.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            target,
            short.as_mut_ptr(),
            &mut short_length,
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(short_length, 24);
    let mut wrapped = vec![0; wrapped_length as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        wrapped,
        [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
            0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ]
    );

    let mut key_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut template = software_unwrap_test_template(&mut key_type, &mut sign, &mut verify);
    let mut unwrapped = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.resolve_object(unwrapped).unwrap().unwrap();
        assert_eq!(object.key_type, CKK_SHA256_HMAC as CK_KEY_TYPE);
        assert!(object.sign && object.verify);
        assert!(!object.local && !object.always_sensitive && !object.never_extractable);
        assert_eq!(object.key_gen_mechanism, None);
        assert_eq!(object.creator_session, Some(TEST_SESSION_HANDLE));
        assert!(
            matches!(object.material, KeyMaterial::SoftwareSecret(ref value) if value.as_slice() == target_value)
        );
    });

    let mut kwp_target_value = *b"arbitrary key material";
    let kwp_target = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_GENERIC_SECRET as CK_KEY_TYPE,
        &mut kwp_target_value,
        false,
        false,
        true,
    );
    let mut kwp = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut kwp_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            wrapper,
            kwp_target,
            std::ptr::null_mut(),
            &mut kwp_length,
        ),
        CKR_OK as CK_RV
    );
    let mut kwp_wrapped = vec![0; kwp_length as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            wrapper,
            kwp_target,
            kwp_wrapped.as_mut_ptr(),
            &mut kwp_length,
        ),
        CKR_OK as CK_RV
    );
    let mut generic_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut generic_sign = CK_FALSE as CK_BBOOL;
    let mut generic_verify = CK_FALSE as CK_BBOOL;
    let mut generic_template =
        software_unwrap_test_template(&mut generic_type, &mut generic_sign, &mut generic_verify);
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            wrapper,
            kwp_wrapped.as_mut_ptr(),
            kwp_wrapped.len() as CK_ULONG,
            generic_template.as_mut_ptr(),
            generic_template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_OK as CK_RV
    );
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut token_template = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut generic_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
    ];
    let object_count = with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len());
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            wrapper,
            kwp_wrapped.as_mut_ptr(),
            kwp_wrapped.len() as CK_ULONG,
            token_template.as_mut_ptr(),
            token_template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_TOKEN_WRITE_PROTECTED as CK_RV
    );
    assert_eq!(
        with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
        object_count
    );
    kwp_wrapped[0] ^= 1;
    let object_count = with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len());
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            wrapper,
            kwp_wrapped.as_mut_ptr(),
            kwp_wrapped.len() as CK_ULONG,
            generic_template.as_mut_ptr(),
            generic_template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_WRAPPED_KEY_INVALID as CK_RV
    );
    assert_eq!(
        with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
        object_count
    );
    finalize_for_test();
}

fn generate_software_rsa_wrap_key_pair(
    session: CK_SESSION_HANDLE,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut modulus_bits = 1024 as CK_ULONG;
    let mut public_wrap = CK_TRUE as CK_BBOOL;
    let mut private_unwrap = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut public_wrap),
    ];
    let mut private_template = [scalar_attribute(
        CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
        &mut private_unwrap,
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

fn software_rsa_wrap_round_trip(
    session: CK_SESSION_HANDLE,
    mechanism: &mut CK_MECHANISM,
    public: CK_OBJECT_HANDLE,
    private: CK_OBJECT_HANDLE,
    target: CK_OBJECT_HANDLE,
    target_value: &[u8],
    expected_wrapped_length: CK_ULONG,
) {
    let mut wrapped_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            mechanism,
            public,
            target,
            std::ptr::null_mut(),
            &mut wrapped_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(wrapped_length, expected_wrapped_length);
    let mut short = vec![0; wrapped_length as usize - 1];
    let mut short_length = short.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            mechanism,
            public,
            target,
            short.as_mut_ptr(),
            &mut short_length,
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(short_length, wrapped_length);

    let mut wrapped = vec![0; wrapped_length as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            mechanism,
            public,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_length,
        ),
        CKR_OK as CK_RV
    );
    let mut key_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut template = software_unwrap_test_template(&mut key_type, &mut sign, &mut verify);
    let mut unwrapped = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            mechanism,
            private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.resolve_object(unwrapped).unwrap().unwrap();
        assert!(object.sign && object.verify);
        assert!(
            matches!(object.material, KeyMaterial::SoftwareSecret(ref value) if value.as_slice() == target_value)
        );
    });

    let object_count = with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len());
    wrapped[0] ^= 1;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            mechanism,
            private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_WRAPPED_KEY_INVALID as CK_RV
    );
    assert_eq!(
        with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
        object_count
    );
    if expected_wrapped_length > 128 {
        wrapped[0] ^= 1;
        wrapped[128] ^= 1;
        assert_eq!(
            crate::api::C_UnwrapKey(
                session,
                mechanism,
                private,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut unwrapped,
            ),
            CKR_WRAPPED_KEY_INVALID as CK_RV
        );
        assert_eq!(
            with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
            object_count
        );
    }
}

#[test]
fn software_rsa_wrap_mechanisms_wrap_and_unwrap_secret_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let (public, private) = generate_software_rsa_wrap_key_pair(TEST_SESSION_HANDLE);
    let mut target_value = [0x5a; 32];
    let target = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_SHA256_HMAC as CK_KEY_TYPE,
        &mut target_value,
        false,
        false,
        true,
    );

    let mut pkcs = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    software_rsa_wrap_round_trip(
        TEST_SESSION_HANDLE,
        &mut pkcs,
        public,
        private,
        target,
        &target_value,
        128,
    );

    let mut oversized_value = [0x33; 118];
    let oversized = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_GENERIC_SECRET as CK_KEY_TYPE,
        &mut oversized_value,
        false,
        false,
        true,
    );
    let mut oversized_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut pkcs,
            public,
            oversized,
            std::ptr::null_mut(),
            &mut oversized_length,
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );

    let mut label = b"software RSA OAEP wrap".to_vec();
    let mut oaep_parameters = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: label.as_mut_ptr().cast(),
        ulSourceDataLen: label.len() as CK_ULONG,
    };
    let mut oaep = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        pParameter: (&mut oaep_parameters as *mut CK_RSA_PKCS_OAEP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    software_rsa_wrap_round_trip(
        TEST_SESSION_HANDLE,
        &mut oaep,
        public,
        private,
        target,
        &target_value,
        128,
    );

    for aes_key_bits in [128, 192, 256] {
        let mut rsa_aes_parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
            ulAESKeyBits: aes_key_bits,
            pOAEPParams: &mut oaep_parameters,
        };
        let mut rsa_aes = CK_MECHANISM {
            mechanism: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
            pParameter: (&mut rsa_aes_parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast(),
            ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
        };
        software_rsa_wrap_round_trip(
            TEST_SESSION_HANDLE,
            &mut rsa_aes,
            public,
            private,
            target,
            &target_value,
            168,
        );
    }
    let mut invalid_parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 64,
        pOAEPParams: &mut oaep_parameters,
    };
    let mut invalid = CK_MECHANISM {
        mechanism: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: (&mut invalid_parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    let mut invalid_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut invalid,
            public,
            target,
            std::ptr::null_mut(),
            &mut invalid_length,
        ),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );

    let mut large_hash_oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA512 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };
    let mut large_hash_parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        pOAEPParams: &mut large_hash_oaep,
    };
    let mut large_hash = CK_MECHANISM {
        mechanism: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: (&mut large_hash_parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut large_hash,
            public,
            target,
            std::ptr::null_mut(),
            &mut invalid_length,
        ),
        CKR_WRAPPING_KEY_SIZE_RANGE as CK_RV
    );
    finalize_for_test();
}

struct YubiHsmWrapTestObject<'a> {
    id: u16,
    object_type: u8,
    algorithm: u8,
    capabilities: &'a [usize],
    delegated_capabilities: &'a [usize],
    label: &'a str,
    public_key: Option<crate::YubiHsmPublicKey>,
}

fn yubihsm_wrap_test_object(
    slot_id: CK_SLOT_ID,
    definition: YubiHsmWrapTestObject<'_>,
) -> Vec<TokenObject> {
    let info = crate::YubiHsmObjectInfo {
        capabilities: crate::yubihsm_capabilities(definition.capabilities),
        id: definition.id,
        length: match definition.algorithm {
            crate::YUBIHSM_ALGO_AES128 | crate::YUBIHSM_ALGO_AES128_CCM_WRAP => 16,
            _ => 256,
        },
        domains: 0xffff,
        object_type: definition.object_type,
        algorithm: definition.algorithm,
        sequence: 1,
        origin: 1,
        label: definition.label.to_owned(),
        delegated_capabilities: crate::yubihsm_capabilities(definition.delegated_capabilities),
    };
    match definition.public_key {
        Some(public_key)
            if definition.object_type == crate::YUBIHSM_ASYMMETRIC_KEY
                || definition.object_type == crate::YUBIHSM_WRAP_KEY =>
        {
            yubihsm_objects_with_persisted_public(slot_id, info, public_key)
        }
        public_key => crate::yubihsm_token_objects(slot_id, info, public_key).unwrap(),
    }
}

fn install_yubihsm_wrap_test_objects(
    session: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
) -> (
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) {
    let public_key = crate::YubiHsmPublicKey {
        algorithm: crate::YUBIHSM_ALGO_RSA_2048,
        key: vec![0xa5; 256],
    };
    let public_wrap_parameters = crate::yubihsm::DelegatedObjectParameters {
        object: crate::YubiHsmObjectParameters {
            id: 33,
            label: "RSA public wrap",
            domains: 0xffff,
            capabilities: [0; 8],
            algorithm: crate::YUBIHSM_ALGO_RSA_2048,
        },
        delegated_capabilities: [0; 8],
    };
    let public_wrap_command = crate::YubiHsmCommand::put_delegated_object(
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        &public_wrap_parameters,
        &public_key.key,
    )
    .unwrap();
    crate::with_session_context_mut(session, |ctx| {
        ctx._get_session(session)?
            .1
            .yubihsm_command(&public_wrap_command)
            .map(|_| ())
    })
    .unwrap();

    let definitions = [
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 30,
                object_type: crate::YUBIHSM_SYMMETRIC_KEY,
                algorithm: crate::YUBIHSM_ALGO_AES128,
                capabilities: &[0x10, 0x32, 0x33],
                delegated_capabilities: &[],
                label: "exportable AES",
                public_key: None,
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 31,
                object_type: crate::YUBIHSM_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_AES128_CCM_WRAP,
                capabilities: &[],
                delegated_capabilities: &[],
                label: "AES-CCM wrap",
                public_key: None,
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 32,
                object_type: crate::YUBIHSM_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_RSA_2048,
                capabilities: &[0x10],
                delegated_capabilities: &[],
                label: "RSA wrap",
                public_key: Some(public_key.clone()),
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 33,
                object_type: crate::YUBIHSM_PUBLIC_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_RSA_2048,
                capabilities: &[],
                delegated_capabilities: &[],
                label: "RSA public wrap",
                public_key: Some(public_key),
            },
        ),
    ];
    let mut target = None;
    let mut ccm = None;
    let mut rsa_private = None;
    let mut rsa_synthetic_public = None;
    let mut rsa_public_wrap = None;
    with_test_slot_context(slot_id, |context| {
        for objects in definitions {
            for object in objects {
                let (id, material_type) = match object.material {
                    KeyMaterial::YubiHsm {
                        id, object_type, ..
                    } => (id, object_type),
                    _ => unreachable!(),
                };
                let handle = context.insert_object(object).unwrap();
                match (id, material_type) {
                    (30, crate::YUBIHSM_SYMMETRIC_KEY) => target = Some(handle),
                    (31, crate::YUBIHSM_WRAP_KEY) => ccm = Some(handle),
                    (32, crate::YUBIHSM_WRAP_KEY) => rsa_private = Some(handle),
                    (32, crate::YUBIHSM_WRAP_KEY_PUBLIC) => rsa_synthetic_public = Some(handle),
                    (33, crate::YUBIHSM_PUBLIC_WRAP_KEY) => rsa_public_wrap = Some(handle),
                    _ => {}
                }
            }
        }
    });
    (
        target.unwrap(),
        ccm.unwrap(),
        rsa_private.unwrap(),
        rsa_synthetic_public.unwrap(),
        rsa_public_wrap.unwrap(),
    )
}

fn install_yubihsm_wrap_targets(slot_id: CK_SLOT_ID) -> Vec<(CK_OBJECT_HANDLE, u8, u16)> {
    let definitions = [
        (
            34,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_DATA,
            "exportable opaque",
            true,
            false,
        ),
        (
            35,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            "exportable certificate",
            true,
            false,
        ),
        (
            36,
            crate::YUBIHSM_TEMPLATE,
            crate::YUBIHSM_ALGO_TEMPLATE_SSH,
            "exportable template",
            true,
            false,
        ),
        (
            37,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_DATA,
            "non-exportable opaque",
            false,
            false,
        ),
        (
            38,
            crate::YUBIHSM_AUTHENTICATION_KEY,
            crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            "delegating authentication key",
            true,
            true,
        ),
    ];
    with_test_slot_context(slot_id, |context| {
        definitions
            .into_iter()
            .map(
                |(id, object_type, algorithm, label, extractable, has_delegated_capabilities)| {
                    let [object] = yubihsm_wrap_test_object(
                        slot_id,
                        YubiHsmWrapTestObject {
                            id,
                            object_type,
                            algorithm,
                            capabilities: if extractable { &[0x10] } else { &[] },
                            delegated_capabilities: if has_delegated_capabilities {
                                &[0x04]
                            } else {
                                &[]
                            },
                            label,
                            public_key: None,
                        },
                    )
                    .try_into()
                    .unwrap();
                    assert_eq!(object.extractable, extractable);
                    if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                        || object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                    {
                        assert_eq!(
                            object.attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE),
                            Some(crate::bool_attribute(extractable))
                        );
                    } else {
                        assert!(object
                            .attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)
                            .is_none());
                    }
                    (context.insert_object(object).unwrap(), object_type, id)
                },
            )
            .collect()
    })
}

#[test]
fn yubihsm_rsa_wrap_generation_uses_pkcs11_template_roles() {
    let mut modulus_bits = 2048 as CK_ULONG;
    let mut wrap = CK_FALSE as CK_BBOOL;
    let mut unwrap = CK_TRUE as CK_BBOOL;
    let public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
    ];
    let private = [scalar_attribute(
        CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
        &mut unwrap,
    )];
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let (_, _, command) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap();
    assert_eq!(command.code(), crate::YubiHsmCommandCode::GenerateWrapKey);

    let mut unsupported_wrap = CK_TRUE as CK_BBOOL;
    let unsupported_public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut unsupported_wrap),
    ];
    assert_eq!(
        CK_RV::from(
            crate::yubihsm_generate_key_pair_command(&mechanism, &unsupported_public, &private)
                .unwrap_err()
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    let mut private_wrap = CK_TRUE as CK_BBOOL;
    let private = [
        scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut unwrap),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut private_wrap),
    ];
    assert_eq!(
        CK_RV::from(
            crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap_err()
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
}

fn rsa_wrap_mechanism(
    full_object: bool,
) -> (
    CK_MECHANISM,
    CK_RSA_AES_KEY_WRAP_PARAMS,
    CK_RSA_PKCS_OAEP_PARAMS,
) {
    let oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };
    let parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        pOAEPParams: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: if full_object {
            crate::CKM_YUBICO_RSA_WRAP
        } else {
            CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE
        },
        pParameter: std::ptr::null_mut(),
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    (mechanism, parameters, oaep)
}

fn initialize_rsa_wrap_mechanism(
    mechanism: &mut CK_MECHANISM,
    parameters: &mut CK_RSA_AES_KEY_WRAP_PARAMS,
    oaep: &mut CK_RSA_PKCS_OAEP_PARAMS,
) {
    parameters.pOAEPParams = oaep;
    mechanism.pParameter = (parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast();
}

fn checked_rv(operation: &str, rv: CK_RV) -> Result<(), String> {
    if rv == CKR_OK as CK_RV {
        Ok(())
    } else {
        Err(format!("{operation} failed with CK_RV 0x{rv:08x}"))
    }
}

fn checked_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, String> {
    let mut attribute = CK_ATTRIBUTE {
        type_: attribute_type,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    checked_rv(
        "C_GetAttributeValue length query",
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
    )?;
    let mut value = vec![0; attribute.ulValueLen as usize];
    attribute.pValue = value.as_mut_ptr().cast();
    checked_rv(
        "C_GetAttributeValue",
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
    )?;
    Ok(value)
}

fn checked_bool_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<bool, String> {
    let value = checked_attribute(session, object, attribute_type)?;
    match value.as_slice() {
        [value] if *value == CK_TRUE as CK_BBOOL => Ok(true),
        [value] if *value == CK_FALSE as CK_BBOOL => Ok(false),
        _ => Err(format!(
            "attribute 0x{attribute_type:08x} was not a CK_BBOOL"
        )),
    }
}

fn checked_ulong_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<CK_ULONG, String> {
    let value = checked_attribute(session, object, attribute_type)?;
    let value: [u8; std::mem::size_of::<CK_ULONG>()] = value
        .try_into()
        .map_err(|_| format!("attribute 0x{attribute_type:08x} was not a CK_ULONG"))?;
    Ok(CK_ULONG::from_ne_bytes(value))
}

fn provision_rsa_public_wrap_key(
    session: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    generated_public: CK_OBJECT_HANDLE,
) -> Result<CK_OBJECT_HANDLE, String> {
    let modulus = checked_attribute(session, generated_public, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
    let algorithm = match modulus.len() {
        256 => crate::YUBIHSM_ALGO_RSA_2048,
        384 => crate::YUBIHSM_ALGO_RSA_3072,
        512 => crate::YUBIHSM_ALGO_RSA_4096,
        length => return Err(format!("unsupported RSA public modulus length {length}")),
    };
    let parameters = crate::yubihsm::DelegatedObjectParameters {
        object: crate::YubiHsmObjectParameters {
            id: 0,
            label: "PKCS11 RSA public wrap test",
            domains: 0xffff,
            capabilities: crate::yubihsm_capabilities(&[0x0c]),
            algorithm,
        },
        delegated_capabilities: [0xff; 8],
    };
    let command = crate::YubiHsmCommand::put_delegated_object(
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        &parameters,
        &modulus,
    )
    .map_err(|error| format!("failed to encode public wrap key: {error:?}"))?;

    crate::with_session_context_mut(session, |ctx| {
        let response = ctx._get_session(session)?.1.yubihsm_command(&command)?;
        let id = crate::parse_yubihsm_object_id(&response)?;
        ctx.refresh_slot_token_objects(slot_id)?;
        ctx.resolved_objects()?
            .into_iter()
            .find_map(|(handle, object)| {
                (object.slot_id == Some(slot_id)
                    && matches!(
                        object.material,
                        KeyMaterial::YubiHsm {
                            id: object_id,
                            object_type: crate::YUBIHSM_PUBLIC_WRAP_KEY,
                            ..
                        } if object_id == id
                    ))
                .then_some(handle)
            })
            .ok_or(CKR_DEVICE_ERROR.into())
    })
    .map_err(|error| format!("failed to provision public wrap key: {error:?}"))
}

pub(super) fn generated_ec_private_rsa_wrap_round_trip(
    slot_id: CK_SLOT_ID,
    pin: &[u8],
) -> Result<(), String> {
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    checked_rv(
        "C_OpenSession",
        crate::api::C_OpenSession(
            slot_id,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
    )?;
    let mut pin = pin.to_vec();
    let login = checked_rv(
        "C_Login",
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
    );
    if let Err(error) = login {
        let _ = crate::api::C_CloseSession(session);
        return Err(error);
    }

    let mut target_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut target_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut wrapper_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut wrapper_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut public_wrap_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut restored = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let operation = (|| -> Result<(), String> {
        let mut ec_parameters = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut sign = CK_TRUE as CK_BBOOL;
        let mut extractable = CK_TRUE as CK_BBOOL;
        let mut token = CK_TRUE as CK_BBOOL;
        let mut ec_public_template = [
            bytes_attribute(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE, &mut ec_parameters),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        ];
        let mut ec_private_template = [
            scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
            scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        ];
        let mut ec_generation = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        checked_rv(
            "C_GenerateKeyPair EC target",
            crate::api::C_GenerateKeyPair(
                session,
                &mut ec_generation,
                ec_public_template.as_mut_ptr(),
                ec_public_template.len() as CK_ULONG,
                ec_private_template.as_mut_ptr(),
                ec_private_template.len() as CK_ULONG,
                &mut target_public,
                &mut target_private,
            ),
        )?;
        let target_id = checked_attribute(session, target_private, CKA_ID as CK_ATTRIBUTE_TYPE)?;

        let mut modulus_bits = 2048 as CK_ULONG;
        let mut wrap = CK_FALSE as CK_BBOOL;
        let mut unwrap = CK_TRUE as CK_BBOOL;
        let mut rsa_public_template = [
            scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
            scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        ];
        let mut rsa_private_template = [
            scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut unwrap),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        ];
        let mut rsa_generation = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        checked_rv(
            "C_GenerateKeyPair RSA wrap key",
            crate::api::C_GenerateKeyPair(
                session,
                &mut rsa_generation,
                rsa_public_template.as_mut_ptr(),
                rsa_public_template.len() as CK_ULONG,
                rsa_private_template.as_mut_ptr(),
                rsa_private_template.len() as CK_ULONG,
                &mut wrapper_public,
                &mut wrapper_private,
            ),
        )?;
        if checked_bool_attribute(session, wrapper_public, CKA_WRAP as CK_ATTRIBUTE_TYPE)?
            || !checked_bool_attribute(session, wrapper_private, CKA_UNWRAP as CK_ATTRIBUTE_TYPE)?
        {
            return Err("generated RSA wrap-key attributes are inconsistent".to_owned());
        }
        public_wrap_key = provision_rsa_public_wrap_key(session, slot_id, wrapper_public)?;

        let (mut mechanism, mut parameters, mut oaep) = rsa_wrap_mechanism(true);
        initialize_rsa_wrap_mechanism(&mut mechanism, &mut parameters, &mut oaep);
        let mut denied_length = 0;
        let denied_rv = crate::api::C_WrapKey(
            session,
            &mut mechanism,
            wrapper_private,
            target_private,
            std::ptr::null_mut(),
            &mut denied_length,
        );
        if denied_rv != CKR_OBJECT_HANDLE_INVALID as CK_RV {
            return Err(format!(
                "C_WrapKey with a private RSA wrap key returned CK_RV 0x{denied_rv:08x}, expected CKR_OBJECT_HANDLE_INVALID"
            ));
        }

        let mut wrapped_length = 0;
        checked_rv(
            "C_WrapKey length query",
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                public_wrap_key,
                target_private,
                std::ptr::null_mut(),
                &mut wrapped_length,
            ),
        )?;
        let mut wrapped = vec![0; wrapped_length as usize];
        checked_rv(
            "C_WrapKey",
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                public_wrap_key,
                target_private,
                wrapped.as_mut_ptr(),
                &mut wrapped_length,
            ),
        )?;
        wrapped.truncate(wrapped_length as usize);

        let collision_rv = crate::api::C_UnwrapKey(
            session,
            &mut mechanism,
            wrapper_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut restored,
        );
        if collision_rv == CKR_OK as CK_RV {
            return Err("C_UnwrapKey replaced an existing object ID".to_owned());
        }
        restored = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

        checked_rv(
            "C_DestroyObject EC target",
            crate::api::C_DestroyObject(session, target_private),
        )?;
        target_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        checked_rv(
            "C_UnwrapKey",
            crate::api::C_UnwrapKey(
                session,
                &mut mechanism,
                wrapper_private,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                std::ptr::null_mut(),
                0,
                &mut restored,
            ),
        )?;

        if checked_ulong_attribute(session, restored, CKA_CLASS as CK_ATTRIBUTE_TYPE)?
            != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || checked_ulong_attribute(session, restored, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
                != CKK_EC as CK_KEY_TYPE
            || checked_attribute(session, restored, CKA_ID as CK_ATTRIBUTE_TYPE)? != target_id
            || !checked_bool_attribute(session, restored, CKA_SIGN as CK_ATTRIBUTE_TYPE)?
            || !checked_bool_attribute(session, restored, CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)?
        {
            return Err("unwrapped EC key does not match the wrapped target".to_owned());
        }
        Ok(())
    })();

    let mut cleanup_error = None;
    for (name, handle) in [
        ("restored EC key", restored),
        ("original EC key", target_private),
        ("RSA public wrap key", public_wrap_key),
        ("RSA wrap key", wrapper_private),
    ] {
        if handle != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            let rv = crate::api::C_DestroyObject(session, handle);
            if rv != CKR_OK as CK_RV && cleanup_error.is_none() {
                cleanup_error = Some(format!("cleanup of {name} failed with CK_RV 0x{rv:08x}"));
            }
        }
    }
    let close_rv = crate::api::C_CloseSession(session);
    if operation.is_ok() && cleanup_error.is_none() && close_rv != CKR_OK as CK_RV {
        cleanup_error = Some(format!("C_CloseSession failed with CK_RV 0x{close_rv:08x}"));
    }
    operation.and_then(|()| cleanup_error.map_or(Ok(()), Err))
}

#[test]
fn generated_ec_key_round_trips_through_private_rsa_wrap_key() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    generated_ec_private_rsa_wrap_round_trip(SLOT_ID, b"0001password").unwrap();

    let commands = commands.borrow();
    for command in [
        crate::YubiHsmCommandCode::GenerateAsymmetricKey,
        crate::YubiHsmCommandCode::GenerateWrapKey,
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        crate::YubiHsmCommandCode::ExportRsaWrapped,
        crate::YubiHsmCommandCode::ImportRsaWrapped,
    ] {
        assert!(
            commands.iter().any(|(actual, _)| *actual == command as u8),
            "missing mock command {command:?}"
        );
    }
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn yubihsm_wrap_and_unwrap_cover_aes_ccm_and_rsa_paths() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let (target, ccm_wrapper, rsa_private, rsa_synthetic_public, rsa_public_wrap) =
        install_yubihsm_wrap_test_objects(session, SLOT_ID);
    let wrap_targets = install_yubihsm_wrap_targets(SLOT_ID);
    assert!(!checked_bool_attribute(session, ccm_wrapper, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(
        !checked_bool_attribute(session, ccm_wrapper, CKA_UNWRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );
    assert!(
        !checked_bool_attribute(session, rsa_private, CKA_UNWRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );
    assert!(
        !checked_bool_attribute(session, rsa_public_wrap, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );

    let mut ccm_mechanism = CK_MECHANISM {
        mechanism: crate::CKM_YUBICO_AES_CCM_WRAP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            target,
            std::ptr::null_mut(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );
    assert!(wrapped_len > 0);
    assert_eq!(
        commands.borrow().last().unwrap().0,
        crate::YubiHsmCommandCode::ExportWrapped as u8
    );

    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut ccm_mechanism,
                ccm_wrapper,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::ExportWrapped as u8);
        assert_eq!(
            last.1,
            [
                0,
                31,
                *target_type,
                target_id.to_be_bytes()[0],
                target_id.to_be_bytes()[1],
            ]
        );
    }
    let mut wrapped = vec![0; wrapped_len as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );
    wrapped.truncate(wrapped_len as usize);
    assert!(wrapped.starts_with(b"wrapped-object:"));
    let last = commands.borrow().last().cloned().unwrap();
    assert_eq!(last.0, crate::YubiHsmCommandCode::ExportWrapped as u8);
    assert_eq!(last.1, [0, 31, crate::YUBIHSM_SYMMETRIC_KEY, 0, 30]);

    let mut imported = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    let imported_is_expected = crate::with_session_context(session, |ctx| {
        let object = ctx
            .resolve_object(imported)?
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        Ok(matches!(
            object.material,
            KeyMaterial::YubiHsm {
                id: 20,
                object_type: crate::YUBIHSM_SYMMETRIC_KEY,
                ..
            }
        ))
    })
    .unwrap();
    assert!(imported_is_expected);

    for (full_object, wrapper, expected_command) in [
        (
            true,
            rsa_public_wrap,
            crate::YubiHsmCommandCode::ExportRsaWrapped,
        ),
        (
            false,
            rsa_private,
            crate::YubiHsmCommandCode::GetRsaWrappedKey,
        ),
    ] {
        let (mut mechanism, mut parameters, mut oaep) = rsa_wrap_mechanism(full_object);
        initialize_rsa_wrap_mechanism(&mut mechanism, &mut parameters, &mut oaep);
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                wrapper,
                target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let mut output = vec![0; length as usize];
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                wrapper,
                target,
                output.as_mut_ptr(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(commands.borrow().last().unwrap().0, expected_command as u8);
    }

    let mut synthetic_output = [0u8; 32];
    let mut synthetic_output_len = synthetic_output.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            rsa_synthetic_public,
            synthetic_output.as_mut_ptr(),
            &mut synthetic_output_len,
        ),
        CKR_KEY_NOT_WRAPPABLE as CK_RV
    );

    let (mut full_rsa, mut full_parameters, mut full_oaep) = rsa_wrap_mechanism(true);
    initialize_rsa_wrap_mechanism(&mut full_rsa, &mut full_parameters, &mut full_oaep);
    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut full_rsa,
                rsa_public_wrap,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::ExportRsaWrapped as u8);
        assert_eq!(last.1[2], *target_type);
        assert_eq!(&last.1[3..5], &target_id.to_be_bytes());
    }

    let (mut key_rsa, mut key_parameters, mut key_oaep) = rsa_wrap_mechanism(false);
    initialize_rsa_wrap_mechanism(&mut key_rsa, &mut key_parameters, &mut key_oaep);
    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut key_rsa,
                rsa_private,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::GetRsaWrappedKey as u8);
        assert_eq!(last.1[2], *target_type);
        assert_eq!(&last.1[3..5], &target_id.to_be_bytes());
    }

    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut full_rsa,
            rsa_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    assert!(commands
        .borrow()
        .iter()
        .any(|(command, _)| { *command == crate::YubiHsmCommandCode::ImportRsaWrapped as u8 }));

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_AES as CK_KEY_TYPE;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut value_len = 16 as CK_ULONG;
    let mut id = 40u16.to_be_bytes();
    let mut label = *b"unwrapped AES";
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut sensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        scalar_attribute(CKA_ENCRYPT as CK_ATTRIBUTE_TYPE, &mut encrypt),
        scalar_attribute(CKA_DECRYPT as CK_ATTRIBUTE_TYPE, &mut decrypt),
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut value_len),
        bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
    ];
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut key_rsa,
            rsa_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    let (imported_id, imported_label, extractable, never_extractable) =
        crate::with_session_context(session, |ctx| {
            let object = ctx
                .resolve_object(imported)?
                .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
            Ok((
                object.id,
                object.label,
                object.extractable,
                object.never_extractable,
            ))
        })
        .unwrap();
    assert_eq!(imported_id, id);
    assert_eq!(imported_label, "unwrapped AES");
    assert!(extractable);
    assert!(!never_extractable);
    assert_eq!(
        commands
            .borrow()
            .iter()
            .filter(|(command, _)| *command == crate::YubiHsmCommandCode::PutRsaWrappedKey as u8)
            .count(),
        1
    );

    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn yubihsm_wrap_rejects_incompatible_keys_and_parameters() {
    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_YUBICO_AES_CCM_WRAP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 1,
    };
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&mechanism).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );

    let mut format = crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS { format: 2 };
    mechanism.pParameter = (&mut format as *mut crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS).cast();
    mechanism.ulParameterLen =
        std::mem::size_of::<crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS>() as CK_ULONG;
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&mechanism).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );

    let (mut rsa, mut parameters, mut oaep) = rsa_wrap_mechanism(true);
    parameters.ulAESKeyBits = 64;
    initialize_rsa_wrap_mechanism(&mut rsa, &mut parameters, &mut oaep);
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&rsa).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
}
