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

fn create_software_trusted_wrap_target(
    session: CK_SESSION_HANDLE,
    value: &mut [u8],
) -> CK_OBJECT_HANDLE {
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut wrap_with_trusted = CK_TRUE as CK_BBOOL;
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, value),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        scalar_attribute(
            CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            &mut wrap_with_trusted,
        ),
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
    let mut trusted_only_value = [0x44; 16];
    let trusted_only =
        create_software_trusted_wrap_target(TEST_SESSION_HANDLE, &mut trusted_only_value);
    assert!(
        checked_bool_attribute(
            TEST_SESSION_HANDLE,
            trusted_only,
            CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
        )
        .unwrap()
    );
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            wrapper,
            trusted_only,
            std::ptr::null_mut(),
            &mut denied_length,
        ),
        CKR_KEY_NOT_WRAPPABLE as CK_RV
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

#[test]
fn software_wrap_and_unwrap_policy_templates_are_enforced_and_reported() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut aes_type = CKK_AES as CK_KEY_TYPE;
    let mut wrapper_value = [0x31; 16];
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut required_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut required_sign = CK_TRUE as CK_BBOOL;
    let mut wrap_policy = [scalar_attribute(
        CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
        &mut required_type,
    )];
    let mut unwrap_policy = [scalar_attribute(
        CKA_SIGN as CK_ATTRIBUTE_TYPE,
        &mut required_sign,
    )];
    let mut wrapper_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes_type),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut wrapper_value),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut enabled),
        scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut enabled),
        CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
            pValue: wrap_policy.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(&wrap_policy) as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNWRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
            pValue: unwrap_policy.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(&unwrap_policy) as CK_ULONG,
        },
    ];
    let mut wrapper = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            wrapper_template.as_mut_ptr(),
            wrapper_template.len() as CK_ULONG,
            &mut wrapper,
        ),
        CKR_OK as CK_RV
    );
    let wrap_policy_pointer = wrapper_template[5].pValue;
    let mut invalid_handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    wrapper_template[5].pValue = std::ptr::null_mut();
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            wrapper_template.as_mut_ptr(),
            wrapper_template.len() as CK_ULONG,
            &mut invalid_handle,
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    wrapper_template[5].pValue = wrap_policy_pointer;
    wrapper_template[5].ulValueLen = 1;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            wrapper_template.as_mut_ptr(),
            wrapper_template.len() as CK_ULONG,
            &mut invalid_handle,
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut target_value = [0x52; 16];
    let target = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_SHA256_HMAC as CK_KEY_TYPE,
        &mut target_value,
        false,
        false,
        true,
    );
    let mut mismatch_value = [0x53; 16];
    let mismatch = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_GENERIC_SECRET as CK_KEY_TYPE,
        &mut mismatch_value,
        false,
        false,
        true,
    );
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            wrapper,
            mismatch,
            std::ptr::null_mut(),
            &mut wrapped_len,
        ),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            wrapper,
            target,
            std::ptr::null_mut(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );
    let mut wrapped = vec![0; wrapped_len as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            wrapper,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );

    let mut outer = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, wrapper, &mut outer, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        outer.ulValueLen as usize,
        std::mem::size_of::<CK_ATTRIBUTE>()
    );
    let mut nested = CK_ATTRIBUTE {
        type_: 0,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    outer.pValue = (&mut nested as *mut CK_ATTRIBUTE).cast();
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, wrapper, &mut outer, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(nested.type_, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE);
    assert_eq!(
        nested.ulValueLen as usize,
        std::mem::size_of::<CK_KEY_TYPE>()
    );
    let mut short = [0u8; 1];
    nested.pValue = short.as_mut_ptr().cast();
    nested.ulValueLen = short.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, wrapper, &mut outer, 1),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(nested.ulValueLen, CK_UNAVAILABLE_INFORMATION as CK_ULONG);
    let mut returned_type = 0 as CK_KEY_TYPE;
    nested.pValue = (&mut returned_type as *mut CK_KEY_TYPE).cast();
    nested.ulValueLen = std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG;
    assert!(!nested.pValue.is_null());
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, wrapper, &mut outer, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(returned_type, CKK_SHA256_HMAC as CK_KEY_TYPE);

    let mut output_type = CKK_SHA256_HMAC as CK_KEY_TYPE;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut output_template = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut output_type),
        scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
    ];
    let mut unwrapped = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            wrapper,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            output_template.as_mut_ptr(),
            output_template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.resolve_object(unwrapped).unwrap().unwrap();
        assert!(object.sign && object.verify);
    });

    let mut disabled = CK_FALSE as CK_BBOOL;
    let mut conflicting = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut output_type),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut disabled),
    ];
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            wrapper,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            conflicting.as_mut_ptr(),
            conflicting.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
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

fn generate_extractable_software_private_key(
    session: CK_SESSION_HANDLE,
    mechanism_type: CK_MECHANISM_TYPE,
    key_type: CK_KEY_TYPE,
    mut parameters: Option<Vec<u8>>,
) -> CK_OBJECT_HANDLE {
    let mut modulus_bits = 1024 as CK_ULONG;
    let mut public_template = if mechanism_type == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        vec![scalar_attribute(
            CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            &mut modulus_bits,
        )]
    } else {
        vec![bytes_attribute(
            CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            parameters.as_mut().unwrap(),
        )]
    };
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut derive = CK_FALSE as CK_BBOOL;
    let mut private_template = [
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
        scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut derive),
    ];
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
        CKR_OK as CK_RV,
        "failed to generate key type {key_type}"
    );
    private
}

fn software_private_unwrap_template(
    key_type: &mut CK_KEY_TYPE,
    class: &mut CK_OBJECT_CLASS,
    label: &mut [u8],
    sign: &mut CK_BBOOL,
    derive: &mut CK_BBOOL,
    sensitive: &mut CK_BBOOL,
    extractable: &mut CK_BBOOL,
) -> [CK_ATTRIBUTE; 7] {
    [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, key_type),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, label),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, sign),
        scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, derive),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, sensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, extractable),
    ]
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

#[test]
fn software_private_keys_wrap_as_bare_pkcs8_with_template_policy() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut wrapping_value = [0x42; 32];
    let aes_wrapper = create_software_wrap_test_key(
        TEST_SESSION_HANDLE,
        CKK_AES as CK_KEY_TYPE,
        &mut wrapping_value,
        true,
        true,
        false,
    );
    let mut kwp = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let cases = [
        (
            CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            CKK_RSA as CK_KEY_TYPE,
            None,
        ),
        (
            CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            CKK_EC as CK_KEY_TYPE,
            Some(vec![
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            ]),
        ),
        (
            CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            CKK_EC_EDWARDS as CK_KEY_TYPE,
            Some(vec![
                0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
            ]),
        ),
        (
            CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            Some(vec![
                0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
            ]),
        ),
    ];
    let mut wrapped_p256 = None;
    let mut p256_target = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    for (mechanism_type, expected_key_type, parameters) in cases {
        let target = generate_extractable_software_private_key(
            TEST_SESSION_HANDLE,
            mechanism_type,
            expected_key_type,
            parameters,
        );
        let expected_public = with_test_slot_context(TEST_SLOT_ID, |context| {
            let object = context.resolve_object(target).unwrap().unwrap();
            assert!(object.sign);
            object.public_key_info().unwrap()
        });
        let mut wrapped_length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                TEST_SESSION_HANDLE,
                &mut kwp,
                aes_wrapper,
                target,
                std::ptr::null_mut(),
                &mut wrapped_length,
            ),
            CKR_OK as CK_RV
        );
        let mut wrapped = vec![0; wrapped_length as usize];
        assert_eq!(
            crate::api::C_WrapKey(
                TEST_SESSION_HANDLE,
                &mut kwp,
                aes_wrapper,
                target,
                wrapped.as_mut_ptr(),
                &mut wrapped_length,
            ),
            CKR_OK as CK_RV
        );

        let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
        let mut key_type = expected_key_type;
        let mut label = b"unwrapped private key".to_vec();
        let mut sign = CK_FALSE as CK_BBOOL;
        let mut derive = CK_TRUE as CK_BBOOL;
        let mut sensitive = CK_FALSE as CK_BBOOL;
        let mut extractable = CK_TRUE as CK_BBOOL;
        let template = software_private_unwrap_template(
            &mut key_type,
            &mut class,
            &mut label,
            &mut sign,
            &mut derive,
            &mut sensitive,
            &mut extractable,
        );
        let mut supplied_template = template
            .into_iter()
            .filter(|attribute| {
                !(expected_key_type == CKK_EC_EDWARDS as CK_KEY_TYPE
                    && attribute.type_ == CKA_CLASS as CK_ATTRIBUTE_TYPE)
                    && !(expected_key_type == CKK_EC_MONTGOMERY as CK_KEY_TYPE
                        && attribute.type_ == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)
            })
            .collect::<Vec<_>>();
        let mut unwrapped = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_UnwrapKey(
                TEST_SESSION_HANDLE,
                &mut kwp,
                aes_wrapper,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                supplied_template.as_mut_ptr(),
                supplied_template.len() as CK_ULONG,
                &mut unwrapped,
            ),
            CKR_OK as CK_RV
        );
        with_test_slot_context(TEST_SLOT_ID, |context| {
            let object = context.resolve_object(unwrapped).unwrap().unwrap();
            assert_eq!(object.class, CKO_PRIVATE_KEY as CK_OBJECT_CLASS);
            assert_eq!(object.key_type, expected_key_type);
            assert_eq!(object.label, "unwrapped private key");
            assert!(!object.sign && object.derive);
            assert!(!object.sensitive && object.extractable);
            assert!(!object.always_sensitive && !object.never_extractable && !object.local);
            assert!(matches!(object.material, KeyMaterial::SoftwarePrivate(_)));
            assert_eq!(object.public_key_info().unwrap(), expected_public);
        });
        if expected_key_type == CKK_EC as CK_KEY_TYPE {
            p256_target = target;
            wrapped_p256 = Some(wrapped);
        }
    }

    let mut kw = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut refused_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut kw,
            aes_wrapper,
            p256_target,
            std::ptr::null_mut(),
            &mut refused_length,
        ),
        CKR_KEY_NOT_WRAPPABLE as CK_RV
    );

    let mut wrapped_p256 = wrapped_p256.unwrap();
    let object_count = with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len());
    wrapped_p256[0] ^= 1;
    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_EC as CK_KEY_TYPE;
    let mut label = b"tampered private key".to_vec();
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut derive = CK_FALSE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_FALSE as CK_BBOOL;
    let mut template = software_private_unwrap_template(
        &mut key_type,
        &mut class,
        &mut label,
        &mut sign,
        &mut derive,
        &mut sensitive,
        &mut extractable,
    );
    let mut unwrapped = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            aes_wrapper,
            wrapped_p256.as_mut_ptr(),
            wrapped_p256.len() as CK_ULONG,
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

    wrapped_p256[0] ^= 1;
    let mut mismatched_key_type = CKK_RSA as CK_KEY_TYPE;
    let mut mismatched_template = software_private_unwrap_template(
        &mut mismatched_key_type,
        &mut class,
        &mut label,
        &mut sign,
        &mut derive,
        &mut sensitive,
        &mut extractable,
    );
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut kwp,
            aes_wrapper,
            wrapped_p256.as_mut_ptr(),
            wrapped_p256.len() as CK_ULONG,
            mismatched_template.as_mut_ptr(),
            mismatched_template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_WRAPPED_KEY_INVALID as CK_RV
    );
    assert_eq!(
        with_test_slot_context(TEST_SLOT_ID, |context| context.memory_objects.len()),
        object_count
    );

    let (rsa_public, rsa_private) = generate_software_rsa_wrap_key_pair(TEST_SESSION_HANDLE);
    let mut oaep_parameters = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };
    let mut rsa_aes_parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        pOAEPParams: &mut oaep_parameters,
    };
    let mut rsa_aes = CK_MECHANISM {
        mechanism: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        pParameter: (&mut rsa_aes_parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    let mut rsa_aes_wrapped_length = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut rsa_aes,
            rsa_public,
            p256_target,
            std::ptr::null_mut(),
            &mut rsa_aes_wrapped_length,
        ),
        CKR_OK as CK_RV
    );
    let mut rsa_aes_wrapped = vec![0; rsa_aes_wrapped_length as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut rsa_aes,
            rsa_public,
            p256_target,
            rsa_aes_wrapped.as_mut_ptr(),
            &mut rsa_aes_wrapped_length,
        ),
        CKR_OK as CK_RV
    );
    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_EC as CK_KEY_TYPE;
    let mut label = b"RSA-AES unwrapped private key".to_vec();
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut derive = CK_FALSE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_FALSE as CK_BBOOL;
    let mut template = software_private_unwrap_template(
        &mut key_type,
        &mut class,
        &mut label,
        &mut sign,
        &mut derive,
        &mut sensitive,
        &mut extractable,
    );
    assert_eq!(
        crate::api::C_UnwrapKey(
            TEST_SESSION_HANDLE,
            &mut rsa_aes,
            rsa_private,
            rsa_aes_wrapped.as_mut_ptr(),
            rsa_aes_wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut unwrapped,
        ),
        CKR_OK as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        let original = context.resolve_object(p256_target).unwrap().unwrap();
        let restored = context.resolve_object(unwrapped).unwrap().unwrap();
        assert_eq!(restored.label, "RSA-AES unwrapped private key");
        assert_eq!(restored.public_key_info(), original.public_key_info());
    });

    let mut oaep = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        pParameter: (&mut oaep_parameters as *mut CK_RSA_PKCS_OAEP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        crate::api::C_WrapKey(
            TEST_SESSION_HANDLE,
            &mut oaep,
            rsa_public,
            p256_target,
            std::ptr::null_mut(),
            &mut refused_length,
        ),
        CKR_KEY_NOT_WRAPPABLE as CK_RV
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
    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut wrap = CK_TRUE as CK_BBOOL;
    let mut label = b"RSA public wrap".to_vec();
    let mut modulus = public_key.key.clone();
    let mut public_exponent = vec![0x01, 0x00, 0x01];
    let mut public_wrap_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
        bytes_attribute(CKA_MODULUS as CK_ATTRIBUTE_TYPE, &mut modulus),
        bytes_attribute(
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            &mut public_exponent,
        ),
    ];
    let mut rsa_public_wrap = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            public_wrap_template.as_mut_ptr(),
            public_wrap_template.len() as CK_ULONG,
            &mut rsa_public_wrap,
        ),
        CKR_OK as CK_RV
    );

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
    ];
    let mut target = None;
    let mut ccm = None;
    let mut rsa_private = None;
    let mut rsa_synthetic_public = None;
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
        rsa_public_wrap,
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
                        assert!(
                            object
                                .attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)
                                .is_none()
                        );
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
    let (private_object, public_object, command) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap();
    assert_eq!(command.code(), crate::YubiHsmCommandCode::GenerateWrapKey);
    assert!(private_object.unwrap);
    assert!(!public_object.wrap);

    let mut public_wrap = CK_TRUE as CK_BBOOL;
    let mut token = CK_TRUE as CK_BBOOL;
    let public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut public_wrap),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
    ];
    let private = [scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token)];
    let (private_object, public_object, command) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap();
    assert_eq!(command.code(), crate::YubiHsmCommandCode::GenerateWrapKey);
    assert!(private_object.unwrap);
    assert!(public_object.wrap);

    let mut no_unwrap = CK_FALSE as CK_BBOOL;
    let private = [
        scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut no_unwrap),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
    ];
    assert_eq!(
        CK_RV::from(
            crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap_err()
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut wrap = CK_FALSE as CK_BBOOL;
    let public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
    ];
    let mut unwrap = CK_TRUE as CK_BBOOL;
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

fn checked_public_wrap_attributes(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> Result<(), String> {
    if checked_ulong_attribute(session, object, CKA_CLASS as CK_ATTRIBUTE_TYPE)?
        != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
        || checked_ulong_attribute(session, object, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
            != CKK_RSA as CK_KEY_TYPE
        || !checked_bool_attribute(session, object, CKA_TOKEN as CK_ATTRIBUTE_TYPE)?
        || !checked_bool_attribute(session, object, CKA_WRAP as CK_ATTRIBUTE_TYPE)?
    {
        return Err(format!(
            "object {object} is not a token RSA public wrap key"
        ));
    }
    Ok(())
}

fn checked_find_public_wrap_by_label(
    session: CK_SESSION_HANDLE,
    label: &[u8],
) -> Result<CK_OBJECT_HANDLE, String> {
    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut wrap = CK_TRUE as CK_BBOOL;
    let mut label = label.to_vec();
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
    ];
    checked_rv(
        "C_FindObjectsInit RSA public wrap key",
        crate::api::C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG),
    )?;
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;
    let find = checked_rv(
        "C_FindObjects RSA public wrap key",
        crate::api::C_FindObjects(
            session,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count,
        ),
    );
    let finish = checked_rv(
        "C_FindObjectsFinal RSA public wrap key",
        crate::api::C_FindObjectsFinal(session),
    );
    find?;
    finish?;
    if count != 1 {
        return Err(format!(
            "expected one RSA public wrap key with label {:?}, found {count}",
            String::from_utf8_lossy(&label)
        ));
    }
    Ok(objects[0])
}

fn checked_wrap_key(
    session: CK_SESSION_HANDLE,
    wrapper: CK_OBJECT_HANDLE,
    target: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, String> {
    let (mut mechanism, mut parameters, mut oaep) = rsa_wrap_mechanism(true);
    initialize_rsa_wrap_mechanism(&mut mechanism, &mut parameters, &mut oaep);
    let mut wrapped_length = 0;
    checked_rv(
        "C_WrapKey length query",
        crate::api::C_WrapKey(
            session,
            &mut mechanism,
            wrapper,
            target,
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
            wrapper,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_length,
        ),
    )?;
    wrapped.truncate(wrapped_length as usize);
    Ok(wrapped)
}

fn create_rsa_public_wrap_key(
    session: CK_SESSION_HANDLE,
    generated_public: CK_OBJECT_HANDLE,
) -> Result<CK_OBJECT_HANDLE, String> {
    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut wrap = CK_TRUE as CK_BBOOL;
    let mut label = b"PKCS11 RSA public wrap test".to_vec();
    let mut modulus =
        checked_attribute(session, generated_public, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
    let mut public_exponent = checked_attribute(
        session,
        generated_public,
        CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
    )?;
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
        bytes_attribute(CKA_MODULUS as CK_ATTRIBUTE_TYPE, &mut modulus),
        bytes_attribute(
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            &mut public_exponent,
        ),
    ];
    let mut public_wrap_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    checked_rv(
        "C_CreateObject RSA public wrap key",
        crate::api::C_CreateObject(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut public_wrap_key,
        ),
    )?;
    Ok(public_wrap_key)
}

fn derive_rsa_public_wrap_key(
    session: CK_SESSION_HANDLE,
    private_wrap_key: CK_OBJECT_HANDLE,
) -> Result<CK_OBJECT_HANDLE, String> {
    let mut token = CK_TRUE as CK_BBOOL;
    let mut wrap = CK_TRUE as CK_BBOOL;
    let mut label = b"PKCS11 RSA derived public wrap test".to_vec();
    let mut template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public_wrap_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    checked_rv(
        "C_DeriveKey RSA public wrap key",
        crate::api::C_DeriveKey(
            session,
            &mut mechanism,
            private_wrap_key,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut public_wrap_key,
        ),
    )?;
    Ok(public_wrap_key)
}

pub(super) fn rsa_public_wrap_round_trip(slot_id: CK_SLOT_ID, pin: &[u8]) -> Result<(), String> {
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
    let mut created_public_wrap = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut derived_public_wrap = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
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
        let mut wrap = CK_TRUE as CK_BBOOL;
        let mut generated_public_label = b"PKCS11 RSA generated public wrap test".to_vec();
        let mut rsa_public_template = [
            scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
            scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
            bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut generated_public_label),
        ];
        let mut rsa_private_template =
            [scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token)];
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
        if !checked_bool_attribute(session, wrapper_private, CKA_TOKEN as CK_ATTRIBUTE_TYPE)?
            || !checked_bool_attribute(session, wrapper_private, CKA_UNWRAP as CK_ATTRIBUTE_TYPE)?
        {
            return Err("generated RSA wrap-key attributes are inconsistent".to_owned());
        }
        created_public_wrap = create_rsa_public_wrap_key(session, wrapper_public)?;
        derived_public_wrap = derive_rsa_public_wrap_key(session, wrapper_private)?;
        for (handle, label) in [
            (
                wrapper_public,
                b"PKCS11 RSA generated public wrap test".as_slice(),
            ),
            (
                created_public_wrap,
                b"PKCS11 RSA public wrap test".as_slice(),
            ),
            (
                derived_public_wrap,
                b"PKCS11 RSA derived public wrap test".as_slice(),
            ),
        ] {
            checked_public_wrap_attributes(session, handle)?;
            if checked_find_public_wrap_by_label(session, label)? != handle {
                return Err(format!(
                    "C_FindObjects returned a different handle for public wrap key {handle}"
                ));
            }
        }

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

        let mut wrapped = checked_wrap_key(session, wrapper_public, target_private)?;
        for wrapper in [created_public_wrap, derived_public_wrap] {
            let alternative = checked_wrap_key(session, wrapper, target_private)?;
            if alternative.is_empty() {
                return Err(format!(
                    "public wrap key {wrapper} produced no wrapped data"
                ));
            }
        }

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
        ("generated RSA public wrap key", wrapper_public),
        ("created RSA public wrap key", created_public_wrap),
        ("derived RSA public wrap key", derived_public_wrap),
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
fn generated_ec_key_round_trips_through_rsa_public_wrap_key() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    rsa_public_wrap_round_trip(SLOT_ID, b"0001password").unwrap();

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
        commands
            .iter()
            .filter(|(actual, _)| { *actual == crate::YubiHsmCommandCode::PutPublicWrapKey as u8 })
            .count(),
        3,
        "generation, C_CreateObject, and C_DeriveKey must each create a native public wrap key"
    );
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn yubihsm_public_wrap_selection_requires_explicit_wrap_and_token() {
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

    let mut modulus_bits = 2048 as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut public_token = CK_FALSE as CK_BBOOL;
    let mut wrap = CK_FALSE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut native_private_label = b"native RSA private key".to_vec();
    let mut public_template = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut public_token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
    ];
    let mut private_template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut native_private_label),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ordinary_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut ordinary_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut ordinary_public,
            &mut ordinary_private,
        ),
        CKR_OK as CK_RV
    );
    let opaque_command_count = || {
        commands
            .borrow()
            .iter()
            .filter(|(command, _)| *command == crate::YubiHsmCommandCode::PutOpaque as u8)
            .count()
    };
    assert_eq!(
        opaque_command_count(),
        0,
        "native generation without overrides must not create metadata"
    );
    let private_metadata_mutation_start = commands.borrow().len();
    let mut override_label = b"temporary private label override".to_vec();
    let mut override_template = [bytes_attribute(
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        &mut override_label,
    )];
    assert_eq!(
        crate::api::C_SetAttributeValue(
            session,
            ordinary_private,
            override_template.as_mut_ptr(),
            override_template.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(opaque_command_count(), 1);
    let mut restore_template = [bytes_attribute(
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        &mut native_private_label,
    )];
    assert_eq!(
        crate::api::C_SetAttributeValue(
            session,
            ordinary_private,
            restore_template.as_mut_ptr(),
            restore_template.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        opaque_command_count(),
        1,
        "restoring the native label must delete metadata instead of replacing it"
    );
    assert!(
        commands.borrow()[private_metadata_mutation_start..]
            .iter()
            .any(|(command, payload)| {
                *command == crate::YubiHsmCommandCode::DeleteObject as u8
                    && payload.get(2) == Some(&crate::YUBIHSM_OPAQUE)
            }),
        "restoring the native private-key label must delete the empty metadata object"
    );

    let mut modulus =
        checked_attribute(session, ordinary_public, CKA_MODULUS as CK_ATTRIBUTE_TYPE).unwrap();
    let mut public_exponent = checked_attribute(
        session,
        ordinary_public,
        CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
    )
    .unwrap();
    let public_wrap_command_count = || {
        commands
            .borrow()
            .iter()
            .filter(|(command, _)| *command == crate::YubiHsmCommandCode::PutPublicWrapKey as u8)
            .count()
    };
    assert_eq!(public_wrap_command_count(), 0);

    let mut created = Vec::new();
    for (label, token_value, wrap_value) in [
        ("default session RSA public key", None, None),
        (
            "default-token explicit non-wrap RSA public key",
            None,
            Some(false),
        ),
        ("explicit session RSA public key", Some(false), None),
        (
            "explicit session non-wrap RSA public key",
            Some(false),
            Some(false),
        ),
        ("ordinary token RSA public key", Some(true), None),
        (
            "explicit non-wrap token RSA public key",
            Some(true),
            Some(false),
        ),
    ] {
        let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
        let mut key_type = CKK_RSA as CK_KEY_TYPE;
        let mut token = CK_BBOOL::from(token_value.unwrap_or(false));
        let mut wrap = CK_BBOOL::from(wrap_value.unwrap_or(false));
        let mut label = label.as_bytes().to_vec();
        let mut template = vec![
            scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
            bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
            bytes_attribute(CKA_MODULUS as CK_ATTRIBUTE_TYPE, &mut modulus),
            bytes_attribute(
                CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
                &mut public_exponent,
            ),
        ];
        if token_value.is_some() {
            template.push(scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token));
        }
        if wrap_value.is_some() {
            template.push(scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap));
        }
        let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let rv = crate::api::C_CreateObject(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut object,
        );
        assert_eq!(
            rv,
            CKR_OK as CK_RV,
            "C_CreateObject failed for {label:?}, CKA_TOKEN={token_value:?}, CKA_WRAP={wrap_value:?}; commands={:?}",
            commands.borrow()
        );
        assert_eq!(
            checked_bool_attribute(session, object, CKA_TOKEN as CK_ATTRIBUTE_TYPE).unwrap(),
            token_value.unwrap_or(false)
        );
        assert!(!checked_bool_attribute(session, object, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
        created.push(object);
    }
    assert_eq!(public_wrap_command_count(), 0);

    let standalone_token_public = created[4];
    assert!(
        !checked_bool_attribute(
            session,
            standalone_token_public,
            CKA_COPYABLE as CK_ATTRIBUTE_TYPE,
        )
        .unwrap()
    );
    let mut copied_standalone = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CopyObject(
            session,
            standalone_token_public,
            std::ptr::null_mut(),
            0,
            &mut copied_standalone,
        ),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(copied_standalone, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    let mut updated_standalone_label = b"updated standalone token key".to_vec();
    let mut update_standalone = [bytes_attribute(
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        &mut updated_standalone_label,
    )];
    assert_eq!(
        crate::api::C_SetAttributeValue(
            session,
            standalone_token_public,
            update_standalone.as_mut_ptr(),
            update_standalone.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        checked_attribute(
            session,
            standalone_token_public,
            CKA_LABEL as CK_ATTRIBUTE_TYPE,
        )
        .unwrap(),
        updated_standalone_label
    );

    let mut projection = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut session_projections = Vec::new();
    let mut default_session_projection = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut projection,
            ordinary_private,
            std::ptr::null_mut(),
            0,
            &mut default_session_projection,
        ),
        CKR_OK as CK_RV
    );
    session_projections.push(default_session_projection);
    let mut projection_token_false = CK_FALSE as CK_BBOOL;
    let mut projection_wrap_false = CK_FALSE as CK_BBOOL;
    let mut explicit_session_template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut projection_token_false),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut projection_wrap_false),
    ];
    let mut explicit_session_projection = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut projection,
            ordinary_private,
            explicit_session_template.as_mut_ptr(),
            explicit_session_template.len() as CK_ULONG,
            &mut explicit_session_projection,
        ),
        CKR_OK as CK_RV
    );
    session_projections.push(explicit_session_projection);
    for object in &session_projections {
        assert!(!checked_bool_attribute(session, *object, CKA_TOKEN as CK_ATTRIBUTE_TYPE).unwrap());
        assert!(!checked_bool_attribute(session, *object, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
    }

    let mut projected_label = b"ordinary token public projection".to_vec();
    let mut projection_template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut projected_label),
    ];
    let mut projected = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut projection,
            ordinary_private,
            projection_template.as_mut_ptr(),
            projection_template.len() as CK_ULONG,
            &mut projected,
        ),
        CKR_OK as CK_RV
    );
    assert!(checked_bool_attribute(session, projected, CKA_TOKEN as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(!checked_bool_attribute(session, projected, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
    let projected_spki_before_morph =
        checked_attribute(session, projected, CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE).unwrap();
    assert!(
        !checked_bool_attribute(session, projected, CKA_COPYABLE as CK_ATTRIBUTE_TYPE,).unwrap()
    );
    let mut projected_copy = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CopyObject(
            session,
            projected,
            std::ptr::null_mut(),
            0,
            &mut projected_copy,
        ),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(projected_copy, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(public_wrap_command_count(), 0);

    let mut wrap_true = CK_TRUE as CK_BBOOL;
    let mut invalid_projection_template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap_true),
    ];
    let mut invalid_projected = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut projection,
            ordinary_private,
            invalid_projection_template.as_mut_ptr(),
            invalid_projection_template.len() as CK_ULONG,
            &mut invalid_projected,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(invalid_projected, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    let mut invalid_session_projection_template = [
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut projection_token_false),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap_true),
    ];
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut projection,
            ordinary_private,
            invalid_session_projection_template.as_mut_ptr(),
            invalid_session_projection_template.len() as CK_ULONG,
            &mut invalid_projected,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut token_false = CK_FALSE as CK_BBOOL;
    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut invalid_create_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token_false),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap_true),
        bytes_attribute(CKA_MODULUS as CK_ATTRIBUTE_TYPE, &mut modulus),
        bytes_attribute(
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            &mut public_exponent,
        ),
    ];
    let mut invalid_created = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            invalid_create_template.as_mut_ptr(),
            invalid_create_template.len() as CK_ULONG,
            &mut invalid_created,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(invalid_created, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    let mut invalid_default_token_template = invalid_create_template
        .iter()
        .copied()
        .filter(|attribute| attribute.type_ != CKA_TOKEN as CK_ATTRIBUTE_TYPE)
        .collect::<Vec<_>>();
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            invalid_default_token_template.as_mut_ptr(),
            invalid_default_token_template.len() as CK_ULONG,
            &mut invalid_created,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(invalid_created, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);

    let mut invalid_generation_public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token_false),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap_true),
    ];
    let mut invalid_generation_private =
        [scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token)];
    let mut invalid_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut invalid_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            invalid_generation_public.as_mut_ptr(),
            invalid_generation_public.len() as CK_ULONG,
            invalid_generation_private.as_mut_ptr(),
            invalid_generation_private.len() as CK_ULONG,
            &mut invalid_public,
            &mut invalid_private,
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    assert_eq!(public_wrap_command_count(), 0);

    let mut native_label = b"explicit token RSA public wrap key".to_vec();
    let mut native_create_template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap_true),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut native_label),
        bytes_attribute(CKA_MODULUS as CK_ATTRIBUTE_TYPE, &mut modulus),
        bytes_attribute(
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            &mut public_exponent,
        ),
    ];
    let mut native_public_wrap = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            native_create_template.as_mut_ptr(),
            native_create_template.len() as CK_ULONG,
            &mut native_public_wrap,
        ),
        CKR_OK as CK_RV
    );
    checked_public_wrap_attributes(session, native_public_wrap).unwrap();
    assert_eq!(public_wrap_command_count(), 1);
    assert!(
        !checked_bool_attribute(
            session,
            native_public_wrap,
            CKA_COPYABLE as CK_ATTRIBUTE_TYPE,
        )
        .unwrap()
    );
    let mut native_copy = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CopyObject(
            session,
            native_public_wrap,
            std::ptr::null_mut(),
            0,
            &mut native_copy,
        ),
        CKR_ACTION_PROHIBITED as CK_RV
    );
    assert_eq!(native_copy, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(public_wrap_command_count(), 1);

    let opaque_before_native_update = opaque_command_count();
    let public_wrap_metadata_mutation_start = commands.borrow().len();
    let mut native_override_label = b"temporary native public wrap override".to_vec();
    let mut native_override = [bytes_attribute(
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        &mut native_override_label,
    )];
    assert_eq!(
        crate::api::C_SetAttributeValue(
            session,
            native_public_wrap,
            native_override.as_mut_ptr(),
            native_override.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(opaque_command_count(), opaque_before_native_update + 1);
    let mut native_restore = [bytes_attribute(
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        &mut native_label,
    )];
    assert_eq!(
        crate::api::C_SetAttributeValue(
            session,
            native_public_wrap,
            native_restore.as_mut_ptr(),
            native_restore.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        opaque_command_count(),
        opaque_before_native_update + 1,
        "restoring a native public-wrap label must remove its metadata without writing a replacement"
    );
    assert!(
        commands.borrow()[public_wrap_metadata_mutation_start..]
            .iter()
            .any(|(command, payload)| {
                *command == crate::YubiHsmCommandCode::DeleteObject as u8
                    && payload.get(2) == Some(&crate::YUBIHSM_OPAQUE)
            }),
        "restoring the native public-wrap label must delete the empty metadata object"
    );

    let command_start = commands.borrow().len();
    assert_eq!(
        crate::api::C_DestroyObject(session, ordinary_private),
        CKR_OK as CK_RV
    );
    let detach_commands = commands.borrow()[command_start..].to_vec();
    let put_index = detach_commands
        .iter()
        .position(|(command, payload)| {
            *command == crate::YubiHsmCommandCode::PutOpaque as u8
                && payload
                    .get(2..42)
                    .is_some_and(|label| label.starts_with(b"pkcs11rs stored "))
        })
        .expect("private-first deletion must write a standalone public-key record");
    let reused_metadata_id = &detach_commands[put_index].1[..2];
    assert_ne!(reused_metadata_id, [0, 0]);
    let linked_delete_index = detach_commands
        .iter()
        .position(|(command, payload)| {
            *command == crate::YubiHsmCommandCode::DeleteObject as u8
                && payload.get(..2) == Some(reused_metadata_id)
                && payload.get(2) == Some(&crate::YUBIHSM_OPAQUE)
        })
        .expect("detachment must free the linked record before reusing its object ID");
    let private_delete_index = detach_commands
        .iter()
        .position(|(command, payload)| {
            *command == crate::YubiHsmCommandCode::DeleteObject as u8
                && payload.get(2) == Some(&crate::YUBIHSM_ASYMMETRIC_KEY)
        })
        .expect("private-first deletion must remove the native private key");
    assert!(linked_delete_index < put_index);
    assert!(put_index < private_delete_index);
    assert!(checked_bool_attribute(session, projected, CKA_TOKEN as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(!checked_bool_attribute(session, projected, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(!projected_spki_before_morph.is_empty());
    assert_eq!(
        checked_attribute(session, projected, CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE).unwrap(),
        projected_spki_before_morph,
        "the same public handle must retain identical key material after becoming standalone"
    );
    assert_eq!(
        checked_attribute(session, projected, CKA_LABEL as CK_ATTRIBUTE_TYPE).unwrap(),
        projected_label,
        "the same public handle must retain its label after becoming standalone"
    );
    assert!(
        !checked_bool_attribute(session, ordinary_public, CKA_TOKEN as CK_ATTRIBUTE_TYPE).unwrap()
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, projected),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, ordinary_public),
        CKR_OK as CK_RV
    );
    for object in session_projections {
        assert_eq!(
            crate::api::C_DestroyObject(session, object),
            CKR_OK as CK_RV
        );
    }
    for object in &created {
        assert_eq!(
            checked_ulong_attribute(session, *object, CKA_CLASS as CK_ATTRIBUTE_TYPE).unwrap(),
            CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            "a standalone public key must outlive the unrelated private key"
        );
    }
    for (name, object) in std::iter::once(("native public wrap key".to_owned(), native_public_wrap))
        .chain(
            created
                .into_iter()
                .enumerate()
                .map(|(index, object)| (format!("created ordinary public key {index}"), object)),
        )
    {
        assert_eq!(
            crate::api::C_DestroyObject(session, object),
            CKR_OK as CK_RV,
            "cleanup failed for {name} handle {object}"
        );
    }
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
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
        checked_bool_attribute(session, rsa_public_wrap, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap()
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
    assert!(
        commands
            .borrow()
            .iter()
            .any(|(command, _)| { *command == crate::YubiHsmCommandCode::ImportRsaWrapped as u8 })
    );

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
fn yubihsm_aes_ccm_wrap_data_encrypts_and_decrypts() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    let session = open_test_session(SLOT_ID);
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

    let object = yubihsm_wrap_test_object(
        SLOT_ID,
        YubiHsmWrapTestObject {
            id: 40,
            object_type: crate::YUBIHSM_WRAP_KEY,
            algorithm: crate::YUBIHSM_ALGO_AES128_CCM_WRAP,
            capabilities: &[0x25, 0x26],
            delegated_capabilities: &[],
            label: "AES-CCM wrap data",
            public_key: None,
        },
    )
    .pop()
    .unwrap();
    let key = with_test_slot_context(SLOT_ID, |context| context.insert_object(object).unwrap());
    assert!(checked_bool_attribute(session, key, CKA_ENCRYPT as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(checked_bool_attribute(session, key, CKA_DECRYPT as CK_ATTRIBUTE_TYPE).unwrap());

    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_YUBICO_AES_CCM_WRAP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut plaintext = b"wrap-data round trip".to_vec();
    assert_eq!(
        crate::api::C_EncryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    let mut ciphertext_len = 0;
    assert_eq!(
        crate::api::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut ciphertext_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(ciphertext_len as usize, plaintext.len() + 1 + 13 + 16);
    let mut ciphertext = vec![0; ciphertext_len as usize];
    assert_eq!(
        crate::api::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        commands.borrow().last().unwrap().0,
        crate::YubiHsmCommandCode::WrapData as u8
    );

    assert_eq!(
        crate::api::C_DecryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    let mut decrypted_len = 0;
    assert_eq!(
        crate::api::C_Decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(decrypted_len as usize, plaintext.len());
    let mut decrypted = vec![0; decrypted_len as usize];
    assert_eq!(
        crate::api::C_Decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as CK_ULONG,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(decrypted, plaintext);
    assert_eq!(
        commands.borrow().last().unwrap().0,
        crate::YubiHsmCommandCode::UnwrapData as u8
    );

    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    finalize_for_test();
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
