use super::*;

fn field<T>(kind: u32, value: &mut T) -> CK_PRF_DATA_PARAM {
    CK_PRF_DATA_PARAM {
        type_: kind as CK_PRF_DATA_TYPE,
        pValue: (value as *mut T).cast(),
        ulValueLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}

fn bytes(value: &mut [u8]) -> CK_PRF_DATA_PARAM {
    CK_PRF_DATA_PARAM {
        type_: CK_SP800_108_BYTE_ARRAY as CK_PRF_DATA_TYPE,
        pValue: value.as_mut_ptr().cast(),
        ulValueLen: value.len() as CK_ULONG,
    }
}

// Owning boxes/buffers keep every nested C parameter stable when this fixture moves.
struct Parameters {
    counter: Box<CK_SP800_108_COUNTER_FORMAT>,
    length: Box<CK_SP800_108_DKM_LENGTH_FORMAT>,
    _label: Vec<u8>,
    _context: Vec<u8>,
    fields: Vec<CK_PRF_DATA_PARAM>,
    params: CK_SP800_108_KDF_PARAMS,
}

impl Parameters {
    fn scp03(constant: u8) -> Self {
        let mut counter = Box::new(CK_SP800_108_COUNTER_FORMAT {
            bLittleEndian: CK_FALSE as CK_BBOOL,
            ulWidthInBits: 8,
        });
        let mut length = Box::new(CK_SP800_108_DKM_LENGTH_FORMAT {
            dkmLengthMethod: CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS as CK_ULONG,
            bLittleEndian: CK_FALSE as CK_BBOOL,
            ulWidthInBits: 16,
        });
        let mut label = vec![0; 13];
        label[11] = constant;
        let mut context = crate::parse_hex("01020304050607081112131415161718").unwrap();
        let mut fields = vec![
            bytes(&mut label),
            field(CK_SP800_108_DKM_LENGTH, length.as_mut()),
            field(CK_SP800_108_ITERATION_VARIABLE, counter.as_mut()),
            bytes(&mut context),
        ];
        let params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_AES_CMAC as CK_MECHANISM_TYPE,
            ulNumberOfDataParams: fields.len() as CK_ULONG,
            pDataParams: fields.as_mut_ptr(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };
        Self {
            counter,
            length,
            _label: label,
            _context: context,
            fields,
            params,
        }
    }

    fn mechanism(&mut self) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE,
            pParameter: (&mut self.params as *mut CK_SP800_108_KDF_PARAMS).cast(),
            ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>() as CK_ULONG,
        }
    }
}

fn base_key(
    session: CK_SESSION_HANDLE,
    value: &mut [u8],
    derive: bool,
    extra: &mut [CK_ATTRIBUTE],
) -> CK_OBJECT_HANDLE {
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_AES as CK_KEY_TYPE;
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut no = CK_FALSE as CK_BBOOL;
    let mut derive = CK_BBOOL::from(derive);
    let mut template = vec![
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, value),
        scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut derive),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut yes),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut no),
    ];
    template.extend_from_slice(extra);
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

fn derive(
    session: CK_SESSION_HANDLE,
    base: CK_OBJECT_HANDLE,
    params: &mut Parameters,
    template: &mut [CK_ATTRIBUTE],
) -> CK_OBJECT_HANDLE {
    let mut handle = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut params.mechanism(),
            base,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut handle
        ),
        CKR_OK as CK_RV
    );
    handle
}

fn check_cmac(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, expected_key: &[u8]) {
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(session, key, &mut attr, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CMAC as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    let mut message = *b"SCP working key";
    let mut mac = [0; 16];
    let mut length = 16 as CK_ULONG;
    assert_eq!(
        crate::api::C_Sign(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            mac.as_mut_ptr(),
            &mut length
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        mac,
        crate::secure_channel_crypto::aes_cmac(expected_key, &message).unwrap()
    );
}

#[test]
fn counter_kdf_scp03_vectors_create_protected_working_keys_on_every_slot() {
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
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        assert_eq!(
            crate::C_GetMechanismInfo(
                82,
                CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE,
                &mut info
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            (info.ulMinKeySize, info.ulMaxKeySize, info.flags),
            (128, 256, CKF_DERIVE as CK_FLAGS)
        );
        let base = base_key(8201, &mut (0x40..0x50).collect::<Vec<u8>>(), true, &mut []);
        let mut last = 0;
        for (mut length, expected) in [
            (16 as CK_ULONG, "d99675d4a95c58de629225730cddb758"),
            (24, "cde1b0fba174796ab9f28d81848d5c7481724bfc0cf193b9"),
            (
                32,
                "451ca221762da5dc0c4db08a2af7147bc25881b77d52b1d3e702f693f440164f",
            ),
        ] {
            let mut params = Parameters::scp03(4);
            let mut aes = CKK_AES as CK_KEY_TYPE;
            let mut yes = CK_TRUE as CK_BBOOL;
            let mut no = CK_FALSE as CK_BBOOL;
            let mut template = [
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
                scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
                scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut yes),
                scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut no),
                scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut yes),
            ];
            last = derive(8201, base, &mut params, &mut template);
            check_cmac(8202, last, &crate::parse_hex(expected).unwrap());
            assert_eq!(
                read_bytes_attribute(8201, last, CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE),
                [CK_FALSE as u8]
            );
            assert_eq!(
                read_bytes_attribute(8201, last, CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE),
                [CK_FALSE as u8]
            );
        }
        // A protected long-term base can derive explicitly readable channel
        // keys. This exercises actual C_DeriveKey/C_GetAttributeValue calls.
        let mut params = Parameters::scp03(4);
        let mut aes = CKK_AES as CK_KEY_TYPE;
        let mut length = 16 as CK_ULONG;
        let mut yes = CK_TRUE as CK_BBOOL;
        let mut no = CK_FALSE as CK_BBOOL;
        let mut output = [
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
            scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
            scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut no),
            scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut yes),
        ];
        let readable = derive(8201, base, &mut params, &mut output);
        assert_eq!(
            read_bytes_attribute(8201, readable, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            crate::parse_hex("d99675d4a95c58de629225730cddb758").unwrap()
        );
        let mut value = CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(8201, base, &mut value, 1),
            CKR_ATTRIBUTE_SENSITIVE as CK_RV
        );
        assert_eq!(crate::api::C_CloseSession(8201), CKR_OK as CK_RV);
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(8202, last, &mut attr, 1),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
    }
    finalize_for_test();
}

#[test]
fn counter_kdf_supports_diversification_and_all_aes_base_sizes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let base = base_key(
        TEST_SESSION_HANDLE,
        &mut (0u8..32).collect::<Vec<_>>(),
        true,
        &mut [],
    );
    for (label, expected) in [
        (1, "6d8ef504cdfca3d667de72f24c4c82af"),
        (2, "90753ab6fd71d3bb9618dbea179e0a56"),
        (3, "53a68b700a229b4314315bfcb162a650"),
    ] {
        let mut params = Parameters::scp03(4);
        let mut public = vec![0, 0, 0, label, 0];
        public.extend(0u8..10);
        params.fields = vec![
            field(CK_SP800_108_ITERATION_VARIABLE, params.counter.as_mut()),
            bytes(&mut public),
            field(CK_SP800_108_DKM_LENGTH, params.length.as_mut()),
        ];
        params.params.pDataParams = params.fields.as_mut_ptr();
        params.params.ulNumberOfDataParams = params.fields.len() as CK_ULONG;
        let mut length = 16 as CK_ULONG;
        let key = derive(
            TEST_SESSION_HANDLE,
            base,
            &mut params,
            &mut [scalar_attribute(
                CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
                &mut length,
            )],
        );
        assert_eq!(
            read_bytes_attribute(TEST_SESSION_HANDLE, key, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            crate::parse_hex(expected).unwrap()
        );
    }
    for size in [16, 24, 32] {
        let key_value = vec![0x42; size];
        let base = base_key(TEST_SESSION_HANDLE, &mut key_value.clone(), true, &mut []);
        for constant in [4, 6, 7] {
            let mut params = Parameters::scp03(constant);
            let mut length = 16 as CK_ULONG;
            let key = derive(
                TEST_SESSION_HANDLE,
                base,
                &mut params,
                &mut [scalar_attribute(
                    CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
                    &mut length,
                )],
            );
            let expected = crate::secure_channel_crypto::scp03_kdf(
                &key_value,
                constant,
                &params._context,
                128,
            )
            .unwrap();
            assert_eq!(
                read_bytes_attribute(TEST_SESSION_HANDLE, key, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                expected
            );
        }
    }
    finalize_for_test();
}

#[test]
fn counter_kdf_rejects_invalid_parameters_and_output_templates_atomically() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let base = base_key(TEST_SESSION_HANDLE, &mut [1; 16], true, &mut []);
    let before = with_test_slot_context(TEST_SLOT_ID, |ctx| ctx.resolved_objects().unwrap().len());
    let reject = |params: &mut Parameters, template: &mut [CK_ATTRIBUTE], error| {
        let mut result = 0xfeed as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_DeriveKey(
                TEST_SESSION_HANDLE,
                &mut params.mechanism(),
                base,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut result
            ),
            error as CK_RV
        );
        assert_eq!(result, 0xfeed);
        assert_eq!(
            with_test_slot_context(TEST_SLOT_ID, |ctx| ctx.resolved_objects().unwrap().len()),
            before
        );
    };
    let mut length = 16 as CK_ULONG;
    let mut template = [scalar_attribute(
        CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        &mut length,
    )];
    for case in 0..16 {
        let mut params = Parameters::scp03(4);
        match case {
            0 => params.params.prfType = CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
            1 => params.params.ulAdditionalDerivedKeys = 1,
            2 => params.params.pAdditionalDerivedKeys = std::ptr::dangling_mut(),
            3 => params.params.ulNumberOfDataParams = 0,
            4 => params.params.ulNumberOfDataParams = 65,
            5 => params.params.pDataParams = std::ptr::null_mut(),
            6 => params.fields[2].type_ = CK_SP800_108_COUNTER as CK_PRF_DATA_TYPE,
            7 => params.fields[2].ulValueLen = 0,
            8 => params.counter.ulWidthInBits = 7,
            9 => params.counter.bLittleEndian = 2,
            10 => params.length.dkmLengthMethod = 99,
            11 => params.length.ulWidthInBits = 0,
            12 => params.fields[0].ulValueLen = 0,
            13 => params.fields[0].ulValueLen = 65537,
            14 => params.fields[0] = params.fields[2],
            15 => params.fields[0] = params.fields[1],
            _ => unreachable!(),
        }
        reject(&mut params, &mut template, CKR_MECHANISM_PARAM_INVALID);
    }
    reject(&mut Parameters::scp03(4), &mut [], CKR_TEMPLATE_INCOMPLETE);
    for mut length in [0 as CK_ULONG, 1025, CK_ULONG::MAX] {
        reject(
            &mut Parameters::scp03(4),
            &mut [scalar_attribute(
                CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
                &mut length,
            )],
            CKR_KEY_SIZE_RANGE,
        );
    }
    let mut params = Parameters::scp03(4);
    params.length.ulWidthInBits = 8;
    let mut length = 32 as CK_ULONG;
    reject(
        &mut params,
        &mut [scalar_attribute(
            CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            &mut length,
        )],
        CKR_KEY_SIZE_RANGE,
    );
    let mut value = [1];
    reject(
        &mut Parameters::scp03(4),
        &mut [bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value)],
        CKR_ATTRIBUTE_READ_ONLY,
    );
    finalize_for_test();
}

#[test]
fn counter_kdf_maps_endianness_and_segment_length_parameters() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let base = base_key(
        TEST_SESSION_HANDLE,
        &mut (0x40..0x50).collect::<Vec<u8>>(),
        true,
        &mut [],
    );
    for (little, method, expected) in [
        (
            false,
            CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
            "be434dc89f7c8d64d9e66c260fb5de321cbcfd74a7a93ded",
        ),
        (
            false,
            CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
            "886fa95692f2b451f3e4c92a4f90b43ed571206b42e9a6e2",
        ),
        (
            true,
            CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
            "bc39563583409986de95ceb37ec76e35126e3d8ec83476ac",
        ),
        (
            true,
            CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
            "321545d9630f704533760c60f3deee6f7ded9d257992e0f4",
        ),
    ] {
        let mut params = Parameters::scp03(4);
        params.counter.bLittleEndian = CK_BBOOL::from(little);
        params.counter.ulWidthInBits = 32;
        params.length.bLittleEndian = CK_BBOOL::from(little);
        params.length.dkmLengthMethod = method as CK_ULONG;
        let mut data = b"label\0context".to_vec();
        params.fields = vec![
            field(CK_SP800_108_ITERATION_VARIABLE, params.counter.as_mut()),
            bytes(&mut data),
            field(CK_SP800_108_DKM_LENGTH, params.length.as_mut()),
        ];
        params.params.pDataParams = params.fields.as_mut_ptr();
        params.params.ulNumberOfDataParams = params.fields.len() as CK_ULONG;
        let mut length = 24 as CK_ULONG;
        let key = derive(
            TEST_SESSION_HANDLE,
            base,
            &mut params,
            &mut [scalar_attribute(
                CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
                &mut length,
            )],
        );
        assert_eq!(
            read_bytes_attribute(TEST_SESSION_HANDLE, key, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            crate::parse_hex(expected).unwrap()
        );
    }
    finalize_for_test();
}

#[test]
fn counter_kdf_enforces_key_permissions_templates_and_history() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut no = CK_FALSE as CK_BBOOL;
    let mut length = 16 as CK_ULONG;
    let mut allowed = [CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE];
    let mut policy = [
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut yes),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut no),
    ];
    let mut template = vec![
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
        scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut yes),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut yes),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut no),
        CK_ATTRIBUTE {
            type_: CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE,
            pValue: allowed.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(&allowed) as CK_ULONG,
        },
    ];
    let mut generate = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut unbound = 0;
    assert_eq!(
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut generate,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut unbound
        ),
        CKR_OK as CK_RV
    );
    template.push(CK_ATTRIBUTE {
        type_: CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE,
        pValue: policy.as_mut_ptr().cast(),
        ulValueLen: std::mem::size_of_val(&policy) as CK_ULONG,
    });
    let mut bound = 0;
    assert_eq!(
        crate::api::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut generate,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut bound
        ),
        CKR_OK as CK_RV
    );
    let mut params = Parameters::scp03(4);
    let mut output_template = [scalar_attribute(
        CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        &mut length,
    )];
    let protected = derive(
        TEST_SESSION_HANDLE,
        bound,
        &mut params,
        &mut output_template,
    );
    for attribute in [CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE] {
        assert_eq!(
            read_bytes_attribute(
                TEST_SESSION_HANDLE,
                protected,
                attribute as CK_ATTRIBUTE_TYPE
            ),
            [CK_TRUE as u8]
        );
    }
    let readable = derive(
        TEST_SESSION_HANDLE,
        unbound,
        &mut params,
        &mut output_template,
    );
    assert_eq!(
        read_bytes_attribute(
            TEST_SESSION_HANDLE,
            readable,
            CKA_VALUE as CK_ATTRIBUTE_TYPE
        )
        .len(),
        16
    );
    for attribute in [CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE] {
        assert_eq!(
            read_bytes_attribute(
                TEST_SESSION_HANDLE,
                readable,
                attribute as CK_ATTRIBUTE_TYPE
            ),
            [CK_FALSE as u8]
        );
    }
    let mut conflicting = [
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut no),
    ];
    let mut result = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            TEST_SESSION_HANDLE,
            &mut params.mechanism(),
            bound,
            conflicting.as_mut_ptr(),
            2,
            &mut result
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    let forbidden = base_key(TEST_SESSION_HANDLE, &mut [1; 16], false, &mut []);
    let wrong_type = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [1; 16], true, true, false);
    let mut cmac_only = [CKM_AES_CMAC as CK_MECHANISM_TYPE];
    let mut restriction = [CK_ATTRIBUTE {
        type_: CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE,
        pValue: cmac_only.as_mut_ptr().cast(),
        ulValueLen: std::mem::size_of_val(&cmac_only) as CK_ULONG,
    }];
    let restricted = base_key(TEST_SESSION_HANDLE, &mut [1; 16], true, &mut restriction);
    for (base, error) in [
        (0, CKR_KEY_HANDLE_INVALID),
        (forbidden, CKR_KEY_FUNCTION_NOT_PERMITTED),
        (wrong_type, CKR_KEY_TYPE_INCONSISTENT),
        (restricted, CKR_MECHANISM_INVALID),
    ] {
        assert_eq!(
            crate::api::C_DeriveKey(
                TEST_SESSION_HANDLE,
                &mut params.mechanism(),
                base,
                output_template.as_mut_ptr(),
                1,
                &mut result
            ),
            error as CK_RV
        );
    }
    let mut slot = test_slot(true);
    slot.software_allowlist = Some(Vec::new());
    install_test_slot_with_backend(82, Box::new(slot));
    install_test_session(82, 8201);
    let base = base_key(8201, &mut [1; 16], true, &mut []);
    assert_eq!(
        crate::api::C_DeriveKey(
            8201,
            &mut params.mechanism(),
            base,
            output_template.as_mut_ptr(),
            1,
            &mut result
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    finalize_for_test();
}

#[test]
fn counter_kdf_uses_yubihsm_cmac_without_signing_permission_or_key_export() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    const SLOT: CK_SLOT_ID = 99;
    let (slot, commands, corrupt_mac, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT, slot);
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            SLOT,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
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

    // Independently calculated with OpenSSL CMAC, using the fixture's AES keys.
    for (id, vectors) in [
        (
            crate::yubihsm::tests::NIST_AES_KEY_ID,
            [
                "e7d9a5d5b3a32d092d3f15ca7446782c",
                "41ee1644a4bc48227e0389ce59e85d99cbdea41597265ad8",
                "25b66e78d44edc95323a3b6ec2cf71eac9560f3294094a93cad5ad41ef159533",
            ],
        ),
        (
            crate::yubihsm::tests::RFC5649_AES_KEY_ID,
            [
                "54d5977beaf84021d7e9605a38930ec3",
                "67f07bc8b2222f3043f955ed555569357e302e1d9cfb88e5",
                "89ba4b1b53eb1c5ceada6d00e6c1d87a214ecc85091890461affbbdc97d6ccae",
            ],
        ),
    ] {
        let base = insert_yubihsm_aes_test_object(SLOT, id);
        with_test_slot_context(SLOT, |ctx| {
            let base = ctx.memory_objects.get_mut(&base).unwrap();
            base.derive = true;
            base.sign = false;
            base.encrypt = false;
            base.allowed_mechanisms = Some(vec![CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE]);
        });
        for (length, expected) in [16, 24, 32].into_iter().zip(vectors) {
            let mut params = Parameters::scp03(4);
            let mut aes = CKK_AES as CK_KEY_TYPE;
            let mut length = length as CK_ULONG;
            let mut yes = CK_TRUE as CK_BBOOL;
            let mut no = CK_FALSE as CK_BBOOL;
            let mut template = [
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
                scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
                scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut no),
                scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut yes),
            ];
            let start = commands.borrow().len();
            let result = derive(session, base, &mut params, &mut template);
            assert_eq!(
                read_bytes_attribute(session, result, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                crate::parse_hex(expected).unwrap()
            );
            assert_eq!(
                read_bytes_attribute(session, result, CKA_TOKEN as CK_ATTRIBUTE_TYPE),
                [CK_FALSE as u8]
            );
            let trace = commands.borrow();
            assert!(trace.len() > start);
            assert!(trace[start..].iter().all(|(command, data)| *command
                == crate::yubihsm::CommandCode::EncryptEcb as u8
                && data[..2] == id.to_be_bytes()));
            drop(trace);
            let mut attr = CK_ATTRIBUTE {
                type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            };
            assert_eq!(
                crate::api::C_GetAttributeValue(session, base, &mut attr, 1),
                CKR_ATTRIBUTE_SENSITIVE as CK_RV
            );
            assert_eq!(
                crate::api::C_DestroyObject(session, result),
                CKR_OK as CK_RV
            );
        }
        // Base permission and output-template errors must not contact the device.
        let mut params = Parameters::scp03(4);
        let mut aes = CKK_AES as CK_KEY_TYPE;
        let mut length = 16 as CK_ULONG;
        let mut template = [
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
            scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
        ];
        for (derive_allowed, capabilities, expected) in [
            (
                false,
                crate::yubihsm_capabilities(&[0x33]),
                CKR_KEY_FUNCTION_NOT_PERMITTED,
            ),
            (
                true,
                crate::yubihsm_capabilities(&[0x35]),
                CKR_KEY_FUNCTION_NOT_PERMITTED,
            ),
        ] {
            with_test_slot_context(SLOT, |ctx| {
                let object = ctx.memory_objects.get_mut(&base).unwrap();
                object.derive = derive_allowed;
                if let crate::KeyMaterial::YubiHsm {
                    capabilities: value,
                    ..
                } = &mut object.material
                {
                    *value = capabilities;
                }
            });
            let start = commands.borrow().len();
            let mut output = 0;
            assert_eq!(
                crate::api::C_DeriveKey(
                    session,
                    &mut params.mechanism(),
                    base,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut output
                ),
                expected as CK_RV
            );
            assert_eq!(output, 0);
            assert_eq!(commands.borrow().len(), start);
        }
    }
    let base = insert_yubihsm_aes_test_object(SLOT, crate::yubihsm::tests::NIST_AES_KEY_ID);
    with_test_slot_context(SLOT, |ctx| {
        ctx.memory_objects.get_mut(&base).unwrap().derive = true
    });
    let mut params = Parameters::scp03(4);
    let mut aes = CKK_AES as CK_KEY_TYPE;
    let mut length = 32 as CK_ULONG;
    let mut template = [
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
    ];
    let count = with_test_slot_context(SLOT, |ctx| ctx.memory_objects.len());
    let start = commands.borrow().len();
    let mut invalid_length = 15 as CK_ULONG;
    template[1] = scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut invalid_length);
    let mut output = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut params.mechanism(),
            base,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut output
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );
    assert_eq!(output, 0);
    assert_eq!(commands.borrow().len(), start);
    assert_eq!(
        with_test_slot_context(SLOT, |ctx| ctx.memory_objects.len()),
        count
    );
    template[1] = scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length);
    corrupt_mac.set(true);
    assert_ne!(
        crate::api::C_DeriveKey(
            session,
            &mut params.mechanism(),
            base,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut output
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(output, 0);
    assert!(with_test_slot_context(SLOT, |ctx| ctx.memory_objects.len()) <= count);
    finalize_for_test();
}

#[test]
fn counter_kdf_native_discovery_and_derive_only_capabilities() {
    let kdf = CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE;
    for (algorithms, expected) in [
        (
            vec![crate::YUBIHSM_ALGO_AES128, crate::YUBIHSM_ALGO_AES_ECB],
            Some((128, 128)),
        ),
        (
            vec![
                crate::YUBIHSM_ALGO_AES192,
                crate::YUBIHSM_ALGO_AES256,
                crate::YUBIHSM_ALGO_AES_ECB,
            ],
            Some((192, 256)),
        ),
        (
            vec![crate::YUBIHSM_ALGO_AES128, crate::YUBIHSM_ALGO_AES_CBC],
            None,
        ),
        (vec![crate::YUBIHSM_ALGO_AES_ECB], None),
    ] {
        let mechanisms = crate::yubihsm_mechanisms(&algorithms);
        let native = mechanisms.iter().find(|m| m.type_ == kdf);
        assert_eq!(native.map(|m| (m.min_key_size, m.max_key_size)), expected);
        if let Some(native) = native {
            assert_eq!(native.flags, (CKF_HW | CKF_DERIVE) as CK_FLAGS);
        }
    }
    let caps = crate::yubihsm_attributes_to_capabilities(
        crate::YUBIHSM_SYMMETRIC_KEY,
        crate::YUBIHSM_ALGO_AES128,
        crate::YubiHsmPkcs11Attributes {
            derive: true,
            ..Default::default()
        },
    );
    assert_eq!(caps, crate::yubihsm_capabilities(&[0x33]));
    assert!(
        crate::yubihsm_capabilities_to_attributes(
            crate::YUBIHSM_SYMMETRIC_KEY,
            crate::YUBIHSM_ALGO_AES128,
            &caps
        )
        .derive
    );
}
