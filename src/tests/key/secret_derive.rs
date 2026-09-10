use super::*;

fn mechanism<T>(kind: CK_MECHANISM_TYPE, parameter: &mut T) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: kind,
        pParameter: (parameter as *mut T).cast(),
        ulParameterLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}

fn derive(
    session: CK_SESSION_HANDLE,
    mechanism: &mut CK_MECHANISM,
    base: CK_OBJECT_HANDLE,
    template: &mut [CK_ATTRIBUTE],
) -> CK_OBJECT_HANDLE {
    let mut result = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            mechanism,
            base,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut result
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(result, 0);
    result
}

fn unreadable(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) {
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(session, key, &mut attr, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
}

#[test]
fn secret_composition_runs_protected_x963_graph_on_every_slot_kind() {
    x963_graph_on_every_slot_kind(false);
}

#[test]
fn secret_composition_runs_readable_x963_graph_on_every_slot_kind() {
    x963_graph_on_every_slot_kind(true);
}

fn x963_graph_on_every_slot_kind(readable: bool) {
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
        for name in [
            CKM_CONCATENATE_BASE_AND_KEY,
            CKM_CONCATENATE_BASE_AND_DATA,
            CKM_SHA256_KEY_DERIVATION,
            CKM_EXTRACT_KEY_FROM_KEY,
        ] {
            let mut info = CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: 0,
            };
            assert_eq!(
                crate::C_GetMechanismInfo(82, name as CK_MECHANISM_TYPE, &mut info),
                CKR_OK as CK_RV
            );
            assert_eq!(
                info.flags & (CKF_DERIVE | CKF_HW) as CK_FLAGS,
                CKF_DERIVE as CK_FLAGS
            );
        }
        let first =
            create_hkdf_test_key(8201, &mut (0u8..32).collect::<Vec<_>>(), true, true, false);
        let mut second =
            create_hkdf_test_key(8201, &mut (32u8..64).collect::<Vec<_>>(), true, true, false);
        let mut enabled = CK_TRUE as CK_BBOOL;
        let mut disabled = CK_FALSE as CK_BBOOL;
        let mut protected = [
            scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut enabled),
            scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut enabled),
            scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut disabled),
        ];
        let mut output_sensitive = CK_BBOOL::from(!readable);
        let mut output_extractable = CK_BBOOL::from(readable);
        let mut output = [
            scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut enabled),
            scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut output_sensitive),
            scalar_attribute(
                CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
                &mut output_extractable,
            ),
        ];
        let mut concat = mechanism(
            CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
            &mut second,
        );
        let z = derive(8201, &mut concat, first, &mut protected);
        unreadable(8201, z);
        let mut blocks = Vec::new();
        for counter in 1u32..=3 {
            let mut suffix = [counter.to_be_bytes().as_slice(), &[0x3c, 0x88, 0x10]].concat();
            let mut data = CK_KEY_DERIVATION_STRING_DATA {
                pData: suffix.as_mut_ptr(),
                ulLen: suffix.len() as CK_ULONG,
            };
            let mut append = mechanism(
                CKM_CONCATENATE_BASE_AND_DATA as CK_MECHANISM_TYPE,
                &mut data,
            );
            let input = derive(8201, &mut append, z, &mut protected);
            unreadable(8201, input);
            let mut hash = CK_MECHANISM {
                mechanism: CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            let block = derive(8201, &mut hash, input, &mut output);
            if !readable {
                unreadable(8201, block);
            }
            blocks.push(block);
        }
        let mut joined = blocks[0];
        for block in &mut blocks[1..] {
            let mut concat = mechanism(CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE, block);
            joined = derive(8201, &mut concat, joined, &mut output);
        }
        let expected = crate::parse_hex("78e6afba798e338b0b6104dfc18e5b9efaabdf39c991de6879d9c7a0c21ff02240998ce38b6d3dd3fd3fa9c7d956b67323d069af6457586600431b7ec83d38c7183f299ddc90b91643d6d2e137eefcff").unwrap();
        for index in 0..5 {
            let mut offset = (index * 128) as CK_EXTRACT_PARAMS;
            let mut extract = mechanism(CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE, &mut offset);
            let mut aes = CKK_AES as CK_KEY_TYPE;
            let mut length = 16 as CK_ULONG;
            let mut template = vec![
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut aes),
                scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
                scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut enabled),
            ];
            if readable {
                template.extend([
                    scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut output_sensitive),
                    scalar_attribute(
                        CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
                        &mut output_extractable,
                    ),
                ]);
            }
            let key = derive(8201, &mut extract, joined, &mut template);
            if readable {
                assert_eq!(
                    read_bytes_attribute(8201, key, CKA_VALUE as CK_ATTRIBUTE_TYPE),
                    &expected[index * 16..index * 16 + 16]
                );
            } else {
                unreadable(8201, key);
                unreadable(8202, key);
            }
            unreadable(8201, first);
            unreadable(8201, second);
            let mut cmac = CK_MECHANISM {
                mechanism: CKM_AES_CMAC as CK_MECHANISM_TYPE,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            assert_eq!(
                crate::api::C_SignInit(8202, &mut cmac, key),
                CKR_OK as CK_RV
            );
            let mut message = *b"protected key graph";
            let mut mac = [0u8; 16];
            let mut mac_len = 16 as CK_ULONG;
            assert_eq!(
                crate::api::C_Sign(
                    8202,
                    message.as_mut_ptr(),
                    message.len() as CK_ULONG,
                    mac.as_mut_ptr(),
                    &mut mac_len
                ),
                CKR_OK as CK_RV
            );
            let expected_mac = crate::secure_channel_crypto::aes_cmac(
                &expected[index * 16..index * 16 + 16],
                &message,
            )
            .unwrap();
            assert_eq!(mac, expected_mac, "{kind:?}, key {index}");
            assert_eq!(
                crate::api::C_SignInit(8301, &mut cmac, key),
                CKR_KEY_HANDLE_INVALID as CK_RV
            );
        }
        assert_eq!(crate::api::C_CloseSession(8201), CKR_OK as CK_RV);
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(8202, joined, &mut attr, 1),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
    }
    finalize_for_test();
}

#[test]
fn secret_composition_matches_standard_extraction_and_length_rules() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let base = create_hkdf_test_key(
        TEST_SESSION_HANDLE,
        &mut [0x32, 0x9f, 0x84, 0xa9],
        true,
        false,
        true,
    );
    let mut offset = 21 as CK_EXTRACT_PARAMS;
    let mut extract = mechanism(CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE, &mut offset);
    let mut length = 2 as CK_ULONG;
    let mut template = [scalar_attribute(
        CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        &mut length,
    )];
    let derived = derive(TEST_SESSION_HANDLE, &mut extract, base, &mut template);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, derived, CKA_VALUE as CK_ATTRIBUTE_TYPE),
        [0x95, 0x26]
    );
    let mut data = CK_KEY_DERIVATION_STRING_DATA {
        pData: std::ptr::null_mut(),
        ulLen: 0,
    };
    let mut append = mechanism(
        CKM_CONCATENATE_BASE_AND_DATA as CK_MECHANISM_TYPE,
        &mut data,
    );
    let copy = derive(TEST_SESSION_HANDLE, &mut append, base, &mut []);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, copy, CKA_VALUE as CK_ATTRIBUTE_TYPE),
        [0x32, 0x9f, 0x84, 0xa9]
    );
    let shortened = derive(TEST_SESSION_HANDLE, &mut append, base, &mut template);
    assert_eq!(
        read_bytes_attribute(
            TEST_SESSION_HANDLE,
            shortened,
            CKA_VALUE as CK_ATTRIBUTE_TYPE
        ),
        [0x32, 0x9f]
    );
    let base = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [0; 32], true, false, true);
    let mut des3 = CKK_DES3 as CK_KEY_TYPE;
    let mut template = [scalar_attribute(
        CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
        &mut des3,
    )];
    let key = derive(TEST_SESSION_HANDLE, &mut append, base, &mut template);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, key, CKA_VALUE as CK_ATTRIBUTE_TYPE),
        [1; 24]
    );
    let mut hash = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let abc = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut b"abc".to_vec(), true, false, true);
    let digest = derive(TEST_SESSION_HANDLE, &mut hash, abc, &mut []);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, digest, CKA_VALUE as CK_ATTRIBUTE_TYPE),
        crate::parse_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap()
    );
    finalize_for_test();
}

#[test]
fn secret_composition_rejects_policy_parameter_and_template_errors_atomically() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let plain = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [1; 32], true, false, true);
    let protected = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [2; 32], true, true, false);
    let forbidden = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [3; 32], false, false, true);
    let count =
        || with_test_slot_context(TEST_SLOT_ID, |ctx| ctx.resolved_objects().unwrap().len());
    let before = count();
    let reject = |mechanism: &mut CK_MECHANISM, base, template: &mut [CK_ATTRIBUTE], error| {
        let mut output = 0xfeed as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_DeriveKey(
                TEST_SESSION_HANDLE,
                mechanism,
                base,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut output
            ),
            error as CK_RV
        );
        assert_eq!(output, 0xfeed);
        assert_eq!(count(), before);
    };
    let mut other = protected;
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut other,
    );
    let mut no = CK_FALSE as CK_BBOOL;
    let mut yes = CK_TRUE as CK_BBOOL;
    reject(
        &mut concat,
        plain,
        &mut [scalar_attribute(
            CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            &mut no,
        )],
        CKR_TEMPLATE_INCONSISTENT,
    );
    reject(
        &mut concat,
        plain,
        &mut [scalar_attribute(
            CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            &mut yes,
        )],
        CKR_TEMPLATE_INCONSISTENT,
    );
    reject(
        &mut concat,
        forbidden,
        &mut [],
        CKR_KEY_FUNCTION_NOT_PERMITTED,
    );
    let mut other = forbidden;
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut other,
    );
    reject(&mut concat, plain, &mut [], CKR_KEY_FUNCTION_NOT_PERMITTED);
    let mut other = 0 as CK_OBJECT_HANDLE;
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut other,
    );
    reject(&mut concat, plain, &mut [], CKR_KEY_HANDLE_INVALID);
    concat.ulParameterLen = 0;
    reject(&mut concat, plain, &mut [], CKR_MECHANISM_PARAM_INVALID);
    let mut offset = 0 as CK_EXTRACT_PARAMS;
    let mut extract = mechanism(CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE, &mut offset);
    reject(&mut extract, plain, &mut [], CKR_TEMPLATE_INCOMPLETE);
    let mut aes = CKK_AES as CK_KEY_TYPE;
    reject(
        &mut extract,
        plain,
        &mut [scalar_attribute(
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            &mut aes,
        )],
        CKR_TEMPLATE_INCOMPLETE,
    );
    for mut length in [0 as CK_ULONG, 33, CK_ULONG::MAX] {
        reject(
            &mut extract,
            plain,
            &mut [scalar_attribute(
                CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
                &mut length,
            )],
            CKR_KEY_SIZE_RANGE,
        );
    }
    let mut offset = CK_EXTRACT_PARAMS::MAX;
    let mut extract = mechanism(CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE, &mut offset);
    reject(&mut extract, plain, &mut [], CKR_MECHANISM_PARAM_INVALID);
    let mut hash = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 1,
    };
    reject(&mut hash, plain, &mut [], CKR_MECHANISM_PARAM_INVALID);
    hash.ulParameterLen = 0;
    reject(
        &mut hash,
        plain,
        &mut [bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut [1])],
        CKR_ATTRIBUTE_READ_ONLY,
    );
    finalize_for_test();
}

#[test]
fn secret_composition_preserves_history_and_both_input_policies() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let generate = |policy: bool| {
        let mut yes = CK_TRUE as CK_BBOOL;
        let mut no = CK_FALSE as CK_BBOOL;
        let mut length = 32 as CK_ULONG;
        let mut derive_policy = [scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut yes)];
        let mut template = vec![
            scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut length),
            scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut yes),
            scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut yes),
            scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut no),
        ];
        if policy {
            template.push(CK_ATTRIBUTE {
                type_: CKA_DERIVE_TEMPLATE as CK_ATTRIBUTE_TYPE,
                pValue: derive_policy.as_mut_ptr().cast(),
                ulValueLen: std::mem::size_of_val(&derive_policy) as CK_ULONG,
            });
        }
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut key = 0;
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
        key
    };
    let base = generate(false);
    let mut other = generate(true);
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut other,
    );
    let key = derive(TEST_SESSION_HANDLE, &mut concat, base, &mut []);
    for attribute in [
        CKA_SENSITIVE,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
        CKA_SIGN,
    ] {
        assert_eq!(
            read_bytes_attribute(TEST_SESSION_HANDLE, key, attribute as CK_ATTRIBUTE_TYPE),
            [CK_TRUE as u8]
        );
    }
    let mut no = CK_FALSE as CK_BBOOL;
    let mut conflict = [scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut no)];
    let mut result = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            TEST_SESSION_HANDLE,
            &mut concat,
            base,
            conflict.as_mut_ptr(),
            1,
            &mut result
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    // An imported component prevents an always/never history even if protected.
    let mut imported = create_hkdf_test_key(TEST_SESSION_HANDLE, &mut [1; 32], true, true, false);
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut imported,
    );
    let key = derive(TEST_SESSION_HANDLE, &mut concat, base, &mut []);
    for attribute in [CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE] {
        assert_eq!(
            read_bytes_attribute(TEST_SESSION_HANDLE, key, attribute as CK_ATTRIBUTE_TYPE),
            [CK_FALSE as u8]
        );
    }
    unreadable(TEST_SESSION_HANDLE, key);
    // Hash derivation has different standard rules: a caller may choose weaker output policy.
    let mut hash = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let digest = derive(TEST_SESSION_HANDLE, &mut hash, base, &mut []);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, digest, CKA_VALUE as CK_ATTRIBUTE_TYPE).len(),
        32
    );
    assert_eq!(
        read_bytes_attribute(
            TEST_SESSION_HANDLE,
            digest,
            CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
        ),
        [CK_FALSE as u8]
    );
    assert_eq!(
        read_bytes_attribute(
            TEST_SESSION_HANDLE,
            digest,
            CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
        ),
        [CK_FALSE as u8]
    );
    let mut allowed = [CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE];
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut value = [1; 32];
    let mut attrs = vec![CK_ATTRIBUTE {
        type_: CKA_ALLOWED_MECHANISMS as CK_ATTRIBUTE_TYPE,
        pValue: allowed.as_mut_ptr().cast(),
        ulValueLen: std::mem::size_of_val(&allowed) as CK_ULONG,
    }];
    attrs.extend([
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut enabled),
        bytes_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
    ]);
    let mut restricted = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            TEST_SESSION_HANDLE,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG,
            &mut restricted
        ),
        CKR_OK as CK_RV
    );
    let mut concat = mechanism(
        CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE,
        &mut restricted,
    );
    assert_eq!(
        crate::api::C_DeriveKey(
            TEST_SESSION_HANDLE,
            &mut concat,
            base,
            std::ptr::null_mut(),
            0,
            &mut result
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    finalize_for_test();
}

#[test]
fn secret_composition_obeys_the_slot_software_mechanism_filter() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let mut slot = test_slot(true);
    slot.software_allowlist = Some(Vec::new());
    install_test_slot_with_backend(82, Box::new(slot));
    install_test_session(82, 8201);
    let base = create_hkdf_test_key(8201, &mut [1; 32], true, true, false);
    let mut info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(
            82,
            CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    let mut hash = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut result = 0;
    assert_eq!(
        crate::api::C_DeriveKey(8201, &mut hash, base, std::ptr::null_mut(), 0, &mut result),
        CKR_MECHANISM_INVALID as CK_RV
    );
    finalize_for_test();
}
