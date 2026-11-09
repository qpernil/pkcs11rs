use super::*;

// Exercise PKCS #11 creation through the virtual core's hardware-like limits.
// Count actual device records, verify exhaustion rollback and reuse, and report
// encoded opaque metadata bytes. Physical opaque probes verify 126-byte pages.
const OBJECT_BUDGET: usize = 256;

#[derive(Clone, Copy, Debug)]
enum Workload {
    Aes,
    AesEncryptOnly,
    AesLongLabel,
    AesEcbList,
    AesImportedEcbList,
    AesEmptyList,
    EcSessionPublic,
    EcTokenPublic,
    EcDefaultPublic,
}

fn create(session: CK_SESSION_HANDLE, workload: Workload) -> Result<Vec<CK_OBJECT_HANDLE>, CK_RV> {
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut public_token = matches!(workload, Workload::EcTokenPublic) as CK_BBOOL;
    let mut length = 16 as CK_ULONG;
    let mut label = vec![b'x'; 80];
    let mut allowed = vec![CKM_AES_ECB as CK_MECHANISM_TYPE];
    let mut parameters = crate::pkcs11_auth::P256_PARAMS.to_vec();
    let mut template = vec![scalar_attribute(CKA_TOKEN as _, &mut yes)];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    match workload {
        Workload::Aes
        | Workload::AesEncryptOnly
        | Workload::AesLongLabel
        | Workload::AesEcbList
        | Workload::AesImportedEcbList
        | Workload::AesEmptyList => {
            template.push(scalar_attribute(CKA_VALUE_LEN as _, &mut length));
            template.push(scalar_attribute(CKA_ENCRYPT as _, &mut yes));
            template.push(scalar_attribute(CKA_DECRYPT as _, &mut yes));
            if matches!(workload, Workload::Aes) {
                template.push(scalar_attribute(CKA_SIGN as _, &mut yes));
                template.push(scalar_attribute(CKA_VERIFY as _, &mut yes));
                template.push(scalar_attribute(CKA_DERIVE as _, &mut yes));
            }
            if matches!(workload, Workload::AesLongLabel) {
                template.push(bytes_attribute(CKA_LABEL as _, &mut label));
            }
            if matches!(
                workload,
                Workload::AesEcbList | Workload::AesImportedEcbList | Workload::AesEmptyList
            ) {
                if matches!(workload, Workload::AesEmptyList) {
                    allowed.clear();
                }
                template.push(CK_ATTRIBUTE {
                    type_: CKA_ALLOWED_MECHANISMS as _,
                    pValue: allowed.as_mut_ptr().cast(),
                    ulValueLen: std::mem::size_of_val(allowed.as_slice()) as _,
                });
            }
            let rv = if matches!(workload, Workload::AesImportedEcbList) {
                let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
                let mut key_type = CKK_AES as CK_KEY_TYPE;
                let mut value = [0x42u8; 16];
                template.retain(|attribute| attribute.type_ != CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE);
                template.push(scalar_attribute(CKA_CLASS as _, &mut class));
                template.push(scalar_attribute(CKA_KEY_TYPE as _, &mut key_type));
                template.push(scalar_attribute(CKA_PRIVATE as _, &mut yes));
                template.push(bytes_attribute(CKA_VALUE as _, &mut value));
                crate::api::C_CreateObject(
                    session,
                    template.as_mut_ptr(),
                    template.len() as _,
                    &mut private,
                )
            } else {
                crate::api::C_GenerateKey(
                    session,
                    &mut mechanism,
                    template.as_mut_ptr(),
                    template.len() as _,
                    &mut private,
                )
            };
            if rv != CKR_OK as CK_RV {
                return Err(rv);
            }
            Ok(vec![private])
        }
        Workload::EcSessionPublic | Workload::EcTokenPublic | Workload::EcDefaultPublic => {
            mechanism.mechanism = CKM_EC_KEY_PAIR_GEN as _;
            template.push(scalar_attribute(CKA_SIGN as _, &mut yes));
            let mut public_template = vec![
                scalar_attribute(CKA_TOKEN as _, &mut public_token),
                scalar_attribute(CKA_VERIFY as _, &mut yes),
                bytes_attribute(CKA_EC_PARAMS as _, &mut parameters),
            ];
            if matches!(workload, Workload::EcDefaultPublic) {
                public_template
                    .retain(|attribute| attribute.type_ != CKA_TOKEN as CK_ATTRIBUTE_TYPE);
            }
            let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
            let rv = crate::api::C_GenerateKeyPair(
                session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as _,
                template.as_mut_ptr(),
                template.len() as _,
                &mut public,
                &mut private,
            );
            if rv != CKR_OK as CK_RV {
                return Err(rv);
            }
            // Delete public first: deleting a private key alone deliberately
            // preserves an independently persistent public object.
            Ok(vec![public, private])
        }
    }
}

fn check_capacity(workload: Workload, records_per_key: usize, metadata_per_key: usize) {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let (slot, peer, _trust) = crate::yubihsm::tests::make_yubihsm_capacity_test_slot();
    install_test_slot_with_backend(TEST_SLOT_ID, slot);
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::api::C_Login(session, CKU_USER as _, pin.as_mut_ptr(), pin.len() as _),
        CKR_OK as CK_RV
    );
    let baseline = peer.storage_usage();
    assert_eq!(baseline, (1, vec![]), "one factory authentication object");
    let capacity = (OBJECT_BUDGET - baseline.0) / records_per_key;
    let mut last = Vec::new();
    for count in 1..=capacity {
        last = create(session, workload).unwrap();
        let (objects, metadata) = peer.storage_usage();
        assert_eq!(
            objects,
            baseline.0 + count * records_per_key,
            "{workload:?}"
        );
        assert_eq!(metadata.len(), count * metadata_per_key, "{workload:?}");
    }
    let (objects, sizes) = peer.storage_usage();
    if matches!(
        workload,
        Workload::AesEcbList | Workload::AesImportedEcbList | Workload::AesEmptyList
    ) {
        let identity = read_bytes_attribute(session, last[0], CKA_UNIQUE_ID as _);
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_Login(session, CKU_USER as _, pin.as_mut_ptr(), pin.len() as _),
            CKR_OK as CK_RV
        );
        last = find_by_bytes_attribute(session, CKO_SECRET_KEY as _, CKA_UNIQUE_ID as _, &identity);
        assert_eq!(last.len(), 1);
        let encoded = read_bytes_attribute(session, last[0], CKA_ALLOWED_MECHANISMS as _);
        let allowed: Vec<_> = encoded
            .as_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>()
            .0
            .iter()
            .map(|bytes| CK_MECHANISM_TYPE::from_ne_bytes(*bytes))
            .collect();
        if matches!(workload, Workload::AesEmptyList) {
            assert!(allowed.is_empty());
            assert_eq!(
                read_bytes_attribute(session, last[0], CKA_ENCRYPT as _),
                [CK_FALSE as u8]
            );
        } else {
            for mechanism in [
                CKM_AES_ECB,
                CKM_AES_GCM,
                CKM_AES_CMAC,
                CKM_SP800_108_COUNTER_KDF,
            ] {
                assert!(allowed.contains(&(mechanism as _)));
            }
            assert!(!allowed.contains(&(CKM_AES_CBC as _)));
            assert_eq!(
                read_bytes_attribute(session, last[0], CKA_SIGN as _),
                [CK_TRUE as u8]
            );
        }
        let mut iv = [0u8; 16];
        let mut cbc = CK_MECHANISM {
            mechanism: CKM_AES_CBC as _,
            pParameter: iv.as_mut_ptr().cast(),
            ulParameterLen: iv.len() as _,
        };
        assert_eq!(
            crate::api::C_EncryptInit(session, &mut cbc, last[0]),
            if matches!(workload, Workload::AesEmptyList) {
                CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
            } else {
                CKR_MECHANISM_INVALID as CK_RV
            }
        );
        assert_eq!(
            peer.storage_usage(),
            (objects, sizes.clone()),
            "rediscovery must not persist the computed policy"
        );
    }
    assert!(OBJECT_BUDGET - objects < records_per_key);
    eprintln!(
        "{workload:?}: {capacity} keys/pairs, {objects} device objects, {} metadata records, {} metadata bytes total, {:?} bytes/record",
        sizes.len(),
        sizes.iter().sum::<usize>(),
        sizes.iter().min().zip(sizes.iter().max())
    );
    assert_eq!(
        create(session, workload).unwrap_err(),
        CKR_DEVICE_MEMORY as CK_RV
    );
    assert_eq!(
        peer.storage_usage(),
        (objects, sizes.clone()),
        "failed creation must not leave an unreturned native key or metadata behind"
    );
    if matches!(
        workload,
        Workload::EcTokenPublic | Workload::EcDefaultPublic
    ) {
        // At full capacity either independent deletion needs a record to retain
        // the other half. Failure must preserve both objects and their storage.
        for handle in last {
            assert_eq!(
                crate::api::C_DestroyObject(session, handle),
                CKR_DEVICE_MEMORY as CK_RV
            );
            assert_eq!(peer.storage_usage(), (objects, sizes.clone()));
        }
        finalize_for_test();
        return;
    }
    for handle in last {
        assert_eq!(
            crate::api::C_DestroyObject(session, handle),
            CKR_OK as CK_RV
        );
    }
    let (after_delete, remaining) = peer.storage_usage();
    assert_eq!(after_delete, objects - records_per_key);
    assert_eq!(remaining.len(), sizes.len() - metadata_per_key);
    if metadata_per_key != 0 {
        assert!(remaining.iter().sum::<usize>() < sizes.iter().sum::<usize>());
    }
    create(session, workload).unwrap();
    assert_eq!(
        peer.storage_usage().0,
        objects,
        "deleted capacity must be reusable"
    );
    finalize_for_test();
}

#[test]
fn yubihsm_capacity_native_aes_uses_no_metadata() {
    check_capacity(Workload::Aes, 1, 0);
}

#[test]
fn yubihsm_capacity_long_labels_share_one_companion_per_key() {
    check_capacity(Workload::AesLongLabel, 2, 1);
}

#[test]
fn yubihsm_capacity_ec_session_public_requires_an_absence_marker() {
    check_capacity(Workload::EcSessionPublic, 2, 1);
}

#[test]
fn yubihsm_capacity_ec_token_pairs_use_no_metadata() {
    check_capacity(Workload::EcTokenPublic, 1, 0);
}

#[test]
fn yubihsm_capacity_aes_usage_roundtrip_uses_no_companion() {
    check_capacity(Workload::AesEncryptOnly, 1, 0);
}

#[test]
fn yubihsm_capacity_mechanism_roundtrip_uses_no_companion_after_relogin() {
    check_capacity(Workload::AesEcbList, 1, 0);
}

#[test]
fn yubihsm_capacity_empty_mechanisms_grant_nothing_without_a_companion() {
    check_capacity(Workload::AesEmptyList, 1, 0);
}

#[test]
fn yubihsm_capacity_imported_mechanism_roundtrip_uses_no_companion() {
    check_capacity(Workload::AesImportedEcbList, 1, 0);
}

fn policy_test_session() -> (
    CK_SESSION_HANDLE,
    std::rc::Rc<crate::yubihsm::tests::NativeDevicePeer>,
    crate::yubihsm::tests::TestTrustEntry,
) {
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let (slot, peer, trust) = crate::yubihsm::tests::make_yubihsm_capacity_test_slot();
    install_test_slot_with_backend(TEST_SLOT_ID, slot);
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::api::C_Login(session, CKU_USER as _, pin.as_mut_ptr(), pin.len() as _),
        CKR_OK as CK_RV
    );
    (session, peer, trust)
}

#[test]
fn yubihsm_native_ids_preserve_wire_bytes_empty_values_and_collisions() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (session, peer, _trust) = policy_test_session();
    for import in [false, true] {
        for requested in [
            None,
            Some(vec![0x12, 0x34]),
            Some(vec![0x12, 0x34]),
            Some(vec![]),
            Some(vec![0]),
            Some(vec![0, 0]),
            Some(vec![0xff, 0xff]),
            Some(vec![0, 1, 2]),
            Some(vec![0x56, 0x78]),
        ] {
            let before = peer.native_ids(crate::YUBIHSM_SYMMETRIC_KEY);
            let before_metadata = peer.storage_usage().1.len();
            let mut yes = CK_TRUE as CK_BBOOL;
            let mut length = 16 as CK_ULONG;
            let mut id = requested.clone().unwrap_or_default();
            let mut template = vec![
                scalar_attribute(CKA_TOKEN as _, &mut yes),
                scalar_attribute(CKA_ENCRYPT as _, &mut yes),
            ];
            if requested.is_some() {
                template.push(bytes_attribute(CKA_ID as _, &mut id));
            }
            let mut object = 0;
            if import {
                let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
                let mut key_type = CKK_AES as CK_KEY_TYPE;
                let mut material = [0x42; 16];
                template.extend([
                    scalar_attribute(CKA_CLASS as _, &mut class),
                    scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
                    scalar_attribute(CKA_PRIVATE as _, &mut yes),
                    bytes_attribute(CKA_VALUE as _, &mut material),
                ]);
                assert_eq!(
                    crate::api::C_CreateObject(
                        session,
                        template.as_mut_ptr(),
                        template.len() as _,
                        &mut object
                    ),
                    CKR_OK as CK_RV
                );
            } else {
                template.push(scalar_attribute(CKA_VALUE_LEN as _, &mut length));
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_KEY_GEN as _,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };
                assert_eq!(
                    crate::api::C_GenerateKey(
                        session,
                        &mut mechanism,
                        template.as_mut_ptr(),
                        template.len() as _,
                        &mut object
                    ),
                    CKR_OK as CK_RV
                );
            }
            let after = peer.native_ids(crate::YUBIHSM_SYMMETRIC_KEY);
            assert_eq!(
                after.len(),
                before.len() + 1,
                "collision must preserve the existing object"
            );
            let native = *after.iter().find(|id| !before.contains(id)).unwrap();
            assert!(native != 0 && native != 0xffff);
            let expected = requested
                .clone()
                .unwrap_or_else(|| native.to_be_bytes().to_vec());
            assert_eq!(read_bytes_attribute(session, object, CKA_ID as _), expected);
            if let Some(bytes) = &requested
                && bytes.len() == 2
            {
                let value = u16::from_be_bytes([bytes[0], bytes[1]]);
                if value != 0 && value != 0xffff && !before.contains(&value) {
                    assert_eq!(native, value, "the two-byte ID must not be byte-swapped");
                }
            }
            assert_eq!(
                peer.storage_usage().1.len(),
                before_metadata + usize::from(expected != native.to_be_bytes())
            );
        }
    }
    finalize_for_test();
}

#[test]
fn yubihsm_generated_pairs_preserve_independent_template_ids() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (session, peer, _trust) = policy_test_session();
    // Use the real virtual device: the fixed ABI fixture cannot generate keys.
    for (public_id, private_id) in [
        (Some(vec![0x12, 0x34]), None),
        (Some(vec![0x12, 0x34]), Some(vec![0x56, 0x78])),
        (None, Some(vec![0x56, 0x78])),
        (Some(vec![]), Some(vec![0, 0])),
    ] {
        let mut yes = CK_TRUE as CK_BBOOL;
        let mut parameters = crate::pkcs11_auth::P256_PARAMS.to_vec();
        let mut public_bytes = public_id.clone().unwrap_or_default();
        let mut private_bytes = private_id.clone().unwrap_or_default();
        let mut public_template = vec![
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            scalar_attribute(CKA_VERIFY as _, &mut yes),
            bytes_attribute(CKA_EC_PARAMS as _, &mut parameters),
        ];
        let mut private_template = vec![
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            scalar_attribute(CKA_SIGN as _, &mut yes),
        ];
        if public_id.is_some() {
            public_template.push(bytes_attribute(CKA_ID as _, &mut public_bytes));
        }
        if private_id.is_some() {
            private_template.push(bytes_attribute(CKA_ID as _, &mut private_bytes));
        }
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as _,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let (mut public, mut private) = (0, 0);
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as _,
                private_template.as_mut_ptr(),
                private_template.len() as _,
                &mut public,
                &mut private,
            ),
            CKR_OK as CK_RV
        );
        let native_ids = peer.native_ids(crate::YUBIHSM_ASYMMETRIC_KEY);
        assert_eq!(native_ids.len(), 1);
        let native_id = native_ids[0].to_be_bytes();
        for (handle, requested) in [(public, public_id), (private, private_id)] {
            assert_eq!(
                read_bytes_attribute(session, handle, CKA_ID as _),
                requested.unwrap_or_else(|| native_id.to_vec())
            );
        }
        assert_eq!(
            crate::api::C_DestroyObject(session, public),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_DestroyObject(session, private),
            CKR_OK as CK_RV
        );
        assert_eq!(peer.storage_usage(), (1, vec![]));
    }
    finalize_for_test();
}

#[test]
fn yubihsm_default_pairs_survive_independent_deletion_and_identity_changes() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (session, peer, _trust) = policy_test_session();
    let first = create(session, Workload::EcTokenPublic).unwrap();
    assert_eq!(peer.storage_usage(), (2, vec![]));
    let public_uid = read_bytes_attribute(session, first[0], CKA_UNIQUE_ID as _);
    let public_id = read_bytes_attribute(session, first[0], CKA_ID as _);
    let public_value = read_bytes_attribute(session, first[0], CKA_PUBLIC_KEY_INFO as _);
    let mut id = b"private override".to_vec();
    let mut update = [bytes_attribute(CKA_ID as _, &mut id)];
    assert_eq!(
        crate::api::C_SetAttributeValue(session, first[1], update.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        read_bytes_attribute(session, first[0], CKA_ID as _),
        public_id
    );
    let mut original = public_id.clone();
    let mut restore = [bytes_attribute(CKA_ID as _, &mut original)];
    assert_eq!(
        crate::api::C_SetAttributeValue(session, first[1], restore.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    assert_eq!(peer.storage_usage(), (2, vec![]));
    assert_eq!(
        crate::api::C_DestroyObject(session, first[1]),
        CKR_OK as CK_RV
    );
    assert!(peer.native_ids(crate::YUBIHSM_ASYMMETRIC_KEY).is_empty());
    assert_eq!(peer.storage_usage().0, 2); // auth key and standalone public record
    assert_eq!(
        read_bytes_attribute(session, first[0], CKA_UNIQUE_ID as _),
        public_uid
    );
    assert_eq!(
        read_bytes_attribute(session, first[0], CKA_PUBLIC_KEY_INFO as _),
        public_value
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, first[0]),
        CKR_OK as CK_RV
    );
    assert_eq!(peer.storage_usage(), (1, vec![]));
    let second = create(session, Workload::EcTokenPublic).unwrap();
    assert_eq!(
        crate::api::C_DestroyObject(session, second[0]),
        CKR_OK as CK_RV
    );
    assert_eq!(peer.storage_usage().0, 3); // auth, private, absence marker
    assert_eq!(
        crate::api::C_DestroyObject(session, second[1]),
        CKR_OK as CK_RV
    );
    assert_eq!(peer.storage_usage(), (1, vec![]));
    finalize_for_test();
}

#[test]
fn yubihsm_capacity_omitted_public_token_uses_native_presence_without_metadata() {
    check_capacity(Workload::EcDefaultPublic, 1, 0);
}

#[test]
fn yubihsm_unwrap_preserves_empty_ids_and_rolls_back_metadata_capacity_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (session, peer, _trust) = policy_test_session();
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut bits = 2048 as CK_ULONG;
    let mut public_template = [
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        scalar_attribute(CKA_WRAP as _, &mut yes),
        scalar_attribute(CKA_MODULUS_BITS as _, &mut bits),
    ];
    let mut private_template = [scalar_attribute(CKA_TOKEN as _, &mut yes)];
    let mut generation = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = 0;
    let mut private = 0;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut generation,
            public_template.as_mut_ptr(),
            public_template.len() as _,
            private_template.as_mut_ptr(),
            private_template.len() as _,
            &mut public,
            &mut private
        ),
        CKR_OK as CK_RV
    );
    let mut length = 16 as CK_ULONG;
    let mut aes_template = [
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        scalar_attribute(CKA_VALUE_LEN as _, &mut length),
        scalar_attribute(CKA_ENCRYPT as _, &mut yes),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut yes),
    ];
    let mut aes_generation = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut original = 0;
    assert_eq!(
        crate::api::C_GenerateKey(
            session,
            &mut aes_generation,
            aes_template.as_mut_ptr(),
            aes_template.len() as _,
            &mut original
        ),
        CKR_OK as CK_RV
    );
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped = [0u8; 256];
    let mut wrapped_len = wrapped.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut mechanism,
            public,
            original,
            wrapped.as_mut_ptr(),
            &mut wrapped_len
        ),
        CKR_OK as CK_RV
    );
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut kind = CKK_AES as CK_KEY_TYPE;
    let mut empty_id = Vec::new();
    let mut template = vec![
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut kind),
        scalar_attribute(CKA_VALUE_LEN as _, &mut length),
        scalar_attribute(CKA_ENCRYPT as _, &mut yes),
        bytes_attribute(CKA_ID as _, &mut empty_id),
    ];
    let baseline = peer.storage_usage();
    let mut imported = 0;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut mechanism,
            private,
            wrapped.as_mut_ptr(),
            wrapped_len,
            template.as_mut_ptr(),
            template.len() as _,
            &mut imported
        ),
        CKR_OK as CK_RV
    );
    assert!(read_bytes_attribute(session, imported, CKA_ID as _).is_empty());
    assert_eq!(peer.storage_usage().0, baseline.0 + 2);
    assert_eq!(
        crate::api::C_DestroyObject(session, imported),
        CKR_OK as CK_RV
    );
    assert_eq!(peer.storage_usage(), baseline);
    while peer.storage_usage().0 < OBJECT_BUDGET - 1 {
        create(session, Workload::Aes).unwrap();
    }
    let full_before = peer.storage_usage();
    let ids_before = peer.native_ids(crate::YUBIHSM_SYMMETRIC_KEY);
    imported = CK_INVALID_HANDLE as _;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut mechanism,
            private,
            wrapped.as_mut_ptr(),
            wrapped_len,
            template.as_mut_ptr(),
            template.len() as _,
            &mut imported
        ),
        CKR_DEVICE_MEMORY as CK_RV
    );
    assert_eq!(imported, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(
        peer.storage_usage(),
        full_before,
        "failed unwrap must restore storage capacity"
    );
    assert_eq!(
        peer.native_ids(crate::YUBIHSM_SYMMETRIC_KEY),
        ids_before,
        "failed unwrap must preserve pre-existing native keys"
    );
    finalize_for_test();
}
