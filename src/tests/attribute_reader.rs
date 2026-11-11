use super::*;
use crate::object::{AttributeValue, LazyCache};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

fn initialize() {
    finalize_for_test();
    assert_eq!(
        initialize_with_configuration(serde_json::json!({
            "version": 1, "hardware": {"discovery": false}, "yubihsm": {"urls": []}
        })),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
}

fn insert(material: crate::KeyMaterial, class: CK_OBJECT_CLASS) -> CK_OBJECT_HANDLE {
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        let mut object = crate::default_objects().unwrap().remove(&1).unwrap();
        object.unique_id.clear();
        object.class = class;
        object.key_type = CKK_AES as CK_KEY_TYPE;
        object.token = false;
        object.private = false;
        object.sensitive = false;
        object.extractable = true;
        object.material = material;
        ctx.insert_object(object).unwrap()
    })
}

fn query(handle: CK_OBJECT_HANDLE, type_: CK_ATTRIBUTE_TYPE) -> (CK_RV, CK_ULONG) {
    let mut attribute = CK_ATTRIBUTE {
        type_,
        pValue: std::ptr::null_mut(),
        ulValueLen: 123,
    };
    let rv = crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, handle, &mut attribute, 1);
    (rv, attribute.ulValueLen)
}

fn opaque(length: usize, value: Rc<RefCell<Option<Vec<u8>>>>) -> crate::KeyMaterial {
    crate::KeyMaterial::YubiHsm {
        id: 1,
        object_type: crate::YUBIHSM_OPAQUE,
        algorithm: 0,
        length,
        domains: 1,
        capabilities: [0; 8],
        delegated_capabilities: [0; 8],
        public_key: Vec::new(),
        value,
    }
}

#[test]
fn resident_attribute_reader_borrows_payloads_and_preserves_batch_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize();
    let payload = vec![0x42; 1024 * 1024];
    let pointer = payload.as_ptr();
    let handle = insert(
        crate::KeyMaterial::Data {
            application: b"reader test".to_vec(),
            object_id: vec![1],
            value: payload.into(),
        },
        CKO_DATA as CK_OBJECT_CLASS,
    );
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        let object = ctx.resolve_object_ref(handle).unwrap().unwrap();
        assert!(matches!(object, std::borrow::Cow::Borrowed(_)));
        let value = object
            .read_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
            .unwrap();
        assert!(matches!(value, AttributeValue::Borrowed(_)));
        assert_eq!(value.as_ref().as_ptr(), pointer);
    });
    assert_eq!(
        query(handle, CKA_VALUE as CK_ATTRIBUTE_TYPE),
        (CKR_OK as CK_RV, 1024 * 1024)
    );
    let mut short = [0x5a; 4];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE as _,
            pValue: short.as_mut_ptr().cast(),
            ulValueLen: 4,
        },
        CK_ATTRIBUTE {
            type_: CKA_ISSUER as _,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        },
        CK_ATTRIBUTE {
            type_: CKA_APPLICATION as _,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        },
    ];
    assert_eq!(
        crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, handle, attrs.as_mut_ptr(), 3),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(short, [0x5a; 4]);
    assert_eq!(attrs[0].ulValueLen, CK_UNAVAILABLE_INFORMATION as CK_ULONG);
    assert_eq!(attrs[1].ulValueLen, CK_UNAVAILABLE_INFORMATION as CK_ULONG);
    assert_eq!(attrs[2].ulValueLen, 11);
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, handle, CKA_VALUE as _),
        vec![0x42; 1024 * 1024]
    );
    finalize_for_test();
}

#[test]
fn native_attribute_lengths_preserve_live_checks_and_actual_read_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize();
    for (material, error, sizing) in [
        (
            opaque(4096, Rc::new(RefCell::new(None))),
            CKR_USER_NOT_LOGGED_IN,
            (CKR_OK as CK_RV, 4096),
        ),
        (
            crate::KeyMaterial::YubiHsmSessionObject {
                handle: 1,
                length: 4096,
            },
            CKR_FUNCTION_NOT_SUPPORTED,
            (CKR_FUNCTION_NOT_SUPPORTED as CK_RV, 123),
        ),
    ] {
        let handle = insert(material, CKO_DATA as CK_OBJECT_CLASS);
        assert_eq!(query(handle, CKA_VALUE as _), sizing);
        let mut output = vec![0x5a; 4096];
        let mut attribute = bytes_attribute(CKA_VALUE as _, &mut output);
        assert_eq!(
            crate::api::C_GetAttributeValue(TEST_SESSION_HANDLE, handle, &mut attribute, 1),
            error as CK_RV
        );
        assert!(output.iter().all(|byte| *byte == 0x5a));
        with_test_slot_context(TEST_SLOT_ID, |ctx| {
            ctx.memory_objects.get_mut(&handle).unwrap().private = true
        });
        assert_eq!(crate::api::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
        assert_eq!(
            query(handle, CKA_VALUE as _).0,
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
        let mut pin = *b"1234";
        assert_eq!(
            crate::api::C_Login(TEST_SESSION_HANDLE, CKU_USER as _, pin.as_mut_ptr(), 4),
            CKR_OK as CK_RV
        );
    }
    let handle = insert(
        crate::KeyMaterial::YubiHsmSessionObject {
            handle: 1,
            length: 4096,
        },
        CKO_SECRET_KEY as _,
    );
    with_test_slot_context(TEST_SLOT_ID, |ctx| {
        ctx.memory_objects.get_mut(&handle).unwrap().sensitive = true
    });
    assert_eq!(
        query(handle, CKA_VALUE as _),
        (
            CKR_ATTRIBUTE_SENSITIVE as CK_RV,
            CK_UNAVAILABLE_INFORMATION as CK_ULONG
        )
    );
    finalize_for_test();
}

#[test]
fn cached_native_attribute_length_and_value_share_the_same_bytes() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize();
    let cache = Rc::new(RefCell::new(Some(vec![1, 2, 3, 4])));
    let handle = insert(opaque(999, cache.clone()), CKO_DATA as _);
    assert_eq!(query(handle, CKA_VALUE as _), (CKR_OK as CK_RV, 4));
    assert_eq!(
        read_bytes_attribute(TEST_SESSION_HANDLE, handle, CKA_VALUE as _),
        [1, 2, 3, 4]
    );
    let _locked = cache.borrow_mut();
    assert_eq!(query(handle, CKA_VALUE as _).0, CKR_CANT_LOCK as CK_RV);
    drop(_locked);
    finalize_for_test();
}

#[test]
fn unknown_length_lazy_attributes_keep_missing_value_and_fetch_once_behavior() {
    let _guard = TEST_LOCK.lock().unwrap();
    initialize();
    let transmissions = Rc::new(Cell::new(0));
    let connector: Rc<dyn crate::Connector> = Rc::new(CountingConnector {
        transmissions: transmissions.clone(),
    });
    let handle = insert(
        crate::KeyMaterial::OpenPgpData {
            tag: 0x0101,
            connector: connector.clone(),
            cache: Rc::new(RefCell::new(LazyCache::Unattempted)),
        },
        CKO_DATA as _,
    );
    assert_eq!(query(handle, CKA_VALUE as _), (CKR_OK as CK_RV, 0));
    assert_eq!(transmissions.get(), 1);
    assert!(read_bytes_attribute(TEST_SESSION_HANDLE, handle, CKA_VALUE as _).is_empty());
    assert_eq!(transmissions.get(), 1);
    let handle = insert(
        crate::KeyMaterial::PivAttestation {
            connector,
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::EccP256,
            cache: Rc::new(RefCell::new(LazyCache::Unattempted)),
        },
        CKO_CERTIFICATE as _,
    );
    assert_eq!(
        query(handle, CKA_VALUE as _),
        (
            CKR_ATTRIBUTE_TYPE_INVALID as CK_RV,
            CK_UNAVAILABLE_INFORMATION as CK_ULONG
        )
    );
    assert_eq!(transmissions.get(), 2);
    assert_eq!(
        query(handle, CKA_VALUE as _).0,
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(transmissions.get(), 2);
    finalize_for_test();
}
