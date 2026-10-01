use crate::pkcs11::*;
use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
#[cfg(unix)]
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
static NEXT_STORAGE_DIRECTORY: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
struct TestFidoStorage {
    root: PathBuf,
}

#[cfg(unix)]
impl TestFidoStorage {
    fn new() -> Self {
        let id = NEXT_STORAGE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "pkcs11rs-preview-sign-storage-test-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn initialize(&self) -> CK_RV {
        super::initialize_with_configuration(serde_json::json!({
            "version": 1,
            "hardware": {"discovery": false},
            "yubihsm": {"urls": []},
            "storage": {"tokens": self.root.to_string_lossy()},
            "embedded": {"readers": [{
                "id": "preview-sign",
                "name": "Embedded CCID previewSign reader",
                "serial": 1,
                "persistent": true,
                "applets": ["fido2"]
            }]}
        }))
    }

    fn embedded_objects(&self) -> PathBuf {
        self.root
            .join("tokens-v1")
            .join("yubico-serial-31")
            .join("fido2")
            .join("objects")
    }
}

fn initialize_embedded() -> CK_RV {
    super::initialize_with_configuration(serde_json::json!({
        "version": 1,
        "hardware": {"discovery": false},
        "yubihsm": {"urls": []},
        "embedded": {"readers": [{
            "id": "preview-sign",
            "name": "Embedded CCID previewSign reader",
            "serial": 1,
            "applets": ["fido2"]
        }]}
    }))
}

#[cfg(unix)]
impl Drop for TestFidoStorage {
    fn drop(&mut self) {
        let _ = crate::api::C_Finalize(std::ptr::null_mut());
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ulong_attribute(type_: CK_ATTRIBUTE_TYPE, value: &mut CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: (value as *mut CK_ULONG).cast(),
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }
}

fn bool_attribute(type_: CK_ATTRIBUTE_TYPE, value: &mut CK_BBOOL) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: (value as *mut CK_BBOOL).cast(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }
}

fn bytes_attribute(type_: CK_ATTRIBUTE_TYPE, value: &mut [u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: value.as_mut_ptr().cast(),
        ulValueLen: value.len() as CK_ULONG,
    }
}

fn read_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    type_: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    let mut attribute = CK_ATTRIBUTE {
        type_,
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

fn find_smoke_key(
    session: CK_SESSION_HANDLE,
    object_class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    identifier: &mut [u8],
) -> Option<CK_OBJECT_HANDLE> {
    let mut object_class = object_class;
    let mut key_type = key_type;
    let mut attributes = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut object_class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, identifier),
    ];
    assert_eq!(
        crate::api::C_FindObjectsInit(
            session,
            attributes.as_mut_ptr(),
            attributes.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut count = 0;
    assert_eq!(
        crate::api::C_FindObjects(session, &mut object, 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
    (count != 0).then_some(object)
}

#[test]
#[cfg(unix)]
fn every_embedded_ccid_applet_starts_with_public_ro_and_rw_sessions() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    assert_eq!(
        super::initialize_with_configuration(serde_json::json!({
            "version": 1,
            "hardware": {"discovery": false},
            "yubihsm": {"urls": []},
            "storage": {"tokens": storage.root.to_string_lossy()},
            "embedded": {"readers": [{
                "id": "login-state",
                "name": "Embedded CCID login-state reader",
                "serial": 41,
                "persistent": true,
                "applets": ["piv", "openpgp", "hsmauth", "issuer-sd", "fido2"]
            }]}
        })),
        CKR_OK as CK_RV
    );

    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    let mut labels = Vec::new();
    for slot in slots {
        let mut token = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::api::C_GetTokenInfo(slot, &mut token),
            CKR_OK as CK_RV
        );
        let label = String::from_utf8_lossy(&token.label).trim_end().to_owned();
        labels.push(label.clone());

        for (flags, expected) in [
            (
                CKF_SERIAL_SESSION as CK_FLAGS,
                CKS_RO_PUBLIC_SESSION as CK_STATE,
            ),
            (
                (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
                CKS_RW_PUBLIC_SESSION as CK_STATE,
            ),
        ] {
            let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
            assert_eq!(
                crate::api::C_OpenSession(slot, flags, std::ptr::null_mut(), None, &mut session,),
                CKR_OK as CK_RV,
                "failed to open {label}"
            );
            let mut info = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
            assert_eq!(
                crate::api::C_GetSessionInfo(session, &mut info),
                CKR_OK as CK_RV,
                "failed to query {label}"
            );
            assert_eq!(info.state, expected, "wrong initial state for {label}");
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        }
    }

    labels.sort();
    assert_eq!(
        labels,
        [
            "FIDO2 FIDO_2_1 #41",
            "HSM Auth #41",
            "Issuer SD #41",
            "OpenPGP #41",
            "PIV #41",
        ]
    );
    super::finalize_for_test();
}

#[test]
#[cfg(unix)]
fn embedded_piv_pqc_enforces_token_wide_role_transitions() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    assert_eq!(
        super::initialize_with_configuration(serde_json::json!({
            "version": 1,
            "hardware": {"discovery": false},
            "yubihsm": {"urls": []},
            "storage": {"tokens": storage.root.to_string_lossy()},
            "embedded": {"readers": [{
                "id": "piv-pqc",
                "name": "pkcs11rs embedded CCID reader",
                "serial": 1,
                "persistent": true,
                "applets": ["piv", "fido2"]
            }]}
        })),
        CKR_OK as CK_RV
    );

    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 2);
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    let labels = slots
        .iter()
        .map(|slot| {
            let mut info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
            assert_eq!(
                crate::api::C_GetTokenInfo(*slot, &mut info),
                CKR_OK as CK_RV
            );
            (
                *slot,
                String::from_utf8_lossy(&info.label).trim_end().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert!(labels.iter().any(|(_, label)| label == "PIV #1"));
    assert!(labels.iter().any(|(_, label)| label == "FIDO2 FIDO_2_1 #1"));
    let slot = labels
        .iter()
        .find_map(|(slot, label)| (label == "PIV #1").then_some(*slot))
        .unwrap();
    let fido_slot = labels
        .iter()
        .find_map(|(slot, label)| (label == "FIDO2 FIDO_2_1 #1").then_some(*slot))
        .unwrap();

    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut session_info = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_FindObjectsInit(session, std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut public_objects = vec![CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 16];
    let mut public_object_count = 0;
    assert_eq!(
        crate::api::C_FindObjects(
            session,
            public_objects.as_mut_ptr(),
            public_objects.len() as CK_ULONG,
            &mut public_object_count,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);

    for (key_type, id) in [
        (CKK_ML_DSA as CK_KEY_TYPE, 5_u8),
        (CKK_ML_KEM as CK_KEY_TYPE, 6_u8),
        (crate::CKK_PKCS11RS_MLKEM768_X25519, 7_u8),
    ] {
        let mut identifier = [id];
        assert!(
            find_smoke_key(
                session,
                CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type,
                &mut identifier,
            )
            .is_none(),
            "fresh embedded PIV slot {id} unexpectedly contains the smoke key"
        );
    }

    let mut management_key = b"010203040506070801020304050607080102030405060708".to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_SO as CK_USER_TYPE,
            management_key.as_mut_ptr(),
            management_key.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);

    // Closing the final session logs the token out. A later consumer run starts
    // public and can perform a fresh SO login.
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_SO as CK_USER_TYPE,
            management_key.as_mut_ptr(),
            management_key.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);

    // Selecting and authenticating the other applet on the same embedded
    // reader invalidates the PIV selected-applet guard. The PIV slot must not
    // continue reporting SO merely because its SlotState recorded that role.
    let mut fido_session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            fido_slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut fido_session,
        ),
        CKR_OK as CK_RV
    );
    let mut fido_pin = b"123456".to_vec();
    assert_eq!(
        crate::api::C_Login(
            fido_session,
            CKU_USER as CK_USER_TYPE,
            fido_pin.as_mut_ptr(),
            fido_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut second_piv_session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut second_piv_session,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(second_piv_session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_CloseSession(second_piv_session),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_SO as CK_USER_TYPE,
            management_key.as_mut_ptr(),
            management_key.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
    assert_eq!(
        crate::api::C_GetSessionInfo(fido_session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_Logout(fido_session),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(crate::api::C_CloseSession(fido_session), CKR_OK as CK_RV);

    let mut generated = Vec::new();
    for (mechanism_type, parameter_set, id, label, public_usage, private_usage) in [
        (
            CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            Some(CKP_ML_DSA_87 as CK_ULONG),
            5_u8,
            b"iPhone smoke ML-DSA-87".as_slice(),
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
        ),
        (
            CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            Some(CKP_ML_KEM_1024 as CK_ULONG),
            6_u8,
            b"iPhone smoke ML-KEM-1024".as_slice(),
            CKA_ENCAPSULATE as CK_ATTRIBUTE_TYPE,
            CKA_DECAPSULATE as CK_ATTRIBUTE_TYPE,
        ),
        (
            crate::CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN,
            None,
            7_u8,
            b"iPhone smoke MLKEM768-X25519".as_slice(),
            CKA_ENCAPSULATE as CK_ATTRIBUTE_TYPE,
            CKA_DECAPSULATE as CK_ATTRIBUTE_TYPE,
        ),
    ] {
        assert_eq!(
            crate::api::C_GetSessionInfo(session, &mut session_info),
            CKR_OK as CK_RV
        );
        assert_eq!(session_info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
        let mut mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut token = CK_TRUE as CK_BBOOL;
        let mut public_usage_value = CK_TRUE as CK_BBOOL;
        let mut private_usage_value = CK_TRUE as CK_BBOOL;
        let mut parameter_set = parameter_set.unwrap_or_default();
        let mut id = [id];
        let mut label = label.to_vec();
        let mut public_template = vec![
            bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
            bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
            bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id),
            bool_attribute(public_usage, &mut public_usage_value),
        ];
        if parameter_set != 0 {
            public_template.insert(
                3,
                ulong_attribute(CKA_PARAMETER_SET as CK_ATTRIBUTE_TYPE, &mut parameter_set),
            );
        }
        let mut private_template = [
            bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
            bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
            bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id),
            bool_attribute(private_usage, &mut private_usage_value),
        ];
        let mut public_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut private_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as CK_ULONG,
                private_template.as_mut_ptr(),
                private_template.len() as CK_ULONG,
                &mut public_key,
                &mut private_key,
            ),
            CKR_OK as CK_RV,
            "PQC key generation mechanism {mechanism_type:#x} failed"
        );
        assert_ne!(public_key, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
        assert_ne!(private_key, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
        assert_eq!(
            crate::api::C_GetSessionInfo(session, &mut session_info),
            CKR_OK as CK_RV
        );
        assert_eq!(session_info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
        generated.push((mechanism_type, public_key, private_key));
    }

    assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    let mut pin = b"123456".to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut session_info),
        CKR_OK as CK_RV
    );
    assert_eq!(session_info.state, CKS_RW_USER_FUNCTIONS as CK_STATE);

    let (_, dsa_public, dsa_private) = generated[0];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut message = b"embedded PIV ML-DSA smoke".to_vec();
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, dsa_private),
        CKR_OK as CK_RV
    );
    let mut signature_length = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            message.as_mut_ptr(),
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
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_VerifyInit(session, &mut mechanism, dsa_public),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_length,
        ),
        CKR_OK as CK_RV
    );

    super::key::assert_hash_ml_dsa_roundtrip(session, dsa_public, dsa_private);

    for (generation, public_key, private_key) in generated.into_iter().skip(1) {
        mechanism.mechanism = if generation == CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
            CKM_ML_KEM as CK_MECHANISM_TYPE
        } else {
            crate::CKM_PKCS11RS_MLKEM768_X25519
        };
        let mut secret_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
        let mut token = CK_FALSE as CK_BBOOL;
        let mut sensitive = CK_FALSE as CK_BBOOL;
        let mut extractable = CK_TRUE as CK_BBOOL;
        let mut value_length = 32 as CK_ULONG;
        let mut secret_template = [
            ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut secret_type),
            bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
            bool_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut sensitive),
            bool_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
            ulong_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut value_length),
        ];
        let mut ciphertext_length = 0;
        let mut encapsulated = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_EncapsulateKey(
                session,
                &mut mechanism,
                public_key,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ciphertext_length,
                &mut encapsulated,
            ),
            CKR_OK as CK_RV
        );
        let mut ciphertext = vec![0; ciphertext_length as usize];
        assert_eq!(
            crate::api::C_EncapsulateKey(
                session,
                &mut mechanism,
                public_key,
                secret_template.as_mut_ptr(),
                secret_template.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_length,
                &mut encapsulated,
            ),
            CKR_OK as CK_RV
        );
        let mut decapsulated = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_DecapsulateKey(
                session,
                &mut mechanism,
                private_key,
                secret_template.as_mut_ptr(),
                secret_template.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                ciphertext_length,
                &mut decapsulated,
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            read_attribute(session, encapsulated, CKA_VALUE as CK_ATTRIBUTE_TYPE),
            read_attribute(session, decapsulated, CKA_VALUE as CK_ATTRIBUTE_TYPE)
        );
    }

    assert_eq!(
        crate::api::C_FindObjectsInit(session, std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut authenticated_objects = vec![CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 32];
    let mut authenticated_object_count = 0;
    assert_eq!(
        crate::api::C_FindObjects(
            session,
            authenticated_objects.as_mut_ptr(),
            authenticated_objects.len() as CK_ULONG,
            &mut authenticated_object_count,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
    assert!(authenticated_object_count >= public_object_count);

    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[cfg(unix)]
fn open_logged_in_embedded(storage: &TestFidoStorage) -> (CK_SLOT_ID, CK_SESSION_HANDLE) {
    assert_eq!(storage.initialize(), CKR_OK as CK_RV);
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    let mut slot = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, &mut slot, &mut count),
        CKR_OK as CK_RV
    );
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = b"123456".to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    (slot, session)
}

fn create_embedded_resident_credential(slot: CK_SLOT_ID) -> Vec<u8> {
    crate::with_context(|context| {
        let slot_contexts = context
            .slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        let child = slot_contexts.get(&slot).ok_or(CKR_SLOT_ID_INVALID)?;
        let mut child = child
            .lock()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        child
            ._get_slot_mut(slot)?
            .create_fido2_test_credential(b"123456")
            .map(|credential| credential.credential_id)
    })
    .expect("failed to create resident credential in virtual YubiKey")
}

fn delete_embedded_resident_credential(slot: CK_SLOT_ID, credential_id: &[u8]) {
    crate::with_context(|context| {
        let slot_contexts = context
            .slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        let child = slot_contexts.get(&slot).ok_or(CKR_SLOT_ID_INVALID)?;
        let mut child = child
            .lock()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        child
            ._get_slot_mut(slot)?
            .delete_fido2_test_credential(b"123456", credential_id)
    })
    .expect("failed to remove resident credential from virtual YubiKey");
}

fn find_objects(
    session: CK_SESSION_HANDLE,
    template: &mut [CK_ATTRIBUTE],
) -> Vec<CK_OBJECT_HANDLE> {
    assert_eq!(
        crate::api::C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG,),
        CKR_OK as CK_RV
    );
    let mut handles = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 16];
    let mut count = 0;
    assert_eq!(
        crate::api::C_FindObjects(
            session,
            handles.as_mut_ptr(),
            handles.len() as CK_ULONG,
            &mut count,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
    handles[..count as usize].to_vec()
}

fn authorize_preview_operation(session: CK_SESSION_HANDLE, digest: &[u8; 32]) {
    let mut length = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr().cast_mut(),
            32,
            std::ptr::null_mut(),
            &mut length
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    let mut pin = *b"123456";
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
}

#[test]
fn embedded_fido_random_generation_in_public_and_user_ro_and_rw_sessions() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    assert_eq!(initialize_embedded(), CKR_OK as CK_RV);

    let mut count = 1;
    let mut slot = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, &mut slot, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    for flags in [
        CKF_SERIAL_SESSION as CK_FLAGS,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
    ] {
        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(slot, flags, std::ptr::null_mut(), None, &mut session),
            CKR_OK as CK_RV
        );
        for logged_in in [false, true, false] {
            if logged_in {
                let mut pin = *b"123456";
                assert_eq!(
                    crate::api::C_Login(
                        session,
                        CKU_USER as CK_USER_TYPE,
                        pin.as_mut_ptr(),
                        pin.len() as CK_ULONG,
                    ),
                    CKR_OK as CK_RV
                );
            }
            for length in [0, 1, 32, 256, 257] {
                let mut random = vec![0; length];
                assert_eq!(
                    crate::api::C_GenerateRandom(
                        session,
                        random.as_mut_ptr(),
                        random.len() as CK_ULONG,
                    ),
                    CKR_OK as CK_RV,
                    "flags {flags:#x}, logged in {logged_in}, length {length}"
                );
            }
            if logged_in {
                assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
            }
        }
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    }
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn pkcs11_preview_sign_embedded_registration_import_derivation_and_signing() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    assert_eq!(initialize_embedded(), CKR_OK as CK_RV);

    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    let mut slot = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, &mut slot, &mut count),
        CKR_OK as CK_RV
    );
    let mut mechanism_count = 0;
    assert_eq!(
        crate::C_GetMechanismList(slot, std::ptr::null_mut(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    let mut mechanisms = vec![0; mechanism_count as usize];
    assert_eq!(
        crate::C_GetMechanismList(slot, mechanisms.as_mut_ptr(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    assert!(mechanisms.contains(&crate::CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN));
    assert!(mechanisms.contains(&crate::CKM_PKCS11RS_PREVIEW_SIGN_DERIVE));
    assert!(mechanisms.contains(&crate::CKM_PKCS11RS_PREVIEW_SIGN));

    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = b"123456".to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ec = CKK_EC as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
    ];
    let mut private_template = [
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
    ];
    let mut public_key = 0;
    let mut credential_private_key = 0;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut public_key,
            &mut credential_private_key,
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(public_key, credential_private_key);

    let registration = read_attribute(
        session,
        credential_private_key,
        crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
    );
    crate::preview_sign::PreviewSignRegistration::from_cbor(&registration).unwrap();

    let mut registration_key_type = crate::CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION as CK_ULONG;
    let mut class = CKO_PRIVATE_KEY as CK_ULONG;
    let mut session_object = CK_TRUE as CK_BBOOL;
    let mut derive = CK_TRUE as CK_BBOOL;
    let mut registration_value = registration.clone();
    let mut import_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            &mut registration_key_type,
        ),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bool_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut derive),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            &mut registration_value,
        ),
    ];
    let mut registration_key = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            import_template.as_mut_ptr(),
            import_template.len() as CK_ULONG,
            &mut registration_key,
        ),
        CKR_TOKEN_WRITE_PROTECTED as CK_RV
    );
    super::with_test_slot_context(slot, |context| {
        context
            .set_token_storage_provider(Box::new(crate::storage::MemoryStorageProvider::new()))
            .unwrap();
    });
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            import_template.as_mut_ptr(),
            import_template.len() as CK_ULONG,
            &mut registration_key,
        ),
        CKR_OK as CK_RV
    );

    let mut context = b"pkcs11rs previewSign demo".to_vec();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
        pParameter: context.as_mut_ptr().cast(),
        ulParameterLen: context.len() as CK_ULONG,
    };
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut derived_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bool_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
    ];
    let mut signing_key = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut mechanism,
            registration_key,
            derived_template.as_mut_ptr(),
            derived_template.len() as CK_ULONG,
            &mut signing_key,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        read_attribute(
            session,
            signing_key,
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        ),
        registration
    );
    let derived_encoded = read_attribute(
        session,
        signing_key,
        crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
    );
    let derived =
        crate::preview_sign::PreviewSignDerivedKeyRecord::from_cbor(&derived_encoded).unwrap();
    assert_eq!(
        crate::api::C_DestroyObject(session, signing_key),
        CKR_OK as CK_RV
    );

    let mut derived_only = derived_encoded.clone();
    let mut missing_registration_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            &mut derived_only,
        ),
    ];
    let mut restored_signing_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            missing_registration_template.as_mut_ptr(),
            missing_registration_template.len() as CK_ULONG,
            &mut restored_signing_key,
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    let mismatched = crate::preview_sign::PreviewSignDerivedKeyRecord::new(
        crate::storage::ContentReference::for_object(b"different registration"),
        derived.algorithm(),
        derived.verification_key_cose().to_vec(),
        derived.additional_args_cbor().map(<[u8]>::to_vec),
        derived.label().map(str::to_owned),
    )
    .unwrap()
    .to_cbor()
    .unwrap();
    let mut mismatched_registration = registration.clone();
    let mut mismatched_derived = mismatched;
    let mut session_token = CK_FALSE as CK_BBOOL;
    let mut mismatched_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_token),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            &mut mismatched_registration,
        ),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            &mut mismatched_derived,
        ),
    ];
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            mismatched_template.as_mut_ptr(),
            mismatched_template.len() as CK_ULONG,
            &mut restored_signing_key,
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );
    mismatched_derived = crate::preview_sign::PreviewSignDerivedKeyRecord::new(
        derived.registration().clone(),
        derived.algorithm(),
        derived.verification_key_cose().to_vec(),
        Some(vec![0xa0]),
        derived.label().map(str::to_owned),
    )
    .unwrap()
    .to_cbor()
    .unwrap();
    mismatched_template[4] = bytes_attribute(
        crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
        &mut mismatched_derived,
    );
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            mismatched_template.as_mut_ptr(),
            mismatched_template.len() as CK_ULONG,
            &mut restored_signing_key,
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut restored_registration = registration.clone();
    let mut restored_derived = derived_encoded.clone();
    let mut restored_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_token),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bool_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            &mut restored_registration,
        ),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            &mut restored_derived,
        ),
    ];
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            restored_template.as_mut_ptr(),
            restored_template.len() as CK_ULONG,
            &mut restored_signing_key,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        read_attribute(
            session,
            restored_signing_key,
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        ),
        registration
    );
    assert_eq!(
        read_attribute(
            session,
            restored_signing_key,
            crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
        ),
        derived_encoded
    );

    let mut project_mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut projected_template = [
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_token),
        bool_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
    ];
    let mut projected_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut project_mechanism,
            restored_signing_key,
            projected_template.as_mut_ptr(),
            projected_template.len() as CK_ULONG,
            &mut projected_key,
        ),
        CKR_OK as CK_RV
    );

    // Match the phone smoke app: obtain the signing input through the FIDO
    // session rather than bypassing C_GenerateRandom with a fixed digest.
    let mut digest = [0u8; 32];
    assert_eq!(
        crate::api::C_GenerateRandom(session, digest.as_mut_ptr(), digest.len() as CK_ULONG),
        CKR_OK as CK_RV
    );
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, restored_signing_key),
        CKR_OK as CK_RV
    );
    authorize_preview_operation(session, &digest);
    assert_eq!(
        read_attribute(
            session,
            restored_signing_key,
            CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE
        ),
        [CK_TRUE as u8]
    );
    let mut signature_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr() as *mut CK_BYTE,
            digest.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 64);
    let mut short_signature = [0u8; 8];
    let mut short_len = short_signature.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr().cast_mut(),
            32,
            short_signature.as_mut_ptr(),
            &mut short_len
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(short_len, 64);
    let mut signature = vec![0; signature_len as usize];
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr() as *mut CK_BYTE,
            digest.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );

    let mut verify_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_VerifyInit(session, &mut verify_mechanism, projected_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            session,
            digest.as_ptr().cast_mut(),
            digest.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_DestroyObject(session, credential_private_key),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, credential_private_key),
        CKR_OK as CK_RV
    );
    // Logout removes private session objects; restore the exported derived key
    // before checking that the deleted parent can no longer sign.
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            restored_template.as_mut_ptr(),
            restored_template.len() as CK_ULONG,
            &mut restored_signing_key
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, restored_signing_key),
        CKR_OK as CK_RV
    );
    authorize_preview_operation(session, &digest);
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr().cast_mut(),
            digest.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_DEVICE_ERROR as CK_RV
    );

    super::with_test_slot_context(slot, |context| {
        context.refresh_slot_token_objects(slot).unwrap();
        assert!(context.resolve_object(registration_key).unwrap().is_some());
        assert!(
            context
                .resolve_object(restored_signing_key)
                .unwrap()
                .is_some()
        );
    });
    assert_eq!(
        crate::api::C_DestroyObject(session, projected_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, restored_signing_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, registration_key),
        CKR_OK as CK_RV
    );
    super::with_test_slot_context(slot, |context| {
        context
            .set_token_storage_provider(Box::new(crate::storage::UnavailableStorageProvider))
            .unwrap();
    });
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
#[cfg(unix)]
fn local_fido_storage_restores_preview_sign_keys_across_module_restart() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    let (_, session) = open_logged_in_embedded(&storage);

    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ec = CKK_EC as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
    ];
    let mut private_template = [
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
    ];
    let mut credential_public_key = 0;
    let mut credential_private_key = 0;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut credential_public_key,
            &mut credential_private_key,
        ),
        CKR_OK as CK_RV
    );
    let registration = read_attribute(
        session,
        credential_private_key,
        crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
    );

    let mut class = CKO_PRIVATE_KEY as CK_ULONG;
    let mut registration_key_type = crate::CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION as CK_ULONG;
    let mut derive = CK_TRUE as CK_BBOOL;
    let mut registration_value = registration.clone();
    let mut registration_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            &mut registration_key_type,
        ),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bool_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut derive),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            &mut registration_value,
        ),
    ];
    let mut registration_key = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            session,
            registration_template.as_mut_ptr(),
            registration_template.len() as CK_ULONG,
            &mut registration_key,
        ),
        CKR_OK as CK_RV
    );

    let mut context = b"pkcs11rs persisted previewSign demo".to_vec();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
        pParameter: context.as_mut_ptr().cast(),
        ulParameterLen: context.len() as CK_ULONG,
    };
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut derived_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        bool_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        bool_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
    ];
    let mut signing_key = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut mechanism,
            registration_key,
            derived_template.as_mut_ptr(),
            derived_template.len() as CK_ULONG,
            &mut signing_key,
        ),
        CKR_OK as CK_RV
    );
    let derived = read_attribute(
        session,
        signing_key,
        crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
    );
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let object_files = std::fs::read_dir(storage.embedded_objects())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "cbor")
        })
        .count();
    assert!(object_files >= 3);

    let (_, session) = open_logged_in_embedded(&storage);
    let mut registration_match = registration.clone();
    let mut registration_find = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        ulong_attribute(
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            &mut registration_key_type,
        ),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            &mut registration_match,
        ),
    ];
    let registration_keys = find_objects(session, &mut registration_find);
    assert_eq!(registration_keys.len(), 1);
    registration_key = registration_keys[0];

    let mut derived_match = derived.clone();
    let mut derived_find = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        bytes_attribute(
            crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            &mut derived_match,
        ),
    ];
    let signing_keys = find_objects(session, &mut derived_find);
    assert_eq!(signing_keys.len(), 1);
    signing_key = signing_keys[0];
    assert_eq!(
        read_attribute(
            session,
            signing_key,
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        ),
        registration
    );

    let mut project = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut session_object = CK_FALSE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut projected_template = [
        bool_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
        bool_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
    ];
    let mut projected_key = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut project,
            signing_key,
            projected_template.as_mut_ptr(),
            projected_template.len() as CK_ULONG,
            &mut projected_key,
        ),
        CKR_OK as CK_RV
    );

    let digest: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
        .digest(b"persisted previewSign signing")
        .try_into()
        .unwrap();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, signing_key),
        CKR_OK as CK_RV
    );
    authorize_preview_operation(session, &digest);
    let mut signature_length = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr().cast_mut(),
            digest.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    let mut signature = vec![0; signature_length as usize];
    assert_eq!(
        crate::api::C_Sign(
            session,
            digest.as_ptr().cast_mut(),
            digest.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_length,
        ),
        CKR_OK as CK_RV
    );
    let mut verify_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_VerifyInit(session, &mut verify_mechanism, projected_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            session,
            digest.as_ptr().cast_mut(),
            digest.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_DestroyObject(session, projected_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, signing_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, registration_key),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let (_, session) = open_logged_in_embedded(&storage);
    assert!(find_objects(session, &mut registration_find).is_empty());
    assert!(find_objects(session, &mut derived_find).is_empty());
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
#[cfg(unix)]
fn corrupt_local_fido_storage_fails_discovery_closed() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    let objects = storage.embedded_objects();
    std::fs::create_dir_all(&objects).unwrap();
    std::fs::write(
        objects.join(format!("sha3-256-{}.cbor", "00".repeat(32))),
        [0xf6],
    )
    .unwrap();

    assert_eq!(storage.initialize(), CKR_OK as CK_RV);
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count,),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
}

#[test]
fn pkcs11_embedded_resident_credential_assertion_is_one_shot_and_verifiable() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    assert_eq!(initialize_embedded(), CKR_OK as CK_RV);

    let mut slot_count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut slot_count),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_count, 1);
    let mut slot = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, &mut slot, &mut slot_count),
        CKR_OK as CK_RV
    );
    let credential_id = create_embedded_resident_credential(slot);
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = b"123456".to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_ULONG;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut rp_id = crate::ctap::FIDO2_TEST_RP_ID.as_bytes().to_vec();
    let mut find_template = [
        ulong_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        bool_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
        bytes_attribute(crate::CKA_PKCS11RS_FIDO_RP_ID, &mut rp_id),
    ];
    assert_eq!(
        crate::api::C_FindObjectsInit(
            session,
            find_template.as_mut_ptr(),
            find_template.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut private_key = 0;
    let mut found = 0;
    assert_eq!(
        crate::api::C_FindObjects(session, &mut private_key, 1, &mut found),
        CKR_OK as CK_RV
    );
    assert_eq!(found, 1);
    assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
    assert_eq!(
        read_attribute(
            session,
            private_key,
            CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE
        ),
        [CK_TRUE as CK_BBOOL]
    );
    assert_eq!(
        read_attribute(session, private_key, crate::CKA_PKCS11RS_FIDO_RP_ID),
        crate::ctap::FIDO2_TEST_RP_ID.as_bytes()
    );

    let mut project_mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut public_template = [bool_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify)];
    let mut public_key = 0;
    assert_eq!(
        crate::api::C_DeriveKey(
            session,
            &mut project_mechanism,
            private_key,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            &mut public_key,
        ),
        CKR_OK as CK_RV
    );
    let point = read_attribute(session, public_key, CKA_EC_POINT as CK_ATTRIBUTE_TYPE);
    let point = crate::der_octet_string_value(&point).unwrap();
    VerifyingKey::from_sec1_bytes(point).unwrap();
    let client_data_hash: [u8; 32] = software_key_core::digest::HashAlgorithm::Sha256
        .digest(b"pkcs11rs resident assertion embedded")
        .try_into()
        .unwrap();
    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_FIDO_ASSERTION,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, private_key),
        CKR_OK as CK_RV
    );
    let mut response_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut response_len,
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Sign(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut response_len,
        ),
        CKR_OK as CK_RV
    );
    let mut short = vec![0; response_len.saturating_sub(1) as usize];
    let mut short_len = short.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_Sign(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
            short.as_mut_ptr(),
            &mut short_len,
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(short_len, response_len);
    let mut response = vec![0; response_len as usize];
    assert_eq!(
        crate::api::C_Sign(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
            response.as_mut_ptr(),
            &mut response_len,
        ),
        CKR_OK as CK_RV
    );

    let mut decoder = minicbor::Decoder::new(&response);
    let count = decoder.map().unwrap().unwrap();
    let mut authenticator_data = None;
    let mut signature = None;
    for _ in 0..count {
        match decoder.u8().unwrap() {
            2 => authenticator_data = Some(decoder.bytes().unwrap().to_vec()),
            3 => signature = Some(decoder.bytes().unwrap().to_vec()),
            _ => decoder.skip().unwrap(),
        }
    }
    assert_eq!(decoder.position(), response.len());
    let authenticator_data = authenticator_data.unwrap();
    let signature = DerSignature::from_bytes(&signature.unwrap()).unwrap();
    let signature = Signature::try_from(signature).unwrap();
    let signature = signature.to_bytes();
    let mut signed = authenticator_data;
    signed.extend_from_slice(&client_data_hash);
    let assertion_digest = software_key_core::digest::HashAlgorithm::Sha256.digest(&signed);
    let mut verify_mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_VerifyInit(session, &mut verify_mechanism, public_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Verify(
            session,
            assertion_digest.as_ptr().cast_mut(),
            assertion_digest.len() as CK_ULONG,
            signature.as_ptr().cast_mut(),
            signature.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut unused_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut unused_len,
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, private_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SignUpdate(
            session,
            client_data_hash.as_ptr() as *mut CK_BYTE,
            client_data_hash.len() as CK_ULONG,
        ),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(
        crate::api::C_SignFinal(session, std::ptr::null_mut(), &mut unused_len),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    delete_embedded_resident_credential(slot, &credential_id);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}
