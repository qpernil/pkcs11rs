use crate::pkcs11::*;
use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_STORAGE_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestFidoStorage {
    root: PathBuf,
}

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
            "storage": {"tokens": self.root.to_string_lossy()}
        }))
    }

    fn mock_objects(&self) -> PathBuf {
        self.root
            .join("tokens-v1")
            .join("yubico-serial-4d4f434b30303031")
            .join("fido2")
            .join("objects")
    }
}

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

fn open_logged_in_mock(storage: &TestFidoStorage) -> (CK_SLOT_ID, CK_SESSION_HANDLE) {
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

fn create_mock_resident_credential(slot: CK_SLOT_ID) -> Vec<u8> {
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

fn delete_mock_resident_credential(slot: CK_SLOT_ID, credential_id: &[u8]) {
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

#[test]
fn pkcs11_preview_sign_mock_registration_import_derivation_and_signing() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

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

    let digest: [u8; 32] = Sha256::digest(b"pkcs11rs previewSign PKCS #11 mock").into();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, restored_signing_key),
        CKR_OK as CK_RV
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
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, restored_signing_key),
        CKR_OK as CK_RV
    );
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
fn local_fido_storage_restores_preview_sign_keys_across_module_restart() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    let (_, session) = open_logged_in_mock(&storage);

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

    let object_files = std::fs::read_dir(storage.mock_objects())
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

    let (_, session) = open_logged_in_mock(&storage);
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

    let digest: [u8; 32] = Sha256::digest(b"persisted previewSign signing").into();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, signing_key),
        CKR_OK as CK_RV
    );
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

    let (_, session) = open_logged_in_mock(&storage);
    assert!(find_objects(session, &mut registration_find).is_empty());
    assert!(find_objects(session, &mut derived_find).is_empty());
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn corrupt_local_fido_storage_fails_discovery_closed() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    let storage = TestFidoStorage::new();
    let objects = storage.mock_objects();
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
        CKR_DEVICE_ERROR as CK_RV
    );
}

#[test]
fn pkcs11_mock_resident_credential_assertion_is_one_shot_and_verifiable() {
    let _guard = super::TEST_LOCK.lock().unwrap();
    super::finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

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
    let credential_id = create_mock_resident_credential(slot);
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
    let client_data_hash: [u8; 32] = Sha256::digest(b"pkcs11rs resident assertion mock").into();
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
    let assertion_digest = Sha256::digest(&signed);
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
    delete_mock_resident_credential(slot, &credential_id);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}
