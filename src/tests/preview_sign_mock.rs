use crate::pkcs11::*;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;

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

fn read_attribute(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, type_: u64) -> Vec<u8> {
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
    let mut session_object = CK_FALSE as CK_BBOOL;
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
    let derived = read_attribute(
        session,
        signing_key,
        crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
    );
    let derived = crate::preview_sign::PreviewSignDerivedKeyRecord::from_cbor(&derived).unwrap();

    let digest: [u8; 32] = Sha256::digest(b"pkcs11rs previewSign PKCS #11 mock").into();
    mechanism = CK_MECHANISM {
        mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(session, &mut mechanism, signing_key),
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

    let projected = crate::project_cose_public_key(derived.verification_key_cose()).unwrap();
    let crate::FidoPublicKey::Ec {
        public_key,
        prefix_uncompressed,
        ..
    } = projected.public_key
    else {
        panic!("derived previewSign key is not EC");
    };
    let mut sec1 = Vec::with_capacity(public_key.len() + 1);
    if prefix_uncompressed {
        sec1.push(4);
    }
    sec1.extend_from_slice(&public_key);
    let verifier = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    verifier.verify_prehash(&digest, &signature).unwrap();

    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}
