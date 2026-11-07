use super::*;
use std::path::PathBuf;

struct PersistentToken {
    root: PathBuf,
    session: CK_SESSION_HANDLE,
}

impl PersistentToken {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pkcs11rs-persistence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let store =
            crate::SoftwareTokenStore::open("persistence".into(), root.clone(), None).unwrap();
        let public = store
            .init_token(b"test security officer PIN", [b' '; 32])
            .unwrap();
        store
            .init_user_pin(b"test persistence PIN", &public)
            .unwrap();
        let mut fixture = Self { root, session: 0 };
        fixture.restart();
        fixture
    }

    fn restart(&mut self) {
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot = crate::SoftwareSlot::new_with_storage(
            "persistence".into(),
            0,
            Some(self.root.clone()),
            None,
        )
        .unwrap();
        install_test_slot_with_backend(TEST_SLOT_ID, Box::new(slot));
        assert_eq!(
            crate::api::C_OpenSession(
                TEST_SLOT_ID,
                (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
                std::ptr::null_mut(),
                None,
                &mut self.session,
            ),
            CKR_OK as CK_RV
        );
        let mut pin = *b"test persistence PIN";
        assert_eq!(
            crate::api::C_Login(
                self.session,
                CKU_USER as _,
                pin.as_mut_ptr(),
                pin.len() as _
            ),
            CKR_OK as CK_RV
        );
    }

    fn find(&self, class: CK_OBJECT_CLASS, key_type: CK_KEY_TYPE) -> Vec<CK_OBJECT_HANDLE> {
        let mut class = class;
        let mut key_type = key_type;
        let mut token = CK_TRUE as CK_BBOOL;
        let mut template = [
            scalar_attribute(CKA_CLASS as _, &mut class),
            scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
            scalar_attribute(CKA_TOKEN as _, &mut token),
        ];
        self.find_template(&mut template)
    }

    fn find_template(&self, template: &mut [CK_ATTRIBUTE]) -> Vec<CK_OBJECT_HANDLE> {
        assert_eq!(
            crate::api::C_FindObjectsInit(self.session, template.as_mut_ptr(), template.len() as _),
            CKR_OK as CK_RV
        );
        let mut objects = [0; 8];
        let mut count = 0;
        assert_eq!(
            crate::api::C_FindObjects(
                self.session,
                objects.as_mut_ptr(),
                objects.len() as _,
                &mut count
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_FindObjectsFinal(self.session),
            CKR_OK as CK_RV
        );
        objects[..count as usize].to_vec()
    }
}

#[test]
fn persistent_data_identity_survives_update_copy_and_restart() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut token = PersistentToken::new();
    let mut ids = Vec::new();
    for mut private in [CK_FALSE as CK_BBOOL, CK_TRUE as CK_BBOOL] {
        let mut class = CKO_DATA as CK_OBJECT_CLASS;
        let mut enabled = CK_TRUE as CK_BBOOL;
        let mut value = *b"original";
        let mut template = [
            scalar_attribute(CKA_CLASS as _, &mut class),
            scalar_attribute(CKA_TOKEN as _, &mut enabled),
            scalar_attribute(CKA_PRIVATE as _, &mut private),
            bytes_attribute(CKA_VALUE as _, &mut value),
        ];
        let mut original = 0;
        assert_eq!(
            crate::api::C_CreateObject(
                token.session,
                template.as_mut_ptr(),
                template.len() as _,
                &mut original
            ),
            CKR_OK as CK_RV
        );
        let original_id = read_bytes_attribute(token.session, original, CKA_UNIQUE_ID as _);
        let mut copy = 0;
        assert_eq!(
            crate::api::C_CopyObject(token.session, original, std::ptr::null_mut(), 0, &mut copy),
            CKR_OK as CK_RV
        );
        assert_ne!(
            read_bytes_attribute(token.session, copy, CKA_UNIQUE_ID as _),
            original_id
        );
        let mut updated = *b"updated";
        let mut attribute = bytes_attribute(CKA_VALUE as _, &mut updated);
        assert_eq!(
            crate::api::C_SetAttributeValue(token.session, original, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            read_bytes_attribute(token.session, original, CKA_UNIQUE_ID as _),
            original_id
        );
        assert_eq!(
            crate::api::C_DestroyObject(token.session, copy),
            CKR_OK as CK_RV
        );
        ids.push(original_id);
    }
    token.restart();
    for mut id in ids {
        let mut template = [bytes_attribute(CKA_UNIQUE_ID as _, &mut id)];
        let keys = token.find_template(&mut template);
        assert_eq!(keys.len(), 1);
        assert_eq!(
            read_bytes_attribute(token.session, keys[0], CKA_VALUE as _),
            b"updated"
        );
    }
}

impl Drop for PersistentToken {
    fn drop(&mut self) {
        finalize_for_test();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn persistent_key_copies_have_independent_stable_identities() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut token = PersistentToken::new();
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut bits = 1024 as CK_ULONG;
    let mut id = *b"stable-identity";
    let mut public_template = [
        scalar_attribute(CKA_MODULUS_BITS as _, &mut bits),
        bytes_attribute(CKA_ID as _, &mut id),
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
    ];
    let mut private_template = [
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
        bytes_attribute(CKA_ID as _, &mut id),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let (mut public, mut private) = (0, 0);
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            token.session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as _,
            private_template.as_mut_ptr(),
            private_template.len() as _,
            &mut public,
            &mut private
        ),
        CKR_OK as CK_RV
    );
    let mut identities = Vec::new();
    for (original, class) in [(public, CKO_PUBLIC_KEY), (private, CKO_PRIVATE_KEY)] {
        let original_id = read_bytes_attribute(token.session, original, CKA_UNIQUE_ID as _);
        let mut copy = 0;
        assert_eq!(
            crate::api::C_CopyObject(token.session, original, std::ptr::null_mut(), 0, &mut copy),
            CKR_OK as CK_RV
        );
        assert_ne!(original, copy);
        let copy_id = read_bytes_attribute(token.session, copy, CKA_UNIQUE_ID as _);
        assert_ne!(original_id, copy_id);
        // Matching attributes must not merge objects or invalidate either handle.
        for label in [b"different".as_slice(), b"".as_slice()] {
            let mut label = label.to_vec();
            let mut attribute = bytes_attribute(CKA_LABEL as _, &mut label);
            assert_eq!(
                crate::api::C_SetAttributeValue(token.session, copy, &mut attribute, 1),
                CKR_OK as CK_RV
            );
            assert_eq!(
                read_bytes_attribute(token.session, original, CKA_UNIQUE_ID as _),
                original_id
            );
            assert_eq!(
                read_bytes_attribute(token.session, copy, CKA_UNIQUE_ID as _),
                copy_id
            );
        }
        identities.push((class, original_id, copy_id));
    }
    token.restart();
    for (class, original_id, copy_id) in &identities {
        let keys = token
            .find(*class as _, CKK_RSA as _)
            .into_iter()
            .filter(|key| read_bytes_attribute(token.session, *key, CKA_ID as _) == id)
            .collect::<Vec<_>>();
        assert_eq!(
            keys.len(),
            2,
            "class={class}, identities={:?}",
            keys.iter()
                .map(|key| (
                    read_bytes_attribute(token.session, *key, CKA_UNIQUE_ID as _),
                    read_bytes_attribute(token.session, *key, CKA_LABEL as _)
                ))
                .collect::<Vec<_>>()
        );
        let original = keys
            .iter()
            .copied()
            .find(|key| {
                read_bytes_attribute(token.session, *key, CKA_UNIQUE_ID as _) == *original_id
            })
            .unwrap();
        let copy = keys
            .iter()
            .copied()
            .find(|key| read_bytes_attribute(token.session, *key, CKA_UNIQUE_ID as _) == *copy_id)
            .unwrap();
        assert_eq!(
            crate::api::C_DestroyObject(token.session, copy),
            CKR_OK as CK_RV
        );
        assert_eq!(
            read_bytes_attribute(token.session, original, CKA_UNIQUE_ID as _),
            *original_id
        );
    }
    token.restart();
    for (class, original_id, _) in identities {
        let keys = token
            .find(class as _, CKK_RSA as _)
            .into_iter()
            .filter(|key| read_bytes_attribute(token.session, *key, CKA_ID as _) == id)
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            read_bytes_attribute(token.session, keys[0], CKA_UNIQUE_ID as _),
            original_id
        );
    }
}

#[test]
fn persistent_rsa_wrapping_permissions_survive_publication_and_restart() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut token = PersistentToken::new();
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut disabled = CK_FALSE as CK_BBOOL;
    let mut bits = 1024 as CK_ULONG;
    let mut public_template = [
        scalar_attribute(CKA_MODULUS_BITS as _, &mut bits),
        scalar_attribute(CKA_WRAP as _, &mut enabled),
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
    ];
    let mut private_id = *b"persisted unwrap";
    let mut private_template = [
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
        scalar_attribute(CKA_UNWRAP as _, &mut enabled),
        bytes_attribute(CKA_ID as _, &mut private_id),
    ];
    let mut generation = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public = 0;
    let mut private = 0;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            token.session,
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
    assert_eq!(
        read_bytes_attribute(token.session, private, CKA_UNWRAP as _),
        [CK_TRUE as u8]
    );
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_AES as CK_KEY_TYPE;
    let mut value = [0x42; 16];
    let mut template = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        bytes_attribute(CKA_VALUE as _, &mut value),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut enabled),
        scalar_attribute(CKA_SENSITIVE as _, &mut disabled),
    ];
    let mut target = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            token.session,
            template.as_mut_ptr(),
            template.len() as _,
            &mut target
        ),
        CKR_OK as CK_RV
    );
    let mut wrapping = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped = [0; 128];
    let mut length = wrapped.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            token.session,
            &mut wrapping,
            public,
            target,
            wrapped.as_mut_ptr(),
            &mut length
        ),
        CKR_OK as CK_RV
    );
    let mut label = *b"renamed RSA";
    let mut change = [bytes_attribute(CKA_LABEL as _, &mut label)];
    assert_eq!(
        crate::api::C_SetAttributeValue(token.session, private, change.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    token.restart();
    let publics = token.find(CKO_PUBLIC_KEY as _, CKK_RSA as _);
    let public = publics
        .into_iter()
        .find(|key| read_bytes_attribute(token.session, *key, CKA_WRAP as _) == [CK_TRUE as u8])
        .unwrap();
    assert_eq!(
        crate::api::C_CreateObject(
            token.session,
            template.as_mut_ptr(),
            template.len() as _,
            &mut target
        ),
        CKR_OK as CK_RV
    );
    length = wrapped.len() as _;
    assert_eq!(
        crate::api::C_WrapKey(
            token.session,
            &mut wrapping,
            public,
            target,
            wrapped.as_mut_ptr(),
            &mut length
        ),
        CKR_OK as CK_RV
    );
    let keys: Vec<_> = token
        .find(CKO_PRIVATE_KEY as _, CKK_RSA as _)
        .into_iter()
        .filter(|key| read_bytes_attribute(token.session, *key, CKA_ID as _) == private_id)
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        read_bytes_attribute(token.session, keys[0], CKA_LABEL as _),
        label
    );
    assert_eq!(
        read_bytes_attribute(token.session, keys[0], CKA_UNWRAP as _),
        [CK_TRUE as u8]
    );
    let mut template = [
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut enabled),
        scalar_attribute(CKA_SENSITIVE as _, &mut disabled),
    ];
    let mut unwrapped = 0;
    assert_eq!(
        crate::api::C_UnwrapKey(
            token.session,
            &mut wrapping,
            keys[0],
            wrapped.as_mut_ptr(),
            length,
            template.as_mut_ptr(),
            template.len() as _,
            &mut unwrapped
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        read_bytes_attribute(token.session, unwrapped, CKA_VALUE as _),
        value
    );
}

fn des3_encrypt(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> [u8; 8] {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_DES3_ECB as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_EncryptInit(session, &mut mechanism, key),
        CKR_OK as CK_RV
    );
    let mut input = *b"persist!";
    let mut output = [0; 8];
    let mut length = output.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_Encrypt(
            session,
            input.as_mut_ptr(),
            input.len() as _,
            output.as_mut_ptr(),
            &mut length
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(length, 8);
    output
}

#[test]
fn persistent_des3_import_and_generation_survive_restart() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut token = PersistentToken::new();
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_DES3 as CK_KEY_TYPE;
    let mut imported_id = [1];
    let mut generated_id = [2];
    let mut value = std::array::from_fn::<_, 24, _>(|i| i as u8 + 1);
    let mut template = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        bytes_attribute(CKA_VALUE as _, &mut value),
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
        scalar_attribute(CKA_PRIVATE as _, &mut enabled),
        scalar_attribute(CKA_ENCRYPT as _, &mut enabled),
        bytes_attribute(CKA_ID as _, &mut imported_id),
    ];
    let mut imported = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            token.session,
            template.as_mut_ptr(),
            template.len() as _,
            &mut imported
        ),
        CKR_OK as CK_RV
    );
    let mut template = [
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
        scalar_attribute(CKA_PRIVATE as _, &mut enabled),
        scalar_attribute(CKA_ENCRYPT as _, &mut enabled),
        bytes_attribute(CKA_ID as _, &mut generated_id),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_DES3_KEY_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut generated = 0;
    assert_eq!(
        crate::api::C_GenerateKey(
            token.session,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as _,
            &mut generated
        ),
        CKR_OK as CK_RV
    );
    let expected = [
        (vec![1], des3_encrypt(token.session, imported)),
        (vec![2], des3_encrypt(token.session, generated)),
    ];
    token.restart();
    let keys = token.find(CKO_SECRET_KEY as _, CKK_DES3 as _);
    assert_eq!(keys.len(), 2);
    for key in keys {
        let id = read_bytes_attribute(token.session, key, CKA_ID as _);
        let ciphertext = expected
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .unwrap()
            .1;
        assert_eq!(des3_encrypt(token.session, key), ciphertext);
    }
}

#[test]
fn persistent_secret_updates_preserve_policy_and_survive_restart() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut token = PersistentToken::new();
    let mut enabled = CK_TRUE as CK_BBOOL;
    let mut disabled = CK_FALSE as CK_BBOOL;
    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_AES as CK_KEY_TYPE;
    let mut value = [0x42; 16];
    let mut template = [
        scalar_attribute(CKA_CLASS as _, &mut class),
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        bytes_attribute(CKA_VALUE as _, &mut value),
        scalar_attribute(CKA_TOKEN as _, &mut enabled),
        scalar_attribute(CKA_PRIVATE as _, &mut enabled),
        scalar_attribute(CKA_SENSITIVE as _, &mut disabled),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut enabled),
    ];
    let mut key = 0;
    assert_eq!(
        crate::api::C_CreateObject(
            token.session,
            template.as_mut_ptr(),
            template.len() as _,
            &mut key
        ),
        CKR_OK as CK_RV
    );
    let unique_id = read_bytes_attribute(token.session, key, CKA_UNIQUE_ID as _);
    let mut label = *b"restricted AES";
    let mut change = [
        bytes_attribute(CKA_LABEL as _, &mut label),
        scalar_attribute(CKA_SENSITIVE as _, &mut enabled),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut disabled),
    ];
    assert_eq!(
        crate::api::C_SetAttributeValue(token.session, key, change.as_mut_ptr(), change.len() as _),
        CKR_OK as CK_RV
    );
    let mut rejected_label = *b"must not persist";
    let mut change = [
        bytes_attribute(CKA_LABEL as _, &mut rejected_label),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut enabled),
    ];
    assert_eq!(
        crate::api::C_SetAttributeValue(token.session, key, change.as_mut_ptr(), change.len() as _),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );
    assert_eq!(
        read_bytes_attribute(token.session, key, CKA_LABEL as _),
        label
    );
    assert_eq!(
        read_bytes_attribute(token.session, key, CKA_UNIQUE_ID as _),
        unique_id
    );
    token.restart();
    let keys = token.find(CKO_SECRET_KEY as _, CKK_AES as _);
    assert_eq!(keys.len(), 1);
    let key = keys[0];
    assert_eq!(
        read_bytes_attribute(token.session, key, CKA_UNIQUE_ID as _),
        unique_id
    );
    assert_eq!(
        read_bytes_attribute(token.session, key, CKA_LABEL as _),
        label
    );
    for (attribute, expected) in [
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_FALSE),
        (CKA_ALWAYS_SENSITIVE, CK_FALSE),
        (CKA_NEVER_EXTRACTABLE, CK_FALSE),
    ] {
        assert_eq!(
            read_bytes_attribute(token.session, key, attribute as _),
            [expected as u8]
        );
    }
    let mut output = [0; 16];
    let mut read = [bytes_attribute(CKA_VALUE as _, &mut output)];
    assert_eq!(
        crate::api::C_GetAttributeValue(token.session, key, read.as_mut_ptr(), 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
}
