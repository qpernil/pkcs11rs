use super::*;
use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat};

#[test]
fn password_credentials_share_a_slot_and_release_the_unused_key() {
    let mut credentials = PasswordCredentials::new(b"password").unwrap();
    let provider = Rc::downgrade(&credentials.scope.session.provider);
    let symmetric = credentials.symmetric().unwrap();
    let asymmetric = credentials.asymmetric().unwrap();
    assert!(Rc::ptr_eq(&symmetric.enc.0.session, &asymmetric.0.session));
    assert_eq!(credentials.scope.count_provider_objects(), 3);
    for key in [&credentials.enc, &credentials.mac, &credentials.asymmetric] {
        let object = credentials.scope.snapshot(key);
        assert!(!object.token && object.private && object.sensitive && !object.extractable);
        assert!(credentials.scope.read(key, CKA_VALUE).is_err());
    }
    credentials.scope.require_aes128(&credentials.enc).unwrap();
    let expected = crate::yubico_kdf::yubico_password_p256_key(b"password").unwrap();
    let SoftwarePublicKey::Ec { uncompressed, .. } = expected.public_key() else {
        panic!("expected EC key")
    };
    assert_eq!(
        credentials
            .scope
            .p256_public(&credentials.asymmetric)
            .unwrap(),
        uncompressed
    );

    // Keep an operation session alive to observe cleanup independently of slot
    // destruction. Retaining the AES pair must not also retain the EC key.
    let observer = Pkcs11KeyScope::for_key(&symmetric.enc).unwrap();
    drop(symmetric);
    drop(asymmetric);
    let retained = credentials.retain_symmetric().unwrap();
    drop(credentials);
    assert_eq!(observer.count_provider_objects(), 2);
    drop(retained);
    assert_eq!(observer.count_provider_objects(), 0);
    drop(observer);
    assert!(provider.upgrade().is_none());
}

#[test]
fn password_credentials_without_retention_release_both_keys() {
    let credentials = PasswordCredentials::new(b"password").unwrap();
    let observer = Pkcs11KeyScope::for_key(&credentials.symmetric().unwrap().enc).unwrap();
    assert_eq!(observer.count_provider_objects(), 3);
    drop(credentials);
    assert_eq!(observer.count_provider_objects(), 0);
}

#[test]
fn symmetric_pair_lookup_requires_exact_unique_aes_roles() {
    let scope = Pkcs11KeyScope::new().unwrap();
    let create = |label: &str, key_type, size: usize| {
        let template = TokenObjectTemplate {
            label: label.to_owned(),
            key_type: Some(key_type),
            ..authentication_aes_template()
        };
        scope
            .session
            .create(template, &[(CKA_VALUE, &vec![0x42; size])])
            .unwrap()
    };
    let find = || SymmetricCredential::find(scope.session.clone(), "auth", false);
    create("auth.enc", CKK_AES as _, 16);
    // Neither a prefix match nor an object with the wrong key type completes
    // the credential. A name without both exact roles cannot authenticate.
    create("auth.mac.extra", CKK_AES as _, 16);
    create("auth.mac", CKK_GENERIC_SECRET as _, 16);
    assert!(matches!(find(), Err(Error::Generic(rv)) if rv == CKR_KEY_HANDLE_INVALID as CK_RV));
    let mac = create("auth.mac", CKK_AES as _, 24);
    assert!(matches!(find(), Err(Error::Generic(rv)) if rv == CKR_KEY_SIZE_RANGE as CK_RV));
    scope.session.destroy(mac).unwrap();
    create("auth.mac", CKK_AES as _, 16);
    assert!(find().is_ok());
    assert!(SymmetricCredential::find(scope.session.clone(), "auth", true).is_err());
    create("auth.enc", CKK_AES as _, 16);
    assert!(matches!(find(), Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCONSISTENT as CK_RV));
}

#[test]
fn symmetric_pair_rejects_keys_from_different_providers() {
    let first = PasswordCredentials::new(b"first password").unwrap();
    let second = PasswordCredentials::new(b"second password").unwrap();
    let enc = first.symmetric().unwrap().enc;
    let mac = second.symmetric().unwrap().mac;
    assert!(
        matches!(SymmetricCredential::new(enc, mac), Err(Error::Generic(rv)) if rv == CKR_KEY_HANDLE_INVALID as CK_RV)
    );
}

fn aes(derive: bool) -> TokenObjectTemplate {
    TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as _),
        key_type: Some(CKK_AES as _),
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        derive,
        verify: true,
        allowed_mechanisms: Some(vec![
            CKM_AES_CMAC as _,
            CKM_AES_CMAC_GENERAL as _,
            CKM_SP800_108_COUNTER_KDF as _,
        ]),
        ..Default::default()
    }
}
fn fields() -> [CounterKdfField<'static>; 1] {
    [CounterKdfField::Counter(IntegerFormat {
        width_bits: 8,
        little_endian: false,
    })]
}
#[test]
fn api_key_handles_are_isolated_and_do_not_keep_destroyed_objects_alive() {
    let mut first = Pkcs11KeyScope::new().unwrap();
    let mut second = Pkcs11KeyScope::new().unwrap();
    let handle = first.import_secret(&[1; 16], aes(true)).unwrap();
    second.import_secret(&[2; 16], aes(true)).unwrap();
    assert!(second.read_aes128(&handle).is_err());
    assert!(
        second
            .derive_counter(&handle, &fields(), aes(false), 16)
            .is_err()
    );
    first.destroy(&handle).unwrap();
    assert_eq!(first.count_provider_objects(), 0);
    first.import_secret(&[3; 16], aes(true)).unwrap();
    assert!(
        first
            .derive_counter(&handle, &fields(), aes(false), 16)
            .is_err()
    );
    drop(first);
    assert!(second.read_aes128(&handle).is_err());
}
#[test]
fn api_derivation_preserves_policy_and_validates_before_publishing() {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let base = scope.import_secret(&[0; 16], aes(true)).unwrap();
    let result = scope
        .derive_counter(&base, &fields(), aes(false), 16)
        .unwrap();
    let expected = crate::parse_hex("1f8262956c5c259946a3d370fe969234").unwrap();
    let mac = crate::software_key_ops::software_aes_cmac(&expected, b"proof").unwrap();
    scope.verify_cmac(&result, b"proof", &mac).unwrap();
    scope.verify_cmac(&result, b"proof", &mac[..8]).unwrap();
    assert!(scope.verify_cmac(&result, b"wrong", &mac).is_err());
    assert!(scope.verify_cmac(&result, b"proof", &[]).is_err());
    assert!(
        scope
            .derive_counter(&result, &fields(), aes(false), 16)
            .is_err()
    );
    assert!(scope.derive_counter(&base, &[], aes(false), 16).is_err());
    assert!(
        scope
            .derive_counter(&base, &fields(), aes(false), 17)
            .is_err()
    );
    assert_eq!(scope.count_provider_objects(), 2);
    let snapshot = scope.snapshot(&result);
    assert!(snapshot.sensitive && !snapshot.extractable);
    assert!(!snapshot.always_sensitive && !snapshot.never_extractable);
    assert!(scope.read_aes128(&result).is_err());
    let readable = TokenObjectTemplate {
        sensitive: Some(false),
        extractable: Some(true),
        ..aes(false)
    };
    let result = scope
        .derive_counter(&base, &fields(), readable, 16)
        .unwrap();
    assert_eq!(scope.read_aes128(&result).unwrap().as_slice(), expected);
    assert!(scope.read_aes128(&base).is_err());

    // Nested source policy must reach the shared handlers intact.
    let mut policy = crate::key_metadata::KeyAttributes::new();
    policy
        .insert(
            CKA_SENSITIVE as _,
            crate::key_metadata::KeyAttributeValue::Boolean(true),
        )
        .unwrap();
    let mut restricted = aes(true);
    restricted.policy_templates.derive = Some(policy);
    let restricted = scope.import_secret(&[0; 16], restricted).unwrap();
    scope
        .derive_counter(&restricted, &fields(), aes(false), 16)
        .unwrap();
    let count = scope.count_provider_objects();
    let readable = TokenObjectTemplate {
        sensitive: Some(false),
        extractable: Some(true),
        ..aes(false)
    };
    assert!(
        scope
            .derive_counter(&restricted, &fields(), readable, 16)
            .is_err()
    );
    assert_eq!(scope.count_provider_objects(), count);
}
#[test]
fn api_bound_keys_hold_only_their_object_and_owning_session() {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let base = scope.import_secret(&[0; 16], aes(true)).unwrap();
    let intermediate = scope
        .derive_counter(&base, &fields(), aes(false), 16)
        .unwrap();
    let provider = Rc::downgrade(&scope.session.provider);
    let binding = scope.take_key(&base).unwrap();
    assert!(scope.read_aes128(&base).is_err());
    drop(scope);
    let mut next = Pkcs11KeyScope::for_key(&binding).unwrap();
    let borrowed = next.bind(&binding).unwrap();
    assert!(next.take_key(&borrowed).is_err());
    next.destroy(&borrowed).unwrap();
    assert_eq!(next.count_provider_objects(), 1);
    assert!(next.read_aes128(&intermediate).is_err());
    let base = next.bind(&binding).unwrap();
    let output = next
        .derive_counter(&base, &fields(), aes(false), 16)
        .unwrap();
    next.destroy(&base).unwrap();
    assert_eq!(next.count_provider_objects(), 2);
    drop(binding);
    assert_eq!(next.count_provider_objects(), 1);
    next.destroy(&output).unwrap();
    assert_eq!(next.count_provider_objects(), 0);
    drop(next);
    assert!(provider.upgrade().is_none());
}
#[test]
fn api_composition_keeps_protected_inputs_unreadable() {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let policy = || {
        generic_template(&[
            CKM_EXTRACT_KEY_FROM_KEY as _,
            CKM_SHA256_KEY_DERIVATION as _,
            CKM_CONCATENATE_BASE_AND_KEY as _,
        ])
    };
    let base = scope.import_secret(&[0x42; 32], policy()).unwrap();
    let readable = || TokenObjectTemplate {
        sensitive: Some(false),
        extractable: Some(true),
        ..aes(false)
    };
    assert!(scope.extract(&base, 0, readable(), 16).is_err());
    let block = scope
        .sha256(
            &base,
            TokenObjectTemplate {
                sensitive: Some(false),
                extractable: Some(true),
                ..policy()
            },
        )
        .unwrap();
    let key = scope.extract(&block, 128, readable(), 16).unwrap();
    assert_eq!(
        scope.read_aes128(&key).unwrap().as_slice(),
        &MessageDigest::Sha256.digest(&[0x42; 32])[16..]
    );
    let mut denied = policy();
    denied.derive = false;
    let denied = scope.import_secret(b"x", denied).unwrap();
    assert!(scope.append_key(&base, &denied, policy(), 33).is_err());
    assert!(scope.snapshot(&base).sensitive);
}
#[test]
fn api_ecdh_validates_points_and_tracks_generated_key_history() {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let key = scope.generate_p256().unwrap();
    let public = scope.p256_public(&key).unwrap();
    let shared = scope
        .ecdh(
            &key,
            &public,
            generic_template(&[CKM_EXTRACT_KEY_FROM_KEY as _]),
        )
        .unwrap();
    scope.require_generic_length(&shared, 32).unwrap();
    let snapshot = scope.snapshot(&shared);
    assert!(
        snapshot.sensitive
            && !snapshot.extractable
            && snapshot.always_sensitive
            && snapshot.never_extractable
    );
    assert!(scope.ecdh(&key, &[0; 65], generic_template(&[])).is_err());
    assert_eq!(scope.count_provider_objects(), 2);
}
