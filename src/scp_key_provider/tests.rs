use super::*;
use crate::{
    pkcs11_auth::Pkcs11Auth,
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
};

#[test]
fn protected_card_dek_crosses_threads_and_releases_only_its_own_session() {
    let mut keys = Scp03Keys::import(&[1; 16], &[2; 16], Some(&[3; 16])).unwrap();
    let observer = Pkcs11KeyScope::from_session(
        ProviderSession::open(keys.scope.session.provider.clone()).unwrap(),
    );
    let dek_handle = keys.dek.as_ref().unwrap();
    assert!(keys.scope.read_secret(dek_handle, 16).is_err());
    let dek = keys.take_dek().unwrap().unwrap();
    drop(keys);
    assert_eq!(observer.count_provider_objects(), 1);
    let ciphertext = std::thread::spawn(move || {
        assert!(crate::pkcs11_provider::selected_context().is_none());
        assert_eq!(dek.len().unwrap(), 16);
        let result = dek.encrypt(&[0; 32]).unwrap();
        assert!(crate::pkcs11_provider::selected_context().is_none());
        result
    })
    .join()
    .unwrap();
    assert_eq!(
        ciphertext,
        crate::secure_channel_crypto::aes_cbc(
            &[3; 16],
            &[0; 16],
            &[0; 32],
            crate::secure_channel_crypto::Direction::Encrypt
        )
        .unwrap()
    );
    assert_eq!(observer.count_provider_objects(), 0);
}

#[test]
fn card_scp03_uses_existing_source_permissions_and_cleans_up_each_path() {
    for length in [16, 24, 32] {
        for path in 0..3 {
            // A separately authorized ordinary source session already exists.
            let provider =
                Pkcs11Provider::new(Box::new(SoftwareSlot::new("card source".into(), 0))).unwrap();
            let original = ProviderSession::open(provider).unwrap();
            original.login(b"source pin").unwrap();
            let child = original
                .call(|| {
                    with_context(|ctx| {
                        Ok(ctx
                            .slot_contexts
                            .read()
                            .unwrap()
                            .values()
                            .next()
                            .unwrap()
                            .clone())
                    })
                })
                .unwrap();
            let owner = ProviderSession::open(Pkcs11Provider::from_slot(child).unwrap()).unwrap();
            assert!(!owner.authorization_required().unwrap());
            let template = || TokenObjectTemplate {
                derive: path == 0,
                encrypt: path != 0,
                allowed_mechanisms: Some(match path {
                    0 => vec![CKM_SP800_108_COUNTER_KDF as _],
                    1 => vec![CKM_AES_ECB as _, CKM_AES_CBC as _],
                    _ => vec![CKM_AES_ECB as _],
                }),
                ..aes_credential_template()
            };
            let mut handles = Vec::new();
            for value in [vec![1; length], vec![2; length]] {
                handles.push(original.create(template(), &[(CKA_VALUE, &value)]).unwrap());
            }
            let enc = BoundKey::from_session(owner.clone(), handles[0]).unwrap();
            let mac = BoundKey::from_session(owner.clone(), handles[1]).unwrap();
            let mut scope = Pkcs11KeyScope::for_key(&enc).unwrap();
            let observer = Pkcs11KeyScope::for_key(&enc).unwrap();
            let enc = scope.bind(&enc).unwrap();
            let mac = scope.bind(&mac).unwrap();
            let mut keys = Scp03Keys {
                scope,
                enc,
                mac,
                dek: None,
            };
            for (enc, constant) in [(true, 4), (false, 6), (false, 7)] {
                let output = keys.derive(enc, constant, &[0x5a; 16], length).unwrap();
                let expected = crate::secure_channel_crypto::scp03_kdf(
                    &vec![if enc { 1 } else { 2 }; length],
                    constant,
                    &[0x5a; 16],
                    (length * 8) as u16,
                )
                .unwrap();
                assert_eq!(&*output, &expected);
            }
            // A 64-bit card challenge uses the same selected provider path.
            assert_eq!(
                &*keys.derive(true, 2, &[9; 11], 8).unwrap(),
                &crate::secure_channel_crypto::scp03_kdf(&vec![1; length], 2, &[9; 11], 64)
                    .unwrap()
            );
            assert_eq!(observer.count_provider_objects(), 2);
            for handle in &handles {
                assert!(owner.attribute(*handle, CKA_VALUE).is_err());
            }
            // A caller logging out the original slot revokes the prepared view.
            assert_eq!(
                original.call(|| api::C_Logout(original.handle)),
                CKR_OK as CK_RV
            );
            assert!(keys.derive(true, 4, &[0; 16], length).is_err());
            drop(keys);
            drop(observer);
        }
    }
}
