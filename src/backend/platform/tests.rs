use super::*;
use crate::pkcs11_auth::{Derivation, Pkcs11Auth};
use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct NativeKey {
    key: SoftwareSigningKey,
    calls: AtomicUsize,
    revoked: AtomicBool,
}
impl EcdhCredential for NativeKey {
    fn public_key(&self) -> Result<SoftwarePublicKey, PlatformCryptoError> {
        Ok(self.key.public_key())
    }
    fn ecdh(&self, peer: &SoftwarePublicKey) -> Result<Zeroizing<Vec<u8>>, PlatformCryptoError> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(PlatformCryptoError::NotFound);
        }
        let SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed,
        } = peer
        else {
            return Err(PlatformCryptoError::InvalidPublicKey);
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        software_key_core::software_key_agreement::derive_with_signing_key(&self.key, uncompressed)
            .map_err(|_| PlatformCryptoError::InvalidPublicKey)
    }
}
fn find(session: &ProviderSession, class: u32) -> Vec<CK_OBJECT_HANDLE> {
    let mut class = class as CK_ULONG;
    let mut label = *b"agreement";
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as _,
            pValue: (&mut class as *mut CK_ULONG).cast(),
            ulValueLen: std::mem::size_of_val(&class) as _,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as _,
            pValue: label.as_mut_ptr().cast(),
            ulValueLen: label.len() as _,
        },
    ];
    session.call(|| {
        assert_eq!(
            api::C_FindObjectsInit(session.handle, template.as_mut_ptr(), template.len() as _),
            CKR_OK as CK_RV
        );
        let mut handles = [0; 8];
        let mut count = 0;
        assert_eq!(
            api::C_FindObjects(
                session.handle,
                handles.as_mut_ptr(),
                handles.len() as _,
                &mut count
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(api::C_FindObjectsFinal(session.handle), CKR_OK as CK_RV);
        handles[..count as usize].to_vec()
    })
}
fn derive(
    session: &ProviderSession,
    private: CK_OBJECT_HANDLE,
    peer: &mut [u8],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL as _,
        pSharedData: std::ptr::null_mut(),
        ulSharedDataLen: 0,
        pPublicData: peer.as_mut_ptr(),
        ulPublicDataLen: peer.len() as _,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE as _,
        pParameter: (&mut params as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
        ulParameterLen: std::mem::size_of_val(&params) as _,
    };
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut no = CK_FALSE as CK_BBOOL;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as _,
            pValue: (&mut yes as *mut CK_BBOOL).cast(),
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as _,
            pValue: (&mut no as *mut CK_BBOOL).cast(),
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            type_: CKA_DERIVE as _,
            pValue: (&mut yes as *mut CK_BBOOL).cast(),
            ulValueLen: 1,
        },
    ];
    let mut result = 0;
    let rv = session.call(|| {
        api::C_DeriveKey(
            session.handle,
            &mut mechanism,
            private,
            template.as_mut_ptr(),
            template.len() as _,
            &mut result,
        )
    });
    if rv == CKR_OK as CK_RV {
        Ok(result)
    } else {
        Err(rv)
    }
}

#[test]
fn platform_slot_public_api_keeps_ecdh_protected_and_owns_session_outputs() {
    let native = Arc::new(NativeKey {
        key: SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap(),
        calls: AtomicUsize::new(0),
        revoked: AtomicBool::new(false),
    });
    let slot = PlatformSlot::with_keys(vec![("agreement".to_owned(), native.clone())]);
    let provider = Pkcs11Provider::new(Box::new(slot)).unwrap();
    let creator = ProviderSession::open(provider.clone()).unwrap();
    let observer = ProviderSession::open(provider).unwrap();
    let private = find(&creator, CKO_PRIVATE_KEY);
    let public = find(&creator, CKO_PUBLIC_KEY);
    assert_eq!(private.len(), 1);
    assert_eq!(public.len(), 1);
    let private = private[0];
    assert_eq!(
        creator.attribute(private, CKA_ID).unwrap(),
        creator.attribute(public[0], CKA_ID).unwrap()
    );
    assert_eq!(
        creator.attribute(private, CKA_PUBLIC_KEY_INFO).unwrap(),
        creator.attribute(public[0], CKA_PUBLIC_KEY_INFO).unwrap()
    );
    assert!(
        matches!(creator.attribute(private, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
    );
    assert_eq!(
        creator.attribute(private, CKA_COPYABLE).unwrap().as_slice(),
        &[CK_FALSE as u8]
    );

    let peer = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
    let SoftwarePublicKey::Ec {
        uncompressed: mut peer_public,
        ..
    } = peer.public_key()
    else {
        unreachable!()
    };
    let SoftwarePublicKey::Ec {
        uncompressed: native_public,
        ..
    } = native.key.public_key()
    else {
        unreachable!()
    };
    let reference =
        software_key_core::software_key_agreement::derive_with_signing_key(&peer, &native_public)
            .unwrap();
    let shared = derive(&creator, private, &mut peer_public).unwrap();
    assert!(
        matches!(observer.attribute(shared, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
    );
    let output = creator
        .derive(
            shared,
            Derivation::Sha256,
            TokenObjectTemplate {
                class: Some(CKO_SECRET_KEY as _),
                key_type: Some(CKK_GENERIC_SECRET as _),
                private: true,
                sensitive: Some(false),
                extractable: Some(true),
                ..Default::default()
            },
            32,
        )
        .unwrap();
    assert_eq!(
        observer.attribute(output, CKA_VALUE).unwrap().as_slice(),
        hash(MessageDigest::Sha256, &reference).unwrap()
    );
    assert_eq!(native.calls.load(Ordering::SeqCst), 1);
    native.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        derive(&creator, private, &mut peer_public),
        Err(CKR_KEY_HANDLE_INVALID as _)
    );
    drop(creator);
    assert!(
        matches!(observer.attribute(shared, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_OBJECT_HANDLE_INVALID as CK_RV)
    );
    assert!(
        matches!(observer.attribute(output, CKA_VALUE), Err(Error::Generic(rv)) if rv == CKR_OBJECT_HANDLE_INVALID as CK_RV)
    );
    assert_eq!(find(&observer, CKO_PRIVATE_KEY), [private]);
}
