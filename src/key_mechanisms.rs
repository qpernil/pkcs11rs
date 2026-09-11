//! Per-key capability projection. Explicit policy remains on the object; this
//! derived view is never persisted or copied back into CKA_ALLOWED_MECHANISMS.
use crate::*;

pub(crate) fn allowed<S: Slot + ?Sized>(slot: &S, key: &TokenObject) -> Vec<CK_MECHANISM_TYPE> {
    let mut result: Vec<_> = slot
        .mechanisms()
        .into_iter()
        .filter(|m| {
            key.allows_mechanism(m.type_)
                && slot.key_mechanism_operations(key, m.type_) & m.flags != 0
        })
        .map(|m| m.type_)
        .collect();
    result.sort_unstable();
    result.dedup();
    result
}

/// Key type, class and usage attributes determine the common operation set.
/// Slots may narrow this for native objects without affecting software objects.
pub(crate) fn operations(key: &TokenObject, m: CK_MECHANISM_TYPE) -> CK_FLAGS {
    let private = key.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let public = key.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let secret = key.class == CKO_SECRET_KEY as CK_OBJECT_CLASS;
    if !private && !public && !secret {
        return 0;
    }
    if m == CKM_PKCS11RS_PROJECT_PUBLIC_KEY {
        return if key.supports_public_projection() {
            CKF_DERIVE as _
        } else {
            0
        };
    }
    match &key.material {
        KeyMaterial::FidoResidentPrivate { .. } if m != CKM_PKCS11RS_FIDO_ASSERTION => return 0,
        KeyMaterial::PreviewSignDerived { .. } if m != CKM_PKCS11RS_PREVIEW_SIGN => return 0,
        _ => {}
    }
    let software_secret = secret && matches!(key.material, KeyMaterial::SoftwareSecret(_));
    let mut usage = 0;
    for (enabled, flag) in [
        (key.sign && (private || secret), CKF_SIGN),
        (key.verify && (public || secret), CKF_VERIFY),
        (key.encrypt && (public || secret), CKF_ENCRYPT),
        (key.decrypt && (private || secret), CKF_DECRYPT),
        (key.can_wrap() && (public || secret || private), CKF_WRAP),
        (key.can_unwrap() && (private || secret), CKF_UNWRAP),
        (key.derive && (private || secret), CKF_DERIVE),
        (key.encapsulate && public, CKF_ENCAPSULATE),
        (key.decapsulate && private, CKF_DECAPSULATE),
    ] {
        if enabled {
            usage |= flag as CK_FLAGS;
        }
    }
    let rsa = key.key_type == CKK_RSA as CK_KEY_TYPE;
    let ec = key.key_type == CKK_EC as CK_KEY_TYPE;
    let aes = key.key_type == CKK_AES as CK_KEY_TYPE;
    let supported = match m {
        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
            if rsa {
                CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP
            } else {
                0
            }
        }
        x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE => {
            if rsa {
                CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT
            } else {
                0
            }
        }
        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
            if rsa {
                CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP
            } else {
                0
            }
        }
        x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE || x == CKM_YUBICO_RSA_WRAP => {
            if rsa {
                CKF_WRAP | CKF_UNWRAP
            } else {
                0
            }
        }
        x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || crate::mechanism::HASHED_RSA_PKCS_MECHANISMS.contains(&x)
            || crate::mechanism::HASHED_RSA_PSS_MECHANISMS.contains(&x) =>
        {
            if rsa {
                CKF_SIGN | CKF_VERIFY
            } else {
                0
            }
        }
        x if x == CKM_ECDSA as CK_MECHANISM_TYPE
            || crate::mechanism::HASHED_ECDSA_MECHANISMS.contains(&x) =>
        {
            if ec {
                CKF_SIGN | CKF_VERIFY
            } else {
                0
            }
        }
        x if x == CKM_EDDSA as CK_MECHANISM_TYPE => {
            if key.key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
                CKF_SIGN | CKF_VERIFY
            } else {
                0
            }
        }
        x if x == CKM_ML_DSA as CK_MECHANISM_TYPE => {
            if key.key_type == CKK_ML_DSA as CK_KEY_TYPE {
                CKF_SIGN | CKF_VERIFY
            } else {
                0
            }
        }
        x if x == CKM_ML_KEM as CK_MECHANISM_TYPE => {
            if key.key_type == CKK_ML_KEM as CK_KEY_TYPE {
                CKF_ENCAPSULATE | CKF_DECAPSULATE
            } else {
                0
            }
        }
        x if x == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE
            || x == CKM_PKCS11RS_PREFIXED_ECDH_DERIVE =>
        {
            if ec || key.key_type == CKK_EC_MONTGOMERY as CK_KEY_TYPE {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE => {
            if ec {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE => {
            if aes {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_HKDF_DERIVE as CK_MECHANISM_TYPE => {
            if software_secret && key.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE
            || x == CKM_CONCATENATE_BASE_AND_DATA as CK_MECHANISM_TYPE
            || x == CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE
            || x == CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE =>
        {
            if software_secret {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
            || x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE =>
        {
            if aes {
                CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP
            } else {
                0
            }
        }
        x if [
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_CCM,
            CKM_AES_GCM,
        ]
        .iter()
        .any(|a| *a as CK_MECHANISM_TYPE == x) =>
        {
            if aes {
                CKF_ENCRYPT | CKF_DECRYPT
            } else {
                0
            }
        }
        x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE
            || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_AES_GMAC as CK_MECHANISM_TYPE =>
        {
            if aes {
                CKF_SIGN | CKF_VERIFY
            } else {
                0
            }
        }
        x if x == CKM_DES3_ECB as CK_MECHANISM_TYPE
            || x == CKM_DES3_CBC as CK_MECHANISM_TYPE
            || x == CKM_DES3_CBC_PAD as CK_MECHANISM_TYPE =>
        {
            if key.key_type == CKK_DES3 as CK_KEY_TYPE {
                CKF_ENCRYPT | CKF_DECRYPT
            } else {
                0
            }
        }
        x if x == CKM_YUBICO_AES_CCM_WRAP => {
            if matches!(
                key.key_type,
                CKK_YUBICO_AES128_CCM_WRAP
                    | CKK_YUBICO_AES192_CCM_WRAP
                    | CKK_YUBICO_AES256_CCM_WRAP
            ) {
                CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP
            } else {
                0
            }
        }
        x if x == CKM_PKCS11RS_PREVIEW_SIGN => {
            if matches!(key.material, KeyMaterial::PreviewSignDerived { .. }) {
                CKF_SIGN
            } else {
                0
            }
        }
        x if x == CKM_PKCS11RS_PREVIEW_SIGN_DERIVE => {
            if key.key_type == CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION {
                CKF_DERIVE
            } else {
                0
            }
        }
        x if x == CKM_PKCS11RS_FIDO_ASSERTION => {
            if matches!(key.material, KeyMaterial::FidoResidentPrivate { .. }) {
                CKF_SIGN
            } else {
                0
            }
        }
        _ => {
            if let Some((kind, _)) = hmac_key_type_and_length(m) {
                if key.key_type == kind || key.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE {
                    CKF_SIGN | CKF_VERIFY
                } else {
                    0
                }
            } else if secret
                && matches!(
                    key.material,
                    KeyMaterial::SoftwareSecret(_) | KeyMaterial::Secret(_)
                )
                && crate::mechanism::SOFTWARE_DIGEST_MECHANISMS
                    .iter()
                    .any(|d| d.type_ == m)
            {
                return CKF_DIGEST as _;
            } else {
                0
            }
        }
    };
    usage & supported as CK_FLAGS
}

pub(crate) fn hmac_key_type_and_length(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<(CK_KEY_TYPE, usize)> {
    match mechanism {
        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA_1_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA_1_HMAC as CK_KEY_TYPE, 20))
        }
        x if x == CKM_SHA224_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA224_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA224_HMAC as CK_KEY_TYPE, 28))
        }
        x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA256_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA256_HMAC as CK_KEY_TYPE, 32))
        }
        x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA384_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA384_HMAC as CK_KEY_TYPE, 48))
        }
        x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA512_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA512_HMAC as CK_KEY_TYPE, 64))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};

    fn decode(bytes: &[u8]) -> Vec<CK_MECHANISM_TYPE> {
        bytes
            .as_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>()
            .0
            .iter()
            .map(|b| CK_MECHANISM_TYPE::from_ne_bytes(*b))
            .collect()
    }

    #[test]
    fn public_attribute_and_find_use_computed_capabilities_without_persisting_them() {
        let session = ProviderSession::open(Pkcs11Provider::private_software().unwrap()).unwrap();
        let key = session
            .create(
                TokenObjectTemplate {
                    class: Some(CKO_SECRET_KEY as _),
                    key_type: Some(CKK_AES as _),
                    sign: true,
                    derive: true,
                    ..Default::default()
                },
                &[(CKA_VALUE, &[0x42; 16])],
            )
            .unwrap();
        let bytes = session.attribute(key, CKA_ALLOWED_MECHANISMS).unwrap();
        let allowed = decode(&bytes);
        assert!(allowed.contains(&(CKM_AES_CMAC as _)));
        assert!(allowed.contains(&(CKM_SP800_108_COUNTER_KDF as _)));
        for denied in [
            CKM_AES_ECB,
            CKM_ECDSA,
            CKM_RSA_PKCS,
            CKM_AES_KEY_GEN,
            CKM_HKDF_DERIVE,
        ] {
            assert!(!allowed.contains(&(denied as _)));
        }
        assert_eq!(
            session.find(&[(CKA_ALLOWED_MECHANISMS, &bytes)]).unwrap(),
            [key]
        );
        let copy = session.copy(key).unwrap();
        session
            .call(|| {
                with_session_context(session.handle, |ctx| {
                    assert!(
                        ctx.resolve_object(key)?
                            .unwrap()
                            .allowed_mechanisms
                            .is_none()
                    );
                    assert!(
                        ctx.resolve_object(copy)?
                            .unwrap()
                            .allowed_mechanisms
                            .is_none()
                    );
                    Ok(())
                })
            })
            .unwrap();
        assert_eq!(
            session.attribute(copy, CKA_ALLOWED_MECHANISMS).unwrap(),
            bytes
        );
        let empty = session
            .create(
                TokenObjectTemplate {
                    class: Some(CKO_SECRET_KEY as _),
                    key_type: Some(CKK_AES as _),
                    sign: true,
                    allowed_mechanisms: Some(vec![]),
                    ..Default::default()
                },
                &[(CKA_VALUE, &[0x42; 16])],
            )
            .unwrap();
        assert!(
            session
                .attribute(empty, CKA_ALLOWED_MECHANISMS)
                .unwrap()
                .is_empty()
        );
        assert!(
            !session
                .can_derive(empty, CKM_SP800_108_COUNTER_KDF as _)
                .unwrap()
        );
    }

    fn native(
        key_type: CK_KEY_TYPE,
        class: CK_OBJECT_CLASS,
        algorithm: u8,
        object_type: u8,
        caps: &[usize],
    ) -> TokenObject {
        let mut key = TokenObjectTemplate {
            class: Some(class),
            key_type: Some(key_type),
            sign: true,
            verify: true,
            encrypt: true,
            decrypt: true,
            derive: true,
            wrap: true,
            unwrap: true,
            ..Default::default()
        }
        .into_object()
        .unwrap();
        key.material = KeyMaterial::YubiHsm {
            id: 42,
            object_type,
            algorithm,
            length: 32,
            domains: 1,
            capabilities: yubihsm_capabilities(caps),
            delegated_capabilities: [0; 8],
            public_key: vec![],
            value: Rc::new(std::cell::RefCell::new(None)),
        };
        key
    }

    #[test]
    fn yubihsm_override_uses_individual_capabilities_and_leaves_software_keys_alone() {
        let (slot, _, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
        let rsa = native(
            CKK_RSA as _,
            CKO_PRIVATE_KEY as _,
            YUBIHSM_ALGO_RSA_2048,
            YUBIHSM_ASYMMETRIC_KEY,
            &[0x05],
        );
        let allowed = slot.allowed_key_mechanisms(&rsa);
        assert!(allowed.contains(&(CKM_RSA_PKCS as _)));
        assert!(allowed.contains(&(CKM_SHA256_RSA_PKCS as _)));
        assert!(!allowed.contains(&(CKM_RSA_PKCS_PSS as _)));
        assert!(!allowed.contains(&(CKM_RSA_PKCS_OAEP as _)));
        assert!(!allowed.contains(&(CKM_RSA_X_509 as _)));
        let mut ec = native(
            CKK_EC as _,
            CKO_PRIVATE_KEY as _,
            YUBIHSM_ALGO_EC_P256,
            YUBIHSM_ASYMMETRIC_KEY,
            &[0x38],
        );
        assert_eq!(
            slot.allowed_key_mechanisms(&ec),
            [CKM_PKCS11RS_PREFIXED_ECDH_DERIVE]
        );
        ec.allowed_mechanisms = Some(vec![CKM_ECDH1_DERIVE as _]);
        assert!(slot.allowed_key_mechanisms(&ec).is_empty());
        let ec = native(
            CKK_EC as _,
            CKO_PRIVATE_KEY as _,
            YUBIHSM_ALGO_EC_P256,
            YUBIHSM_ASYMMETRIC_KEY,
            &[0x0b],
        );
        let allowed = slot.allowed_key_mechanisms(&ec);
        assert!(allowed.contains(&(CKM_ECDH1_DERIVE as _)));
        assert!(allowed.contains(&CKM_PKCS11RS_PREFIXED_ECDH_DERIVE));
        let mut aes = native(
            CKK_AES as _,
            CKO_SECRET_KEY as _,
            YUBIHSM_ALGO_AES128,
            YUBIHSM_SYMMETRIC_KEY,
            &[0x33],
        );
        let allowed = slot.allowed_key_mechanisms(&aes);
        for yes in [
            CKM_AES_ECB,
            CKM_AES_GCM,
            CKM_AES_CMAC,
            CKM_SP800_108_COUNTER_KDF,
        ] {
            assert!(allowed.contains(&(yes as _)));
        }
        for no in [
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CCM,
            CKM_CONCATENATE_BASE_AND_KEY,
        ] {
            assert!(!allowed.contains(&(no as _)));
        }
        aes.material = KeyMaterial::SoftwareSecret(Zeroizing::new(vec![0; 16]));
        let allowed = slot.allowed_key_mechanisms(&aes);
        assert!(allowed.contains(&(CKM_AES_CBC as _)));
        assert!(allowed.contains(&(CKM_CONCATENATE_BASE_AND_KEY as _)));
        for (kind, algorithm) in [
            (
                CKK_YUBICO_HSMAUTH_SYMMETRIC,
                YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            ),
            (
                CKK_YUBICO_HSMAUTH_ASYMMETRIC,
                YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            ),
        ] {
            let auth = native(
                kind,
                CKO_SECRET_KEY as _,
                algorithm,
                YUBIHSM_AUTHENTICATION_KEY,
                &[0x33, 0x0b],
            );
            assert!(slot.allowed_key_mechanisms(&auth).is_empty());
        }
    }
}
