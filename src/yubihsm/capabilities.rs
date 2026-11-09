//! Native permission granularity shared by creation and mechanism reporting.
//! A row lists the capabilities required together for an operation. Different
//! rows are alternatives; a single capability can permit several mechanisms.
use crate::*;

type Requirement = (CK_FLAGS, &'static [usize]);

fn requirements(object_type: u8, mechanism: CK_MECHANISM_TYPE) -> &'static [Requirement] {
    match mechanism {
        x if crate::is_ml_dsa_mechanism(x) => &[(CKF_SIGN as _, &[0x3a])],
        x if x == CKM_ML_KEM as CK_MECHANISM_TYPE => &[(CKF_DECAPSULATE as _, &[0x3c])],
        CKM_PKCS11RS_MLKEM768_P256 | CKM_PKCS11RS_MLKEM768_X25519 | CKM_PKCS11RS_MLKEM1024_P384 => {
            &[(CKF_DECAPSULATE as _, &[0x3e])]
        }
        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
            if object_type == YUBIHSM_PUBLIC_WRAP_KEY {
                &[(CKF_WRAP as _, &[0x0c])]
            } else if object_type == YUBIHSM_WRAP_KEY {
                &[(CKF_UNWRAP as _, &[0x0d])]
            } else {
                &[(CKF_SIGN as _, &[0x05]), (CKF_DECRYPT as _, &[0x09])]
            }
        }
        x if crate::mechanism::HASHED_RSA_PKCS_MECHANISMS.contains(&x) => {
            &[(CKF_SIGN as _, &[0x05])]
        }
        x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || crate::mechanism::HASHED_RSA_PSS_MECHANISMS.contains(&x) =>
        {
            &[(CKF_SIGN as _, &[0x06])]
        }
        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
            if object_type == YUBIHSM_PUBLIC_WRAP_KEY {
                &[(CKF_WRAP as _, &[0x0c])]
            } else if object_type == YUBIHSM_WRAP_KEY {
                &[(CKF_UNWRAP as _, &[0x0d])]
            } else {
                &[(CKF_DECRYPT as _, &[0x0a])]
            }
        }
        x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE || x == CKM_YUBICO_RSA_WRAP => {
            &[(CKF_WRAP as _, &[0x0c]), (CKF_UNWRAP as _, &[0x0d])]
        }
        x if x == CKM_ECDSA as CK_MECHANISM_TYPE
            || crate::mechanism::HASHED_ECDSA_MECHANISMS.contains(&x) =>
        {
            &[(CKF_SIGN as _, &[0x07])]
        }
        x if x == CKM_EDDSA as CK_MECHANISM_TYPE => &[(CKF_SIGN as _, &[0x08])],
        x if x == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE
            || x == CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE =>
        {
            &[(CKF_DERIVE as _, &[0x0b])]
        }
        CKM_PKCS11RS_PREFIXED_ECDH_DERIVE => &[(CKF_DERIVE as _, &[0x38])],
        x if x == CKM_AES_ECB as CK_MECHANISM_TYPE
            || x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
            || x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE =>
        {
            &[(CKF_ENCRYPT as _, &[0x33]), (CKF_DECRYPT as _, &[0x32])]
        }
        x if x == CKM_AES_CBC as CK_MECHANISM_TYPE || x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE => {
            &[(CKF_ENCRYPT as _, &[0x35]), (CKF_DECRYPT as _, &[0x34])]
        }
        x if x == CKM_AES_CTR as CK_MECHANISM_TYPE || x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
            &[((CKF_ENCRYPT | CKF_DECRYPT) as _, &[0x33])]
        }
        x if x == CKM_AES_CCM as CK_MECHANISM_TYPE => {
            &[((CKF_ENCRYPT | CKF_DECRYPT) as _, &[0x33, 0x35])]
        }
        x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE
            || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_AES_GMAC as CK_MECHANISM_TYPE =>
        {
            &[((CKF_SIGN | CKF_VERIFY) as _, &[0x33])]
        }
        x if x == CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE => &[(CKF_DERIVE as _, &[0x33])],
        CKM_YUBICO_AES_CCM_WRAP => &[
            (CKF_WRAP as _, &[0x0c]),
            (CKF_UNWRAP as _, &[0x0d]),
            (CKF_ENCRYPT as _, &[0x25]),
            (CKF_DECRYPT as _, &[0x26]),
        ],
        x if crate::key_mechanisms::hmac_key_type_and_length(x).is_some() => {
            &[(CKF_SIGN as _, &[0x16]), (CKF_VERIFY as _, &[0x17])]
        }
        _ => &[],
    }
}

pub(crate) fn operations(
    object_type: u8,
    capabilities: &[u8; 8],
    mechanism: CK_MECHANISM_TYPE,
) -> CK_FLAGS {
    requirements(object_type, mechanism)
        .iter()
        .fold(0, |flags, (operation, bits)| {
            if bits
                .iter()
                .all(|bit| yubihsm_capability(capabilities, *bit))
            {
                flags | operation
            } else {
                flags
            }
        })
}

/// Check the operation direction as well as the mechanism: e.g. PKCS#1 signing
/// capability must not authorize PKCS#1 decryption on an OAEP-only decrypt key.
pub(crate) fn require_operation(
    key: &TokenObject,
    mechanism: CK_MECHANISM_TYPE,
    operation: CK_FLAGS,
) -> Result<(), Error> {
    if matches!(key.material, KeyMaterial::YubiHsm { .. })
        && crate::backend::yubihsm_key_mechanism_operations(key, mechanism) & operation == 0
    {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    Ok(())
}

/// Translate usage plus an optional mechanism list to hardware permissions.
/// An empty list grants no operations. Exportability is a property of the key,
/// not an operation performed with it, and is kept independently.
pub(crate) fn for_object(
    object: &TokenObject,
    object_type: u8,
    algorithm: u8,
) -> Result<[u8; 8], Error> {
    let attributes = YubiHsmPkcs11Attributes {
        encapsulate: object.encapsulate,
        decapsulate: object.decapsulate,
        encrypt: object.encrypt,
        decrypt: object.decrypt,
        sign: object.sign,
        verify: object.verify,
        derive: object.derive,
        wrap: object.can_wrap(),
        unwrap: object.can_unwrap(),
        extractable: object.extractable,
    };
    let Some(allowed) = &object.allowed_mechanisms else {
        return Ok(yubihsm_attributes_to_capabilities(
            object_type,
            algorithm,
            attributes,
        ));
    };
    // Native private keys also support public projection, independently of
    // their crypto capability bits. An empty list cannot suppress that intrinsic
    // operation without a software restriction, so reject it before creation.
    if allowed.is_empty() && object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let mut capabilities = [0; 8];
    set_yubihsm_capability(
        &mut capabilities,
        0x10,
        object.extractable
            && !matches!(
                object_type,
                YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC | YUBIHSM_PUBLIC_WRAP_KEY
            ),
    );
    for mechanism in allowed {
        let usage = crate::key_mechanisms::operations(object, *mechanism);
        let requirements = requirements(object_type, *mechanism);
        if usage != 0 && requirements.is_empty() {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        for (operation, bits) in requirements {
            if usage & operation != 0 {
                for bit in *bits {
                    set_yubihsm_capability(&mut capabilities, *bit, true);
                }
            }
        }
    }
    Ok(capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(
        class: CK_OBJECT_CLASS,
        key_type: CK_KEY_TYPE,
        usage: CK_FLAGS,
        allowed: Option<Vec<CK_MECHANISM_TYPE>>,
    ) -> TokenObject {
        TokenObjectTemplate {
            class: Some(class),
            key_type: Some(key_type),
            token: true,
            sign: usage & CKF_SIGN as CK_FLAGS != 0,
            verify: usage & CKF_VERIFY as CK_FLAGS != 0,
            encrypt: usage & CKF_ENCRYPT as CK_FLAGS != 0,
            decrypt: usage & CKF_DECRYPT as CK_FLAGS != 0,
            derive: usage & CKF_DERIVE as CK_FLAGS != 0,
            wrap: usage & CKF_WRAP as CK_FLAGS != 0,
            unwrap: usage & CKF_UNWRAP as CK_FLAGS != 0,
            encapsulate: usage & CKF_ENCAPSULATE as CK_FLAGS != 0,
            decapsulate: usage & CKF_DECAPSULATE as CK_FLAGS != 0,
            allowed_mechanisms: allowed,
            ..Default::default()
        }
        .into_object()
        .unwrap()
    }

    #[test]
    fn native_mapping_selects_command_families_and_roundtrips_their_operations() {
        let cases = [
            (
                CKO_PRIVATE_KEY,
                CKK_RSA,
                YUBIHSM_ASYMMETRIC_KEY,
                YUBIHSM_ALGO_RSA_2048,
                CKF_SIGN,
                CKM_SHA256_RSA_PKCS,
                vec![0x05],
                CKM_RSA_PKCS,
                CKM_RSA_PKCS_PSS,
            ),
            (
                CKO_PRIVATE_KEY,
                CKK_RSA,
                YUBIHSM_ASYMMETRIC_KEY,
                YUBIHSM_ALGO_RSA_2048,
                CKF_SIGN,
                CKM_SHA256_RSA_PKCS_PSS,
                vec![0x06],
                CKM_RSA_PKCS_PSS,
                CKM_RSA_PKCS,
            ),
            (
                CKO_PRIVATE_KEY,
                CKK_RSA,
                YUBIHSM_ASYMMETRIC_KEY,
                YUBIHSM_ALGO_RSA_2048,
                CKF_DECRYPT,
                CKM_RSA_PKCS_OAEP,
                vec![0x0a],
                CKM_RSA_PKCS_OAEP,
                CKM_RSA_PKCS,
            ),
            (
                CKO_PRIVATE_KEY,
                CKK_EC,
                YUBIHSM_ASYMMETRIC_KEY,
                YUBIHSM_ALGO_EC_P256,
                CKF_SIGN,
                CKM_ECDSA_SHA256,
                vec![0x07],
                CKM_ECDSA,
                CKM_ECDH1_DERIVE,
            ),
            (
                CKO_PRIVATE_KEY,
                CKK_EC,
                YUBIHSM_ASYMMETRIC_KEY,
                YUBIHSM_ALGO_EC_P256,
                CKF_DERIVE,
                CKM_ECDH1_DERIVE,
                vec![0x0b],
                CKM_ECDH1_COFACTOR_DERIVE,
                CKM_ECDSA,
            ),
            (
                CKO_SECRET_KEY,
                CKK_AES,
                YUBIHSM_SYMMETRIC_KEY,
                YUBIHSM_ALGO_AES128,
                CKF_ENCRYPT,
                CKM_AES_KEY_WRAP,
                vec![0x33],
                CKM_AES_KEY_WRAP_KWP,
                CKM_AES_CBC,
            ),
            (
                CKO_SECRET_KEY,
                CKK_AES,
                YUBIHSM_SYMMETRIC_KEY,
                YUBIHSM_ALGO_AES128,
                CKF_DECRYPT,
                CKM_AES_GCM,
                vec![0x33],
                CKM_AES_CTR,
                CKM_AES_CBC,
            ),
            (
                CKO_SECRET_KEY,
                CKK_AES,
                YUBIHSM_SYMMETRIC_KEY,
                YUBIHSM_ALGO_AES128,
                CKF_DECRYPT,
                CKM_AES_CCM,
                vec![0x33, 0x35],
                CKM_AES_GCM,
                CKM_AES_ECB,
            ),
            (
                CKO_SECRET_KEY,
                CKK_AES,
                YUBIHSM_SYMMETRIC_KEY,
                YUBIHSM_ALGO_AES128,
                CKF_DECRYPT,
                CKM_AES_CBC_PAD,
                vec![0x34],
                CKM_AES_CBC,
                CKM_AES_GCM,
            ),
            (
                CKO_SECRET_KEY,
                CKK_AES,
                YUBIHSM_SYMMETRIC_KEY,
                YUBIHSM_ALGO_AES128,
                CKF_SIGN,
                CKM_AES_CMAC_GENERAL,
                vec![0x33],
                CKM_AES_CMAC,
                CKM_AES_CBC,
            ),
            (
                CKO_SECRET_KEY,
                CKK_SHA256_HMAC,
                YUBIHSM_HMAC_KEY,
                YUBIHSM_ALGO_HMAC_SHA256,
                CKF_SIGN,
                CKM_SHA256_HMAC_GENERAL,
                vec![0x16],
                CKM_SHA256_HMAC,
                CKM_SHA512_HMAC,
            ),
        ];
        for (class, kind, object_type, algorithm, usage, requested, bits, enabled, disabled) in
            cases
        {
            let object = key(
                class as _,
                kind as _,
                usage as _,
                Some(vec![requested as _]),
            );
            let capabilities = for_object(&object, object_type, algorithm).unwrap();
            assert_eq!(
                capabilities,
                yubihsm_capabilities(&bits),
                "mechanism {requested:x}"
            );
            let info = YubiHsmObjectInfo {
                id: 42,
                object_type,
                algorithm,
                capabilities,
                length: 32,
                domains: 1,
                sequence: 1,
                origin: 0,
                label: String::new(),
                delegated_capabilities: [0; 8],
            };
            let restored = yubihsm_token_objects(0, info, None).unwrap().remove(0);
            assert!(require_operation(&restored, enabled as _, usage as _).is_ok());
            assert_eq!(
                CK_RV::from(require_operation(&restored, disabled as _, usage as _).unwrap_err()),
                CKR_MECHANISM_INVALID as CK_RV,
            );
            let effective = |m| {
                crate::key_mechanisms::operations(&restored, m)
                    & operations(object_type, &capabilities, m)
            };
            assert_ne!(
                effective(enabled as _) & usage as CK_FLAGS,
                0,
                "mechanism {requested:x}"
            );
            assert_eq!(
                effective(disabled as _) & usage as CK_FLAGS,
                0,
                "mechanism {requested:x}"
            );
            assert!(
                restored.allowed_mechanisms.is_none(),
                "derived lists need no metadata"
            );
        }
    }

    #[test]
    fn native_mapping_preserves_empty_as_no_operations_and_keeps_exportability_separate() {
        let mut object = key(
            CKO_SECRET_KEY as _,
            CKK_AES as _,
            (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_DERIVE) as _,
            Some(vec![]),
        );
        assert_eq!(
            for_object(&object, YUBIHSM_SYMMETRIC_KEY, YUBIHSM_ALGO_AES128).unwrap(),
            [0; 8]
        );
        object.extractable = true;
        assert_eq!(
            for_object(&object, YUBIHSM_SYMMETRIC_KEY, YUBIHSM_ALGO_AES128).unwrap(),
            yubihsm_capabilities(&[0x10])
        );
        object.allowed_mechanisms = None;
        assert_eq!(
            for_object(&object, YUBIHSM_SYMMETRIC_KEY, YUBIHSM_ALGO_AES128).unwrap(),
            yubihsm_capabilities(&[0x10, 0x32, 0x33, 0x34, 0x35])
        );
        let private = key(
            CKO_PRIVATE_KEY as _,
            CKK_EC as _,
            CKF_SIGN as _,
            Some(vec![]),
        );
        assert_eq!(
            CK_RV::from(
                for_object(&private, YUBIHSM_ASYMMETRIC_KEY, YUBIHSM_ALGO_EC_P256).unwrap_err()
            ),
            CKR_TEMPLATE_INCONSISTENT as CK_RV
        );
    }

    #[test]
    fn native_mapping_extension_permissions_use_their_native_bits() {
        let ec = key(
            CKO_PRIVATE_KEY as _,
            CKK_EC as _,
            CKF_DERIVE as _,
            Some(vec![CKM_PKCS11RS_PREFIXED_ECDH_DERIVE]),
        );
        assert_eq!(
            for_object(&ec, YUBIHSM_ASYMMETRIC_KEY, YUBIHSM_ALGO_EC_P256).unwrap(),
            yubihsm_capabilities(&[0x38])
        );
        let private = key(
            CKO_PRIVATE_KEY as _,
            CKK_ML_KEM as _,
            CKF_DECAPSULATE as _,
            Some(vec![CKM_ML_KEM as _]),
        );
        assert_eq!(
            for_object(&private, YUBIHSM_ASYMMETRIC_KEY, YUBIHSM_ALGO_ML_KEM_768).unwrap(),
            yubihsm_capabilities(&[0x3c])
        );
    }
}
