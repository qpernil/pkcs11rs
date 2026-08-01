use crate::pkcs11::*;
use crate::{
    as_mut, map, with_slot_context_mut, Error, SlotContext, CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
    CKM_YUBICO_AES_CCM_WRAP, CKM_YUBICO_RSA_WRAP, YUBIHSM_ALGO_AES128,
    YUBIHSM_ALGO_AES128_CCM_WRAP, YUBIHSM_ALGO_AES192, YUBIHSM_ALGO_AES192_CCM_WRAP,
    YUBIHSM_ALGO_AES256, YUBIHSM_ALGO_AES256_CCM_WRAP, YUBIHSM_ALGO_AES_CBC, YUBIHSM_ALGO_AES_ECB,
    YUBIHSM_ALGO_AES_KWP, YUBIHSM_ALGO_EC_BP256, YUBIHSM_ALGO_EC_BP384, YUBIHSM_ALGO_EC_BP512,
    YUBIHSM_ALGO_EC_ECDSA_SHA1, YUBIHSM_ALGO_EC_ECDSA_SHA256, YUBIHSM_ALGO_EC_ECDSA_SHA384,
    YUBIHSM_ALGO_EC_ECDSA_SHA512, YUBIHSM_ALGO_EC_K256, YUBIHSM_ALGO_EC_P224, YUBIHSM_ALGO_EC_P256,
    YUBIHSM_ALGO_EC_P384, YUBIHSM_ALGO_EC_P521, YUBIHSM_ALGO_ED25519, YUBIHSM_ALGO_HMAC_SHA1,
    YUBIHSM_ALGO_HMAC_SHA256, YUBIHSM_ALGO_HMAC_SHA384, YUBIHSM_ALGO_HMAC_SHA512,
    YUBIHSM_ALGO_RSA_2048, YUBIHSM_ALGO_RSA_3072, YUBIHSM_ALGO_RSA_4096,
    YUBIHSM_ALGO_RSA_OAEP_SHA1, YUBIHSM_ALGO_RSA_OAEP_SHA256, YUBIHSM_ALGO_RSA_OAEP_SHA384,
    YUBIHSM_ALGO_RSA_OAEP_SHA512, YUBIHSM_ALGO_RSA_PKCS1_DECRYPT, YUBIHSM_ALGO_RSA_PKCS1_SHA1,
    YUBIHSM_ALGO_RSA_PKCS1_SHA256, YUBIHSM_ALGO_RSA_PKCS1_SHA384, YUBIHSM_ALGO_RSA_PKCS1_SHA512,
    YUBIHSM_ALGO_RSA_PSS_SHA1, YUBIHSM_ALGO_RSA_PSS_SHA256, YUBIHSM_ALGO_RSA_PSS_SHA384,
    YUBIHSM_ALGO_RSA_PSS_SHA512, YUBIHSM_ALGO_X25519,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct MechanismDetails {
    pub(crate) type_: CK_MECHANISM_TYPE,
    pub(crate) min_key_size: CK_ULONG,
    pub(crate) max_key_size: CK_ULONG,
    pub(crate) flags: CK_FLAGS,
}

pub(crate) const MECHANISMS: [MechanismDetails; 5] = [
    MechanismDetails {
        type_: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 1024,
        max_key_size: 4096,
        flags: CKF_GENERATE_KEY_PAIR as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        min_key_size: 1024,
        max_key_size: 4096,
        flags: (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP)
            as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 256,
        max_key_size: 521,
        flags: (CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDSA as CK_MECHANISM_TYPE,
        min_key_size: 256,
        max_key_size: 521,
        flags: (CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 4096,
        flags: CKF_GENERATE as CK_FLAGS,
    },
];

pub(crate) const SOFTWARE_DIGEST_MECHANISMS: [MechanismDetails; 9] = [
    MechanismDetails {
        type_: CKM_SHA_1 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA224 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA256 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA384 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA512 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA3_224 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA3_256 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA3_384 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA3_512 as CK_MECHANISM_TYPE,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DIGEST as CK_FLAGS,
    },
];

pub(crate) fn software_public_mechanisms() -> Vec<MechanismDetails> {
    let mut mechanisms = Vec::new();
    for type_ in [
        CKM_RSA_X_509,
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_OAEP,
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA224_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA3_224_RSA_PKCS,
        CKM_SHA3_256_RSA_PKCS,
        CKM_SHA3_384_RSA_PKCS,
        CKM_SHA3_512_RSA_PKCS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA224_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_SHA3_224_RSA_PKCS_PSS,
        CKM_SHA3_256_RSA_PKCS_PSS,
        CKM_SHA3_384_RSA_PKCS_PSS,
        CKM_SHA3_512_RSA_PKCS_PSS,
    ] {
        let encrypt = matches!(type_, CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP);
        let verify = type_ != CKM_RSA_PKCS_OAEP;
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: ((if verify { CKF_VERIFY } else { 0 }) | if encrypt { CKF_ENCRYPT } else { 0 })
                as CK_FLAGS,
        });
    }
    for type_ in [
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
        CKM_ECDSA_SHA224,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256,
        CKM_ECDSA_SHA3_384,
        CKM_ECDSA_SHA3_512,
    ] {
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 224,
            max_key_size: 521,
            flags: (CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
        });
    }
    mechanisms.push(MechanismDetails {
        type_: CKM_EDDSA as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: CKF_VERIFY as CK_FLAGS,
    });
    mechanisms.push(MechanismDetails {
        type_: CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        min_key_size: 0,
        max_key_size: 0,
        flags: CKF_DERIVE as CK_FLAGS,
    });
    mechanisms
}

pub(crate) fn software_private_mechanisms() -> Vec<MechanismDetails> {
    // C_GetMechanismInfo cannot filter by curve or storage location. These
    // ranges are therefore the envelope of all supported software session
    // private keys; CKA_EC_PARAMS or the selected key handle chooses the exact
    // curve for an operation.
    let mut mechanisms = vec![
        MechanismDetails {
            type_: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            min_key_size: 224,
            max_key_size: 521,
            flags: (CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 255,
            flags: (CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 255,
            flags: (CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 224,
            max_key_size: 521,
            flags: CKF_DERIVE as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 224,
            max_key_size: 521,
            flags: CKF_DERIVE as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_EDDSA as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_SIGN as CK_FLAGS,
        },
    ];
    for type_ in [
        CKM_RSA_X_509,
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_OAEP,
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA224_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA3_224_RSA_PKCS,
        CKM_SHA3_256_RSA_PKCS,
        CKM_SHA3_384_RSA_PKCS,
        CKM_SHA3_512_RSA_PKCS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA224_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_SHA3_224_RSA_PKCS_PSS,
        CKM_SHA3_256_RSA_PKCS_PSS,
        CKM_SHA3_384_RSA_PKCS_PSS,
        CKM_SHA3_512_RSA_PKCS_PSS,
    ] {
        let decrypt = matches!(type_, CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP);
        let sign = type_ != CKM_RSA_PKCS_OAEP;
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: ((if sign { CKF_SIGN } else { 0 }) | if decrypt { CKF_DECRYPT } else { 0 })
                as CK_FLAGS,
        });
    }
    for type_ in [
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
        CKM_ECDSA_SHA224,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256,
        CKM_ECDSA_SHA3_384,
        CKM_ECDSA_SHA3_512,
    ] {
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 224,
            max_key_size: 521,
            flags: (CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
        });
    }
    mechanisms
}

pub(crate) fn software_secret_mechanisms() -> Vec<MechanismDetails> {
    let mut mechanisms = vec![
        MechanismDetails {
            type_: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            min_key_size: 1,
            max_key_size: 1024,
            flags: CKF_GENERATE as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_AES_KEY_GEN as CK_MECHANISM_TYPE,
            min_key_size: 16,
            max_key_size: 32,
            flags: CKF_GENERATE as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_HKDF_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 20,
            max_key_size: 64,
            flags: CKF_DERIVE as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: (CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: (CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
        },
        MechanismDetails {
            type_: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
            min_key_size: 1024,
            max_key_size: 4096,
            flags: (CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
        },
    ];
    for type_ in [
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CTR,
        CKM_AES_CCM,
        CKM_AES_GCM,
        CKM_AES_KEY_WRAP,
        CKM_AES_KEY_WRAP_KWP,
    ] {
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 16,
            max_key_size: 32,
            flags: if matches!(type_, CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP) {
                (CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP) as CK_FLAGS
            } else {
                (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS
            },
        });
    }
    for type_ in [CKM_AES_CMAC, CKM_AES_CMAC_GENERAL, CKM_AES_GMAC] {
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 16,
            max_key_size: 32,
            flags: (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        });
    }
    for type_ in [
        CKM_SHA_1_HMAC,
        CKM_SHA256_HMAC,
        CKM_SHA384_HMAC,
        CKM_SHA512_HMAC,
    ] {
        mechanisms.push(MechanismDetails {
            type_: type_ as CK_MECHANISM_TYPE,
            min_key_size: 1,
            max_key_size: 1024,
            flags: (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        });
    }
    mechanisms
}

pub(crate) const YUBIHSM_MECHANISMS: [MechanismDetails; 30] = [
    MechanismDetails {
        type_: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_YUBICO_RSA_WRAP,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_YUBICO_AES_CCM_WRAP,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_WRAP | CKF_UNWRAP) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDSA as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_DERIVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EDDSA as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_GENERATE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_ECB as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CBC as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CBC_PAD as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CTR as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CCM as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_GCM as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_GMAC as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CMAC as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 20,
        max_key_size: 64,
        flags: (CKF_HW | CKF_GENERATE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA_1_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 512,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 512,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA384_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 1024,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA512_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 1024,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
];

pub(crate) fn yubihsm_mechanisms(algorithms: &[u8]) -> Vec<MechanismDetails> {
    let any = |candidates: &[u8]| candidates.iter().any(|value| algorithms.contains(value));
    let has_rsa = any(&[
        YUBIHSM_ALGO_RSA_2048,
        YUBIHSM_ALGO_RSA_3072,
        YUBIHSM_ALGO_RSA_4096,
    ]);
    let has_ec = any(&[
        YUBIHSM_ALGO_EC_P224,
        YUBIHSM_ALGO_EC_P256,
        YUBIHSM_ALGO_EC_P384,
        YUBIHSM_ALGO_EC_P521,
        YUBIHSM_ALGO_EC_K256,
        YUBIHSM_ALGO_EC_BP256,
        YUBIHSM_ALGO_EC_BP384,
        YUBIHSM_ALGO_EC_BP512,
    ]);
    let has_x25519 = algorithms.contains(&YUBIHSM_ALGO_X25519);
    let has_ed25519 = algorithms.contains(&YUBIHSM_ALGO_ED25519);
    let has_rsa_wrap = has_rsa
        && algorithms.contains(&YUBIHSM_ALGO_AES_KWP)
        && any(&[
            YUBIHSM_ALGO_RSA_OAEP_SHA1,
            YUBIHSM_ALGO_RSA_OAEP_SHA256,
            YUBIHSM_ALGO_RSA_OAEP_SHA384,
            YUBIHSM_ALGO_RSA_OAEP_SHA512,
        ]);
    let rsa_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_RSA_2048 => Some(2048),
            YUBIHSM_ALGO_RSA_3072 => Some(3072),
            YUBIHSM_ALGO_RSA_4096 => Some(4096),
            _ => None,
        })
        .collect();
    let ec_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_EC_P224 => Some(224),
            YUBIHSM_ALGO_EC_P256 | YUBIHSM_ALGO_EC_K256 | YUBIHSM_ALGO_EC_BP256 => Some(256),
            YUBIHSM_ALGO_EC_P384 | YUBIHSM_ALGO_EC_BP384 => Some(384),
            YUBIHSM_ALGO_EC_BP512 => Some(512),
            YUBIHSM_ALGO_EC_P521 => Some(521),
            _ => None,
        })
        .collect();
    let x25519_sizes = [255 as CK_ULONG];
    let ed25519_sizes = [255 as CK_ULONG];
    let mut derive_sizes = ec_sizes.clone();
    if has_x25519 {
        derive_sizes.push(255);
    }
    let aes_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_AES128 => Some(16),
            YUBIHSM_ALGO_AES192 => Some(24),
            YUBIHSM_ALGO_AES256 => Some(32),
            _ => None,
        })
        .collect();
    let ccm_wrap_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_AES128_CCM_WRAP => Some(16),
            YUBIHSM_ALGO_AES192_CCM_WRAP => Some(24),
            YUBIHSM_ALGO_AES256_CCM_WRAP => Some(32),
            _ => None,
        })
        .collect();
    let mut mechanisms: Vec<MechanismDetails> = YUBIHSM_MECHANISMS
        .iter()
        .filter_map(|details| {
            let mut details = *details;
            let sizes: &[CK_ULONG] = match details.type_ {
                y if y == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE
                    || y == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE
                    || y == CKM_YUBICO_RSA_WRAP =>
                {
                    &rsa_sizes
                }
                y if y == CKM_YUBICO_AES_CCM_WRAP => &ccm_wrap_sizes,
                y if y == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_ECDSA as CK_MECHANISM_TYPE =>
                {
                    &ec_sizes
                }
                y if y == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => &x25519_sizes,
                y if y == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_EDDSA as CK_MECHANISM_TYPE =>
                {
                    &ed25519_sizes
                }
                y if y == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE => &derive_sizes,
                y if y == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE
                    || y == CKM_AES_ECB as CK_MECHANISM_TYPE
                    || y == CKM_AES_CBC as CK_MECHANISM_TYPE
                    || y == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE
                    || y == CKM_AES_CTR as CK_MECHANISM_TYPE
                    || y == CKM_AES_CCM as CK_MECHANISM_TYPE
                    || y == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
                    || y == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE
                    || y == CKM_AES_GCM as CK_MECHANISM_TYPE
                    || y == CKM_AES_GMAC as CK_MECHANISM_TYPE
                    || y == CKM_AES_CMAC as CK_MECHANISM_TYPE
                    || y == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE =>
                {
                    &aes_sizes
                }
                _ => &[],
            };
            if let (Some(minimum), Some(maximum)) = (sizes.iter().min(), sizes.iter().max()) {
                details.min_key_size = *minimum;
                details.max_key_size = *maximum;
            }
            let supported = match details.type_ {
                x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_rsa,
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
                    details.flags = (CKF_HW | CKF_ENCRYPT | CKF_VERIFY) as CK_FLAGS;
                    if any(&[
                        YUBIHSM_ALGO_RSA_PKCS1_SHA1,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA256,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA384,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA512,
                    ]) {
                        details.flags |= CKF_SIGN as CK_FLAGS;
                    }
                    if algorithms.contains(&YUBIHSM_ALGO_RSA_PKCS1_DECRYPT) {
                        details.flags |= CKF_DECRYPT as CK_FLAGS;
                    }
                    has_rsa
                }
                x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
                    has_rsa
                        && any(&[
                            YUBIHSM_ALGO_RSA_PSS_SHA1,
                            YUBIHSM_ALGO_RSA_PSS_SHA256,
                            YUBIHSM_ALGO_RSA_PSS_SHA384,
                            YUBIHSM_ALGO_RSA_PSS_SHA512,
                        ])
                }
                x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                    has_rsa
                        && any(&[
                            YUBIHSM_ALGO_RSA_OAEP_SHA1,
                            YUBIHSM_ALGO_RSA_OAEP_SHA256,
                            YUBIHSM_ALGO_RSA_OAEP_SHA384,
                            YUBIHSM_ALGO_RSA_OAEP_SHA512,
                        ])
                }
                x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE || x == CKM_YUBICO_RSA_WRAP => {
                    has_rsa_wrap
                }
                x if x == CKM_YUBICO_AES_CCM_WRAP => !ccm_wrap_sizes.is_empty(),
                x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_ec,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE => {
                    has_ec
                        && any(&[
                            YUBIHSM_ALGO_EC_ECDSA_SHA1,
                            YUBIHSM_ALGO_EC_ECDSA_SHA256,
                            YUBIHSM_ALGO_EC_ECDSA_SHA384,
                            YUBIHSM_ALGO_EC_ECDSA_SHA512,
                        ])
                }
                x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_x25519,
                x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_ed25519,
                x if x == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE => has_ec || has_x25519,
                x if x == CKM_EDDSA as CK_MECHANISM_TYPE => has_ed25519,
                x if x == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE => any(&[
                    YUBIHSM_ALGO_AES128,
                    YUBIHSM_ALGO_AES192,
                    YUBIHSM_ALGO_AES256,
                ]),
                x if x == CKM_AES_ECB as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_CBC)
                }
                x if x == CKM_AES_CBC_PAD as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_CBC)
                }
                x if x == CKM_AES_CTR as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_CCM as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                        && algorithms.contains(&YUBIHSM_ALGO_AES_CBC)
                }
                x if x == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
                    || x == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE =>
                {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_GMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE
                    || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE =>
                {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE => any(&[
                    YUBIHSM_ALGO_HMAC_SHA1,
                    YUBIHSM_ALGO_HMAC_SHA256,
                    YUBIHSM_ALGO_HMAC_SHA384,
                    YUBIHSM_ALGO_HMAC_SHA512,
                ]),
                x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA1)
                }
                x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA256)
                }
                x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA384)
                }
                x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA512)
                }
                _ => false,
            };
            supported.then_some(details)
        })
        .collect();
    for (algorithm, type_) in [
        (YUBIHSM_ALGO_RSA_PKCS1_SHA1, CKM_SHA1_RSA_PKCS),
        (YUBIHSM_ALGO_RSA_PKCS1_SHA256, CKM_SHA256_RSA_PKCS),
        (YUBIHSM_ALGO_RSA_PKCS1_SHA384, CKM_SHA384_RSA_PKCS),
        (YUBIHSM_ALGO_RSA_PKCS1_SHA512, CKM_SHA512_RSA_PKCS),
    ] {
        if let (true, Some(min_key_size), Some(max_key_size)) = (
            has_rsa && algorithms.contains(&algorithm),
            rsa_sizes.iter().min(),
            rsa_sizes.iter().max(),
        ) {
            mechanisms.push(MechanismDetails {
                type_: type_ as CK_MECHANISM_TYPE,
                min_key_size: *min_key_size,
                max_key_size: *max_key_size,
                flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            });
        }
    }
    mechanisms
}

pub(crate) fn mechanism_details(
    mechanisms: &[MechanismDetails],
    type_: CK_MECHANISM_TYPE,
) -> Result<MechanismDetails, Error> {
    mechanisms
        .iter()
        .copied()
        .find(|mechanism| mechanism.type_ == type_)
        .ok_or(CKR_MECHANISM_INVALID.into())
}

pub(crate) fn require_slot_mechanism(
    ctx: &SlotContext,
    slot_id: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    operation: CK_FLAGS,
) -> Result<MechanismDetails, Error> {
    let details = mechanism_details(&ctx.get_slot(slot_id)?.mechanisms(), type_)?;
    if details.flags & operation == 0 {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    Ok(details)
}

ffi_entry_point! {
    pub fn C_GetMechanismList(
        slotID: CK_SLOT_ID,
        mechanism_list: *mut CK_MECHANISM_TYPE,
        count: *mut ::std::os::raw::c_ulong,
    ) -> CK_RV {
        log!(
            2,
            "C_GetMechanismList called with {:?}",
            (slotID, mechanism_list, count)
        );
        map(get_mechanism_list(slotID, mechanism_list, count))
    }
}

pub(crate) fn get_mechanism_list(
    slotID: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let count = unsafe { as_mut(count) }?;
    with_slot_context_mut(slotID, |ctx| {
        let mechanisms = ctx.get_present_slot(slotID)?.mechanisms();

        let required = mechanisms.len() as CK_ULONG;
        if mechanism_list.is_null() {
            *count = required;
            log!(2, "C_GetMechanismList returning {:?}", *count);
            return Ok(());
        }
        if *count < required {
            *count = required;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let list = unsafe { crate::_from_raw_parts_mut(mechanism_list, mechanisms.len()) }?;
        for (slot, mechanism) in list.iter_mut().zip(mechanisms) {
            *slot = mechanism.type_;
        }
        *count = required;
        log!(2, "C_GetMechanismList returning {:?}", list);
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_GetMechanismInfo(
        slotID: CK_SLOT_ID,
        type_: CK_MECHANISM_TYPE,
        info_ptr: *mut CK_MECHANISM_INFO,
    ) -> CK_RV {
        log!(
            2,
            "C_GetMechanismInfo called with {:?}",
            (slotID, type_, info_ptr)
        );
        map(get_mechanism_info(slotID, type_, info_ptr))
    }
}

pub(crate) fn get_mechanism_info(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: CK_MECHANISM_INFO_PTR,
) -> Result<(), Error> {
    let info = unsafe { as_mut(info_ptr) }?;
    with_slot_context_mut(slotID, |ctx| {
        let mechanisms = ctx.get_present_slot(slotID)?.mechanisms();

        let mechanism = mechanism_details(&mechanisms, type_)?;
        info.ulMinKeySize = mechanism.min_key_size;
        info.ulMaxKeySize = mechanism.max_key_size;
        info.flags = mechanism.flags;
        log!(2, "C_GetMechanismInfo returning {:?}", info);
        Ok(())
    })
}
