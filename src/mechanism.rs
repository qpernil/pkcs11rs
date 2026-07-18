#[derive(Debug, Clone, Copy)]
struct MechanismDetails {
    type_: CK_MECHANISM_TYPE,
    min_key_size: CK_ULONG,
    max_key_size: CK_ULONG,
    flags: CK_FLAGS,
}

const MECHANISMS: [MechanismDetails; 5] = [
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

const YUBIHSM_MECHANISMS: [MechanismDetails; 19] = [
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
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_DECRYPT) as CK_FLAGS,
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
        flags: (CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
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
        type_: CKM_AES_GCM as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
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
        max_key_size: 64,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 64,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA384_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 128,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA512_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 128,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
];

fn yubihsm_mechanisms(algorithms: &[u8]) -> Vec<MechanismDetails> {
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
    YUBIHSM_MECHANISMS
        .iter()
        .filter_map(|details| {
            let mut details = *details;
            let sizes: &[CK_ULONG] = match details.type_ {
                y if y == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
                {
                    &rsa_sizes
                }
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
                    || y == CKM_AES_GCM as CK_MECHANISM_TYPE =>
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
                x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
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
        .collect()
}

fn mechanism_details(
    mechanisms: &[MechanismDetails],
    type_: CK_MECHANISM_TYPE,
) -> Result<MechanismDetails, Error> {
    mechanisms
        .iter()
        .copied()
        .find(|mechanism| mechanism.type_ == type_)
        .ok_or(CKR_MECHANISM_INVALID.into())
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(
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

fn get_mechanism_list(
    slotID: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let count = as_mut(count)?;
    with_context_mut(|ctx| {
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

        let list = unsafe { slice::from_raw_parts_mut(mechanism_list, mechanisms.len()) };
        for (slot, mechanism) in list.iter_mut().zip(mechanisms) {
            *slot = mechanism.type_;
        }
        *count = required;
        log!(2, "C_GetMechanismList returning {:?}", list);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
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

fn get_mechanism_info(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: CK_MECHANISM_INFO_PTR,
) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        let mechanisms = ctx.get_present_slot(slotID)?.mechanisms();

        let mechanism = mechanism_details(&mechanisms, type_)?;
        info.ulMinKeySize = mechanism.min_key_size;
        info.ulMaxKeySize = mechanism.max_key_size;
        info.flags = mechanism.flags;
        log!(2, "C_GetMechanismInfo returning {:?}", info);
        Ok(())
    })
}

