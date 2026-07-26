use super::*;
use crate::{KeyMaterial, TokenObject};

struct YubiHsmWrapTestObject<'a> {
    id: u16,
    object_type: u8,
    algorithm: u8,
    capabilities: &'a [usize],
    delegated_capabilities: &'a [usize],
    label: &'a str,
    public_key: Option<crate::YubiHsmPublicKey>,
}

fn yubihsm_wrap_test_object(
    slot_id: CK_SLOT_ID,
    definition: YubiHsmWrapTestObject<'_>,
) -> Vec<TokenObject> {
    crate::yubihsm_token_objects(
        slot_id,
        crate::YubiHsmObjectInfo {
            capabilities: crate::yubihsm_capabilities(definition.capabilities),
            id: definition.id,
            length: match definition.algorithm {
                crate::YUBIHSM_ALGO_AES128 | crate::YUBIHSM_ALGO_AES128_CCM_WRAP => 16,
                _ => 256,
            },
            domains: 0xffff,
            object_type: definition.object_type,
            algorithm: definition.algorithm,
            sequence: 1,
            origin: 1,
            label: definition.label.to_owned(),
            delegated_capabilities: crate::yubihsm_capabilities(definition.delegated_capabilities),
        },
        definition.public_key,
    )
    .unwrap()
}

fn install_yubihsm_wrap_test_objects(
    session: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
) -> (
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) {
    let public_key = crate::YubiHsmPublicKey {
        algorithm: crate::YUBIHSM_ALGO_RSA_2048,
        key: vec![0xa5; 256],
    };
    let public_wrap_parameters = crate::yubihsm::DelegatedObjectParameters {
        object: crate::YubiHsmObjectParameters {
            id: 33,
            label: "RSA public wrap",
            domains: 0xffff,
            capabilities: [0; 8],
            algorithm: crate::YUBIHSM_ALGO_RSA_2048,
        },
        delegated_capabilities: [0; 8],
    };
    let public_wrap_command = crate::YubiHsmCommand::put_delegated_object(
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        &public_wrap_parameters,
        &public_key.key,
    )
    .unwrap();
    crate::with_session_context_mut(session, |ctx| {
        ctx._get_session(session)?
            .1
            .yubihsm_command(&public_wrap_command)
            .map(|_| ())
    })
    .unwrap();

    let definitions = [
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 30,
                object_type: crate::YUBIHSM_SYMMETRIC_KEY,
                algorithm: crate::YUBIHSM_ALGO_AES128,
                capabilities: &[0x10, 0x32, 0x33],
                delegated_capabilities: &[],
                label: "exportable AES",
                public_key: None,
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 31,
                object_type: crate::YUBIHSM_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_AES128_CCM_WRAP,
                capabilities: &[],
                delegated_capabilities: &[],
                label: "AES-CCM wrap",
                public_key: None,
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 32,
                object_type: crate::YUBIHSM_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_RSA_2048,
                capabilities: &[0x10],
                delegated_capabilities: &[],
                label: "RSA wrap",
                public_key: Some(public_key.clone()),
            },
        ),
        yubihsm_wrap_test_object(
            slot_id,
            YubiHsmWrapTestObject {
                id: 33,
                object_type: crate::YUBIHSM_PUBLIC_WRAP_KEY,
                algorithm: crate::YUBIHSM_ALGO_RSA_2048,
                capabilities: &[],
                delegated_capabilities: &[],
                label: "RSA public wrap",
                public_key: Some(public_key),
            },
        ),
    ];
    let mut target = None;
    let mut ccm = None;
    let mut rsa_private = None;
    let mut rsa_synthetic_public = None;
    let mut rsa_public_wrap = None;
    with_test_slot_context(slot_id, |context| {
        for objects in definitions {
            for object in objects {
                let (id, material_type) = match object.material {
                    KeyMaterial::YubiHsm {
                        id, object_type, ..
                    } => (id, object_type),
                    _ => unreachable!(),
                };
                let handle = context.insert_object(object);
                match (id, material_type) {
                    (30, crate::YUBIHSM_SYMMETRIC_KEY) => target = Some(handle),
                    (31, crate::YUBIHSM_WRAP_KEY) => ccm = Some(handle),
                    (32, crate::YUBIHSM_WRAP_KEY) => rsa_private = Some(handle),
                    (32, crate::YUBIHSM_WRAP_KEY_PUBLIC) => rsa_synthetic_public = Some(handle),
                    (33, crate::YUBIHSM_PUBLIC_WRAP_KEY) => rsa_public_wrap = Some(handle),
                    _ => {}
                }
            }
        }
    });
    (
        target.unwrap(),
        ccm.unwrap(),
        rsa_private.unwrap(),
        rsa_synthetic_public.unwrap(),
        rsa_public_wrap.unwrap(),
    )
}

fn install_yubihsm_wrap_targets(slot_id: CK_SLOT_ID) -> Vec<(CK_OBJECT_HANDLE, u8, u16)> {
    let definitions = [
        (
            34,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_DATA,
            "exportable opaque",
            true,
            false,
        ),
        (
            35,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            "exportable certificate",
            true,
            false,
        ),
        (
            36,
            crate::YUBIHSM_TEMPLATE,
            crate::YUBIHSM_ALGO_TEMPLATE_SSH,
            "exportable template",
            true,
            false,
        ),
        (
            37,
            crate::YUBIHSM_OPAQUE,
            crate::YUBIHSM_ALGO_OPAQUE_DATA,
            "non-exportable opaque",
            false,
            false,
        ),
        (
            38,
            crate::YUBIHSM_AUTHENTICATION_KEY,
            crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            "delegating authentication key",
            true,
            true,
        ),
    ];
    with_test_slot_context(slot_id, |context| {
        definitions
            .into_iter()
            .map(
                |(id, object_type, algorithm, label, extractable, has_delegated_capabilities)| {
                    let [object] = yubihsm_wrap_test_object(
                        slot_id,
                        YubiHsmWrapTestObject {
                            id,
                            object_type,
                            algorithm,
                            capabilities: if extractable { &[0x10] } else { &[] },
                            delegated_capabilities: if has_delegated_capabilities {
                                &[0x04]
                            } else {
                                &[]
                            },
                            label,
                            public_key: None,
                        },
                    )
                    .try_into()
                    .unwrap();
                    assert_eq!(object.extractable, extractable);
                    if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                        || object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                    {
                        assert_eq!(
                            object.attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE),
                            Some(crate::bool_attribute(extractable))
                        );
                    } else {
                        assert!(object
                            .attribute_value(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)
                            .is_none());
                    }
                    (context.insert_object(object), object_type, id)
                },
            )
            .collect()
    })
}

#[test]
fn yubihsm_rsa_wrap_generation_uses_pkcs11_template_roles() {
    let mut modulus_bits = 2048 as CK_ULONG;
    let mut wrap = CK_FALSE as CK_BBOOL;
    let mut unwrap = CK_TRUE as CK_BBOOL;
    let public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
    ];
    let private = [scalar_attribute(
        CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
        &mut unwrap,
    )];
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let (_, _, command) =
        crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap();
    assert_eq!(command.code(), crate::YubiHsmCommandCode::GenerateWrapKey);

    let mut unsupported_wrap = CK_TRUE as CK_BBOOL;
    let unsupported_public = [
        scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut unsupported_wrap),
    ];
    assert_eq!(
        CK_RV::from(
            crate::yubihsm_generate_key_pair_command(&mechanism, &unsupported_public, &private)
                .unwrap_err()
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
    let mut private_wrap = CK_TRUE as CK_BBOOL;
    let private = [
        scalar_attribute(CKA_UNWRAP as CK_ATTRIBUTE_TYPE, &mut unwrap),
        scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut private_wrap),
    ];
    assert_eq!(
        CK_RV::from(
            crate::yubihsm_generate_key_pair_command(&mechanism, &public, &private).unwrap_err()
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );
}

fn rsa_wrap_mechanism(
    full_object: bool,
) -> (
    CK_MECHANISM,
    CK_RSA_AES_KEY_WRAP_PARAMS,
    CK_RSA_PKCS_OAEP_PARAMS,
) {
    let oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };
    let parameters = CK_RSA_AES_KEY_WRAP_PARAMS {
        ulAESKeyBits: 256,
        pOAEPParams: std::ptr::null_mut(),
    };
    let mechanism = CK_MECHANISM {
        mechanism: if full_object {
            crate::CKM_YUBICO_RSA_WRAP
        } else {
            CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE
        },
        pParameter: std::ptr::null_mut(),
        ulParameterLen: std::mem::size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>() as CK_ULONG,
    };
    (mechanism, parameters, oaep)
}

fn initialize_rsa_wrap_mechanism(
    mechanism: &mut CK_MECHANISM,
    parameters: &mut CK_RSA_AES_KEY_WRAP_PARAMS,
    oaep: &mut CK_RSA_PKCS_OAEP_PARAMS,
) {
    parameters.pOAEPParams = oaep;
    mechanism.pParameter = (parameters as *mut CK_RSA_AES_KEY_WRAP_PARAMS).cast();
}

fn checked_rv(operation: &str, rv: CK_RV) -> Result<(), String> {
    if rv == CKR_OK as CK_RV {
        Ok(())
    } else {
        Err(format!("{operation} failed with CK_RV 0x{rv:08x}"))
    }
}

fn checked_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, String> {
    let mut attribute = CK_ATTRIBUTE {
        type_: attribute_type,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    checked_rv(
        "C_GetAttributeValue length query",
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
    )?;
    let mut value = vec![0; attribute.ulValueLen as usize];
    attribute.pValue = value.as_mut_ptr().cast();
    checked_rv(
        "C_GetAttributeValue",
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
    )?;
    Ok(value)
}

fn checked_bool_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<bool, String> {
    let value = checked_attribute(session, object, attribute_type)?;
    match value.as_slice() {
        [value] if *value == CK_TRUE as CK_BBOOL => Ok(true),
        [value] if *value == CK_FALSE as CK_BBOOL => Ok(false),
        _ => Err(format!(
            "attribute 0x{attribute_type:08x} was not a CK_BBOOL"
        )),
    }
}

fn checked_ulong_attribute(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<CK_ULONG, String> {
    let value = checked_attribute(session, object, attribute_type)?;
    let value: [u8; std::mem::size_of::<CK_ULONG>()] = value
        .try_into()
        .map_err(|_| format!("attribute 0x{attribute_type:08x} was not a CK_ULONG"))?;
    Ok(CK_ULONG::from_ne_bytes(value))
}

fn provision_rsa_public_wrap_key(
    session: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    generated_public: CK_OBJECT_HANDLE,
) -> Result<CK_OBJECT_HANDLE, String> {
    let modulus = checked_attribute(session, generated_public, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
    let algorithm = match modulus.len() {
        256 => crate::YUBIHSM_ALGO_RSA_2048,
        384 => crate::YUBIHSM_ALGO_RSA_3072,
        512 => crate::YUBIHSM_ALGO_RSA_4096,
        length => return Err(format!("unsupported RSA public modulus length {length}")),
    };
    let parameters = crate::yubihsm::DelegatedObjectParameters {
        object: crate::YubiHsmObjectParameters {
            id: 0,
            label: "PKCS11 RSA public wrap test",
            domains: 0xffff,
            capabilities: crate::yubihsm_capabilities(&[0x0c]),
            algorithm,
        },
        delegated_capabilities: [0xff; 8],
    };
    let command = crate::YubiHsmCommand::put_delegated_object(
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        &parameters,
        &modulus,
    )
    .map_err(|error| format!("failed to encode public wrap key: {error:?}"))?;

    crate::with_session_context_mut(session, |ctx| {
        let response = ctx._get_session(session)?.1.yubihsm_command(&command)?;
        let id = crate::parse_yubihsm_object_id(&response)?;
        ctx.refresh_slot_token_objects(slot_id)?;
        ctx.resolved_objects()?
            .into_iter()
            .find_map(|(handle, object)| {
                (object.slot_id == Some(slot_id)
                    && matches!(
                        object.material,
                        KeyMaterial::YubiHsm {
                            id: object_id,
                            object_type: crate::YUBIHSM_PUBLIC_WRAP_KEY,
                            ..
                        } if object_id == id
                    ))
                .then_some(handle)
            })
            .ok_or(CKR_DEVICE_ERROR.into())
    })
    .map_err(|error| format!("failed to provision public wrap key: {error:?}"))
}

pub(super) fn generated_ec_private_rsa_wrap_round_trip(
    slot_id: CK_SLOT_ID,
    pin: &[u8],
) -> Result<(), String> {
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    checked_rv(
        "C_OpenSession",
        crate::api::C_OpenSession(
            slot_id,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
    )?;
    let mut pin = pin.to_vec();
    let login = checked_rv(
        "C_Login",
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
    );
    if let Err(error) = login {
        let _ = crate::api::C_CloseSession(session);
        return Err(error);
    }

    let mut target_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut target_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut wrapper_public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut wrapper_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut public_wrap_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut restored = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let operation = (|| -> Result<(), String> {
        let mut ec_parameters = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut sign = CK_TRUE as CK_BBOOL;
        let mut extractable = CK_TRUE as CK_BBOOL;
        let mut ec_public_template = [bytes_attribute(
            CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            &mut ec_parameters,
        )];
        let mut ec_private_template = [
            scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
            scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        ];
        let mut ec_generation = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        checked_rv(
            "C_GenerateKeyPair EC target",
            crate::api::C_GenerateKeyPair(
                session,
                &mut ec_generation,
                ec_public_template.as_mut_ptr(),
                ec_public_template.len() as CK_ULONG,
                ec_private_template.as_mut_ptr(),
                ec_private_template.len() as CK_ULONG,
                &mut target_public,
                &mut target_private,
            ),
        )?;
        let target_id = checked_attribute(session, target_private, CKA_ID as CK_ATTRIBUTE_TYPE)?;

        let mut modulus_bits = 2048 as CK_ULONG;
        let mut wrap = CK_FALSE as CK_BBOOL;
        let mut unwrap = CK_TRUE as CK_BBOOL;
        let mut rsa_public_template = [
            scalar_attribute(CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE, &mut modulus_bits),
            scalar_attribute(CKA_WRAP as CK_ATTRIBUTE_TYPE, &mut wrap),
        ];
        let mut rsa_private_template = [scalar_attribute(
            CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
            &mut unwrap,
        )];
        let mut rsa_generation = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        checked_rv(
            "C_GenerateKeyPair RSA wrap key",
            crate::api::C_GenerateKeyPair(
                session,
                &mut rsa_generation,
                rsa_public_template.as_mut_ptr(),
                rsa_public_template.len() as CK_ULONG,
                rsa_private_template.as_mut_ptr(),
                rsa_private_template.len() as CK_ULONG,
                &mut wrapper_public,
                &mut wrapper_private,
            ),
        )?;
        if checked_bool_attribute(session, wrapper_public, CKA_WRAP as CK_ATTRIBUTE_TYPE)?
            || !checked_bool_attribute(session, wrapper_private, CKA_UNWRAP as CK_ATTRIBUTE_TYPE)?
        {
            return Err("generated RSA wrap-key attributes are inconsistent".to_owned());
        }
        public_wrap_key = provision_rsa_public_wrap_key(session, slot_id, wrapper_public)?;

        let (mut mechanism, mut parameters, mut oaep) = rsa_wrap_mechanism(true);
        initialize_rsa_wrap_mechanism(&mut mechanism, &mut parameters, &mut oaep);
        let mut denied_length = 0;
        let denied_rv = crate::api::C_WrapKey(
            session,
            &mut mechanism,
            wrapper_private,
            target_private,
            std::ptr::null_mut(),
            &mut denied_length,
        );
        if denied_rv != CKR_OBJECT_HANDLE_INVALID as CK_RV {
            return Err(format!(
                "C_WrapKey with a private RSA wrap key returned CK_RV 0x{denied_rv:08x}, expected CKR_OBJECT_HANDLE_INVALID"
            ));
        }

        let mut wrapped_length = 0;
        checked_rv(
            "C_WrapKey length query",
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                public_wrap_key,
                target_private,
                std::ptr::null_mut(),
                &mut wrapped_length,
            ),
        )?;
        let mut wrapped = vec![0; wrapped_length as usize];
        checked_rv(
            "C_WrapKey",
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                public_wrap_key,
                target_private,
                wrapped.as_mut_ptr(),
                &mut wrapped_length,
            ),
        )?;
        wrapped.truncate(wrapped_length as usize);

        let collision_rv = crate::api::C_UnwrapKey(
            session,
            &mut mechanism,
            wrapper_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut restored,
        );
        if collision_rv == CKR_OK as CK_RV {
            return Err("C_UnwrapKey replaced an existing object ID".to_owned());
        }
        restored = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

        checked_rv(
            "C_DestroyObject EC target",
            crate::api::C_DestroyObject(session, target_private),
        )?;
        target_private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        checked_rv(
            "C_UnwrapKey",
            crate::api::C_UnwrapKey(
                session,
                &mut mechanism,
                wrapper_private,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                std::ptr::null_mut(),
                0,
                &mut restored,
            ),
        )?;

        if checked_ulong_attribute(session, restored, CKA_CLASS as CK_ATTRIBUTE_TYPE)?
            != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || checked_ulong_attribute(session, restored, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)?
                != CKK_EC as CK_KEY_TYPE
            || checked_attribute(session, restored, CKA_ID as CK_ATTRIBUTE_TYPE)? != target_id
            || !checked_bool_attribute(session, restored, CKA_SIGN as CK_ATTRIBUTE_TYPE)?
            || !checked_bool_attribute(session, restored, CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE)?
        {
            return Err("unwrapped EC key does not match the wrapped target".to_owned());
        }
        Ok(())
    })();

    let mut cleanup_error = None;
    for (name, handle) in [
        ("restored EC key", restored),
        ("original EC key", target_private),
        ("RSA public wrap key", public_wrap_key),
        ("RSA wrap key", wrapper_private),
    ] {
        if handle != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            let rv = crate::api::C_DestroyObject(session, handle);
            if rv != CKR_OK as CK_RV && cleanup_error.is_none() {
                cleanup_error = Some(format!("cleanup of {name} failed with CK_RV 0x{rv:08x}"));
            }
        }
    }
    let close_rv = crate::api::C_CloseSession(session);
    if operation.is_ok() && cleanup_error.is_none() && close_rv != CKR_OK as CK_RV {
        cleanup_error = Some(format!("C_CloseSession failed with CK_RV 0x{close_rv:08x}"));
    }
    operation.and_then(|()| cleanup_error.map_or(Ok(()), Err))
}

#[test]
fn generated_ec_key_round_trips_through_private_rsa_wrap_key() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    generated_ec_private_rsa_wrap_round_trip(SLOT_ID, b"0001password").unwrap();

    let commands = commands.borrow();
    for command in [
        crate::YubiHsmCommandCode::GenerateAsymmetricKey,
        crate::YubiHsmCommandCode::GenerateWrapKey,
        crate::YubiHsmCommandCode::PutPublicWrapKey,
        crate::YubiHsmCommandCode::ExportRsaWrapped,
        crate::YubiHsmCommandCode::ImportRsaWrapped,
    ] {
        assert!(
            commands.iter().any(|(actual, _)| *actual == command as u8),
            "missing mock command {command:?}"
        );
    }
    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn yubihsm_wrap_and_unwrap_cover_aes_ccm_and_rsa_paths() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, _, _trust) = crate::yubihsm::tests::make_yubihsm_test_slot();
    install_test_slot_with_backend(SLOT_ID, slot);
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut pin = *b"0001password";
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let (target, ccm_wrapper, rsa_private, rsa_synthetic_public, rsa_public_wrap) =
        install_yubihsm_wrap_test_objects(session, SLOT_ID);
    let wrap_targets = install_yubihsm_wrap_targets(SLOT_ID);
    assert!(!checked_bool_attribute(session, ccm_wrapper, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap());
    assert!(
        !checked_bool_attribute(session, ccm_wrapper, CKA_UNWRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );
    assert!(
        !checked_bool_attribute(session, rsa_private, CKA_UNWRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );
    assert!(
        !checked_bool_attribute(session, rsa_public_wrap, CKA_WRAP as CK_ATTRIBUTE_TYPE).unwrap()
    );

    let mut ccm_mechanism = CK_MECHANISM {
        mechanism: crate::CKM_YUBICO_AES_CCM_WRAP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len = 0;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            target,
            std::ptr::null_mut(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );
    assert!(wrapped_len > 0);
    assert_eq!(
        commands.borrow().last().unwrap().0,
        crate::YubiHsmCommandCode::ExportWrapped as u8
    );

    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut ccm_mechanism,
                ccm_wrapper,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::ExportWrapped as u8);
        assert_eq!(
            last.1,
            [
                0,
                31,
                *target_type,
                target_id.to_be_bytes()[0],
                target_id.to_be_bytes()[1],
            ]
        );
    }
    let mut wrapped = vec![0; wrapped_len as usize];
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            target,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        ),
        CKR_OK as CK_RV
    );
    wrapped.truncate(wrapped_len as usize);
    assert!(wrapped.starts_with(b"wrapped-object:"));
    let last = commands.borrow().last().cloned().unwrap();
    assert_eq!(last.0, crate::YubiHsmCommandCode::ExportWrapped as u8);
    assert_eq!(last.1, [0, 31, crate::YUBIHSM_SYMMETRIC_KEY, 0, 30]);

    let mut imported = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    let imported_object = crate::with_session_context(session, |ctx| {
        ctx.resolve_object(imported)?
            .ok_or(CKR_OBJECT_HANDLE_INVALID.into())
    })
    .unwrap();
    assert!(matches!(
        imported_object.material,
        KeyMaterial::YubiHsm {
            id: 20,
            object_type: crate::YUBIHSM_SYMMETRIC_KEY,
            ..
        }
    ));

    for (full_object, wrapper, expected_command) in [
        (
            true,
            rsa_public_wrap,
            crate::YubiHsmCommandCode::ExportRsaWrapped,
        ),
        (
            false,
            rsa_private,
            crate::YubiHsmCommandCode::GetRsaWrappedKey,
        ),
    ] {
        let (mut mechanism, mut parameters, mut oaep) = rsa_wrap_mechanism(full_object);
        initialize_rsa_wrap_mechanism(&mut mechanism, &mut parameters, &mut oaep);
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                wrapper,
                target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let mut output = vec![0; length as usize];
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut mechanism,
                wrapper,
                target,
                output.as_mut_ptr(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(commands.borrow().last().unwrap().0, expected_command as u8);
    }

    let mut synthetic_output = [0u8; 32];
    let mut synthetic_output_len = synthetic_output.len() as CK_ULONG;
    assert_eq!(
        crate::api::C_WrapKey(
            session,
            &mut ccm_mechanism,
            ccm_wrapper,
            rsa_synthetic_public,
            synthetic_output.as_mut_ptr(),
            &mut synthetic_output_len,
        ),
        CKR_KEY_NOT_WRAPPABLE as CK_RV
    );

    let (mut full_rsa, mut full_parameters, mut full_oaep) = rsa_wrap_mechanism(true);
    initialize_rsa_wrap_mechanism(&mut full_rsa, &mut full_parameters, &mut full_oaep);
    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut full_rsa,
                rsa_public_wrap,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::ExportRsaWrapped as u8);
        assert_eq!(last.1[2], *target_type);
        assert_eq!(&last.1[3..5], &target_id.to_be_bytes());
    }

    let (mut key_rsa, mut key_parameters, mut key_oaep) = rsa_wrap_mechanism(false);
    initialize_rsa_wrap_mechanism(&mut key_rsa, &mut key_parameters, &mut key_oaep);
    for (target, target_type, target_id) in &wrap_targets {
        let mut length = 0;
        assert_eq!(
            crate::api::C_WrapKey(
                session,
                &mut key_rsa,
                rsa_private,
                *target,
                std::ptr::null_mut(),
                &mut length,
            ),
            CKR_OK as CK_RV
        );
        let last = commands.borrow().last().cloned().unwrap();
        assert_eq!(last.0, crate::YubiHsmCommandCode::GetRsaWrappedKey as u8);
        assert_eq!(last.1[2], *target_type);
        assert_eq!(&last.1[3..5], &target_id.to_be_bytes());
    }

    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut full_rsa,
            rsa_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    assert!(commands
        .borrow()
        .iter()
        .any(|(command, _)| { *command == crate::YubiHsmCommandCode::ImportRsaWrapped as u8 }));

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_AES as CK_KEY_TYPE;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut value_len = 16 as CK_ULONG;
    let mut id = 40u16.to_be_bytes();
    let mut label = *b"unwrapped AES";
    let mut template = [
        scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
        scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
        scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        scalar_attribute(CKA_SENSITIVE as CK_ATTRIBUTE_TYPE, &mut sensitive),
        scalar_attribute(CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE, &mut extractable),
        scalar_attribute(CKA_ENCRYPT as CK_ATTRIBUTE_TYPE, &mut encrypt),
        scalar_attribute(CKA_DECRYPT as CK_ATTRIBUTE_TYPE, &mut decrypt),
        scalar_attribute(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE, &mut value_len),
        bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id),
        bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
    ];
    assert_eq!(
        crate::api::C_UnwrapKey(
            session,
            &mut key_rsa,
            rsa_private,
            wrapped.as_mut_ptr(),
            wrapped.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut imported,
        ),
        CKR_OK as CK_RV
    );
    let imported_object = crate::with_session_context(session, |ctx| {
        ctx.resolve_object(imported)?
            .ok_or(CKR_OBJECT_HANDLE_INVALID.into())
    })
    .unwrap();
    assert_eq!(imported_object.id, id);
    assert_eq!(imported_object.label, "unwrapped AES");
    assert!(imported_object.extractable);
    assert!(!imported_object.never_extractable);
    assert_eq!(
        commands
            .borrow()
            .iter()
            .filter(|(command, _)| *command == crate::YubiHsmCommandCode::PutRsaWrappedKey as u8)
            .count(),
        1
    );

    assert_eq!(
        crate::api::C_Finalize(std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn yubihsm_wrap_rejects_incompatible_keys_and_parameters() {
    let mut mechanism = CK_MECHANISM {
        mechanism: crate::CKM_YUBICO_AES_CCM_WRAP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 1,
    };
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&mechanism).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );

    let mut format = crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS { format: 2 };
    mechanism.pParameter = (&mut format as *mut crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS).cast();
    mechanism.ulParameterLen =
        std::mem::size_of::<crate::CKM_YUBICO_AES_CCM_WRAP_PARAMS>() as CK_ULONG;
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&mechanism).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );

    let (mut rsa, mut parameters, mut oaep) = rsa_wrap_mechanism(true);
    parameters.ulAESKeyBits = 64;
    initialize_rsa_wrap_mechanism(&mut rsa, &mut parameters, &mut oaep);
    assert_eq!(
        CK_RV::from(crate::parse_yubihsm_wrap_mechanism(&rsa).unwrap_err()),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
}
