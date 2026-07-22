#[no_mangle]
pub extern "C" fn C_CreateObject(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CreateObject called with {:?}",
        (session_handle, templ, count, object)
    );
    match create_object(session_handle, templ, count, object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn create_object(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let object_handle = as_mut(object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.is_piv() {
            let import = piv_import_parameters(templ)?;
            match import {
                PivImport::Private {
                    slot,
                    key,
                    pin_policy,
                    touch_policy,
                    object,
                } => {
                    validate_new_object_access(&object, flags, logged_in)?;
                    let replaced = piv_key_object_handles(ctx, slot_id, slot)?;
                    ctx._get_slot_mut(slot_id)?.piv_import_private_key(
                        slot,
                        &key,
                        pin_policy,
                        touch_policy,
                    )?;
                    for (handle, _, _) in replaced {
                        ctx.remove_object_handle(handle);
                    }
                    ctx.refresh_slot_token_objects(slot_id)?;
                    *object_handle = find_piv_key_handle(
                        ctx,
                        slot_id,
                        slot,
                        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                    )?;
                }
                PivImport::Certificate {
                    slot,
                    certificate,
                    object,
                } => {
                    validate_new_object_access(&object, flags, logged_in)?;
                    let replaced = ctx
                        .resolved_objects()?
                        .into_iter()
                        .filter_map(|(handle, candidate)| {
                            (candidate.slot_id == Some(slot_id)
                                && candidate.class == CKO_CERTIFICATE as CK_OBJECT_CLASS
                                && candidate.id == [slot.cka_id()]
                                && candidate.token)
                                .then_some(handle)
                        })
                        .collect::<Vec<_>>();
                    ctx._get_slot_mut(slot_id)?
                        .piv_import_certificate(slot, &certificate)?;
                    for handle in replaced {
                        ctx.remove_object_handle(handle);
                    }
                    ctx.refresh_slot_token_objects(slot_id)?;
                    *object_handle = ctx
                        .resolved_objects()?
                        .into_iter()
                        .find(|(_, object)| {
                            object.slot_id == Some(slot_id)
                                && object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS
                                && object.id == [slot.cka_id()]
                        })
                        .map(|(handle, _)| handle)
                        .ok_or(CKR_DEVICE_ERROR)?;
                }
                PivImport::Data {
                    object_id,
                    value,
                    object,
                } => {
                    validate_new_object_access(&object, flags, logged_in)?;
                    let replaced = ctx
                        .resolved_objects()?
                        .into_iter()
                        .filter_map(|(handle, candidate)| {
                            (candidate.slot_id == Some(slot_id)
                                && matches!(
                                candidate.material,
                                KeyMaterial::PivData {
                                    object_id: candidate,
                                    ..
                                } if candidate == object_id
                            ))
                            .then_some(handle)
                        })
                        .collect::<Vec<_>>();
                    ctx._get_slot_mut(slot_id)?
                        .piv_write_data(object_id, &value)?;
                    for handle in replaced {
                        ctx.remove_object_handle(handle);
                    }
                    ctx.refresh_slot_token_objects(slot_id)?;
                    *object_handle = ctx
                        .resolved_objects()?
                        .into_iter()
                        .find(|(_, object)| {
                            object.slot_id == Some(slot_id)
                                && matches!(
                                    object.material,
                                    KeyMaterial::PivData {
                                        object_id: candidate,
                                        ..
                                    } if candidate == object_id
                                )
                        })
                        .map(|(handle, _)| handle)
                        .ok_or(CKR_DEVICE_ERROR)?;
                }
            }
            return Ok(());
        }
        if ctx.get_slot(slot_id)?.is_openpgp() {
            let import = openpgp_private_import(templ)?;
            validate_new_object_access(&import.object, flags, logged_in)?;
            ctx._get_slot_mut(slot_id)?.openpgp_import_private_key(
                import.key_ref,
                import.algorithm,
                &import.material,
            )?;
            if import.touch_policy != 0 {
                ctx._get_slot_mut(slot_id)?.openpgp_set_touch_policy(
                    import.key_ref,
                    import.touch_policy,
                )?;
            }
            ctx.refresh_slot_token_objects(slot_id)?;
            *object_handle = find_openpgp_key_handle(
                ctx,
                slot_id,
                import.key_ref,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            )?;
            return Ok(());
        }
        let mut object = parse_create_object_template(templ)?;
        validate_new_object_access(&object, flags, logged_in)?;
        if ctx.get_slot(slot_id)?.is_yubihsm() {
            let (command, expected_class) = yubihsm_import_command(&object)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            let id = parse_yubihsm_object_id(&response)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            *object_handle = ctx
                .resolved_objects()?
                .into_iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == expected_class
                        && matches!(object.material, KeyMaterial::YubiHsm { id: object_id, .. } if object_id == id)
                })
                .map(|(handle, _)| handle)
                .ok_or(CKR_DEVICE_ERROR)?;
            return Ok(());
        }
        object.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(object);
        *object_handle = handle;
        Ok(())
    })
}

struct OpenPgpImport {
    key_ref: OpenPgpKeyRef,
    algorithm: OpenPgpAlgorithm,
    material: KeyMaterial,
    object: TokenObject,
    touch_policy: u8,
}

fn openpgp_private_import(templ: &[CK_ATTRIBUTE]) -> Result<OpenPgpImport, Error> {
    validate_unique_template(templ)?;
    let key_type_attribute =
        template_attribute(templ, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
            .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let key_type = read_ulong_template_attribute(key_type_attribute).map_err(Error::from)?;
    let filtered = templ
        .iter()
        .filter(|attribute| {
            !matches!(
                attribute.type_,
                x if is_key_component_attribute(x)
                    || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
                    || x == CKA_YUBICO_TOUCH_POLICY
            )
        })
        .copied()
        .collect::<Vec<_>>();
    let object = key_pair_object(
        &filtered,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    if !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let key_ref = openpgp_key_ref(&object.id)?;
    let (algorithm, material) = if key_type == CKK_RSA as CK_KEY_TYPE {
        let without_touch = templ
            .iter()
            .filter(|attribute| attribute.type_ != CKA_YUBICO_TOUCH_POLICY)
            .copied()
            .collect::<Vec<_>>();
        let parsed = parse_create_object_template(&without_touch)?;
        let KeyMaterial::RsaPrivate(key) = parsed.material else {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        };
        let bits = key.size() as usize * 8;
        if !matches!(bits, 2048 | 3072 | 4096) {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        (OpenPgpAlgorithm::Rsa { bits }, KeyMaterial::RsaPrivate(key))
    } else {
        let private = required_template_value(templ, CKA_VALUE as CK_ATTRIBUTE_TYPE)?;
        let params = required_template_value(templ, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
        let algorithm = if key_type == CKK_EC as CK_KEY_TYPE {
            let curve = openpgp_curve(&params)?;
            if key_ref == OpenPgpKeyRef::Decipher {
                OpenPgpAlgorithm::Ecdh(curve)
            } else {
                OpenPgpAlgorithm::Ecdsa(curve)
            }
        } else if key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
            if params.as_slice() != openpgp::Curve::Ed25519.oid()
                || key_ref == OpenPgpKeyRef::Decipher
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            OpenPgpAlgorithm::Ed25519
        } else if key_type == CKK_EC_MONTGOMERY as CK_KEY_TYPE {
            if params.as_slice() != openpgp::Curve::X25519.oid()
                || key_ref != OpenPgpKeyRef::Decipher
            {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            OpenPgpAlgorithm::Ecdh(openpgp::Curve::X25519)
        } else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        (algorithm, KeyMaterial::Secret(private))
    };
    let touch_policy = match template_attribute(templ, CKA_YUBICO_TOUCH_POLICY) {
        Some(attribute) => {
            let value = read_ulong_template_attribute(attribute).map_err(Error::from)?;
            match value {
                1..=5 => value as u8,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            }
        }
        None => 0,
    };
    Ok(OpenPgpImport {
        key_ref,
        algorithm,
        material,
        object,
        touch_policy,
    })
}

fn piv_key_object_handles(
    ctx: &Context,
    slot_id: CK_SLOT_ID,
    piv_slot: piv::Slot,
) -> Result<Vec<(CK_OBJECT_HANDLE, CK_OBJECT_CLASS, bool)>, Error> {
    Ok(ctx
        .resolved_objects()?
        .into_iter()
        .filter_map(|(handle, candidate)| {
            let key_object = candidate.slot_id == Some(slot_id)
                && candidate.id == [piv_slot.cka_id()]
                && matches!(
                    candidate.class,
                    x if x == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                        || x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                );
            let attestation = candidate.slot_id == Some(slot_id)
                && matches!(
                    candidate.material,
                    KeyMaterial::PivAttestation { slot, .. } if slot == piv_slot
                );
            (key_object || attestation).then_some((handle, candidate.class, candidate.token))
        })
        .collect())
}

enum PivImport {
    Private {
        slot: piv::Slot,
        key: piv::PrivateKeyImport,
        pin_policy: u8,
        touch_policy: u8,
        object: TokenObject,
    },
    Certificate {
        slot: piv::Slot,
        certificate: Vec<u8>,
        object: TokenObject,
    },
    Data {
        object_id: u32,
        value: Vec<u8>,
        object: TokenObject,
    },
}

fn required_template_value(
    templ: &[CK_ATTRIBUTE],
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let attribute = template_attribute(templ, attribute_type).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let value = Zeroizing::new(read_attribute_value(attribute).map_err(Error::from)?);
    if value.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    Ok(value)
}

fn piv_import_slot(id: &[u8], allow_attestation: bool) -> Result<piv::Slot, Error> {
    let [id] = id else {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    };
    let slot = piv::Slot::from_cka_id(*id).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
    if slot == piv::Slot::Attestation && !allow_attestation {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    Ok(slot)
}

fn piv_private_template_object(
    templ: &[CK_ATTRIBUTE],
    key_type: CK_KEY_TYPE,
) -> Result<TokenObject, Error> {
    let filtered = templ
        .iter()
        .filter(|attribute| {
            !matches!(attribute.type_,
                x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
                    || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
                    || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                    || x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
                    || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
                    || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
                    || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
                    || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
                    || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
                    || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
                    || x == CKA_YUBICO_TOUCH_POLICY
                    || x == CKA_YUBICO_PIN_POLICY)
        })
        .copied()
        .collect::<Vec<_>>();
    piv_key_pair_object(
        &filtered,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )
}

fn piv_private_import(templ: &[CK_ATTRIBUTE]) -> Result<PivImport, Error> {
    let key_type_attribute =
        template_attribute(templ, CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
            .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let key_type = read_ulong_template_attribute(key_type_attribute).map_err(Error::from)?;
    let object = piv_private_template_object(templ, key_type)?;
    if !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let slot = piv_import_slot(&object.id, false)?;
    let pin_policy = piv_policy_attribute(templ, CKA_YUBICO_PIN_POLICY, 5)?;
    let touch_policy = piv_policy_attribute(templ, CKA_YUBICO_TOUCH_POLICY, 3)?;

    let key = if key_type == CKK_RSA as CK_KEY_TYPE {
        let filtered = templ
            .iter()
            .filter(|attribute| {
                !matches!(
                    attribute.type_,
                    CKA_YUBICO_TOUCH_POLICY | CKA_YUBICO_PIN_POLICY
                )
            })
            .copied()
            .collect::<Vec<_>>();
        let parsed = parse_create_object_template(&filtered)?;
        let KeyMaterial::RsaPrivate(key) = parsed.material else {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        };
        let algorithm = match key.size() {
            128 => piv::Algorithm::Rsa1024,
            256 => piv::Algorithm::Rsa2048,
            384 => piv::Algorithm::Rsa3072,
            512 => piv::Algorithm::Rsa4096,
            _ => return Err(CKR_KEY_SIZE_RANGE.into()),
        };
        piv::PrivateKeyImport {
            algorithm,
            components: vec![
                (0x01, Zeroizing::new(key.p().ok_or(CKR_TEMPLATE_INCOMPLETE)?.to_vec())),
                (0x02, Zeroizing::new(key.q().ok_or(CKR_TEMPLATE_INCOMPLETE)?.to_vec())),
                (0x03, Zeroizing::new(key.dmp1().ok_or(CKR_TEMPLATE_INCOMPLETE)?.to_vec())),
                (0x04, Zeroizing::new(key.dmq1().ok_or(CKR_TEMPLATE_INCOMPLETE)?.to_vec())),
                (0x05, Zeroizing::new(key.iqmp().ok_or(CKR_TEMPLATE_INCOMPLETE)?.to_vec())),
            ],
            public_key: MetadataPublicKey::Rsa {
                modulus: key.n().to_vec(),
                exponent: key.e().to_vec(),
            },
        }
    } else {
        let private = required_template_value(templ, CKA_VALUE as CK_ATTRIBUTE_TYPE)?;
        let (algorithm, component_tag, public_key) = if key_type == CKK_EC as CK_KEY_TYPE {
            let params = required_template_value(templ, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)?;
            let (algorithm, nid, length) = match params.as_slice() {
                [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => {
                    (piv::Algorithm::EccP256, Nid::X9_62_PRIME256V1, 32)
                }
                [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => {
                    (piv::Algorithm::EccP384, Nid::SECP384R1, 48)
                }
                _ => return Err(CKR_CURVE_NOT_SUPPORTED.into()),
            };
            if private.len() > length {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
            let scalar = BigNum::from_slice(&private).map_err(Error::from)?;
            let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
            let mut point = EcPoint::new(&group).map_err(Error::from)?;
            point
                .mul_generator2(&group, &scalar, &mut context)
                .map_err(Error::from)?;
            let public = point
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
                .map_err(Error::from)?;
            (algorithm, 0x06, MetadataPublicKey::Ec(public))
        } else if key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
            if private.len() != 32 {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let key = PKey::private_key_from_raw_bytes(&private, Id::ED25519)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            (
                piv::Algorithm::Ed25519,
                0x07,
                MetadataPublicKey::Raw(key.raw_public_key().map_err(Error::from)?),
            )
        } else if key_type == CKK_EC_MONTGOMERY as CK_KEY_TYPE {
            if private.len() != 32 {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let key = PKey::private_key_from_raw_bytes(&private, Id::X25519)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            (
                piv::Algorithm::X25519,
                0x08,
                MetadataPublicKey::Raw(key.raw_public_key().map_err(Error::from)?),
            )
        } else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        piv::PrivateKeyImport {
            algorithm,
            components: vec![(component_tag, private)],
            public_key,
        }
    };
    Ok(PivImport::Private {
        slot,
        key,
        pin_policy,
        touch_policy,
        object,
    })
}

fn piv_certificate_import(templ: &[CK_ATTRIBUTE]) -> Result<PivImport, Error> {
    let allowed = [
        CKA_CLASS as CK_ATTRIBUTE_TYPE,
        CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE,
        CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        CKA_ID as CK_ATTRIBUTE_TYPE,
        CKA_VALUE as CK_ATTRIBUTE_TYPE,
    ];
    if templ
        .iter()
        .any(|attribute| !allowed.contains(&attribute.type_))
    {
        return Err(CKR_ATTRIBUTE_TYPE_INVALID.into());
    }
    let certificate = required_template_value(templ, CKA_VALUE as CK_ATTRIBUTE_TYPE)?.to_vec();
    let algorithm = piv_algorithm_from_certificate(&certificate).ok_or(CKR_DATA_INVALID)?;
    let id = required_template_value(templ, CKA_ID as CK_ATTRIBUTE_TYPE)?.to_vec();
    let slot = piv_import_slot(&id, true)?;
    let certificate_type_attribute =
        template_attribute(templ, CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE)
            .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let certificate_type =
        read_ulong_template_attribute(certificate_type_attribute).map_err(Error::from)?;
    if certificate_type != CKC_X_509 as CK_ULONG {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    let token = template_attribute(templ, CKA_TOKEN as CK_ATTRIBUTE_TYPE)
        .map(read_bool_template_attribute)
        .transpose()
        .map_err(Error::from)?
        .unwrap_or(true);
    let private = template_attribute(templ, CKA_PRIVATE as CK_ATTRIBUTE_TYPE)
        .map(read_bool_template_attribute)
        .transpose()
        .map_err(Error::from)?
        .unwrap_or(false);
    if !token || private {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let label = template_attribute(templ, CKA_LABEL as CK_ATTRIBUTE_TYPE)
        .map(|attribute| read_attribute_value(attribute).map_err(Error::from))
        .transpose()?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?
        .unwrap_or_else(|| piv_slot_label(slot, true, slot == piv::Slot::Attestation));
    let key_type = PivPublicKey::Raw(Vec::new()).key_type(algorithm);
    let object = TokenObject {
        slot_id: None,
        unique_id: String::new(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type,
        label,
        id,
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: KeyMaterial::PivCertificate {
            algorithm,
            value: certificate.clone(),
            attestation: slot == piv::Slot::Attestation,
        },
    };
    Ok(PivImport::Certificate {
        slot,
        certificate,
        object,
    })
}

fn piv_data_import(templ: &[CK_ATTRIBUTE]) -> Result<PivImport, Error> {
    let allowed = [
        CKA_CLASS as CK_ATTRIBUTE_TYPE,
        CKA_TOKEN as CK_ATTRIBUTE_TYPE,
        CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
        CKA_LABEL as CK_ATTRIBUTE_TYPE,
        CKA_APPLICATION as CK_ATTRIBUTE_TYPE,
        CKA_ID as CK_ATTRIBUTE_TYPE,
        CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE,
        CKA_PKCS11RS_PIV_OBJECT_TAG,
        CKA_VALUE as CK_ATTRIBUTE_TYPE,
    ];
    if templ
        .iter()
        .any(|attribute| !allowed.contains(&attribute.type_))
    {
        return Err(CKR_ATTRIBUTE_TYPE_INVALID.into());
    }
    let from_cka_id = template_attribute(templ, CKA_ID as CK_ATTRIBUTE_TYPE)
        .map(|attribute| {
            let value = read_attribute_value(attribute).map_err(Error::from)?;
            let [id] = value.as_slice() else {
                return Err(Error::from(CKR_ATTRIBUTE_VALUE_INVALID));
            };
            piv::data_object_mapping_by_cka_id(*id)
                .map(|mapping| mapping.object_id)
                .ok_or_else(|| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))
        })
        .transpose()?;
    let from_oid = template_attribute(templ, CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE)
        .map(|attribute| {
            let value = read_attribute_value(attribute).map_err(Error::from)?;
            piv::data_object_mapping_by_oid(&value)
                .map(|mapping| mapping.object_id)
                .ok_or_else(|| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))
        })
        .transpose()?;
    let from_tag = template_attribute(templ, CKA_PKCS11RS_PIV_OBJECT_TAG)
        .map(|attribute| {
            let value = read_attribute_value(attribute).map_err(Error::from)?;
            if value.is_empty() || value.len() > 3 {
                return Err(Error::from(CKR_ATTRIBUTE_VALUE_INVALID));
            }
            Ok(value
                .iter()
                .fold(0u32, |object_id, byte| (object_id << 8) | *byte as u32))
        })
        .transpose()?;
    let object_ids = [from_cka_id, from_oid, from_tag]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let object_id = *object_ids.first().ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if object_ids.iter().any(|candidate| *candidate != object_id) {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if !piv::data_object_allowed(object_id) {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    let value = required_template_value(templ, CKA_VALUE as CK_ATTRIBUTE_TYPE)?.to_vec();
    let token = template_attribute(templ, CKA_TOKEN as CK_ATTRIBUTE_TYPE)
        .map(read_bool_template_attribute)
        .transpose()
        .map_err(Error::from)?
        .unwrap_or(true);
    if !token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let private = template_attribute(templ, CKA_PRIVATE as CK_ATTRIBUTE_TYPE)
        .map(read_bool_template_attribute)
        .transpose()
        .map_err(Error::from)?
        .unwrap_or(false);
    let label = template_attribute(templ, CKA_LABEL as CK_ATTRIBUTE_TYPE)
        .map(|attribute| read_attribute_value(attribute).map_err(Error::from))
        .transpose()?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?
        .unwrap_or_else(|| piv::data_object_name(object_id));
    let object = TokenObject {
        slot_id: None,
        unique_id: String::new(),
        class: CKO_DATA as CK_OBJECT_CLASS,
        key_type: 0,
        label,
        id: piv::data_object_mapping(object_id)
            .map(|mapping| vec![mapping.cka_id])
            .unwrap_or_default(),
        token: true,
        private,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: KeyMaterial::PivData {
            object_id,
            value: value.clone(),
        },
    };
    Ok(PivImport::Data {
        object_id,
        value,
        object,
    })
}

fn piv_import_parameters(templ: &[CK_ATTRIBUTE]) -> Result<PivImport, Error> {
    validate_unique_template(templ)?;
    let class_attribute = template_attribute(templ, CKA_CLASS as CK_ATTRIBUTE_TYPE)
        .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    match read_ulong_template_attribute(class_attribute).map_err(Error::from)? {
        class if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => piv_private_import(templ),
        class if class == CKO_CERTIFICATE as CK_OBJECT_CLASS => piv_certificate_import(templ),
        class if class == CKO_DATA as CK_OBJECT_CLASS => piv_data_import(templ),
        _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
    }
}

fn yubihsm_id(id: &[u8]) -> Result<u16, Error> {
    match id {
        [] => Ok(0),
        [high, low] => Ok(u16::from_be_bytes([*high, *low])),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

fn padded_big_num(value: &openssl::bn::BigNumRef, length: usize) -> Result<Vec<u8>, Error> {
    let encoded = value.to_vec();
    if encoded.len() > length {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let mut padded = vec![0; length];
    padded[length - encoded.len()..].copy_from_slice(&encoded);
    Ok(padded)
}

fn yubihsm_object_parameters(
    object: &TokenObject,
    algorithm: u8,
) -> Result<YubiHsmObjectParameters<'_>, Error> {
    if !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let mut bits = Vec::new();
    if object.sign
        && (object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || is_hmac_key_type(object.key_type))
    {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x05, 0x06]);
        } else if object.key_type == CKK_EC as CK_KEY_TYPE {
            bits.push(0x07);
        } else if object.key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
            bits.push(0x08);
        } else {
            bits.push(0x16);
        }
    }
    if object.verify {
        bits.push(0x17);
    }
    if object.derive {
        bits.push(0x0b);
    }
    if object.decrypt {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x09, 0x0a]);
        } else {
            bits.extend([0x32, 0x34]);
        }
    }
    if object.encrypt {
        bits.extend([0x33, 0x35]);
    }
    if object.extractable
        && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
        && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
    {
        bits.push(0x10);
    }
    Ok(YubiHsmObjectParameters {
        id: yubihsm_id(&object.id)?,
        label: &object.label,
        domains: 0xffff,
        capabilities: yubihsm_capabilities(&bits),
        algorithm,
    })
}

fn yubihsm_import_command(
    object: &TokenObject,
) -> Result<(YubiHsmCommand, CK_OBJECT_CLASS), Error> {
    match &object.material {
        KeyMaterial::RsaPrivate(key) if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
            let (algorithm, component_length) = match key.size() {
                256 => (YUBIHSM_ALGO_RSA_2048, 128),
                384 => (YUBIHSM_ALGO_RSA_3072, 192),
                512 => (YUBIHSM_ALGO_RSA_4096, 256),
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            let mut value =
                padded_big_num(key.p().ok_or(CKR_TEMPLATE_INCOMPLETE)?, component_length)?;
            value.extend_from_slice(&padded_big_num(
                key.q().ok_or(CKR_TEMPLATE_INCOMPLETE)?,
                component_length,
            )?);
            Ok((
                YubiHsmCommand::put_object(
                    YubiHsmCommandCode::PutAsymmetricKey,
                    &yubihsm_object_parameters(object, algorithm)?,
                    &value,
                )?,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            ))
        }
        KeyMaterial::Secret(value) if object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS => {
            let (code, algorithm) = if object.key_type == CKK_AES as CK_KEY_TYPE {
                let algorithm = match value.len() {
                    16 => YUBIHSM_ALGO_AES128,
                    24 => YUBIHSM_ALGO_AES192,
                    32 => YUBIHSM_ALGO_AES256,
                    _ => return Err(CKR_KEY_SIZE_RANGE.into()),
                };
                (YubiHsmCommandCode::PutSymmetricKey, algorithm)
            } else {
                let algorithm = match object.key_type {
                    x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA1,
                    x if x == CKK_SHA384_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA384,
                    x if x == CKK_SHA512_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA512,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE =>
                    {
                        YUBIHSM_ALGO_HMAC_SHA256
                    }
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                };
                (YubiHsmCommandCode::PutHmacKey, algorithm)
            };
            Ok((
                YubiHsmCommand::put_object(
                    code,
                    &yubihsm_object_parameters(object, algorithm)?,
                    value,
                )?,
                CKO_SECRET_KEY as CK_OBJECT_CLASS,
            ))
        }
        _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
    }
}

fn parse_create_object_template(templ: &[CK_ATTRIBUTE]) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let mut object_template = TokenObjectTemplate::default();
    let mut key_components = HashMap::new();
    for attribute in templ {
        if is_key_component_attribute(attribute.type_) {
            key_components.insert(
                attribute.type_,
                Zeroizing::new(read_attribute_value(attribute).map_err(Error::from)?),
            );
            continue;
        }
        object_template
            .apply_attribute(attribute)
            .map_err(Error::from)?;
    }
    let mut object = object_template.into_object().map_err(Error::from)?;
    object.material = build_imported_key_material(&object, key_components)?;
    Ok(object)
}

fn is_key_component_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
    )
}

fn required_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<BigNum, Error> {
    let value = components
        .remove(&attribute_type)
        .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if value.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    BigNum::from_slice(&value).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
}

fn optional_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<BigNum>, Error> {
    components
        .remove(&attribute_type)
        .map(|value| {
            if value.is_empty() {
                Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
            } else {
                BigNum::from_slice(&value)
                    .map(Some)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
            }
        })
        .unwrap_or(Ok(None))
}

fn build_imported_key_material(
    object: &TokenObject,
    mut components: HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
) -> Result<KeyMaterial, Error> {
    let material = match (object.class, object.key_type) {
        (class, key_type)
            if class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                && matches!(
                    key_type,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_AES as CK_KEY_TYPE
                        || x == CKK_SHA_1_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA384_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA512_HMAC as CK_KEY_TYPE
                ) =>
        {
            let value = components
                .remove(&(CKA_VALUE as CK_ATTRIBUTE_TYPE))
                .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            if value.is_empty() {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            KeyMaterial::Secret(value)
        }
        (class, key_type)
            if class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let key = Rsa::from_public_components(modulus, exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            KeyMaterial::RsaPublic(key)
        }
        (class, key_type)
            if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let public_exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let private_exponent =
                required_big_num(&mut components, CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let mut builder = RsaPrivateKeyBuilder::new(modulus, public_exponent, private_exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

            let prime_1 = optional_big_num(&mut components, CKA_PRIME_1 as CK_ATTRIBUTE_TYPE)?;
            let prime_2 = optional_big_num(&mut components, CKA_PRIME_2 as CK_ATTRIBUTE_TYPE)?;
            let has_factors = prime_1.is_some() || prime_2.is_some();
            builder = match (prime_1, prime_2) {
                (Some(prime_1), Some(prime_2)) => builder
                    .set_factors(prime_1, prime_2)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };

            let exponent_1 =
                optional_big_num(&mut components, CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE)?;
            let exponent_2 =
                optional_big_num(&mut components, CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE)?;
            let coefficient =
                optional_big_num(&mut components, CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE)?;
            builder = match (exponent_1, exponent_2, coefficient) {
                (Some(exponent_1), Some(exponent_2), Some(coefficient)) if has_factors => builder
                    .set_crt_params(exponent_1, exponent_2, coefficient)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };
            KeyMaterial::RsaPrivate(builder.build())
        }
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };
    if components.is_empty() {
        Ok(material)
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

fn validate_unique_template(templ: &[CK_ATTRIBUTE]) -> Result<(), Error> {
    let mut types = HashSet::new();
    if templ.iter().all(|attribute| types.insert(attribute.type_)) {
        Ok(())
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

#[no_mangle]
pub extern "C" fn C_CopyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    new_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CopyObject called with {:?}",
        (session_handle, object, templ, count, new_object)
    );
    match copy_object(session_handle, object, templ, count, new_object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn copy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    new_object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let new_object_handle = as_mut(new_object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mut copied_object = ctx
            .resolve_object(object)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if matches!(
            copied_object.material,
            KeyMaterial::IssuerSecurityDomainData { .. }
                | KeyMaterial::IssuerSecurityDomainCertificate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::HsmAuthPublic { .. }
        ) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        if matches!(copied_object.material, KeyMaterial::YubiHsm { .. }) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = copied_object.set_copy_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }
        if rv != CKR_OK as CK_RV {
            return Err(rv.into());
        }
        validate_new_object_access(&copied_object, flags, logged_in)?;
        copied_object.set_owner(session_handle, slot_id);
        copied_object.unique_id.clear();

        let handle = ctx.insert_object(copied_object);
        *new_object_handle = handle;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_DestroyObject called with {:?}",
        (session_handle, object)
    );
    map(destroy_object(session_handle, object))
}

fn destroy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .resolve_object(object)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if matches!(
            stored_object.material,
            KeyMaterial::IssuerSecurityDomainData { .. }
                | KeyMaterial::IssuerSecurityDomainCertificate { .. }
                | KeyMaterial::HsmAuthCredential { .. }
                | KeyMaterial::HsmAuthPublic { .. }
                | KeyMaterial::YubiHsmDevicePublic { .. }
                | KeyMaterial::OpenPgpPrivate { .. }
                | KeyMaterial::OpenPgpPublic { .. }
                | KeyMaterial::OpenPgpCertificate { .. }
        ) {
            return Err(CKR_ACTION_PROHIBITED.into());
        }
        let piv_action = match &stored_object.material {
            KeyMaterial::PivPrivate { slot, .. } => Some((true, *slot)),
            KeyMaterial::PivCertificate { .. } => {
                let [id] = stored_object.id.as_slice() else {
                    return Err(CKR_DEVICE_ERROR.into());
                };
                Some((false, piv::Slot::from_cka_id(*id).ok_or(CKR_DEVICE_ERROR)?))
            }
            KeyMaterial::PivPublic { .. } | KeyMaterial::RsaPublic(_)
                if ctx.get_slot(slot_id)?.is_piv() =>
            {
                return Err(CKR_ACTION_PROHIBITED.into());
            }
            KeyMaterial::PivAttestation { .. } => {
                ctx.remove_object_handle(object);
                return Ok(());
            }
            KeyMaterial::PivData { object_id, .. } => {
                ctx._get_slot_mut(slot_id)?.piv_delete_data(*object_id)?;
                ctx.refresh_slot_token_objects(slot_id)?;
                return Ok(());
            }
            _ => None,
        };
        if let Some((delete_key, piv_slot)) = piv_action {
            if delete_key {
                ctx._get_slot_mut(slot_id)?.piv_delete_key(piv_slot)?;
            } else {
                ctx._get_slot_mut(slot_id)?
                    .piv_delete_certificate(piv_slot)?;
            }
            ctx.refresh_slot_token_objects(slot_id)?;
            return Ok(());
        }
        if let KeyMaterial::YubiHsm {
            id, object_type, ..
        } = stored_object.material
        {
            if matches!(object_type, YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC) {
                return Ok(());
            }
            ctx._get_session(session_handle)?
                .1
                .yubihsm_command(&YubiHsmCommand::delete_object(id, object_type & !0x80))?;
            let removed: Vec<_> = ctx
                .resolved_objects()?
                .into_iter()
                .filter_map(|(handle, candidate)| match candidate.material {
                    KeyMaterial::YubiHsm {
                        id: candidate_id,
                        object_type: candidate_type,
                        ..
                    } if candidate.slot_id == Some(slot_id)
                        && candidate_id == id
                        && candidate_type & !0x80 == object_type & !0x80 =>
                    {
                        Some(handle)
                    }
                    _ => None,
                })
                .collect();
            for handle in removed {
                ctx.remove_object_handle(handle);
            }
            return Ok(());
        }
        ctx.remove_object_handle(object);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetObjectSize called with {:?}",
        (session_handle, object, size)
    );
    map(get_object_size(session_handle, object, size))
}

fn get_object_size(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> Result<(), Error> {
    let size = as_mut(size)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .resolve_object(object)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        *size = object.size();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match get_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn get_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = _from_raw_parts_mut(templ, count as usize)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .resolve_object(object)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let KeyMaterial::YubiHsm {
                id,
                object_type,
                algorithm,
                value,
                ..
            } = &object.material
            {
                if *object_type == YUBIHSM_OPAQUE
                    && *algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE
                    && is_certificate_attribute(attribute.type_)
                {
                    let payload = yubihsm_opaque_value(ctx, session_handle, *id, value)?;
                    match piv_certificate_attribute(&payload, attribute.type_) {
                        Some(value) => {
                            if let Err(error) = write_attribute_value(attribute, &value) {
                                rv = combine_attribute_rv(rv, error);
                            }
                        }
                        None => {
                            attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                            rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                        }
                    }
                    continue;
                }
            }
            if attribute.type_ == CKA_VALUE as CK_ATTRIBUTE_TYPE {
                match &object.material {
                    KeyMaterial::DerivedSecret(value) => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(value) if !object.sensitive && object.extractable => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(_) => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
                    }
                    KeyMaterial::HsmAuthCredential { .. } => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
                    }
                    KeyMaterial::PivCertificate { .. }
                    | KeyMaterial::PivAttestation { .. }
                    | KeyMaterial::PivData { .. }
                    | KeyMaterial::OpenPgpCertificate { .. }
                    | KeyMaterial::IssuerSecurityDomainData { .. }
                    | KeyMaterial::IssuerSecurityDomainCertificate { .. } => {
                        match object.attribute_value(attribute.type_) {
                            Some(value) => {
                                if let Err(e) = write_attribute_value(attribute, &value) {
                                    rv = combine_attribute_rv(rv, e);
                                }
                            }
                            None => {
                                attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                                rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                            }
                        }
                    }
                    KeyMaterial::YubiHsm {
                        id,
                        object_type,
                        value,
                        ..
                    } if *object_type == YUBIHSM_OPAQUE => {
                        if value.borrow().is_none() {
                            let payload = ctx._get_session(session_handle)?.1.yubihsm_command(
                                &YubiHsmCommand::get_object(YubiHsmCommandCode::GetOpaque, *id)?,
                            )?;
                            *value.borrow_mut() = Some(payload);
                        }
                        let payload = value.borrow();
                        if let Err(e) = write_attribute_value(
                            attribute,
                            payload.as_deref().ok_or(CKR_DEVICE_ERROR)?,
                        ) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    _ => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                    }
                }
                continue;
            }
            match object.attribute_value(attribute.type_) {
                Some(value) => {
                    if let Err(e) = write_attribute_value(attribute, &value) {
                        rv = combine_attribute_rv(rv, e);
                    }
                }
                None => {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                    rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
            }
        }

        if rv == CKR_OK as CK_RV {
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

fn yubihsm_opaque_value(
    ctx: &Context,
    session_handle: CK_SESSION_HANDLE,
    id: u16,
    value: &Rc<RefCell<Option<Vec<u8>>>>,
) -> Result<Vec<u8>, Error> {
    if value
        .try_borrow()
        .map_err(|_| Error::from(CKR_CANT_LOCK))?
        .is_none()
    {
        let payload = ctx._get_session(session_handle)?.1.yubihsm_command(
            &YubiHsmCommand::get_object(YubiHsmCommandCode::GetOpaque, id)?,
        )?;
        *value.try_borrow_mut()? = Some(payload);
    }
    value
        .try_borrow()
        .map_err(|_| Error::from(CKR_CANT_LOCK))?
        .clone()
        .ok_or(CKR_DEVICE_ERROR.into())
}

fn write_attribute_value(attribute: &mut CK_ATTRIBUTE, value: &[u8]) -> Result<(), CK_RV> {
    let required_len = value.len() as CK_ULONG;
    if attribute.pValue.is_null() {
        attribute.ulValueLen = required_len;
        return Ok(());
    }
    if attribute.ulValueLen < required_len {
        attribute.ulValueLen = required_len;
        return Err(CKR_BUFFER_TOO_SMALL as CK_RV);
    }

    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), attribute.pValue as *mut u8, value.len());
    }
    attribute.ulValueLen = required_len;
    Ok(())
}

fn read_attribute_value(attribute: &CK_ATTRIBUTE) -> Result<Vec<u8>, CK_RV> {
    if attribute.ulValueLen > 0 && attribute.pValue.is_null() {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }
    let value = if attribute.ulValueLen == 0 {
        &[]
    } else {
        unsafe {
            slice::from_raw_parts(attribute.pValue as *const u8, attribute.ulValueLen as usize)
        }
    };
    Ok(value.to_vec())
}

fn read_ulong_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<CK_ULONG, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?;
    let mut bytes = [0u8; ::std::mem::size_of::<CK_ULONG>()];
    bytes.copy_from_slice(&value);
    Ok(CK_ULONG::from_ne_bytes(bytes))
}

fn read_bool_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<bool, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?[0];
    match value {
        x if x == CK_FALSE as CK_BBOOL => Ok(false),
        x if x == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV),
    }
}

fn combine_attribute_rv(current: CK_RV, next: CK_RV) -> CK_RV {
    if current == CKR_ARGUMENTS_BAD as CK_RV {
        current
    } else if next == CKR_ARGUMENTS_BAD as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        next
    } else if current == CKR_BUFFER_TOO_SMALL as CK_RV {
        current
    } else {
        next
    }
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_SetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match set_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn set_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .resolve_object(object)?
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if let KeyMaterial::OpenPgpPrivate { key_ref, .. } = stored_object.material {
            let [attribute] = templ else {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            };
            if attribute.type_ != CKA_YUBICO_TOUCH_POLICY {
                return Err(CKR_ATTRIBUTE_READ_ONLY.into());
            }
            let policy = read_ulong_template_attribute(attribute).map_err(Error::from)?;
            if !matches!(policy, 1..=5) {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            ctx._get_slot_mut(slot_id)?
                .openpgp_set_touch_policy(key_ref, policy as u8)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            return Ok(());
        }
        if ctx.token_object_handles.contains_key(&object)
            && !matches!(stored_object.material, KeyMaterial::PivPrivate { .. })
        {
            return Err(CKR_ATTRIBUTE_READ_ONLY.into());
        }
        if let KeyMaterial::PivPrivate { slot: from, .. } = stored_object.material {
            let [attribute] = templ else {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            };
            if attribute.type_ != CKA_ID as CK_ATTRIBUTE_TYPE {
                return Err(CKR_ATTRIBUTE_READ_ONLY.into());
            }
            let id = read_attribute_value(attribute).map_err(Error::from)?;
            let [id] = id.as_slice() else {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            };
            let to = piv::Slot::from_cka_id(*id).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
            if to == piv::Slot::Attestation {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            let source_objects = piv_key_object_handles(ctx, slot_id, from)?;
            let destination_objects = piv_key_object_handles(ctx, slot_id, to)?;
            ctx._get_slot_mut(slot_id)?.piv_move_key(from, to)?;
            for (handle, _, _) in source_objects
                .iter()
                .chain(destination_objects.iter())
                .copied()
                .filter(|(_, _, token)| !token)
            {
                ctx.remove_object_handle(handle);
            }
            let token_objects = ctx.get_slot(slot_id)?.token_objects(slot_id)?;
            let source_handles = source_objects
                .into_iter()
                .filter(|(_, _, token)| *token)
                .map(|(handle, class, _)| (handle, class))
                .collect::<Vec<_>>();
            let mut rebindings = Vec::with_capacity(source_handles.len());
            for (handle, class) in source_handles {
                let target = token_objects
                    .iter()
                    .find(|candidate| {
                        candidate.id == [to.cka_id()]
                            && candidate.class == class
                            && candidate.token
                    })
                    .ok_or(CKR_DEVICE_ERROR)?;
                rebindings.push((handle, target.unique_id.clone()));
            }
            ctx.reconcile_slot_token_objects_with_rebindings(
                slot_id,
                token_objects,
                &rebindings,
            )?;
            return Ok(());
        }
        let mut updated_object = stored_object;

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = updated_object.set_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }

        if rv == CKR_OK as CK_RV {
            ctx.memory_objects.insert(object, updated_object);
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjectsInit called with {:?}",
        (session_handle, templ, count)
    );
    if count > 0 && templ.is_null() {
        return CKR_ARGUMENTS_BAD.into();
    }
    map(find_objects_init(session_handle, templ, count))
}

fn find_objects_init(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    let templ: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = templ
        .iter()
        .map(|attribute| {
            Ok((
                attribute.type_,
                read_attribute_value(attribute).map_err(Error::from)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.find_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        ctx.insert_session_objects(slot_id, session_handle)?;
        log!(2, "C_FindObjectsInit template {:?}", templ);
        let mut objects: Vec<CK_OBJECT_HANDLE> = ctx
            .resolved_objects()?
            .into_iter()
            .filter(|(_handle, object)| {
                object.is_visible_to(session_handle, slot_id, logged_in)
                    && object.matches_template(&templ)
            })
            .map(|(handle, _object)| handle)
            .collect();
        objects.sort();
        ctx.find_operations
            .insert(session_handle, FindOperation { objects, next: 0 });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    session_handle: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: ::std::os::raw::c_ulong,
    object_count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjects called with {:?}",
        (session_handle, object, max_object_count, object_count)
    );
    map(find_objects(
        session_handle,
        object,
        max_object_count,
        object_count,
    ))
}

fn find_objects(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    object_count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let object_count = as_mut(object_count)?;
    let output = _from_raw_parts_mut(object, max_object_count as usize)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .find_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;

        let remaining = &operation.objects[operation.next..];
        let returned = remaining.len().min(max_object_count as usize);
        output[..returned].copy_from_slice(&remaining[..returned]);
        operation.next += returned;
        *object_count = returned as CK_ULONG;
        log!(2, "C_FindObjects returning {:?}", &output[..returned]);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_FindObjectsFinal called with {:?}", session_handle);
    map(find_objects_final(session_handle))
}

fn find_objects_final(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        ctx.find_operations
            .remove(&session_handle)
            .map(|_| ())
            .ok_or(CKR_OPERATION_NOT_INITIALIZED.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(type_: CK_ATTRIBUTE_TYPE, value: &mut [u8]) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_,
            pValue: value.as_mut_ptr().cast(),
            ulValueLen: value.len() as CK_ULONG,
        }
    }

    fn imported_data_object_id(template: &[CK_ATTRIBUTE]) -> Result<u32, Error> {
        match piv_data_import(template)? {
            PivImport::Data { object_id, .. } => Ok(object_id),
            _ => unreachable!(),
        }
    }

    #[test]
    fn piv_data_templates_resolve_equivalent_ykcs11_identifiers() {
        let mut value = [1];
        let mut cka_id = [27];
        let mut oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00];
        let mut tag = [0x5f, 0xc1, 0x02];
        let value_attribute = attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value);
        let id_attribute = attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut cka_id);
        let oid_attribute = attribute(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE, &mut oid);
        let tag_attribute = attribute(CKA_PKCS11RS_PIV_OBJECT_TAG, &mut tag);

        for identifiers in [
            vec![id_attribute],
            vec![oid_attribute],
            vec![tag_attribute],
            vec![id_attribute, oid_attribute, tag_attribute],
        ] {
            let mut template = vec![value_attribute];
            template.extend(identifiers);
            assert_eq!(imported_data_object_id(&template).unwrap(), 0x5f_c102);
        }
    }

    #[test]
    fn piv_data_templates_reject_mismatched_standard_identifiers() {
        let mut value = [1];
        let mut cka_id = [27];
        let mut ccc_oid = [
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x01, 0x81, 0x5b, 0x00,
        ];
        let template = [
            attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
            attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut cka_id),
            attribute(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE, &mut ccc_oid),
        ];
        let error = imported_data_object_id(&template).unwrap_err();
        assert_eq!(CK_RV::from(error), CKR_TEMPLATE_INCONSISTENT as CK_RV);
    }

    #[test]
    fn arbitrary_piv_data_tags_do_not_gain_standard_identifiers() {
        let mut value = [1];
        let mut tag = [0x5f, 0xff, 0x10];
        let template = [
            attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE, &mut value),
            attribute(CKA_PKCS11RS_PIV_OBJECT_TAG, &mut tag),
        ];
        let object = match piv_data_import(&template).unwrap() {
            PivImport::Data { object, .. } => object,
            _ => unreachable!(),
        };
        assert_eq!(object.attribute_value(CKA_ID as CK_ATTRIBUTE_TYPE), None);
        assert_eq!(
            object.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
            None
        );
        assert_eq!(
            object.attribute_value(CKA_PKCS11RS_PIV_OBJECT_TAG),
            Some(tag.to_vec())
        );
    }
}
