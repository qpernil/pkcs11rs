//! Exercise every provider PQC construction through the public PKCS #11 API.
use super::*;

#[derive(Clone, Copy, Debug)]
enum Backend {
    Software,
    YubiHsm,
    DeployedYubiHsm,
    #[cfg(all(feature = "embedded-virtual-yubikey", not(feature = "abi-tests")))]
    Piv,
}

struct Case {
    name: &'static str,
    generation: CK_MECHANISM_TYPE,
    operation: CK_MECHANISM_TYPE,
    parameter: Option<CK_ULONG>,
    public_length: usize,
    output_length: usize,
}

fn cases() -> [Case; 9] {
    [
        Case {
            name: "ML-DSA-44",
            generation: CKM_ML_DSA_KEY_PAIR_GEN as _,
            operation: CKM_ML_DSA as _,
            parameter: Some(CKP_ML_DSA_44 as _),
            public_length: 1312,
            output_length: 2420,
        },
        Case {
            name: "ML-DSA-65",
            generation: CKM_ML_DSA_KEY_PAIR_GEN as _,
            operation: CKM_ML_DSA as _,
            parameter: Some(CKP_ML_DSA_65 as _),
            public_length: 1952,
            output_length: 3309,
        },
        Case {
            name: "ML-DSA-87",
            generation: CKM_ML_DSA_KEY_PAIR_GEN as _,
            operation: CKM_ML_DSA as _,
            parameter: Some(CKP_ML_DSA_87 as _),
            public_length: 2592,
            output_length: 4627,
        },
        Case {
            name: "ML-KEM-512",
            generation: CKM_ML_KEM_KEY_PAIR_GEN as _,
            operation: CKM_ML_KEM as _,
            parameter: Some(CKP_ML_KEM_512 as _),
            public_length: 800,
            output_length: 768,
        },
        Case {
            name: "ML-KEM-768",
            generation: CKM_ML_KEM_KEY_PAIR_GEN as _,
            operation: CKM_ML_KEM as _,
            parameter: Some(CKP_ML_KEM_768 as _),
            public_length: 1184,
            output_length: 1088,
        },
        Case {
            name: "ML-KEM-1024",
            generation: CKM_ML_KEM_KEY_PAIR_GEN as _,
            operation: CKM_ML_KEM as _,
            parameter: Some(CKP_ML_KEM_1024 as _),
            public_length: 1568,
            output_length: 1568,
        },
        Case {
            name: "MLKEM768-P256",
            generation: crate::CKM_PKCS11RS_MLKEM768_P256_KEY_PAIR_GEN,
            operation: crate::CKM_PKCS11RS_MLKEM768_P256,
            parameter: None,
            public_length: 1249,
            output_length: 1153,
        },
        Case {
            name: "MLKEM768-X25519",
            generation: crate::CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN,
            operation: crate::CKM_PKCS11RS_MLKEM768_X25519,
            parameter: None,
            public_length: 1216,
            output_length: 1120,
        },
        Case {
            name: "MLKEM1024-P384",
            generation: crate::CKM_PKCS11RS_MLKEM1024_P384_KEY_PAIR_GEN,
            operation: crate::CKM_PKCS11RS_MLKEM1024_P384,
            parameter: None,
            public_length: 1665,
            output_length: 1665,
        },
    ]
}

fn login(session: CK_SESSION_HANDLE, role: CK_USER_TYPE, credential: &[u8]) {
    let mut credential = zeroize::Zeroizing::new(credential.to_vec());
    assert_eq!(
        crate::api::C_Login(
            session,
            role,
            credential.as_mut_ptr(),
            credential.len() as _
        ),
        CKR_OK as CK_RV
    );
}

fn read_value(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as _,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    let mut value = vec![0; attribute.ulValueLen as usize];
    attribute.pValue = value.as_mut_ptr().cast();
    assert_eq!(
        crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
        CKR_OK as CK_RV
    );
    value
}

fn generate(
    session: CK_SESSION_HANDLE,
    case: &Case,
    id: &mut [u8],
    token: bool,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mechanism = CK_MECHANISM {
        mechanism: case.generation,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut parameter = case.parameter.unwrap_or_default();
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut token = CK_BBOOL::from(token);
    let signing = case.operation == CKM_ML_DSA as CK_MECHANISM_TYPE;
    let mut public = vec![
        scalar_attribute(CKA_TOKEN as _, &mut token),
        scalar_attribute(
            if signing { CKA_VERIFY } else { CKA_ENCAPSULATE } as _,
            &mut yes,
        ),
        bytes_attribute(CKA_ID as _, id),
    ];
    if case.parameter.is_some() {
        public.push(scalar_attribute(CKA_PARAMETER_SET as _, &mut parameter));
    }
    let mut private = [
        scalar_attribute(CKA_TOKEN as _, &mut token),
        scalar_attribute(
            if signing { CKA_SIGN } else { CKA_DECAPSULATE } as _,
            &mut yes,
        ),
        bytes_attribute(CKA_ID as _, id),
    ];
    let (mut public_key, mut private_key) = (0, 0);
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public.as_mut_ptr(),
            public.len() as _,
            private.as_mut_ptr(),
            private.len() as _,
            &mut public_key,
            &mut private_key
        ),
        CKR_OK as CK_RV,
        "{} generation",
        case.name
    );
    assert_eq!(
        read_value(session, public_key).len(),
        case.public_length,
        "{} public encoding",
        case.name
    );
    (public_key, private_key)
}

fn assert_pure_signatures(
    session: CK_SESSION_HANDLE,
    public: CK_OBJECT_HANDLE,
    private: CK_OBJECT_HANDLE,
    signature_length: usize,
) {
    for context_length in [0, 255] {
        let mut context = vec![0x61; context_length];
        for hedge in [
            CKH_DETERMINISTIC_REQUIRED,
            CKH_HEDGE_REQUIRED,
            CKH_HEDGE_PREFERRED,
        ] {
            let mut parameters = CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: hedge as _,
                pContext: context.as_mut_ptr(),
                ulContextLen: context.len() as _,
            };
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_ML_DSA as _,
                pParameter: (&mut parameters as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast(),
                ulParameterLen: std::mem::size_of_val(&parameters) as _,
            };
            let mut message = b"PQC provider matrix".to_vec();
            assert_eq!(
                crate::api::C_SignInit(session, &mut mechanism, private),
                CKR_OK as CK_RV
            );
            let mut length = signature_length as CK_ULONG;
            let mut signature = vec![0; signature_length];
            assert_eq!(
                crate::api::C_Sign(
                    session,
                    message.as_mut_ptr(),
                    message.len() as _,
                    signature.as_mut_ptr(),
                    &mut length
                ),
                CKR_OK as CK_RV
            );
            assert_eq!(length as usize, signature_length);
            assert_eq!(
                crate::api::C_VerifyInit(session, &mut mechanism, public),
                CKR_OK as CK_RV
            );
            assert_eq!(
                crate::api::C_Verify(
                    session,
                    message.as_mut_ptr(),
                    message.len() as _,
                    signature.as_mut_ptr(),
                    length
                ),
                CKR_OK as CK_RV
            );
            // Multipart pure ML-DSA retains the full message; deterministic
            // signatures must still agree with the single-part operation.
            assert_eq!(
                crate::api::C_SignInit(session, &mut mechanism, private),
                CKR_OK as CK_RV
            );
            for part in message.chunks_mut(7) {
                assert_eq!(
                    crate::api::C_SignUpdate(session, part.as_mut_ptr(), part.len() as _),
                    CKR_OK as CK_RV
                );
            }
            let mut multipart = vec![0; signature_length];
            assert_eq!(
                crate::api::C_SignFinal(session, multipart.as_mut_ptr(), &mut length),
                CKR_OK as CK_RV
            );
            if hedge == CKH_DETERMINISTIC_REQUIRED {
                assert_eq!(signature, multipart);
            }
            assert_eq!(
                crate::api::C_VerifyInit(session, &mut mechanism, public),
                CKR_OK as CK_RV
            );
            for part in message.chunks_mut(5) {
                assert_eq!(
                    crate::api::C_VerifyUpdate(session, part.as_mut_ptr(), part.len() as _),
                    CKR_OK as CK_RV
                );
            }
            assert_eq!(
                crate::api::C_VerifyFinal(session, multipart.as_mut_ptr(), length),
                CKR_OK as CK_RV
            );
            signature[0] ^= 1;
            assert_eq!(
                crate::api::C_VerifyInit(session, &mut mechanism, public),
                CKR_OK as CK_RV
            );
            assert_eq!(
                crate::api::C_Verify(
                    session,
                    message.as_mut_ptr(),
                    message.len() as _,
                    signature.as_mut_ptr(),
                    length
                ),
                CKR_SIGNATURE_INVALID as CK_RV
            );
        }
    }
}

fn assert_kem(
    session: CK_SESSION_HANDLE,
    case: &Case,
    public: CK_OBJECT_HANDLE,
    private: CK_OBJECT_HANDLE,
) {
    let mut mechanism = CK_MECHANISM {
        mechanism: case.operation,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut no = CK_FALSE as CK_BBOOL;
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut template = [
        scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
        scalar_attribute(CKA_TOKEN as _, &mut no),
        scalar_attribute(CKA_SENSITIVE as _, &mut no),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut yes),
    ];
    let (mut length, mut encapsulated) = (0, 0);
    assert_eq!(
        crate::api::C_EncapsulateKey(
            session,
            &mut mechanism,
            public,
            template.as_mut_ptr(),
            template.len() as _,
            std::ptr::null_mut(),
            &mut length,
            &mut encapsulated
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(length as usize, case.output_length);
    assert_eq!(encapsulated, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    let mut ciphertext = vec![0; case.output_length];
    let mut short_length = (ciphertext.len() - 1) as CK_ULONG;
    assert_eq!(
        crate::api::C_EncapsulateKey(
            session,
            &mut mechanism,
            public,
            template.as_mut_ptr(),
            template.len() as _,
            ciphertext.as_mut_ptr(),
            &mut short_length,
            &mut encapsulated
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(short_length, length);
    assert_eq!(encapsulated, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    assert_eq!(
        crate::api::C_EncapsulateKey(
            session,
            &mut mechanism,
            public,
            template.as_mut_ptr(),
            template.len() as _,
            ciphertext.as_mut_ptr(),
            &mut length,
            &mut encapsulated
        ),
        CKR_OK as CK_RV
    );
    let mut decapsulated = 0;
    assert_eq!(
        crate::api::C_DecapsulateKey(
            session,
            &mut mechanism,
            private,
            template.as_mut_ptr(),
            template.len() as _,
            ciphertext.as_mut_ptr(),
            length,
            &mut decapsulated
        ),
        CKR_OK as CK_RV
    );
    let expected = read_value(session, encapsulated);
    assert_eq!(expected.len(), 32);
    assert_eq!(
        expected,
        read_value(session, decapsulated),
        "{} shared secret",
        case.name
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, decapsulated),
        CKR_OK as CK_RV
    );
    // Truncation must fail before publishing any derived secret.
    decapsulated = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_DecapsulateKey(
            session,
            &mut mechanism,
            private,
            template.as_mut_ptr(),
            template.len() as _,
            ciphertext.as_mut_ptr(),
            length - 1,
            &mut decapsulated
        ),
        CKR_ENCRYPTED_DATA_LEN_RANGE as CK_RV
    );
    assert_eq!(decapsulated, CK_INVALID_HANDLE as CK_OBJECT_HANDLE);
    // Corrupt only the ML-KEM ciphertext component, leaving the traditional
    // component valid in hybrid constructions: implicit rejection changes ss.
    ciphertext[0] ^= 1;
    assert_eq!(
        crate::api::C_DecapsulateKey(
            session,
            &mut mechanism,
            private,
            template.as_mut_ptr(),
            template.len() as _,
            ciphertext.as_mut_ptr(),
            length,
            &mut decapsulated
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(expected, read_value(session, decapsulated));
    for key in [encapsulated, decapsulated] {
        assert_eq!(crate::api::C_DestroyObject(session, key), CKR_OK as CK_RV);
    }
}

fn run_matrix(backend: Backend) {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut config = serde_json::json!({"version": 1, "hardware": {"discovery": false}, "platform": {"enabled": false}, "yubihsm": {"urls": []}, "ccid": {"applications": ["piv"]}});
    #[cfg(all(feature = "embedded-virtual-yubikey", not(feature = "abi-tests")))]
    if matches!(backend, Backend::Piv) {
        config["embedded"] = serde_json::json!({"readers": [{"id": "pqc-matrix", "name": "PQC matrix PIV", "serial": 77, "applets": ["piv"]}]});
    }
    if matches!(backend, Backend::DeployedYubiHsm) {
        let serial = std::env::var("PKCS11RS_PQC_SERIAL").expect("set PKCS11RS_PQC_SERIAL");
        let endpoint = std::env::var("PKCS11RS_PQC_ENDPOINT")
            .expect("set PKCS11RS_PQC_ENDPOINT to an HTTP URL or usb");
        config["slots"] = serde_json::json!({"serials": [serial]});
        config["hardware"]["discovery"] = (endpoint == "usb").into();
        config["platform"]["enabled"] = (std::env::var("PKCS11RS_PQC_AUTH_URI").is_ok()).into();
        config["yubihsm"]["urls"] = if endpoint == "usb" {
            serde_json::json!([])
        } else {
            serde_json::json!([endpoint])
        };
        // Serial filtering and PIV-only discovery exclude physical OpenPGP applets.
        config["ccid"]["applications"] = serde_json::json!(["piv"]);
    }
    assert_eq!(initialize_with_configuration(config), CKR_OK as CK_RV);
    let mut trust = None;
    let mut source_session = None;
    let (slot, session) = match backend {
        Backend::Software => {
            install_software_private_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
            (TEST_SLOT_ID, TEST_SESSION_HANDLE)
        }
        _ => {
            let slot = if matches!(backend, Backend::YubiHsm) {
                let (slot, entry) = crate::yubihsm::tests::make_yubihsm_native_hmac_test_slot();
                trust = Some(entry);
                install_test_slot_with_backend(0x484d, slot);
                0x484d
            } else {
                let mut count = 0;
                assert_eq!(
                    crate::api::C_GetSlotList(CK_TRUE as _, std::ptr::null_mut(), &mut count),
                    CKR_OK as CK_RV
                );
                let mut slots = vec![0; count as usize];
                assert_eq!(
                    crate::api::C_GetSlotList(CK_TRUE as _, slots.as_mut_ptr(), &mut count),
                    CKR_OK as CK_RV
                );
                if matches!(backend, Backend::DeployedYubiHsm) {
                    let serial = std::env::var("PKCS11RS_PQC_SERIAL").unwrap();
                    let label = format!("YubiHSM #{serial}");
                    if std::env::var("PKCS11RS_PQC_AUTH_URI").is_ok() {
                        for &id in &slots {
                            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
                            assert_eq!(crate::api::C_GetTokenInfo(id, &mut info), CKR_OK as CK_RV);
                            if String::from_utf8_lossy(&info.label).trim() == "Secure Enclave" {
                                let mut source = 0;
                                assert_eq!(
                                    crate::api::C_OpenSession(
                                        id,
                                        CKF_SERIAL_SESSION as _,
                                        std::ptr::null_mut(),
                                        None,
                                        &mut source
                                    ),
                                    CKR_OK as CK_RV
                                );
                                login(source, CKU_USER as _, b"");
                                source_session = Some(source);
                            }
                        }
                        assert!(
                            source_session.is_some(),
                            "platform credential source is unavailable"
                        );
                    }
                    let selected: Vec<_> = slots
                        .into_iter()
                        .filter(|&id| {
                            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
                            assert_eq!(crate::api::C_GetTokenInfo(id, &mut info), CKR_OK as CK_RV);
                            String::from_utf8_lossy(&info.label).trim() == label
                        })
                        .collect();
                    assert_eq!(selected.len(), 1, "expected the selected YubiHSM");
                    selected[0]
                } else {
                    assert_eq!(count, 1);
                    slots[0]
                }
            };
            let mut session = 0;
            assert_eq!(
                crate::api::C_OpenSession(
                    slot,
                    (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
                    std::ptr::null_mut(),
                    None,
                    &mut session
                ),
                CKR_OK as CK_RV
            );
            (slot, session)
        }
    };
    let piv = !matches!(
        backend,
        Backend::Software | Backend::YubiHsm | Backend::DeployedYubiHsm
    );
    if piv {
        login(
            session,
            CKU_SO as _,
            b"010203040506070801020304050607080102030405060708",
        );
    } else if matches!(backend, Backend::YubiHsm) {
        login(session, CKU_USER as _, b"0001password");
    }
    if matches!(backend, Backend::DeployedYubiHsm) {
        if let Ok(uri) = std::env::var("PKCS11RS_PQC_AUTH_URI") {
            let mut uri = uri.into_bytes();
            assert_eq!(
                crate::api::C_LoginUser(
                    session,
                    CKU_USER as _,
                    std::ptr::null_mut(),
                    0,
                    uri.as_mut_ptr(),
                    uri.len() as _
                ),
                CKR_OK as CK_RV
            );
        } else {
            assert_eq!(
                std::env::var("PKCS11RS_PQC_FACTORY_AUTH").as_deref(),
                Ok("1"),
                "explicitly select factory auth for a virtual test device"
            );
            login(session, CKU_USER as _, b"0001password");
        }
    }
    let mut cleanup = DeployedKeyCleanup {
        session,
        keys: Vec::new(),
        active: matches!(backend, Backend::DeployedYubiHsm),
    };
    let mut count = 0;
    assert_eq!(
        crate::C_GetMechanismList(slot, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut advertised = vec![0; count as usize];
    assert_eq!(
        crate::C_GetMechanismList(slot, advertised.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    let cases = cases();
    let mut keys = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        assert!(
            advertised.contains(&case.generation),
            "{backend:?} missing {} generation",
            case.name
        );
        assert!(
            advertised.contains(&case.operation),
            "{backend:?} missing {} operation",
            case.name
        );
        let mut id = if piv {
            vec![5 + index as u8]
        } else {
            (0x7e40 + index as u16).to_be_bytes().to_vec()
        };
        if matches!(backend, Backend::DeployedYubiHsm) {
            let mut template = [bytes_attribute(CKA_ID as _, &mut id)];
            assert_eq!(
                crate::api::C_FindObjectsInit(session, template.as_mut_ptr(), 1),
                CKR_OK as CK_RV
            );
            let (mut found, mut count) = (0, 0);
            assert_eq!(
                crate::api::C_FindObjects(session, &mut found, 1, &mut count),
                CKR_OK as CK_RV
            );
            assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
            assert_eq!(count, 0, "refusing to overwrite existing object ID");
        }
        keys.push(generate(
            session,
            case,
            &mut id,
            !matches!(backend, Backend::Software),
        ));
        if cleanup.active {
            cleanup.keys.push(keys.last().unwrap().1);
        }
    }
    if piv {
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        login(session, CKU_USER as _, b"123456");
    }
    for (case, &(public, private)) in cases.iter().zip(&keys) {
        eprintln!("PQC matrix {backend:?}: {}", case.name);
        if case.operation == CKM_ML_DSA as CK_MECHANISM_TYPE {
            assert_pure_signatures(session, public, private, case.output_length);
            key::assert_hash_ml_dsa_roundtrip(session, public, private);
            key::assert_module_hash_ml_dsa_roundtrip(session, public, private);
        } else {
            assert_kem(session, case, public, private);
        }
    }
    // Reject every mismatched pairing of the three concrete constructions.
    for (case_index, case) in cases.iter().enumerate().skip(6) {
        for (key_index, &(public, private)) in keys.iter().enumerate().skip(6) {
            if case_index == key_index {
                continue;
            }
            let mut mechanism = CK_MECHANISM {
                mechanism: case.operation,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            let (mut length, mut secret) = (0, 0);
            assert_eq!(
                crate::api::C_EncapsulateKey(
                    session,
                    &mut mechanism,
                    public,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut length,
                    &mut secret
                ),
                CKR_KEY_TYPE_INCONSISTENT as CK_RV
            );
            let mut ciphertext = vec![0; case.output_length];
            assert_eq!(
                crate::api::C_DecapsulateKey(
                    session,
                    &mut mechanism,
                    private,
                    std::ptr::null_mut(),
                    0,
                    ciphertext.as_mut_ptr(),
                    ciphertext.len() as _,
                    &mut secret
                ),
                CKR_KEY_TYPE_INCONSISTENT as CK_RV
            );
        }
    }
    if cleanup.active {
        for &private in &cleanup.keys {
            assert_eq!(
                crate::api::C_DestroyObject(session, private),
                CKR_OK as CK_RV,
                "delete temporary device key"
            );
        }
        cleanup.active = false;
    }
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    if let Some(source) = source_session {
        assert_eq!(crate::api::C_CloseSession(source), CKR_OK as CK_RV);
    }
    finalize_for_test();
    drop(trust);
}

#[test]
fn pqc_matrix_software() {
    run_matrix(Backend::Software);
}

#[test]
fn pqc_matrix_virtual_yubihsm_secure_channel() {
    run_matrix(Backend::YubiHsm);
}

#[test]
#[cfg(all(feature = "embedded-virtual-yubikey", not(feature = "abi-tests")))]
fn pqc_matrix_virtual_piv_apdus() {
    run_matrix(Backend::Piv);
}

// Clean up generated device keys even when an assertion unwinds.
struct DeployedKeyCleanup {
    session: CK_SESSION_HANDLE,
    keys: Vec<CK_OBJECT_HANDLE>,
    active: bool,
}
impl Drop for DeployedKeyCleanup {
    fn drop(&mut self) {
        if self.active {
            for &key in &self.keys {
                let result = crate::api::C_DestroyObject(self.session, key);
                if result != CKR_OK as CK_RV {
                    eprintln!("temporary PQC key cleanup returned {result:#x}");
                }
            }
        }
    }
}

#[test]
#[ignore = "requires an explicitly selected deployed HSM and enrolled authentication"]
fn pqc_matrix_deployed_yubihsm() {
    run_matrix(Backend::DeployedYubiHsm);
}
