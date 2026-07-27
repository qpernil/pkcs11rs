#[cfg(not(feature = "abi-tests"))]
use super::*;

#[cfg(not(feature = "abi-tests"))]
mod hardware_provisioning {
    use super::*;
    use p256::ecdsa::SigningKey;
    use std::rc::Rc;

    const ENABLE_ENV: &str = "PKCS11RS_TEST_PROVISION_ASYMMETRIC_HSMAUTH";
    const AUTHKEY_ID_ENV: &str = "PKCS11RS_TEST_YUBIHSM_AUTHKEY_ID";
    const TOUCH_ENABLE_ENV: &str = "PKCS11RS_TEST_PROVISION_TOUCH_ASYMMETRIC_HSMAUTH";
    const TOUCH_AUTHKEY_ID_ENV: &str = "PKCS11RS_TEST_YUBIHSM_TOUCH_AUTHKEY_ID";
    const SCP11B_ENABLE_ENV: &str = "PKCS11RS_TEST_PROVISION_SCP11B";
    const SCP11B_KVN_ENV: &str = "PKCS11RS_TEST_SCP11B_KVN";
    const RSA_WRAP_ENABLE_ENV: &str = "PKCS11RS_TEST_YUBIHSM_RSA_WRAP";
    const X25519_INTEROP_ENABLE_ENV: &str = "PKCS11RS_TEST_X25519_INTEROP";
    const DEFAULT_MANAGEMENT_KEY: &str = "00000000000000000000000000000000";
    const DEFAULT_PIV_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";
    const DEFAULT_PIV_PIN: &str = "123456";
    const DEFAULT_LABEL: &str = "pkcs11rs-asymmetric";
    const DEFAULT_TOUCH_LABEL: &str = "pkcs11rs-asymmetric-touch";
    const DEFAULT_CREDENTIAL_PASSWORD: &str = "password";
    const DEFAULT_ADMIN_ID: &str = "0001";
    const DEFAULT_ADMIN_PASSWORD: &str = "password";
    const AUTHENTICATION_KEY_DOMAINS: u16 = 0xffff;
    const SCP11B_TEST_CA_KEY: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL7CkZ7A1x1NWahBWRhsgefvFnA0fLI9OLgEJRyWsvSioAoGCCqGSM49
AwEHoUQDQgAEwh/eTK7LFECBbeTnetWWBsUjiJt+wV8Bbvwa5Hguiee07eo2J3Eu
ViNXydALTwAmo9VlKYPGrLh/DGD6qrrzeA==
-----END EC PRIVATE KEY-----
"#;

    fn environment(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_owned())
    }

    fn hex_u16(name: &str, value: &str) -> u16 {
        assert_eq!(
            value.len(),
            4,
            "{name} must contain exactly four hexadecimal characters"
        );
        u16::from_str_radix(value, 16)
            .unwrap_or_else(|_| panic!("{name} must contain exactly four hexadecimal characters"))
    }

    fn required_byte(name: &str) -> u8 {
        let value =
            std::env::var(name).unwrap_or_else(|_| panic!("{name} is required when provisioning"));
        let parsed = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse(), |value| u8::from_str_radix(value, 16));
        parsed.unwrap_or_else(|_| panic!("{name} must be a decimal or 0x-prefixed byte"))
    }

    fn scp11b_certificate_chain(public_point: &[u8], kvn: u8) -> Vec<Vec<u8>> {
        let ca_secret =
            p256::SecretKey::from_sec1_pem(std::str::from_utf8(SCP11B_TEST_CA_KEY).unwrap())
                .expect("invalid embedded SCP11B test CA key");
        let ca_key = SigningKey::from(ca_secret);
        let ca_name = "CN=pkcs11rs SCP11 test CA";
        let ca = crate::certificate_builder::p256_certificate(
            ca_key.verifying_key(),
            &ca_key,
            ca_name,
            ca_name,
            1,
            true,
        );
        let leaf_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_point)
            .expect("device returned an invalid P-256 public key");
        let leaf = crate::certificate_builder::p256_certificate(
            &leaf_key,
            &ca_key,
            &format!("CN=pkcs11rs SCP11B KVN {kvn}"),
            ca_name,
            u32::from(kvn) + 1,
            false,
        );
        vec![ca, leaf]
    }

    fn select_connector(
        connectors: Vec<Rc<dyn crate::Connector>>,
        selector_name: &str,
        kind: &str,
    ) -> Rc<dyn crate::Connector> {
        let selector = std::env::var(selector_name).ok();
        let mut matches = connectors.into_iter().filter(|connector| {
            selector.as_ref().is_none_or(|selector| {
                connector.serial() == selector || connector.name() == *selector
            })
        });
        let connector = matches
            .next()
            .unwrap_or_else(|| panic!("no {kind} matched {selector_name}={selector:?}"));
        assert!(
            matches.next().is_none(),
            "multiple {kind} devices matched; set {selector_name} to a serial number or full device name"
        );
        connector
    }

    fn select_yubihsm_slot() -> CK_SLOT_ID {
        let selector = std::env::var("PKCS11RS_TEST_YUBIHSM_SOURCE").ok();
        crate::with_context(|context| {
            context.init()?;
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let mut matches = slot_contexts.iter().filter_map(|(slot_id, child)| {
                let child = child.lock().ok()?;
                (child.slot.kind() == crate::SlotKind::YubiHsm
                    && child.slot.is_present()
                    && selector.as_ref().is_none_or(|selector| {
                        child.slot.serial() == selector || child.slot.name() == *selector
                    }))
                .then_some(*slot_id)
            });
            let slot_id = matches.next().ok_or(CKR_SLOT_ID_INVALID)?;
            if matches.next().is_some() {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            Ok(slot_id)
        })
        .unwrap_or_else(|error| {
            panic!(
                "expected exactly one present YubiHSM matching PKCS11RS_TEST_YUBIHSM_SOURCE={selector:?}: {error:?}"
            )
        })
    }

    fn select_piv_slot() -> CK_SLOT_ID {
        let selector = std::env::var("PKCS11RS_TEST_PIV_SOURCE").ok();
        crate::with_context(|context| {
            context.init()?;
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let mut matches = slot_contexts.iter().filter_map(|(slot_id, child)| {
                let child = child.lock().ok()?;
                (child.slot.kind()
                    == crate::SlotKind::Ccid(crate::CcidApplication::Piv)
                    && child.slot.is_present()
                    && selector.as_ref().is_none_or(|selector| {
                        child.slot.serial() == selector || child.slot.name() == *selector
                    }))
                .then_some(*slot_id)
            });
            let slot_id = matches.next().ok_or(CKR_SLOT_ID_INVALID)?;
            if matches.next().is_some() {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            Ok(slot_id)
        })
        .unwrap_or_else(|error| {
            panic!(
                "expected exactly one present PIV slot matching PKCS11RS_TEST_PIV_SOURCE={selector:?}: {error:?}"
            )
        })
    }

    fn select_two_yubihsm_slots() -> Vec<(CK_SLOT_ID, String)> {
        let mut count = 0;
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count,),
            CKR_OK as CK_RV
        );
        let mut slot_ids = vec![0; count as usize];
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slot_ids.as_mut_ptr(), &mut count,),
            CKR_OK as CK_RV
        );

        let slots = slot_ids
            .into_iter()
            .filter_map(|slot_id| {
                let mut info = CK_SLOT_INFO {
                    slotDescription: [0; 64],
                    manufacturerID: [0; 32],
                    flags: 0,
                    hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                    firmwareVersion: CK_VERSION { major: 0, minor: 0 },
                };
                assert_eq!(
                    crate::api::C_GetSlotInfo(slot_id, &mut info),
                    CKR_OK as CK_RV
                );
                let description = String::from_utf8_lossy(&info.slotDescription)
                    .trim_end()
                    .to_owned();
                description
                    .starts_with("Yubico YubiHSM ")
                    .then_some((slot_id, description))
            })
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(
            slots.len(),
            2,
            "expected at least two present YubiHSM slots for concurrency testing"
        );
        slots
    }

    fn open_hardware_session(slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        session
    }

    #[test]
    #[ignore = "runs many concurrent PKCS #11 operations against two present YubiHSM hardware slots"]
    fn concurrent_yubihsm_hardware_slots_survive_many_threaded_operations() {
        const THREAD_COUNT: usize = 16;
        const CALLS_PER_THREAD: usize = 100;
        const OUTPUT_LENGTH: usize = 32;

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );

        let slots = select_two_yubihsm_slots();
        eprintln!(
            "concurrency hardware test uses slot {} {} and slot {} {}",
            slots[0].0, slots[0].1, slots[1].0, slots[1].1
        );

        let pin = format!("{DEFAULT_ADMIN_ID}{DEFAULT_ADMIN_PASSWORD}");

        let control_sessions = [
            open_hardware_session(slots[0].0),
            open_hardware_session(slots[1].0),
        ];
        for slot_index in 0..2 {
            let mut pin = pin.as_bytes().to_vec();
            assert_eq!(
                crate::api::C_Login(
                    control_sessions[slot_index],
                    CKU_USER as CK_USER_TYPE,
                    pin.as_mut_ptr(),
                    pin.len() as CK_ULONG,
                ),
                CKR_OK as CK_RV,
                "failed to log in to {}",
                slots[slot_index].1
            );
        }

        let sessions = (0..THREAD_COUNT)
            .map(|thread_index| {
                let slot_index = thread_index % 2;
                (slot_index, open_hardware_session(slots[slot_index].0))
            })
            .collect::<Vec<_>>();
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let start = std::sync::Arc::new(std::sync::Barrier::new(THREAD_COUNT));
        std::thread::scope(|scope| {
            let workers = sessions
                .into_iter()
                .map(|(slot_index, session)| {
                    let completed = completed.clone();
                    let start = start.clone();
                    let slot_name = slots[slot_index].1.clone();
                    scope.spawn(move || {
                        start.wait();
                        let mut previous = None;
                        for _ in 0..CALLS_PER_THREAD {
                            let mut output = [0u8; OUTPUT_LENGTH];
                            assert_eq!(
                                crate::api::C_GenerateRandom(
                                    session,
                                    output.as_mut_ptr(),
                                    output.len() as CK_ULONG,
                                ),
                                CKR_OK as CK_RV,
                                "random generation failed on {}",
                                slot_name
                            );
                            if let Some(previous) = previous {
                                assert_ne!(
                                    output, previous,
                                    "YubiHSM returned the same random block twice"
                                );
                            }
                            previous = Some(output);
                            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().unwrap();
            }
        });

        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            THREAD_COUNT * CALLS_PER_THREAD
        );
        for session in control_sessions {
            assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        }
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    #[test]
    #[ignore = "generates, wraps, destroys, restores, and cleans up persistent keys on a live YubiHSM"]
    fn generated_ec_key_round_trips_through_private_rsa_wrap_key_on_hardware() {
        if std::env::var(RSA_WRAP_ENABLE_ENV).as_deref() != Ok("1") {
            eprintln!("skipped hardware wrap test; set {RSA_WRAP_ENABLE_ENV}=1 to enable it");
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot_id = select_yubihsm_slot();
        let admin_id = hex_u16(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_ID",
            &environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
        );
        let admin_password = environment(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
            DEFAULT_ADMIN_PASSWORD,
        );
        let pin = format!("{admin_id:04x}{admin_password}");
        let result = generated_ec_private_rsa_wrap_round_trip(slot_id, pin.as_bytes());
        let finalize = crate::api::C_Finalize(std::ptr::null_mut());
        result.unwrap();
        assert_eq!(finalize, CKR_OK as CK_RV);
    }

    #[test]
    #[ignore = "generates and retains persistent X25519 keys on a live YubiKey PIV applet and YubiHSM"]
    fn piv_and_yubihsm_x25519_hardware_keys_derive_the_same_secret() {
        if std::env::var(X25519_INTEROP_ENABLE_ENV).as_deref() != Ok("1") {
            eprintln!(
                "skipped X25519 interoperability test; set {X25519_INTEROP_ENABLE_ENV}=1 to enable it"
            );
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );

        let piv_slot_id = select_piv_slot();
        let yubihsm_slot_id = select_yubihsm_slot();
        let piv_session = open_hardware_session(piv_slot_id);
        let yubihsm_session = open_hardware_session(yubihsm_slot_id);

        let piv_key_id_text = environment("PKCS11RS_TEST_PIV_X25519_CKA_ID", "24");
        let piv_key_id = piv_key_id_text
            .strip_prefix("0x")
            .or_else(|| piv_key_id_text.strip_prefix("0X"))
            .map_or_else(
                || piv_key_id_text.parse::<u8>(),
                |value| u8::from_str_radix(value, 16),
            )
            .expect("PKCS11RS_TEST_PIV_X25519_CKA_ID must be a decimal or 0x-prefixed byte");
        assert!(
            crate::piv::Slot::from_cka_id(piv_key_id).is_some(),
            "PKCS11RS_TEST_PIV_X25519_CKA_ID does not identify a PIV key slot"
        );

        let existing = find_hardware_object(
            piv_session,
            CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            &[piv_key_id],
        );
        assert!(
            existing.is_none(),
            "PIV CKA_ID {piv_key_id} is occupied; choose an empty PKCS11RS_TEST_PIV_X25519_CKA_ID"
        );

        let yubihsm_pin = format!(
            "{}{}",
            environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
            environment(
                "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
                DEFAULT_ADMIN_PASSWORD
            )
        );
        login_hardware_session(yubihsm_session, CKU_USER as CK_USER_TYPE, &yubihsm_pin);

        let piv_management_key = environment(
            "PKCS11RS_TEST_PIV_MANAGEMENT_KEY",
            DEFAULT_PIV_MANAGEMENT_KEY,
        );
        login_hardware_session(piv_session, CKU_SO as CK_USER_TYPE, &piv_management_key);

        let _ = generate_hardware_x25519_key_pair(piv_session, &[piv_key_id], "PIV X25519 interop");
        assert_eq!(crate::api::C_Logout(piv_session), CKR_OK as CK_RV);

        let (yubihsm_public, yubihsm_private) =
            generate_hardware_x25519_key_pair(yubihsm_session, &[0, 0], "PIV X25519 interop");
        let yubihsm_key_id = read_hardware_attribute(
            yubihsm_session,
            yubihsm_private,
            CKA_ID as CK_ATTRIBUTE_TYPE,
        );
        assert_eq!(
            yubihsm_key_id.len(),
            2,
            "YubiHSM returned a noncanonical X25519 CKA_ID"
        );
        assert_ne!(
            yubihsm_key_id,
            [0, 0],
            "YubiHSM did not auto-allocate the X25519 key ID"
        );
        let yubihsm_object_id = u16::from_be_bytes(yubihsm_key_id.as_slice().try_into().unwrap());

        let piv_pin = environment("PKCS11RS_TEST_PIV_PIN", DEFAULT_PIV_PIN);
        login_hardware_session(piv_session, CKU_USER as CK_USER_TYPE, &piv_pin);
        let piv_private = find_hardware_object(
            piv_session,
            CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            &[piv_key_id],
        )
        .expect("generated PIV X25519 private key disappeared after login");
        let piv_public = find_hardware_object(
            piv_session,
            CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            &[piv_key_id],
        )
        .expect("generated PIV X25519 public key disappeared after login");

        let piv_point =
            read_hardware_attribute(piv_session, piv_public, CKA_EC_POINT as CK_ATTRIBUTE_TYPE);
        let yubihsm_point = read_hardware_attribute(
            yubihsm_session,
            yubihsm_public,
            CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
        );
        let from_piv = derive_hardware_x25519(piv_session, piv_private, &yubihsm_point);
        let from_yubihsm = derive_hardware_x25519(yubihsm_session, yubihsm_private, &piv_point);
        assert_eq!(from_piv.len(), 32);
        assert_eq!(from_piv, from_yubihsm);

        assert_eq!(crate::api::C_Logout(piv_session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_Logout(yubihsm_session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(piv_session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(yubihsm_session), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );

        eprintln!(
            "retained X25519 keys at PIV CKA_ID {piv_key_id} and YubiHSM CKA_ID {yubihsm_object_id:04x}"
        );
    }

    fn login_hardware_session(
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        credential: &str,
    ) {
        let mut credential = credential.as_bytes().to_vec();
        assert_eq!(
            crate::api::C_Login(
                session,
                user_type,
                credential.as_mut_ptr(),
                credential.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
    }

    fn find_hardware_object(
        session: CK_SESSION_HANDLE,
        class: CK_OBJECT_CLASS,
        id: &[u8],
    ) -> Option<CK_OBJECT_HANDLE> {
        let mut class = class;
        let mut id = id.to_vec();
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
                pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: id.as_mut_ptr().cast(),
                ulValueLen: id.len() as CK_ULONG,
            },
        ];
        assert_eq!(
            crate::api::C_FindObjectsInit(
                session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
        let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut count = 0;
        assert_eq!(
            crate::api::C_FindObjects(session, &mut object, 1, &mut count),
            CKR_OK as CK_RV
        );
        assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
        (count == 1).then_some(object)
    }

    fn generate_hardware_x25519_key_pair(
        session: CK_SESSION_HANDLE,
        id: &[u8],
        label: &str,
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let mut parameters = crate::openpgp::Curve::X25519.oid().to_vec();
        let mut id = id.to_vec();
        let mut label = label.as_bytes().to_vec();
        let mut token = CK_TRUE as CK_BBOOL;
        let mut derive = CK_TRUE as CK_BBOOL;
        let mut public_template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
                pValue: parameters.as_mut_ptr().cast(),
                ulValueLen: parameters.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: id.as_mut_ptr().cast(),
                ulValueLen: id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
                pValue: label.as_mut_ptr().cast(),
                ulValueLen: label.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let mut private_template = [
            CK_ATTRIBUTE {
                type_: CKA_ID as CK_ATTRIBUTE_TYPE,
                pValue: id.as_mut_ptr().cast(),
                ulValueLen: id.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
                pValue: label.as_mut_ptr().cast(),
                ulValueLen: label.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE as CK_ATTRIBUTE_TYPE,
                pValue: (&mut derive as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as CK_ULONG,
                private_template.as_mut_ptr(),
                private_template.len() as CK_ULONG,
                &mut public,
                &mut private,
            ),
            CKR_OK as CK_RV
        );
        (public, private)
    }

    fn read_hardware_attribute(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        attribute_type: CK_ATTRIBUTE_TYPE,
    ) -> Vec<u8> {
        let mut attribute = CK_ATTRIBUTE {
            type_: attribute_type,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        assert_ne!(attribute.ulValueLen, CK_UNAVAILABLE_INFORMATION as CK_ULONG);
        let mut value = vec![0; attribute.ulValueLen as usize];
        attribute.pValue = value.as_mut_ptr().cast();
        assert_eq!(
            crate::api::C_GetAttributeValue(session, object, &mut attribute, 1),
            CKR_OK as CK_RV
        );
        value.truncate(attribute.ulValueLen as usize);
        value
    }

    fn derive_hardware_x25519(
        session: CK_SESSION_HANDLE,
        private: CK_OBJECT_HANDLE,
        peer_point: &[u8],
    ) -> Vec<u8> {
        let mut peer_point = peer_point.to_vec();
        let mut parameters = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_EC_KDF_TYPE,
            pSharedData: std::ptr::null_mut(),
            ulSharedDataLen: 0,
            pPublicData: peer_point.as_mut_ptr(),
            ulPublicDataLen: peer_point.len() as CK_ULONG,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
            pParameter: (&mut parameters as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
        };
        let mut derived = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_DeriveKey(
                session,
                &mut mechanism,
                private,
                std::ptr::null_mut(),
                0,
                &mut derived,
            ),
            CKR_OK as CK_RV
        );
        read_hardware_attribute(session, derived, CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }

    #[test]
    fn provisioning_connectors_are_exposed_by_the_matching_slots() {
        let connector = || -> Rc<dyn crate::Connector> {
            Rc::new(SelectableConnector {
                present: std::cell::Cell::new(true),
                select_ok: std::cell::Cell::new(true),
                serial: "PROVISION",
            })
        };
        let hsmauth_aid = crate::hsmauth::AID.to_vec();
        let hsmauth = crate::HsmAuthSlot::new(connector(), hsmauth_aid);
        assert!(crate::Slot::hsmauth_provisioning_connector(&hsmauth).is_some());

        let issuer_sd = crate::IssuerSecurityDomainSlot::new(
            connector(),
            crate::DEFAULT_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
        );
        assert!(crate::Slot::hsmauth_provisioning_connector(&issuer_sd).is_none());
        assert!(crate::Slot::security_domain_provisioning_connector(&issuer_sd).is_some());

        let yubihsm = crate::YubiHsmSlot::new(connector(), (2, 4, 0), Vec::new());
        assert!(crate::Slot::yubihsm_provisioning_connector(&yubihsm).is_some());
    }

    #[test]
    #[ignore = "provisions a persistent SCP11B key and certificate chain on a live YubiKey"]
    fn provisions_and_authenticates_scp11b_key() {
        if std::env::var(SCP11B_ENABLE_ENV).as_deref() != Ok("1") {
            eprintln!("skipped persistent provisioning; set {SCP11B_ENABLE_ENV}=1 to enable it");
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        crate::initialize_debug_logging().expect("invalid PKCS11RS_DEBUG level");

        let protocol = std::env::var("PKCS11RS_CCID_SECURE_CHANNEL")
            .expect("PKCS11RS_CCID_SECURE_CHANNEL must configure an OCE-authenticated channel");
        assert!(
            matches!(
                protocol.to_ascii_lowercase().as_str(),
                "scp03" | "scp11a" | "scp11c"
            ),
            "SCP11B provisioning requires SCP03, SCP11A, or SCP11C authentication"
        );
        let kvn = required_byte(SCP11B_KVN_ENV);
        assert_ne!(kvn, 0, "{SCP11B_KVN_ENV} must not be zero");
        assert!(kvn < 0x80, "{SCP11B_KVN_ENV} must be less than 0x80");
        let key_ref = crate::security_domain::KeyRef {
            kid: crate::security_domain::KID_SCP11B,
            kvn,
        };

        let context = crate::ModuleContext::new().expect("failed to create hardware context");
        context.init().unwrap();
        let slot_contexts = context.slot_contexts.read().unwrap();
        let issuer_sd = select_connector(
            slot_contexts
                .values()
                .filter_map(|child| {
                    child
                        .lock()
                        .ok()?
                        .slot
                        .security_domain_provisioning_connector()
                })
                .collect(),
            "PKCS11RS_TEST_ISSUER_SD_SOURCE",
            "Issuer SD applet",
        );
        issuer_sd
            .establish_secure_channel(&crate::configured_issuer_security_domain_aid().unwrap())
            .expect("failed to establish the Issuer SD provisioning channel");

        let before = crate::SecurityDomainClient
            .discover(issuer_sd.as_ref())
            .expect("failed to inspect Issuer SD keys before provisioning");
        assert!(
            !before.keys.iter().any(|key| key.key_ref == key_ref),
            "SCP11B KVN {kvn} already exists; choose a fresh {SCP11B_KVN_ENV}"
        );

        let public_point = issuer_sd
            .security_domain_scp11_administration(&crate::Scp11Administration::GenerateKey {
                key_ref,
                replace_kvn: 0,
                curve: 0,
            })
            .expect("failed to generate the SCP11B P-256 key");
        assert_eq!(public_point.len(), 65);
        assert_eq!(public_point[0], 0x04);

        let certificates = scp11b_certificate_chain(&public_point, kvn);
        issuer_sd
            .security_domain_scp11_administration(
                &crate::Scp11Administration::StoreCertificateChain {
                    key_ref,
                    certificates: certificates.clone(),
                },
            )
            .expect("failed to store the SCP11B certificate chain");

        let after = crate::SecurityDomainClient
            .discover(issuer_sd.as_ref())
            .expect("failed to rediscover the provisioned SCP11B key");
        assert!(after.keys.iter().any(|key| key.key_ref == key_ref));
        assert!(after
            .certificate_bundles
            .iter()
            .any(|bundle| { bundle.key_ref == key_ref && bundle.certificates == certificates }));

        let keys = crate::Scp11KeySet::scp11b_from_certificates(
            kvn,
            &certificates[1..],
            &certificates[..1],
        )
        .expect("the generated SD certificate chain did not validate");
        issuer_sd.clear_secure_channel();
        let mut session = keys
            .authenticate_selected(issuer_sd.as_ref())
            .expect("failed to establish SCP11B with the generated key");
        let command = crate::CommandApdu {
            cla: 0,
            ins: 0xca,
            p1: 0,
            p2: 0xe0,
            data: Vec::new(),
            le: Some(256),
            extended: false,
        };
        let response = session
            .transmit(issuer_sd.as_ref(), &command)
            .and_then(|response| response.require_success(&command))
            .expect("SCP11B-protected Issuer SD GET DATA failed");
        assert!(!response.data.is_empty());

        eprintln!(
            "provisioned persistent SCP11B P-256 key and certificate chain at KID 0x13 KVN {kvn}"
        );
    }

    #[test]
    #[ignore = "provisions persistent keys on a live YubiKey and YubiHSM"]
    fn provisions_asymmetric_hsmauth_credential_on_yubihsm() {
        provision_asymmetric_hsmauth_credential(HsmAuthProvisioningCase {
            enable_env: ENABLE_ENV,
            authkey_id_env: AUTHKEY_ID_ENV,
            label_env: "PKCS11RS_TEST_HSMAUTH_LABEL",
            default_label: DEFAULT_LABEL,
            touch_required: false,
        });
    }

    #[test]
    #[ignore = "provisions persistent touch-required keys on a live YubiKey and YubiHSM"]
    fn provisions_touch_required_asymmetric_hsmauth_credential_on_yubihsm() {
        provision_asymmetric_hsmauth_credential(HsmAuthProvisioningCase {
            enable_env: TOUCH_ENABLE_ENV,
            authkey_id_env: TOUCH_AUTHKEY_ID_ENV,
            label_env: "PKCS11RS_TEST_HSMAUTH_TOUCH_LABEL",
            default_label: DEFAULT_TOUCH_LABEL,
            touch_required: true,
        });
    }

    struct HsmAuthProvisioningCase {
        enable_env: &'static str,
        authkey_id_env: &'static str,
        label_env: &'static str,
        default_label: &'static str,
        touch_required: bool,
    }

    fn provision_asymmetric_hsmauth_credential(case: HsmAuthProvisioningCase) {
        if std::env::var(case.enable_env).as_deref() != Ok("1") {
            eprintln!(
                "skipped persistent provisioning; set {}=1 to enable it",
                case.enable_env
            );
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        crate::initialize_debug_logging().expect("invalid PKCS11RS_DEBUG level");

        let authkey_id = hex_u16(
            case.authkey_id_env,
            &std::env::var(case.authkey_id_env).unwrap_or_else(|_| {
                panic!("{} is required when provisioning", case.authkey_id_env)
            }),
        );
        assert_ne!(authkey_id, 0, "{} must not be zero", case.authkey_id_env);
        let admin_id = hex_u16(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_ID",
            &environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
        );
        let label = environment(case.label_env, case.default_label);
        assert!(
            !label.is_empty() && label.len() <= 40,
            "label must be 1..=40 bytes"
        );
        let credential_password = crate::Zeroizing::new(environment(
            "PKCS11RS_TEST_HSMAUTH_CREDENTIAL_PASSWORD",
            DEFAULT_CREDENTIAL_PASSWORD,
        ));
        assert!(
            credential_password.len() <= 16,
            "YubiHSM Auth credential password must not exceed 16 bytes"
        );
        let management_key = crate::Zeroizing::new(
            crate::parse_hex(&environment(
                "PKCS11RS_TEST_HSMAUTH_MANAGEMENT_KEY",
                DEFAULT_MANAGEMENT_KEY,
            ))
            .expect("invalid YubiHSM Auth management key encoding"),
        );
        assert_eq!(management_key.len(), 16, "management key must be 16 bytes");
        let admin_password = crate::Zeroizing::new(environment(
            "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
            DEFAULT_ADMIN_PASSWORD,
        ));
        assert!(
            (8..=64).contains(&admin_password.len()),
            "YubiHSM admin password must be 8..=64 bytes"
        );

        let context = crate::ModuleContext::new().expect("failed to create hardware context");
        context.init().unwrap();
        let slot_contexts = context.slot_contexts.read().unwrap();
        let hsmauth = select_connector(
            slot_contexts
                .values()
                .filter_map(|child| child.lock().ok()?.slot.hsmauth_provisioning_connector())
                .collect(),
            "PKCS11RS_TEST_HSMAUTH_SOURCE",
            "YubiHSM Auth applet",
        );
        let yubihsm = select_connector(
            slot_contexts
                .values()
                .filter_map(|child| child.lock().ok()?.slot.yubihsm_provisioning_connector())
                .collect(),
            "PKCS11RS_TEST_YUBIHSM_SOURCE",
            "YubiHSM",
        );

        let credentials = crate::HsmAuthClient
            .list_credentials(hsmauth.as_ref())
            .expect("failed to list YubiHSM Auth credentials");
        let existing_credential = credentials
            .into_iter()
            .find(|credential| credential.label == label);
        if let Some(credential) = &existing_credential {
            assert_eq!(
                credential.algorithm,
                crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
                "existing YubiHSM Auth credential {label:?} is not asymmetric P-256"
            );
            assert_eq!(
                credential.touch_required, case.touch_required,
                "existing YubiHSM Auth credential {label:?} has the wrong touch policy"
            );
        }

        let (mut admin_session, _) = crate::YubiHsmSecureSession::authenticate_direct(
            yubihsm.as_ref(),
            admin_id,
            admin_password.as_bytes(),
            None,
            None,
        )
        .expect("failed to authenticate to the YubiHSM provisioning key");
        let existing_key = (|| -> Result<Option<crate::YubiHsmObjectInfo>, crate::Error> {
            let response = admin_session.send_command(
                yubihsm.as_ref(),
                &crate::YubiHsmCommand::list_objects(&[
                    crate::yubihsm::ObjectFilter::Id(authkey_id),
                    crate::yubihsm::ObjectFilter::Type(crate::YUBIHSM_AUTHENTICATION_KEY),
                ])?,
            )?;
            let entries = crate::parse_yubihsm_object_list(&response)?;
            match entries.as_slice() {
                [] => Ok(None),
                [entry] => crate::YubiHsmObjectInfo::parse(&admin_session.send_command(
                    yubihsm.as_ref(),
                    &crate::YubiHsmCommand::get_object_info(entry.id, entry.object_type),
                )?)
                .map(Some),
                _ => Err(crate::CKR_DEVICE_ERROR.into()),
            }
        })();
        let preflight_close =
            admin_session.send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session());
        let existing_key = existing_key
            .expect("failed to query the target YubiHSM authentication-key ID and metadata");
        preflight_close.expect("failed to close the YubiHSM preflight session");
        if let Some(info) = &existing_key {
            assert_eq!(
                info.label, label,
                "target YubiHSM object ID has another label"
            );
            assert_eq!(
                info.algorithm,
                crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
                "target YubiHSM object is not an asymmetric P-256 authentication key"
            );
        }

        if existing_key.is_some() {
            let (mut admin_session, _) = crate::YubiHsmSecureSession::authenticate_direct(
                yubihsm.as_ref(),
                admin_id,
                admin_password.as_bytes(),
                None,
                None,
            )
            .expect("failed to reopen the YubiHSM provisioning session for cleanup");
            let deletion = admin_session
                .send_command(
                    yubihsm.as_ref(),
                    &crate::YubiHsmCommand::delete_object(
                        authkey_id,
                        crate::YUBIHSM_AUTHENTICATION_KEY,
                    ),
                )
                .and_then(|response| {
                    if response.is_empty() {
                        Ok(())
                    } else {
                        Err(crate::CKR_DEVICE_ERROR.into())
                    }
                });
            let cleanup_close = admin_session
                .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session());
            deletion.expect("failed to delete the prior YubiHSM authentication key");
            cleanup_close.expect("failed to close the YubiHSM cleanup session");
            eprintln!("deleted prior YubiHSM authentication key {authkey_id:04x}");
        }

        if existing_credential.is_some() {
            crate::HsmAuthClient
                .delete_credential(hsmauth.as_ref(), management_key.as_slice(), &label)
                .expect("failed to delete the prior YubiHSM Auth credential");
            eprintln!("deleted prior YubiHSM Auth credential {label:?}");
        }

        crate::HsmAuthClient
            .put_asymmetric_credential(
                hsmauth.as_ref(),
                management_key.as_slice(),
                &label,
                None,
                credential_password.as_bytes(),
                case.touch_required,
            )
            .expect("failed to generate the YubiHSM Auth asymmetric credential");
        let public_key = crate::HsmAuthClient
            .get_public_key(hsmauth.as_ref(), &label)
            .expect("failed to read the generated YubiHSM Auth public key");
        let public_key = public_key
            .strip_prefix(&[0x04])
            .expect("YubiHSM Auth returned a non-SEC1 P-256 public key");
        assert_eq!(public_key.len(), 64);

        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id: authkey_id,
                label: &label,
                domains: AUTHENTICATION_KEY_DOMAINS,
                capabilities: [0; 8],
                algorithm: crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: [0; 8],
        };
        let command = crate::YubiHsmCommand::put_delegated_object(
            crate::YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            public_key,
        )
        .expect("failed to encode the asymmetric authentication key");
        let (mut admin_session, _) = crate::YubiHsmSecureSession::authenticate_direct(
            yubihsm.as_ref(),
            admin_id,
            admin_password.as_bytes(),
            None,
            None,
        )
        .expect("failed to reopen the YubiHSM provisioning session");
        let installed = (|| -> Result<(u16, crate::YubiHsmObjectInfo), crate::Error> {
            let installed_id = admin_session
                .send_command(yubihsm.as_ref(), &command)
                .and_then(|response| crate::parse_yubihsm_object_id(&response))?;
            let info = admin_session
                .send_command(
                    yubihsm.as_ref(),
                    &crate::YubiHsmCommand::get_object_info(
                        installed_id,
                        crate::YUBIHSM_AUTHENTICATION_KEY,
                    ),
                )
                .and_then(|response| crate::YubiHsmObjectInfo::parse(&response))?;
            Ok((installed_id, info))
        })();
        let provisioning_close =
            admin_session.send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session());
        let (installed_id, installed_info) =
            installed.expect("failed to install the asymmetric authentication key in the YubiHSM");
        provisioning_close.expect("failed to close the YubiHSM provisioning session");
        assert_eq!(installed_id, authkey_id);
        assert_eq!(installed_info.domains, AUTHENTICATION_KEY_DOMAINS);

        let info = crate::HsmAuthClient
            .discover(hsmauth.as_ref())
            .expect("failed to rediscover the generated YubiHSM Auth credential");
        let credential = info
            .credentials
            .into_iter()
            .find(|credential| credential.label == label)
            .expect("generated YubiHSM Auth credential was not rediscovered");
        assert_eq!(credential.touch_required, case.touch_required);
        let mut session = crate::HsmAuthProvider {
            connector: hsmauth,
            credential,
            version: info.version,
            trust_prefix: None,
        }
        .authenticate(yubihsm.as_ref(), authkey_id, credential_password.as_bytes())
        .expect("the provisioned asymmetric YubiHSM Auth pair could not authenticate");
        session
            .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session())
            .expect("failed to close the verification session");

        eprintln!(
            "provisioned persistent YubiHSM Auth credential {label:?} (touch required {}) and YubiHSM authentication key {authkey_id:04x}",
            case.touch_required
        );
    }
}

#[cfg(not(feature = "abi-tests"))]
mod fido2_hardware {
    use super::*;

    const CURRENT_PIN_ENV: &str = "PKCS11RS_FIDO2_TEST_PIN";
    const NEW_PIN_ENV: &str = "PKCS11RS_FIDO2_NEW_PIN";

    fn fido2_slot_id() -> CK_SLOT_ID {
        let selector = std::env::var("PKCS11RS_FIDO2_TEST_SOURCE").ok();
        crate::with_context(|context| {
            context.init()?;
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let mut matches = slot_contexts.iter().filter_map(|(slot_id, child)| {
                let child = child.lock().ok()?;
                (child.slot.kind()
                    == crate::SlotKind::Ccid(crate::CcidApplication::Fido2)
                    && selector.as_ref().is_none_or(|selector| {
                        child.slot.serial() == selector || child.slot.name() == *selector
                    }))
                .then_some(*slot_id)
            });
            let slot_id = matches.next().ok_or(CKR_SLOT_ID_INVALID)?;
            if matches.next().is_some() {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            Ok(slot_id)
        })
        .unwrap_or_else(|error| {
            panic!(
                "expected exactly one FIDO2 slot matching PKCS11RS_FIDO2_TEST_SOURCE={selector:?}: {error:?}"
            )
        })
    }

    #[test]
    #[ignore = "requires a YubiKey with the FIDO AID exposed through PC/SC"]
    fn fido2_ccid_compatibility_probe() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot_id = fido2_slot_id();
        crate::with_context(|context| {
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let child = slot_contexts.get(&slot_id).ok_or(CKR_SLOT_ID_INVALID)?;
            let child = child
                .lock()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let slot = child.get_slot(slot_id)?;
            let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
            slot.get_slot_info(&mut slot_info)?;
            let description = String::from_utf8_lossy(&slot_info.slotDescription)
                .trim_end()
                .to_owned();
            eprintln!(
                "selected FIDO2 slot {slot_id}: {description}; serial {}; firmware {}.{}",
                slot.serial(),
                slot_info.firmwareVersion.major,
                slot_info.firmwareVersion.minor
            );
            let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
            slot.get_token_info(&mut token_info)?;
            let label = String::from_utf8_lossy(&token_info.label)
                .trim_end()
                .to_owned();
            eprintln!(
                "GetInfo succeeded: token {label}; flags {:#x}; PIN length {}..={}",
                token_info.flags, token_info.ulMinPinLen, token_info.ulMaxPinLen
            );
            Ok(())
        })
        .expect("selected FIDO applet did not complete authenticatorGetInfo");
    }

    #[test]
    #[ignore = "requires a YubiKey FIDO2 smart-card applet over USB CCID or NFC and PKCS11RS_FIDO2_TEST_PIN"]
    fn fido2_read_only_resident_credential_enumeration() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let pin = std::env::var("PKCS11RS_FIDO2_TEST_PIN")
            .expect("PKCS11RS_FIDO2_TEST_PIN must contain the configured FIDO2 PIN");
        let slot_id = fido2_slot_id();
        crate::with_context(|context| {
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let child = slot_contexts
                .get(&slot_id)
                .ok_or(CKR_SLOT_ID_INVALID)?;
            let mut child = child
                .lock()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            child._get_slot_mut(slot_id)?.login(pin.as_bytes())?;
            let objects = child.get_slot(slot_id)?.backend_token_objects(slot_id)?;
            let credential_count = objects
                .iter()
                .filter(|object| object.class == CKO_DATA as CK_OBJECT_CLASS)
                .count();
            eprintln!(
                "enumerated {credential_count} read-only FIDO2 discoverable credentials as {} objects",
                objects.len(),
            );
            for object in &objects {
                eprintln!("  {} ({})", object.label, object.unique_id);
            }
            child._get_slot_mut(slot_id)?.logout()?;
            Ok(())
        })
        .expect("read-only FIDO2 resident-credential enumeration failed");
    }

    #[test]
    #[ignore = "creates a persistent discoverable FIDO2 credential and requires touch"]
    fn creates_and_rediscovers_synthetic_fido2_credential() {
        let Ok(pin) = std::env::var(CURRENT_PIN_ENV) else {
            eprintln!(
                "skipped persistent FIDO2 credential creation; set {CURRENT_PIN_ENV} to enable it"
            );
            return;
        };
        let mut pin = zeroize::Zeroizing::new(pin.into_bytes());
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot_id = fido2_slot_id();
        let credential_id = crate::with_context(|context| {
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let child = slot_contexts.get(&slot_id).ok_or(CKR_SLOT_ID_INVALID)?;
            let mut child = child
                .lock()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            child
                ._get_slot_mut(slot_id)?
                .create_fido2_test_credential(&pin)
        })
        .expect("authenticatorMakeCredential failed for the synthetic hardware fixture");

        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_Login could not enumerate the newly created credential"
        );
        let unique_id = crate::with_context(|context| {
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let child = slot_contexts.get(&slot_id).ok_or(CKR_SLOT_ID_INVALID)?;
            let child = child
                .lock()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            child
                .get_slot(slot_id)?
                .backend_token_objects(slot_id)?
                .into_iter()
                .find(|object| {
                    object.class == CKO_DATA as CK_OBJECT_CLASS
                        && object
                            .label
                            .contains(crate::ctap::FIDO2_TEST_USER_DISPLAY_NAME)
                        && object.id == credential_id
                })
                .map(|object| object.unique_id)
                .ok_or_else(|| crate::Error::from(CKR_DEVICE_ERROR))
        })
        .expect("the synthetic credential was not rediscovered as a PKCS #11 object");
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        eprintln!(
            "created and rediscovered synthetic FIDO2 credential {unique_id} for RP {}",
            crate::ctap::FIDO2_TEST_RP_ID
        );
    }

    #[test]
    #[ignore = "sets and verifies the initial persistent FIDO2 PIN on a live authenticator"]
    fn provisions_initial_fido2_pin() {
        let Ok(new_pin) = std::env::var(NEW_PIN_ENV) else {
            eprintln!("skipped persistent FIDO2 PIN provisioning; set {NEW_PIN_ENV} to enable it");
            return;
        };
        let mut new_pin = zeroize::Zeroizing::new(new_pin.into_bytes());
        assert!(
            (4..=63).contains(&new_pin.len()),
            "{NEW_PIN_ENV} must contain 4 through 63 printable ASCII characters"
        );
        assert!(
            new_pin.iter().all(|byte| (0x20..=0x7e).contains(byte)),
            "{NEW_PIN_ENV} must contain only printable ASCII so it is unambiguously NFC-normalized"
        );

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot_id = fido2_slot_id();
        let mut before = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::api::C_GetTokenInfo(slot_id, &mut before),
            CKR_OK as CK_RV
        );
        assert_eq!(
            before.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS,
            0,
            "refusing to provision: the selected FIDO2 authenticator already reports a PIN"
        );
        assert!(
            new_pin.len() >= before.ulMinPinLen as usize,
            "{NEW_PIN_ENV} is shorter than the authenticator's reported minimum of {} characters",
            before.ulMinPinLen
        );

        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        // GUI PKCS #11 clients commonly pass a pointer to an empty string
        // rather than NULL_PTR for the uninitialized old PIN.
        let mut empty_old_pin = [0_u8];
        assert_eq!(
            crate::api::C_SetPIN(
                session,
                empty_old_pin.as_mut_ptr(),
                0,
                new_pin.as_mut_ptr(),
                new_pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "initial FIDO2 PIN provisioning through C_SetPIN failed"
        );

        let mut after = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::api::C_GetTokenInfo(slot_id, &mut after),
            CKR_OK as CK_RV
        );
        assert_ne!(
            after.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS,
            0,
            "C_SetPIN returned success but GetInfo still reports no configured PIN"
        );
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                new_pin.as_mut_ptr(),
                new_pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_Login could not authenticate with the newly provisioned FIDO2 PIN"
        );
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        eprintln!(
            "provisioned and verified the initial FIDO2 PIN through C_SetPIN and C_Login on slot {slot_id}; minimum PIN length {}",
            after.ulMinPinLen
        );
    }

    #[test]
    #[ignore = "changes and verifies the persistent FIDO2 PIN on a live authenticator"]
    fn changes_existing_fido2_pin() {
        let (Ok(current_pin), Ok(new_pin)) =
            (std::env::var(CURRENT_PIN_ENV), std::env::var(NEW_PIN_ENV))
        else {
            eprintln!(
                "skipped persistent FIDO2 PIN change; set both {CURRENT_PIN_ENV} and {NEW_PIN_ENV} to enable it"
            );
            return;
        };
        let mut current_pin = zeroize::Zeroizing::new(current_pin.into_bytes());
        let mut new_pin = zeroize::Zeroizing::new(new_pin.into_bytes());
        for (name, pin) in [
            (CURRENT_PIN_ENV, current_pin.as_slice()),
            (NEW_PIN_ENV, new_pin.as_slice()),
        ] {
            assert!(
                (4..=63).contains(&pin.len()),
                "{name} must contain 4 through 63 printable ASCII characters"
            );
            assert!(
                pin.iter().all(|byte| (0x20..=0x7e).contains(byte)),
                "{name} must contain only printable ASCII so it is unambiguously NFC-normalized"
            );
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(
            crate::api::C_Initialize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        let slot_id = fido2_slot_id();
        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::api::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
        assert_ne!(
            token_info.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS,
            0,
            "refusing to change: the selected FIDO2 authenticator reports no configured PIN"
        );
        assert!(
            new_pin.len() >= token_info.ulMinPinLen as usize,
            "{NEW_PIN_ENV} is shorter than the authenticator's reported minimum of {} characters",
            token_info.ulMinPinLen
        );

        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_SetPIN(
                session,
                current_pin.as_mut_ptr(),
                current_pin.len() as CK_ULONG,
                new_pin.as_mut_ptr(),
                new_pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "FIDO2 PIN change through C_SetPIN failed"
        );
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                new_pin.as_mut_ptr(),
                new_pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "C_Login could not authenticate with the changed FIDO2 PIN"
        );
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        eprintln!(
            "changed and verified the FIDO2 PIN through C_SetPIN and C_Login on slot {slot_id}"
        );
    }
}
