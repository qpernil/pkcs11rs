#[cfg(not(feature = "abi-tests"))]
use super::*;

#[cfg(not(feature = "abi-tests"))]
fn initialize_direct_hardware(recreate_yubihsm_sessions: bool) -> CK_RV {
    initialize_with_configuration(serde_json::json!({
        "version": 1,
        "hardware": {"discovery": true},
        "yubihsm": {
            "urls": [],
            "recreate_sessions": recreate_yubihsm_sessions
        }
    }))
}

#[cfg(not(feature = "abi-tests"))]
mod hardware_provisioning {
    use super::*;
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
    const REUSE_HSMAUTH_CREDENTIAL_ENV: &str = "PKCS11RS_TEST_REUSE_ASYMMETRIC_HSMAUTH_CREDENTIAL";

    fn direct_hardware_configuration() -> crate::ModuleConfiguration {
        let mut configuration = crate::ModuleConfiguration::resolve(None)
            .expect("failed to resolve hardware configuration");
        configuration.hardware_discovery = true;
        configuration.yubihsm_urls.clear();
        configuration
    }

    fn all_yubihsm_configuration() -> crate::ModuleConfiguration {
        let mut configuration = crate::ModuleConfiguration::resolve(None)
            .expect("failed to resolve hardware configuration");
        configuration.hardware_discovery = true;
        configuration
    }

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
        let ca_key = crate::certificate_builder::p256_key();
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
            selector
                .as_ref()
                .is_none_or(|selector| connector.name() == *selector)
        });
        let connector = matches
            .next()
            .unwrap_or_else(|| panic!("no {kind} matched {selector_name}={selector:?}"));
        assert!(
            matches.next().is_none(),
            "multiple {kind} devices matched; set {selector_name} to the full endpoint name"
        );
        connector
    }

    fn with_ccid_operation<T>(
        connector: &dyn crate::Connector,
        operation: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let device = connector.device_context();
        let _operation = device
            .as_ref()
            .map(|device| device.lock_operation(crate::device::DeviceOperationKind::Ccid))
            .transpose()?;
        operation()
    }

    fn find_public_key_companions(
        session: CK_SESSION_HANDLE,
        id: &[u8],
        label: &str,
    ) -> Vec<CK_OBJECT_HANDLE> {
        let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
        let mut id = id.to_vec();
        let mut label = label.as_bytes().to_vec();
        let mut template = [
            scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
            bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id),
            bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label),
        ];
        assert_eq!(
            crate::api::C_FindObjectsInit(
                session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
        let mut objects = Vec::new();
        loop {
            let mut batch = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 8];
            let mut count = 0;
            assert_eq!(
                crate::api::C_FindObjects(
                    session,
                    batch.as_mut_ptr(),
                    batch.len() as CK_ULONG,
                    &mut count,
                ),
                CKR_OK as CK_RV
            );
            if count == 0 {
                break;
            }
            objects.extend_from_slice(&batch[..count as usize]);
        }
        assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
        objects
    }

    fn provision_public_key_companions(
        authkey_id: u16,
        label: &str,
        public_point: &[u8],
        admin_id: u16,
        admin_password: &str,
        expected_targets: usize,
        yubihsm_urls: &[String],
    ) {
        finalize_for_test();
        assert_eq!(
            initialize_with_configuration(serde_json::json!({
                "version": 1,
                "hardware": {"discovery": true},
                "yubihsm": {
                    "urls": yubihsm_urls,
                    "public_discovery": format!("{admin_id:04x}{admin_password}")
                }
            })),
            CKR_OK as CK_RV
        );
        let slots = crate::with_context(|context| {
            context.init()?;
            context.refresh_discovery()?;
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            Ok(slot_contexts
                .iter()
                .filter_map(|(slot_id, child)| {
                    let child = child.lock().ok()?;
                    (child.slot.kind() == crate::SlotKind::YubiHsm && child.slot.is_present())
                        .then_some((*slot_id, child.slot.name().to_owned()))
                })
                .collect::<Vec<_>>())
        })
        .expect("failed to rediscover YubiHSM slots for companion provisioning");
        assert_eq!(
            slots.len(),
            expected_targets,
            "YubiHSM target count changed before companion provisioning"
        );

        let id = authkey_id.to_be_bytes();
        let point = crate::der_octet_string(public_point)
            .expect("failed to DER-encode the YubiHSM Auth public key");
        let parameters = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        for (slot, target) in slots {
            let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
            assert_eq!(
                crate::api::C_OpenSession(
                    slot,
                    (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
                    std::ptr::null_mut(),
                    None,
                    &mut session,
                ),
                CKR_OK as CK_RV,
                "failed to open YubiHSM {target:?} for companion provisioning"
            );
            login_hardware_session(
                session,
                CKU_USER as CK_USER_TYPE,
                &format!("{admin_id:04x}{admin_password}"),
            );
            for existing in find_public_key_companions(session, &id, label) {
                assert_eq!(
                    crate::api::C_DestroyObject(session, existing),
                    CKR_OK as CK_RV,
                    "failed to remove the previous public-key companion from {target:?}"
                );
            }

            let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
            let mut key_type = CKK_EC as CK_KEY_TYPE;
            let mut token = CK_TRUE as CK_BBOOL;
            let mut id_value = id;
            let mut label_value = label.as_bytes().to_vec();
            let mut parameters_value = parameters;
            let mut point_value = point.clone();
            let mut template = [
                scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut key_type),
                scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
                bytes_attribute(CKA_ID as CK_ATTRIBUTE_TYPE, &mut id_value),
                bytes_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE, &mut label_value),
                bytes_attribute(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE, &mut parameters_value),
                bytes_attribute(CKA_EC_POINT as CK_ATTRIBUTE_TYPE, &mut point_value),
            ];
            let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
            assert_eq!(
                crate::api::C_CreateObject(
                    session,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut object,
                ),
                CKR_OK as CK_RV,
                "failed to persist the public-key companion on {target:?}"
            );
            assert_eq!(
                read_bytes_attribute(session, object, CKA_EC_POINT as CK_ATTRIBUTE_TYPE),
                point
            );
            assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);

            let mut public_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
            assert_eq!(
                crate::api::C_OpenSession(
                    slot,
                    CKF_SERIAL_SESSION as CK_FLAGS,
                    std::ptr::null_mut(),
                    None,
                    &mut public_session,
                ),
                CKR_OK as CK_RV
            );
            let discovered = find_public_key_companions(public_session, &id, label);
            assert_eq!(
                discovered.len(),
                1,
                "public discovery did not expose exactly one companion on {target:?}"
            );
            assert_eq!(
                read_bytes_attribute(
                    public_session,
                    discovered[0],
                    CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
                ),
                point,
                "public discovery returned the wrong companion key on {target:?}"
            );
            assert_eq!(crate::api::C_CloseSession(public_session), CKR_OK as CK_RV);
            eprintln!(
                "persisted public-key companion for Authentication Key {authkey_id:04x} on {target:?}"
            );
        }
        finalize_for_test();
    }

    fn select_yubihsm_slot() -> CK_SLOT_ID {
        let selector = std::env::var("PKCS11RS_TEST_YUBIHSM_SOURCE").ok();
        crate::with_context(|context| {
            context.init()?;
            context.refresh_discovery()?;
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

    fn hardware_session_state(session: CK_SESSION_HANDLE) -> CK_STATE {
        let mut info = CK_SESSION_INFO {
            slotID: 0,
            state: 0,
            flags: 0,
            ulDeviceError: 0,
        };
        assert_eq!(
            crate::api::C_GetSessionInfo(session, &mut info),
            CKR_OK as CK_RV
        );
        info.state
    }

    #[test]
    #[ignore = "requires at least one directly connected YubiHSM accessed through nusb"]
    fn direct_hardware_survives_initialize_finalize_orderings() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();

        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
        );
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        assert_eq!(
            initialize_direct_hardware(false),
            CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV
        );

        let mut count = 0;
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
            CKR_OK as CK_RV
        );
        let mut slot_ids = vec![0; count as usize];
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slot_ids.as_mut_ptr(), &mut count),
            CKR_OK as CK_RV
        );
        slot_ids.truncate(count as usize);
        assert!(
            slot_ids.into_iter().any(|slot_id| {
                let mut info = CK_SLOT_INFO {
                    slotDescription: [0; 64],
                    manufacturerID: [0; 32],
                    flags: 0,
                    hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                    firmwareVersion: CK_VERSION { major: 0, minor: 0 },
                };
                crate::api::C_GetSlotInfo(slot_id, &mut info) == CKR_OK as CK_RV
                    && String::from_utf8_lossy(&info.slotDescription)
                        .trim_end()
                        .starts_with("Yubico YubiHSM ")
            }),
            "expected at least one directly connected YubiHSM"
        );

        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
        );

        for _ in 0..3 {
            assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
            assert_eq!(
                crate::api::C_Finalize(std::ptr::null_mut()),
                CKR_OK as CK_RV
            );
        }
    }

    #[test]
    #[ignore = "requires at least one directly connected YubiHSM accessed through nusb"]
    fn direct_yubihsm_usb_slot_reports_metadata() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let mut count = 0;
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, std::ptr::null_mut(), &mut count),
            CKR_OK as CK_RV
        );
        let mut slot_ids = vec![0; count as usize];
        assert_eq!(
            crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slot_ids.as_mut_ptr(), &mut count),
            CKR_OK as CK_RV
        );
        slot_ids.truncate(count as usize);

        let mut yubihsm_count = 0;
        for slot_id in slot_ids {
            let mut slot_info = CK_SLOT_INFO {
                slotDescription: [0; 64],
                manufacturerID: [0; 32],
                flags: 0,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 0 },
            };
            assert_eq!(
                crate::api::C_GetSlotInfo(slot_id, &mut slot_info),
                CKR_OK as CK_RV
            );
            if !String::from_utf8_lossy(&slot_info.slotDescription)
                .trim_end()
                .starts_with("Yubico YubiHSM ")
            {
                continue;
            }

            yubihsm_count += 1;
            let mut token_info = CK_TOKEN_INFO {
                label: [0; 32],
                manufacturerID: [0; 32],
                model: [0; 16],
                serialNumber: [0; 16],
                flags: 0,
                ulMaxSessionCount: 0,
                ulSessionCount: 0,
                ulMaxRwSessionCount: 0,
                ulRwSessionCount: 0,
                ulMaxPinLen: 0,
                ulMinPinLen: 0,
                ulTotalPublicMemory: 0,
                ulFreePublicMemory: 0,
                ulTotalPrivateMemory: 0,
                ulFreePrivateMemory: 0,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 0 },
                utcTime: [0; 16],
            };
            assert_eq!(
                crate::api::C_GetTokenInfo(slot_id, &mut token_info),
                CKR_OK as CK_RV
            );
            assert!(
                token_info
                    .serialNumber
                    .iter()
                    .any(|value| !value.is_ascii_whitespace())
            );
        }
        assert!(
            yubihsm_count > 0,
            "expected at least one directly connected YubiHSM"
        );
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    #[test]
    #[ignore = "waits for a live YubiHSM secure session to expire after 30 seconds"]
    fn recreates_expired_yubihsm_session_on_hardware() {
        const SESSION_EXPIRY_WAIT: std::time::Duration = std::time::Duration::from_secs(35);

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(true), CKR_OK as CK_RV);

        let slot_id = select_yubihsm_slot();
        let session = open_hardware_session(slot_id);
        let credential = format!(
            "{}{}",
            environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
            environment(
                "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
                DEFAULT_ADMIN_PASSWORD,
            )
        );
        login_hardware_session(session, CKU_USER as CK_USER_TYPE, &credential);

        let mut baseline = [0u8; 32];
        assert_eq!(
            crate::api::C_GenerateRandom(
                session,
                baseline.as_mut_ptr(),
                baseline.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
        eprintln!(
            "waiting {} seconds without a YubiHSM command so the secure session expires",
            SESSION_EXPIRY_WAIT.as_secs()
        );
        std::thread::sleep(SESSION_EXPIRY_WAIT);

        let mut after_expiry = [0u8; 32];
        assert_eq!(
            crate::api::C_GenerateRandom(
                session,
                after_expiry.as_mut_ptr(),
                after_expiry.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV,
            "the first command after expiry should recreate the secure session and run once"
        );
        assert_ne!(baseline, after_expiry);

        assert_eq!(
            hardware_session_state(session),
            CKS_RO_USER_FUNCTIONS as CK_STATE
        );

        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    #[test]
    #[ignore = "waits for a live YubiHSM secure session to expire after 30 seconds"]
    fn expired_yubihsm_session_logs_out_every_pkcs11_session_on_hardware() {
        const SESSION_EXPIRY_WAIT: std::time::Duration = std::time::Duration::from_secs(35);

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);

        let slot_id = select_yubihsm_slot();
        let sessions = [
            open_hardware_session(slot_id),
            open_hardware_session(slot_id),
        ];
        let credential = format!(
            "{}{}",
            environment("PKCS11RS_TEST_YUBIHSM_ADMIN_ID", DEFAULT_ADMIN_ID),
            environment(
                "PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD",
                DEFAULT_ADMIN_PASSWORD,
            )
        );
        login_hardware_session(sessions[0], CKU_USER as CK_USER_TYPE, &credential);
        for session in sessions {
            assert_eq!(
                hardware_session_state(session),
                CKS_RO_USER_FUNCTIONS as CK_STATE
            );
        }

        let mut baseline = [0u8; 32];
        assert_eq!(
            crate::api::C_GenerateRandom(
                sessions[0],
                baseline.as_mut_ptr(),
                baseline.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
        eprintln!(
            "waiting {} seconds without a YubiHSM command so the secure session expires",
            SESSION_EXPIRY_WAIT.as_secs()
        );
        std::thread::sleep(SESSION_EXPIRY_WAIT);

        let mut after_expiry = [0u8; 32];
        assert_eq!(
            crate::api::C_GenerateRandom(
                sessions[1],
                after_expiry.as_mut_ptr(),
                after_expiry.len() as CK_ULONG,
            ),
            CKR_SESSION_CLOSED as CK_RV
        );
        for session in sessions {
            assert_eq!(
                hardware_session_state(session),
                CKS_RO_PUBLIC_SESSION as CK_STATE
            );
        }
        assert_eq!(
            crate::api::C_Logout(sessions[0]),
            CKR_USER_NOT_LOGGED_IN as CK_RV
        );

        for session in sessions {
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        }
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    #[test]
    #[ignore = "runs many concurrent PKCS #11 operations against two present YubiHSM hardware slots"]
    fn concurrent_yubihsm_hardware_slots_survive_many_threaded_operations() {
        const THREAD_COUNT: usize = 16;
        const CALLS_PER_THREAD: usize = 100;
        const OUTPUT_LENGTH: usize = 32;

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);

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
    fn generated_ec_key_round_trips_through_rsa_public_wrap_key_on_hardware() {
        if std::env::var(RSA_WRAP_ENABLE_ENV).as_deref() != Ok("1") {
            eprintln!("skipped hardware wrap test; set {RSA_WRAP_ENABLE_ENV}=1 to enable it");
            return;
        }

        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
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
        let result = rsa_public_wrap_round_trip(slot_id, pin.as_bytes());
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
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);

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
                present: std::sync::atomic::AtomicBool::new(true),
                select_ok: std::sync::atomic::AtomicBool::new(true),
                serial: "PROVISION",
            })
        };
        let hsmauth_aid = crate::hsmauth::AID.to_vec();
        let hsmauth = crate::HsmAuthSlot::new(connector(), hsmauth_aid);
        assert!(crate::Slot::hsmauth_provisioning_connector(&hsmauth).is_some());

        let issuer_sd = crate::IssuerSecurityDomainSlot::new(
            connector(),
            crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
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

        let configuration = direct_hardware_configuration();
        let context = crate::ModuleContext::new_with_configuration(configuration)
            .expect("failed to create hardware context");
        context.init().unwrap();
        context.refresh_discovery().unwrap();
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
            .establish_secure_channel(&crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID)
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
        assert!(
            after
                .certificate_bundles
                .iter()
                .any(|bundle| { bundle.key_ref == key_ref && bundle.certificates == certificates })
        );

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
    #[ignore = "provisions persistent keys on a live YubiKey and all discovered YubiHSMs"]
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
    #[ignore = "provisions persistent touch-required keys on a live YubiKey and all discovered YubiHSMs"]
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
        let reuse_credential = std::env::var(REUSE_HSMAUTH_CREDENTIAL_ENV).as_deref() == Ok("1");
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

        let configuration = all_yubihsm_configuration();
        let yubihsm_urls = configuration.yubihsm_urls.clone();
        let context = crate::ModuleContext::new_with_configuration(configuration)
            .expect("failed to create hardware context");
        context.init().unwrap();
        context.refresh_discovery().unwrap();
        let (hsmauth, mut yubihsms) = {
            let slot_contexts = context.slot_contexts.read().unwrap();
            let hsmauth = select_connector(
                slot_contexts
                    .values()
                    .filter_map(|child| child.lock().ok()?.slot.hsmauth_provisioning_connector())
                    .collect(),
                "PKCS11RS_TEST_HSMAUTH_SOURCE",
                "YubiHSM Auth applet",
            );
            let yubihsms = slot_contexts
                .values()
                .filter_map(|child| child.lock().ok()?.slot.yubihsm_provisioning_connector())
                .collect::<Vec<_>>();
            (hsmauth, yubihsms)
        };
        assert!(
            !yubihsms.is_empty(),
            "no configured or locally attached YubiHSM was discovered"
        );
        yubihsms.sort_by_key(|connector| connector.name());
        for pair in yubihsms.windows(2) {
            assert_ne!(
                pair[0].name(),
                pair[1].name(),
                "the same YubiHSM endpoint was discovered more than once"
            );
        }

        let credentials = with_ccid_operation(hsmauth.as_ref(), || {
            crate::HsmAuthClient.list_credentials(hsmauth.as_ref())
        })
        .expect("failed to list YubiHSM Auth credentials");
        let existing_credential = credentials
            .into_iter()
            .find(|credential| credential.label == label);
        if reuse_credential {
            assert!(
                existing_credential.is_some(),
                "{}=1 requires an existing YubiHSM Auth credential named {label:?}",
                REUSE_HSMAUTH_CREDENTIAL_ENV
            );
        }
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

        let mut existing_keys = Vec::with_capacity(yubihsms.len());
        for yubihsm in &yubihsms {
            let target = yubihsm.name();
            let (mut admin_session, _, _) = crate::YubiHsmSecureSession::authenticate_direct(
                yubihsm.as_ref(),
                admin_id,
                admin_password.as_bytes(),
                None,
                None,
            )
            .unwrap_or_else(|error| {
                panic!("failed to authenticate to YubiHSM {target:?} for preflight: {error:?}")
            });
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
            let preflight_close = admin_session
                .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session());
            let existing_key = existing_key.unwrap_or_else(|error| {
                panic!(
                    "failed to query authentication-key ID {authkey_id:04x} on YubiHSM {target:?}: {error:?}"
                )
            });
            preflight_close.unwrap_or_else(|error| {
                panic!("failed to close the preflight session on YubiHSM {target:?}: {error:?}")
            });
            if let Some(info) = &existing_key {
                assert_eq!(
                    info.label, label,
                    "YubiHSM {target:?} object ID {authkey_id:04x} has another label"
                );
                assert_eq!(
                    info.algorithm,
                    crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
                    "YubiHSM {target:?} object ID {authkey_id:04x} is not an asymmetric P-256 authentication key"
                );
            }
            existing_keys.push(existing_key.is_some());
        }

        for (yubihsm, existing_key) in yubihsms.iter().zip(existing_keys) {
            if !existing_key {
                continue;
            }
            let target = yubihsm.name();
            let (mut admin_session, _, _) = crate::YubiHsmSecureSession::authenticate_direct(
                yubihsm.as_ref(),
                admin_id,
                admin_password.as_bytes(),
                None,
                None,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "failed to reopen YubiHSM {target:?} provisioning session for cleanup: {error:?}"
                )
            });
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
            deletion.unwrap_or_else(|error| {
                panic!(
                    "failed to delete authentication key {authkey_id:04x} from YubiHSM {target:?}: {error:?}"
                )
            });
            cleanup_close.unwrap_or_else(|error| {
                panic!("failed to close the cleanup session on YubiHSM {target:?}: {error:?}")
            });
            eprintln!("deleted prior YubiHSM authentication key {authkey_id:04x} from {target:?}");
        }

        if existing_credential.is_some() && !reuse_credential {
            with_ccid_operation(hsmauth.as_ref(), || {
                crate::HsmAuthClient.delete_credential(
                    hsmauth.as_ref(),
                    management_key.as_slice(),
                    &label,
                )
            })
            .expect("failed to delete the prior YubiHSM Auth credential");
            eprintln!("deleted prior YubiHSM Auth credential {label:?}");
        }

        if !reuse_credential {
            with_ccid_operation(hsmauth.as_ref(), || {
                crate::HsmAuthClient.put_asymmetric_credential(
                    hsmauth.as_ref(),
                    management_key.as_slice(),
                    &label,
                    None,
                    credential_password.as_bytes(),
                    case.touch_required,
                )
            })
            .expect("failed to generate the YubiHSM Auth asymmetric credential");
        }
        let public_point = with_ccid_operation(hsmauth.as_ref(), || {
            crate::HsmAuthClient.get_public_key(hsmauth.as_ref(), &label)
        })
        .expect("failed to read the generated YubiHSM Auth public key");
        let public_key = public_point
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
        for yubihsm in &yubihsms {
            let target = yubihsm.name();
            let (mut admin_session, _, _) = crate::YubiHsmSecureSession::authenticate_direct(
                yubihsm.as_ref(),
                admin_id,
                admin_password.as_bytes(),
                None,
                None,
            )
            .unwrap_or_else(|error| {
                panic!("failed to reopen YubiHSM {target:?} provisioning session: {error:?}")
            });
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
            let provisioning_close = admin_session
                .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session());
            let (installed_id, installed_info) = installed.unwrap_or_else(|error| {
                panic!(
                    "failed to install authentication key {authkey_id:04x} in YubiHSM {target:?}: {error:?}"
                )
            });
            provisioning_close.unwrap_or_else(|error| {
                panic!("failed to close the provisioning session on YubiHSM {target:?}: {error:?}")
            });
            assert_eq!(installed_id, authkey_id);
            assert_eq!(installed_info.domains, AUTHENTICATION_KEY_DOMAINS);
            eprintln!("installed YubiHSM authentication key {authkey_id:04x} in {target:?}");
        }

        let info = with_ccid_operation(hsmauth.as_ref(), || {
            crate::HsmAuthClient.discover(hsmauth.as_ref())
        })
        .expect("failed to rediscover the generated YubiHSM Auth credential");
        let credential = info
            .credentials
            .into_iter()
            .find(|credential| credential.label == label)
            .expect("generated YubiHSM Auth credential was not rediscovered");
        assert_eq!(credential.touch_required, case.touch_required);
        let provider = crate::HsmAuthProvider {
            connector: hsmauth.into(),
            credential,
            version: info.version,
            trust_prefix: None,
            source: String::new(),
        };
        for yubihsm in &yubihsms {
            let target = yubihsm.name();
            let mut session = provider
                .authenticate(yubihsm.as_ref(), authkey_id, credential_password.as_bytes())
                .unwrap_or_else(|error| {
                    panic!(
                        "the provisioned asymmetric YubiHSM Auth pair could not authenticate to {target:?}: {error:?}"
                    )
                });
            session
                .send_command(yubihsm.as_ref(), &crate::YubiHsmCommand::close_session())
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to close the verification session on YubiHSM {target:?}: {error:?}"
                    )
                });
            eprintln!("verified YubiHSM Auth authentication to {target:?}");
        }

        let target_count = yubihsms.len();
        drop(provider);
        drop(yubihsms);
        drop(context);
        provision_public_key_companions(
            authkey_id,
            &label,
            &public_point,
            admin_id,
            admin_password.as_str(),
            target_count,
            &yubihsm_urls,
        );

        eprintln!(
            "provisioned {} YubiHSM Auth credential {label:?} (touch required {}) with authentication key {authkey_id:04x} and public-key companion on {target_count} YubiHSM(s)",
            if reuse_credential {
                "existing"
            } else {
                "persistent"
            },
            case.touch_required,
        );
    }
}

#[cfg(not(feature = "abi-tests"))]
mod fido2_hardware {
    use super::*;
    use crate::Connector;
    use sha2::Digest;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    const CURRENT_PIN_ENV: &str = "PKCS11RS_FIDO2_TEST_PIN";
    const NEW_PIN_ENV: &str = "PKCS11RS_FIDO2_NEW_PIN";
    const CROSS_INTERFACE_ITERATIONS: usize = 50;

    #[derive(Clone)]
    struct HidCandidate {
        descriptor: crate::ctap_hid::HidDeviceDescriptor,
        serial: String,
        firmware: (u8, u8, u8),
    }

    #[derive(Clone)]
    struct PcscCandidate {
        reader: CString,
        name: String,
        serial: String,
    }

    struct CrossInterfaceFixture {
        hid: HidCandidate,
        pcsc: PcscCandidate,
    }

    #[derive(Clone, Copy, Debug)]
    enum CcidProbe {
        Management,
        Piv,
        Fido,
    }

    impl CcidProbe {
        fn label(self) -> &'static str {
            match self {
                Self::Management => "Management",
                Self::Piv => "PIV",
                Self::Fido => "FIDO-over-CCID",
            }
        }

        fn run(self, connector: &crate::PcscConnector) -> Result<(), crate::Error> {
            match self {
                Self::Management => crate::YubiKeyClient.discover(connector).map(|_| ()),
                Self::Piv => crate::piv::Client
                    .select(connector, &crate::piv::PIV_AID)
                    .map(|_| ()),
                Self::Fido => fido_ccid_get_info(connector),
            }
        }
    }

    #[derive(Debug, Default)]
    struct ProbeStats {
        attempts: usize,
        successes: usize,
        errors: BTreeMap<String, usize>,
        elapsed: Duration,
    }

    impl ProbeStats {
        fn observe<T, E: std::fmt::Debug>(&mut self, result: Result<T, E>) {
            self.attempts += 1;
            match result {
                Ok(_) => self.successes += 1,
                Err(error) => {
                    *self.errors.entry(format!("{error:?}")).or_default() += 1;
                }
            }
        }
    }

    fn normalize_yubico_serial(serial: &str) -> Option<String> {
        let serial = serial.trim_start_matches('0');
        (!serial.is_empty()).then(|| serial.to_owned())
    }

    fn discover_hid_candidates() -> Vec<HidCandidate> {
        crate::ctap_hid::enumerate_fido_devices()
            .expect("failed to enumerate FIDO HID devices")
            .into_iter()
            .filter(|descriptor| descriptor.is_yubico())
            .filter_map(|descriptor| {
                let io = descriptor.open().ok()?;
                let (transport, init) =
                    crate::ctap_hid::CtapHidTransport::connect(Box::new(io)).ok()?;
                let transport = Rc::new(transport);
                let device_info = crate::YubiKeyClient
                    .discover_from_config_pages(Some(init.firmware_version), |page| {
                        transport.command(0x42, &[page])
                    })
                    .ok();
                let serial = device_info
                    .as_ref()
                    .and_then(|info| info.serial.as_deref())
                    .or_else(|| descriptor.serial())
                    .and_then(normalize_yubico_serial)?;
                let firmware = device_info
                    .and_then(|info| info.version)
                    .unwrap_or(init.firmware_version);
                Some(HidCandidate {
                    descriptor,
                    serial,
                    firmware,
                })
            })
            .collect()
    }

    fn open_pcsc_connector(reader: CString) -> Result<crate::PcscConnector, crate::Error> {
        let context = pcsc::Context::establish(pcsc::Scope::System)?;
        let connector = crate::PcscConnector::new(reader, context);
        connector.refresh()?;
        Ok(connector)
    }

    fn discover_pcsc_candidates() -> Vec<PcscCandidate> {
        let context =
            pcsc::Context::establish(pcsc::Scope::System).expect("failed to establish PC/SC");
        context
            .list_readers_owned()
            .expect("failed to list PC/SC readers")
            .into_iter()
            .filter_map(|reader| {
                let name = reader.to_string_lossy().into_owned();
                let connector = crate::PcscConnector::new(reader.clone(), context.clone());
                connector.refresh().ok()?;
                let info = crate::YubiKeyClient.discover(&connector).ok()?;
                let serial = normalize_yubico_serial(info.serial.as_deref()?)?;
                Some(PcscCandidate {
                    reader,
                    name,
                    serial,
                })
            })
            .collect()
    }

    fn cross_interface_fixture() -> CrossInterfaceFixture {
        let selector = std::env::var("PKCS11RS_FIDO2_TEST_SOURCE").ok();
        let hid = discover_hid_candidates();
        let pcsc = discover_pcsc_candidates();
        let mut paired = Vec::new();
        for hid in hid {
            for pcsc in pcsc.iter().filter(|pcsc| pcsc.serial == hid.serial) {
                paired.push(CrossInterfaceFixture {
                    hid: hid.clone(),
                    pcsc: pcsc.clone(),
                });
            }
        }
        let mut matches = paired.into_iter().filter(|fixture| {
            selector.as_ref().is_none_or(|selector| {
                selector == &fixture.hid.serial
                    || selector == &fixture.hid.descriptor.name()
                    || selector == &fixture.pcsc.name
            })
        });
        let fixture = matches.next().unwrap_or_else(|| {
            panic!(
                "no YubiKey with the same validated serial was found over both HID and CCID; selector {selector:?}"
            )
        });
        assert!(
            matches.next().is_none(),
            "multiple dual-interface YubiKeys matched; set PKCS11RS_FIDO2_TEST_SOURCE"
        );
        fixture
    }

    fn hid_get_info(descriptor: &crate::ctap_hid::HidDeviceDescriptor) -> Result<(), crate::Error> {
        let io = descriptor.open()?;
        let (transport, _) = crate::ctap_hid::CtapHidTransport::connect(Box::new(io))?;
        crate::CtapClient::new(Rc::new(transport))
            .get_info()
            .map(|_| ())
            .map_err(crate::CtapError::into_pkcs11)
    }

    fn fido_ccid_get_info(connector: &crate::PcscConnector) -> Result<(), crate::Error> {
        crate::select_application(connector, &crate::ctap::FIDO2_AID)?;
        let command = crate::CommandApdu {
            cla: 0x80,
            ins: 0x10,
            p1: 0x80,
            p2: 0,
            data: vec![crate::ctap::AUTHENTICATOR_GET_INFO],
            le: Some(256),
            extended: false,
        };
        let response = connector.send_apdu(&command)?.require_success(&command)?;
        match response.data.split_first() {
            Some((&0, cbor)) if !cbor.is_empty() => Ok(()),
            _ => Err(CKR_DEVICE_ERROR.into()),
        }
    }

    fn run_cross_interface_phase(
        fixture: &CrossInterfaceFixture,
        ccid_probe: CcidProbe,
        device: Option<std::sync::Arc<crate::device::DeviceContext>>,
    ) -> (ProbeStats, ProbeStats) {
        let iteration_barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let setup_barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let setup_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        std::thread::scope(|scope| {
            let hid_descriptor = fixture.hid.descriptor.clone();
            let hid_iteration_barrier = iteration_barrier.clone();
            let hid_setup_barrier = setup_barrier.clone();
            let hid_setup_ok = setup_ok.clone();
            let hid_device = device.clone();
            let hid_worker = scope.spawn(move || {
                let setup = (|| {
                    let io = hid_descriptor
                        .open()
                        .map_err(|error| format!("{error:?}"))?;
                    let (transport, _) = crate::ctap_hid::CtapHidTransport::connect(Box::new(io))
                        .map_err(|error| format!("{error:?}"))?;
                    Ok::<_, String>(crate::CtapClient::new(Rc::new(transport)))
                })();
                if setup.is_err() {
                    hid_setup_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                hid_setup_barrier.wait();
                if !hid_setup_ok.load(std::sync::atomic::Ordering::Relaxed) {
                    return setup
                        .map(|_| ProbeStats::default())
                        .and_then(|_| Err(String::from("CCID worker setup failed")));
                }
                let client = setup?;
                let started = Instant::now();
                let mut stats = ProbeStats::default();
                for _ in 0..CROSS_INTERFACE_ITERATIONS {
                    hid_iteration_barrier.wait();
                    stats.observe((|| {
                        let _operation = hid_device
                            .as_ref()
                            .map(|device| {
                                device.lock_operation(crate::device::DeviceOperationKind::Hid)
                            })
                            .transpose()?;
                        client
                            .get_info()
                            .map(|_| ())
                            .map_err(crate::CtapError::into_pkcs11)
                    })());
                }
                stats.elapsed = started.elapsed();
                Ok(stats)
            });

            let pcsc_reader = fixture.pcsc.reader.clone();
            let ccid_iteration_barrier = iteration_barrier;
            let ccid_setup_barrier = setup_barrier.clone();
            let ccid_setup_ok = setup_ok.clone();
            let ccid_device = device;
            let ccid_worker = scope.spawn(move || {
                let setup = open_pcsc_connector(pcsc_reader).map_err(|error| format!("{error:?}"));
                if setup.is_err() {
                    ccid_setup_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                ccid_setup_barrier.wait();
                if !ccid_setup_ok.load(std::sync::atomic::Ordering::Relaxed) {
                    return setup
                        .map(|_| ProbeStats::default())
                        .and_then(|_| Err(String::from("HID worker setup failed")));
                }
                let connector = setup?;
                let started = Instant::now();
                let mut stats = ProbeStats::default();
                for _ in 0..CROSS_INTERFACE_ITERATIONS {
                    ccid_iteration_barrier.wait();
                    stats.observe((|| {
                        let _operation = ccid_device
                            .as_ref()
                            .map(|device| {
                                device.lock_operation(crate::device::DeviceOperationKind::Ccid)
                            })
                            .transpose()?;
                        ccid_probe.run(&connector)
                    })());
                }
                stats.elapsed = started.elapsed();
                Ok(stats)
            });

            setup_barrier.wait();
            let hid = hid_worker
                .join()
                .expect("HID probe worker panicked")
                .expect("HID probe worker could not initialize");
            let ccid = ccid_worker
                .join()
                .expect("CCID probe worker panicked")
                .expect("CCID probe worker could not initialize");
            (hid, ccid)
        })
    }

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
                    == crate::SlotKind::Fido2
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

    fn read_attribute(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        type_: CK_ATTRIBUTE_TYPE,
    ) -> Vec<u8> {
        let mut attribute = CK_ATTRIBUTE {
            type_,
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

    fn delete_fido2_test_credential(
        slot_id: CK_SLOT_ID,
        pin: &[u8],
        credential_id: &[u8],
    ) -> Result<(), crate::Error> {
        crate::with_context(|context| {
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
                .delete_fido2_test_credential(pin, credential_id)
        })
    }

    struct PreviewCredentialCleanup {
        slot_id: CK_SLOT_ID,
        pin: zeroize::Zeroizing<Vec<u8>>,
        credential_id: Vec<u8>,
        armed: bool,
    }

    impl PreviewCredentialCleanup {
        fn new(slot_id: CK_SLOT_ID, pin: &[u8], credential_id: &[u8]) -> Self {
            Self {
                slot_id,
                pin: zeroize::Zeroizing::new(pin.to_vec()),
                credential_id: credential_id.to_vec(),
                armed: true,
            }
        }

        fn delete_and_verify(&mut self) {
            delete_fido2_test_credential(self.slot_id, &self.pin, &self.credential_id)
                .expect("failed to delete the previewSign parent credential");
            let error = delete_fido2_test_credential(self.slot_id, &self.pin, &self.credential_id)
                .expect_err("the deleted previewSign credential was accepted a second time");
            assert_eq!(CK_RV::from(error), CKR_DEVICE_ERROR as CK_RV);
            self.armed = false;
        }
    }

    impl Drop for PreviewCredentialCleanup {
        fn drop(&mut self) {
            if self.armed {
                if let Err(error) =
                    delete_fido2_test_credential(self.slot_id, &self.pin, &self.credential_id)
                {
                    eprintln!(
                        "failed to clean up previewSign credential {:02x?}: {error:?}",
                        self.credential_id
                    );
                }
            }
        }
    }

    fn paired_hid_fido_and_piv_slot_ids() -> (CK_SLOT_ID, CK_SLOT_ID) {
        let selector = std::env::var("PKCS11RS_FIDO2_TEST_SOURCE").ok();
        crate::with_context(|context| {
            context.init()?;
            let slot_contexts = context
                .slot_contexts
                .read()
                .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
            let mut hid_matches = slot_contexts.iter().filter_map(|(slot_id, child)| {
                let child = child.lock().ok()?;
                let selected = child.slot.kind() == crate::SlotKind::Fido2
                    && child.slot.name().contains("HID")
                    && selector.as_ref().is_none_or(|selector| {
                        child.slot.serial() == selector || child.slot.name() == *selector
                    });
                selected.then(|| (*slot_id, child.device.clone()))
            });
            let (hid_slot_id, Some(hid_device)) =
                hid_matches.next().ok_or(CKR_SLOT_ID_INVALID)?
            else {
                return Err(CKR_DEVICE_ERROR.into());
            };
            if hid_matches.next().is_some() {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            let mut piv_matches = slot_contexts.iter().filter_map(|(slot_id, child)| {
                let child = child.lock().ok()?;
                (child.slot.kind()
                    == crate::SlotKind::Ccid(crate::CcidApplication::Piv)
                    && child
                        .device
                        .as_ref()
                        .is_some_and(|device| std::sync::Arc::ptr_eq(device, &hid_device)))
                .then_some(*slot_id)
            });
            let piv_slot_id = piv_matches.next().ok_or(CKR_SLOT_ID_INVALID)?;
            if piv_matches.next().is_some() {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            Ok((hid_slot_id, piv_slot_id))
        })
        .unwrap_or_else(|error| {
            panic!(
                "expected one serial-correlated HID FIDO slot and PIV slot matching PKCS11RS_FIDO2_TEST_SOURCE={selector:?}: {error:?}"
            )
        })
    }

    #[test]
    #[ignore = "requires a FIDO2 authenticator exposed through USB HID"]
    fn fido2_hid_read_only_get_info() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
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
            if !slot.name().contains("HID") {
                return Err(CKR_TOKEN_NOT_RECOGNIZED.into());
            }
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
        .expect("selected FIDO HID authenticator did not complete authenticatorGetInfo");
    }

    #[test]
    #[ignore = "requires a YubiKey exposed through PC/SC"]
    fn pcsc_shared_connection_blocks_peers_only_during_an_operation() {
        let _guard = TEST_LOCK.lock().unwrap();
        let context = pcsc::Context::establish(pcsc::Scope::System)
            .expect("failed to establish PC/SC context");
        let reader = context
            .list_readers_owned()
            .expect("failed to list PC/SC readers")
            .into_iter()
            .next()
            .expect("no PC/SC reader with a card is available");
        let connector = crate::PcscConnector::new(reader.clone(), context.clone());
        connector
            .refresh()
            .expect("pkcs11rs failed to open a shared PC/SC connection");
        let peer_context = pcsc::Context::establish(pcsc::Scope::System)
            .expect("failed to establish the peer PC/SC context");
        let mut peer = peer_context
            .connect(
                &reader,
                pcsc::ShareMode::Shared,
                pcsc::Protocols::T0 | pcsc::Protocols::T1,
            )
            .expect("a second shared PC/SC connection could not coexist with pkcs11rs");

        let device = connector.device_context().unwrap();
        let operation = device
            .lock_operation(crate::device::DeviceOperationKind::Ccid)
            .expect("failed to enter the pkcs11rs PC/SC operation");
        CcidProbe::Management
            .run(&connector)
            .expect("read-only management probe failed inside the transaction");

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let peer_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = peer.transaction().map(drop);
            finished_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(250))
                .is_err(),
            "the peer entered a PC/SC transaction before pkcs11rs released its operation"
        );

        drop(operation);
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the peer remained blocked after pkcs11rs ended its operation")
            .expect("the peer transaction failed after pkcs11rs released the card");
        peer_thread.join().unwrap();
    }

    #[test]
    #[ignore = "requires two YubiKeys exposed through PC/SC"]
    fn pcsc_reader_workers_on_different_cards_remain_independent() {
        let _guard = TEST_LOCK.lock().unwrap();
        let context = pcsc::Context::establish(pcsc::Scope::System)
            .expect("failed to establish PC/SC context");
        let readers = context
            .list_readers_owned()
            .expect("failed to list PC/SC readers")
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(readers.len(), 2, "two PC/SC readers are required");

        let first = crate::PcscConnector::new(readers[0].clone(), context.clone());
        let second = crate::PcscConnector::new(readers[1].clone(), context.clone());
        first.refresh().expect("failed to open the first reader");
        second.refresh().expect("failed to open the second reader");

        let first_device = first.device_context().unwrap();
        let first_operation = first_device
            .lock_operation(crate::device::DeviceOperationKind::Ccid)
            .expect("failed to enter the first reader operation");
        CcidProbe::Management
            .run(&first)
            .expect("the first read-only management probe failed");

        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let second_thread = std::thread::spawn(move || {
            let device = second.device_context().unwrap();
            let operation = device
                .lock_operation(crate::device::DeviceOperationKind::Ccid)
                .expect("failed to enter the second reader operation");
            let result = CcidProbe::Management.run(&second);
            drop(operation);
            finished_tx.send(result).unwrap();
        });
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the second reader was blocked by the first reader's transaction")
            .expect("the second read-only management probe failed");

        drop(first_operation);
        second_thread.join().unwrap();
    }

    #[test]
    #[ignore = "requires two YubiKeys exposed through PC/SC"]
    fn one_pcsc_context_allows_transactions_on_different_readers() {
        let _guard = TEST_LOCK.lock().unwrap();
        let context = pcsc::Context::establish(pcsc::Scope::System)
            .expect("failed to establish PC/SC context");
        let readers = context
            .list_readers_owned()
            .expect("failed to list PC/SC readers")
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(readers.len(), 2, "two PC/SC readers are required");
        let mut first = context
            .connect(
                &readers[0],
                pcsc::ShareMode::Shared,
                pcsc::Protocols::T0 | pcsc::Protocols::T1,
            )
            .expect("failed to connect to the first reader");
        let mut second = context
            .connect(
                &readers[1],
                pcsc::ShareMode::Shared,
                pcsc::Protocols::T0 | pcsc::Protocols::T1,
            )
            .expect("failed to connect to the second reader");

        let first_transaction = first
            .transaction()
            .expect("failed to begin the first reader transaction");
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let second_thread = std::thread::spawn(move || {
            let result = second.transaction().map(drop);
            finished_tx.send(result).unwrap();
        });
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the shared context blocked a transaction on another reader")
            .expect("the second reader transaction failed");

        drop(first_transaction);
        second_thread.join().unwrap();
    }

    #[test]
    #[ignore = "deliberately overlaps raw HID and CCID operations on one physical YubiKey"]
    fn diagnoses_yubikey_hid_ccid_cross_interface_concurrency() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        let fixture = cross_interface_fixture();
        eprintln!(
            "cross-interface diagnostic uses serial {}, HID endpoint {:?}, PC/SC reader {:?}, firmware {}.{}.{}, host {}-{}",
            fixture.hid.serial,
            fixture.hid.descriptor.name(),
            fixture.pcsc.name,
            fixture.hid.firmware.0,
            fixture.hid.firmware.1,
            fixture.hid.firmware.2,
            std::env::consts::OS,
            std::env::consts::ARCH,
        );

        hid_get_info(&fixture.hid.descriptor)
            .expect("sequential HID authenticatorGetInfo baseline failed");
        let management_connector = open_pcsc_connector(fixture.pcsc.reader.clone())
            .expect("sequential PC/SC baseline connection failed");
        CcidProbe::Management
            .run(&management_connector)
            .expect("sequential CCID Management baseline failed");
        drop(management_connector);

        let mut supported = vec![CcidProbe::Management];
        for probe in [CcidProbe::Piv, CcidProbe::Fido] {
            let connector = open_pcsc_connector(fixture.pcsc.reader.clone())
                .expect("PC/SC capability probe connection failed");
            match probe.run(&connector) {
                Ok(()) => supported.push(probe),
                Err(error) => eprintln!(
                    "skipping HID versus {} phase because its sequential baseline failed: {error:?}",
                    probe.label()
                ),
            }
        }

        for probe in supported {
            let (hid, ccid) = run_cross_interface_phase(&fixture, probe, None);
            eprintln!(
                "HID GetInfo versus {}: HID {}/{} successful in {:?}, CCID {}/{} successful in {:?}",
                probe.label(),
                hid.successes,
                hid.attempts,
                hid.elapsed,
                ccid.successes,
                ccid.attempts,
                ccid.elapsed,
            );
            if !hid.errors.is_empty() {
                eprintln!("  HID errors: {:?}", hid.errors);
            }
            if !ccid.errors.is_empty() {
                eprintln!("  CCID errors: {:?}", ccid.errors);
            }

            hid_get_info(&fixture.hid.descriptor).unwrap_or_else(|error| {
                panic!(
                    "HID failed its sequential health check after overlap with {}: {error:?}",
                    probe.label()
                )
            });
            let connector = open_pcsc_connector(fixture.pcsc.reader.clone())
                .expect("PC/SC post-overlap health-check connection failed");
            probe.run(&connector).unwrap_or_else(|error| {
                panic!(
                    "{} failed its sequential health check after overlap: {error:?}",
                    probe.label()
                )
            });
        }
    }

    #[test]
    #[ignore = "requires one serial-matched YubiKey exposed through both FIDO HID and PC/SC"]
    fn serializes_yubikey_hid_ccid_cross_interface_operations() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        let fixture = cross_interface_fixture();
        let device = std::sync::Arc::new(crate::device::DeviceContext::test());
        let mut supported = Vec::new();
        for probe in [CcidProbe::Management, CcidProbe::Piv, CcidProbe::Fido] {
            let connector = open_pcsc_connector(fixture.pcsc.reader.clone())
                .expect("PC/SC capability probe connection failed");
            if probe.run(&connector).is_ok() {
                supported.push(probe);
            }
        }
        assert!(
            !supported.is_empty(),
            "the serial-matched PC/SC interface had no supported read-only probe"
        );

        for probe in supported {
            let (hid, ccid) = run_cross_interface_phase(&fixture, probe, Some(device.clone()));
            assert_eq!(
                hid.successes,
                hid.attempts,
                "coordinated HID GetInfo failed against {}: {:?}",
                probe.label(),
                hid.errors
            );
            assert_eq!(
                ccid.successes,
                ccid.attempts,
                "coordinated {} failed against HID GetInfo: {:?}",
                probe.label(),
                ccid.errors
            );
        }
    }

    #[test]
    #[ignore = "requires one serial-matched HID/PCSC YubiKey and PKCS11RS_FIDO2_TEST_PIN"]
    fn pkcs11_dispatch_serializes_fido_hid_login_against_piv_ccid() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        let mut pin = std::env::var(CURRENT_PIN_ENV)
            .expect("PKCS11RS_FIDO2_TEST_PIN gates the single FIDO PIN verification")
            .into_bytes();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let (hid_slot_id, piv_slot_id) = paired_hid_fido_and_piv_slot_ids();

        let mut hid_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                hid_slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut hid_session,
            ),
            CKR_OK as CK_RV
        );

        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let hid_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pcsc_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hid_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let login_result = std::thread::scope(|scope| {
            let hid_start = start.clone();
            let hid_ready_for_worker = hid_ready.clone();
            let pcsc_started_for_hid = pcsc_started.clone();
            let hid_done_for_worker = hid_done.clone();
            let hid_worker = scope.spawn(move || {
                hid_start.wait();
                hid_ready_for_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                while !pcsc_started_for_hid.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                let result = crate::api::C_Login(
                    hid_session,
                    CKU_USER as CK_USER_TYPE,
                    pin.as_mut_ptr(),
                    pin.len() as CK_ULONG,
                );
                hid_done_for_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                result
            });

            let pcsc_start = start;
            let hid_ready_for_pcsc = hid_ready;
            let pcsc_started_for_worker = pcsc_started;
            let hid_done_for_pcsc = hid_done;
            let pcsc_worker = scope.spawn(move || {
                pcsc_start.wait();
                while !hid_ready_for_pcsc.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                for _ in 0..CROSS_INTERFACE_ITERATIONS {
                    pcsc_started_for_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                    let mut piv_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
                    assert_eq!(
                        crate::api::C_OpenSession(
                            piv_slot_id,
                            CKF_SERIAL_SESSION as CK_FLAGS,
                            std::ptr::null_mut(),
                            None,
                            &mut piv_session,
                        ),
                        CKR_OK as CK_RV
                    );
                    assert_eq!(crate::api::C_CloseSession(piv_session), CKR_OK as CK_RV);
                    if hid_done_for_pcsc.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                }
            });

            let login_result = hid_worker.join().expect("HID PKCS #11 worker panicked");
            pcsc_worker.join().expect("PIV PKCS #11 worker panicked");
            login_result
        });

        assert_eq!(
            login_result, CKR_OK as CK_RV,
            "the single FIDO PIN verification failed"
        );
        assert_eq!(crate::api::C_Logout(hid_session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(hid_session), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    #[test]
    #[ignore = "requires a FIDO2 authenticator and PKCS11RS_FIDO2_TEST_PIN"]
    fn fido2_read_only_resident_credential_enumeration() {
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
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
    #[ignore = "requires a discoverable FIDO2 credential, its PIN, and user presence"]
    fn fido2_resident_credential_get_assertion() {
        let Ok(pin) = std::env::var(CURRENT_PIN_ENV) else {
            eprintln!("skipped resident-credential assertion; set {CURRENT_PIN_ENV} to enable it");
            return;
        };
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let slot_id = fido2_slot_id();
        let mut session = 0;
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
        let mut pin = pin.into_bytes();
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );

        let mut class = CKO_PRIVATE_KEY as CK_ULONG;
        let mut can_sign = CK_TRUE as CK_BBOOL;
        let mut label = b"pkcs11rs.invalid: pkcs11rs synthetic user private key".to_vec();
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
                pValue: (&mut can_sign as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
                pValue: label.as_mut_ptr().cast(),
                ulValueLen: label.len() as CK_ULONG,
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
        let mut key = 0;
        let mut count = 0;
        assert_eq!(
            crate::api::C_FindObjects(session, &mut key, 1, &mut count),
            CKR_OK as CK_RV
        );
        assert_eq!(crate::api::C_FindObjectsFinal(session), CKR_OK as CK_RV);
        assert_eq!(
            count, 1,
            "the synthetic resident FIDO credential was not discovered"
        );

        let mut mechanism = CK_MECHANISM {
            mechanism: crate::CKM_PKCS11RS_FIDO_ASSERTION,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert_eq!(
            crate::api::C_SignInit(session, &mut mechanism, key),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_Login(
                session,
                CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
        let client_data_hash: [u8; 32] =
            sha2::Sha256::digest(b"pkcs11rs FIDO2 hardware assertion").into();
        let mut response_len = 0;
        assert_eq!(
            crate::api::C_Sign(
                session,
                client_data_hash.as_ptr() as *mut CK_BYTE,
                client_data_hash.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut response_len,
            ),
            CKR_OK as CK_RV
        );
        let mut response = vec![0; response_len as usize];
        assert_eq!(
            crate::api::C_Sign(
                session,
                client_data_hash.as_ptr() as *mut CK_BYTE,
                client_data_hash.len() as CK_ULONG,
                response.as_mut_ptr(),
                &mut response_len,
            ),
            CKR_OK as CK_RV
        );
        let mut decoder = minicbor::Decoder::new(&response);
        let fields = decoder
            .map()
            .expect("GetAssertion response is not CBOR")
            .expect("GetAssertion response uses an indefinite map");
        for _ in 0..fields {
            decoder.skip().expect("invalid GetAssertion response key");
            decoder.skip().expect("invalid GetAssertion response value");
        }
        assert_eq!(decoder.position(), response.len());
        eprintln!(
            "received and validated a {}-byte CTAP GetAssertion response",
            response.len()
        );
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
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
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let slot_id = fido2_slot_id();
        let credential = crate::with_context(|context| {
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
        eprintln!(
            "makeCredential attestation: {:?}, certificate count {}, AAGUID {:02x?}",
            credential.attestation_trust,
            credential.attestation_certificate_count,
            credential.aaguid
        );

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
                        && object.id == credential.credential_id
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
    #[ignore = "creates a persistent FIDO credential with the experimental previewSign extension and requires touch"]
    fn creates_preview_sign_registration() {
        let Ok(pin) = std::env::var(CURRENT_PIN_ENV) else {
            eprintln!(
                "skipped persistent previewSign registration; set {CURRENT_PIN_ENV} (to an empty value for an authenticator without a PIN) to enable it"
            );
            return;
        };
        let pin = zeroize::Zeroizing::new(pin.into_bytes());
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let slot_id = fido2_slot_id();
        let registration = crate::with_context(|context| {
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
                .create_fido2_preview_sign_test_registration(&pin)
        })
        .expect("authenticatorMakeCredential rejected the previewSign registration");
        eprintln!(
            "created previewSign registration: parent credential {} bytes, signing key handle {} bytes, seed COSE key {} bytes, algorithm {}, policy {:?}, AAGUID {:02x?}, serial hint {:?}, wrapper {} bytes",
            registration.credential_id().len(),
            registration.signing_key_handle().len(),
            registration.signing_seed_public_key_cose().len(),
            registration.algorithm(),
            registration.policy(),
            registration.aaguid(),
            registration.token_serial_hint(),
            registration
                .to_cbor()
                .expect("previewSign wrapper encoding failed")
                .len(),
        );
    }

    #[test]
    #[ignore = "completes and cleans up a persistent previewSign credential through live hardware"]
    fn completes_preview_sign_pkcs11_cycle_on_hardware() {
        let Ok(pin) = std::env::var(CURRENT_PIN_ENV) else {
            eprintln!("skipped previewSign hardware cycle; set {CURRENT_PIN_ENV} to enable it");
            return;
        };
        let mut pin = zeroize::Zeroizing::new(pin.into_bytes());
        let _guard = TEST_LOCK.lock().unwrap();
        finalize_for_test();
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
        let slot_id = fido2_slot_id();

        let mut mechanism_count = 0;
        assert_eq!(
            crate::C_GetMechanismList(slot_id, std::ptr::null_mut(), &mut mechanism_count),
            CKR_OK as CK_RV
        );
        let mut mechanisms = vec![0; mechanism_count as usize];
        assert_eq!(
            crate::C_GetMechanismList(slot_id, mechanisms.as_mut_ptr(), &mut mechanism_count,),
            CKR_OK as CK_RV
        );
        for required in [
            crate::CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
            crate::CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
            crate::CKM_PKCS11RS_PREVIEW_SIGN,
            crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        ] {
            assert!(
                mechanisms.contains(&required),
                "FIDO slot does not advertise required mechanism {required:#x}"
            );
        }

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
            crate::api::C_Login(
                session,
                CKU_USER as CK_USER_TYPE,
                pin.as_mut_ptr(),
                pin.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );

        let mut mechanism = CK_MECHANISM {
            mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut ec = CKK_EC as CK_ULONG;
        let mut token = CK_TRUE as CK_BBOOL;
        let mut private = CK_TRUE as CK_BBOOL;
        let mut public_template = [
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
        ];
        let mut private_template = [
            scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut token),
            scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
        ];
        let mut credential_public_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        let mut credential_private_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as CK_ULONG,
                private_template.as_mut_ptr(),
                private_template.len() as CK_ULONG,
                &mut credential_public_key,
                &mut credential_private_key,
            ),
            CKR_OK as CK_RV
        );
        assert_ne!(credential_public_key, credential_private_key);

        let registration_encoded = read_attribute(
            session,
            credential_private_key,
            crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        );
        let registration =
            crate::preview_sign::PreviewSignRegistration::from_cbor(&registration_encoded)
                .expect("hardware returned an invalid previewSign registration wrapper");
        let mut cleanup =
            PreviewCredentialCleanup::new(slot_id, &pin, registration.credential_id());

        let mut class = CKO_PRIVATE_KEY as CK_ULONG;
        let mut registration_key_type = crate::CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION as CK_ULONG;
        let mut session_object = CK_FALSE as CK_BBOOL;
        let mut derive = CK_TRUE as CK_BBOOL;
        let mut registration_value = registration_encoded.clone();
        let mut registration_template = [
            scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
            scalar_attribute(
                CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
                &mut registration_key_type,
            ),
            scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
            scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
            scalar_attribute(CKA_DERIVE as CK_ATTRIBUTE_TYPE, &mut derive),
            bytes_attribute(
                crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
                &mut registration_value,
            ),
        ];
        let mut registration_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
        assert_eq!(
            crate::api::C_CreateObject(
                session,
                registration_template.as_mut_ptr(),
                registration_template.len() as CK_ULONG,
                &mut registration_key,
            ),
            CKR_OK as CK_RV
        );

        let mut sign = CK_TRUE as CK_BBOOL;
        let mut verify = CK_TRUE as CK_BBOOL;
        let digest: [u8; 32] = sha2::Sha256::digest(b"pkcs11rs previewSign hardware cycle").into();
        let mut derived_encodings = Vec::new();
        let mut public_points = Vec::new();
        let mut signatures = Vec::new();
        let mut projected_keys = Vec::new();
        let mut session_objects = Vec::new();

        for context in [
            b"pkcs11rs previewSign hardware key one".as_slice(),
            b"pkcs11rs previewSign hardware key two".as_slice(),
        ] {
            let mut derivation_context = context.to_vec();
            mechanism = CK_MECHANISM {
                mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
                pParameter: derivation_context.as_mut_ptr().cast(),
                ulParameterLen: derivation_context.len() as CK_ULONG,
            };
            let mut derived_template = [
                scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
                scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
                scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
                scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
            ];
            let mut signing_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
            assert_eq!(
                crate::api::C_DeriveKey(
                    session,
                    &mut mechanism,
                    registration_key,
                    derived_template.as_mut_ptr(),
                    derived_template.len() as CK_ULONG,
                    &mut signing_key,
                ),
                CKR_OK as CK_RV
            );
            assert_eq!(
                read_attribute(
                    session,
                    signing_key,
                    crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
                ),
                registration_encoded
            );
            let derived_encoded = read_attribute(
                session,
                signing_key,
                crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
            );
            crate::preview_sign::PreviewSignDerivedKeyRecord::from_cbor(&derived_encoded)
                .expect("hardware derivation produced an invalid derived-key wrapper");
            assert_eq!(
                crate::api::C_DestroyObject(session, signing_key),
                CKR_OK as CK_RV
            );

            let mut restored_registration = registration_encoded.clone();
            let mut restored_derived = derived_encoded.clone();
            let mut restore_template = [
                scalar_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE, &mut class),
                scalar_attribute(CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE, &mut ec),
                scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
                scalar_attribute(CKA_PRIVATE as CK_ATTRIBUTE_TYPE, &mut private),
                scalar_attribute(CKA_SIGN as CK_ATTRIBUTE_TYPE, &mut sign),
                bytes_attribute(
                    crate::CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
                    &mut restored_registration,
                ),
                bytes_attribute(
                    crate::CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
                    &mut restored_derived,
                ),
            ];
            let mut restored_signing_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
            assert_eq!(
                crate::api::C_CreateObject(
                    session,
                    restore_template.as_mut_ptr(),
                    restore_template.len() as CK_ULONG,
                    &mut restored_signing_key,
                ),
                CKR_OK as CK_RV
            );

            let mut project = CK_MECHANISM {
                mechanism: crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut projected_template = [
                scalar_attribute(CKA_TOKEN as CK_ATTRIBUTE_TYPE, &mut session_object),
                scalar_attribute(CKA_VERIFY as CK_ATTRIBUTE_TYPE, &mut verify),
            ];
            let mut projected_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
            assert_eq!(
                crate::api::C_DeriveKey(
                    session,
                    &mut project,
                    restored_signing_key,
                    projected_template.as_mut_ptr(),
                    projected_template.len() as CK_ULONG,
                    &mut projected_key,
                ),
                CKR_OK as CK_RV
            );

            mechanism = CK_MECHANISM {
                mechanism: crate::CKM_PKCS11RS_PREVIEW_SIGN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            assert_eq!(
                crate::api::C_SignInit(session, &mut mechanism, restored_signing_key),
                CKR_OK as CK_RV
            );
            let mut signature_length = 0;
            assert_eq!(
                crate::api::C_Sign(
                    session,
                    digest.as_ptr().cast_mut(),
                    digest.len() as CK_ULONG,
                    std::ptr::null_mut(),
                    &mut signature_length,
                ),
                CKR_OK as CK_RV
            );
            assert_eq!(signature_length, 64);
            let mut signature = vec![0; signature_length as usize];
            assert_eq!(
                crate::api::C_Sign(
                    session,
                    digest.as_ptr().cast_mut(),
                    digest.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut signature_length,
                ),
                CKR_OK as CK_RV
            );
            signature.truncate(signature_length as usize);

            let mut verify_mechanism = CK_MECHANISM {
                mechanism: CKM_ECDSA as CK_MECHANISM_TYPE,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            assert_eq!(
                crate::api::C_VerifyInit(session, &mut verify_mechanism, projected_key),
                CKR_OK as CK_RV
            );
            assert_eq!(
                crate::api::C_Verify(
                    session,
                    digest.as_ptr().cast_mut(),
                    digest.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    signature.len() as CK_ULONG,
                ),
                CKR_OK as CK_RV
            );

            derived_encodings.push(derived_encoded);
            public_points.push(read_attribute(
                session,
                projected_key,
                CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
            ));
            signatures.push(signature);
            projected_keys.push(projected_key);
            session_objects.extend([projected_key, restored_signing_key]);
        }

        assert_ne!(derived_encodings[0], derived_encodings[1]);
        assert_ne!(public_points[0], public_points[1]);
        assert_ne!(signatures[0], signatures[1]);
        let mut verify_mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA as CK_MECHANISM_TYPE,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert_eq!(
            crate::api::C_VerifyInit(session, &mut verify_mechanism, projected_keys[0]),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_Verify(
                session,
                digest.as_ptr().cast_mut(),
                digest.len() as CK_ULONG,
                signatures[1].as_ptr().cast_mut(),
                signatures[1].len() as CK_ULONG,
            ),
            CKR_SIGNATURE_INVALID as CK_RV
        );

        session_objects.push(registration_key);
        for object in session_objects {
            assert_eq!(
                crate::api::C_DestroyObject(session, object),
                CKR_OK as CK_RV
            );
        }
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        cleanup.delete_and_verify();
        assert_eq!(
            crate::api::C_Finalize(std::ptr::null_mut()),
            CKR_OK as CK_RV
        );

        eprintln!(
            "completed two-key previewSign hardware cycle and deleted parent credential: registration {} bytes, derived wrappers {:?}, signatures {:?}, serial hint {:?}",
            registration_encoded.len(),
            derived_encodings.iter().map(Vec::len).collect::<Vec<_>>(),
            signatures.iter().map(Vec::len).collect::<Vec<_>>(),
            registration.token_serial_hint(),
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
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
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
        assert_eq!(initialize_direct_hardware(false), CKR_OK as CK_RV);
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
