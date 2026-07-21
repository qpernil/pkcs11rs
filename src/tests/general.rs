#[test]
pub fn bindgen_test_layout_CK_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_INFO>(),
        88usize,
        concat!("Size of: ", stringify!(CK_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, cryptokiVersion),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(cryptokiVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, manufacturerID),
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, flags),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryDescription),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(libraryDescription)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryVersion),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(libraryVersion)
        )
    );
}

#[test]
pub fn all_pkcs11_2_40_function_list_entries_are_present() {
    let mut function_list: CK_FUNCTION_LIST_PTR = ::std::ptr::null_mut();

    assert_eq!(
        crate::C_GetFunctionList(&mut function_list),
        CKR_OK as CK_RV
    );
    assert_eq!(unsafe { (*function_list).version.major }, 2);
    assert_eq!(unsafe { (*function_list).version.minor }, 40);
    assert_function_slots_present(function_list, PKCS11_2_40_FUNCTION_COUNT);
}

#[test]
pub fn all_supported_interfaces_are_discoverable() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut count = 0;
    assert_eq!(
        crate::C_GetInterfaceList(::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 4);

    let empty_interface = CK_INTERFACE {
        pInterfaceName: ::std::ptr::null_mut(),
        pFunctionList: ::std::ptr::null_mut(),
        flags: 0,
    };
    let mut interfaces = [empty_interface; 4];
    assert_eq!(
        crate::C_GetInterfaceList(interfaces.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 4);
    for interface in &interfaces {
        assert!(!interface.pInterfaceName.is_null());
        assert!(!interface.pFunctionList.is_null());
    }
    let versions: Vec<(u8, u8)> = interfaces
        .iter()
        .map(|interface| {
            let version = unsafe { &*(interface.pFunctionList as *const CK_VERSION) };
            (version.major, version.minor)
        })
        .collect();
    assert_eq!(versions, [(2, 40), (3, 0), (3, 1), (3, 2)]);

    let function_list = interfaces[3].pFunctionList as CK_FUNCTION_LIST_3_2_PTR;
    assert_eq!(unsafe { (*function_list).version.major }, 3);
    assert_eq!(unsafe { (*function_list).version.minor }, 2);
    assert!(unsafe { (*function_list).C_GetInterface.is_some() });
    assert!(unsafe { (*function_list).C_EncapsulateKey.is_some() });
    assert_function_slots_present(
        function_list,
        PKCS11_2_40_FUNCTION_COUNT + PKCS11_3_0_FUNCTION_COUNT + PKCS11_3_2_FUNCTION_COUNT,
    );
}

#[test]
pub fn get_info_reports_cryptoki_3_2() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32usize],
        flags: 0,
        libraryDescription: [0; 32usize],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    assert_eq!(crate::C_GetInfo(&mut info), CKR_OK as CK_RV);
    assert_eq!(info.cryptokiVersion.major, 3);
    assert_eq!(info.cryptokiVersion.minor, 2);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn initialize_and_finalize_reject_reserved_args() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: 1 as CK_VOID_PTR,
    };

    assert_eq!(
        crate::C_Initialize(&mut init_args as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Finalize(1 as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}

#[test]
pub fn finalize_clears_context_after_device_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_Finalize(::std::ptr::null_mut()),
        CKR_FUNCTION_FAILED as CK_RV
    );
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn initialize_validates_mutex_callback_configuration() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut partial_callbacks = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(test_create_mutex),
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut partial_callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut os_locking = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK as CK_FLAGS,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut os_locking as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut callbacks = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(test_create_mutex),
        DestroyMutex: Some(test_destroy_mutex),
        LockMutex: Some(test_lock_mutex),
        UnlockMutex: Some(test_unlock_mutex),
        flags: 0,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_CANT_LOCK as CK_RV
    );

    callbacks.flags = CKF_OS_LOCKING_OK as CK_FLAGS;
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    callbacks.flags = 1 << 31;
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}

#[test]
pub fn short_usb_writes_are_device_errors() {
    assert!(crate::ensure_complete_write(64, 64).is_ok());
    let rv: CK_RV = crate::ensure_complete_write(63, 64).unwrap_err().into();
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
}

#[test]
pub fn usb_zlp_is_only_required_on_nonzero_packet_boundaries() {
    assert!(crate::needs_zero_length_packet(64, 64));
    assert!(crate::needs_zero_length_packet(128, 64));
    assert!(!crate::needs_zero_length_packet(63, 64));
    assert!(!crate::needs_zero_length_packet(0, 0));
}

#[test]
pub fn yubikey_login_preserves_connector_errors() {
    let base: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let mut slot = crate::GlobalPlatformSlot {
        connector: std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        )),
        application_aid,
        authenticated: std::cell::Cell::new(false),
    };

    let rv: CK_RV = crate::Slot::login(&mut slot, b"1234").unwrap_err().into();
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
}

#[test]
fn applet_configuration_accepts_only_canonical_names() {
    assert_eq!(
        crate::parse_ccid_application("globalplatform").unwrap(),
        crate::CcidApplication::GlobalPlatform
    );
    for invalid in ["pgp", "yubihsm-auth", "global-platform", "gp", "scp03"] {
        assert!(crate::parse_ccid_application(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn secure_channel_configuration_accepts_only_explicit_protocols() {
    assert_eq!(
        crate::parse_secure_channel("scp03").unwrap(),
        crate::SecureChannelProtocol::Scp03
    );
    assert_eq!(
        crate::parse_secure_channel("scp11a").unwrap(),
        crate::SecureChannelProtocol::Scp11a
    );
    assert_eq!(
        crate::parse_secure_channel("scp11b").unwrap(),
        crate::SecureChannelProtocol::Scp11b
    );
    assert!(crate::parse_secure_channel("scp11").is_err());
}

#[test]
fn ccid_application_discovery_defaults_to_supported_applets() {
    assert_eq!(
        crate::default_ccid_applications(),
        vec![
            crate::CcidApplication::Piv,
            crate::CcidApplication::OpenPgp,
            crate::CcidApplication::HsmAuth,
            crate::CcidApplication::GlobalPlatform,
        ]
    );
}

#[test]
fn pcsc_applet_presence_requires_a_successful_aid_select() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
    );

    assert_eq!(
        crate::Connector::name(&connector),
        crate::Connector::name(base.as_ref())
    );
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    base.select_ok.set(false);
    assert!(crate::Connector::refresh(&connector).is_err());
    assert!(!crate::Connector::is_present(&connector));
    assert!(connector
        .discovery_error
        .borrow()
        .as_deref()
        .is_some_and(|reason| reason.contains("Generic")));
    base.select_ok.set(true);
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    assert!(connector.discovery_error.borrow().is_none());
}

#[test]
fn pcsc_applet_connector_reuses_selected_aid() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
    );
    let mut receive = [0; 16];

    assert!(crate::Connector::transmit(
        &connector,
        &[0x00, 0x00],
        &mut receive,
        std::time::Duration::from_secs(1),
    )
    .is_ok());
    base.select_ok.set(false);
    assert!(crate::Connector::transmit(
        &connector,
        &[0x00, 0x00],
        &mut receive,
        std::time::Duration::from_secs(1),
    )
    .is_ok());
}

#[test]
fn openpgp_slot_info_reports_application_version_and_serial() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let mut slot = crate::OpenPgpSlot::new(connector, aid);
    slot.version = (3, 4);
    slot.serial = String::from("12345678");

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.hardwareVersion.major,
            slot_info.hardwareVersion.minor
        ),
        (1, 0)
    );
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (3, 4)
    );
    assert_eq!(crate::Slot::serial(&slot), "12345678");
}

#[test]
fn openpgp_slot_uses_shared_serial_before_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::OpenPgpSlot::new(connector, aid);

    assert_eq!(crate::Slot::serial(&slot), "12345678");
}

#[test]
fn openpgp_slot_uses_shared_firmware_before_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::OpenPgpSlot::new(connector, aid);

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (5, 7)
    );
}

#[test]
fn openpgp_attestation_key_matches_private_key_visibility_without_capabilities() {
    let generated = openssl::rsa::Rsa::generate(2048).unwrap();
    let public_key = openssl::rsa::Rsa::from_public_components(
        generated.n().to_owned().unwrap(),
        generated.e().to_owned().unwrap(),
    )
    .unwrap();
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let slot = crate::OpenPgpSlot {
        connector,
        application_aid: Vec::new(),
        authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        version: (3, 4),
        serial: String::from("TEST0001"),
        pin_min: 6,
        pin_max: 127,
        admin_pin_min: 8,
        admin_pin_max: 127,
        kdf: None,
        keys: vec![crate::openpgp::KeyInfo {
            key_ref: crate::openpgp::KeyRef::Attestation,
            algorithm: crate::openpgp::Algorithm::Rsa { bits: 2048 },
            public_key: crate::openpgp::PublicKey::Rsa(public_key),
            pin_policy: 0,
            local: false,
        }],
        certificates: vec![crate::OpenPgpCertificate {
            key_ref: crate::openpgp::KeyRef::Attestation,
            key_type: CKK_RSA as CK_KEY_TYPE,
            value: vec![0x30, 0],
        }],
    };

    let objects = crate::Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(objects.len(), 3);

    let public = objects
        .iter()
        .find(|object| object.unique_id == b"openpgp-81-public")
        .unwrap();
    assert_eq!(public.class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert!(public.verify);

    let private = objects
        .iter()
        .find(|object| object.unique_id == b"openpgp-81-private")
        .unwrap();
    assert_eq!(private.class, CKO_PRIVATE_KEY as CK_OBJECT_CLASS);
    assert!(private.private);
    assert!(private.sensitive);
    assert!(!private.extractable);
    assert!(!private.local);
    assert_eq!(private.key_gen_mechanism, None);
    assert!(!private.encrypt);
    assert!(!private.decrypt);
    assert!(!private.sign);
    assert!(!private.verify);
    assert!(!private.derive);

    let certificate = objects
        .iter()
        .find(|object| object.unique_id == b"openpgp-81-certificate")
        .unwrap();
    assert_eq!(certificate.class, CKO_CERTIFICATE as CK_OBJECT_CLASS);
}

#[test]
fn openpgp_generated_key_algorithms_report_key_pair_generation_mechanisms() {
    assert_eq!(
        crate::openpgp_key_generation_mechanism(crate::openpgp::Algorithm::Rsa { bits: 2048 }),
        Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    );
    assert_eq!(
        crate::openpgp_key_generation_mechanism(crate::openpgp::Algorithm::Ecdsa(
            crate::openpgp::Curve::P256,
        )),
        Some(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    );
    assert_eq!(
        crate::openpgp_key_generation_mechanism(crate::openpgp::Algorithm::Ed25519),
        Some(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    );
    assert_eq!(
        crate::openpgp_key_generation_mechanism(crate::openpgp::Algorithm::Ecdh(
            crate::openpgp::Curve::X25519,
        )),
        Some(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    );
}

#[test]
fn openpgp_metadata_failure_does_not_hide_selected_applet() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let mut slot = crate::OpenPgpSlot::new(connector, aid);

    assert!(crate::Slot::is_present(&slot));
    assert!(crate::Slot::init_slot(&mut slot).is_err());
    assert!(crate::Slot::is_present(&slot));
}

#[test]
fn openpgp_pw1_policy_maps_sign_once_to_context_specific_login() {
    assert!(crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Signature,
        crate::openpgp::PW1_ONE_SIGNATURE,
    ));
    assert!(!crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Signature,
        crate::openpgp::PW1_MULTIPLE_SIGNATURES,
    ));
    assert!(!crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Authentication,
        crate::openpgp::PW1_ONE_SIGNATURE,
    ));

    let mut object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: b"openpgp-private".to_vec(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: b"OpenPGP signature key".to_vec(),
        id: vec![1],
        token: true,
        private: true,
        encrypt: false,
        decrypt: false,
        sign: true,
        verify: false,
        derive: false,
        sensitive: true,
        extractable: false,
        always_sensitive: true,
        never_extractable: true,
        local: true,
        key_gen_mechanism: None,
        owner_session: None,
        material: crate::KeyMaterial::OpenPgpPrivate {
            key_ref: crate::openpgp::KeyRef::Signature,
            algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
            modulus: vec![0; 256],
            public_exponent: vec![1, 0, 1],
            public_key: vec![0; 256],
            pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
        },
    };
    assert!(object
        .attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE)
        .is_some());
    object.material = crate::KeyMaterial::OpenPgpPrivate {
        key_ref: crate::openpgp::KeyRef::Authentication,
        algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
        modulus: vec![0; 256],
        public_exponent: vec![1, 0, 1],
        public_key: vec![0; 256],
        pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
    };
    assert_eq!(
        object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
}

#[test]
fn openpgp_always_authenticate_expires_after_one_signature() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "OPENPGP001",
    });
    let authenticated = std::rc::Rc::new(std::cell::Cell::new(true));
    let session = crate::OpenPgpSession {
        slotID: TEST_SLOT_ID,
        flags: CKF_SERIAL_SESSION as CK_FLAGS,
        connector,
        authenticated: authenticated.clone(),
    };

    let _ = crate::Session::openpgp_sign(
        &session,
        crate::openpgp::KeyRef::Signature,
        &[],
        crate::openpgp::PW1_ONE_SIGNATURE,
    );
    assert!(!authenticated.get());
}

#[test]
fn piv_slot_uses_shared_metadata_before_piv_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = crate::piv::PIV_AID.to_vec();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::PivSlot::new(connector, aid);

    assert_eq!(crate::Slot::serial(&slot), "12345678");
    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (5, 70)
    );
}

#[test]
fn globalplatform_token_model_identifies_the_applet() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::GlobalPlatformSlot {
        connector,
        application_aid: aid,
        authenticated: std::cell::Cell::new(false),
    };

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    assert!(crate::Slot::get_token_info(&slot, &mut token_info).is_ok());
    assert_eq!(&token_info.model[..9], b"Issuer SD");
    assert_eq!(&token_info.label[..21], b"Issuer SD #SELECT0001");
}

#[test]
fn ccid_application_list_is_an_allowlist() {
    assert_eq!(
        crate::parse_ccid_application_list("openpgp, piv, openpgp").unwrap(),
        vec![crate::CcidApplication::OpenPgp, crate::CcidApplication::Piv,]
    );
    assert!(crate::parse_ccid_application_list(", ,").is_err());
}

#[test]
pub fn missing_scp_session_invalidates_pkcs11_login_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let base: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.slots.insert(
            TEST_SLOT_ID,
            Box::new(crate::GlobalPlatformSlot {
                connector: connector.clone(),
                application_aid,
                authenticated: std::cell::Cell::new(false),
            }),
        );
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(crate::PcscAppletSession {
                slotID: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
                connector,
            }),
        );
        context
            .logged_in_slots
            .insert(TEST_SLOT_ID, crate::LoginRole::User);
    }

    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_DEVICE_ERROR as CK_RV
    );
    let context = crate::lock_context().unwrap();
    assert!(!context
        .as_ref()
        .unwrap()
        .logged_in_slots
        .contains_key(&TEST_SLOT_ID));
    drop(context);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn authentication_loss_cancels_active_private_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let login_active = std::rc::Rc::new(std::cell::Cell::new(true));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.slots.insert(
            TEST_SLOT_ID,
            Box::new(TestSlot {
                present: std::cell::Cell::new(true),
                remove_on_refresh: false,
                login_active: Some(login_active.clone()),
            }),
        );
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(TestSession {
                slot_id: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
            }),
        );
        context
            .logged_in_slots
            .insert(TEST_SLOT_ID, crate::LoginRole::User);
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    login_active.set(false);
    let mut data = *b"test";
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn login_controls_private_object_visibility_and_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_public_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE + 1,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut private_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_SO as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    let mut bad_pin = *b"9999";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            bad_pin.as_mut_ptr(),
            bad_pin.len() as CK_ULONG
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!((count, objects[0]), (1, 2));
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::C_Logout(TEST_SESSION_HANDLE),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn context_specific_login_authenticates_an_always_authenticate_operation() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    {
        let mut context = crate::lock_context().unwrap();
        let object = context.as_mut().unwrap().objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            modulus: vec![0; 128],
            public_exponent: vec![1, 0, 1],
            pin_policy: 3,
            touch_policy: 1,
        };
        object.private = true;
        object.sign = true;
        object.decrypt = false;
        object.sensitive = true;
        object.extractable = false;
        assert_eq!(
            object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_TRUE as CK_BBOOL])
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        TEST_CONTEXT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn context_specific_login_does_not_require_always_authenticate_attribute() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    {
        let mut context = crate::lock_context().unwrap();
        let object = context.as_mut().unwrap().objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            modulus: vec![0; 128],
            public_exponent: vec![1, 0, 1],
            pin_policy: 2,
            touch_policy: 1,
        };
        object.private = true;
        object.sign = true;
        object.decrypt = false;
        object.sensitive = true;
        object.extractable = false;
        assert_eq!(
            object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_FALSE as CK_BBOOL])
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        TEST_CONTEXT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn context_specific_login_requires_user_login() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_public_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    {
        let mut context = crate::lock_context().unwrap();
        let object = context.as_mut().unwrap().objects.get_mut(&2).unwrap();
        object.private = false;
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn login_is_shared_and_logout_invalidates_private_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut ro_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut rw_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut ro_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut rw_session
        ),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            rw_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );

    let mut ro_info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    let mut rw_info = ro_info;
    assert_eq!(
        crate::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(rw_session, &mut rw_info),
        CKR_OK as CK_RV
    );
    assert_eq!(ro_info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);
    assert_eq!(rw_info.state, CKS_RW_USER_FUNCTIONS as CK_STATE);

    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(ro_session, &mut sign_mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut generate_mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut private_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut private_session_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            rw_session,
            &mut generate_mechanism,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut private_session_key
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Logout(rw_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(rw_session, &mut rw_info),
        CKR_OK as CK_RV
    );
    assert_eq!(ro_info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(rw_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            ro_session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::C_GetObjectSize(ro_session, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(ro_session, private_session_key, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut find_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut new_private_handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            ro_session,
            find_template.as_mut_ptr(),
            find_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(ro_session, &mut new_private_handle, 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_ne!(new_private_handle, 2);
    assert_ne!(new_private_handle, private_session_key);
    assert_eq!(crate::C_FindObjectsFinal(ro_session), CKR_OK as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn token_authentication_survives_initiating_session_and_logs_out_on_last_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_LOGGED_IN.store(false, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGOUT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);
    let mut first_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut second_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    for session in [&mut first_session, &mut second_session] {
        assert_eq!(
            crate::C_OpenSession(
                TEST_SLOT_ID,
                CKF_SERIAL_SESSION as CK_FLAGS,
                ::std::ptr::null_mut(),
                None,
                session
            ),
            CKR_OK as CK_RV
        );
    }

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            first_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert!(TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_CloseSession(first_session), CKR_OK as CK_RV);
    assert!(TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::C_GetSessionInfo(second_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(crate::C_CloseSession(second_session), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut close_all_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut close_all_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            close_all_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseAllSessions(TEST_SLOT_ID), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    let mut final_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut final_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            final_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        3
    );
}

#[test]
pub fn token_info_reports_current_session_counts() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut read_only_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut read_write_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_only_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_write_session
        ),
        CKR_OK as CK_RV
    );

    let mut info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE as CK_ULONG);
    assert_eq!(info.ulSessionCount, 2);
    assert_eq!(
        info.ulMaxRwSessionCount,
        CK_EFFECTIVELY_INFINITE as CK_ULONG
    );
    assert_eq!(info.ulRwSessionCount, 1);
    assert_eq!(
        info.ulTotalPublicMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulFreePublicMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulTotalPrivateMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulFreePrivateMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    assert_eq!(crate::C_CloseSession(read_write_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulSessionCount, 1);
    assert_eq!(info.ulRwSessionCount, 0);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn session_entry_points_validate_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    assert_session_entry_points_return(999, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_session_entry_points_return(999, CKR_SESSION_HANDLE_INVALID as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn non_session_stub_entry_points_report_unsupported() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut slot = 0;

    assert_eq!(
        crate::C_InitToken(0, ::std::ptr::null_mut(), 0, ::std::ptr::null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(
        crate::C_WaitForSlotEvent(0, &mut slot, ::std::ptr::null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
}

#[test]
pub fn slot_and_mechanism_calls_validate_slot_ids() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    let mut count = 0;
    let mut mechanism_info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };

    assert_eq!(crate::C_CloseAllSessions(999), CKR_SLOT_ID_INVALID as CK_RV);
    assert_eq!(
        crate::C_GetMechanismList(999, ::std::ptr::null_mut(), &mut count),
        CKR_SLOT_ID_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(999, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut mechanism_info),
        CKR_SLOT_ID_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn token_and_mechanism_queries_require_a_present_token() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(false)));
    }

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    let mut count = 0;
    let mut mechanism_info = unsafe { ::std::mem::zeroed::<CK_MECHANISM_INFO>() };
    assert_eq!(
        crate::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut token_info),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), &mut count),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            &mut mechanism_info
        ),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn open_session_validates_session_flags() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;

    assert_eq!(
        crate::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);
    assert_eq!(
        crate::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_SESSION_PARALLEL_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_ASYNC_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_SESSION_ASYNC_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    for flags in [
        CKF_SERIAL_SESSION as CK_FLAGS,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
    ] {
        assert_eq!(
            crate::C_OpenSession(
                TEST_SLOT_ID,
                flags,
                ::std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_OK as CK_RV
        );
        assert_ne!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);
        assert_eq!(crate::C_CloseSession(session), CKR_OK as CK_RV);
        session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_pin_validates_session_and_changes_supported_token_pin() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::C_SetPIN(
            999,
            ::std::ptr::null_mut(),
            1,
            ::std::ptr::null_mut(),
            1,
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);
    assert_eq!(
        crate::C_SetPIN(
            999,
            ::std::ptr::null_mut(),
            1,
            ::std::ptr::null_mut(),
            1,
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut old_pin = *b"1234";
    let mut new_pin = *b"5678";
    assert_eq!(
        crate::C_SetPIN(
            session,
            old_pin.as_mut_ptr(),
            old_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    assert_eq!(crate::C_CloseSession(session), CKR_OK as CK_RV);

    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut wrong_pin = *b"0000";
    assert_eq!(
        crate::C_SetPIN(
            session,
            wrong_pin.as_mut_ptr(),
            wrong_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::C_SetPIN(
            session,
            old_pin.as_mut_ptr(),
            old_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn so_login_enforces_session_rules_and_initializes_user_pin() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut read_only_session = 0;
    let mut read_write_session = 0;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_only_session,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_write_session,
        ),
        CKR_OK as CK_RV
    );

    let mut admin_pin = *b"12345678";
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_SESSION_READ_ONLY_EXISTS as CK_RV
    );
    assert_eq!(crate::C_CloseSession(read_only_session), CKR_OK as CK_RV);

    let mut wrong_admin_pin = *b"00000000";
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            wrong_admin_pin.as_mut_ptr(),
            wrong_admin_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    let mut user_pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_USER as CK_USER_TYPE,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV
    );

    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::C_GetSessionInfo(read_write_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
    let mut object_size = 0;
    assert_eq!(
        crate::C_GetObjectSize(read_write_session, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut another_read_only_session = 0;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut another_read_only_session,
        ),
        CKR_SESSION_READ_WRITE_SO_EXISTS as CK_RV
    );
    assert_eq!(
        crate::C_InitPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut new_admin_pin = *b"87654321";
    assert_eq!(
        crate::C_SetPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
            new_admin_pin.as_mut_ptr(),
            new_admin_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SetPIN(
            read_write_session,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
            new_admin_pin.as_mut_ptr(),
            new_admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(read_write_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::C_InitPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn open_session_refreshes_token_presence() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(
            TEST_SLOT_ID,
            Box::new(TestSlot {
                present: std::cell::Cell::new(true),
                remove_on_refresh: true,
                login_active: None,
            }),
        );
    }

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn close_cleans_local_state_after_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert_eq!(
        crate::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    {
        let context = crate::lock_context().unwrap();
        let context = context.as_ref().unwrap();
        assert!(!context.logged_in_slots.contains_key(&TEST_SLOT_ID));
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
    }

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);
    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_CloseAllSessions(TEST_SLOT_ID),
        CKR_DEVICE_ERROR as CK_RV
    );
    {
        let context = crate::lock_context().unwrap();
        let context = context.as_ref().unwrap();
        assert!(!context.logged_in_slots.contains_key(&TEST_SLOT_ID));
        assert!(context
            .sessions
            .values()
            .all(|session| session.slotID() != TEST_SLOT_ID));
    }

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn read_only_sessions_cannot_mutate_token_or_private_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );

    let mut label = *b"read only";
    let mut label_attribute = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(session, 1, &mut label_attribute, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(session, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(session, 1, ::std::ptr::null_mut(), 0, &mut copied),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut token_true = CK_TRUE as CK_BBOOL;
    let mut token_false = CK_FALSE as CK_BBOOL;
    let mut private_true = CK_TRUE as CK_BBOOL;
    let mut private_false = CK_FALSE as CK_BBOOL;
    let mut value = [0x22u8; 16];
    let mut base_template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut token_object_template = [
        base_template[0],
        base_template[1],
        base_template[2],
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            session,
            token_object_template.as_mut_ptr(),
            token_object_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut private_object_template = [
        base_template[0],
        base_template[1],
        base_template[2],
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_CreateObject(
            session,
            private_object_template.as_mut_ptr(),
            private_object_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let value_len_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let mut token_key_template = [
        value_len_attribute,
        token_object_template[3],
        token_object_template[4],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            session,
            &mut mechanism,
            token_key_template.as_mut_ptr(),
            token_key_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut private_key_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        private_object_template[3],
        private_object_template[4],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            session,
            &mut mechanism,
            private_key_template.as_mut_ptr(),
            private_key_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::C_CreateObject(
            session,
            base_template.as_mut_ptr(),
            base_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_DestroyObject(session, object), CKR_OK as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}
