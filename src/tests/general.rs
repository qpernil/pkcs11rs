use super::*;

#[test]
pub fn bindgen_test_layout_CK_INFO() {
    let ck_ulong_size = ::std::mem::size_of::<CK_ULONG>();
    let ck_ulong_alignment = ::std::mem::align_of::<CK_ULONG>();
    let flags_offset = super::align_offset(34, ck_ulong_alignment);
    let description_offset = flags_offset + ck_ulong_size;
    let version_offset = description_offset + 32;
    assert_eq!(
        ::std::mem::size_of::<CK_INFO>(),
        super::align_offset(version_offset + 2, ck_ulong_alignment),
        concat!("Size of: ", stringify!(CK_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_INFO>(),
        ck_ulong_alignment,
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
        flags_offset,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryDescription),
        description_offset,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(libraryDescription)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryVersion),
        version_offset,
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
        crate::api::C_GetFunctionList(&mut function_list),
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
        crate::api::C_GetInterfaceList(::std::ptr::null_mut(), &mut count),
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
        crate::api::C_GetInterfaceList(interfaces.as_mut_ptr(), &mut count),
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
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let mut info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32usize],
        flags: 0,
        libraryDescription: [0; 32usize],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    assert_eq!(crate::api::C_GetInfo(&mut info), CKR_OK as CK_RV);
    assert_eq!(info.cryptokiVersion.major, 3);
    assert_eq!(info.cryptokiVersion.minor, 2);
    assert_eq!(info.flags, 0);
    assert_eq!(
        std::str::from_utf8(&info.manufacturerID)
            .unwrap()
            .trim_end(),
        "Nilsson Crypto Systems"
    );
    assert_eq!(
        std::str::from_utf8(&info.libraryDescription)
            .unwrap()
            .trim_end(),
        "pkcs11rs native PKCS#11 module"
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn initialize_finalize_orderings_and_empty_cycles_are_stable() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    for _ in 0..3 {
        assert_eq!(
            crate::api::C_Initialize(::std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_Finalize(::std::ptr::null_mut()),
            CKR_OK as CK_RV
        );
    }

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn initialize_accepts_json_reserved_configuration() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut configuration =
        b"{\"version\":1,\"logging\":{\"level\":\"warn\"},\"hardware\":{\"discovery\":false}}\0"
            .to_vec();
    let mut init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: configuration.as_mut_ptr().cast(),
    };

    assert_eq!(
        crate::api::C_Initialize(&mut init_args as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    {
        let module = crate::lock_context_read().unwrap();
        let context = module.as_ref().unwrap();
        assert!(context.logging.is_some());
        assert!(!context.hardware_discovery);
    }
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn finalize_rejects_reserved_arg() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(1 as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn lifecycle_transitions_fail_while_an_api_call_is_active() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let active_call = crate::MODULE_CONTEXT.read().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let initialize = std::thread::spawn({
        let sender = sender.clone();
        move || {
            sender
                .send(crate::api::C_Initialize(::std::ptr::null_mut()))
                .unwrap();
        }
    });
    let finalize = std::thread::spawn(move || {
        sender
            .send(crate::api::C_Finalize(::std::ptr::null_mut()))
            .unwrap();
    });
    let results = [
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
    ];
    drop(active_call);
    initialize.join().unwrap();
    finalize.join().unwrap();

    assert_eq!(results, [CKR_FUNCTION_FAILED as CK_RV; 2]);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn ordinary_calls_fail_while_a_lifecycle_transition_is_active() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let transition = crate::MODULE_CONTEXT.write().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let call = std::thread::spawn(move || {
        let mut info = CK_INFO {
            cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
            manufacturerID: [0; 32],
            flags: 0,
            libraryDescription: [0; 32],
            libraryVersion: CK_VERSION { major: 0, minor: 0 },
        };
        sender.send(crate::api::C_GetInfo(&mut info)).unwrap();
    });
    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    drop(transition);
    call.join().unwrap();

    assert_eq!(result, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn finalize_clears_context_after_device_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_FUNCTION_FAILED as CK_RV
    );
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
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
        crate::api::C_Initialize(
            &mut partial_callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR
        ),
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
        crate::api::C_Initialize(&mut os_locking as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let mut callbacks = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(test_create_mutex),
        DestroyMutex: Some(test_destroy_mutex),
        LockMutex: Some(test_lock_mutex),
        UnlockMutex: Some(test_unlock_mutex),
        flags: 0,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::api::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_CANT_LOCK as CK_RV
    );

    callbacks.flags = CKF_OS_LOCKING_OK as CK_FLAGS;
    assert_eq!(
        crate::api::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    callbacks.flags = 1 << 31;
    assert_eq!(
        crate::api::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
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
pub fn usb_bcd_version_extracts_major_and_minor_components() {
    assert_eq!(crate::usb_bcd_version(0x0210), (2, 1));
    assert_eq!(crate::usb_bcd_version(0x1234), (12, 3));
}

#[test]
pub fn yubikey_login_preserves_connector_errors() {
    let base: crate::SharedConnector = std::sync::Arc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let mut slot = crate::IssuerSecurityDomainSlot::new(
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::sync::Arc::new(crate::PcscReaderState::default()),
        )),
        application_aid,
    );

    let nonempty: CK_RV = crate::Slot::login(&mut slot, b"1234").unwrap_err().into();
    assert_eq!(nonempty, CKR_PIN_INCORRECT as CK_RV);
    let rv: CK_RV = crate::Slot::login(&mut slot, b"").unwrap_err().into();
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
}

#[test]
fn applet_configuration_accepts_only_canonical_names() {
    assert_eq!(
        crate::parse_ccid_application("issuer-sd").unwrap(),
        crate::CcidApplication::IssuerSecurityDomain
    );
    assert_eq!(
        crate::parse_ccid_application("fido2").unwrap(),
        crate::CcidApplication::Fido2
    );
    for invalid in [
        "pgp",
        "yubihsm-auth",
        "globalplatform",
        "global-platform",
        "gp",
        "scp03",
    ] {
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
    assert_eq!(
        crate::parse_secure_channel("scp11c").unwrap(),
        crate::SecureChannelProtocol::Scp11c
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
            crate::CcidApplication::IssuerSecurityDomain,
            crate::CcidApplication::Fido2,
        ]
    );
}

#[test]
fn pcsc_applet_presence_requires_a_successful_aid_select() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::sync::Arc::new(crate::PcscReaderState::default()),
    );

    assert_eq!(
        crate::Connector::name(&connector),
        crate::Connector::name(base.as_ref())
    );
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    base.select_ok
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(crate::Connector::refresh(&connector).is_err());
    assert!(!crate::Connector::is_present(&connector));
    assert!(
        connector
            .discovery_error()
            .as_deref()
            .is_some_and(|reason| reason.contains("Generic"))
    );
    base.select_ok
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    assert!(connector.discovery_error().is_none());
}

#[test]
fn pcsc_applet_connector_reuses_selected_aid() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::sync::Arc::new(crate::PcscReaderState::default()),
    );
    let mut receive = [0; 16];

    assert!(
        crate::Connector::transmit(
            &connector,
            &[0x00, 0x00],
            &mut receive,
            std::time::Duration::from_secs(1),
        )
        .is_ok()
    );
    base.select_ok
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        crate::Connector::transmit(
            &connector,
            &[0x00, 0x00],
            &mut receive,
            std::time::Duration::from_secs(1),
        )
        .is_ok()
    );
}

#[test]
fn pcsc_applet_connectors_share_selected_aid_state() {
    let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let base = std::sync::Arc::new(RecordingConnector {
        commands: commands.clone(),
    });
    let state = std::sync::Arc::new(crate::PcscReaderState::default());
    let first_aid = vec![1, 2, 3, 4, 5];
    let second_aid = vec![6, 7, 8, 9, 10];
    let first = crate::PcscAppletConnector::new(base.clone(), &first_aid, None, state.clone());
    let second = crate::PcscAppletConnector::new(base, &second_aid, None, state);
    let command = crate::CommandApdu {
        cla: 0,
        ins: 0xca,
        p1: 0,
        p2: 0,
        data: Vec::new(),
        le: None,
        extended: false,
    };

    crate::Connector::send_apdu(&first, &command).unwrap();
    crate::Connector::send_apdu(&first, &command).unwrap();
    crate::Connector::send_apdu(&second, &command).unwrap();
    crate::Connector::send_apdu(&first, &command).unwrap();

    let selected = commands
        .lock()
        .unwrap()
        .iter()
        .filter_map(|encoded| {
            let command = crate::CommandApdu::decode(encoded).ok()?;
            (command.ins == 0xa4).then_some(command.data)
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, vec![first_aid.clone(), second_aid, first_aid]);
}

#[test]
fn selected_aid_is_reused_only_within_its_transaction() {
    let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let base = std::sync::Arc::new(RecordingConnector {
        commands: commands.clone(),
    });
    let state = std::sync::Arc::new(crate::PcscReaderState::default());
    let aid = vec![1, 2, 3, 4, 5];
    let connector = crate::PcscAppletConnector::new(base, &aid, None, state.clone());
    let command = crate::CommandApdu {
        cla: 0,
        ins: 0xca,
        p1: 0,
        p2: 0,
        data: Vec::new(),
        le: None,
        extended: false,
    };

    state.begin_transaction().unwrap();
    crate::Connector::send_apdu(&connector, &command).unwrap();
    crate::Connector::send_apdu(&connector, &command).unwrap();
    state.end_transaction();

    state.begin_transaction().unwrap();
    crate::Connector::send_apdu(&connector, &command).unwrap();
    state.end_transaction();

    let selected = commands
        .lock()
        .unwrap()
        .iter()
        .filter_map(|encoded| {
            let command = crate::CommandApdu::decode(encoded).ok()?;
            (command.ins == 0xa4).then_some(command.data)
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, vec![aid.clone(), aid]);
}

#[test]
fn passive_ccid_slots_do_not_repeat_presence_select() {
    let connector = || -> std::rc::Rc<dyn crate::Connector> {
        std::rc::Rc::new(SelectableConnector {
            present: std::sync::atomic::AtomicBool::new(true),
            select_ok: std::sync::atomic::AtomicBool::new(false),
            serial: "SELECT0001",
        })
    };

    let hsmauth_aid = crate::hsmauth::AID.to_vec();
    let mut hsmauth = crate::HsmAuthSlot::new(connector(), hsmauth_aid);
    assert!(crate::Slot::init_slot(&mut hsmauth).is_ok());
    assert!(
        !crate::Slot::mechanisms(&hsmauth)
            .iter()
            .any(|mechanism| mechanism.type_ == crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY)
    );

    let issuer_sd_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let mut issuer_sd = crate::IssuerSecurityDomainSlot::new(connector(), issuer_sd_aid);
    assert!(crate::Slot::init_slot(&mut issuer_sd).is_ok());
    assert!(
        !crate::Slot::mechanisms(&issuer_sd)
            .iter()
            .any(|mechanism| mechanism.type_ == crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY)
    );
}

#[test]
fn openpgp_slot_info_reports_application_version_and_serial() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::sync::Arc::new(crate::PcscReaderState::default()),
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
fn openpgp_token_pin_bounds_cover_user_and_admin_passwords() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let mut slot = crate::OpenPgpSlot::new(connector, crate::openpgp::OPENPGP_AID.to_vec());
    slot.pin_min = 6;
    slot.pin_max = 32;
    slot.admin_pin_min = 8;
    slot.admin_pin_max = 64;

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    crate::Slot::get_token_info(&slot, &mut token_info).unwrap();
    assert_eq!(token_info.ulMinPinLen, 6);
    assert_eq!(token_info.ulMaxPinLen, 64);
}

#[test]
fn openpgp_slot_uses_shared_serial_before_metadata_is_loaded() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let reader = std::sync::Arc::new(crate::PcscReaderState::default());
    reader
        .device
        .replace(
            0,
            crate::device::DeviceIdentity {
                manufacturer: String::from("Yubico"),
                product: String::from("YubiKey"),
                serial: String::from("12345678"),
                hardware_version: None,
                firmware_version: Some((5, 7, 0)),
            },
        )
        .unwrap();
    let device = reader.device.clone();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(base, &aid, None, reader));
    let slot = crate::OpenPgpSlot::new_with_device(connector, aid, device);

    assert_eq!(crate::Slot::serial(&slot), "12345678");
}

#[test]
fn openpgp_slot_uses_shared_firmware_before_metadata_is_loaded() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::sync::Arc::new(crate::PcscReaderState::default()),
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
    let generated = crate::certificate_builder::p256_key();
    let public_key = crate::certificate_builder::p256_public_point(generated.verifying_key());
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let slot = crate::OpenPgpSlot {
        connector,
        device: std::sync::Arc::new(crate::device::DeviceContext::test()),
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
            algorithm: crate::openpgp::Algorithm::Ecdsa(crate::openpgp::Curve::P256),
            public_key: crate::openpgp::PublicKey::Ec {
                curve: crate::openpgp::Curve::P256,
                point: public_key,
            },
            pin_policy: 0,
            touch_policy: 1,
            local: false,
        }],
        certificates: vec![crate::OpenPgpCertificate {
            key_ref: crate::openpgp::KeyRef::Attestation,
            key_type: CKK_EC as CK_KEY_TYPE,
            value: vec![0x30, 0],
        }],
        data_objects: Vec::new(),
    };

    let objects = crate::Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        objects
            .iter()
            .filter(|object| object.class != CKO_PROFILE as CK_OBJECT_CLASS)
            .count(),
        3
    );

    let public = objects
        .iter()
        .find(|object| object.unique_id == "openpgp-81-public")
        .unwrap();
    assert_eq!(public.class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert!(public.verify);

    let private = objects
        .iter()
        .find(|object| object.unique_id == "openpgp-81-private")
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
        .find(|object| object.unique_id == "openpgp-81-certificate")
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
fn openpgp_mechanisms_are_unique_and_add_only_paired_software_public_flags() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let slot = crate::OpenPgpSlot::new(connector, crate::openpgp::OPENPGP_AID.to_vec());
    let mechanisms = crate::Slot::mechanisms(&slot);
    let unique = mechanisms
        .iter()
        .map(|mechanism| mechanism.type_)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), mechanisms.len());

    let rsa_pkcs = mechanisms
        .iter()
        .find(|mechanism| mechanism.type_ == CKM_RSA_PKCS as CK_MECHANISM_TYPE)
        .unwrap();
    assert_eq!(
        rsa_pkcs.flags & (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS
    );
    let raw_rsa = mechanisms
        .iter()
        .find(|mechanism| mechanism.type_ == CKM_RSA_X_509 as CK_MECHANISM_TYPE)
        .unwrap();
    assert_eq!(
        raw_rsa.flags & (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS
    );
    for mechanism_type in [
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
    ] {
        let mechanism = mechanisms
            .iter()
            .find(|mechanism| mechanism.type_ == mechanism_type as CK_MECHANISM_TYPE)
            .unwrap();
        assert_eq!(
            mechanism.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
        );
    }
    for mechanism_type in [
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_EC_KEY_PAIR_GEN,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    ] {
        let mechanism = mechanisms
            .iter()
            .find(|mechanism| mechanism.type_ == mechanism_type as CK_MECHANISM_TYPE)
            .unwrap();
        assert_eq!(
            mechanism.flags & CKF_GENERATE_KEY_PAIR as CK_FLAGS,
            CKF_GENERATE_KEY_PAIR as CK_FLAGS
        );
    }
}

#[test]
fn composite_signing_advertisement_is_exact_for_every_general_slot_family() {
    fn assert_exact(mechanisms: Vec<crate::MechanismDetails>, expected: &[CK_MECHANISM_TYPE]) {
        let candidates = crate::HASHED_RSA_PKCS_MECHANISMS
            .into_iter()
            .chain(crate::HASHED_RSA_PSS_MECHANISMS)
            .chain(crate::HASHED_ECDSA_MECHANISMS)
            .collect::<Vec<_>>();
        for candidate in candidates {
            let mechanism = mechanisms
                .iter()
                .find(|mechanism| mechanism.type_ == candidate);
            assert_eq!(
                mechanism.is_some(),
                expected.contains(&candidate),
                "unexpected advertisement for {:?}",
                crate::mechanism_name(candidate)
            );
            if let Some(mechanism) = mechanism {
                assert_eq!(
                    mechanism.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
                    (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
                );
            }
        }
    }

    let software = crate::SoftwareSlot::new(String::from("contract-test"), 0);
    let all = crate::HASHED_RSA_PKCS_MECHANISMS
        .into_iter()
        .chain(crate::HASHED_RSA_PSS_MECHANISMS)
        .chain(crate::HASHED_ECDSA_MECHANISMS)
        .collect::<Vec<_>>();
    assert_exact(crate::Slot::mechanisms(&software), &all);

    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let openpgp = crate::OpenPgpSlot::new(connector, crate::openpgp::OPENPGP_AID.to_vec());
    let openpgp_expected = [
        CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
    ];
    assert_exact(crate::Slot::mechanisms(&openpgp), &openpgp_expected);

    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = crate::piv::PIV_AID.to_vec();
    let reader = std::sync::Arc::new(crate::PcscReaderState::default());
    reader
        .device
        .replace(
            0,
            crate::device::DeviceIdentity {
                manufacturer: String::from("Yubico"),
                product: String::from("YubiKey"),
                serial: String::from("12345678"),
                hardware_version: None,
                firmware_version: Some((5, 7, 0)),
            },
        )
        .unwrap();
    let device = reader.device.clone();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(base, &aid, None, reader));
    let piv = crate::PivSlot::new_with_device(connector, aid, device);
    assert_exact(crate::Slot::mechanisms(&piv), &all);

    let yubihsm = crate::yubihsm_mechanisms(&[
        crate::YUBIHSM_ALGO_RSA_2048,
        crate::YUBIHSM_ALGO_RSA_PKCS1_SHA1,
        crate::YUBIHSM_ALGO_RSA_PKCS1_SHA256,
        crate::YUBIHSM_ALGO_RSA_PKCS1_SHA384,
        crate::YUBIHSM_ALGO_RSA_PKCS1_SHA512,
        crate::YUBIHSM_ALGO_RSA_PSS_SHA1,
        crate::YUBIHSM_ALGO_RSA_PSS_SHA256,
        crate::YUBIHSM_ALGO_RSA_PSS_SHA384,
        crate::YUBIHSM_ALGO_RSA_PSS_SHA512,
        crate::YUBIHSM_ALGO_EC_P256,
        crate::YUBIHSM_ALGO_EC_ECDSA_SHA1,
        crate::YUBIHSM_ALGO_EC_ECDSA_SHA256,
        crate::YUBIHSM_ALGO_EC_ECDSA_SHA384,
        crate::YUBIHSM_ALGO_EC_ECDSA_SHA512,
    ]);
    let yubihsm_expected = [
        CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
        CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
    ];
    assert_exact(yubihsm, &yubihsm_expected);
}

#[test]
fn openpgp_data_objects_expose_application_tag_and_lazy_value() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: "openpgp-data-005b".to_owned(),
        class: CKO_DATA as CK_OBJECT_CLASS,
        key_type: 0,
        label: "OpenPGP Cardholder name".to_owned(),
        id: Vec::new(),
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        wrap: false,
        unwrap: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        allowed_mechanisms: None,
        wrap_with_trusted: false,
        policy_templates: crate::KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: crate::KeyMaterial::OpenPgpData {
            tag: 0x005b,
            connector,
            cache: std::rc::Rc::new(std::cell::RefCell::new(crate::LazyCache::Unattempted)),
        },
    };
    assert_eq!(
        object.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
        Some(b"OpenPGP".to_vec())
    );
    assert_eq!(
        object.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0, 0x5b])
    );
    assert_eq!(
        object.attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
        Some(Vec::new())
    );
}

#[test]
fn openpgp_private_key_template_uses_extended_header_list() {
    let material = crate::KeyMaterial::Secret(zeroize::Zeroizing::new(vec![0x55; 32]));
    let encoded = crate::openpgp_private_key_template(
        crate::OpenPgpKeyRef::Signature,
        crate::OpenPgpAlgorithm::Ed25519,
        &[0x16, 1],
        &material,
    )
    .unwrap();
    assert_eq!(&encoded[..8], &[0x4d, 0x2a, 0xb6, 0, 0x7f, 0x48, 2, 0x92]);
    assert_eq!(encoded[8], 32);
    assert_eq!(&encoded[9..12], &[0x5f, 0x48, 32]);
    assert_eq!(&encoded[12..], &[0x55; 32]);
}

#[test]
fn openpgp_uif_modes_map_to_yubico_touch_policy_values() {
    for (mode, policy) in [(0, 1), (1, 2), (2, 4), (3, 3), (4, 5)] {
        assert_eq!(crate::openpgp_touch_policy(&[mode, 0x20]), Some(policy));
    }
    assert_eq!(crate::openpgp_touch_policy(&[5, 0x20]), None);
    assert_eq!(crate::openpgp_touch_policy(&[]), None);
}

#[test]
fn openpgp_metadata_failure_does_not_hide_selected_applet() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::sync::Arc::new(crate::PcscReaderState::default()),
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
        unique_id: "openpgp-private".to_owned(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "OpenPGP signature key".to_owned(),
        id: vec![1],
        token: true,
        private: true,
        encrypt: false,
        decrypt: false,
        sign: true,
        verify: false,
        derive: false,
        wrap: false,
        unwrap: false,
        sensitive: true,
        extractable: false,
        always_sensitive: true,
        never_extractable: true,
        local: true,
        key_gen_mechanism: None,
        allowed_mechanisms: None,
        wrap_with_trusted: false,
        policy_templates: crate::KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: crate::KeyMaterial::OpenPgpPrivate {
            key_ref: crate::openpgp::KeyRef::Signature,
            algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
            pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
            touch_policy: 1,
        },
    };
    assert!(
        object
            .attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE)
            .is_some()
    );
    assert_eq!(
        object.attribute_value(crate::CKA_YUBICO_TOUCH_POLICY),
        Some(crate::ulong_attribute(1))
    );
    object.material = crate::KeyMaterial::OpenPgpPrivate {
        key_ref: crate::openpgp::KeyRef::Authentication,
        algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
        pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
        touch_policy: 2,
    };
    assert_eq!(
        object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );
    assert_eq!(
        object.attribute_value(crate::CKA_YUBICO_TOUCH_POLICY),
        Some(crate::ulong_attribute(2))
    );
}

#[test]
fn openpgp_always_authenticate_expires_after_one_signature() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "OPENPGP001",
    });
    let authenticated = std::rc::Rc::new(std::cell::Cell::new(true));
    let session = crate::OpenPgpSession {
        slotID: TEST_SLOT_ID,
        flags: CKF_SERIAL_SESSION as CK_FLAGS,
        connector,
        authenticated: authenticated.clone(),
    };

    let _ = crate::BackendSession::openpgp_sign(
        &session,
        crate::openpgp::KeyRef::Signature,
        &[],
        crate::openpgp::PW1_ONE_SIGNATURE,
    );
    assert!(!authenticated.get());
}

#[test]
fn piv_slot_uses_shared_metadata_before_piv_metadata_is_loaded() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "12345678",
    });
    let aid = crate::piv::PIV_AID.to_vec();
    let reader = std::sync::Arc::new(crate::PcscReaderState::default());
    reader
        .device
        .replace(
            0,
            crate::device::DeviceIdentity {
                manufacturer: String::from("Yubico"),
                product: String::from("YubiKey"),
                serial: String::from("12345678"),
                hardware_version: None,
                firmware_version: Some((5, 7, 0)),
            },
        )
        .unwrap();
    let device = reader.device.clone();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(base, &aid, None, reader));
    let slot = crate::PivSlot::new_with_device(connector, aid, device);

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

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    crate::Slot::get_token_info(&slot, &mut token_info).unwrap();
    assert_eq!(token_info.ulMinPinLen, 6);
    assert_eq!(token_info.ulMaxPinLen, 64);

    let mechanisms = crate::Slot::mechanisms(&slot);
    for mechanism_type in crate::HASHED_RSA_PKCS_MECHANISMS
        .into_iter()
        .chain(crate::HASHED_RSA_PSS_MECHANISMS)
        .chain(crate::HASHED_ECDSA_MECHANISMS)
    {
        let mechanism = mechanisms
            .iter()
            .find(|mechanism| mechanism.type_ == mechanism_type)
            .unwrap();
        assert_eq!(
            mechanism.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
        );
    }
}

#[test]
fn issuer_sd_token_uses_device_model_and_applet_label() {
    let base = std::sync::Arc::new(SelectableConnector {
        present: std::sync::atomic::AtomicBool::new(true),
        select_ok: std::sync::atomic::AtomicBool::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let reader = std::sync::Arc::new(crate::PcscReaderState::default());
    reader
        .device
        .replace(
            0,
            crate::device::DeviceIdentity {
                manufacturer: String::from("Test"),
                product: String::from("Selectable connector"),
                serial: String::from("SELECT0001"),
                hardware_version: None,
                firmware_version: Some((5, 7, 0)),
            },
        )
        .unwrap();
    let device = reader.device.clone();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(base, &aid, None, reader));
    let mut slot = crate::IssuerSecurityDomainSlot::new_with_device(connector, aid, device);

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    assert!(crate::Slot::get_token_info(&slot, &mut token_info).is_ok());
    assert_eq!(&token_info.model, b"Selectable conne");
    assert_eq!(&token_info.label[..21], b"Issuer SD #SELECT0001");
    assert_eq!(token_info.ulMinPinLen, 0);
    assert_eq!(token_info.ulMaxPinLen, 0);
    assert!(crate::Slot::backend_mechanisms(&slot).is_empty());
    let mechanisms = crate::Slot::mechanisms(&slot);
    for unsupported in crate::SOFTWARE_DIGEST_MECHANISMS {
        assert!(
            !mechanisms
                .iter()
                .any(|mechanism| mechanism.type_ == unsupported.type_)
        );
    }
    for unsupported in crate::software_public_mechanisms()
        .into_iter()
        .filter(|mechanism| mechanism.type_ != crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY)
    {
        assert!(
            !mechanisms
                .iter()
                .any(|mechanism| mechanism.type_ == unsupported.type_)
        );
    }
    assert!(
        !mechanisms
            .iter()
            .any(|mechanism| mechanism.type_ == crate::CKM_PKCS11RS_PROJECT_PUBLIC_KEY)
    );
    for private_only in [
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_EC_KEY_PAIR_GEN,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        CKM_ECDH1_DERIVE,
        CKM_ECDH1_COFACTOR_DERIVE,
    ] {
        assert!(
            !mechanisms
                .iter()
                .any(|mechanism| mechanism.type_ == private_only as CK_MECHANISM_TYPE)
        );
    }
    assert!(crate::Slot::login(&mut slot, &[]).is_ok());
    assert!(crate::Slot::login_is_active(&slot));
    crate::Slot::logout(&mut slot).unwrap();
    assert!(matches!(
        crate::Slot::login(&mut slot, b"ignored"),
        Err(crate::Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as CK_RV
    ));
}

#[test]
fn issuer_sd_metadata_becomes_read_only_pkcs11_objects() {
    let info = crate::SecurityDomainInfo {
        keys: vec![crate::security_domain::KeyInfo {
            key_ref: crate::security_domain::KeyRef {
                kid: crate::security_domain::KID_SCP11B,
                kvn: 1,
            },
            components: vec![crate::security_domain::KeyComponent {
                key_type: 0xb1,
                length: 32,
            }],
        }],
        card_recognition_data: Some(vec![1, 2]),
        cplc: Some(vec![0x40, 0x90]),
        ca_identifiers: vec![crate::security_domain::CaIdentifier {
            kind: crate::security_domain::CaIdentifierKind::Klcc,
            key_ref: crate::security_domain::KeyRef { kid: 0x20, kvn: 1 },
            subject_key_identifier: vec![0xaa, 0xbb],
        }],
        certificate_bundles: vec![crate::security_domain::CertificateBundle {
            key_ref: crate::security_domain::KeyRef {
                kid: crate::security_domain::KID_SCP11B,
                kvn: 1,
            },
            certificates: vec![vec![0x30, 0]],
        }],
    };

    let objects = crate::issuer_security_domain_token_objects(TEST_SLOT_ID, &info);
    assert_eq!(objects.len(), 5);
    let key = &objects[0];
    assert_eq!(key.class, CKO_DATA as CK_OBJECT_CLASS);
    assert_eq!(key.id, vec![0x13, 1]);
    assert_eq!(
        key.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0x13, 1])
    );
    assert_eq!(
        key.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
        Some(b"Issuer SD".to_vec())
    );
    assert_eq!(
        key.attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
        Some(vec![0xb1, 32])
    );
    assert_eq!(
        key.attribute_value(CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE),
        Some(vec![CK_FALSE as CK_BBOOL])
    );

    let certificate = objects.last().unwrap();
    assert_eq!(certificate.class, CKO_CERTIFICATE as CK_OBJECT_CLASS);
    assert_eq!(certificate.id, key.id);
    assert_eq!(
        certificate.attribute_value(CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE),
        Some((CKC_X_509 as CK_ULONG).to_ne_bytes().to_vec())
    );
    assert_eq!(
        certificate.attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
        Some(vec![0x30, 0])
    );

    let card_recognition = &objects[1];
    assert_eq!(
        card_recognition.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0x66])
    );
    let cplc = &objects[2];
    assert_eq!(
        cplc.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0x9f, 0x7f])
    );
    let ca = &objects[3];
    assert_eq!(
        ca.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
        Some(vec![0xff, 0x34, 0x20, 1])
    );
}

#[test]
fn issuer_sd_leaf_certificate_shares_the_key_id() {
    let key_ref = crate::security_domain::KeyRef {
        kid: crate::security_domain::KID_SCP11A,
        kvn: 7,
    };
    let info = crate::SecurityDomainInfo {
        keys: vec![crate::security_domain::KeyInfo {
            key_ref,
            components: Vec::new(),
        }],
        certificate_bundles: vec![crate::security_domain::CertificateBundle {
            key_ref,
            certificates: vec![vec![0x30, 0], vec![0x30, 0]],
        }],
        ..Default::default()
    };

    let objects = crate::issuer_security_domain_token_objects(TEST_SLOT_ID, &info);
    assert_eq!(objects[0].id, vec![0x11, 7]);
    assert_eq!(objects[1].id, vec![0x11, 7, 0, 0]);
    assert_eq!(objects[2].id, vec![0x11, 7]);
}

#[test]
fn hsmauth_objects_expose_credential_metadata_without_secret_material() {
    let info = crate::HsmAuthInfo {
        version: (5, 7, 1),
        management_key_retries: 8,
        credentials: vec![
            crate::HsmAuthCredential {
                label: "symmetric".to_owned(),
                algorithm: crate::HsmAuthAlgorithm::Aes128YubicoAuthentication,
                retries: 7,
                touch_required: false,
                public_key: None,
            },
            crate::HsmAuthCredential {
                label: "asymmetric".to_owned(),
                algorithm: crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
                retries: 6,
                touch_required: true,
                public_key: Some([vec![0x04], vec![0x11; 64]].concat()),
            },
        ],
    };

    let objects = crate::hsmauth_token_objects(TEST_SLOT_ID, &info);
    assert_eq!(objects.len(), 3);

    let symmetric = &objects[0];
    assert_eq!(symmetric.class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(symmetric.key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert!(!symmetric.sign);
    assert!(!symmetric.verify);
    assert!(!symmetric.derive);
    assert_eq!(
        symmetric.attribute_value(CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE),
        Some((32 as CK_ULONG).to_ne_bytes().to_vec())
    );
    assert_eq!(
        symmetric.attribute_value(crate::CKA_YUBICO_HSMAUTH_ALGORITHM),
        Some((38 as CK_ULONG).to_ne_bytes().to_vec())
    );
    assert_eq!(
        symmetric.attribute_value(crate::CKA_YUBICO_HSMAUTH_RETRIES),
        Some((7 as CK_ULONG).to_ne_bytes().to_vec())
    );

    let asymmetric = &objects[1];
    assert_eq!(
        asymmetric.attribute_value(crate::CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED),
        Some(vec![CK_TRUE as CK_BBOOL])
    );
    let public = &objects[2];
    assert_eq!(public.class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(public.key_type, CKK_EC as CK_KEY_TYPE);
    assert!(!public.verify);
    assert!(
        public
            .attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE)
            .is_some()
    );
    let public_key_info = public
        .attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert!(spki::SubjectPublicKeyInfoRef::try_from(public_key_info.as_slice()).is_ok());
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
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let base: crate::SharedConnector = std::sync::Arc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::sync::Arc::new(crate::PcscReaderState::default()),
        ));
    install_test_slot_with_backend(
        TEST_SLOT_ID,
        Box::new(crate::IssuerSecurityDomainSlot::new(
            connector.clone(),
            application_aid,
        )),
    );
    {
        let child = test_slot_context(TEST_SLOT_ID);
        let mut context = child.lock().unwrap();
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            crate::SessionContext::new(Box::new(crate::PcscAppletSession {
                slotID: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
                connector,
            })),
        );
        context.login_role = Some(crate::LoginRole::User);
    }
    crate::register_session_slot(TEST_SESSION_HANDLE, TEST_SLOT_ID).unwrap();

    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::api::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);

    let mut pin = [];
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert!(with_test_slot_context(TEST_SLOT_ID, |context| {
        context.login_role.is_none()
    }));

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn authentication_loss_cancels_active_private_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    let login_active = std::rc::Rc::new(std::cell::Cell::new(true));
    install_test_slot_with_backend(
        TEST_SLOT_ID,
        Box::new(TestSlot {
            present: std::cell::Cell::new(true),
            remove_on_refresh: false,
            login_active: Some(login_active.clone()),
            software_private_operations: false,
            mechanisms: crate::MECHANISMS.to_vec(),
            token_objects: Vec::new(),
            session_objects: Vec::new(),
        }),
    );
    {
        let child = test_slot_context(TEST_SLOT_ID);
        let mut context = child.lock().unwrap();
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            crate::SessionContext::new(Box::new(TestSession {
                slot_id: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
            })),
        );
        context.login_role = Some(crate::LoginRole::User);
    }
    crate::register_session_slot(TEST_SESSION_HANDLE, TEST_SLOT_ID).unwrap();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    login_active.set(false);
    let mut data = *b"test";
    let mut signature_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn login_controls_private_object_visibility_and_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut pin = *b"1234";
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_public_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    assert_eq!(
        crate::api::C_Login(
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
        crate::api::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
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
        crate::api::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::api::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::api::C_GetObjectSize(TEST_SESSION_HANDLE, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_SO as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    let mut bad_pin = *b"9999";
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            bad_pin.as_mut_ptr(),
            bad_pin.len() as CK_ULONG
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(
        crate::api::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!((count, objects[0]), (1, 2));
    assert_eq!(
        crate::api::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::api::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::api::C_Logout(TEST_SESSION_HANDLE),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn context_specific_login_authenticates_an_always_authenticate_operation() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.memory_objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
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
    });

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::api::C_Login(
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

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn context_specific_login_does_not_require_always_authenticate_attribute() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.memory_objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
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
    });

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::api::C_Login(
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

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn context_specific_login_requires_user_login() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_public_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    with_test_slot_context(TEST_SLOT_ID, |context| {
        let object = context.memory_objects.get_mut(&2).unwrap();
        object.private = false;
    });

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::api::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::api::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn login_is_shared_and_logout_invalidates_private_session_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);

    let mut ro_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut rw_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut ro_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
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
        crate::api::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(rw_session, &mut rw_info),
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
        crate::api::C_SignInit(ro_session, &mut sign_mechanism, 2),
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
        crate::api::C_GenerateKey(
            rw_session,
            &mut generate_mechanism,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut private_session_key
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::api::C_Logout(rw_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(rw_session, &mut rw_info),
        CKR_OK as CK_RV
    );
    assert_eq!(ro_info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(rw_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::api::C_Sign(
            ro_session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::api::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::api::C_GetObjectSize(ro_session, 2, &mut object_size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetObjectSize(ro_session, private_session_key, &mut object_size),
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
        crate::api::C_FindObjectsInit(
            ro_session,
            find_template.as_mut_ptr(),
            find_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_FindObjects(ro_session, &mut new_private_handle, 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(new_private_handle, 2);
    assert_ne!(new_private_handle, private_session_key);
    assert_eq!(crate::api::C_FindObjectsFinal(ro_session), CKR_OK as CK_RV);

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn token_authentication_survives_initiating_session_and_logs_out_on_last_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_LOGGED_IN.store(false, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGOUT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);
    let mut first_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut second_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    for session in [&mut first_session, &mut second_session] {
        assert_eq!(
            crate::api::C_OpenSession(
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
        crate::api::C_Login(
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

    assert_eq!(crate::api::C_CloseSession(first_session), CKR_OK as CK_RV);
    assert!(TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::api::C_GetSessionInfo(second_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(crate::api::C_CloseSession(second_session), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut close_all_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut close_all_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            close_all_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_CloseAllSessions(TEST_SLOT_ID),
        CKR_OK as CK_RV
    );
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    let mut final_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut final_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            final_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
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
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);

    let mut read_only_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut read_write_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_only_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
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

    assert_eq!(
        crate::api::C_CloseSession(read_write_session),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulSessionCount, 1);
    assert_eq!(info.ulRwSessionCount, 0);

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn session_entry_points_validate_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    assert_session_entry_points_return(999, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    assert_session_entry_points_return(999, CKR_SESSION_HANDLE_INVALID as CK_RV);

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn non_session_entry_points_validate_arguments_or_report_unsupported() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut slot = 0;

    assert_eq!(
        crate::api::C_InitToken(0, ::std::ptr::null_mut(), 0, ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::api::C_WaitForSlotEvent(0, &mut slot, ::std::ptr::null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
}

#[test]
pub fn slot_and_mechanism_calls_validate_slot_ids() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    let mut count = 0;
    let mut mechanism_info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };

    assert_eq!(
        crate::api::C_CloseAllSessions(999),
        CKR_SLOT_ID_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismList(999, ::std::ptr::null_mut(), &mut count),
        CKR_SLOT_ID_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(999, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut mechanism_info),
        CKR_SLOT_ID_INVALID as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn token_and_mechanism_queries_require_a_present_token() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot_with_backend(TEST_SLOT_ID, Box::new(test_slot(false)));

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    let mut count = 0;
    let mut mechanism_info = unsafe { ::std::mem::zeroed::<CK_MECHANISM_INFO>() };
    assert_eq!(
        crate::api::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(
        crate::api::C_GetTokenInfo(TEST_SLOT_ID, &mut token_info),
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

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn open_session_validates_session_flags() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;

    assert_eq!(
        crate::api::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);
    assert_eq!(
        crate::api::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_SESSION_PARALLEL_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(
        crate::api::C_OpenSession(
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
            crate::api::C_OpenSession(
                TEST_SLOT_ID,
                flags,
                ::std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_OK as CK_RV
        );
        assert_ne!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    }

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn set_pin_validates_session_and_changes_supported_token_pin() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_SetPIN(999, ::std::ptr::null_mut(), 1, ::std::ptr::null_mut(), 1,),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);
    assert_eq!(
        crate::api::C_SetPIN(999, ::std::ptr::null_mut(), 1, ::std::ptr::null_mut(), 1,),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_SetPIN(
            session,
            old_pin.as_mut_ptr(),
            old_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);

    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_SetPIN(
            session,
            std::ptr::null_mut(),
            0,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::api::C_SetPIN(
            session,
            wrong_pin.as_mut_ptr(),
            wrong_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::api::C_SetPIN(
            session,
            old_pin.as_mut_ptr(),
            old_pin.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn pin_entry_points_require_valid_utf8() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);

    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );

    let mut invalid_utf8 = [0xff];
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            invalid_utf8.as_mut_ptr(),
            invalid_utf8.len() as CK_ULONG,
        ),
        CKR_PIN_INVALID as CK_RV
    );

    let mut valid_utf8 = "räka".as_bytes().to_vec();
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            valid_utf8.as_mut_ptr(),
            valid_utf8.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );

    let mut old_pin = *b"1234";
    let mut new_pin = *b"5678";
    assert_eq!(
        crate::api::C_SetPIN(
            session,
            invalid_utf8.as_mut_ptr(),
            invalid_utf8.len() as CK_ULONG,
            new_pin.as_mut_ptr(),
            new_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INVALID as CK_RV
    );
    assert_eq!(
        crate::api::C_SetPIN(
            session,
            old_pin.as_mut_ptr(),
            old_pin.len() as CK_ULONG,
            invalid_utf8.as_mut_ptr(),
            invalid_utf8.len() as CK_ULONG,
        ),
        CKR_PIN_INVALID as CK_RV
    );

    let mut admin_pin = *b"12345678";
    assert_eq!(
        crate::api::C_Login(
            session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_InitPIN(
            session,
            invalid_utf8.as_mut_ptr(),
            invalid_utf8.len() as CK_ULONG,
        ),
        CKR_PIN_INVALID as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn so_login_enforces_session_rules_and_initializes_user_pin() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);

    let mut read_only_session = 0;
    let mut read_write_session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_only_session,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_SESSION_READ_ONLY_EXISTS as CK_RV
    );
    assert_eq!(
        crate::api::C_CloseSession(read_only_session),
        CKR_OK as CK_RV
    );

    let mut wrong_admin_pin = *b"00000000";
    assert_eq!(
        crate::api::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            wrong_admin_pin.as_mut_ptr(),
            wrong_admin_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    let mut user_pin = *b"1234";
    assert_eq!(
        crate::api::C_Login(
            read_write_session,
            CKU_USER as CK_USER_TYPE,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV
    );

    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::api::C_GetSessionInfo(read_write_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
    let mut object_size = 0;
    assert_eq!(
        crate::api::C_GetObjectSize(read_write_session, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut another_read_only_session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut another_read_only_session,
        ),
        CKR_SESSION_READ_WRITE_SO_EXISTS as CK_RV
    );
    assert_eq!(
        crate::api::C_InitPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut new_admin_pin = *b"87654321";
    assert_eq!(
        crate::api::C_SetPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
            new_admin_pin.as_mut_ptr(),
            new_admin_pin.len() as CK_ULONG,
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::api::C_Login(
            read_write_session,
            CKU_SO as CK_USER_TYPE,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::api::C_SetPIN(
            read_write_session,
            admin_pin.as_mut_ptr(),
            admin_pin.len() as CK_ULONG,
            new_admin_pin.as_mut_ptr(),
            new_admin_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_GetSessionInfo(read_write_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE);
    assert_eq!(
        crate::api::C_InitPIN(
            read_write_session,
            user_pin.as_mut_ptr(),
            user_pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn open_session_refreshes_token_presence() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot_with_backend(
        TEST_SLOT_ID,
        Box::new(TestSlot {
            present: std::cell::Cell::new(true),
            remove_on_refresh: true,
            login_active: None,
            software_private_operations: false,
            mechanisms: crate::MECHANISMS.to_vec(),
            token_objects: Vec::new(),
            session_objects: Vec::new(),
        }),
    );

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn get_slot_list_refreshes_registered_slot_presence() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot_with_backend(
        TEST_SLOT_ID,
        Box::new(TestSlot {
            present: std::cell::Cell::new(true),
            remove_on_refresh: true,
            login_active: None,
            software_private_operations: false,
            mechanisms: crate::MECHANISMS.to_vec(),
            token_objects: Vec::new(),
            session_objects: Vec::new(),
        }),
    );

    let mut count = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, ::std::ptr::null_mut(), &mut count,),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert!(!slots[..count as usize].contains(&TEST_SLOT_ID));

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn different_yubihsm_slots_execute_concurrently() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const FIRST_SLOT_ID: CK_SLOT_ID = 200;
    const SECOND_SLOT_ID: CK_SLOT_ID = 201;
    let state = std::sync::Arc::new(ConcurrentOperationState::default());
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .insert_yubihsm_slot(
                FIRST_SLOT_ID,
                Box::new(ConcurrentSlot {
                    state: state.clone(),
                    slot_index: 0,
                    kind: crate::SlotKind::YubiHsm,
                    device: None,
                }),
            )
            .unwrap();
        context
            .insert_yubihsm_slot(
                SECOND_SLOT_ID,
                Box::new(ConcurrentSlot {
                    state: state.clone(),
                    slot_index: 1,
                    kind: crate::SlotKind::YubiHsm,
                    device: None,
                }),
            )
            .unwrap();
    }

    let mut first_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut second_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
            FIRST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut first_session,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_OpenSession(
            SECOND_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut second_session,
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(first_session, second_session);

    let (first_result, second_result) = std::thread::scope(|scope| {
        let first = scope.spawn(move || {
            let mut output = [0u8; 8];
            crate::api::C_GenerateRandom(
                first_session,
                output.as_mut_ptr(),
                output.len() as CK_ULONG,
            )
        });
        let second = scope.spawn(move || {
            let mut output = [0u8; 8];
            crate::api::C_GenerateRandom(
                second_session,
                output.as_mut_ptr(),
                output.len() as CK_ULONG,
            )
        });
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_eq!(first_result, CKR_OK as CK_RV);
    assert_eq!(second_result, CKR_OK as CK_RV);
    assert_eq!(
        state.max_active.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "different YubiHSM slot contexts must not share an operation lock"
    );
    assert!(
        !state
            .same_slot_overlap
            .load(std::sync::atomic::Ordering::SeqCst),
        "one operation was active per slot"
    );
    assert_eq!(crate::api::C_CloseSession(first_session), CKR_OK as CK_RV);
    assert_eq!(crate::api::C_CloseSession(second_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

fn assert_pcsc_slot_context_concurrency(same_slot: bool) {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const FIRST_SLOT_ID: CK_SLOT_ID = 220;
    const SECOND_SLOT_ID: CK_SLOT_ID = 221;
    let state = std::sync::Arc::new(ConcurrentOperationState::default());
    let slot = |slot_id, slot_index| {
        (
            slot_id,
            Box::new(ConcurrentSlot {
                state: state.clone(),
                slot_index,
                kind: crate::SlotKind::Ccid(crate::CcidApplication::Piv),
                device: None,
            }) as Box<dyn crate::Slot>,
        )
    };
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .insert_pcsc_slots(vec![slot(FIRST_SLOT_ID, 0), slot(SECOND_SLOT_ID, 1)])
            .unwrap();
    }

    let open = |slot_id| {
        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                ::std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        session
    };
    let first_session = open(FIRST_SLOT_ID);
    let second_session = open(if same_slot {
        FIRST_SLOT_ID
    } else {
        SECOND_SLOT_ID
    });

    std::thread::scope(|scope| {
        let workers = [first_session, second_session].map(|session| {
            scope.spawn(move || {
                let mut output = [0u8; 8];
                assert_eq!(
                    crate::api::C_GenerateRandom(
                        session,
                        output.as_mut_ptr(),
                        output.len() as CK_ULONG,
                    ),
                    CKR_OK as CK_RV
                );
                assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
            })
        });
        for worker in workers {
            worker.join().unwrap();
        }
    });

    assert_eq!(
        state.max_active.load(std::sync::atomic::Ordering::SeqCst),
        if same_slot { 1 } else { 2 },
        "logical state must serialize per PKCS slot, not per reader"
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn pcsc_applets_use_independent_slot_contexts() {
    assert_pcsc_slot_context_concurrency(false);
}

#[test]
fn pcsc_sessions_on_one_slot_share_a_slot_context() {
    assert_pcsc_slot_context_concurrency(true);
}

#[test]
fn corrupt_fido_storage_does_not_suppress_sibling_pcsc_applets() {
    struct StorageEnvironment {
        root: std::path::PathBuf,
    }

    impl Drop for StorageEnvironment {
        fn drop(&mut self) {
            let _ = crate::api::C_Finalize(std::ptr::null_mut());
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "pkcs11rs-pcsc-fido-storage-test-{}-{id}",
        std::process::id()
    ));
    let objects = root
        .join("fido2-v1")
        .join("yubico-serial-434f4e43555252454e5430")
        .join("objects");
    std::fs::create_dir_all(&objects).unwrap();
    std::fs::write(
        objects.join(format!("sha3-256-{}.cbor", "00".repeat(32))),
        [0xf6],
    )
    .unwrap();
    let environment = StorageEnvironment { root };

    assert_eq!(
        super::initialize_with_configuration(serde_json::json!({
            "version": 1,
            "storage": {"fido2_compatibility": environment.root.to_string_lossy()}
        })),
        CKR_OK as CK_RV
    );
    const FIDO_SLOT_ID: CK_SLOT_ID = 224;
    const PIV_SLOT_ID: CK_SLOT_ID = 225;
    let state = std::sync::Arc::new(ConcurrentOperationState::default());
    let slots = vec![
        (
            FIDO_SLOT_ID,
            Box::new(ConcurrentSlot {
                state: state.clone(),
                slot_index: 0,
                kind: crate::SlotKind::Fido2,
                device: None,
            }) as Box<dyn crate::Slot>,
        ),
        (
            PIV_SLOT_ID,
            Box::new(ConcurrentSlot {
                state,
                slot_index: 1,
                kind: crate::SlotKind::Ccid(crate::CcidApplication::Piv),
                device: None,
            }) as Box<dyn crate::Slot>,
        ),
    ];
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().insert_pcsc_slots(slots).unwrap();
    }
    let context = crate::lock_context_read().unwrap();
    let slots = context.as_ref().unwrap().slot_contexts.read().unwrap();
    assert!(!slots.contains_key(&FIDO_SLOT_ID));
    assert!(slots.contains_key(&PIV_SLOT_ID));
}

fn assert_physical_device_gate(
    shared_device: bool,
    second_kind: crate::SlotKind,
    expected_max_active: usize,
) {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const HID_SLOT_ID: CK_SLOT_ID = 222;
    const CCID_SLOT_ID: CK_SLOT_ID = 223;
    let state = std::sync::Arc::new(ConcurrentOperationState::default());
    let first_device = std::sync::Arc::new(crate::device::DeviceContext::test());
    let second_device = if shared_device {
        first_device.clone()
    } else {
        std::sync::Arc::new(crate::device::DeviceContext::test())
    };
    let slots = vec![
        (
            HID_SLOT_ID,
            Box::new(ConcurrentSlot {
                state: state.clone(),
                slot_index: 0,
                kind: crate::SlotKind::Fido2,
                device: Some(first_device),
            }) as Box<dyn crate::Slot>,
        ),
        (
            CCID_SLOT_ID,
            Box::new(ConcurrentSlot {
                state: state.clone(),
                slot_index: 1,
                kind: second_kind,
                device: Some(second_device),
            }) as Box<dyn crate::Slot>,
        ),
    ];
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().insert_pcsc_slots(slots).unwrap();
    }

    let open = |slot_id| {
        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                ::std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        session
    };
    let hid_session = open(HID_SLOT_ID);
    let ccid_session = open(CCID_SLOT_ID);

    std::thread::scope(|scope| {
        let workers = [hid_session, ccid_session].map(|session| {
            scope.spawn(move || {
                let mut output = [0u8; 8];
                assert_eq!(
                    crate::api::C_GenerateRandom(
                        session,
                        output.as_mut_ptr(),
                        output.len() as CK_ULONG,
                    ),
                    CKR_OK as CK_RV
                );
            })
        });
        for worker in workers {
            worker.join().unwrap();
        }
    });

    assert_eq!(
        state.max_active.load(std::sync::atomic::Ordering::SeqCst),
        expected_max_active,
        "the physical-device gate applied the wrong transport-sharing policy"
    );
    assert_eq!(crate::api::C_CloseSession(hid_session), CKR_OK as CK_RV);
    assert_eq!(crate::api::C_CloseSession(ccid_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
fn hid_and_ccid_slots_for_one_device_share_an_operation_gate() {
    assert_physical_device_gate(true, crate::SlotKind::Ccid(crate::CcidApplication::Piv), 1);
}

#[test]
fn hid_slots_for_one_device_may_execute_concurrently() {
    assert_physical_device_gate(true, crate::SlotKind::Fido2, 2);
}

#[test]
fn slots_for_different_physical_devices_execute_concurrently() {
    assert_physical_device_gate(false, crate::SlotKind::Ccid(crate::CcidApplication::Piv), 2);
}

#[test]
pub fn many_threads_repeat_operations_on_independent_yubihsm_slots() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    const FIRST_SLOT_ID: CK_SLOT_ID = 210;
    const SECOND_SLOT_ID: CK_SLOT_ID = 211;
    const THREAD_COUNT: usize = 16;
    const CALLS_PER_THREAD: usize = 100;

    let state = std::sync::Arc::new(ConcurrentOperationState::default());
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .insert_yubihsm_slot(
                FIRST_SLOT_ID,
                Box::new(ConcurrentSlot {
                    state: state.clone(),
                    slot_index: 0,
                    kind: crate::SlotKind::YubiHsm,
                    device: None,
                }),
            )
            .unwrap();
        context
            .insert_yubihsm_slot(
                SECOND_SLOT_ID,
                Box::new(ConcurrentSlot {
                    state: state.clone(),
                    slot_index: 1,
                    kind: crate::SlotKind::YubiHsm,
                    device: None,
                }),
            )
            .unwrap();
    }

    let mut sessions = Vec::with_capacity(THREAD_COUNT);
    for thread_index in 0..THREAD_COUNT {
        let slot_id = if thread_index % 2 == 0 {
            FIRST_SLOT_ID
        } else {
            SECOND_SLOT_ID
        };
        let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
        assert_eq!(
            crate::api::C_OpenSession(
                slot_id,
                CKF_SERIAL_SESSION as CK_FLAGS,
                ::std::ptr::null_mut(),
                None,
                &mut session,
            ),
            CKR_OK as CK_RV
        );
        sessions.push((slot_id, session));
    }

    let start = std::sync::Arc::new(std::sync::Barrier::new(THREAD_COUNT));
    std::thread::scope(|scope| {
        let workers = sessions
            .into_iter()
            .map(|(slot_id, session)| {
                let start = start.clone();
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..CALLS_PER_THREAD {
                        let mut output = [0u8; 8];
                        assert_eq!(
                            crate::api::C_GenerateRandom(
                                session,
                                output.as_mut_ptr(),
                                output.len() as CK_ULONG,
                            ),
                            CKR_OK as CK_RV
                        );
                        assert_eq!(output, [slot_id as u8; 8]);
                    }
                    assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
    });

    assert!(
        !state
            .same_slot_overlap
            .load(std::sync::atomic::Ordering::SeqCst),
        "operations on one YubiHSM slot must remain serialized"
    );
    assert_eq!(
        state.max_active.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the two YubiHSM slots must make progress concurrently"
    );
    assert_eq!(
        state.operations_by_slot[0].load(std::sync::atomic::Ordering::SeqCst),
        THREAD_COUNT / 2 * CALLS_PER_THREAD
    );
    assert_eq!(
        state.operations_by_slot[1].load(std::sync::atomic::Ordering::SeqCst),
        THREAD_COUNT / 2 * CALLS_PER_THREAD
    );
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn close_cleans_local_state_after_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert_eq!(
        crate::api::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        assert!(context.login_role.is_none());
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
    });

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);
    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_CloseAllSessions(TEST_SLOT_ID),
        CKR_DEVICE_ERROR as CK_RV
    );
    with_test_slot_context(TEST_SLOT_ID, |context| {
        assert!(context.login_role.is_none());
        assert!(context.sessions.is_empty());
    });

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}

#[test]
pub fn read_only_sessions_cannot_mutate_token_or_private_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(
        crate::api::C_Initialize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
    install_test_slot(TEST_SLOT_ID);

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::api::C_OpenSession(
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
        crate::api::C_SetAttributeValue(session, 1, &mut label_attribute, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_CopyObject(session, 1, ::std::ptr::null_mut(), 0, &mut copied),
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
        crate::api::C_CreateObject(
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
        crate::api::C_CreateObject(
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
        crate::api::C_GenerateKey(
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
        crate::api::C_GenerateKey(
            session,
            &mut mechanism,
            private_key_template.as_mut_ptr(),
            private_key_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::api::C_CreateObject(
            session,
            base_template.as_mut_ptr(),
            base_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::api::C_DestroyObject(session, object),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::api::C_Finalize(::std::ptr::null_mut()),
        CKR_OK as CK_RV
    );
}
#[test]
fn object_handles_are_unique_across_storage_kinds_and_slots() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let handles = std::sync::Arc::new(crate::HandleCounters::new());
    let mut first = new_test_slot_context_with_handles(100, handles.clone());
    let mut first_slot_object = first.memory_objects.values().next().unwrap().clone();
    first_slot_object.slot_id = Some(100);
    first_slot_object.unique_id = "slot-100-object".to_owned();
    first_slot_object.token = true;
    first
        .reconcile_slot_token_objects(100, vec![first_slot_object.clone()])
        .unwrap();

    let mut second = new_test_slot_context_with_handles(101, handles);
    let mut second_slot_object = first_slot_object;
    second_slot_object.slot_id = Some(101);
    second_slot_object.unique_id = "slot-101-object".to_owned();
    second
        .reconcile_slot_token_objects(101, vec![second_slot_object])
        .unwrap();

    let handles = first
        .memory_objects
        .keys()
        .chain(first.token_object_handles.keys())
        .chain(second.memory_objects.keys())
        .chain(second.token_object_handles.keys())
        .copied()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        handles.len(),
        first.memory_objects.len()
            + first.token_object_handles.len()
            + second.memory_objects.len()
            + second.token_object_handles.len()
    );
    finalize_for_test();
}

#[test]
fn token_object_handles_are_allocated_in_stable_identity_order() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    fn reconcile_order(context: &mut crate::SlotContext, unique_ids: &[&str]) -> Vec<String> {
        let template = context.memory_objects.values().next().unwrap().clone();
        let objects = unique_ids
            .iter()
            .map(|unique_id| {
                let mut object = template.clone();
                object.slot_id = Some(100);
                object.unique_id = (*unique_id).to_owned();
                object.token = true;
                object
            })
            .collect();
        context.reconcile_slot_token_objects(100, objects).unwrap();
        let mut handles = context
            .token_object_handles
            .iter()
            .map(|(handle, locator)| (*handle, locator.unique_id.clone()))
            .collect::<Vec<_>>();
        handles.sort_by_key(|(handle, _)| *handle);
        handles
            .into_iter()
            .map(|(_, unique_id)| unique_id)
            .collect()
    }

    let mut first = new_test_slot_context(100);
    let first_order = reconcile_order(&mut first, &["object-c", "object-a", "object-b"]);
    drop(first);

    let mut second = new_test_slot_context(100);
    let second_order = reconcile_order(&mut second, &["object-b", "object-c", "object-a"]);

    assert_eq!(first_order, ["object-a", "object-b", "object-c"]);
    assert_eq!(second_order, first_order);
    finalize_for_test();
}

#[test]
fn exhausted_pkcs11_handle_spaces_return_host_memory_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    #[allow(clippy::unnecessary_cast)]
    let maximum = CK_ULONG::MAX as u64;
    let handles = crate::HandleCounters::new();

    handles.set_next_object(maximum);
    assert_eq!(handles.allocate_object().unwrap(), CK_OBJECT_HANDLE::MAX);
    let object_error: CK_RV = handles.allocate_object().unwrap_err().into();
    assert_eq!(object_error, CKR_HOST_MEMORY as CK_RV);

    handles.set_next_session(maximum);
    assert_eq!(handles.allocate_session().unwrap(), CK_SESSION_HANDLE::MAX);
    let session_error: CK_RV = handles.allocate_session().unwrap_err().into();
    assert_eq!(session_error, CKR_HOST_MEMORY as CK_RV);
}

#[test]
fn token_object_reconciliation_preserves_replaces_and_rebinds_handles() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut context = new_test_slot_context(100);
    let mut object = context.memory_objects.values().next().unwrap().clone();
    object.slot_id = Some(100);
    object.unique_id = "native-object-v1".to_owned();
    object.token = true;
    context
        .reconcile_slot_token_objects(100, vec![object.clone()])
        .unwrap();
    let original = *context.token_object_handles.keys().next().unwrap();

    context
        .reconcile_slot_token_objects(100, vec![object.clone()])
        .unwrap();
    assert!(context.token_object_handles.contains_key(&original));

    context.sessions.insert(
        TEST_SESSION_HANDLE,
        crate::SessionContext::new(Box::new(TestSession {
            slot_id: 100,
            flags: CKF_SERIAL_SESSION as CK_FLAGS,
        })),
    );
    context
        .sessions
        .get_mut(&TEST_SESSION_HANDLE)
        .unwrap()
        .find_operation = Some(crate::FindOperation {
        objects: vec![original],
        next: 0,
    });
    object.unique_id = "native-object-v2".to_owned();
    context
        .reconcile_slot_token_objects(100, vec![object.clone()])
        .unwrap();
    let replacement = *context.token_object_handles.keys().next().unwrap();
    assert_ne!(replacement, original);
    assert!(
        context.sessions[&TEST_SESSION_HANDLE]
            .find_operation
            .as_ref()
            .unwrap()
            .objects
            .is_empty()
    );

    let mut moved = object;
    moved.unique_id = "native-object-moved".to_owned();
    context
        .reconcile_slot_token_objects_with_rebindings(
            100,
            vec![moved.clone()],
            &[(replacement, moved.unique_id.clone())],
        )
        .unwrap();
    assert_eq!(
        context.token_object_handles[&replacement].unique_id,
        "native-object-moved"
    );

    assert!(
        context
            .reconcile_slot_token_objects(100, vec![moved.clone(), moved])
            .is_err()
    );
    finalize_for_test();
}
