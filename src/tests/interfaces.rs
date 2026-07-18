#[test]
pub fn interface_list_checks_buffer_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut count = 0;
    let mut interface = CK_INTERFACE {
        pInterfaceName: ::std::ptr::null_mut(),
        pFunctionList: ::std::ptr::null_mut(),
        flags: 0,
    };

    assert_eq!(
        crate::C_GetInterfaceList(&mut interface, &mut count),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(count, 4);
}

fn assert_get_interface_returns_requested_table(version: CK_VERSION) {
    let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
    let mut version = version;
    let name = b"PKCS 11\0";

    assert_eq!(
        crate::C_GetInterface(
            name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_OK as CK_RV
    );
    assert!(!interface.is_null());

    match (version.major, version.minor) {
        (2, 40) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 2);
            assert_eq!(unsafe { (*function_list).version.minor }, 40);
            assert!(unsafe { (*function_list).C_GetFunctionList.is_some() });
        }
        (3, 0) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_0_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 0);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_MessageEncryptInit.is_some() });
        }
        (3, 1) => {
            // PKCS #11 3.2 headers have no CK_FUNCTION_LIST_3_1 type; 3.1 uses
            // the 3.0-shaped function list while reporting version 3.1.
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_0_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 1);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_MessageEncryptInit.is_some() });
        }
        (3, 2) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_2_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 2);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_EncapsulateKey.is_some() });
            assert!(unsafe { (*function_list).C_UnwrapKeyAuthenticated.is_some() });
        }
        _ => panic!("unexpected supported version"),
    }
}

#[test]
pub fn get_interface_returns_requested_version_and_documented_table_layout() {
    let _guard = TEST_LOCK.lock().unwrap();
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 2 });
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 1 });
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 0 });
    assert_get_interface_returns_requested_table(CK_VERSION {
        major: 2,
        minor: 40,
    });
}

#[test]
pub fn get_interface_rejects_wrong_version_and_name() {
    let _guard = TEST_LOCK.lock().unwrap();
    let name = b"PKCS 11\0";
    let wrong_name = b"NOT PKCS\0";
    let short_name = b"X\0";

    for rejected_version in [
        CK_VERSION {
            major: 2,
            minor: 39,
        },
        CK_VERSION { major: 3, minor: 3 },
        CK_VERSION { major: 3, minor: 4 },
    ] {
        let mut version = rejected_version;
        let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
        assert_eq!(
            crate::C_GetInterface(
                name.as_ptr() as *mut CK_BYTE,
                &mut version,
                &mut interface,
                0
            ),
            CKR_ARGUMENTS_BAD as CK_RV
        );
    }

    let mut version = CK_VERSION { major: 3, minor: 2 };
    let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
    assert_eq!(
        crate::C_GetInterface(
            wrong_name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GetInterface(
            short_name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GetInterface(
            name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            CKF_INTERFACE_FORK_SAFE as CK_FLAGS
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}
#[test]
pub fn bindgen_test_layout_CK_SLOT_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_SLOT_INFO>(),
        112usize,
        concat!("Size of: ", stringify!(CK_SLOT_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_SLOT_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_SLOT_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, slotDescription),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(slotDescription)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, manufacturerID),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, flags),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, hardwareVersion),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, firmwareVersion),
        106usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_TOKEN_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_TOKEN_INFO>(),
        208usize,
        concat!("Size of: ", stringify!(CK_TOKEN_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_TOKEN_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_TOKEN_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, label),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(label)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, manufacturerID),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, model),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(model)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, serialNumber),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(serialNumber)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, flags),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxSessionCount),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulSessionCount),
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxRwSessionCount),
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxRwSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulRwSessionCount),
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulRwSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxPinLen),
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxPinLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMinPinLen),
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMinPinLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPublicMemory),
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPublicMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulFreePublicMemory),
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePublicMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPrivateMemory),
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPrivateMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulFreePrivateMemory),
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePrivateMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, hardwareVersion),
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, firmwareVersion),
        186usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, utcTime),
        188usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(utcTime)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_SESSION_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_SESSION_INFO>(),
        32usize,
        concat!("Size of: ", stringify!(CK_SESSION_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_SESSION_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_SESSION_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, slotID),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(slotID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, state),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, flags),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, ulDeviceError),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(ulDeviceError)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_ATTRIBUTE() {
    assert_eq!(
        ::std::mem::size_of::<CK_ATTRIBUTE>(),
        24usize,
        concat!("Size of: ", stringify!(CK_ATTRIBUTE))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_ATTRIBUTE>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_ATTRIBUTE))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, type_),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, pValue),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(pValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, ulValueLen),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(ulValueLen)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_DATE() {
    assert_eq!(
        ::std::mem::size_of::<CK_DATE>(),
        8usize,
        concat!("Size of: ", stringify!(CK_DATE))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_DATE>(),
        1usize,
        concat!("Alignment of ", stringify!(CK_DATE))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, year),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(year)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, month),
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(month)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, day),
        6usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(day)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_MECHANISM() {
    assert_eq!(
        ::std::mem::size_of::<CK_MECHANISM>(),
        24usize,
        concat!("Size of: ", stringify!(CK_MECHANISM))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_MECHANISM>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_MECHANISM))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, mechanism),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(mechanism)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, pParameter),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(pParameter)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, ulParameterLen),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(ulParameterLen)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_MECHANISM_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_MECHANISM_INFO>(),
        24usize,
        concat!("Size of: ", stringify!(CK_MECHANISM_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_MECHANISM_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_MECHANISM_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, ulMinKeySize),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
            "::",
            stringify!(ulMinKeySize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, ulMaxKeySize),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
            "::",
            stringify!(ulMaxKeySize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, flags),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
            "::",
            stringify!(flags)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_ECDH1_DERIVE_PARAMS() {
    assert_eq!(
        ::std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>(),
        40usize,
        concat!("Size of: ", stringify!(CK_ECDH1_DERIVE_PARAMS))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_ECDH1_DERIVE_PARAMS>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_ECDH1_DERIVE_PARAMS))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, kdf),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(kdf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulSharedDataLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, pSharedData),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(pSharedData)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, ulPublicDataLen),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulPublicDataLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, pPublicData),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(pPublicData)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_RSA_PKCS_OAEP_PARAMS() {
    assert_eq!(
        ::std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
        40usize,
        concat!("Size of: ", stringify!(CK_RSA_PKCS_OAEP_PARAMS))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_RSA_PKCS_OAEP_PARAMS))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(source)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(pSourceData)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(ulSourceDataLen)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_RSA_PKCS_PSS_PARAMS() {
    assert_eq!(
        ::std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>(),
        24usize,
        concat!("Size of: ", stringify!(CK_RSA_PKCS_PSS_PARAMS))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_RSA_PKCS_PSS_PARAMS>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_RSA_PKCS_PSS_PARAMS))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, hashAlg),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, mgf),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, sLen),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(sLen)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_VERSION() {
    assert_eq!(
        ::std::mem::size_of::<CK_VERSION>(),
        2usize,
        concat!("Size of: ", stringify!(CK_VERSION))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_VERSION>(),
        1usize,
        concat!("Alignment of ", stringify!(CK_VERSION))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_VERSION, major),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_VERSION),
            "::",
            stringify!(major)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_VERSION, minor),
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_VERSION),
            "::",
            stringify!(minor)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_C_INITIALIZE_ARGS() {
    assert_eq!(
        ::std::mem::size_of::<CK_C_INITIALIZE_ARGS>(),
        48usize,
        concat!("Size of: ", stringify!(CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_C_INITIALIZE_ARGS>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, CreateMutex),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(CreateMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, DestroyMutex),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(DestroyMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, LockMutex),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(LockMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, UnlockMutex),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(UnlockMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, flags),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, pReserved),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pReserved)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_FUNCTION_LIST() {
    assert_eq!(
        ::std::mem::size_of::<CK_FUNCTION_LIST>(),
        552usize,
        concat!("Size of: ", stringify!(CK_FUNCTION_LIST))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_FUNCTION_LIST>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_FUNCTION_LIST))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, version),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Initialize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Finalize),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Finalize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetInfo),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetFunctionList),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotList),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotInfo),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetTokenInfo),
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetTokenInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismList),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismInfo),
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_InitToken),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitToken)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_InitPIN),
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitPIN)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetPIN),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetPIN)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_OpenSession),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_OpenSession)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CloseSession),
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseSession)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CloseAllSessions),
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseAllSessions)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSessionInfo),
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSessionInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetOperationState),
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetOperationState)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetOperationState),
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetOperationState)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Login),
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Login)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Logout),
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Logout)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CreateObject),
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CreateObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CopyObject),
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CopyObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DestroyObject),
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DestroyObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetObjectSize),
        192usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetObjectSize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetAttributeValue),
        200usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetAttributeValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetAttributeValue),
        208usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetAttributeValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsInit),
        216usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjects),
        224usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjects)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsFinal),
        232usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptInit),
        240usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Encrypt),
        248usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Encrypt)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptUpdate),
        256usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptFinal),
        264usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptInit),
        272usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Decrypt),
        280usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Decrypt)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptUpdate),
        288usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptFinal),
        296usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestInit),
        304usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Digest),
        312usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Digest)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestUpdate),
        320usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestKey),
        328usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestFinal),
        336usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignInit),
        344usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Sign),
        352usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Sign)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignUpdate),
        360usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignFinal),
        368usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignRecoverInit),
        376usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecoverInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignRecover),
        384usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecover)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyInit),
        392usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Verify),
        400usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Verify)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyUpdate),
        408usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyFinal),
        416usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyRecoverInit),
        424usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecoverInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyRecover),
        432usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecover)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestEncryptUpdate),
        440usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestEncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptDigestUpdate),
        448usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptDigestUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignEncryptUpdate),
        456usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignEncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptVerifyUpdate),
        464usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptVerifyUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateKey),
        472usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateKeyPair),
        480usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKeyPair)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_WrapKey),
        488usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_WrapKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_UnwrapKey),
        496usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_UnwrapKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DeriveKey),
        504usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DeriveKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SeedRandom),
        512usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SeedRandom)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateRandom),
        520usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateRandom)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetFunctionStatus),
        528usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionStatus)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CancelFunction),
        536usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CancelFunction)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_WaitForSlotEvent),
        544usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_WaitForSlotEvent)
        )
    );
}

#[cfg(feature = "abi-tests")]
#[test]
fn abi_test_slots_are_hardware_free_and_reach_backend_sessions() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut count = 0;
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(
        slots,
        vec![
            crate::ABI_TEST_SLOT_ID,
            crate::ABI_TEST_PIV_SLOT_ID,
            crate::ABI_TEST_SCP03_SLOT_ID,
            crate::ABI_TEST_YUBIHSM_SLOT_ID,
            crate::ABI_TEST_SCP11_SLOT_ID,
        ]
    );

    for slot_id in &slots {
        let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
        assert_eq!(
            crate::C_GetSlotInfo(*slot_id, &mut slot_info),
            CKR_OK as CK_RV
        );
        let description = String::from_utf8_lossy(&slot_info.slotDescription);
        assert!(!description.to_ascii_lowercase().contains("token"));
        if *slot_id == crate::ABI_TEST_PIV_SLOT_ID {
            assert_eq!(
                &slot_info.slotDescription[..b"PKCS11RS ABI PIV test slot".len()],
                b"PKCS11RS ABI PIV test slot"
            );
        }
    }

    for (slot_id, label, serial) in [
        (
            crate::ABI_TEST_SLOT_ID,
            b"ABI test token #ABI00001".as_slice(),
            b"ABI00001".as_slice(),
        ),
        (
            crate::ABI_TEST_PIV_SLOT_ID,
            b"YubiKey PIV #PIV00001".as_slice(),
            b"PIV00001".as_slice(),
        ),
        (
            crate::ABI_TEST_SCP03_SLOT_ID,
            b"ABI SCP03 #SCP03001".as_slice(),
            b"SCP03001".as_slice(),
        ),
        (
            crate::ABI_TEST_YUBIHSM_SLOT_ID,
            b"ABI YubiHSM #HSM00001".as_slice(),
            b"HSM00001".as_slice(),
        ),
        (
            crate::ABI_TEST_SCP11_SLOT_ID,
            b"ABI SCP11 #SCP11001".as_slice(),
            b"SCP11001".as_slice(),
        ),
    ] {
        let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
        assert_eq!(&token_info.label[..label.len()], label);
        assert_eq!(&token_info.serialNumber[..serial.len()], serial);
    }

    for (slot_id, model) in [
        (crate::ABI_TEST_SLOT_ID, b"ABI test token".as_slice()),
        (crate::ABI_TEST_PIV_SLOT_ID, b"YubiKey PIV".as_slice()),
        (crate::ABI_TEST_SCP03_SLOT_ID, b"ABI SCP03".as_slice()),
        (crate::ABI_TEST_YUBIHSM_SLOT_ID, b"ABI YubiHSM".as_slice()),
        (crate::ABI_TEST_SCP11_SLOT_ID, b"ABI SCP11".as_slice()),
    ] {
        let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
        assert_eq!(&token_info.model[..model.len()], model);
        assert!(token_info.model[model.len()..]
            .iter()
            .all(|byte| *byte == b' '));
    }

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            crate::ABI_TEST_SCP03_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_ptr() as *mut CK_BYTE,
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut random = [0; 16];
    assert_eq!(
        crate::C_GenerateRandom(session, random.as_mut_ptr(), random.len() as CK_ULONG),
        CKR_OK as CK_RV
    );
    assert_eq!(random, [0; 16]);

    finalize_for_test();
}

#[cfg(not(feature = "abi-tests"))]
#[test]
#[ignore = "requires a live YubiKey or YubiHSM"]
fn live_hardware_slots_report_metadata() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut count = 0;
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    slots.truncate(count as usize);
    for slot_id in slots {
        let mut slot_info = CK_SLOT_INFO {
            slotDescription: [0; 64],
            manufacturerID: [0; 32],
            flags: 0,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
        };
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
            crate::C_GetSlotInfo(slot_id, &mut slot_info),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
    }
    finalize_for_test();
}
