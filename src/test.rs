#[cfg(test)]
use crate::pkcs11::*;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const LEGACY_FUNCTION_COUNT: usize = 68;
const PKCS11_3_0_FUNCTION_COUNT: usize = 24;
const PKCS11_3_2_FUNCTION_COUNT: usize = 12;

fn finalize_for_test() {
    let _ = crate::C_Finalize(::std::ptr::null_mut());
}

fn assert_function_slots_present<T>(function_list: *const T, function_count: usize) {
    assert!(!function_list.is_null());
    let first_function_offset = ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize);
    let pointer_size = ::std::mem::size_of::<*const ::std::os::raw::c_void>();

    for index in 0..function_count {
        let slot = unsafe {
            (function_list as *const u8).add(first_function_offset + index * pointer_size)
                as *const *const ::std::os::raw::c_void
        };
        assert!(
            !unsafe { *slot }.is_null(),
            "function slot {index} should be stubbed"
        );
    }
}

fn assert_unsupported_session_stubs_return(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let mut data = [0u8; 8];
    let mut data_len = data.len() as CK_ULONG;
    let mut object = 0;
    let mut second_object = 0;
    let mut flags = 0;
    let mut async_data = CK_ASYNC_DATA {
        ulVersion: 0,
        pValue: ::std::ptr::null_mut(),
        ulValue: 0,
        hObject: 0,
        hAdditionalObject: 0,
    };

    macro_rules! assert_stub {
        ($name:literal, $call:expr) => {
            assert_eq!($call, expected, "{} should behave as a stub", $name);
        };
    }

    assert_stub!(
        "C_InitPIN",
        crate::C_InitPIN(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_SetPIN",
        crate::C_SetPIN(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_GetOperationState",
        crate::C_GetOperationState(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SetOperationState",
        crate::C_SetOperationState(session, data.as_mut_ptr(), data.len() as CK_ULONG, 0, 0)
    );
    assert_stub!(
        "C_CreateObject",
        crate::C_CreateObject(session, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!(
        "C_CopyObject",
        crate::C_CopyObject(session, 0, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!("C_DestroyObject", crate::C_DestroyObject(session, 0));
    assert_stub!(
        "C_GetObjectSize",
        crate::C_GetObjectSize(session, 0, &mut data_len)
    );
    assert_stub!(
        "C_GetAttributeValue",
        crate::C_GetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SetAttributeValue",
        crate::C_SetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptInit",
        crate::C_EncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Encrypt",
        crate::C_Encrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptUpdate",
        crate::C_EncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptFinal",
        crate::C_EncryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DecryptInit",
        crate::C_DecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Decrypt",
        crate::C_Decrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptUpdate",
        crate::C_DecryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptFinal",
        crate::C_DecryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DigestInit",
        crate::C_DigestInit(session, ::std::ptr::null_mut())
    );
    assert_stub!(
        "C_Digest",
        crate::C_Digest(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestUpdate",
        crate::C_DigestUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!("C_DigestKey", crate::C_DigestKey(session, 0));
    assert_stub!(
        "C_DigestFinal",
        crate::C_DigestFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SignInit",
        crate::C_SignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Sign",
        crate::C_Sign(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignUpdate",
        crate::C_SignUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_SignFinal",
        crate::C_SignFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SignRecoverInit",
        crate::C_SignRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignRecover",
        crate::C_SignRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_VerifyInit",
        crate::C_VerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Verify",
        crate::C_Verify(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyUpdate",
        crate::C_VerifyUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifyFinal",
        crate::C_VerifyFinal(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifyRecoverInit",
        crate::C_VerifyRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyRecover",
        crate::C_VerifyRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestEncryptUpdate",
        crate::C_DigestEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptDigestUpdate",
        crate::C_DecryptDigestUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignEncryptUpdate",
        crate::C_SignEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptVerifyUpdate",
        crate::C_DecryptVerifyUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_GenerateKeyPair",
        crate::C_GenerateKeyPair(
            session,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object,
            &mut second_object
        )
    );
    assert_stub!(
        "C_WrapKey",
        crate::C_WrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKey",
        crate::C_UnwrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            &mut object
        )
    );
    assert_stub!(
        "C_DeriveKey",
        crate::C_DeriveKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object
        )
    );
    assert_stub!("C_GetFunctionStatus", crate::C_GetFunctionStatus(session));
    assert_stub!("C_CancelFunction", crate::C_CancelFunction(session));
    assert_stub!(
        "C_LoginUser",
        crate::C_LoginUser(
            session,
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_SessionCancel", crate::C_SessionCancel(session, 0));
    assert_stub!(
        "C_MessageEncryptInit",
        crate::C_MessageEncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptMessage",
        crate::C_EncryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptMessageBegin",
        crate::C_EncryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_EncryptMessageNext",
        crate::C_EncryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageEncryptFinal",
        crate::C_MessageEncryptFinal(session)
    );
    assert_stub!(
        "C_MessageDecryptInit",
        crate::C_MessageDecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_DecryptMessage",
        crate::C_DecryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptMessageBegin",
        crate::C_DecryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_DecryptMessageNext",
        crate::C_DecryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageDecryptFinal",
        crate::C_MessageDecryptFinal(session)
    );
    assert_stub!(
        "C_MessageSignInit",
        crate::C_MessageSignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessage",
        crate::C_SignMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignMessageBegin",
        crate::C_SignMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessageNext",
        crate::C_SignMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!("C_MessageSignFinal", crate::C_MessageSignFinal(session));
    assert_stub!(
        "C_MessageVerifyInit",
        crate::C_MessageVerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessage",
        crate::C_VerifyMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyMessageBegin",
        crate::C_VerifyMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessageNext",
        crate::C_VerifyMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_MessageVerifyFinal", crate::C_MessageVerifyFinal(session));
    assert_stub!(
        "C_EncapsulateKey",
        crate::C_EncapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            &mut data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_DecapsulateKey",
        crate::C_DecapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_VerifySignatureInit",
        crate::C_VerifySignatureInit(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifySignature",
        crate::C_VerifySignature(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureUpdate",
        crate::C_VerifySignatureUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureFinal",
        crate::C_VerifySignatureFinal(session)
    );
    assert_stub!(
        "C_GetSessionValidationFlags",
        crate::C_GetSessionValidationFlags(session, 0, &mut flags)
    );
    assert_stub!(
        "C_AsyncComplete",
        crate::C_AsyncComplete(session, data.as_mut_ptr(), &mut async_data)
    );
    assert_stub!(
        "C_AsyncGetID",
        crate::C_AsyncGetID(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_AsyncJoin",
        crate::C_AsyncJoin(
            session,
            data.as_mut_ptr(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_WrapKeyAuthenticated",
        crate::C_WrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKeyAuthenticated",
        crate::C_UnwrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            &mut object
        )
    );
}

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
pub fn all_legacy_function_list_entries_are_stubbed() {
    let mut function_list: CK_FUNCTION_LIST_PTR = ::std::ptr::null_mut();

    assert_eq!(
        crate::C_GetFunctionList(&mut function_list),
        CKR_OK as CK_RV
    );
    assert_eq!(unsafe { (*function_list).version.major }, 2);
    assert_eq!(unsafe { (*function_list).version.minor }, 40);
    assert_function_slots_present(function_list, LEGACY_FUNCTION_COUNT);
}

#[test]
pub fn cryptoki_3_2_interface_is_discoverable() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut count = 0;
    assert_eq!(
        crate::C_GetInterfaceList(::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);

    let mut interface = CK_INTERFACE {
        pInterfaceName: ::std::ptr::null_mut(),
        pFunctionList: ::std::ptr::null_mut(),
        flags: 0,
    };
    assert_eq!(
        crate::C_GetInterfaceList(&mut interface, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert!(!interface.pInterfaceName.is_null());
    assert!(!interface.pFunctionList.is_null());

    let function_list = interface.pFunctionList as CK_FUNCTION_LIST_3_2_PTR;
    assert_eq!(unsafe { (*function_list).version.major }, 3);
    assert_eq!(unsafe { (*function_list).version.minor }, 2);
    assert!(unsafe { (*function_list).C_GetInterface.is_some() });
    assert!(unsafe { (*function_list).C_EncapsulateKey.is_some() });
    assert_function_slots_present(
        function_list,
        LEGACY_FUNCTION_COUNT + PKCS11_3_0_FUNCTION_COUNT + PKCS11_3_2_FUNCTION_COUNT,
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
pub fn session_stub_entry_points_validate_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    assert_unsupported_session_stubs_return(999, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_unsupported_session_stubs_return(999, CKR_SESSION_HANDLE_INVALID as CK_RV);

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

    assert_eq!(crate::C_CloseAllSessions(999), CKR_SLOT_ID_INVALID as CK_RV);
    assert_eq!(
        crate::C_GetMechanismList(999, ::std::ptr::null_mut(), &mut count),
        CKR_SLOT_ID_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_random_validates_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut random_data = [0u8; 16];

    assert_eq!(
        crate::C_GenerateRandom(1, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GenerateRandom(999, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

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
    assert_eq!(count, 1);
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
