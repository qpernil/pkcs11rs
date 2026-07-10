#[cfg(test)]
use crate::pkcs11::*;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const LEGACY_FUNCTION_COUNT: usize = 68;
const PKCS11_3_0_FUNCTION_COUNT: usize = 24;
const PKCS11_3_2_FUNCTION_COUNT: usize = 12;
const TEST_SLOT_ID: CK_SLOT_ID = 77;
const TEST_SESSION_HANDLE: CK_SESSION_HANDLE = 88;

fn finalize_for_test() {
    let _ = crate::C_Finalize(::std::ptr::null_mut());
}

#[derive(Debug)]
struct TestSlot;

#[derive(Debug)]
struct TestSession {
    slot_id: CK_SLOT_ID,
}

impl crate::Session for TestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        CKF_SERIAL_SESSION as CK_FLAGS
    }

    fn state(&self) -> CK_STATE {
        CKS_RO_PUBLIC_SESSION as CK_STATE
    }

    fn login(&mut self, _pin: &[u8]) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn logout(&mut self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn get_session_info(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn generate(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }
}

impl crate::Slot for TestSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        String::from("Test Slot")
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Test Token"
    }

    fn serial(&self) -> &str {
        "TEST0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        true
    }

    fn open_session(&mut self, slotID: CK_SLOT_ID, _flags: CK_FLAGS) -> Box<dyn crate::Session> {
        Box::new(TestSession { slot_id: slotID })
    }

    fn init_slot(&mut self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), crate::error::Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), crate::error::Error> {
        self.format_token_info(info);
        Ok(())
    }
}

fn install_test_slot(slot_id: CK_SLOT_ID) {
    let mut context = crate::lock_context().unwrap();
    context
        .as_mut()
        .unwrap()
        .slots
        .insert(slot_id, Box::new(TestSlot));
}

fn install_test_session(slot_id: CK_SLOT_ID, session_handle: CK_SESSION_HANDLE) {
    let mut context = crate::lock_context().unwrap();
    let context = context.as_mut().unwrap();
    context.slots.insert(slot_id, Box::new(TestSlot));
    context
        .sessions
        .insert(session_handle, Box::new(TestSession { slot_id }));
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
pub fn mechanism_list_reports_supported_mechanisms() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let expected = [
        CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_ECDSA as CK_MECHANISM_TYPE,
        CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
    ];
    let mut count = 0;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut too_small = [0; 1];
    count = too_small.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, too_small.as_mut_ptr(), &mut count),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut mechanisms = [0; 5];
    count = mechanisms.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, mechanisms.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);
    assert_eq!(mechanisms, expected);

    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn mechanism_info_reports_supported_mechanism_details() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(TEST_SLOT_ID, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1024);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & CKF_GENERATE as CK_FLAGS,
        CKF_GENERATE as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_VENDOR_DEFINED as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_tracks_empty_search_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 999;

    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OPERATION_ACTIVE as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 2);
    assert_eq!(objects, [1, 2]);

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);

    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_tracks_single_part_operation_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
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
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 32);

    let mut small_signature = [0u8; 4];
    signature_len = small_signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            small_signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(signature_len, 32);

    let mut signature = [0u8; 32];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 32);
    assert!(signature.iter().any(|byte| *byte != 0));
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_init_reports_key_and_mechanism_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_SignInit(999, &mut mechanism, 2),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 2),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut unsupported, 2),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 999),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OPERATION_ACTIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_operation_is_cleared_when_session_closes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);

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
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_filters_by_attribute_template() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut templ = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_validates_sessions_and_cleans_up_on_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(999, ::std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(999, ::std::ptr::null_mut(), 0, &mut count),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(999),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_removes_object_from_store_and_search() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_updates_active_search_results() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 1);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 2),
        CKR_OK as CK_RV
    );
    count = 999;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_adds_readable_findable_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut label = *b"Created public key";
    let mut id = [4u8, 5, 6];
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut templ = [
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
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(object, 3);

    let mut read_label = [0u8; 18];
    let mut read_verify = CK_FALSE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Created public key");
    assert_eq!(read_verify, CK_TRUE as CK_BBOOL);

    let mut search_label = *b"Created public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], object);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, object),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, read_attrs.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_preserves_all_supported_template_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut label = *b"Created private key";
    let mut id = [7u8, 8, 9, 10];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_FALSE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_FALSE as CK_BBOOL;
    let mut templ = [
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
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut read_class = 0 as CK_OBJECT_CLASS;
    let mut read_key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 19];
    let mut read_id = [0u8; 4];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_private = CK_FALSE as CK_BBOOL;
    let mut read_encrypt = CK_TRUE as CK_BBOOL;
    let mut read_decrypt = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_verify = CK_TRUE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(read_class, CKO_PRIVATE_KEY as CK_OBJECT_CLASS);
    assert_eq!(read_key_type, CKK_RSA as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Created private key");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_private, CK_TRUE as CK_BBOOL);
    assert_eq!(read_encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(read_decrypt, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);
    assert_eq!(read_verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_defaults_optional_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut templ = [
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
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    let mut id_attr = CK_ATTRIBUTE {
        type_: CKA_ID as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(label_attr.ulValueLen, 0);
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut id_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(id_attr.ulValueLen, 0);

    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut bool_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            bool_attrs.as_mut_ptr(),
            bool_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(token, CK_FALSE as CK_BBOOL);
    assert_eq!(private, CK_FALSE as CK_BBOOL);
    assert_eq!(encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(decrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);
    assert_eq!(verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_reports_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0, &mut object),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1, &mut object),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut incomplete = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            incomplete.as_mut_ptr(),
            incomplete.len() as CK_ULONG,
            &mut object
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    let mut bad_class = [0u8; 1];
    let mut invalid_class_len = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: bad_class.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: bad_class.len() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_class_len.as_mut_ptr(),
            invalid_class_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut invalid_bool_len = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool_len.as_mut_ptr(),
            invalid_bool_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut null_class_value = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            null_class_value.as_mut_ptr(),
            null_class_value.len() as CK_ULONG,
            &mut object
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            999,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn copy_object_clones_and_overrides_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Copied public key";
    let mut id = [8u8, 6, 4, 2];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut copied
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied, 3);

    let mut copied_class = 0 as CK_OBJECT_CLASS;
    let mut copied_key_type = 999 as CK_KEY_TYPE;
    let mut copied_label = [0u8; 17];
    let mut copied_id = [0u8; 4];
    let mut copied_verify = CK_FALSE as CK_BBOOL;
    let mut copied_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: copied_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: copied_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            copied,
            copied_attrs.as_mut_ptr(),
            copied_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied_class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(copied_key_type, CKK_RSA as CK_KEY_TYPE);
    assert_eq!(&copied_label, b"Copied public key");
    assert_eq!(copied_id, id);
    assert_eq!(copied_verify, CK_TRUE as CK_BBOOL);

    let mut original_label = [0u8; 19];
    let mut original_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: original_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut original_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&original_label, b"Test RSA public key");

    let mut search_label = *b"Copied public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], copied);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn copy_object_reports_template_and_handle_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            999,
            ::std::ptr::null_mut(),
            0,
            &mut copied
        ),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            1,
            &mut copied
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            readonly_attr.as_mut_ptr(),
            readonly_attr.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            999,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, unknown.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_attribute_storage_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (2 * ::std::mem::size_of::<CK_ULONG>() + b"Test RSA public key".len() + 1 + 6) as CK_ULONG
    );

    let mut label = *b"Short";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (2 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 6) as CK_ULONG
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_created_object_size_and_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut label = *b"Sized key";
    let mut id = [1u8, 2, 3, 4, 5];
    let mut templ = [
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
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (2 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 6) as CK_ULONG
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 999, &mut size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(999, object, &mut size),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_sizes_and_values() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        label_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut label = [0u8; 19];
    label_attr.pValue = label.as_mut_ptr() as CK_VOID_PTR;
    label_attr.ulValueLen = label.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&label, b"Test RSA public key");

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut small_label = [0u8; 4];
    let mut small_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: small_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: small_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut small_attr, 1),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(
        small_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut unknown_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut unknown_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        unknown_attr.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 999, &mut unknown_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(999, 1, &mut unknown_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_updates_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Renamed public key";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );

    let mut read_label = [0u8; 18];
    let mut read_id = [0u8; 3];
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Renamed public key");
    assert_eq!(read_id, id);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut readonly_attr, 1),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut invalid_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut invalid_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );

    let mut bad_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 1,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut bad_attr, 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 999, &mut invalid_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(999, 1, &mut invalid_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_key_creates_secret_key_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut label = *b"Generated secret";
    let mut id = [3u8, 1, 4];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(key, 3);

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 16];
    let mut read_id = [0u8; 3];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_attrs = [
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
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Generated secret");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);

    let mut search_label = *b"Generated secret";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], key);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_key_reports_mechanism_and_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(999, &mut mechanism, ::std::ptr::null_mut(), 0, &mut key),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            1,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut unsupported,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut inconsistent = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            inconsistent.as_mut_ptr(),
            inconsistent.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut key
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, invalid_bool.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
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
