#[no_mangle]
pub extern "C" fn C_GetFunctionStatus(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_CancelFunction(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
    interfaces_list: *mut CK_INTERFACE,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    unsafe {
        let count = match count.as_mut() {
            Some(count) => count,
            None => return CKR_ARGUMENTS_BAD.into(),
        };

        const INTERFACE_COUNT: CK_ULONG = 4;

        if interfaces_list.is_null() {
            *count = INTERFACE_COUNT;
            return CKR_OK.into();
        }

        if *count < INTERFACE_COUNT {
            *count = INTERFACE_COUNT;
            return CKR_BUFFER_TOO_SMALL.into();
        }

        let interfaces = [
            G_INTERFACE_2_40,
            G_INTERFACE_3_0,
            G_INTERFACE_3_1,
            G_INTERFACE_3_2,
        ];
        ptr::copy_nonoverlapping(interfaces.as_ptr(), interfaces_list, interfaces.len());
        *count = INTERFACE_COUNT;
        CKR_OK.into()
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetInterface(
    interface_name: *mut ::std::os::raw::c_uchar,
    version: *mut CK_VERSION,
    interface_: *mut *mut CK_INTERFACE,
    flags: CK_FLAGS,
) -> CK_RV {
    unsafe {
        let interface_ = match interface_.as_mut() {
            Some(interface_) => interface_,
            None => return CKR_ARGUMENTS_BAD.into(),
        };

        let selected_interface = match version
            .as_ref()
            .map(|version| (version.major, version.minor))
        {
            Some((2, 40)) => &G_INTERFACE_2_40,
            Some((3, 0)) => &G_INTERFACE_3_0,
            Some((3, 1)) => &G_INTERFACE_3_1,
            Some((3, 2)) | None => &G_INTERFACE_3_2,
            Some(_) => return CKR_ARGUMENTS_BAD.into(),
        };

        if flags & !selected_interface.flags != 0 {
            return CKR_ARGUMENTS_BAD.into();
        }

        if !interface_name.is_null() {
            let name = CStr::from_ptr(interface_name.cast());
            if name.to_bytes() != b"PKCS 11" {
                return CKR_ARGUMENTS_BAD.into();
            }
        }

        *interface_ = selected_interface as *const CK_INTERFACE as CK_INTERFACE_PTR;
        CKR_OK.into()
    }
}

#[no_mangle]
pub extern "C" fn C_LoginUser(
    session_handle: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: *mut ::std::os::raw::c_uchar,
    _pin_len: ::std::os::raw::c_ulong,
    _username: *mut ::std::os::raw::c_uchar,
    _username_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SessionCancel(session_handle: CK_SESSION_HANDLE, _flags: CK_FLAGS) -> CK_RV {
    session_function_not_supported(session_handle)
}

macro_rules! message_stub {
    ($name:ident ( $($arg:ident : $typ:ty),* $(,)? )) => {
        #[no_mangle]
        pub extern "C" fn $name(session_handle: CK_SESSION_HANDLE, $($arg: $typ),*) -> CK_RV {
            $(let _ = $arg;)*
            session_function_not_supported(session_handle)
        }
    };
}

message_stub!(C_MessageEncryptInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
message_stub!(C_EncryptMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    plaintext: *mut ::std::os::raw::c_uchar,
    plaintext_len: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_EncryptMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
));
message_stub!(C_EncryptMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    plaintext_part: *mut ::std::os::raw::c_uchar,
    plaintext_part_len: ::std::os::raw::c_ulong,
    ciphertext_part: *mut ::std::os::raw::c_uchar,
    ciphertext_part_len: *mut ::std::os::raw::c_ulong,
    flags: CK_FLAGS,
));
message_stub!(C_MessageEncryptFinal());

message_stub!(C_MessageDecryptInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
message_stub!(C_DecryptMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: ::std::os::raw::c_ulong,
    plaintext: *mut ::std::os::raw::c_uchar,
    plaintext_len: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_DecryptMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
));
message_stub!(C_DecryptMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    ciphertext_part: *mut ::std::os::raw::c_uchar,
    ciphertext_part_len: ::std::os::raw::c_ulong,
    plaintext_part: *mut ::std::os::raw::c_uchar,
    plaintext_part_len: *mut ::std::os::raw::c_ulong,
    flags: CK_FLAGS,
));
message_stub!(C_MessageDecryptFinal());

message_stub!(C_MessageSignInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
message_stub!(C_SignMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_SignMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
));
message_stub!(C_SignMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_MessageSignFinal());

message_stub!(C_MessageVerifyInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
message_stub!(C_VerifyMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
message_stub!(C_VerifyMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
));
message_stub!(C_VerifyMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
message_stub!(C_MessageVerifyFinal());

message_stub!(C_EncapsulateKey(
    mechanism: *mut CK_MECHANISM,
    public_key: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: *mut ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
));
message_stub!(C_DecapsulateKey(
    mechanism: *mut CK_MECHANISM,
    private_key: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
));
message_stub!(C_VerifySignatureInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
message_stub!(C_VerifySignature(
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
));
message_stub!(C_VerifySignatureUpdate(
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
));
message_stub!(C_VerifySignatureFinal());
message_stub!(C_GetSessionValidationFlags(
    type_: CK_SESSION_VALIDATION_FLAGS_TYPE,
    flags: *mut CK_FLAGS,
));
message_stub!(C_AsyncComplete(
    function_name: *mut ::std::os::raw::c_uchar,
    result: *mut CK_ASYNC_DATA,
));
message_stub!(C_AsyncGetID(
    function_name: *mut ::std::os::raw::c_uchar,
    id: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_AsyncJoin(
    function_name: *mut ::std::os::raw::c_uchar,
    id: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
));
message_stub!(C_WrapKeyAuthenticated(
    mechanism: *mut CK_MECHANISM,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    wrapped_key: *mut ::std::os::raw::c_uchar,
    wrapped_key_len: *mut ::std::os::raw::c_ulong,
));
message_stub!(C_UnwrapKeyAuthenticated(
    mechanism: *mut CK_MECHANISM,
    unwrapping_key: CK_OBJECT_HANDLE,
    wrapped_key: *mut ::std::os::raw::c_uchar,
    wrapped_key_len: ::std::os::raw::c_ulong,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
));

const fn function_list_2_40(version: CK_VERSION) -> CK_FUNCTION_LIST {
    CK_FUNCTION_LIST {
        version,

        C_Initialize: Some(C_Initialize),
        C_Finalize: Some(C_Finalize),
        C_GetInfo: Some(C_GetInfo),
        C_GetFunctionList: Some(C_GetFunctionList),

        C_GetSlotList: Some(C_GetSlotList),
        C_GetSlotInfo: Some(C_GetSlotInfo),
        C_GetTokenInfo: Some(C_GetTokenInfo),

        C_GetMechanismList: Some(C_GetMechanismList),
        C_GetMechanismInfo: Some(C_GetMechanismInfo),

        C_InitToken: Some(C_InitToken),
        C_InitPIN: Some(C_InitPIN),
        C_SetPIN: Some(C_SetPIN),

        C_OpenSession: Some(C_OpenSession),
        C_CloseSession: Some(C_CloseSession),
        C_CloseAllSessions: Some(C_CloseAllSessions),
        C_GetSessionInfo: Some(C_GetSessionInfo),

        C_GetOperationState: Some(C_GetOperationState),
        C_SetOperationState: Some(C_SetOperationState),

        C_Login: Some(C_Login),
        C_Logout: Some(C_Logout),

        C_CreateObject: Some(C_CreateObject),
        C_CopyObject: Some(C_CopyObject),
        C_DestroyObject: Some(C_DestroyObject),
        C_GetObjectSize: Some(C_GetObjectSize),

        C_GetAttributeValue: Some(C_GetAttributeValue),
        C_SetAttributeValue: Some(C_SetAttributeValue),

        C_FindObjectsInit: Some(C_FindObjectsInit),
        C_FindObjects: Some(C_FindObjects),
        C_FindObjectsFinal: Some(C_FindObjectsFinal),

        C_EncryptInit: Some(C_EncryptInit),
        C_Encrypt: Some(C_Encrypt),
        C_EncryptUpdate: Some(C_EncryptUpdate),
        C_EncryptFinal: Some(C_EncryptFinal),

        C_DecryptInit: Some(C_DecryptInit),
        C_Decrypt: Some(C_Decrypt),
        C_DecryptUpdate: Some(C_DecryptUpdate),
        C_DecryptFinal: Some(C_DecryptFinal),

        C_DigestInit: Some(C_DigestInit),
        C_Digest: Some(C_Digest),
        C_DigestUpdate: Some(C_DigestUpdate),
        C_DigestKey: Some(C_DigestKey),
        C_DigestFinal: Some(C_DigestFinal),

        C_SignInit: Some(C_SignInit),
        C_Sign: Some(C_Sign),
        C_SignUpdate: Some(C_SignUpdate),
        C_SignFinal: Some(C_SignFinal),
        C_SignRecoverInit: Some(C_SignRecoverInit),
        C_SignRecover: Some(C_SignRecover),

        C_VerifyInit: Some(C_VerifyInit),
        C_Verify: Some(C_Verify),
        C_VerifyUpdate: Some(C_VerifyUpdate),
        C_VerifyFinal: Some(C_VerifyFinal),
        C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
        C_VerifyRecover: Some(C_VerifyRecover),

        C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),

        C_GenerateKey: Some(C_GenerateKey),
        C_GenerateKeyPair: Some(C_GenerateKeyPair),

        C_WrapKey: Some(C_WrapKey),
        C_UnwrapKey: Some(C_UnwrapKey),
        C_DeriveKey: Some(C_DeriveKey),

        C_SeedRandom: Some(C_SeedRandom),
        C_GenerateRandom: Some(C_GenerateRandom),

        C_GetFunctionStatus: Some(C_GetFunctionStatus),
        C_CancelFunction: Some(C_CancelFunction),
        C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
    }
}

const fn function_list_3_0(version: CK_VERSION) -> CK_FUNCTION_LIST_3_0 {
    CK_FUNCTION_LIST_3_0 {
        version,

        C_Initialize: Some(C_Initialize),
        C_Finalize: Some(C_Finalize),
        C_GetInfo: Some(C_GetInfo),
        C_GetFunctionList: Some(C_GetFunctionList),

        C_GetSlotList: Some(C_GetSlotList),
        C_GetSlotInfo: Some(C_GetSlotInfo),
        C_GetTokenInfo: Some(C_GetTokenInfo),

        C_GetMechanismList: Some(C_GetMechanismList),
        C_GetMechanismInfo: Some(C_GetMechanismInfo),

        C_InitToken: Some(C_InitToken),
        C_InitPIN: Some(C_InitPIN),
        C_SetPIN: Some(C_SetPIN),

        C_OpenSession: Some(C_OpenSession),
        C_CloseSession: Some(C_CloseSession),
        C_CloseAllSessions: Some(C_CloseAllSessions),
        C_GetSessionInfo: Some(C_GetSessionInfo),

        C_GetOperationState: Some(C_GetOperationState),
        C_SetOperationState: Some(C_SetOperationState),

        C_Login: Some(C_Login),
        C_Logout: Some(C_Logout),

        C_CreateObject: Some(C_CreateObject),
        C_CopyObject: Some(C_CopyObject),
        C_DestroyObject: Some(C_DestroyObject),
        C_GetObjectSize: Some(C_GetObjectSize),

        C_GetAttributeValue: Some(C_GetAttributeValue),
        C_SetAttributeValue: Some(C_SetAttributeValue),

        C_FindObjectsInit: Some(C_FindObjectsInit),
        C_FindObjects: Some(C_FindObjects),
        C_FindObjectsFinal: Some(C_FindObjectsFinal),

        C_EncryptInit: Some(C_EncryptInit),
        C_Encrypt: Some(C_Encrypt),
        C_EncryptUpdate: Some(C_EncryptUpdate),
        C_EncryptFinal: Some(C_EncryptFinal),

        C_DecryptInit: Some(C_DecryptInit),
        C_Decrypt: Some(C_Decrypt),
        C_DecryptUpdate: Some(C_DecryptUpdate),
        C_DecryptFinal: Some(C_DecryptFinal),

        C_DigestInit: Some(C_DigestInit),
        C_Digest: Some(C_Digest),
        C_DigestUpdate: Some(C_DigestUpdate),
        C_DigestKey: Some(C_DigestKey),
        C_DigestFinal: Some(C_DigestFinal),

        C_SignInit: Some(C_SignInit),
        C_Sign: Some(C_Sign),
        C_SignUpdate: Some(C_SignUpdate),
        C_SignFinal: Some(C_SignFinal),
        C_SignRecoverInit: Some(C_SignRecoverInit),
        C_SignRecover: Some(C_SignRecover),

        C_VerifyInit: Some(C_VerifyInit),
        C_Verify: Some(C_Verify),
        C_VerifyUpdate: Some(C_VerifyUpdate),
        C_VerifyFinal: Some(C_VerifyFinal),
        C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
        C_VerifyRecover: Some(C_VerifyRecover),

        C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),

        C_GenerateKey: Some(C_GenerateKey),
        C_GenerateKeyPair: Some(C_GenerateKeyPair),

        C_WrapKey: Some(C_WrapKey),
        C_UnwrapKey: Some(C_UnwrapKey),
        C_DeriveKey: Some(C_DeriveKey),

        C_SeedRandom: Some(C_SeedRandom),
        C_GenerateRandom: Some(C_GenerateRandom),

        C_GetFunctionStatus: Some(C_GetFunctionStatus),
        C_CancelFunction: Some(C_CancelFunction),
        C_WaitForSlotEvent: Some(C_WaitForSlotEvent),

        C_GetInterfaceList: Some(C_GetInterfaceList),
        C_GetInterface: Some(C_GetInterface),
        C_LoginUser: Some(C_LoginUser),
        C_SessionCancel: Some(C_SessionCancel),

        C_MessageEncryptInit: Some(C_MessageEncryptInit),
        C_EncryptMessage: Some(C_EncryptMessage),
        C_EncryptMessageBegin: Some(C_EncryptMessageBegin),
        C_EncryptMessageNext: Some(C_EncryptMessageNext),
        C_MessageEncryptFinal: Some(C_MessageEncryptFinal),

        C_MessageDecryptInit: Some(C_MessageDecryptInit),
        C_DecryptMessage: Some(C_DecryptMessage),
        C_DecryptMessageBegin: Some(C_DecryptMessageBegin),
        C_DecryptMessageNext: Some(C_DecryptMessageNext),
        C_MessageDecryptFinal: Some(C_MessageDecryptFinal),

        C_MessageSignInit: Some(C_MessageSignInit),
        C_SignMessage: Some(C_SignMessage),
        C_SignMessageBegin: Some(C_SignMessageBegin),
        C_SignMessageNext: Some(C_SignMessageNext),
        C_MessageSignFinal: Some(C_MessageSignFinal),

        C_MessageVerifyInit: Some(C_MessageVerifyInit),
        C_VerifyMessage: Some(C_VerifyMessage),
        C_VerifyMessageBegin: Some(C_VerifyMessageBegin),
        C_VerifyMessageNext: Some(C_VerifyMessageNext),
        C_MessageVerifyFinal: Some(C_MessageVerifyFinal),
    }
}

const fn function_list_3_2(version: CK_VERSION) -> CK_FUNCTION_LIST_3_2 {
    CK_FUNCTION_LIST_3_2 {
        version,

        C_Initialize: Some(C_Initialize),
        C_Finalize: Some(C_Finalize),
        C_GetInfo: Some(C_GetInfo),
        C_GetFunctionList: Some(C_GetFunctionList),

        C_GetSlotList: Some(C_GetSlotList),
        C_GetSlotInfo: Some(C_GetSlotInfo),
        C_GetTokenInfo: Some(C_GetTokenInfo),

        C_GetMechanismList: Some(C_GetMechanismList),
        C_GetMechanismInfo: Some(C_GetMechanismInfo),

        C_InitToken: Some(C_InitToken),
        C_InitPIN: Some(C_InitPIN),
        C_SetPIN: Some(C_SetPIN),

        C_OpenSession: Some(C_OpenSession),
        C_CloseSession: Some(C_CloseSession),
        C_CloseAllSessions: Some(C_CloseAllSessions),
        C_GetSessionInfo: Some(C_GetSessionInfo),

        C_GetOperationState: Some(C_GetOperationState),
        C_SetOperationState: Some(C_SetOperationState),

        C_Login: Some(C_Login),
        C_Logout: Some(C_Logout),

        C_CreateObject: Some(C_CreateObject),
        C_CopyObject: Some(C_CopyObject),
        C_DestroyObject: Some(C_DestroyObject),
        C_GetObjectSize: Some(C_GetObjectSize),

        C_GetAttributeValue: Some(C_GetAttributeValue),
        C_SetAttributeValue: Some(C_SetAttributeValue),

        C_FindObjectsInit: Some(C_FindObjectsInit),
        C_FindObjects: Some(C_FindObjects),
        C_FindObjectsFinal: Some(C_FindObjectsFinal),

        C_EncryptInit: Some(C_EncryptInit),
        C_Encrypt: Some(C_Encrypt),
        C_EncryptUpdate: Some(C_EncryptUpdate),
        C_EncryptFinal: Some(C_EncryptFinal),

        C_DecryptInit: Some(C_DecryptInit),
        C_Decrypt: Some(C_Decrypt),
        C_DecryptUpdate: Some(C_DecryptUpdate),
        C_DecryptFinal: Some(C_DecryptFinal),

        C_DigestInit: Some(C_DigestInit),
        C_Digest: Some(C_Digest),
        C_DigestUpdate: Some(C_DigestUpdate),
        C_DigestKey: Some(C_DigestKey),
        C_DigestFinal: Some(C_DigestFinal),

        C_SignInit: Some(C_SignInit),
        C_Sign: Some(C_Sign),
        C_SignUpdate: Some(C_SignUpdate),
        C_SignFinal: Some(C_SignFinal),
        C_SignRecoverInit: Some(C_SignRecoverInit),
        C_SignRecover: Some(C_SignRecover),

        C_VerifyInit: Some(C_VerifyInit),
        C_Verify: Some(C_Verify),
        C_VerifyUpdate: Some(C_VerifyUpdate),
        C_VerifyFinal: Some(C_VerifyFinal),
        C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
        C_VerifyRecover: Some(C_VerifyRecover),

        C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),

        C_GenerateKey: Some(C_GenerateKey),
        C_GenerateKeyPair: Some(C_GenerateKeyPair),

        C_WrapKey: Some(C_WrapKey),
        C_UnwrapKey: Some(C_UnwrapKey),
        C_DeriveKey: Some(C_DeriveKey),

        C_SeedRandom: Some(C_SeedRandom),
        C_GenerateRandom: Some(C_GenerateRandom),

        C_GetFunctionStatus: Some(C_GetFunctionStatus),
        C_CancelFunction: Some(C_CancelFunction),
        C_WaitForSlotEvent: Some(C_WaitForSlotEvent),

        C_GetInterfaceList: Some(C_GetInterfaceList),
        C_GetInterface: Some(C_GetInterface),
        C_LoginUser: Some(C_LoginUser),
        C_SessionCancel: Some(C_SessionCancel),

        C_MessageEncryptInit: Some(C_MessageEncryptInit),
        C_EncryptMessage: Some(C_EncryptMessage),
        C_EncryptMessageBegin: Some(C_EncryptMessageBegin),
        C_EncryptMessageNext: Some(C_EncryptMessageNext),
        C_MessageEncryptFinal: Some(C_MessageEncryptFinal),

        C_MessageDecryptInit: Some(C_MessageDecryptInit),
        C_DecryptMessage: Some(C_DecryptMessage),
        C_DecryptMessageBegin: Some(C_DecryptMessageBegin),
        C_DecryptMessageNext: Some(C_DecryptMessageNext),
        C_MessageDecryptFinal: Some(C_MessageDecryptFinal),

        C_MessageSignInit: Some(C_MessageSignInit),
        C_SignMessage: Some(C_SignMessage),
        C_SignMessageBegin: Some(C_SignMessageBegin),
        C_SignMessageNext: Some(C_SignMessageNext),
        C_MessageSignFinal: Some(C_MessageSignFinal),

        C_MessageVerifyInit: Some(C_MessageVerifyInit),
        C_VerifyMessage: Some(C_VerifyMessage),
        C_VerifyMessageBegin: Some(C_VerifyMessageBegin),
        C_VerifyMessageNext: Some(C_VerifyMessageNext),
        C_MessageVerifyFinal: Some(C_MessageVerifyFinal),

        C_EncapsulateKey: Some(C_EncapsulateKey),
        C_DecapsulateKey: Some(C_DecapsulateKey),
        C_VerifySignatureInit: Some(C_VerifySignatureInit),
        C_VerifySignature: Some(C_VerifySignature),
        C_VerifySignatureUpdate: Some(C_VerifySignatureUpdate),
        C_VerifySignatureFinal: Some(C_VerifySignatureFinal),
        C_GetSessionValidationFlags: Some(C_GetSessionValidationFlags),
        C_AsyncComplete: Some(C_AsyncComplete),
        C_AsyncGetID: Some(C_AsyncGetID),
        C_AsyncJoin: Some(C_AsyncJoin),
        C_WrapKeyAuthenticated: Some(C_WrapKeyAuthenticated),
        C_UnwrapKeyAuthenticated: Some(C_UnwrapKeyAuthenticated),
    }
}

static G_FUNCTION_LIST: CK_FUNCTION_LIST = function_list_2_40(CK_VERSION {
    major: 2,
    minor: 40,
});

static G_FUNCTION_LIST_3_0: CK_FUNCTION_LIST_3_0 =
    function_list_3_0(CK_VERSION { major: 3, minor: 0 });

// PKCS #11 3.2 headers do not define a CK_FUNCTION_LIST_3_1 layout.
// A 3.1 request gets the 3.0-shaped table with the requested 3.1 version.
static G_FUNCTION_LIST_3_1: CK_FUNCTION_LIST_3_0 =
    function_list_3_0(CK_VERSION { major: 3, minor: 1 });

static G_FUNCTION_LIST_3_2: CK_FUNCTION_LIST_3_2 =
    function_list_3_2(CK_VERSION { major: 3, minor: 2 });

static G_INTERFACE_2_40: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut ::std::os::raw::c_void,
    flags: 0,
};

static G_INTERFACE_3_0: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_0 as *const CK_FUNCTION_LIST_3_0
        as *mut ::std::os::raw::c_void,
    flags: 0,
};

static G_INTERFACE_3_1: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_1 as *const CK_FUNCTION_LIST_3_0
        as *mut ::std::os::raw::c_void,
    flags: 0,
};

static G_INTERFACE_3_2: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_2 as *const CK_FUNCTION_LIST_3_2
        as *mut ::std::os::raw::c_void,
    flags: 0,
};
