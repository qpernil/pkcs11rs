use crate::*;

#[repr(transparent)]
#[derive(Copy, Clone)]
struct StaticInterface(CK_INTERFACE);

// SAFETY: These wrappers contain only process-lifetime pointers to immutable
// interface names and function lists. Restricting Sync to the wrapper avoids
// promising that every caller-created CK_INTERFACE is safe to share.
unsafe impl Sync for StaticInterface {}

session_unsupported_stub!(C_GetFunctionStatus());
session_unsupported_stub!(C_CancelFunction());

#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
    interfaces_list: *mut CK_INTERFACE,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    crate::ffi_boundary(|| unsafe {
        let count = match as_mut(count) {
            Ok(count) => count,
            Err(error) => return error.into(),
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
            G_INTERFACE_2_40.0,
            G_INTERFACE_3_0.0,
            G_INTERFACE_3_1.0,
            G_INTERFACE_3_2.0,
        ];
        let output = match _from_raw_parts_mut(interfaces_list, interfaces.len()) {
            Ok(output) => output,
            Err(error) => return error.into(),
        };
        output.copy_from_slice(&interfaces);
        *count = INTERFACE_COUNT;
        CKR_OK.into()
    })
}

#[no_mangle]
pub extern "C" fn C_GetInterface(
    interface_name: *mut ::std::os::raw::c_uchar,
    version: *mut CK_VERSION,
    interface_: *mut *mut CK_INTERFACE,
    flags: CK_FLAGS,
) -> CK_RV {
    crate::ffi_boundary(|| unsafe {
        let interface_ = match as_mut(interface_) {
            Ok(interface_) => interface_,
            Err(error) => return error.into(),
        };

        let selected_interface = match version
            .as_ref()
            .map(|version| (version.major, version.minor))
        {
            Some((2, 40)) => &G_INTERFACE_2_40.0,
            Some((3, 0)) => &G_INTERFACE_3_0.0,
            Some((3, 1)) => &G_INTERFACE_3_1.0,
            Some((3, 2)) | None => &G_INTERFACE_3_2.0,
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
    })
}

session_unsupported_stub!(C_SessionCancel(_flags: CK_FLAGS));

session_unsupported_stub!(C_MessageEncryptInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_EncryptMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    plaintext: *mut ::std::os::raw::c_uchar,
    plaintext_len: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_EncryptMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_EncryptMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    plaintext_part: *mut ::std::os::raw::c_uchar,
    plaintext_part_len: ::std::os::raw::c_ulong,
    ciphertext_part: *mut ::std::os::raw::c_uchar,
    ciphertext_part_len: *mut ::std::os::raw::c_ulong,
    flags: CK_FLAGS,
));
session_unsupported_stub!(C_MessageEncryptFinal());

session_unsupported_stub!(C_MessageDecryptInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_DecryptMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: ::std::os::raw::c_ulong,
    plaintext: *mut ::std::os::raw::c_uchar,
    plaintext_len: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_DecryptMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_DecryptMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    ciphertext_part: *mut ::std::os::raw::c_uchar,
    ciphertext_part_len: ::std::os::raw::c_ulong,
    plaintext_part: *mut ::std::os::raw::c_uchar,
    plaintext_part_len: *mut ::std::os::raw::c_ulong,
    flags: CK_FLAGS,
));
session_unsupported_stub!(C_MessageDecryptFinal());

session_unsupported_stub!(C_MessageSignInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_SignMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_SignMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_SignMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_MessageSignFinal());

session_unsupported_stub!(C_MessageVerifyInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_VerifyMessage(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_VerifyMessageBegin(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_VerifyMessageNext(
    parameter: *mut ::std::os::raw::c_void,
    parameter_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_MessageVerifyFinal());

session_unsupported_stub!(C_EncapsulateKey(
    mechanism: *mut CK_MECHANISM,
    public_key: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: *mut ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_DecapsulateKey(
    mechanism: *mut CK_MECHANISM,
    private_key: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    ciphertext: *mut ::std::os::raw::c_uchar,
    ciphertext_len: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
));
session_unsupported_stub!(C_VerifySignatureInit(
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_VerifySignature(
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_VerifySignatureUpdate(
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_VerifySignatureFinal());
session_unsupported_stub!(C_GetSessionValidationFlags(
    type_: CK_SESSION_VALIDATION_FLAGS_TYPE,
    flags: *mut CK_FLAGS,
));
session_unsupported_stub!(C_AsyncComplete(
    function_name: *mut ::std::os::raw::c_uchar,
    result: *mut CK_ASYNC_DATA,
));
session_unsupported_stub!(C_AsyncGetID(
    function_name: *mut ::std::os::raw::c_uchar,
    id: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_AsyncJoin(
    function_name: *mut ::std::os::raw::c_uchar,
    id: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_WrapKeyAuthenticated(
    mechanism: *mut CK_MECHANISM,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    associated_data: *mut ::std::os::raw::c_uchar,
    associated_data_len: ::std::os::raw::c_ulong,
    wrapped_key: *mut ::std::os::raw::c_uchar,
    wrapped_key_len: *mut ::std::os::raw::c_ulong,
));
session_unsupported_stub!(C_UnwrapKeyAuthenticated(
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

        C_Initialize: Some(crate::api::C_Initialize),
        C_Finalize: Some(crate::api::C_Finalize),
        C_GetInfo: Some(crate::api::C_GetInfo),
        C_GetFunctionList: Some(crate::api::C_GetFunctionList),

        C_GetSlotList: Some(crate::api::C_GetSlotList),
        C_GetSlotInfo: Some(crate::api::C_GetSlotInfo),
        C_GetTokenInfo: Some(crate::api::C_GetTokenInfo),

        C_GetMechanismList: Some(crate::mechanism::C_GetMechanismList),
        C_GetMechanismInfo: Some(crate::mechanism::C_GetMechanismInfo),

        C_InitToken: Some(crate::api::C_InitToken),
        C_InitPIN: Some(crate::api::C_InitPIN),
        C_SetPIN: Some(crate::api::C_SetPIN),

        C_OpenSession: Some(crate::api::C_OpenSession),
        C_CloseSession: Some(crate::api::C_CloseSession),
        C_CloseAllSessions: Some(crate::api::C_CloseAllSessions),
        C_GetSessionInfo: Some(crate::api::C_GetSessionInfo),

        C_GetOperationState: Some(crate::api::C_GetOperationState),
        C_SetOperationState: Some(crate::api::C_SetOperationState),

        C_Login: Some(crate::api::C_Login),
        C_Logout: Some(crate::api::C_Logout),

        C_CreateObject: Some(crate::api::C_CreateObject),
        C_CopyObject: Some(crate::api::C_CopyObject),
        C_DestroyObject: Some(crate::api::C_DestroyObject),
        C_GetObjectSize: Some(crate::api::C_GetObjectSize),

        C_GetAttributeValue: Some(crate::api::C_GetAttributeValue),
        C_SetAttributeValue: Some(crate::api::C_SetAttributeValue),

        C_FindObjectsInit: Some(crate::api::C_FindObjectsInit),
        C_FindObjects: Some(crate::api::C_FindObjects),
        C_FindObjectsFinal: Some(crate::api::C_FindObjectsFinal),

        C_EncryptInit: Some(crate::api::C_EncryptInit),
        C_Encrypt: Some(crate::api::C_Encrypt),
        C_EncryptUpdate: Some(crate::api::C_EncryptUpdate),
        C_EncryptFinal: Some(crate::api::C_EncryptFinal),

        C_DecryptInit: Some(crate::api::C_DecryptInit),
        C_Decrypt: Some(crate::api::C_Decrypt),
        C_DecryptUpdate: Some(crate::api::C_DecryptUpdate),
        C_DecryptFinal: Some(crate::api::C_DecryptFinal),

        C_DigestInit: Some(crate::api::C_DigestInit),
        C_Digest: Some(crate::api::C_Digest),
        C_DigestUpdate: Some(crate::api::C_DigestUpdate),
        C_DigestKey: Some(crate::api::C_DigestKey),
        C_DigestFinal: Some(crate::api::C_DigestFinal),

        C_SignInit: Some(crate::api::C_SignInit),
        C_Sign: Some(crate::api::C_Sign),
        C_SignUpdate: Some(crate::api::C_SignUpdate),
        C_SignFinal: Some(crate::api::C_SignFinal),
        C_SignRecoverInit: Some(crate::api::C_SignRecoverInit),
        C_SignRecover: Some(crate::api::C_SignRecover),

        C_VerifyInit: Some(crate::api::C_VerifyInit),
        C_Verify: Some(crate::api::C_Verify),
        C_VerifyUpdate: Some(crate::api::C_VerifyUpdate),
        C_VerifyFinal: Some(crate::api::C_VerifyFinal),
        C_VerifyRecoverInit: Some(crate::api::C_VerifyRecoverInit),
        C_VerifyRecover: Some(crate::api::C_VerifyRecover),

        C_DigestEncryptUpdate: Some(crate::api::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(crate::api::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(crate::api::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(crate::api::C_DecryptVerifyUpdate),

        C_GenerateKey: Some(crate::api::C_GenerateKey),
        C_GenerateKeyPair: Some(crate::api::C_GenerateKeyPair),

        C_WrapKey: Some(crate::api::C_WrapKey),
        C_UnwrapKey: Some(crate::api::C_UnwrapKey),
        C_DeriveKey: Some(crate::api::C_DeriveKey),

        C_SeedRandom: Some(crate::api::C_SeedRandom),
        C_GenerateRandom: Some(crate::api::C_GenerateRandom),

        C_GetFunctionStatus: Some(crate::api::C_GetFunctionStatus),
        C_CancelFunction: Some(crate::api::C_CancelFunction),
        C_WaitForSlotEvent: Some(crate::api::C_WaitForSlotEvent),
    }
}

const fn function_list_3_0(version: CK_VERSION) -> CK_FUNCTION_LIST_3_0 {
    CK_FUNCTION_LIST_3_0 {
        version,

        C_Initialize: Some(crate::api::C_Initialize),
        C_Finalize: Some(crate::api::C_Finalize),
        C_GetInfo: Some(crate::api::C_GetInfo),
        C_GetFunctionList: Some(crate::api::C_GetFunctionList),

        C_GetSlotList: Some(crate::api::C_GetSlotList),
        C_GetSlotInfo: Some(crate::api::C_GetSlotInfo),
        C_GetTokenInfo: Some(crate::api::C_GetTokenInfo),

        C_GetMechanismList: Some(crate::mechanism::C_GetMechanismList),
        C_GetMechanismInfo: Some(crate::mechanism::C_GetMechanismInfo),

        C_InitToken: Some(crate::api::C_InitToken),
        C_InitPIN: Some(crate::api::C_InitPIN),
        C_SetPIN: Some(crate::api::C_SetPIN),

        C_OpenSession: Some(crate::api::C_OpenSession),
        C_CloseSession: Some(crate::api::C_CloseSession),
        C_CloseAllSessions: Some(crate::api::C_CloseAllSessions),
        C_GetSessionInfo: Some(crate::api::C_GetSessionInfo),

        C_GetOperationState: Some(crate::api::C_GetOperationState),
        C_SetOperationState: Some(crate::api::C_SetOperationState),

        C_Login: Some(crate::api::C_Login),
        C_Logout: Some(crate::api::C_Logout),

        C_CreateObject: Some(crate::api::C_CreateObject),
        C_CopyObject: Some(crate::api::C_CopyObject),
        C_DestroyObject: Some(crate::api::C_DestroyObject),
        C_GetObjectSize: Some(crate::api::C_GetObjectSize),

        C_GetAttributeValue: Some(crate::api::C_GetAttributeValue),
        C_SetAttributeValue: Some(crate::api::C_SetAttributeValue),

        C_FindObjectsInit: Some(crate::api::C_FindObjectsInit),
        C_FindObjects: Some(crate::api::C_FindObjects),
        C_FindObjectsFinal: Some(crate::api::C_FindObjectsFinal),

        C_EncryptInit: Some(crate::api::C_EncryptInit),
        C_Encrypt: Some(crate::api::C_Encrypt),
        C_EncryptUpdate: Some(crate::api::C_EncryptUpdate),
        C_EncryptFinal: Some(crate::api::C_EncryptFinal),

        C_DecryptInit: Some(crate::api::C_DecryptInit),
        C_Decrypt: Some(crate::api::C_Decrypt),
        C_DecryptUpdate: Some(crate::api::C_DecryptUpdate),
        C_DecryptFinal: Some(crate::api::C_DecryptFinal),

        C_DigestInit: Some(crate::api::C_DigestInit),
        C_Digest: Some(crate::api::C_Digest),
        C_DigestUpdate: Some(crate::api::C_DigestUpdate),
        C_DigestKey: Some(crate::api::C_DigestKey),
        C_DigestFinal: Some(crate::api::C_DigestFinal),

        C_SignInit: Some(crate::api::C_SignInit),
        C_Sign: Some(crate::api::C_Sign),
        C_SignUpdate: Some(crate::api::C_SignUpdate),
        C_SignFinal: Some(crate::api::C_SignFinal),
        C_SignRecoverInit: Some(crate::api::C_SignRecoverInit),
        C_SignRecover: Some(crate::api::C_SignRecover),

        C_VerifyInit: Some(crate::api::C_VerifyInit),
        C_Verify: Some(crate::api::C_Verify),
        C_VerifyUpdate: Some(crate::api::C_VerifyUpdate),
        C_VerifyFinal: Some(crate::api::C_VerifyFinal),
        C_VerifyRecoverInit: Some(crate::api::C_VerifyRecoverInit),
        C_VerifyRecover: Some(crate::api::C_VerifyRecover),

        C_DigestEncryptUpdate: Some(crate::api::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(crate::api::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(crate::api::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(crate::api::C_DecryptVerifyUpdate),

        C_GenerateKey: Some(crate::api::C_GenerateKey),
        C_GenerateKeyPair: Some(crate::api::C_GenerateKeyPair),

        C_WrapKey: Some(crate::api::C_WrapKey),
        C_UnwrapKey: Some(crate::api::C_UnwrapKey),
        C_DeriveKey: Some(crate::api::C_DeriveKey),

        C_SeedRandom: Some(crate::api::C_SeedRandom),
        C_GenerateRandom: Some(crate::api::C_GenerateRandom),

        C_GetFunctionStatus: Some(crate::api::C_GetFunctionStatus),
        C_CancelFunction: Some(crate::api::C_CancelFunction),
        C_WaitForSlotEvent: Some(crate::api::C_WaitForSlotEvent),

        C_GetInterfaceList: Some(crate::api::C_GetInterfaceList),
        C_GetInterface: Some(crate::api::C_GetInterface),
        C_LoginUser: Some(crate::api::C_LoginUser),
        C_SessionCancel: Some(crate::api::C_SessionCancel),

        C_MessageEncryptInit: Some(crate::api::C_MessageEncryptInit),
        C_EncryptMessage: Some(crate::api::C_EncryptMessage),
        C_EncryptMessageBegin: Some(crate::api::C_EncryptMessageBegin),
        C_EncryptMessageNext: Some(crate::api::C_EncryptMessageNext),
        C_MessageEncryptFinal: Some(crate::api::C_MessageEncryptFinal),

        C_MessageDecryptInit: Some(crate::api::C_MessageDecryptInit),
        C_DecryptMessage: Some(crate::api::C_DecryptMessage),
        C_DecryptMessageBegin: Some(crate::api::C_DecryptMessageBegin),
        C_DecryptMessageNext: Some(crate::api::C_DecryptMessageNext),
        C_MessageDecryptFinal: Some(crate::api::C_MessageDecryptFinal),

        C_MessageSignInit: Some(crate::api::C_MessageSignInit),
        C_SignMessage: Some(crate::api::C_SignMessage),
        C_SignMessageBegin: Some(crate::api::C_SignMessageBegin),
        C_SignMessageNext: Some(crate::api::C_SignMessageNext),
        C_MessageSignFinal: Some(crate::api::C_MessageSignFinal),

        C_MessageVerifyInit: Some(crate::api::C_MessageVerifyInit),
        C_VerifyMessage: Some(crate::api::C_VerifyMessage),
        C_VerifyMessageBegin: Some(crate::api::C_VerifyMessageBegin),
        C_VerifyMessageNext: Some(crate::api::C_VerifyMessageNext),
        C_MessageVerifyFinal: Some(crate::api::C_MessageVerifyFinal),
    }
}

const fn function_list_3_2(version: CK_VERSION) -> CK_FUNCTION_LIST_3_2 {
    CK_FUNCTION_LIST_3_2 {
        version,

        C_Initialize: Some(crate::api::C_Initialize),
        C_Finalize: Some(crate::api::C_Finalize),
        C_GetInfo: Some(crate::api::C_GetInfo),
        C_GetFunctionList: Some(crate::api::C_GetFunctionList),

        C_GetSlotList: Some(crate::api::C_GetSlotList),
        C_GetSlotInfo: Some(crate::api::C_GetSlotInfo),
        C_GetTokenInfo: Some(crate::api::C_GetTokenInfo),

        C_GetMechanismList: Some(crate::mechanism::C_GetMechanismList),
        C_GetMechanismInfo: Some(crate::mechanism::C_GetMechanismInfo),

        C_InitToken: Some(crate::api::C_InitToken),
        C_InitPIN: Some(crate::api::C_InitPIN),
        C_SetPIN: Some(crate::api::C_SetPIN),

        C_OpenSession: Some(crate::api::C_OpenSession),
        C_CloseSession: Some(crate::api::C_CloseSession),
        C_CloseAllSessions: Some(crate::api::C_CloseAllSessions),
        C_GetSessionInfo: Some(crate::api::C_GetSessionInfo),

        C_GetOperationState: Some(crate::api::C_GetOperationState),
        C_SetOperationState: Some(crate::api::C_SetOperationState),

        C_Login: Some(crate::api::C_Login),
        C_Logout: Some(crate::api::C_Logout),

        C_CreateObject: Some(crate::api::C_CreateObject),
        C_CopyObject: Some(crate::api::C_CopyObject),
        C_DestroyObject: Some(crate::api::C_DestroyObject),
        C_GetObjectSize: Some(crate::api::C_GetObjectSize),

        C_GetAttributeValue: Some(crate::api::C_GetAttributeValue),
        C_SetAttributeValue: Some(crate::api::C_SetAttributeValue),

        C_FindObjectsInit: Some(crate::api::C_FindObjectsInit),
        C_FindObjects: Some(crate::api::C_FindObjects),
        C_FindObjectsFinal: Some(crate::api::C_FindObjectsFinal),

        C_EncryptInit: Some(crate::api::C_EncryptInit),
        C_Encrypt: Some(crate::api::C_Encrypt),
        C_EncryptUpdate: Some(crate::api::C_EncryptUpdate),
        C_EncryptFinal: Some(crate::api::C_EncryptFinal),

        C_DecryptInit: Some(crate::api::C_DecryptInit),
        C_Decrypt: Some(crate::api::C_Decrypt),
        C_DecryptUpdate: Some(crate::api::C_DecryptUpdate),
        C_DecryptFinal: Some(crate::api::C_DecryptFinal),

        C_DigestInit: Some(crate::api::C_DigestInit),
        C_Digest: Some(crate::api::C_Digest),
        C_DigestUpdate: Some(crate::api::C_DigestUpdate),
        C_DigestKey: Some(crate::api::C_DigestKey),
        C_DigestFinal: Some(crate::api::C_DigestFinal),

        C_SignInit: Some(crate::api::C_SignInit),
        C_Sign: Some(crate::api::C_Sign),
        C_SignUpdate: Some(crate::api::C_SignUpdate),
        C_SignFinal: Some(crate::api::C_SignFinal),
        C_SignRecoverInit: Some(crate::api::C_SignRecoverInit),
        C_SignRecover: Some(crate::api::C_SignRecover),

        C_VerifyInit: Some(crate::api::C_VerifyInit),
        C_Verify: Some(crate::api::C_Verify),
        C_VerifyUpdate: Some(crate::api::C_VerifyUpdate),
        C_VerifyFinal: Some(crate::api::C_VerifyFinal),
        C_VerifyRecoverInit: Some(crate::api::C_VerifyRecoverInit),
        C_VerifyRecover: Some(crate::api::C_VerifyRecover),

        C_DigestEncryptUpdate: Some(crate::api::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(crate::api::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(crate::api::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(crate::api::C_DecryptVerifyUpdate),

        C_GenerateKey: Some(crate::api::C_GenerateKey),
        C_GenerateKeyPair: Some(crate::api::C_GenerateKeyPair),

        C_WrapKey: Some(crate::api::C_WrapKey),
        C_UnwrapKey: Some(crate::api::C_UnwrapKey),
        C_DeriveKey: Some(crate::api::C_DeriveKey),

        C_SeedRandom: Some(crate::api::C_SeedRandom),
        C_GenerateRandom: Some(crate::api::C_GenerateRandom),

        C_GetFunctionStatus: Some(crate::api::C_GetFunctionStatus),
        C_CancelFunction: Some(crate::api::C_CancelFunction),
        C_WaitForSlotEvent: Some(crate::api::C_WaitForSlotEvent),

        C_GetInterfaceList: Some(crate::api::C_GetInterfaceList),
        C_GetInterface: Some(crate::api::C_GetInterface),
        C_LoginUser: Some(crate::api::C_LoginUser),
        C_SessionCancel: Some(crate::api::C_SessionCancel),

        C_MessageEncryptInit: Some(crate::api::C_MessageEncryptInit),
        C_EncryptMessage: Some(crate::api::C_EncryptMessage),
        C_EncryptMessageBegin: Some(crate::api::C_EncryptMessageBegin),
        C_EncryptMessageNext: Some(crate::api::C_EncryptMessageNext),
        C_MessageEncryptFinal: Some(crate::api::C_MessageEncryptFinal),

        C_MessageDecryptInit: Some(crate::api::C_MessageDecryptInit),
        C_DecryptMessage: Some(crate::api::C_DecryptMessage),
        C_DecryptMessageBegin: Some(crate::api::C_DecryptMessageBegin),
        C_DecryptMessageNext: Some(crate::api::C_DecryptMessageNext),
        C_MessageDecryptFinal: Some(crate::api::C_MessageDecryptFinal),

        C_MessageSignInit: Some(crate::api::C_MessageSignInit),
        C_SignMessage: Some(crate::api::C_SignMessage),
        C_SignMessageBegin: Some(crate::api::C_SignMessageBegin),
        C_SignMessageNext: Some(crate::api::C_SignMessageNext),
        C_MessageSignFinal: Some(crate::api::C_MessageSignFinal),

        C_MessageVerifyInit: Some(crate::api::C_MessageVerifyInit),
        C_VerifyMessage: Some(crate::api::C_VerifyMessage),
        C_VerifyMessageBegin: Some(crate::api::C_VerifyMessageBegin),
        C_VerifyMessageNext: Some(crate::api::C_VerifyMessageNext),
        C_MessageVerifyFinal: Some(crate::api::C_MessageVerifyFinal),

        C_EncapsulateKey: Some(crate::api::C_EncapsulateKey),
        C_DecapsulateKey: Some(crate::api::C_DecapsulateKey),
        C_VerifySignatureInit: Some(crate::api::C_VerifySignatureInit),
        C_VerifySignature: Some(crate::api::C_VerifySignature),
        C_VerifySignatureUpdate: Some(crate::api::C_VerifySignatureUpdate),
        C_VerifySignatureFinal: Some(crate::api::C_VerifySignatureFinal),
        C_GetSessionValidationFlags: Some(crate::api::C_GetSessionValidationFlags),
        C_AsyncComplete: Some(crate::api::C_AsyncComplete),
        C_AsyncGetID: Some(crate::api::C_AsyncGetID),
        C_AsyncJoin: Some(crate::api::C_AsyncJoin),
        C_WrapKeyAuthenticated: Some(crate::api::C_WrapKeyAuthenticated),
        C_UnwrapKeyAuthenticated: Some(crate::api::C_UnwrapKeyAuthenticated),
    }
}

pub(super) static G_FUNCTION_LIST: CK_FUNCTION_LIST = function_list_2_40(CK_VERSION {
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

static G_INTERFACE_2_40: StaticInterface = StaticInterface(CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut ::std::os::raw::c_void,
    flags: 0,
});

static G_INTERFACE_3_0: StaticInterface = StaticInterface(CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_0 as *const CK_FUNCTION_LIST_3_0
        as *mut ::std::os::raw::c_void,
    flags: 0,
});

static G_INTERFACE_3_1: StaticInterface = StaticInterface(CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_1 as *const CK_FUNCTION_LIST_3_0
        as *mut ::std::os::raw::c_void,
    flags: 0,
});

static G_INTERFACE_3_2: StaticInterface = StaticInterface(CK_INTERFACE {
    pInterfaceName: c"PKCS 11".as_ptr() as *mut CK_UTF8CHAR,
    pFunctionList: &G_FUNCTION_LIST_3_2 as *const CK_FUNCTION_LIST_3_2
        as *mut ::std::os::raw::c_void,
    flags: 0,
});
