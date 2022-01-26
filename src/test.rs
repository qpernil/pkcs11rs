#[test]
fn bindgen_test_layout__CK_INFO() {
    assert_eq!(
        ::std::mem::size_of::<_CK_INFO>(),
        88usize,
        concat!("Size of: ", stringify!(_CK_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_INFO))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_INFO>())).cryptokiVersion as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_INFO),
            "::",
            stringify!(cryptokiVersion)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_INFO>())).manufacturerID as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_INFO>())).flags as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_INFO>())).libraryDescription as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_INFO),
            "::",
            stringify!(libraryDescription)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_INFO>())).libraryVersion as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_INFO),
            "::",
            stringify!(libraryVersion)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_SLOT_INFO() {
    assert_eq!(
        ::std::mem::size_of::<_CK_SLOT_INFO>(),
        112usize,
        concat!("Size of: ", stringify!(_CK_SLOT_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_SLOT_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_SLOT_INFO))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SLOT_INFO>())).slotDescription as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SLOT_INFO),
            "::",
            stringify!(slotDescription)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SLOT_INFO>())).manufacturerID as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SLOT_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SLOT_INFO>())).flags as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SLOT_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SLOT_INFO>())).hardwareVersion as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SLOT_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SLOT_INFO>())).firmwareVersion as *const _ as usize },
        106usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SLOT_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_TOKEN_INFO() {
    assert_eq!(
        ::std::mem::size_of::<_CK_TOKEN_INFO>(),
        208usize,
        concat!("Size of: ", stringify!(_CK_TOKEN_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_TOKEN_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_TOKEN_INFO))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).label as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(label)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).manufacturerID as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).model as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(model)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).serialNumber as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(serialNumber)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).flags as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulMaxSessionCount as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxSessionCount)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulSessionCount as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulSessionCount)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulMaxRwSessionCount as *const _ as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxRwSessionCount)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulRwSessionCount as *const _ as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulRwSessionCount)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulMaxPinLen as *const _ as usize },
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxPinLen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulMinPinLen as *const _ as usize },
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulMinPinLen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulTotalPublicMemory as *const _ as usize },
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPublicMemory)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulFreePublicMemory as *const _ as usize },
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePublicMemory)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulTotalPrivateMemory as *const _ as usize },
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPrivateMemory)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).ulFreePrivateMemory as *const _ as usize },
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePrivateMemory)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).hardwareVersion as *const _ as usize },
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).firmwareVersion as *const _ as usize },
        186usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_TOKEN_INFO>())).utcTime as *const _ as usize },
        188usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_TOKEN_INFO),
            "::",
            stringify!(utcTime)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_SESSION_INFO() {
    assert_eq!(
        ::std::mem::size_of::<_CK_SESSION_INFO>(),
        32usize,
        concat!("Size of: ", stringify!(_CK_SESSION_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_SESSION_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_SESSION_INFO))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SESSION_INFO>())).slotID as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SESSION_INFO),
            "::",
            stringify!(slotID)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SESSION_INFO>())).state as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SESSION_INFO),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SESSION_INFO>())).flags as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SESSION_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_SESSION_INFO>())).ulDeviceError as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_SESSION_INFO),
            "::",
            stringify!(ulDeviceError)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_ATTRIBUTE() {
    assert_eq!(
        ::std::mem::size_of::<_CK_ATTRIBUTE>(),
        24usize,
        concat!("Size of: ", stringify!(_CK_ATTRIBUTE))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_ATTRIBUTE>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_ATTRIBUTE))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_ATTRIBUTE>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_ATTRIBUTE),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_ATTRIBUTE>())).pValue as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_ATTRIBUTE),
            "::",
            stringify!(pValue)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_ATTRIBUTE>())).ulValueLen as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_ATTRIBUTE),
            "::",
            stringify!(ulValueLen)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_DATE() {
    assert_eq!(
        ::std::mem::size_of::<_CK_DATE>(),
        8usize,
        concat!("Size of: ", stringify!(_CK_DATE))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_DATE>(),
        1usize,
        concat!("Alignment of ", stringify!(_CK_DATE))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_DATE>())).year as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_DATE),
            "::",
            stringify!(year)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_DATE>())).month as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_DATE),
            "::",
            stringify!(month)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_DATE>())).day as *const _ as usize },
        6usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_DATE),
            "::",
            stringify!(day)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_MECHANISM() {
    assert_eq!(
        ::std::mem::size_of::<_CK_MECHANISM>(),
        24usize,
        concat!("Size of: ", stringify!(_CK_MECHANISM))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_MECHANISM>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_MECHANISM))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM>())).mechanism as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM),
            "::",
            stringify!(mechanism)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM>())).pParameter as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM),
            "::",
            stringify!(pParameter)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM>())).ulParameterLen as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM),
            "::",
            stringify!(ulParameterLen)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_MECHANISM_INFO() {
    assert_eq!(
        ::std::mem::size_of::<_CK_MECHANISM_INFO>(),
        24usize,
        concat!("Size of: ", stringify!(_CK_MECHANISM_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_MECHANISM_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_MECHANISM_INFO))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM_INFO>())).ulMinKeySize as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM_INFO),
            "::",
            stringify!(ulMinKeySize)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM_INFO>())).ulMaxKeySize as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM_INFO),
            "::",
            stringify!(ulMaxKeySize)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_MECHANISM_INFO>())).flags as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_MECHANISM_INFO),
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
        unsafe { &(*(::std::ptr::null::<CK_ECDH1_DERIVE_PARAMS>())).kdf as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(kdf)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<CK_ECDH1_DERIVE_PARAMS>())).ulSharedDataLen as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulSharedDataLen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_ECDH1_DERIVE_PARAMS>())).pSharedData as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(pSharedData)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<CK_ECDH1_DERIVE_PARAMS>())).ulPublicDataLen as *const _ as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulPublicDataLen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_ECDH1_DERIVE_PARAMS>())).pPublicData as *const _ as usize },
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
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_OAEP_PARAMS>())).hashAlg as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_OAEP_PARAMS>())).mgf as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_OAEP_PARAMS>())).source as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(source)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_OAEP_PARAMS>())).pSourceData as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(pSourceData)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<CK_RSA_PKCS_OAEP_PARAMS>())).ulSourceDataLen as *const _ as usize
        },
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
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_PSS_PARAMS>())).hashAlg as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_PSS_PARAMS>())).mgf as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<CK_RSA_PKCS_PSS_PARAMS>())).sLen as *const _ as usize },
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
fn bindgen_test_layout__CK_VERSION() {
    assert_eq!(
        ::std::mem::size_of::<_CK_VERSION>(),
        2usize,
        concat!("Size of: ", stringify!(_CK_VERSION))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_VERSION>(),
        1usize,
        concat!("Alignment of ", stringify!(_CK_VERSION))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_VERSION>())).major as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_VERSION),
            "::",
            stringify!(major)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_VERSION>())).minor as *const _ as usize },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_VERSION),
            "::",
            stringify!(minor)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_C_INITIALIZE_ARGS() {
    assert_eq!(
        ::std::mem::size_of::<_CK_C_INITIALIZE_ARGS>(),
        48usize,
        concat!("Size of: ", stringify!(_CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_C_INITIALIZE_ARGS>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).pfnCreateMutex as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pfnCreateMutex)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).pfnDestroyMutex as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pfnDestroyMutex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).pfnLockMutex as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pfnLockMutex)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).pfnUnlockMutex as *const _ as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pfnUnlockMutex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).flags as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_C_INITIALIZE_ARGS>())).pReserved as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pReserved)
        )
    );
}
#[test]
fn bindgen_test_layout__CK_FUNCTION_LIST() {
    assert_eq!(
        ::std::mem::size_of::<_CK_FUNCTION_LIST>(),
        552usize,
        concat!("Size of: ", stringify!(_CK_FUNCTION_LIST))
    );
    assert_eq!(
        ::std::mem::align_of::<_CK_FUNCTION_LIST>(),
        8usize,
        concat!("Alignment of ", stringify!(_CK_FUNCTION_LIST))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).version as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Initialize as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Initialize)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Finalize as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Finalize)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetInfo as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetInfo)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetFunctionList as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionList)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetSlotList as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotList)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetSlotInfo as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotInfo)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetTokenInfo as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetTokenInfo)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetMechanismList as *const _ as usize
        },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismList)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetMechanismInfo as *const _ as usize
        },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismInfo)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_InitToken as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitToken)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_InitPIN as *const _ as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitPIN)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SetPIN as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetPIN)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_OpenSession as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_OpenSession)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_CloseSession as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseSession)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_CloseAllSessions as *const _ as usize
        },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseAllSessions)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetSessionInfo as *const _ as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSessionInfo)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetOperationState as *const _ as usize
        },
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetOperationState)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SetOperationState as *const _ as usize
        },
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetOperationState)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Login as *const _ as usize },
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Login)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Logout as *const _ as usize },
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Logout)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_CreateObject as *const _ as usize },
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_CreateObject)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_CopyObject as *const _ as usize },
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_CopyObject)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DestroyObject as *const _ as usize },
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DestroyObject)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetObjectSize as *const _ as usize },
        192usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetObjectSize)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetAttributeValue as *const _ as usize
        },
        200usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetAttributeValue)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SetAttributeValue as *const _ as usize
        },
        208usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetAttributeValue)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_FindObjectsInit as *const _ as usize },
        216usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_FindObjects as *const _ as usize },
        224usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjects)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_FindObjectsFinal as *const _ as usize
        },
        232usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsFinal)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_EncryptInit as *const _ as usize },
        240usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Encrypt as *const _ as usize },
        248usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Encrypt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_EncryptUpdate as *const _ as usize },
        256usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_EncryptFinal as *const _ as usize },
        264usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptFinal)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DecryptInit as *const _ as usize },
        272usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Decrypt as *const _ as usize },
        280usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Decrypt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DecryptUpdate as *const _ as usize },
        288usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DecryptFinal as *const _ as usize },
        296usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptFinal)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DigestInit as *const _ as usize },
        304usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Digest as *const _ as usize },
        312usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Digest)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DigestUpdate as *const _ as usize },
        320usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DigestKey as *const _ as usize },
        328usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestKey)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DigestFinal as *const _ as usize },
        336usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestFinal)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignInit as *const _ as usize },
        344usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Sign as *const _ as usize },
        352usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Sign)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignUpdate as *const _ as usize },
        360usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignFinal as *const _ as usize },
        368usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignFinal)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignRecoverInit as *const _ as usize },
        376usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecoverInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignRecover as *const _ as usize },
        384usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecover)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_VerifyInit as *const _ as usize },
        392usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_Verify as *const _ as usize },
        400usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_Verify)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_VerifyUpdate as *const _ as usize },
        408usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_VerifyFinal as *const _ as usize },
        416usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyFinal)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_VerifyRecoverInit as *const _ as usize
        },
        424usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecoverInit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_VerifyRecover as *const _ as usize },
        432usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecover)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DigestEncryptUpdate as *const _ as usize
        },
        440usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestEncryptUpdate)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DecryptDigestUpdate as *const _ as usize
        },
        448usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptDigestUpdate)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SignEncryptUpdate as *const _ as usize
        },
        456usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignEncryptUpdate)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DecryptVerifyUpdate as *const _ as usize
        },
        464usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptVerifyUpdate)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GenerateKey as *const _ as usize },
        472usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKey)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GenerateKeyPair as *const _ as usize },
        480usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKeyPair)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_WrapKey as *const _ as usize },
        488usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_WrapKey)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_UnwrapKey as *const _ as usize },
        496usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_UnwrapKey)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_DeriveKey as *const _ as usize },
        504usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_DeriveKey)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_SeedRandom as *const _ as usize },
        512usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_SeedRandom)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GenerateRandom as *const _ as usize },
        520usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateRandom)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_GetFunctionStatus as *const _ as usize
        },
        528usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionStatus)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_CancelFunction as *const _ as usize },
        536usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_CancelFunction)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_CK_FUNCTION_LIST>())).C_WaitForSlotEvent as *const _ as usize
        },
        544usize,
        concat!(
            "Offset of field: ",
            stringify!(_CK_FUNCTION_LIST),
            "::",
            stringify!(C_WaitForSlotEvent)
        )
    );
}
