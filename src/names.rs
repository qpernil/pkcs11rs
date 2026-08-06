use crate::pkcs11::*;
use crate::{
    CKA_PKCS11RS_FIDO_RP_ID, CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
    CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION, CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
    CKK_YUBICO_AES128_CCM_WRAP, CKK_YUBICO_AES192_CCM_WRAP, CKK_YUBICO_AES256_CCM_WRAP,
};
use std::ffi::{c_char, CStr};

macro_rules! constant_name {
    ($value:expr, $type:ty; $($constant:ident),+ $(,)?) => {
        match $value {
            $(candidate if candidate == $constant as $type => {
                // Each input is a Rust identifier, so its stringified form
                // cannot contain an interior NUL. concat! appends the only NUL.
                Some(unsafe {
                    CStr::from_bytes_with_nul_unchecked(
                        concat!(stringify!($constant), "\0").as_bytes()
                    )
                })
            })+
            _ => None,
        }
    };
}

fn return_value_name(value: CK_RV) -> Option<&'static CStr> {
    constant_name!(value, CK_RV;
        CKR_OK,
        CKR_CANCEL,
        CKR_HOST_MEMORY,
        CKR_SLOT_ID_INVALID,
        CKR_GENERAL_ERROR,
        CKR_FUNCTION_FAILED,
        CKR_ARGUMENTS_BAD,
        CKR_NO_EVENT,
        CKR_NEED_TO_CREATE_THREADS,
        CKR_CANT_LOCK,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_ACTION_PROHIBITED,
        CKR_DATA_INVALID,
        CKR_DATA_LEN_RANGE,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_MEMORY,
        CKR_DEVICE_REMOVED,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE,
        CKR_AEAD_DECRYPT_FAILED,
        CKR_FUNCTION_CANCELED,
        CKR_FUNCTION_NOT_PARALLEL,
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_KEY_HANDLE_INVALID,
        CKR_KEY_SIZE_RANGE,
        CKR_KEY_TYPE_INCONSISTENT,
        CKR_KEY_NOT_NEEDED,
        CKR_KEY_CHANGED,
        CKR_KEY_NEEDED,
        CKR_KEY_INDIGESTIBLE,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE,
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_OBJECT_HANDLE_INVALID,
        CKR_OPERATION_ACTIVE,
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_PIN_INCORRECT,
        CKR_PIN_INVALID,
        CKR_PIN_LEN_RANGE,
        CKR_PIN_EXPIRED,
        CKR_PIN_LOCKED,
        CKR_SESSION_CLOSED,
        CKR_SESSION_COUNT,
        CKR_SESSION_HANDLE_INVALID,
        CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        CKR_SESSION_READ_ONLY,
        CKR_SESSION_EXISTS,
        CKR_SESSION_READ_ONLY_EXISTS,
        CKR_SESSION_READ_WRITE_SO_EXISTS,
        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_TOKEN_NOT_PRESENT,
        CKR_TOKEN_NOT_RECOGNIZED,
        CKR_TOKEN_NOT_INITIALIZED,
        CKR_TOKEN_WRITE_PROTECTED,
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        CKR_UNWRAPPING_KEY_SIZE_RANGE,
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_USER_ALREADY_LOGGED_IN,
        CKR_USER_NOT_LOGGED_IN,
        CKR_USER_PIN_NOT_INITIALIZED,
        CKR_USER_TYPE_INVALID,
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        CKR_USER_TOO_MANY_TYPES,
        CKR_WRAPPED_KEY_INVALID,
        CKR_WRAPPED_KEY_LEN_RANGE,
        CKR_WRAPPING_KEY_HANDLE_INVALID,
        CKR_WRAPPING_KEY_SIZE_RANGE,
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_RANDOM_SEED_NOT_SUPPORTED,
        CKR_RANDOM_NO_RNG,
        CKR_DOMAIN_PARAMS_INVALID,
        CKR_CURVE_NOT_SUPPORTED,
        CKR_BUFFER_TOO_SMALL,
        CKR_SAVED_STATE_INVALID,
        CKR_INFORMATION_SENSITIVE,
        CKR_STATE_UNSAVEABLE,
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_MUTEX_BAD,
        CKR_MUTEX_NOT_LOCKED,
        CKR_NEW_PIN_MODE,
        CKR_NEXT_OTP,
        CKR_EXCEEDED_MAX_ITERATIONS,
        CKR_FIPS_SELF_TEST_FAILED,
        CKR_LIBRARY_LOAD_FAILED,
        CKR_PIN_TOO_WEAK,
        CKR_PUBLIC_KEY_INVALID,
        CKR_FUNCTION_REJECTED,
        CKR_TOKEN_RESOURCE_EXCEEDED,
        CKR_OPERATION_CANCEL_FAILED,
        CKR_KEY_EXHAUSTED,
        CKR_OPERATION_NOT_VALIDATED,
        CKR_SESSION_ASYNC_NOT_SUPPORTED,
        CKR_PENDING,
        CKR_PARAMETER_SET_NOT_SUPPORTED,
        CKR_SEED_RANDOM_REQUIRED,
        CKR_VENDOR_DEFINED,
    )
}

fn object_class_name(value: CK_OBJECT_CLASS) -> Option<&'static CStr> {
    constant_name!(value, CK_OBJECT_CLASS;
        CKO_DATA,
        CKO_CERTIFICATE,
        CKO_PUBLIC_KEY,
        CKO_PRIVATE_KEY,
        CKO_SECRET_KEY,
        CKO_HW_FEATURE,
        CKO_DOMAIN_PARAMETERS,
        CKO_MECHANISM,
        CKO_OTP_KEY,
        CKO_PROFILE,
        CKO_VALIDATION,
        CKO_TRUST,
        CKO_VENDOR_DEFINED,
    )
}

fn key_type_name(value: CK_KEY_TYPE) -> Option<&'static CStr> {
    constant_name!(value, CK_KEY_TYPE;
        CKK_RSA,
        CKK_DSA,
        CKK_DH,
        CKK_EC,
        CKK_X9_42_DH,
        CKK_KEA,
        CKK_GENERIC_SECRET,
        CKK_RC2,
        CKK_RC4,
        CKK_DES,
        CKK_DES2,
        CKK_DES3,
        CKK_CAST,
        CKK_CAST3,
        CKK_CAST128,
        CKK_RC5,
        CKK_IDEA,
        CKK_SKIPJACK,
        CKK_BATON,
        CKK_JUNIPER,
        CKK_CDMF,
        CKK_AES,
        CKK_BLOWFISH,
        CKK_TWOFISH,
        CKK_SECURID,
        CKK_HOTP,
        CKK_ACTI,
        CKK_CAMELLIA,
        CKK_ARIA,
        CKK_MD5_HMAC,
        CKK_SHA_1_HMAC,
        CKK_RIPEMD128_HMAC,
        CKK_RIPEMD160_HMAC,
        CKK_SHA256_HMAC,
        CKK_SHA384_HMAC,
        CKK_SHA512_HMAC,
        CKK_SHA224_HMAC,
        CKK_SEED,
        CKK_GOSTR3410,
        CKK_GOSTR3411,
        CKK_GOST28147,
        CKK_CHACHA20,
        CKK_POLY1305,
        CKK_AES_XTS,
        CKK_SHA3_224_HMAC,
        CKK_SHA3_256_HMAC,
        CKK_SHA3_384_HMAC,
        CKK_SHA3_512_HMAC,
        CKK_BLAKE2B_160_HMAC,
        CKK_BLAKE2B_256_HMAC,
        CKK_BLAKE2B_384_HMAC,
        CKK_BLAKE2B_512_HMAC,
        CKK_SALSA20,
        CKK_X2RATCHET,
        CKK_EC_EDWARDS,
        CKK_EC_MONTGOMERY,
        CKK_HKDF,
        CKK_SHA512_224_HMAC,
        CKK_SHA512_256_HMAC,
        CKK_SHA512_T_HMAC,
        CKK_HSS,
        CKK_XMSS,
        CKK_XMSSMT,
        CKK_ML_KEM,
        CKK_ML_DSA,
        CKK_SLH_DSA,
        CKK_YUBICO_AES128_CCM_WRAP,
        CKK_YUBICO_AES192_CCM_WRAP,
        CKK_YUBICO_AES256_CCM_WRAP,
        CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        CKK_VENDOR_DEFINED,
    )
}

fn attribute_type_name(value: CK_ATTRIBUTE_TYPE) -> Option<&'static CStr> {
    constant_name!(value, CK_ATTRIBUTE_TYPE;
        CKA_CLASS,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_LABEL,
        CKA_UNIQUE_ID,
        CKA_APPLICATION,
        CKA_VALUE,
        CKA_OBJECT_ID,
        CKA_CERTIFICATE_TYPE,
        CKA_ISSUER,
        CKA_SERIAL_NUMBER,
        CKA_AC_ISSUER,
        CKA_OWNER,
        CKA_ATTR_TYPES,
        CKA_TRUSTED,
        CKA_CERTIFICATE_CATEGORY,
        CKA_JAVA_MIDP_SECURITY_DOMAIN,
        CKA_URL,
        CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
        CKA_HASH_OF_ISSUER_PUBLIC_KEY,
        CKA_NAME_HASH_ALGORITHM,
        CKA_CHECK_VALUE,
        CKA_KEY_TYPE,
        CKA_SUBJECT,
        CKA_ID,
        CKA_SENSITIVE,
        CKA_ENCRYPT,
        CKA_DECRYPT,
        CKA_WRAP,
        CKA_UNWRAP,
        CKA_SIGN,
        CKA_SIGN_RECOVER,
        CKA_VERIFY,
        CKA_VERIFY_RECOVER,
        CKA_DERIVE,
        CKA_START_DATE,
        CKA_END_DATE,
        CKA_MODULUS,
        CKA_MODULUS_BITS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT,
        CKA_PUBLIC_KEY_INFO,
        CKA_PRIME,
        CKA_SUBPRIME,
        CKA_BASE,
        CKA_PRIME_BITS,
        CKA_SUBPRIME_BITS,
        CKA_VALUE_BITS,
        CKA_VALUE_LEN,
        CKA_EXTRACTABLE,
        CKA_LOCAL,
        CKA_NEVER_EXTRACTABLE,
        CKA_ALWAYS_SENSITIVE,
        CKA_KEY_GEN_MECHANISM,
        CKA_MODIFIABLE,
        CKA_COPYABLE,
        CKA_DESTROYABLE,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
        CKA_SECONDARY_AUTH,
        CKA_AUTH_PIN_FLAGS,
        CKA_ALWAYS_AUTHENTICATE,
        CKA_WRAP_WITH_TRUSTED,
        CKA_WRAP_TEMPLATE,
        CKA_UNWRAP_TEMPLATE,
        CKA_DERIVE_TEMPLATE,
        CKA_OTP_FORMAT,
        CKA_OTP_LENGTH,
        CKA_OTP_TIME_INTERVAL,
        CKA_OTP_USER_FRIENDLY_MODE,
        CKA_OTP_CHALLENGE_REQUIREMENT,
        CKA_OTP_TIME_REQUIREMENT,
        CKA_OTP_COUNTER_REQUIREMENT,
        CKA_OTP_PIN_REQUIREMENT,
        CKA_OTP_COUNTER,
        CKA_OTP_TIME,
        CKA_OTP_USER_IDENTIFIER,
        CKA_OTP_SERVICE_IDENTIFIER,
        CKA_OTP_SERVICE_LOGO,
        CKA_OTP_SERVICE_LOGO_TYPE,
        CKA_GOSTR3410_PARAMS,
        CKA_GOSTR3411_PARAMS,
        CKA_GOST28147_PARAMS,
        CKA_HW_FEATURE_TYPE,
        CKA_RESET_ON_INIT,
        CKA_HAS_RESET,
        CKA_PIXEL_X,
        CKA_PIXEL_Y,
        CKA_RESOLUTION,
        CKA_CHAR_ROWS,
        CKA_CHAR_COLUMNS,
        CKA_COLOR,
        CKA_BITS_PER_PIXEL,
        CKA_CHAR_SETS,
        CKA_ENCODING_METHODS,
        CKA_MIME_TYPES,
        CKA_MECHANISM_TYPE,
        CKA_REQUIRED_CMS_ATTRIBUTES,
        CKA_DEFAULT_CMS_ATTRIBUTES,
        CKA_SUPPORTED_CMS_ATTRIBUTES,
        CKA_ALLOWED_MECHANISMS,
        CKA_PROFILE_ID,
        CKA_X2RATCHET_BAG,
        CKA_X2RATCHET_BAGSIZE,
        CKA_X2RATCHET_BOBS1STMSG,
        CKA_X2RATCHET_CKR,
        CKA_X2RATCHET_CKS,
        CKA_X2RATCHET_DHP,
        CKA_X2RATCHET_DHR,
        CKA_X2RATCHET_DHS,
        CKA_X2RATCHET_HKR,
        CKA_X2RATCHET_HKS,
        CKA_X2RATCHET_ISALICE,
        CKA_X2RATCHET_NHKR,
        CKA_X2RATCHET_NHKS,
        CKA_X2RATCHET_NR,
        CKA_X2RATCHET_NS,
        CKA_X2RATCHET_PNS,
        CKA_X2RATCHET_RK,
        CKA_HSS_LEVELS,
        CKA_HSS_LMS_TYPE,
        CKA_HSS_LMOTS_TYPE,
        CKA_HSS_LMS_TYPES,
        CKA_HSS_LMOTS_TYPES,
        CKA_HSS_KEYS_REMAINING,
        CKA_PARAMETER_SET,
        CKA_OBJECT_VALIDATION_FLAGS,
        CKA_VALIDATION_TYPE,
        CKA_VALIDATION_VERSION,
        CKA_VALIDATION_LEVEL,
        CKA_VALIDATION_MODULE_ID,
        CKA_VALIDATION_FLAG,
        CKA_VALIDATION_AUTHORITY_TYPE,
        CKA_VALIDATION_COUNTRY,
        CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
        CKA_VALIDATION_CERTIFICATE_URI,
        CKA_VALIDATION_VENDOR_URI,
        CKA_VALIDATION_PROFILE,
        CKA_TRUST_SERVER_AUTH,
        CKA_TRUST_CLIENT_AUTH,
        CKA_TRUST_CODE_SIGNING,
        CKA_TRUST_EMAIL_PROTECTION,
        CKA_TRUST_IPSEC_IKE,
        CKA_TRUST_TIME_STAMPING,
        CKA_TRUST_OCSP_SIGNING,
        CKA_ENCAPSULATE_TEMPLATE,
        CKA_DECAPSULATE_TEMPLATE,
        CKA_ENCAPSULATE,
        CKA_DECAPSULATE,
        CKA_HASH_OF_CERTIFICATE,
        CKA_PUBLIC_CRC64_VALUE,
        CKA_SEED,
        CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
        CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
        CKA_PKCS11RS_FIDO_RP_ID,
        CKA_VENDOR_DEFINED,
    )
}

fn profile_id_name(value: CK_PROFILE_ID) -> Option<&'static CStr> {
    constant_name!(value, CK_PROFILE_ID;
        CKP_INVALID_ID,
        CKP_BASELINE_PROVIDER,
        CKP_EXTENDED_PROVIDER,
        CKP_AUTHENTICATION_TOKEN,
        CKP_PUBLIC_CERTIFICATES_TOKEN,
        CKP_COMPLETE_PROVIDER,
        CKP_HKDF_TLS_TOKEN,
        CKP_VENDOR_DEFINED,
    )
}

macro_rules! export_name_function {
    ($function:ident, $type:ty, $lookup:ident) => {
        #[no_mangle]
        pub extern "C" fn $function(value: $type) -> *const c_char {
            $lookup(value).map_or(std::ptr::null(), CStr::as_ptr)
        }
    };
}

export_name_function!(PKCS11RS_GetReturnValueName, CK_RV, return_value_name);
export_name_function!(
    PKCS11RS_GetObjectClassName,
    CK_OBJECT_CLASS,
    object_class_name
);
export_name_function!(PKCS11RS_GetKeyTypeName, CK_KEY_TYPE, key_type_name);
export_name_function!(
    PKCS11RS_GetAttributeTypeName,
    CK_ATTRIBUTE_TYPE,
    attribute_type_name
);
export_name_function!(PKCS11RS_GetProfileIdName, CK_PROFILE_ID, profile_id_name);

#[cfg(test)]
mod tests {
    use super::*;

    fn returned_name(pointer: *const c_char) -> Option<&'static str> {
        (!pointer.is_null())
            .then(|| unsafe { CStr::from_ptr(pointer) })
            .and_then(|name| name.to_str().ok())
    }

    #[test]
    fn exported_helpers_name_standard_and_vendor_values() {
        assert_eq!(
            returned_name(PKCS11RS_GetReturnValueName(CKR_BUFFER_TOO_SMALL.into())),
            Some("CKR_BUFFER_TOO_SMALL")
        );
        assert_eq!(
            returned_name(PKCS11RS_GetObjectClassName(CKO_PRIVATE_KEY.into())),
            Some("CKO_PRIVATE_KEY")
        );
        assert_eq!(
            returned_name(PKCS11RS_GetKeyTypeName(
                CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION
            )),
            Some("CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION")
        );
        assert_eq!(
            returned_name(PKCS11RS_GetAttributeTypeName(CKA_PKCS11RS_FIDO_RP_ID)),
            Some("CKA_PKCS11RS_FIDO_RP_ID")
        );
        assert_eq!(
            returned_name(PKCS11RS_GetProfileIdName(CKP_EXTENDED_PROVIDER.into())),
            Some("CKP_EXTENDED_PROVIDER")
        );
    }

    #[test]
    fn aliases_use_canonical_names_and_unknown_values_return_null() {
        assert_eq!(
            returned_name(PKCS11RS_GetKeyTypeName(CKK_ECDSA.into())),
            Some("CKK_EC")
        );
        assert_eq!(
            returned_name(PKCS11RS_GetAttributeTypeName(CKA_ECDSA_PARAMS.into())),
            Some("CKA_EC_PARAMS")
        );
        assert!(PKCS11RS_GetReturnValueName(CK_ULONG::MAX).is_null());
        assert!(PKCS11RS_GetObjectClassName(CK_ULONG::MAX).is_null());
        assert!(PKCS11RS_GetKeyTypeName(CK_ULONG::MAX).is_null());
        assert!(PKCS11RS_GetAttributeTypeName(CK_ULONG::MAX).is_null());
        assert!(PKCS11RS_GetProfileIdName(CK_ULONG::MAX).is_null());
    }
}
