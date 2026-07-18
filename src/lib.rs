#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate curl;
extern crate openssl;
extern crate pcsc;
extern crate rusb;

#[cfg(feature = "abi-tests")]
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    rsa::{Padding, Rsa, RsaPrivateKeyBuilder},
    sign::Verifier,
};
use rusb::UsbContext;
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    ffi::CStr,
    io::Write,
    ptr,
    rc::Rc,
    slice,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex, MutexGuard, OnceLock,
    },
    time::Duration,
};
use zeroize::Zeroizing;

static DEBUG_LEVEL: AtomicU8 = AtomicU8::new(0);

fn parse_debug_level(value: Option<&str>) -> u8 {
    match value {
        None | Some("0") => 0,
        Some("1") => 1,
        Some("2") => 2,
        Some(_) => 2,
    }
}

fn initialize_debug_logging() {
    let level = parse_debug_level(std::env::var("PKCS11RS_DEBUG").ok().as_deref());
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

/// Emit diagnostic output when the configured level includes the message.
macro_rules! log {
    ($level:literal, $($arg:tt)*) => {
        if crate::DEBUG_LEVEL.load(std::sync::atomic::Ordering::Relaxed) >= $level {
            eprintln!($($arg)*);
        }
    };
}

pub mod error;
use error::*;

mod secure_channel_crypto;

mod scp03;
use scp03::{
    configured_security_level, parse_hex, select_application, CommandApdu, ResponseApdu,
    Scp03KeySet, Scp03Session, YUBIKEY_ISSUER_SECURITY_DOMAIN_AID,
};

mod scp11;
use scp11::{Scp11KeySet, Scp11Variant};

mod piv;
use piv::{Client as PivClient, DeviceInfo as PivDeviceInfo, MetadataPublicKey};

mod openpgp;
use openpgp::{
    Algorithm as OpenPgpAlgorithm, Client as OpenPgpClient, KeyRef as OpenPgpKeyRef,
    PublicKey as OpenPgpPublicKey,
};

mod yubihsm;
use yubihsm::{
    get_device_info as get_yubihsm_device_info,
    parse_asymmetric_pin as parse_yubihsm_asymmetric_pin,
    parse_object_id as parse_yubihsm_object_id, parse_object_list as parse_yubihsm_object_list,
    parse_pin as parse_yubihsm_pin, Command as YubiHsmCommand, CommandCode as YubiHsmCommandCode,
    ObjectInfo as YubiHsmObjectInfo, ObjectParameters as YubiHsmObjectParameters,
    PublicKey as YubiHsmPublicKey, SecureSession as YubiHsmSecureSession,
};

#[allow(dead_code)]
mod yubihsm_object_type {
    pub(super) const YUBIHSM_OPAQUE: u8 = 0x01;
    pub(super) const YUBIHSM_AUTHENTICATION_KEY: u8 = 0x02;
    pub(super) const YUBIHSM_ASYMMETRIC_KEY: u8 = 0x03;
    pub(super) const YUBIHSM_WRAP_KEY: u8 = 0x04;
    pub(super) const YUBIHSM_HMAC_KEY: u8 = 0x05;
    pub(super) const YUBIHSM_TEMPLATE: u8 = 0x06;
    pub(super) const YUBIHSM_OTP_AEAD_KEY: u8 = 0x07;
    pub(super) const YUBIHSM_SYMMETRIC_KEY: u8 = 0x08;
    pub(super) const YUBIHSM_PUBLIC_WRAP_KEY: u8 = 0x09;
    pub(super) const YUBIHSM_PUBLIC_KEY: u8 = YUBIHSM_ASYMMETRIC_KEY | 0x80;
    pub(super) const YUBIHSM_WRAP_KEY_PUBLIC: u8 = YUBIHSM_WRAP_KEY | 0x80;
}
use yubihsm_object_type::*;
#[allow(dead_code)]
mod yubihsm_algorithm {
    pub(super) const YUBIHSM_ALGO_RSA_PKCS1_SHA1: u8 = 1;
    pub(super) const YUBIHSM_ALGO_RSA_PKCS1_SHA256: u8 = 2;
    pub(super) const YUBIHSM_ALGO_RSA_PKCS1_SHA384: u8 = 3;
    pub(super) const YUBIHSM_ALGO_RSA_PKCS1_SHA512: u8 = 4;
    pub(super) const YUBIHSM_ALGO_RSA_PSS_SHA1: u8 = 5;
    pub(super) const YUBIHSM_ALGO_RSA_PSS_SHA256: u8 = 6;
    pub(super) const YUBIHSM_ALGO_RSA_PSS_SHA384: u8 = 7;
    pub(super) const YUBIHSM_ALGO_RSA_PSS_SHA512: u8 = 8;
    pub(super) const YUBIHSM_ALGO_RSA_2048: u8 = 9;
    pub(super) const YUBIHSM_ALGO_RSA_3072: u8 = 10;
    pub(super) const YUBIHSM_ALGO_RSA_4096: u8 = 11;
    pub(super) const YUBIHSM_ALGO_EC_P256: u8 = 12;
    pub(super) const YUBIHSM_ALGO_EC_P384: u8 = 13;
    pub(super) const YUBIHSM_ALGO_EC_P521: u8 = 14;
    pub(super) const YUBIHSM_ALGO_EC_K256: u8 = 15;
    pub(super) const YUBIHSM_ALGO_EC_BP256: u8 = 16;
    pub(super) const YUBIHSM_ALGO_EC_BP384: u8 = 17;
    pub(super) const YUBIHSM_ALGO_EC_BP512: u8 = 18;
    pub(super) const YUBIHSM_ALGO_HMAC_SHA1: u8 = 19;
    pub(super) const YUBIHSM_ALGO_HMAC_SHA256: u8 = 20;
    pub(super) const YUBIHSM_ALGO_HMAC_SHA384: u8 = 21;
    pub(super) const YUBIHSM_ALGO_HMAC_SHA512: u8 = 22;
    pub(super) const YUBIHSM_ALGO_EC_ECDSA_SHA1: u8 = 23;
    pub(super) const YUBIHSM_ALGO_EC_ECDH: u8 = 24;
    pub(super) const YUBIHSM_ALGO_RSA_OAEP_SHA1: u8 = 25;
    pub(super) const YUBIHSM_ALGO_RSA_OAEP_SHA256: u8 = 26;
    pub(super) const YUBIHSM_ALGO_RSA_OAEP_SHA384: u8 = 27;
    pub(super) const YUBIHSM_ALGO_RSA_OAEP_SHA512: u8 = 28;
    pub(super) const YUBIHSM_ALGO_AES128_CCM_WRAP: u8 = 29;
    pub(super) const YUBIHSM_ALGO_OPAQUE_DATA: u8 = 30;
    pub(super) const YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE: u8 = 31;
    pub(super) const YUBIHSM_ALGO_MGF1_SHA1: u8 = 32;
    pub(super) const YUBIHSM_ALGO_MGF1_SHA256: u8 = 33;
    pub(super) const YUBIHSM_ALGO_MGF1_SHA384: u8 = 34;
    pub(super) const YUBIHSM_ALGO_MGF1_SHA512: u8 = 35;
    pub(super) const YUBIHSM_ALGO_TEMPLATE_SSH: u8 = 36;
    pub(super) const YUBIHSM_ALGO_AES128_YUBICO_OTP: u8 = 37;
    pub(super) const YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION: u8 = 38;
    pub(super) const YUBIHSM_ALGO_AES192_YUBICO_OTP: u8 = 39;
    pub(super) const YUBIHSM_ALGO_AES256_YUBICO_OTP: u8 = 40;
    pub(super) const YUBIHSM_ALGO_AES192_CCM_WRAP: u8 = 41;
    pub(super) const YUBIHSM_ALGO_AES256_CCM_WRAP: u8 = 42;
    pub(super) const YUBIHSM_ALGO_EC_ECDSA_SHA256: u8 = 43;
    pub(super) const YUBIHSM_ALGO_EC_ECDSA_SHA384: u8 = 44;
    pub(super) const YUBIHSM_ALGO_EC_ECDSA_SHA512: u8 = 45;
    pub(super) const YUBIHSM_ALGO_ED25519: u8 = 46;
    pub(super) const YUBIHSM_ALGO_EC_P224: u8 = 47;
    pub(super) const YUBIHSM_ALGO_RSA_PKCS1_DECRYPT: u8 = 48;
    pub(super) const YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION: u8 = 49;
    pub(super) const YUBIHSM_ALGO_AES128: u8 = 50;
    pub(super) const YUBIHSM_ALGO_AES192: u8 = 51;
    pub(super) const YUBIHSM_ALGO_AES256: u8 = 52;
    pub(super) const YUBIHSM_ALGO_AES_ECB: u8 = 53;
    pub(super) const YUBIHSM_ALGO_AES_CBC: u8 = 54;
    pub(super) const YUBIHSM_ALGO_AES_KWP: u8 = 55;
    pub(super) const YUBIHSM_ALGO_X25519: u8 = 56;
}
use yubihsm_algorithm::*;

const YUBICO_BASE_VENDOR: CK_KEY_TYPE = 0x5955_4200;
const CKK_YUBICO_AES128_CCM_WRAP: CK_KEY_TYPE = CKK_VENDOR_DEFINED as CK_KEY_TYPE
    | YUBICO_BASE_VENDOR
    | YUBIHSM_ALGO_AES128_CCM_WRAP as CK_KEY_TYPE;
const CKK_YUBICO_AES192_CCM_WRAP: CK_KEY_TYPE = CKK_VENDOR_DEFINED as CK_KEY_TYPE
    | YUBICO_BASE_VENDOR
    | YUBIHSM_ALGO_AES192_CCM_WRAP as CK_KEY_TYPE;
const CKK_YUBICO_AES256_CCM_WRAP: CK_KEY_TYPE = CKK_VENDOR_DEFINED as CK_KEY_TYPE
    | YUBICO_BASE_VENDOR
    | YUBIHSM_ALGO_AES256_CCM_WRAP as CK_KEY_TYPE;

fn is_hmac_key_type(key_type: CK_KEY_TYPE) -> bool {
    matches!(
        key_type,
        x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE
            || x == CKK_SHA256_HMAC as CK_KEY_TYPE
            || x == CKK_SHA384_HMAC as CK_KEY_TYPE
            || x == CKK_SHA512_HMAC as CK_KEY_TYPE
    )
}

fn is_montgomery_key_type(key_type: CK_KEY_TYPE) -> bool {
    key_type == CKK_EC_MONTGOMERY as CK_KEY_TYPE
}

fn is_yubihsm_ccm_wrap(algorithm: u8) -> bool {
    matches!(
        algorithm,
        YUBIHSM_ALGO_AES128_CCM_WRAP | YUBIHSM_ALGO_AES192_CCM_WRAP | YUBIHSM_ALGO_AES256_CCM_WRAP
    )
}

fn yubihsm_capability(capabilities: &[u8; 8], bit: usize) -> bool {
    capabilities[7 - bit / 8] & (1 << (bit % 8)) != 0
}

fn yubihsm_capabilities(bits: &[usize]) -> [u8; 8] {
    let mut capabilities = [0; 8];
    for bit in bits {
        capabilities[7 - bit / 8] |= 1 << (bit % 8);
    }
    capabilities
}

fn yubihsm_material_has_capability(material: &KeyMaterial, bit: usize) -> bool {
    match material {
        KeyMaterial::YubiHsm { capabilities, .. } => yubihsm_capability(capabilities, bit),
        _ => true,
    }
}

fn is_yubihsm_rsa(algorithm: u8) -> bool {
    matches!(
        algorithm,
        YUBIHSM_ALGO_RSA_2048 | YUBIHSM_ALGO_RSA_3072 | YUBIHSM_ALGO_RSA_4096
    )
}

fn is_yubihsm_ec(algorithm: u8) -> bool {
    matches!(
        algorithm,
        YUBIHSM_ALGO_EC_P224
            | YUBIHSM_ALGO_EC_P256
            | YUBIHSM_ALGO_EC_P384
            | YUBIHSM_ALGO_EC_P521
            | YUBIHSM_ALGO_EC_K256
            | YUBIHSM_ALGO_EC_BP256
            | YUBIHSM_ALGO_EC_BP384
            | YUBIHSM_ALGO_EC_BP512
    )
}

fn is_yubihsm_x25519(algorithm: u8) -> bool {
    algorithm == YUBIHSM_ALGO_X25519
}

fn yubihsm_ec_parameters(algorithm: u8) -> Option<&'static [u8]> {
    match algorithm {
        YUBIHSM_ALGO_EC_P224 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21]),
        YUBIHSM_ALGO_EC_P256 => Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        YUBIHSM_ALGO_EC_P384 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        YUBIHSM_ALGO_EC_P521 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        YUBIHSM_ALGO_EC_K256 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]),
        YUBIHSM_ALGO_EC_BP256 => Some(&[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
        ]),
        YUBIHSM_ALGO_EC_BP384 => Some(&[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
        ]),
        YUBIHSM_ALGO_EC_BP512 => Some(&[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
        ]),
        YUBIHSM_ALGO_ED25519 => Some(&[0x06, 0x03, 0x2b, 0x65, 0x70]),
        YUBIHSM_ALGO_X25519 => Some(&[
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        _ => None,
    }
}

fn der_octet_string(value: &[u8]) -> Option<Vec<u8>> {
    let mut encoded = Vec::with_capacity(value.len() + 3);
    encoded.push(0x04);
    if value.len() < 128 {
        encoded.push(value.len() as u8);
    } else if value.len() <= u8::MAX as usize {
        encoded.extend_from_slice(&[0x81, value.len() as u8]);
    } else {
        return None;
    }
    encoded.extend_from_slice(value);
    Some(encoded)
}

fn der_octet_string_value(value: &[u8]) -> Option<&[u8]> {
    if value.first().copied()? != 0x04 {
        return None;
    }
    let (length, offset) = match value.get(1).copied()? {
        length @ 0..=127 => (length as usize, 2usize),
        0x81 => (value.get(2).copied()? as usize, 3usize),
        _ => return None,
    };
    value
        .get(offset..offset.checked_add(length)?)
        .filter(|_| offset + length == value.len())
}

fn piv_ecdsa_signature(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    let signature = EcdsaSig::from_der(signature).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut output = vec![0; coordinate_length * 2];
    let r = signature.r().to_vec();
    let s = signature.s().to_vec();
    if r.len() > coordinate_length || s.len() > coordinate_length {
        return Err(CKR_DEVICE_ERROR.into());
    }
    output[coordinate_length - r.len()..coordinate_length].copy_from_slice(&r);
    output[2 * coordinate_length - s.len()..].copy_from_slice(&s);
    Ok(output)
}

pub mod pkcs11 {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]

    include!(concat!(env!("OUT_DIR"), "/pkcs11.rs"));
}
use pkcs11::*;

unsafe impl Sync for CK_INTERFACE {}

#[cfg(test)]
mod test;

fn str_pad(src: &str, dst: &mut [u8]) {
    let src = src.as_bytes();
    let src_len = src.len();
    let dst_len = dst.len();
    if src_len < dst_len {
        dst[..src_len].copy_from_slice(src);
        dst[src_len..].fill(32);
    } else {
        dst.copy_from_slice(&src[..dst_len]);
    }
}

fn next_key<T>(
    map: &HashMap<::std::os::raw::c_ulong, T>,
    min: ::std::os::raw::c_ulong,
) -> ::std::os::raw::c_ulong {
    match map.keys().max() {
        Some(k) => k + 1,
        None => min,
    }
}

fn lock_context() -> Result<MutexGuard<'static, Option<Context>>, Error> {
    G_CONTEXT.lock().map_err(|_| CKR_MUTEX_BAD.into())
}

fn with_context<T>(f: impl FnOnce(&Context) -> Result<T, Error>) -> Result<T, Error> {
    let guard = lock_context()?;
    let ctx = guard.as_ref().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    f(ctx)
}

fn with_context_mut<T>(f: impl FnOnce(&mut Context) -> Result<T, Error>) -> Result<T, Error> {
    let mut guard = lock_context()?;
    let ctx = guard.as_mut().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    f(ctx)
}

fn _as_ref<'a, T>(ptr: *const T) -> Result<&'a T, Error> {
    unsafe { ptr.as_ref() }.ok_or(CKR_ARGUMENTS_BAD.into())
}

fn as_mut<'a, T>(ptr: *mut T) -> Result<&'a mut T, Error> {
    unsafe { ptr.as_mut() }.ok_or(CKR_ARGUMENTS_BAD.into())
}

fn from_raw_parts<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], Error> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD.into())
    } else {
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

fn _from_raw_parts_mut<'a, T>(ptr: *mut T, len: usize) -> Result<&'a mut [T], Error> {
    if len == 0 {
        Ok(&mut [])
    } else if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD.into())
    } else {
        Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
    }
}

include!("backend/traits.rs");

include!("backend/yubihsm.rs");

include!("backend/piv.rs");

include!("backend/crypto.rs");

include!("backend/ccid.rs");

include!("backend/openpgp.rs");

#[cfg(any(test, feature = "abi-tests"))]
const ABI_TEST_SLOT_ID: CK_SLOT_ID = 77;

#[cfg(feature = "abi-tests")]
const ABI_TEST_PIV_SLOT_ID: CK_SLOT_ID = 78;

#[cfg(feature = "abi-tests")]
const ABI_TEST_SCP03_SLOT_ID: CK_SLOT_ID = 79;

#[cfg(feature = "abi-tests")]
const ABI_TEST_YUBIHSM_SLOT_ID: CK_SLOT_ID = 80;

#[cfg(feature = "abi-tests")]
const ABI_TEST_SCP11_SLOT_ID: CK_SLOT_ID = 81;

#[cfg(feature = "abi-tests")]
mod abi_test_backend;
#[cfg(feature = "abi-tests")]
use abi_test_backend::*;

mod connector;
pub(crate) use connector::{
    bulk_out_packet_size, Connector, PcscAppletConnector, PcscConnector, SecureChannelState,
    UsbConnector,
};
#[cfg(test)]
pub(crate) use connector::{ensure_complete_write, needs_zero_length_packet};

include!("context.rs");

include!("object.rs");

fn session_function_not_supported(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let result: Result<(), Error> = with_context(|ctx| {
        ctx._get_session(session_handle)?;
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    });
    map(result)
}

#[no_mangle]
pub extern "C" fn C_Initialize(init_args: CK_VOID_PTR) -> CK_RV {
    initialize_debug_logging();
    log!(2, "C_Initialize called with {:?}", init_args);
    if let Err(rv) = validate_initialize_args(init_args) {
        return rv;
    }
    match lock_context() {
        Ok(mut guard) => match guard.as_mut() {
            Some(_) => CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV,
            None => match Context::new() {
                Ok(context) => {
                    *guard = Some(context);
                    CKR_OK as CK_RV
                }
                Err(error) => error.into(),
            },
        },
        Err(e) => e.into(),
    }
}

fn validate_initialize_args(init_args: CK_VOID_PTR) -> Result<(), CK_RV> {
    if init_args.is_null() {
        return Ok(());
    }

    let args = unsafe { &*(init_args as CK_C_INITIALIZE_ARGS_PTR) };
    if !args.pReserved.is_null() {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    let callbacks = [
        args.CreateMutex.is_some(),
        args.DestroyMutex.is_some(),
        args.LockMutex.is_some(),
        args.UnlockMutex.is_some(),
    ];
    let any_callbacks = callbacks.iter().any(|present| *present);
    let all_callbacks = callbacks.iter().all(|present| *present);
    if any_callbacks != all_callbacks {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    let known_flags = (CKF_LIBRARY_CANT_CREATE_OS_THREADS | CKF_OS_LOCKING_OK) as CK_FLAGS;
    if args.flags & !known_flags != 0 {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }

    if all_callbacks && args.flags & CKF_OS_LOCKING_OK as CK_FLAGS == 0 {
        return Err(CKR_CANT_LOCK as CK_RV);
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: *mut ::std::os::raw::c_void) -> CK_RV {
    log!(2, "C_Finalize called with {:?}", pReserved);
    if !pReserved.is_null() {
        return CKR_ARGUMENTS_BAD.into();
    }
    match lock_context() {
        Ok(mut guard) => match guard.as_mut() {
            Some(ctx) => {
                let logged_in_slots: Vec<CK_SLOT_ID> =
                    ctx.logged_in_slots.iter().copied().collect();
                let mut logout_failed = false;
                for slot_id in logged_in_slots {
                    if ctx.logout_slot(slot_id).is_err() {
                        ctx.clear_login_state(slot_id);
                        logout_failed = true;
                    }
                }
                *guard = None;
                if logout_failed {
                    CKR_FUNCTION_FAILED as CK_RV
                } else {
                    CKR_OK as CK_RV
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
        },
        Err(e) => e.into(),
    }
}

// Cryptoki declares these as callable C function pointers. They validate each
// caller-owned pointer before dereferencing it, but cannot be exposed as unsafe
// Rust functions without changing the generated PKCS #11 function-list types.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetFunctionList(function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    unsafe {
        log!(2, "C_GetFunctionList called with {:?}", function_list);
        match function_list.as_mut() {
            Some(function_list) => {
                *function_list =
                    &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
                log!(2, "C_GetFunctionList returning {:?}", *function_list);
                CKR_OK
            }
            None => CKR_ARGUMENTS_BAD,
        }
    }
    .into()
}

fn get_info(info_ptr: CK_INFO_PTR) -> Result<(), Error> {
    with_context(|ctx| ctx.get_info(as_mut(info_ptr)?))
}

#[no_mangle]
pub extern "C" fn C_GetInfo(info_ptr: *mut CK_INFO) -> CK_RV {
    log!(2, "C_GetInfo called with {:?}", info_ptr);
    map(get_info(info_ptr))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetSlotList(
    token_present: ::std::os::raw::c_uchar,
    slot_list: *mut CK_SLOT_ID,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    unsafe {
        log!(
            2,
            "C_GetSlotList called with {:?}",
            (token_present, slot_list, count)
        );
        let count = match count.as_mut() {
            Some(count) => count,
            None => return CKR_ARGUMENTS_BAD.into(),
        };
        match with_context_mut(|ctx| {
            ctx.init();
            let mut keys: Vec<CK_SLOT_ID> = if token_present == 0 {
                ctx.slots.keys().cloned().collect()
            } else {
                ctx.slots
                    .iter()
                    .filter(|s| s.1.flags() & (CKF_TOKEN_PRESENT as CK_FLAGS) != 0)
                    .map(|s| *s.0)
                    .collect()
            };
            match slot_list.as_mut() {
                Some(_) => {
                    if *count >= keys.len() as ::std::os::raw::c_ulong {
                        keys.sort();
                        ptr::copy(keys.as_ptr(), slot_list, keys.len());
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        log!(2, "C_GetSlotList returning {:?}", (keys, *count));
                        Ok(CKR_OK as CK_RV)
                    } else {
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        log!(2, "C_GetSlotList returning {:?}", *count);
                        Ok(CKR_BUFFER_TOO_SMALL as CK_RV)
                    }
                }
                None => {
                    *count = keys.len() as ::std::os::raw::c_ulong;
                    log!(2, "C_GetSlotList returning {:?}", *count);
                    Ok(CKR_OK as CK_RV)
                }
            }
        }) {
            Ok(rv) => rv,
            Err(e) => e.into(),
        }
    }
}

fn get_slot_info(slotID: CK_SLOT_ID, info_ptr: CK_SLOT_INFO_PTR) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context(|ctx| ctx.get_slot(slotID)?.get_slot_info(info))
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_SLOT_INFO) -> CK_RV {
    log!(2, "C_GetSlotInfo called with {:?}", (slotID, info_ptr));
    map(get_slot_info(slotID, info_ptr))
}

fn get_token_info(slotID: CK_SLOT_ID, info_ptr: CK_TOKEN_INFO_PTR) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        ctx.get_present_slot(slotID)?.get_token_info(info)?;
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulSessionCount = ctx
            .sessions
            .values()
            .filter(|session| session.slotID() == slotID)
            .count() as CK_ULONG;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulRwSessionCount = ctx
            .sessions
            .values()
            .filter(|session| {
                session.slotID() == slotID && session.flags() & CKF_RW_SESSION as CK_FLAGS != 0
            })
            .count() as CK_ULONG;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_TOKEN_INFO) -> CK_RV {
    log!(2, "C_GetTokenInfo called with {:?}", (slotID, info_ptr));
    map(get_token_info(slotID, info_ptr))
}

#[no_mangle]
pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: *mut CK_SLOT_ID,
    _pReserved: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

include!("mechanism.rs");

#[no_mangle]
pub extern "C" fn C_InitToken(
    _slotID: CK_SLOT_ID,
    _pin: *mut ::std::os::raw::c_uchar,
    _pin_len: ::std::os::raw::c_ulong,
    _label: *mut ::std::os::raw::c_uchar,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_InitPIN(
    session_handle: CK_SESSION_HANDLE,
    _pin: *mut ::std::os::raw::c_uchar,
    _pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SetPIN(
    session_handle: CK_SESSION_HANDLE,
    _old_pin: *mut ::std::os::raw::c_uchar,
    _old_len: ::std::os::raw::c_ulong,
    _new_pin: *mut ::std::os::raw::c_uchar,
    _new_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: *mut ::std::os::raw::c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    log!(2, "C_OpenSession called with {:?}", (slotID, flags));
    unsafe {
        let session = match session.as_mut() {
            Some(session) => session,
            None => return CKR_ARGUMENTS_BAD.into(),
        };
        match with_context_mut(|ctx| {
            if flags & CKF_SERIAL_SESSION as CK_FLAGS == 0 {
                return Ok(CKR_SESSION_PARALLEL_NOT_SUPPORTED as CK_RV);
            }
            if flags & CKF_ASYNC_SESSION as CK_FLAGS != 0 {
                return Ok(CKR_SESSION_ASYNC_NOT_SUPPORTED as CK_RV);
            }

            match ctx.slots.get_mut(&slotID) {
                Some(slot) => {
                    let _ = slot.refresh();
                    log!(2, "{:?}", slot);
                    if slot.flags() & CKF_TOKEN_PRESENT as CK_FLAGS != 0 {
                        let k = next_key(&ctx.sessions, 1);
                        log!(2, "C_OpenSession sessions before {:?}", ctx.sessions);
                        ctx.sessions.insert(k, slot.open_session(slotID, flags));
                        log!(2, "C_OpenSession sessions after {:?}", ctx.sessions);
                        log!(2, "C_OpenSession returning {:?}", k);
                        *session = k;
                        Ok(CKR_OK as CK_RV)
                    } else {
                        Ok(CKR_TOKEN_NOT_PRESENT as CK_RV)
                    }
                }
                None => Ok(CKR_SLOT_ID_INVALID as CK_RV),
            }
        }) {
            Ok(rv) => rv,
            Err(e) => e.into(),
        }
    }
}

#[no_mangle]
pub extern "C" fn C_CloseSession(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_CloseSession called with {:?}", session_handle);
    match with_context_mut(|ctx| {
        log!(2, "C_CloseSession sessions before {:?}", ctx.sessions);
        let slot_id = match ctx.sessions.get(&session_handle) {
            Some(session) => session.slotID(),
            None => return Ok(CKR_SESSION_HANDLE_INVALID as CK_RV),
        };
        let is_last_session = !ctx
            .sessions
            .iter()
            .any(|(handle, session)| *handle != session_handle && session.slotID() == slot_id);
        ctx.reconcile_login_state(slot_id);
        let logout_error = if is_last_session && ctx.is_slot_logged_in(slot_id) {
            match ctx.logout_slot(slot_id) {
                Ok(()) => None,
                Err(error) => {
                    ctx.clear_login_state(slot_id);
                    if let Some(slot) = ctx.slots.get_mut(&slot_id) {
                        slot.clear_session();
                    }
                    Some(error)
                }
            }
        } else {
            None
        };
        let session = ctx.sessions.remove(&session_handle).unwrap();
        ctx.find_operations.remove(&session_handle);
        ctx.encrypt_operations.remove(&session_handle);
        ctx.decrypt_operations.remove(&session_handle);
        ctx.sign_operations.remove(&session_handle);
        ctx.verify_operations.remove(&session_handle);
        ctx.objects
            .retain(|_, object| object.owner_session != Some(session_handle));
        log!(2, "C_CloseSession removed {:?}", (session_handle, session));
        log!(2, "C_CloseSession sessions after {:?}", ctx.sessions);
        match logout_error {
            Some(error) => Err(error),
            None => Ok(CKR_OK as CK_RV),
        }
    }) {
        Ok(rv) => rv,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    log!(2, "C_CloseAllSessions called with {:?}", slotID);
    match with_context_mut(|ctx| {
        if !ctx.slots.contains_key(&slotID) {
            return Ok(CKR_SLOT_ID_INVALID as CK_RV);
        }
        log!(2, "C_CloseAllSessions sessions before {:?}", ctx.sessions);
        let closed_sessions: HashSet<CK_SESSION_HANDLE> = ctx
            .sessions
            .iter()
            .filter(|(_k, v)| v.slotID() == slotID)
            .map(|(k, _v)| *k)
            .collect();
        ctx.reconcile_login_state(slotID);
        let logout_error = if ctx.is_slot_logged_in(slotID) {
            match ctx.logout_slot(slotID) {
                Ok(()) => None,
                Err(error) => {
                    ctx.clear_login_state(slotID);
                    if let Some(slot) = ctx.slots.get_mut(&slotID) {
                        slot.clear_session();
                    }
                    Some(error)
                }
            }
        } else {
            None
        };
        ctx.sessions.retain(|_k, v| v.slotID() != slotID);
        ctx.find_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.encrypt_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.decrypt_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.sign_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.verify_operations
            .retain(|session, _operation| !closed_sessions.contains(session));
        ctx.objects.retain(|_, object| {
            object
                .owner_session
                .map(|owner| !closed_sessions.contains(&owner))
                .unwrap_or(true)
        });
        log!(2, "C_CloseAllSessions sessions after {:?}", ctx.sessions);
        match logout_error {
            Some(error) => Err(error),
            None => Ok(CKR_OK as CK_RV),
        }
    }) {
        Ok(rv) => rv,
        Err(e) => e.into(),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn C_GetSessionInfo(
    session_handle: CK_SESSION_HANDLE,
    info_ptr: *mut CK_SESSION_INFO,
) -> CK_RV {
    log!(2, "C_GetSessionInfo called with {:?}", session_handle);
    map(get_session_info(session_handle, info_ptr))
}

fn get_session_info(
    session_handle: CK_SESSION_HANDLE,
    info_ptr: *mut CK_SESSION_INFO,
) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        let (slot_id, flags) = {
            let session = ctx._get_session(session_handle)?.1;
            (session.slotID(), session.flags())
        };
        if ctx.is_slot_logged_in(slot_id) {
            if let Err(error) = ctx._get_session(session_handle)?.1.get_session_info() {
                ctx.reconcile_login_state(slot_id);
                return Err(error);
            }
        }
        ctx.reconcile_login_state(slot_id);
        info.slotID = slot_id;
        info.state = session_state(flags, ctx.is_slot_logged_in(slot_id));
        info.flags = flags;
        info.ulDeviceError = 0;
        log!(2, "C_GetSessionInfo returning {:?}", info);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetOperationState(
    session_handle: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SetOperationState(
    session_handle: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: ::std::os::raw::c_ulong,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentiation_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

fn login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *const ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            let pin = from_raw_parts(pin, pin_len as usize)?;
            let mut context_operation = None;
            if let Some(operation) = ctx.sign_operations.get(&session_handle) {
                context_operation = Some((operation.slot_id, operation.context_specific_extended));
            }
            if let Some(operation) = ctx.decrypt_operations.get(&session_handle) {
                if context_operation.is_some() {
                    return Err(CKR_OPERATION_ACTIVE.into());
                }
                context_operation = Some((operation.slot_id, operation.context_specific_extended));
            }
            let (slot_id, extended) = context_operation.ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            ctx.reconcile_login_state(slot_id);
            if !ctx.is_slot_logged_in(slot_id) {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            ctx._get_slot_mut(slot_id)?
                .login_context_specific(pin, extended)?;
            return Ok(());
        }
        if user_type != CKU_USER as CK_USER_TYPE {
            return Err(CKR_USER_TYPE_INVALID.into());
        }
        ctx.reconcile_login_state(slot_id);
        if ctx.is_slot_logged_in(slot_id) {
            return Err(CKR_USER_ALREADY_LOGGED_IN.into());
        }
        let pin = from_raw_parts(pin, pin_len as usize)?;
        ctx._get_slot_mut(slot_id)?.login(pin)?;
        ctx.logged_in_slots.insert(slot_id);
        if ctx.get_slot(slot_id)?.is_yubihsm() {
            if let Err(error) = ctx.refresh_slot_token_objects(slot_id) {
                let _ = ctx._get_slot_mut(slot_id)?.logout();
                ctx.clear_login_state(slot_id);
                return Err(error);
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_Login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *mut ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Login called with {:?}",
        (session_handle, user_type, pin, pin_len)
    );
    map(login(session_handle, user_type, pin, pin_len))
}

fn logout(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let slot_id = ctx._get_session(session_handle)?.1.slotID();
        ctx.reconcile_login_state(slot_id);
        if !ctx.is_slot_logged_in(slot_id) {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        ctx.logout_slot(slot_id)
    })
}

#[no_mangle]
pub extern "C" fn C_Logout(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_Logout called with {:?}", session_handle);
    map(logout(session_handle))
}

#[no_mangle]
pub extern "C" fn C_CreateObject(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CreateObject called with {:?}",
        (session_handle, templ, count, object)
    );
    match create_object(session_handle, templ, count, object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn create_object(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let object_handle = as_mut(object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mut object = parse_create_object_template(templ)?;
        validate_new_object_access(&object, flags, logged_in)?;
        if ctx.get_slot(slot_id)?.is_yubihsm() {
            let (command, expected_class) = yubihsm_import_command(&object)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            let id = parse_yubihsm_object_id(&response)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            *object_handle = ctx
                .objects
                .iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == expected_class
                        && matches!(object.material, KeyMaterial::YubiHsm { id: object_id, .. } if object_id == id)
                })
                .map(|(handle, _)| *handle)
                .ok_or(CKR_DEVICE_ERROR)?;
            return Ok(());
        }
        object.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(object);
        *object_handle = handle;
        Ok(())
    })
}

fn yubihsm_id(id: &[u8]) -> Result<u16, Error> {
    match id {
        [] => Ok(0),
        [high, low] => Ok(u16::from_be_bytes([*high, *low])),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

fn padded_big_num(value: &openssl::bn::BigNumRef, length: usize) -> Result<Vec<u8>, Error> {
    let encoded = value.to_vec();
    if encoded.len() > length {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let mut padded = vec![0; length];
    padded[length - encoded.len()..].copy_from_slice(&encoded);
    Ok(padded)
}

fn yubihsm_object_parameters(
    object: &TokenObject,
    algorithm: u8,
) -> Result<YubiHsmObjectParameters<'_>, Error> {
    if !object.token {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let mut bits = Vec::new();
    if object.sign
        && (object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || is_hmac_key_type(object.key_type))
    {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x05, 0x06]);
        } else if object.key_type == CKK_EC as CK_KEY_TYPE {
            bits.push(0x07);
        } else if object.key_type == CKK_EC_EDWARDS as CK_KEY_TYPE {
            bits.push(0x08);
        } else {
            bits.push(0x16);
        }
    }
    if object.verify {
        bits.push(0x17);
    }
    if object.derive {
        bits.push(0x0b);
    }
    if object.decrypt {
        if object.key_type == CKK_RSA as CK_KEY_TYPE {
            bits.extend([0x09, 0x0a]);
        } else {
            bits.extend([0x32, 0x34]);
        }
    }
    if object.encrypt {
        bits.extend([0x33, 0x35]);
    }
    if object.extractable
        && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
        && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
    {
        bits.push(0x10);
    }
    Ok(YubiHsmObjectParameters {
        id: yubihsm_id(&object.id)?,
        label: &object.label,
        domains: 0xffff,
        capabilities: yubihsm_capabilities(&bits),
        algorithm,
    })
}

fn yubihsm_import_command(
    object: &TokenObject,
) -> Result<(YubiHsmCommand, CK_OBJECT_CLASS), Error> {
    match &object.material {
        KeyMaterial::RsaPrivate(key) if object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
            let (algorithm, component_length) = match key.size() {
                256 => (YUBIHSM_ALGO_RSA_2048, 128),
                384 => (YUBIHSM_ALGO_RSA_3072, 192),
                512 => (YUBIHSM_ALGO_RSA_4096, 256),
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            let mut value =
                padded_big_num(key.p().ok_or(CKR_TEMPLATE_INCOMPLETE)?, component_length)?;
            value.extend_from_slice(&padded_big_num(
                key.q().ok_or(CKR_TEMPLATE_INCOMPLETE)?,
                component_length,
            )?);
            Ok((
                YubiHsmCommand::put_object(
                    YubiHsmCommandCode::PutAsymmetricKey,
                    &yubihsm_object_parameters(object, algorithm)?,
                    &value,
                )?,
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            ))
        }
        KeyMaterial::Secret(value) if object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS => {
            let (code, algorithm) = if object.key_type == CKK_AES as CK_KEY_TYPE {
                let algorithm = match value.len() {
                    16 => YUBIHSM_ALGO_AES128,
                    24 => YUBIHSM_ALGO_AES192,
                    32 => YUBIHSM_ALGO_AES256,
                    _ => return Err(CKR_KEY_SIZE_RANGE.into()),
                };
                (YubiHsmCommandCode::PutSymmetricKey, algorithm)
            } else {
                let algorithm = match object.key_type {
                    x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA1,
                    x if x == CKK_SHA384_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA384,
                    x if x == CKK_SHA512_HMAC as CK_KEY_TYPE => YUBIHSM_ALGO_HMAC_SHA512,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE =>
                    {
                        YUBIHSM_ALGO_HMAC_SHA256
                    }
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                };
                (YubiHsmCommandCode::PutHmacKey, algorithm)
            };
            Ok((
                YubiHsmCommand::put_object(
                    code,
                    &yubihsm_object_parameters(object, algorithm)?,
                    value,
                )?,
                CKO_SECRET_KEY as CK_OBJECT_CLASS,
            ))
        }
        _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
    }
}

fn parse_create_object_template(templ: &[CK_ATTRIBUTE]) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let mut object_template = TokenObjectTemplate::default();
    let mut key_components = HashMap::new();
    for attribute in templ {
        if is_key_component_attribute(attribute.type_) {
            key_components.insert(
                attribute.type_,
                Zeroizing::new(read_attribute_value(attribute).map_err(Error::from)?),
            );
            continue;
        }
        object_template
            .apply_attribute(attribute)
            .map_err(Error::from)?;
    }
    let mut object = object_template.into_object().map_err(Error::from)?;
    object.material = build_imported_key_material(&object, key_components)?;
    Ok(object)
}

fn is_key_component_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_MODULUS as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_PRIME_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE
            || x == CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE
            || x == CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE
    )
}

fn required_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<BigNum, Error> {
    let value = components
        .remove(&attribute_type)
        .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if value.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
    }
    BigNum::from_slice(&value).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
}

fn optional_big_num(
    components: &mut HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Option<BigNum>, Error> {
    components
        .remove(&attribute_type)
        .map(|value| {
            if value.is_empty() {
                Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
            } else {
                BigNum::from_slice(&value)
                    .map(Some)
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID.into())
            }
        })
        .unwrap_or(Ok(None))
}

fn build_imported_key_material(
    object: &TokenObject,
    mut components: HashMap<CK_ATTRIBUTE_TYPE, Zeroizing<Vec<u8>>>,
) -> Result<KeyMaterial, Error> {
    let material = match (object.class, object.key_type) {
        (class, key_type)
            if class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                && matches!(
                    key_type,
                    x if x == CKK_GENERIC_SECRET as CK_KEY_TYPE
                        || x == CKK_AES as CK_KEY_TYPE
                        || x == CKK_SHA_1_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA256_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA384_HMAC as CK_KEY_TYPE
                        || x == CKK_SHA512_HMAC as CK_KEY_TYPE
                ) =>
        {
            let value = components
                .remove(&(CKA_VALUE as CK_ATTRIBUTE_TYPE))
                .ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            if value.is_empty() {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }
            KeyMaterial::Secret(value)
        }
        (class, key_type)
            if class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let key = Rsa::from_public_components(modulus, exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
            KeyMaterial::RsaPublic(key)
        }
        (class, key_type)
            if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                && key_type == CKK_RSA as CK_KEY_TYPE =>
        {
            let modulus = required_big_num(&mut components, CKA_MODULUS as CK_ATTRIBUTE_TYPE)?;
            let public_exponent =
                required_big_num(&mut components, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let private_exponent =
                required_big_num(&mut components, CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE)?;
            let mut builder = RsaPrivateKeyBuilder::new(modulus, public_exponent, private_exponent)
                .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

            let prime_1 = optional_big_num(&mut components, CKA_PRIME_1 as CK_ATTRIBUTE_TYPE)?;
            let prime_2 = optional_big_num(&mut components, CKA_PRIME_2 as CK_ATTRIBUTE_TYPE)?;
            let has_factors = prime_1.is_some() || prime_2.is_some();
            builder = match (prime_1, prime_2) {
                (Some(prime_1), Some(prime_2)) => builder
                    .set_factors(prime_1, prime_2)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };

            let exponent_1 =
                optional_big_num(&mut components, CKA_EXPONENT_1 as CK_ATTRIBUTE_TYPE)?;
            let exponent_2 =
                optional_big_num(&mut components, CKA_EXPONENT_2 as CK_ATTRIBUTE_TYPE)?;
            let coefficient =
                optional_big_num(&mut components, CKA_COEFFICIENT as CK_ATTRIBUTE_TYPE)?;
            builder = match (exponent_1, exponent_2, coefficient) {
                (Some(exponent_1), Some(exponent_2), Some(coefficient)) if has_factors => builder
                    .set_crt_params(exponent_1, exponent_2, coefficient)
                    .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                (None, None, None) => builder,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };
            KeyMaterial::RsaPrivate(builder.build())
        }
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };
    if components.is_empty() {
        Ok(material)
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

fn validate_unique_template(templ: &[CK_ATTRIBUTE]) -> Result<(), Error> {
    let mut types = HashSet::new();
    if templ.iter().all(|attribute| types.insert(attribute.type_)) {
        Ok(())
    } else {
        Err(CKR_TEMPLATE_INCONSISTENT.into())
    }
}

#[no_mangle]
pub extern "C" fn C_CopyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    new_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_CopyObject called with {:?}",
        (session_handle, object, templ, count, new_object)
    );
    match copy_object(session_handle, object, templ, count, new_object) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn copy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    new_object: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let new_object_handle = as_mut(new_object)?;
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let mut copied_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?
            .clone();
        if matches!(copied_object.material, KeyMaterial::YubiHsm { .. }) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = copied_object.set_copy_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }
        if rv != CKR_OK as CK_RV {
            return Err(rv.into());
        }
        validate_new_object_access(&copied_object, flags, logged_in)?;
        copied_object.set_owner(session_handle, slot_id);
        copied_object.unique_id.clear();

        let handle = ctx.insert_object(copied_object);
        *new_object_handle = handle;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_DestroyObject called with {:?}",
        (session_handle, object)
    );
    map(destroy_object(session_handle, object))
}

fn destroy_object(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?
            .clone();
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if let KeyMaterial::YubiHsm {
            id, object_type, ..
        } = stored_object.material
        {
            if matches!(object_type, YUBIHSM_PUBLIC_KEY | YUBIHSM_WRAP_KEY_PUBLIC) {
                return Ok(());
            }
            ctx._get_session(session_handle)?
                .1
                .yubihsm_command(&YubiHsmCommand::delete_object(id, object_type & !0x80))?;
            let removed: Vec<_> = ctx
                .objects
                .iter()
                .filter_map(|(handle, candidate)| match candidate.material {
                    KeyMaterial::YubiHsm {
                        id: candidate_id,
                        object_type: candidate_type,
                        ..
                    } if candidate.slot_id == Some(slot_id)
                        && candidate_id == id
                        && candidate_type & !0x80 == object_type & !0x80 =>
                    {
                        Some(*handle)
                    }
                    _ => None,
                })
                .collect();
            for handle in removed {
                ctx.objects.remove(&handle);
                remove_object_from_find_operations(&mut ctx.find_operations, handle);
            }
            return Ok(());
        }
        ctx.objects.remove(&object);
        remove_object_from_find_operations(&mut ctx.find_operations, object);
        Ok(())
    })
}

fn remove_object_from_find_operations(
    find_operations: &mut HashMap<CK_SESSION_HANDLE, FindOperation>,
    object: CK_OBJECT_HANDLE,
) {
    for operation in find_operations.values_mut() {
        let already_returned = operation.next.min(operation.objects.len());
        let removed_before_cursor = operation.objects[..already_returned]
            .iter()
            .filter(|&&handle| handle == object)
            .count();
        operation.objects.retain(|&handle| handle != object);
        operation.next -= removed_before_cursor;
    }
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetObjectSize called with {:?}",
        (session_handle, object, size)
    );
    map(get_object_size(session_handle, object, size))
}

fn get_object_size(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> Result<(), Error> {
    let size = as_mut(size)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        *size = object.size();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match get_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn get_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = _from_raw_parts_mut(templ, count as usize)?;
    with_context(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if attribute.type_ == CKA_VALUE as CK_ATTRIBUTE_TYPE {
                match &object.material {
                    KeyMaterial::DerivedSecret(value) => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(value) if !object.sensitive && object.extractable => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(_) => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
                    }
                    KeyMaterial::PivCertificate { .. }
                    | KeyMaterial::PivAttestation { .. }
                    | KeyMaterial::OpenPgpCertificate { .. } => {
                        match object.attribute_value(attribute.type_) {
                            Some(value) => {
                                if let Err(e) = write_attribute_value(attribute, &value) {
                                    rv = combine_attribute_rv(rv, e);
                                }
                            }
                            None => {
                                attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                                rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                            }
                        }
                    }
                    KeyMaterial::YubiHsm {
                        id,
                        object_type,
                        value,
                        ..
                    } if *object_type == YUBIHSM_OPAQUE => {
                        if value.borrow().is_none() {
                            let payload = ctx._get_session(session_handle)?.1.yubihsm_command(
                                &YubiHsmCommand::get_object(YubiHsmCommandCode::GetOpaque, *id)?,
                            )?;
                            *value.borrow_mut() = Some(payload);
                        }
                        let payload = value.borrow();
                        if let Err(e) = write_attribute_value(
                            attribute,
                            payload.as_deref().ok_or(CKR_DEVICE_ERROR)?,
                        ) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    _ => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                    }
                }
                continue;
            }
            match object.attribute_value(attribute.type_) {
                Some(value) => {
                    if let Err(e) = write_attribute_value(attribute, &value) {
                        rv = combine_attribute_rv(rv, e);
                    }
                }
                None => {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                    rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
            }
        }

        if rv == CKR_OK as CK_RV {
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

fn write_attribute_value(attribute: &mut CK_ATTRIBUTE, value: &[u8]) -> Result<(), CK_RV> {
    let required_len = value.len() as CK_ULONG;
    if attribute.pValue.is_null() {
        attribute.ulValueLen = required_len;
        return Ok(());
    }
    if attribute.ulValueLen < required_len {
        attribute.ulValueLen = required_len;
        return Err(CKR_BUFFER_TOO_SMALL as CK_RV);
    }

    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), attribute.pValue as *mut u8, value.len());
    }
    attribute.ulValueLen = required_len;
    Ok(())
}

fn read_attribute_value(attribute: &CK_ATTRIBUTE) -> Result<Vec<u8>, CK_RV> {
    if attribute.ulValueLen > 0 && attribute.pValue.is_null() {
        return Err(CKR_ARGUMENTS_BAD as CK_RV);
    }
    let value = if attribute.ulValueLen == 0 {
        &[]
    } else {
        unsafe {
            slice::from_raw_parts(attribute.pValue as *const u8, attribute.ulValueLen as usize)
        }
    };
    Ok(value.to_vec())
}

fn read_ulong_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<CK_ULONG, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?;
    let mut bytes = [0u8; ::std::mem::size_of::<CK_ULONG>()];
    bytes.copy_from_slice(&value);
    Ok(CK_ULONG::from_ne_bytes(bytes))
}

fn read_bool_template_attribute(attribute: &CK_ATTRIBUTE) -> Result<bool, CK_RV> {
    if attribute.ulValueLen as usize != ::std::mem::size_of::<CK_BBOOL>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
    }
    let value = read_attribute_value(attribute)?[0];
    match value {
        x if x == CK_FALSE as CK_BBOOL => Ok(false),
        x if x == CK_TRUE as CK_BBOOL => Ok(true),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV),
    }
}

fn combine_attribute_rv(current: CK_RV, next: CK_RV) -> CK_RV {
    if current == CKR_ARGUMENTS_BAD as CK_RV {
        current
    } else if next == CKR_ARGUMENTS_BAD as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_SENSITIVE as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_TYPE_INVALID as CK_RV {
        next
    } else if current == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        current
    } else if next == CKR_ATTRIBUTE_READ_ONLY as CK_RV {
        next
    } else if current == CKR_BUFFER_TOO_SMALL as CK_RV {
        current
    } else {
        next
    }
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_SetAttributeValue called with {:?}",
        (session_handle, object, templ, count)
    );
    match set_attribute_value(session_handle, object, templ, count) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn set_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    validate_unique_template(templ)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let stored_object = ctx
            .objects
            .get(&object)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if matches!(stored_object.material, KeyMaterial::YubiHsm { .. }) {
            return Err(CKR_ATTRIBUTE_READ_ONLY.into());
        }
        let mut updated_object = stored_object.clone();

        let mut rv = CKR_OK as CK_RV;
        for attribute in templ {
            if let Err(e) = updated_object.set_attribute_value(attribute) {
                rv = combine_attribute_rv(rv, e);
            }
        }

        if rv == CKR_OK as CK_RV {
            ctx.objects.insert(object, updated_object);
            Ok(())
        } else {
            Err(rv.into())
        }
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjectsInit called with {:?}",
        (session_handle, templ, count)
    );
    if count > 0 && templ.is_null() {
        return CKR_ARGUMENTS_BAD.into();
    }
    map(find_objects_init(session_handle, templ, count))
}

fn find_objects_init(
    session_handle: CK_SESSION_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), Error> {
    let templ = from_raw_parts(templ, count as usize)?;
    let templ: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = templ
        .iter()
        .map(|attribute| {
            Ok((
                attribute.type_,
                read_attribute_value(attribute).map_err(Error::from)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.find_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        ctx.insert_session_objects(slot_id, session_handle)?;
        log!(2, "C_FindObjectsInit template {:?}", templ);
        let mut objects: Vec<CK_OBJECT_HANDLE> = ctx
            .objects
            .iter()
            .filter(|(_handle, object)| {
                object.is_visible_to(session_handle, slot_id, logged_in)
                    && object.matches_template(&templ)
            })
            .map(|(handle, _object)| *handle)
            .collect();
        objects.sort();
        ctx.find_operations
            .insert(session_handle, FindOperation { objects, next: 0 });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    session_handle: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: ::std::os::raw::c_ulong,
    object_count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_FindObjects called with {:?}",
        (session_handle, object, max_object_count, object_count)
    );
    map(find_objects(
        session_handle,
        object,
        max_object_count,
        object_count,
    ))
}

fn find_objects(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    object_count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let object_count = as_mut(object_count)?;
    let output = _from_raw_parts_mut(object, max_object_count as usize)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .find_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;

        let remaining = &operation.objects[operation.next..];
        let returned = remaining.len().min(max_object_count as usize);
        output[..returned].copy_from_slice(&remaining[..returned]);
        operation.next += returned;
        *object_count = returned as CK_ULONG;
        log!(2, "C_FindObjects returning {:?}", &output[..returned]);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    log!(2, "C_FindObjectsFinal called with {:?}", session_handle);
    map(find_objects_final(session_handle))
}

fn find_objects_final(session_handle: CK_SESSION_HANDLE) -> Result<(), Error> {
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        ctx.find_operations
            .remove(&session_handle)
            .map(|_| ())
            .ok_or(CKR_OPERATION_NOT_INITIALIZED.into())
    })
}

#[no_mangle]
pub extern "C" fn C_EncryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    map(crypt_init(session_handle, mechanism, key, true))
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    encrypted_data: *mut ::std::os::raw::c_uchar,
    encrypted_data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        data,
        data_len,
        encrypted_data,
        encrypted_data_len,
        true,
    ))
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    session_handle: CK_SESSION_HANDLE,
    _last_encrypted_part: *mut ::std::os::raw::c_uchar,
    _last_encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    map(crypt_init(session_handle, mechanism, key, false))
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    session_handle: CK_SESSION_HANDLE,
    encrypted_data: *mut ::std::os::raw::c_uchar,
    encrypted_data_len: ::std::os::raw::c_ulong,
    data: *mut ::std::os::raw::c_uchar,
    data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(crypt(
        session_handle,
        encrypted_data,
        encrypted_data_len,
        data,
        data_len,
        false,
    ))
}

fn parse_gcm_parameters(mechanism: &CK_MECHANISM) -> Result<GcmParameters, Error> {
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_GCM_PARAMS>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = _as_ref(mechanism.pParameter as CK_GCM_PARAMS_PTR)?;
    let iv_len = usize::try_from(parameters.ulIvLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let aad_len = usize::try_from(parameters.ulAADLen)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let tag_bits = usize::try_from(parameters.ulTagBits)
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    if iv_len == 0
        || iv_len > u32::MAX as usize
        || aad_len > u32::MAX as usize
        || tag_bits > 128
        || parameters.pIv.is_null()
        || (aad_len != 0 && parameters.pAAD.is_null())
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(GcmParameters {
        iv: from_raw_parts(parameters.pIv as *const u8, iv_len)?.to_vec(),
        aad: from_raw_parts(parameters.pAAD as *const u8, aad_len)?.to_vec(),
        tag_bits,
    })
}

fn crypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
    encrypting: bool,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;
        let operations = if encrypting {
            &ctx.encrypt_operations
        } else {
            &ctx.decrypt_operations
        };
        if operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }
        let mechanism = _as_ref(mechanism)?;
        let (iv, gcm, oaep) = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_AES_ECB as CK_MECHANISM_TYPE =>
            {
                if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                (None, None, None)
            }
            x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => {
                if mechanism.ulParameterLen != 16 || mechanism.pParameter.is_null() {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let bytes = from_raw_parts(mechanism.pParameter as *const u8, 16)?;
                (
                    Some(bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?),
                    None,
                    None,
                )
            }
            x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                (None, Some(parse_gcm_parameters(mechanism)?), None)
            }
            x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                if mechanism.ulParameterLen as usize
                    != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_OAEP_PARAMS_PTR)?;
                if parameters.source != CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let digest = digest_for_hash_mechanism(parameters.hashAlg)?;
                let mgf = match parameters.mgf {
                    x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => 32,
                    x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => 33,
                    x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => 34,
                    x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => 35,
                    x if x == CKG_MGF1_SHA224 as CK_RSA_PKCS_MGF_TYPE => 36,
                    x if x == CKG_MGF1_SHA3_224 as CK_RSA_PKCS_MGF_TYPE => 37,
                    x if x == CKG_MGF1_SHA3_256 as CK_RSA_PKCS_MGF_TYPE => 38,
                    x if x == CKG_MGF1_SHA3_384 as CK_RSA_PKCS_MGF_TYPE => 39,
                    x if x == CKG_MGF1_SHA3_512 as CK_RSA_PKCS_MGF_TYPE => 40,
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
                };
                let label = from_raw_parts(
                    parameters.pSourceData as *const u8,
                    parameters.ulSourceDataLen as usize,
                )?;
                (
                    None,
                    None,
                    Some((mgf, parameters.hashAlg, hash(digest, label)?.to_vec())),
                )
            }
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        let object = ctx
            .objects
            .get(&key)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if (encrypting && !object.encrypt) || (!encrypting && !object.decrypt) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let required_capability = match (mechanism.mechanism, encrypting) {
            (mechanism, false) if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE => 0x09,
            (mechanism, false) if mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => 0x0a,
            (mechanism, false) if mechanism == CKM_AES_ECB as CK_MECHANISM_TYPE => 0x32,
            (mechanism, true) if mechanism == CKM_AES_ECB as CK_MECHANISM_TYPE => 0x33,
            (mechanism, false) if mechanism == CKM_AES_CBC as CK_MECHANISM_TYPE => 0x34,
            (mechanism, true) if mechanism == CKM_AES_CBC as CK_MECHANISM_TYPE => 0x35,
            (mechanism, _) if mechanism == CKM_AES_GCM as CK_MECHANISM_TYPE => 0x33,
            _ => 0,
        };
        if required_capability != 0
            && !yubihsm_material_has_capability(&object.material, required_capability)
        {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let valid_key = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
            {
                object.key_type == CKK_RSA as CK_KEY_TYPE
                    && if encrypting {
                        matches!(object.material, KeyMaterial::RsaPublic(_))
                    } else {
                        matches!(
                            object.material,
                            KeyMaterial::YubiHsm { .. }
                                | KeyMaterial::PivPrivate { .. }
                                | KeyMaterial::OpenPgpPrivate { .. }
                        )
                    }
            }
            _ => {
                object.key_type == CKK_AES as CK_KEY_TYPE
                    && matches!(object.material, KeyMaterial::YubiHsm { .. })
            }
        };
        if !valid_key {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let operation = CryptOperation {
            key: object.material.clone(),
            slot_id,
            requires_login: object.private,
            context_specific_extended: matches!(
                &object.material,
                KeyMaterial::OpenPgpPrivate { .. }
            ),
            mechanism: mechanism.mechanism,
            iv,
            gcm,
            oaep,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
        };
        if encrypting {
            ctx.encrypt_operations.insert(session_handle, operation);
        } else {
            ctx.decrypt_operations.insert(session_handle, operation);
        }
        Ok(())
    })
}

fn yubihsm_rsa_length(algorithm: u8) -> Result<usize, Error> {
    match algorithm {
        YUBIHSM_ALGO_RSA_2048 => Ok(256),
        YUBIHSM_ALGO_RSA_3072 => Ok(384),
        YUBIHSM_ALGO_RSA_4096 => Ok(512),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

const AES_BLOCK_LENGTH: usize = 16;
const YUBIHSM_ECB_CHUNK_LENGTH: usize = 2016;

fn ghash_multiply(left: u128, right: u128) -> u128 {
    const REDUCTION: u128 = 0xe1000000000000000000000000000000;
    let mut product = 0;
    let mut factor = right;
    for bit in 0..128 {
        if left & (1u128 << (127 - bit)) != 0 {
            product ^= factor;
        }
        factor = if factor & 1 == 0 {
            factor >> 1
        } else {
            (factor >> 1) ^ REDUCTION
        };
    }
    product
}

fn ghash_update(mut hash: u128, key: u128, data: &[u8]) -> u128 {
    for chunk in data.chunks(AES_BLOCK_LENGTH) {
        let mut block = [0; AES_BLOCK_LENGTH];
        block[..chunk.len()].copy_from_slice(chunk);
        hash = ghash_multiply(hash ^ u128::from_be_bytes(block), key);
    }
    hash
}

fn ghash(key: [u8; AES_BLOCK_LENGTH], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], Error> {
    let aad_bits = u64::try_from(aad.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let ciphertext_bits = u64::try_from(ciphertext.len().checked_mul(8).ok_or(CKR_DATA_LEN_RANGE)?)
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    let key = u128::from_be_bytes(key);
    let mut hash = ghash_update(0, key, aad);
    hash = ghash_update(hash, key, ciphertext);
    let mut lengths = [0; AES_BLOCK_LENGTH];
    lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    Ok(ghash_multiply(hash ^ u128::from_be_bytes(lengths), key).to_be_bytes())
}

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_LENGTH]) {
    let value = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&value.to_be_bytes());
}

fn gcm_tag(full_tag: [u8; AES_BLOCK_LENGTH], tag_bits: usize) -> Vec<u8> {
    let tag_length = tag_bits.div_ceil(8);
    let mut tag = full_tag[..tag_length].to_vec();
    if !tag_bits.is_multiple_of(8) {
        let mask = 0xff << (8 - tag_bits % 8);
        if let Some(last) = tag.last_mut() {
            *last &= mask;
        }
    }
    tag
}

fn aes_gcm<F>(
    parameters: &GcmParameters,
    input: &[u8],
    encrypting: bool,
    mut encrypt_blocks: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, Error>,
{
    if parameters.iv.is_empty() || parameters.tag_bits > 128 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let tag_length = parameters.tag_bits.div_ceil(8);
    let (payload, supplied_tag) = if encrypting {
        (input, None)
    } else {
        if input.len() < tag_length {
            return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
        }
        let split = input.len() - tag_length;
        (&input[..split], Some(&input[split..]))
    };
    let block_count = payload.len().div_ceil(AES_BLOCK_LENGTH);
    if block_count > u32::MAX as usize - 2 {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }

    let hash_subkey = encrypt_blocks(&[0; AES_BLOCK_LENGTH])?;
    let hash_subkey: [u8; AES_BLOCK_LENGTH] = hash_subkey
        .as_slice()
        .try_into()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut initial_counter = if parameters.iv.len() == 12 {
        let mut counter = [0; AES_BLOCK_LENGTH];
        counter[..12].copy_from_slice(&parameters.iv);
        counter[15] = 1;
        counter
    } else {
        ghash(hash_subkey, &[], &parameters.iv)?
    };

    let counter_capacity = (block_count + 1)
        .checked_mul(AES_BLOCK_LENGTH)
        .ok_or_else(|| {
            if encrypting {
                Error::from(CKR_DATA_LEN_RANGE)
            } else {
                Error::from(CKR_ENCRYPTED_DATA_LEN_RANGE)
            }
        })?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    counter_blocks.extend_from_slice(&initial_counter);
    for _ in 0..block_count {
        increment_gcm_counter(&mut initial_counter);
        counter_blocks.extend_from_slice(&initial_counter);
    }
    let encrypted_counters = encrypt_blocks(&counter_blocks)?;
    if encrypted_counters.len() != counter_blocks.len() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut transformed = Vec::with_capacity(payload.len());
    for (block, key_stream) in payload
        .chunks(AES_BLOCK_LENGTH)
        .zip(encrypted_counters[AES_BLOCK_LENGTH..].chunks(AES_BLOCK_LENGTH))
    {
        transformed.extend(
            block
                .iter()
                .zip(key_stream)
                .map(|(left, right)| left ^ right),
        );
    }
    let ciphertext = if encrypting { &transformed } else { payload };
    let hash = ghash(hash_subkey, &parameters.aad, ciphertext)?;
    let mut full_tag = [0; AES_BLOCK_LENGTH];
    for ((output, mask), value) in full_tag
        .iter_mut()
        .zip(&encrypted_counters[..AES_BLOCK_LENGTH])
        .zip(hash)
    {
        *output = mask ^ value;
    }
    let expected_tag = gcm_tag(full_tag, parameters.tag_bits);
    if let Some(supplied_tag) = supplied_tag {
        if !openssl::memcmp::eq(&expected_tag, supplied_tag) {
            transformed.fill(0);
            return Err(CKR_ENCRYPTED_DATA_INVALID.into());
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&expected_tag);
        Ok(transformed)
    }
}

fn yubihsm_encrypt_ecb_blocks(
    ctx: &mut Context,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    blocks: &[u8],
) -> Result<Vec<u8>, Error> {
    if !blocks.len().is_multiple_of(AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encrypted = Vec::with_capacity(blocks.len());
    for chunk in blocks.chunks(YUBIHSM_ECB_CHUNK_LENGTH) {
        let command = YubiHsmCommand::key_data(YubiHsmCommandCode::EncryptEcb, key_id, chunk)?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        if response.len() != chunk.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        encrypted.extend_from_slice(&response);
    }
    Ok(encrypted)
}

fn crypt(
    session_handle: CK_SESSION_HANDLE,
    input: *const u8,
    input_len: CK_ULONG,
    output: *mut u8,
    output_len: CK_ULONG_PTR,
    encrypting: bool,
) -> Result<(), Error> {
    if output_len.is_null() {
        let _ = with_context_mut(|ctx| {
            ctx.encrypt_operations.remove(&session_handle);
            ctx.decrypt_operations.remove(&session_handle);
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = as_mut(output_len)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = if encrypting {
            ctx.encrypt_operations.get(&session_handle)
        } else {
            ctx.decrypt_operations.get(&session_handle)
        }
        .cloned()
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.encrypt_operations.remove(&session_handle);
            ctx.decrypt_operations.remove(&session_handle);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let input = match from_raw_parts(input, input_len as usize) {
            Ok(input) => input,
            Err(error) => {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(error);
            }
        };
        let required = if operation.mechanism == CKM_AES_GCM as CK_MECHANISM_TYPE {
            let Some(parameters) = operation.gcm.as_ref() else {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let tag_length = parameters.tag_bits.div_ceil(8);
            let required = if encrypting {
                input.len().checked_add(tag_length)
            } else {
                input.len().checked_sub(tag_length)
            };
            let Some(required) = required else {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(if encrypting {
                    CKR_DATA_LEN_RANGE.into()
                } else {
                    CKR_ENCRYPTED_DATA_LEN_RANGE.into()
                });
            };
            required
        } else {
            match &operation.key {
                KeyMaterial::RsaPublic(key) => key.size() as usize,
                KeyMaterial::PivPrivate { modulus, .. } if !encrypting => modulus.len(),
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !encrypting => modulus.len(),
                KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                    match yubihsm_rsa_length(*algorithm) {
                        Ok(length) => length,
                        Err(error) => {
                            ctx.encrypt_operations.remove(&session_handle);
                            ctx.decrypt_operations.remove(&session_handle);
                            return Err(error);
                        }
                    }
                }
                KeyMaterial::YubiHsm { .. } => input.len(),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        };
        if output.is_null() {
            *output_len = required as CK_ULONG;
            return Ok(());
        }
        let result = (|| -> Result<Vec<u8>, Error> {
            match &operation.key {
                KeyMaterial::RsaPublic(key)
                    if encrypting && operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE =>
                {
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(input, &mut encrypted, Padding::PKCS1)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::RsaPublic(key)
                    if encrypting && operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE =>
                {
                    if input.len() != key.size() as usize {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(input, &mut encrypted, Padding::NONE)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::RsaPublic(key)
                    if encrypting
                        && operation.mechanism == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
                {
                    let (mgf, hash_mechanism, label_digest) =
                        operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    let encoded = rsa_oaep_pad(
                        input,
                        key.size() as usize,
                        *mgf,
                        *hash_mechanism,
                        label_digest,
                    )?;
                    let mut encrypted = vec![0; key.size() as usize];
                    let written = key.public_encrypt(&encoded, &mut encrypted, Padding::NONE)?;
                    encrypted.truncate(written);
                    Ok(encrypted)
                }
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } if !encrypting => {
                    let raw = ctx._get_session(session_handle)?.1.piv_decipher(
                        *slot,
                        *algorithm,
                        input,
                        operation.piv_pin_policy.unwrap_or_default(),
                    )?;
                    let raw = if let Some(expected) = algorithm.rsa_input_length() {
                        if raw.len() > expected {
                            return Err(CKR_DEVICE_ERROR.into());
                        }
                        if raw.len() < expected {
                            let mut padded = vec![0; expected - raw.len()];
                            padded.extend_from_slice(&raw);
                            padded
                        } else {
                            raw
                        }
                    } else {
                        raw
                    };
                    match operation.mechanism {
                        x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE => Ok(raw),
                        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => rsa_pkcs1_v1_5_unpad(&raw),
                        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                            let (mgf, hash_mechanism, label_digest) =
                                operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                            rsa_oaep_unpad(&raw, *mgf, *hash_mechanism, label_digest)
                        }
                        _ => Err(CKR_MECHANISM_INVALID.into()),
                    }
                }
                KeyMaterial::OpenPgpPrivate { algorithm, .. } if !encrypting => {
                    if !matches!(algorithm, OpenPgpAlgorithm::Rsa { .. }) {
                        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
                    }
                    ctx._get_session(session_handle)?.1.openpgp_decipher(
                        input,
                        operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE,
                    )
                }
                KeyMaterial::YubiHsm { id, .. } => {
                    let command = match operation.mechanism {
                        x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE && !encrypting => {
                            YubiHsmCommand::key_data(YubiHsmCommandCode::DecryptPkcs1, *id, input)?
                        }
                        x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE && !encrypting => {
                            let (mgf, _hash_mechanism, label_digest) =
                                operation.oaep.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                            YubiHsmCommand::decrypt_oaep(*id, *mgf, input, label_digest)?
                        }
                        x if x == CKM_AES_ECB as CK_MECHANISM_TYPE => YubiHsmCommand::key_data(
                            if encrypting {
                                YubiHsmCommandCode::EncryptEcb
                            } else {
                                YubiHsmCommandCode::DecryptEcb
                            },
                            *id,
                            input,
                        )?,
                        x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => YubiHsmCommand::crypt_cbc(
                            if encrypting {
                                YubiHsmCommandCode::EncryptCbc
                            } else {
                                YubiHsmCommandCode::DecryptCbc
                            },
                            *id,
                            operation.iv.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            input,
                        )?,
                        x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                            return aes_gcm(
                                operation.gcm.as_ref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                input,
                                encrypting,
                                |blocks| {
                                    yubihsm_encrypt_ecb_blocks(ctx, session_handle, *id, blocks)
                                },
                            );
                        }
                        _ => return Err(CKR_MECHANISM_INVALID.into()),
                    };
                    ctx._get_session(session_handle)?
                        .1
                        .yubihsm_command(&command)
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                ctx.encrypt_operations.remove(&session_handle);
                ctx.decrypt_operations.remove(&session_handle);
                return Err(error);
            }
        };
        if *output_len < result.len() as CK_ULONG {
            *output_len = result.len() as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        unsafe { ptr::copy_nonoverlapping(result.as_ptr(), output, result.len()) };
        *output_len = result.len() as CK_ULONG;
        ctx.encrypt_operations.remove(&session_handle);
        ctx.decrypt_operations.remove(&session_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    session_handle: CK_SESSION_HANDLE,
    _last_part: *mut ::std::os::raw::c_uchar,
    _last_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_Digest(
    session_handle: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestKey(session_handle: CK_SESSION_HANDLE, _key: CK_OBJECT_HANDLE) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    session_handle: CK_SESSION_HANDLE,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_SignInit called with {:?}",
        (session_handle, mechanism, key)
    );
    map(sign_init(session_handle, mechanism, key))
}

fn sign_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx.sign_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = _as_ref(mechanism)?;
        let pss = if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR)?;
            let mgf = match parameters.mgf {
                x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => 32,
                x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => 33,
                x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => 34,
                x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => 35,
                x if x == CKG_MGF1_SHA224 as CK_RSA_PKCS_MGF_TYPE => 36,
                x if x == CKG_MGF1_SHA3_224 as CK_RSA_PKCS_MGF_TYPE => 37,
                x if x == CKG_MGF1_SHA3_256 as CK_RSA_PKCS_MGF_TYPE => 38,
                x if x == CKG_MGF1_SHA3_384 as CK_RSA_PKCS_MGF_TYPE => 39,
                x if x == CKG_MGF1_SHA3_512 as CK_RSA_PKCS_MGF_TYPE => 40,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
            };
            let salt_length = u16::try_from(parameters.sLen)
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
            Some((mgf, salt_length, parameters.hashAlg))
        } else if piv_is_pss_mechanism(mechanism.mechanism) {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let digest =
                piv_hash_mechanism(mechanism.mechanism).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let hash = pss_hash_mechanism(mechanism.mechanism)?;
            Some((0, digest.size() as u16, hash))
        } else {
            if !matches!(
                mechanism.mechanism,
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                    || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
                    || x == CKM_EDDSA as CK_MECHANISM_TYPE
                    || x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
            ) {
                return Err(CKR_MECHANISM_INVALID.into());
            }
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };

        let object = ctx.objects.get(&key).ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !object.is_visible_to(session_handle, slot_id, logged_in) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        if !object.sign {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let required_capability = match mechanism.mechanism {
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || piv_is_hashed_rsa_pkcs(x) =>
            {
                0x05
            }
            x if piv_is_pss_mechanism(x) => 0x06,
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE => 0x07,
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => 0x08,
            _ => 0x16,
        };
        if !yubihsm_material_has_capability(&object.material, required_capability) {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let expected_key_type = match mechanism.mechanism {
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE || piv_is_hashed_ecdsa(x) => {
                CKK_EC as CK_KEY_TYPE
            }
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => CKK_EC_EDWARDS as CK_KEY_TYPE,
            x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => CKK_SHA_1_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => CKK_SHA256_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => CKK_SHA384_HMAC as CK_KEY_TYPE,
            x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => CKK_SHA512_HMAC as CK_KEY_TYPE,
            _ => CKK_RSA as CK_KEY_TYPE,
        };
        let hmac_yubihsm = is_hmac_key_type(expected_key_type)
            && matches!(object.material, KeyMaterial::YubiHsm { .. });
        if ((!hmac_yubihsm && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            || (hmac_yubihsm && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS))
            || object.key_type != expected_key_type
            || !matches!(
                object.material,
                KeyMaterial::RsaPrivate(_)
                    | KeyMaterial::PivPrivate { .. }
                    | KeyMaterial::OpenPgpPrivate { .. }
                    | KeyMaterial::YubiHsm { .. }
            )
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let piv_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::PivPrivate { algorithm, .. }
                if piv_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        let openpgp_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::OpenPgpPrivate { algorithm, .. }
                if openpgp_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        if !matches!(object.material, KeyMaterial::YubiHsm { .. })
            && !piv_mechanism_supported
            && !openpgp_mechanism_supported
            && !matches!(
                &object.material,
                KeyMaterial::RsaPrivate(_) if mechanism.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            )
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if matches!(object.material, KeyMaterial::YubiHsm { .. })
            && (piv_is_hashed_rsa_pkcs(mechanism.mechanism)
                || piv_is_hashed_ecdsa(mechanism.mechanism)
                || (piv_is_pss_mechanism(mechanism.mechanism)
                    && mechanism.mechanism != CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE))
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        ctx.sign_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: object.private,
                context_specific_extended: false,
                mechanism: mechanism.mechanism,
                pss,
                piv_pin_policy: match &object.material {
                    KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                    _ => None,
                },
                buffer: Vec::new(),
            },
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_Sign(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Sign called with {:?}",
        (session_handle, data, data_len, signature, signature_len)
    );
    map(sign(
        session_handle,
        data,
        data_len,
        signature,
        signature_len,
    ))
}

fn sign(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    if signature_len.is_null() {
        let _ = with_context_mut(|ctx| {
            if ctx._get_session(session_handle).is_ok() {
                ctx.sign_operations.remove(&session_handle);
            }
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_len = as_mut(signature_len)?;
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .sign_operations
            .get(&session_handle)
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.sign_operations.remove(&session_handle);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let data = match from_raw_parts(data, data_len as usize) {
            Ok(data) => data,
            Err(error) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(error);
            }
        };
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let required = match &operation.key {
            KeyMaterial::RsaPrivate(key) => key.size() as usize,
            KeyMaterial::PivPrivate {
                algorithm, modulus, ..
            } => match algorithm {
                piv::Algorithm::Rsa1024
                | piv::Algorithm::Rsa2048
                | piv::Algorithm::Rsa3072
                | piv::Algorithm::Rsa4096 => modulus.len(),
                piv::Algorithm::EccP256 => 64,
                piv::Algorithm::EccP384 => 96,
                piv::Algorithm::Ed25519 => 64,
                piv::Algorithm::X25519 => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::OpenPgpPrivate {
                algorithm, modulus, ..
            } => match algorithm {
                OpenPgpAlgorithm::Rsa { .. } => modulus.len(),
                OpenPgpAlgorithm::Ecdsa(_) => openpgp_ec_coordinate_length(*algorithm).unwrap() * 2,
                OpenPgpAlgorithm::Ed25519 => 64,
                OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                match *algorithm {
                    YUBIHSM_ALGO_RSA_2048 => 256,
                    YUBIHSM_ALGO_RSA_3072 => 384,
                    YUBIHSM_ALGO_RSA_4096 => 512,
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                }
            }
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm) => {
                yubihsm_ec_coordinate_length(*algorithm)? * 2
            }
            KeyMaterial::YubiHsm {
                algorithm: YUBIHSM_ALGO_ED25519,
                ..
            } => 64,
            KeyMaterial::YubiHsm { algorithm, .. } => match *algorithm {
                YUBIHSM_ALGO_HMAC_SHA1 => 20,
                YUBIHSM_ALGO_HMAC_SHA256 => 32,
                YUBIHSM_ALGO_HMAC_SHA384 => 48,
                YUBIHSM_ALGO_HMAC_SHA512 => 64,
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if (operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            || operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
            || piv_is_hashed_rsa_pkcs(operation.mechanism))
            && data.len() > required.saturating_sub(11)
        {
            ctx.sign_operations.remove(&session_handle);
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            let Some((_mgf, _salt, hash)) = operation.pss else {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let expected = digest_for_hash_mechanism(hash)?.size();
            if data.len() != expected {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        }

        if signature.is_null() {
            *signature_len = required as CK_ULONG;
            return Ok(());
        }
        if *signature_len < required as CK_ULONG {
            *signature_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let signature_result = (|| -> Result<Vec<u8>, Error> {
            match &operation.key {
                KeyMaterial::RsaPrivate(private_key) => {
                    let mut signature = vec![0; required];
                    private_key
                        .private_encrypt(data, &mut signature, Padding::PKCS1)
                        .map(|written| {
                            signature.truncate(written);
                            signature
                        })
                        .map_err(Error::from)
                }
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()
                        .map_err(Error::from)?;
                    let input = if piv_is_pss_mechanism(operation.mechanism) {
                        let (mgf, salt_length, hash_mechanism) =
                            operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        let digest = digest.as_deref().unwrap_or(data);
                        encode_rsa_pss(digest, required, hash_mechanism, mgf, salt_length as usize)?
                    } else if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                        let digest = digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        encode_pkcs1_v1_5_signature_input(
                            &piv_digest_info(operation.mechanism, digest)
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            required,
                        )?
                    } else if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                        encode_pkcs1_v1_5_signature_input(data, required)?
                    } else if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                        if data.len() != required {
                            return Err(CKR_DATA_LEN_RANGE.into());
                        }
                        data.to_vec()
                    } else if piv_is_hashed_ecdsa(operation.mechanism) {
                        digest.ok_or(CKR_MECHANISM_PARAM_INVALID)?
                    } else {
                        data.to_vec()
                    };
                    let response = ctx._get_session(session_handle)?.1.piv_sign(
                        *slot,
                        *algorithm,
                        &input,
                        operation.piv_pin_policy.unwrap_or(0),
                    )?;
                    match algorithm {
                        piv::Algorithm::EccP256 => piv_ecdsa_signature(&response, 32),
                        piv::Algorithm::EccP384 => piv_ecdsa_signature(&response, 48),
                        _ => Ok(response),
                    }
                }
                KeyMaterial::OpenPgpPrivate {
                    key_ref,
                    algorithm,
                    pin_policy,
                    ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()
                        .map_err(Error::from)?;
                    let input = match algorithm {
                        OpenPgpAlgorithm::Rsa { .. } => {
                            if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                                piv_digest_info(
                                    operation.mechanism,
                                    digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                )
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?
                            } else {
                                data.to_vec()
                            }
                        }
                        OpenPgpAlgorithm::Ecdsa(_) => digest.unwrap_or_else(|| data.to_vec()),
                        OpenPgpAlgorithm::Ed25519 => data.to_vec(),
                        OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                    };
                    let response = ctx._get_session(session_handle)?.1.openpgp_sign(
                        *key_ref,
                        &input,
                        *pin_policy,
                    )?;
                    match algorithm {
                        OpenPgpAlgorithm::Ecdsa(curve) => {
                            openpgp_signature(&response, curve.coordinate_length().unwrap())
                        }
                        _ => Ok(response),
                    }
                }
                KeyMaterial::YubiHsm { id, algorithm, .. } => {
                    let command = if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignPkcs1, *id, data)?
                    } else if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
                        let (mgf, salt_length, _) =
                            operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        YubiHsmCommand::sign_pss(*id, mgf, salt_length, data)?
                    } else if matches!(
                        operation.mechanism,
                        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
                            || x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
                    ) {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignHmac, *id, data)?
                    } else if operation.mechanism == CKM_EDDSA as CK_MECHANISM_TYPE {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignEddsa, *id, data)?
                    } else {
                        YubiHsmCommand::key_data(YubiHsmCommandCode::SignEcdsa, *id, data)?
                    };
                    let response = ctx
                        ._get_session(session_handle)?
                        .1
                        .yubihsm_command(&command)?;
                    if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                        yubihsm_ecdsa_signature(
                            &response,
                            yubihsm_ec_coordinate_length(*algorithm)?,
                        )
                    } else {
                        Ok(response)
                    }
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let signature_bytes = match signature_result {
            Ok(signature) if signature.len() == required => signature,
            Ok(_) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(CKR_DEVICE_ERROR.into());
            }
            Err(error) => {
                ctx.sign_operations.remove(&session_handle);
                return Err(error);
            }
        };

        unsafe {
            ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
        }
        *signature_len = required as CK_ULONG;
        ctx.sign_operations.remove(&session_handle);
        Ok(())
    })
}

fn yubihsm_ec_coordinate_length(algorithm: u8) -> Result<usize, Error> {
    match algorithm {
        YUBIHSM_ALGO_EC_P224 => Ok(28),
        YUBIHSM_ALGO_EC_P256 | YUBIHSM_ALGO_EC_K256 | YUBIHSM_ALGO_EC_BP256 => Ok(32),
        YUBIHSM_ALGO_EC_P384 | YUBIHSM_ALGO_EC_BP384 => Ok(48),
        YUBIHSM_ALGO_EC_BP512 => Ok(64),
        YUBIHSM_ALGO_EC_P521 => Ok(66),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn yubihsm_ecdsa_signature(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    let signature = EcdsaSig::from_der(signature).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut output = Vec::with_capacity(coordinate_length * 2);
    for coordinate in [signature.r(), signature.s()] {
        let encoded = coordinate.to_vec();
        if encoded.len() > coordinate_length {
            return Err(CKR_DEVICE_ERROR.into());
        }
        output.resize(output.len() + coordinate_length - encoded.len(), 0);
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}

fn encode_pkcs1_v1_5_signature_input(data: &[u8], modulus_size: usize) -> Result<Vec<u8>, Error> {
    if data.len() > modulus_size.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = Vec::with_capacity(modulus_size);
    encoded.extend([0, 1]);
    encoded.resize(modulus_size - data.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend_from_slice(data);
    Ok(encoded)
}

fn rsa_pkcs1_v1_5_unpad(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded.len() < 11 || encoded.get(0..2) != Some(&[0, 2]) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let separator = encoded[2..]
        .iter()
        .position(|value| *value == 0)
        .map(|position| position + 2)
        .ok_or(CKR_ENCRYPTED_DATA_INVALID)?;
    if separator < 10 || encoded[2..separator].contains(&0) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(encoded[separator + 1..].to_vec())
}

fn rsa_oaep_unpad(
    encoded: &[u8],
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let digest = digest_for_hash_mechanism(hash_mechanism)?;
    let mgf_digest = mgf_digest(mgf_code, hash_mechanism)?;
    let hash_len = digest.size();
    if encoded.len() < 2 * hash_len + 2 || encoded[0] != 0 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let masked_seed = &encoded[1..hash_len + 1];
    let masked_db = &encoded[hash_len + 1..];
    let seed_mask = mgf1(masked_db, hash_len, mgf_digest)?;
    let mut seed = masked_seed.to_vec();
    for (value, mask) in seed.iter_mut().zip(seed_mask) {
        *value ^= mask;
    }
    let db_mask = mgf1(&seed, masked_db.len(), mgf_digest)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(db_mask) {
        *value ^= mask;
    }
    if db.get(..hash_len) != Some(label_digest) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let separator = db[hash_len..]
        .iter()
        .position(|value| *value == 1)
        .map(|position| position + hash_len)
        .ok_or(CKR_ENCRYPTED_DATA_INVALID)?;
    if db[hash_len..separator].iter().any(|value| *value != 0) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(db[separator + 1..].to_vec())
}

fn rsa_oaep_pad(
    input: &[u8],
    modulus_size: usize,
    mgf_code: u8,
    hash_mechanism: CK_MECHANISM_TYPE,
    label_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let digest = digest_for_hash_mechanism(hash_mechanism)?;
    let mgf_digest = mgf_digest(mgf_code, hash_mechanism)?;
    let hash_len = digest.size();
    if input.len() > modulus_size.saturating_sub(2 * hash_len + 2) || label_digest.len() != hash_len
    {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut seed = vec![0; hash_len];
    openssl::rand::rand_bytes(&mut seed).map_err(|_| CKR_RANDOM_NO_RNG)?;
    let mut db = label_digest.to_vec();
    db.extend(std::iter::repeat_n(
        0,
        modulus_size - input.len() - 2 * hash_len - 2,
    ));
    db.push(1);
    db.extend_from_slice(input);
    let db_mask = mgf1(&seed, db.len(), mgf_digest)?;
    for (value, mask) in db.iter_mut().zip(db_mask) {
        *value ^= mask;
    }
    let seed_mask = mgf1(&db, hash_len, mgf_digest)?;
    let mut encoded = vec![0];
    encoded.extend(seed.iter().zip(seed_mask).map(|(value, mask)| value ^ mask));
    encoded.extend_from_slice(&db);
    Ok(encoded)
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let part = from_raw_parts(part, part_len as usize)?.to_vec();
        let operation = ctx
            .sign_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        operation.buffer.extend_from_slice(&part);
        Ok(())
    }))
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    session_handle: CK_SESSION_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    map(sign(
        session_handle,
        ptr::null(),
        0,
        signature,
        signature_len,
    ))
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    session_handle: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_VerifyInit called with {:?}",
        (session_handle, mechanism, key)
    );
    map(verify_init(session_handle, mechanism, key))
}

fn verify_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx.verify_operations.contains_key(&session_handle) {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = _as_ref(mechanism)?;
        let pss = if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters = _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR)?;
            let mgf = match parameters.mgf {
                x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => 32,
                x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => 33,
                x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => 34,
                x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => 35,
                x if x == CKG_MGF1_SHA224 as CK_RSA_PKCS_MGF_TYPE => 36,
                x if x == CKG_MGF1_SHA3_224 as CK_RSA_PKCS_MGF_TYPE => 37,
                x if x == CKG_MGF1_SHA3_256 as CK_RSA_PKCS_MGF_TYPE => 38,
                x if x == CKG_MGF1_SHA3_384 as CK_RSA_PKCS_MGF_TYPE => 39,
                x if x == CKG_MGF1_SHA3_512 as CK_RSA_PKCS_MGF_TYPE => 40,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
            };
            Some((
                mgf,
                u16::try_from(parameters.sLen)
                    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?,
                parameters.hashAlg,
            ))
        } else if piv_is_pss_mechanism(mechanism.mechanism) {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let digest =
                piv_hash_mechanism(mechanism.mechanism).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let hash = pss_hash_mechanism(mechanism.mechanism)?;
            Some((0, digest.size() as u16, hash))
        } else {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };
        let rsa_mechanism = mechanism.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            || mechanism.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
            || piv_is_hashed_rsa_pkcs(mechanism.mechanism)
            || piv_is_pss_mechanism(mechanism.mechanism);
        let ecdsa_mechanism = mechanism.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE
            || piv_is_hashed_ecdsa(mechanism.mechanism);
        let eddsa_mechanism = mechanism.mechanism == CKM_EDDSA as CK_MECHANISM_TYPE;
        if !rsa_mechanism && !ecdsa_mechanism && !eddsa_mechanism {
            return Err(CKR_MECHANISM_INVALID.into());
        }

        let object = ctx
            .objects
            .get(&key)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if !object.verify {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        if object.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || (rsa_mechanism
                && (object.key_type != CKK_RSA as CK_KEY_TYPE
                    || !matches!(object.material, KeyMaterial::RsaPublic(_))))
            || (ecdsa_mechanism
                && (object.key_type != CKK_EC as CK_KEY_TYPE
                    || (!matches!(
                        &object.material,
                        KeyMaterial::PivPublic { .. } | KeyMaterial::OpenPgpPublic { .. }
                    ) && !matches!(
                        &object.material,
                        KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm)
                    ))))
            || (eddsa_mechanism
                && (object.key_type != CKK_EC_EDWARDS as CK_KEY_TYPE
                    || (!matches!(
                        &object.material,
                        KeyMaterial::PivPublic { .. } | KeyMaterial::OpenPgpPublic { .. }
                    ) && !matches!(
                        &object.material,
                        KeyMaterial::YubiHsm { algorithm, .. }
                            if *algorithm == YUBIHSM_ALGO_ED25519
                    ))))
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }

        ctx.verify_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: false,
                context_specific_extended: false,
                mechanism: mechanism.mechanism,
                pss,
                piv_pin_policy: None,
                buffer: Vec::new(),
            },
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_Verify(
    session_handle: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_Verify called with {:?}",
        (session_handle, data, data_len, signature, signature_len)
    );
    map(verify(
        session_handle,
        data,
        data_len,
        signature,
        signature_len,
    ))
}

fn verify(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *const ::std::os::raw::c_uchar,
    signature_len: CK_ULONG,
) -> Result<(), Error> {
    with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let operation = ctx
            .verify_operations
            .remove(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let data = from_raw_parts(data, data_len as usize)?;
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let signature = from_raw_parts(signature, signature_len as usize)?;
        match &operation.key {
            KeyMaterial::RsaPublic(public_key) => {
                if signature.len() != public_key.size() as usize {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let mut recovered = vec![0; public_key.size() as usize];
                let padding = if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                    Padding::NONE
                } else {
                    Padding::PKCS1
                };
                let recovered_len = public_key
                    .public_decrypt(signature, &mut recovered, padding)
                    .map_err(|_| Error::from(CKR_SIGNATURE_INVALID))?;
                recovered.truncate(recovered_len);
                let expected = if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                    let digest = hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?;
                    piv_digest_info(operation.mechanism, digest.as_ref())
                        .ok_or(CKR_MECHANISM_INVALID)?
                } else if piv_is_pss_mechanism(operation.mechanism) {
                    let (mgf, salt_length, hash_mechanism) =
                        operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    let digest = if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
                        data.to_vec()
                    } else {
                        hash(
                            piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                            data,
                        )?
                        .to_vec()
                    };
                    if !verify_rsa_pss(
                        &recovered,
                        &digest,
                        hash_mechanism,
                        mgf,
                        salt_length as usize,
                    )? {
                        return Err(CKR_SIGNATURE_INVALID.into());
                    }
                    return Ok(());
                } else {
                    return Err(CKR_MECHANISM_INVALID.into());
                };
                if recovered != expected {
                    return Err(CKR_SIGNATURE_INVALID.into());
                }
                Ok(())
            }
            KeyMaterial::PivPublic {
                algorithm,
                public_key,
            } => {
                if *algorithm == piv::Algorithm::Ed25519 {
                    if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                        return Err(CKR_MECHANISM_INVALID.into());
                    }
                    return verify_ed25519(public_key, data, signature);
                }
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length =
                    piv_ec_coordinate_length(*algorithm).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = piv_ec_public_key(*algorithm, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::OpenPgpPublic {
                algorithm: OpenPgpAlgorithm::Ed25519,
                public_key,
            } => {
                if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                    return Err(CKR_MECHANISM_INVALID.into());
                }
                verify_ed25519(public_key, data, signature)
            }
            KeyMaterial::OpenPgpPublic {
                algorithm: OpenPgpAlgorithm::Ecdsa(curve),
                public_key,
            } => {
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length =
                    curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = openpgp_ec_public_key(*curve, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::YubiHsm {
                algorithm,
                public_key,
                ..
            } if is_yubihsm_ec(*algorithm) => {
                let digest = if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE {
                    data.to_vec()
                } else {
                    hash(
                        piv_hash_mechanism(operation.mechanism).ok_or(CKR_MECHANISM_INVALID)?,
                        data,
                    )?
                    .to_vec()
                };
                let coordinate_length = yubihsm_ec_coordinate_length(*algorithm)?;
                if signature.len() != coordinate_length * 2 {
                    return Err(CKR_SIGNATURE_LEN_RANGE.into());
                }
                let r = BigNum::from_slice(&signature[..coordinate_length])?;
                let s = BigNum::from_slice(&signature[coordinate_length..])?;
                let signature = EcdsaSig::from_private_components(r, s)?;
                let key = yubihsm_ec_public_key(*algorithm, public_key)?;
                if signature.verify(&digest, &key)? {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID.into())
                }
            }
            KeyMaterial::YubiHsm {
                algorithm: YUBIHSM_ALGO_ED25519,
                public_key,
                ..
            } => {
                if operation.mechanism != CKM_EDDSA as CK_MECHANISM_TYPE {
                    return Err(CKR_MECHANISM_INVALID.into());
                }
                verify_ed25519(public_key, data, signature)
            }
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        }
    })
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    session_handle: CK_SESSION_HANDLE,
    part: *mut ::std::os::raw::c_uchar,
    part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(with_context_mut(|ctx| {
        ctx._get_session(session_handle)?;
        let part = from_raw_parts(part, part_len as usize)?.to_vec();
        let operation = ctx
            .verify_operations
            .get_mut(&session_handle)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        operation.buffer.extend_from_slice(&part);
        Ok(())
    }))
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    session_handle: CK_SESSION_HANDLE,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    map(verify(
        session_handle,
        ptr::null(),
        0,
        signature,
        signature_len,
    ))
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_VerifyRecover(
    session_handle: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DigestEncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptDigestUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DecryptVerifyUpdate(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_GenerateKey(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log!(
        2,
        "C_GenerateKey called with {:?}",
        (session_handle, mechanism, templ, count, key)
    );
    match generate_key(session_handle, mechanism, templ, count, key) {
        Ok(()) => CKR_OK as CK_RV,
        Err(e) => e.into(),
    }
}

fn generate_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    templ: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let key_handle = as_mut(key)?;
    let mechanism = _as_ref(mechanism)?;
    let templ = from_raw_parts(templ, count as usize)?;

    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if ctx.get_slot(slot_id)?.is_yubihsm() {
            let (object, command) = yubihsm_generate_key_command(mechanism, templ)?;
            validate_new_object_access(&object, flags, logged_in)?;
            let response = ctx
                ._get_session(session_handle)?
                .1
                .yubihsm_command(&command)?;
            let id = parse_yubihsm_object_id(&response)?;
            ctx.refresh_slot_token_objects(slot_id)?;
            *key_handle = ctx
                .objects
                .iter()
                .find(|(_, object)| {
                    object.slot_id == Some(slot_id)
                        && object.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
                        && matches!(&object.material, KeyMaterial::YubiHsm { id: object_id, .. } if *object_id == id)
                })
                .map(|(handle, _)| *handle)
                .ok_or(CKR_DEVICE_ERROR)?;
            return Ok(());
        }
        let mut key = generate_key_object(mechanism, templ)?;
        validate_new_object_access(&key, flags, logged_in)?;
        key.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(key);
        *key_handle = handle;
        Ok(())
    })
}

fn yubihsm_generate_key_command(
    mechanism: &CK_MECHANISM,
    templ: &[CK_ATTRIBUTE],
) -> Result<(TokenObject, YubiHsmCommand), Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if !matches!(
        mechanism.mechanism,
        x if x == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE
            || x == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE
    ) {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    validate_unique_template(templ)?;
    let default_key_type = if mechanism.mechanism == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE {
        CKK_AES as CK_KEY_TYPE
    } else {
        CKK_GENERIC_SECRET as CK_KEY_TYPE
    };
    let mut key_template = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        key_type: Some(default_key_type),
        token: true,
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        ..TokenObjectTemplate::default()
    };
    let mut value_len = None;
    for attribute in templ {
        if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
            value_len = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
        } else {
            key_template
                .apply_attribute(attribute)
                .map_err(Error::from)?;
        }
    }
    let mut object = key_template.into_object().map_err(Error::from)?;
    if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let supplied_value_len = value_len.map(|length| length as usize);
    let (code, algorithm, expected_len) =
        if mechanism.mechanism == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE {
            let value_len = supplied_value_len.ok_or(CKR_TEMPLATE_INCOMPLETE)?;
            let algorithm = match value_len {
                16 => YUBIHSM_ALGO_AES128,
                24 => YUBIHSM_ALGO_AES192,
                32 => YUBIHSM_ALGO_AES256,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            (
                YubiHsmCommandCode::GenerateSymmetricKey,
                algorithm,
                value_len,
            )
        } else {
            let (algorithm, expected_len) = match object.key_type {
                x if x == CKK_SHA_1_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA1, 20),
                x if x == CKK_SHA384_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA384, 48),
                x if x == CKK_SHA512_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA512, 64),
                x if x == CKK_SHA256_HMAC as CK_KEY_TYPE => (YUBIHSM_ALGO_HMAC_SHA256, 32),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            };
            (YubiHsmCommandCode::GenerateHmacKey, algorithm, expected_len)
        };
    if supplied_value_len.is_some_and(|value_len| value_len != expected_len) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let command =
        YubiHsmCommand::generate_object(code, &yubihsm_object_parameters(&object, algorithm)?)?;
    object.local = true;
    Ok((object, command))
}

fn generate_key_object(
    mechanism: &CK_MECHANISM,
    templ: &[CK_ATTRIBUTE],
) -> Result<TokenObject, Error> {
    if mechanism.mechanism != CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    validate_unique_template(templ)?;

    let mut key_template = TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        key_type: Some(CKK_GENERIC_SECRET as CK_KEY_TYPE),
        sensitive: Some(true),
        extractable: Some(false),
        ..TokenObjectTemplate::default()
    };
    let mut value_len = None;
    for attribute in templ {
        if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
            if value_len.is_some() {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            value_len = Some(read_ulong_template_attribute(attribute).map_err(Error::from)?);
            continue;
        }
        key_template
            .apply_attribute(attribute)
            .map_err(Error::from)?;
    }
    let mut key = key_template.into_object().map_err(Error::from)?;
    if key.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
        || key.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let value_len = value_len.ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let key_size_bits = value_len
        .checked_mul(8)
        .ok_or(CKR_KEY_SIZE_RANGE as CK_RV)?;
    let details = mechanism_details(&MECHANISMS, mechanism.mechanism)?;
    if key_size_bits < details.min_key_size || key_size_bits > details.max_key_size {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let mut value = vec![0; value_len as usize];
    openssl::rand::rand_bytes(&mut value).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
    key.material = KeyMaterial::Secret(Zeroizing::new(value));
    key.local = true;
    key.key_gen_mechanism = Some(mechanism.mechanism);
    Ok(key)
}

#[no_mangle]
pub extern "C" fn C_GenerateKeyPair(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    public_key_template: *mut CK_ATTRIBUTE,
    public_key_attribute_count: ::std::os::raw::c_ulong,
    private_key_template: *mut CK_ATTRIBUTE,
    private_key_attribute_count: ::std::os::raw::c_ulong,
    public_key: *mut CK_OBJECT_HANDLE,
    private_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    map(generate_key_pair(
        session_handle,
        mechanism,
        public_key_template,
        public_key_attribute_count,
        private_key_template,
        private_key_attribute_count,
        public_key,
        private_key,
    ))
}

#[allow(clippy::too_many_arguments)]
fn generate_key_pair(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    public_template: CK_ATTRIBUTE_PTR,
    public_count: CK_ULONG,
    private_template: CK_ATTRIBUTE_PTR,
    private_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    with_context(|ctx| ctx._get_session(session_handle).map(|_| ()))?;
    let mechanism = _as_ref(mechanism)?;
    let public_template = from_raw_parts(public_template, public_count as usize)?;
    let private_template = from_raw_parts(private_template, private_count as usize)?;
    let public_handle = as_mut(public_key)?;
    let private_handle = as_mut(private_key)?;
    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        if !ctx.get_slot(slot_id)?.is_yubihsm() {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        let (private_object, command) =
            yubihsm_generate_key_pair_command(mechanism, public_template, private_template)?;
        validate_new_object_access(&private_object, flags, logged_in)?;
        let response = ctx
            ._get_session(session_handle)?
            .1
            .yubihsm_command(&command)?;
        let id = parse_yubihsm_object_id(&response)?;
        ctx.refresh_slot_token_objects(slot_id)?;
        *private_handle = ctx
            .objects
            .iter()
            .find(|(_, object)| {
                object.slot_id == Some(slot_id)
                    && object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
                    && matches!(&object.material, KeyMaterial::YubiHsm { id: object_id, .. } if *object_id == id)
            })
            .map(|(handle, _)| *handle)
            .ok_or(CKR_DEVICE_ERROR)?;
        *public_handle = ctx
            .objects
            .iter()
            .find(|(_, object)| {
                object.slot_id == Some(slot_id)
                    && object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                    && object.id == id.to_be_bytes()
            })
            .map(|(handle, _)| *handle)
            .ok_or(CKR_DEVICE_ERROR)?;
        Ok(())
    })
}

fn key_pair_object(
    templ: &[CK_ATTRIBUTE],
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
) -> Result<TokenObject, Error> {
    validate_unique_template(templ)?;
    let mut parsed = TokenObjectTemplate {
        class: Some(class),
        key_type: Some(key_type),
        token: true,
        private: class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        sensitive: (class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS).then_some(true),
        extractable: (class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS).then_some(false),
        ..TokenObjectTemplate::default()
    };
    for attribute in templ {
        if matches!(
            attribute.type_,
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE
                || x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE
        ) {
            continue;
        }
        parsed.apply_attribute(attribute).map_err(Error::from)?;
    }
    let object = parsed.into_object().map_err(Error::from)?;
    if object.class != class || object.key_type != key_type {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    Ok(object)
}

fn template_attribute(
    templ: &[CK_ATTRIBUTE],
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Option<&CK_ATTRIBUTE> {
    templ
        .iter()
        .find(|attribute| attribute.type_ == attribute_type)
}

fn yubihsm_ec_algorithm(parameters: &[u8]) -> Result<u8, Error> {
    match parameters {
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21] => Ok(YUBIHSM_ALGO_EC_P224),
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Ok(YUBIHSM_ALGO_EC_P256),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => Ok(YUBIHSM_ALGO_EC_P384),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] => Ok(YUBIHSM_ALGO_EC_P521),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a] => Ok(YUBIHSM_ALGO_EC_K256),
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => {
            Ok(YUBIHSM_ALGO_EC_BP256)
        }
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b] => {
            Ok(YUBIHSM_ALGO_EC_BP384)
        }
        [0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d] => {
            Ok(YUBIHSM_ALGO_EC_BP512)
        }
        [0x06, 0x03, 0x2b, 0x65, 0x70] => Ok(YUBIHSM_ALGO_ED25519),
        [0x13, 0x07, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39] => Ok(YUBIHSM_ALGO_ED25519),
        [0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39] => {
            Ok(YUBIHSM_ALGO_X25519)
        }
        [0x06, 0x03, 0x2b, 0x65, 0x6e] => Ok(YUBIHSM_ALGO_X25519),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

fn yubihsm_generate_key_pair_command(
    mechanism: &CK_MECHANISM,
    public_template: &[CK_ATTRIBUTE],
    private_template: &[CK_ATTRIBUTE],
) -> Result<(TokenObject, YubiHsmCommand), Error> {
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let (key_type, algorithm) = match mechanism.mechanism {
        x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let bits_attribute =
                template_attribute(public_template, CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let bits = read_ulong_template_attribute(bits_attribute).map_err(Error::from)?;
            if let Some(exponent) =
                template_attribute(public_template, CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE)
            {
                if read_attribute_value(exponent).map_err(Error::from)? != [0x01, 0x00, 0x01] {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            let algorithm = match bits {
                2048 => YUBIHSM_ALGO_RSA_2048,
                3072 => YUBIHSM_ALGO_RSA_3072,
                4096 => YUBIHSM_ALGO_RSA_4096,
                _ => return Err(CKR_KEY_SIZE_RANGE.into()),
            };
            (CKK_RSA as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if is_yubihsm_x25519(algorithm) || algorithm == YUBIHSM_ALGO_ED25519 {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if !is_yubihsm_x25519(algorithm) {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC_MONTGOMERY as CK_KEY_TYPE, algorithm)
        }
        x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
            let parameters_attribute =
                template_attribute(public_template, CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE)
                    .ok_or_else(|| Error::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameters = read_attribute_value(parameters_attribute).map_err(Error::from)?;
            let algorithm = yubihsm_ec_algorithm(&parameters)?;
            if algorithm != YUBIHSM_ALGO_ED25519 {
                return Err(CKR_CURVE_NOT_SUPPORTED.into());
            }
            (CKK_EC_EDWARDS as CK_KEY_TYPE, algorithm)
        }
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    };
    let public_object =
        key_pair_object(public_template, CKO_PUBLIC_KEY as CK_OBJECT_CLASS, key_type)?;
    let mut private_object = key_pair_object(
        private_template,
        CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type,
    )?;
    if is_montgomery_key_type(key_type)
        && (public_object.encrypt
            || public_object.decrypt
            || public_object.sign
            || public_object.verify
            || public_object.derive
            || private_object.encrypt
            || private_object.decrypt
            || private_object.sign
            || private_object.verify)
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if private_object.id.is_empty() {
        private_object.id = public_object.id;
    }
    if private_object.label.is_empty() {
        private_object.label = public_object.label;
    }
    let command = YubiHsmCommand::generate_object(
        YubiHsmCommandCode::GenerateAsymmetricKey,
        &yubihsm_object_parameters(&private_object, algorithm)?,
    )?;
    Ok((private_object, command))
}

#[no_mangle]
pub extern "C" fn C_WrapKey(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _wrapping_key: CK_OBJECT_HANDLE,
    _key: CK_OBJECT_HANDLE,
    _wrapped_key: *mut ::std::os::raw::c_uchar,
    _wrapped_key_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_UnwrapKey(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _unwrapping_key: CK_OBJECT_HANDLE,
    _wrapped_key: *mut ::std::os::raw::c_uchar,
    _wrapped_key_len: ::std::os::raw::c_ulong,
    _templ: *mut CK_ATTRIBUTE,
    _attribute_count: ::std::os::raw::c_ulong,
    _key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_DeriveKey(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    base_key: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    attribute_count: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    map(derive_key(
        session_handle,
        mechanism,
        base_key,
        templ,
        attribute_count,
        key,
    ))
}

fn derive_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    base_key: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let key_handle = as_mut(key)?;
    let mechanism = _as_ref(mechanism)?;
    if mechanism.mechanism != CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE
        && mechanism.mechanism != CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE
    {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = _as_ref(mechanism.pParameter as CK_ECDH1_DERIVE_PARAMS_PTR)?;
    if parameters.kdf != CKD_NULL as CK_EC_KDF_TYPE {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let shared_data = from_raw_parts(
        parameters.pSharedData as *const u8,
        parameters.ulSharedDataLen as usize,
    )?;
    if !shared_data.is_empty() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let public_data = from_raw_parts(
        parameters.pPublicData as *const u8,
        parameters.ulPublicDataLen as usize,
    )?;
    let public_data = der_octet_string_value(public_data).unwrap_or(public_data);
    let templ = from_raw_parts(templ, attribute_count as usize)?;
    validate_unique_template(templ)?;

    with_context_mut(|ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        let object = ctx
            .objects
            .get(&base_key)
            .filter(|object| object.is_visible_to(session_handle, slot_id, logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if !object.derive {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        #[derive(Clone, Copy)]
        enum DeriveSource {
            Piv {
                slot: piv::Slot,
                algorithm: piv::Algorithm,
                pin_policy: u8,
            },
            OpenPgp {
                key_ref: OpenPgpKeyRef,
                algorithm: OpenPgpAlgorithm,
                pin_policy: u8,
            },
            YubiHsm {
                id: u16,
                algorithm: u8,
            },
        }
        let source = match &object.material {
            KeyMaterial::PivPrivate {
                slot,
                algorithm,
                pin_policy,
                ..
            } => DeriveSource::Piv {
                slot: *slot,
                algorithm: *algorithm,
                pin_policy: *pin_policy,
            },
            KeyMaterial::OpenPgpPrivate {
                key_ref,
                algorithm: algorithm @ OpenPgpAlgorithm::Ecdh(_),
                pin_policy,
                ..
            } => DeriveSource::OpenPgp {
                key_ref: *key_ref,
                algorithm: *algorithm,
                pin_policy: *pin_policy,
            },
            KeyMaterial::YubiHsm { id, algorithm, .. }
                if is_yubihsm_ec(*algorithm) || is_yubihsm_x25519(*algorithm) =>
            {
                DeriveSource::YubiHsm {
                    id: *id,
                    algorithm: *algorithm,
                }
            }
            _ => return Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
        };
        match source {
            DeriveSource::Piv {
                slot, pin_policy, ..
            } if piv_policy_requires_login(slot, pin_policy) && !logged_in => {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            DeriveSource::OpenPgp { .. } if !logged_in => {
                return Err(CKR_USER_NOT_LOGGED_IN.into());
            }
            _ => {}
        }
        let (expected_length, expected_public_length, requires_uncompressed) = match source {
            DeriveSource::Piv { algorithm, .. } => match algorithm {
                piv::Algorithm::EccP256 => (32, 65, true),
                piv::Algorithm::EccP384 => (48, 97, true),
                piv::Algorithm::X25519 => (32, 32, false),
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            DeriveSource::OpenPgp { algorithm, .. } => match algorithm {
                OpenPgpAlgorithm::Ecdh(curve) => {
                    let coordinate_length = curve.coordinate_length();
                    (
                        coordinate_length.unwrap_or(32),
                        coordinate_length.map(|length| length * 2 + 1).unwrap_or(32),
                        coordinate_length.is_some(),
                    )
                }
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            DeriveSource::YubiHsm { algorithm, .. } if is_yubihsm_x25519(algorithm) => {
                (32, 32, false)
            }
            DeriveSource::YubiHsm { algorithm, .. } if is_yubihsm_ec(algorithm) => {
                let coordinate_length = yubihsm_ec_coordinate_length(algorithm)?;
                (coordinate_length, coordinate_length * 2 + 1, true)
            }
            DeriveSource::YubiHsm { .. } => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if public_data.len() != expected_public_length
            || (requires_uncompressed && public_data.first() != Some(&0x04))
        {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let derived =
            match source {
                DeriveSource::Piv {
                    slot,
                    algorithm,
                    pin_policy,
                } => ctx._get_session(session_handle)?.1.piv_decipher(
                    slot,
                    algorithm,
                    public_data,
                    pin_policy,
                )?,
                DeriveSource::OpenPgp {
                    key_ref,
                    algorithm,
                    pin_policy,
                } => ctx._get_session(session_handle)?.1.openpgp_derive(
                    key_ref,
                    algorithm,
                    public_data,
                    pin_policy,
                )?,
                DeriveSource::YubiHsm { id, .. } => {
                    ctx._get_session(session_handle)?.1.yubihsm_command(
                        &YubiHsmCommand::key_data(YubiHsmCommandCode::DeriveEcdh, id, public_data)?,
                    )?
                }
            };
        if derived.len() != expected_length {
            return Err(CKR_DEVICE_ERROR.into());
        }

        let mut object_template = TokenObjectTemplate {
            class: Some(CKO_SECRET_KEY as CK_OBJECT_CLASS),
            key_type: Some(CKK_GENERIC_SECRET as CK_KEY_TYPE),
            private: true,
            sensitive: Some(true),
            extractable: Some(false),
            ..TokenObjectTemplate::default()
        };
        let mut requested_length = None;
        for attribute in templ {
            if attribute.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE {
                requested_length =
                    Some(read_ulong_template_attribute(attribute).map_err(Error::from)? as usize);
            } else {
                object_template
                    .apply_attribute(attribute)
                    .map_err(Error::from)?;
            }
        }
        let requested_length = requested_length.unwrap_or(expected_length);
        if requested_length == 0 || requested_length > derived.len() {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        let mut derived_object = object_template.into_object().map_err(Error::from)?;
        if derived_object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS
            || derived_object.key_type != CKK_GENERIC_SECRET as CK_KEY_TYPE
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        derived_object.private = false;
        derived_object.sensitive = false;
        derived_object.extractable = true;
        derived_object.always_sensitive = false;
        derived_object.never_extractable = false;
        derived_object.encrypt = false;
        derived_object.decrypt = false;
        derived_object.sign = false;
        derived_object.verify = false;
        derived_object.derive = false;
        derived_object.material =
            KeyMaterial::DerivedSecret(Zeroizing::new(derived[..requested_length].to_vec()));
        derived_object.local = false;
        validate_new_object_access(&derived_object, flags, logged_in)?;
        derived_object.set_owner(session_handle, slot_id);
        *key_handle = ctx.insert_object(derived_object);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_SeedRandom(
    session: CK_SESSION_HANDLE,
    _seed: *mut ::std::os::raw::c_uchar,
    _seed_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(2, "C_SeedRandom called");
    let result: Result<(), Error> = with_context(|ctx| {
        ctx._get_session(session)?;
        Err(CKR_RANDOM_SEED_NOT_SUPPORTED.into())
    });
    map(result)
}

#[no_mangle]
pub extern "C" fn C_GenerateRandom(
    session: CK_SESSION_HANDLE,
    random_data: *mut ::std::os::raw::c_uchar,
    random_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(2, "C_GenerateRandom called");
    let result: Result<(), Error> = with_context(|ctx| {
        let random_data = _from_raw_parts_mut(random_data, random_len as usize)?;
        ctx._get_session(session)?.1.generate_random(random_data)
    });
    map(result)
}

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

const fn legacy_function_list(version: CK_VERSION) -> CK_FUNCTION_LIST {
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

static G_FUNCTION_LIST: CK_FUNCTION_LIST = legacy_function_list(CK_VERSION {
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
