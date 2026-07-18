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
    get_device_info as get_yubihsm_device_info, parse_object_id as parse_yubihsm_object_id,
    parse_object_list as parse_yubihsm_object_list, parse_pin as parse_yubihsm_pin,
    Command as YubiHsmCommand, CommandCode as YubiHsmCommandCode, ObjectInfo as YubiHsmObjectInfo,
    ObjectParameters as YubiHsmObjectParameters, PublicKey as YubiHsmPublicKey,
    SecureSession as YubiHsmSecureSession,
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

trait Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn name(&self) -> String;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn hardware_major(&self) -> u8 {
        1
    }
    fn hardware_minor(&self) -> u8 {
        0
    }
    fn is_present(&self) -> bool;
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session>;
    fn login(&mut self, pin: &[u8]) -> Result<(), Error>;
    fn login_context_specific(&mut self, _pin: &[u8], _extended: bool) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn logout(&mut self) -> Result<(), Error>;
    fn init_slot(&mut self) -> Result<(), Error>;
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error>;
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error>;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }
    #[allow(dead_code)]
    fn set_applet_present(&self, _present: bool) {}
    fn set_discovery_error(&self, _error: &Error) {}
    fn clear_discovery_error(&self) {}
    fn clear_session(&mut self) {}
    fn token_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn session_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        MECHANISMS.to_vec()
    }
    fn is_yubihsm(&self) -> bool {
        false
    }
    fn login_is_active(&self) -> bool {
        true
    }

    fn flags(&self) -> CK_FLAGS {
        if self.is_present() {
            (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT) as CK_FLAGS
        } else {
            (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE) as CK_FLAGS
        }
    }

    fn label(&self) -> String {
        format!("{} #{}", self.model(), self.serial())
    }

    fn model(&self) -> &str {
        self.product()
    }

    fn format_slot_info(&self, info: &mut CK_SLOT_INFO) {
        info.firmwareVersion.major = 1;
        info.firmwareVersion.minor = 0;
        info.hardwareVersion.major = self.hardware_major();
        info.hardwareVersion.minor = self.hardware_minor();
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = self.flags();
    }

    fn format_token_info(&self, info: &mut CK_TOKEN_INFO) {
        str_pad(&self.label(), &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.model(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        info.flags =
            (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
                as CK_FLAGS;
        info.ulMaxSessionCount = 0;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 8;
        info.ulMinPinLen = 6;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.hardwareVersion.major = self.hardware_major();
        info.hardwareVersion.minor = self.hardware_minor();
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
    }
}

fn apply_connector_versions(info: &mut CK_SLOT_INFO, connector: &dyn Connector) {
    if let Some((major, minor)) = connector.hardware_version() {
        info.hardwareVersion.major = major;
        info.hardwareVersion.minor = minor;
    }
    if let Some((major, minor, patch)) = connector.firmware_version() {
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
    }
}

impl std::fmt::Debug for dyn Slot + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[derive(Debug)]
struct YubiHsmSlot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
    version: (u8, u8, u8),
    algorithms: Vec<u8>,
}

fn send_yubihsm_secure_command(
    connector: &dyn Connector,
    shared_session: &RefCell<Option<YubiHsmSecureSession>>,
    command: &YubiHsmCommand,
) -> Result<Vec<u8>, Error> {
    let mut session_guard = shared_session.try_borrow_mut()?;
    let session = session_guard
        .as_mut()
        .ok_or_else(|| Error::from(CKR_USER_NOT_LOGGED_IN))?;
    YubiHsmSecureSession::validate_command(connector, command)?;
    let result = session.send_command(connector, command);
    if !session.is_valid() {
        *session_guard = None;
    }
    result
}

fn yubihsm_key_type(algorithm: u8) -> CK_KEY_TYPE {
    match algorithm {
        YUBIHSM_ALGO_HMAC_SHA1 => CKK_SHA_1_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA256 => CKK_SHA256_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA384 => CKK_SHA384_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_HMAC_SHA512 => CKK_SHA512_HMAC as CK_KEY_TYPE,
        YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION | YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION => {
            CKK_GENERIC_SECRET as CK_KEY_TYPE
        }
        YUBIHSM_ALGO_AES128 | YUBIHSM_ALGO_AES192 | YUBIHSM_ALGO_AES256 => CKK_AES as CK_KEY_TYPE,
        YUBIHSM_ALGO_ED25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
        YUBIHSM_ALGO_X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
        algorithm if is_yubihsm_rsa(algorithm) => CKK_RSA as CK_KEY_TYPE,
        algorithm if is_yubihsm_ec(algorithm) => CKK_EC as CK_KEY_TYPE,
        algorithm => CKK_VENDOR_DEFINED as CK_KEY_TYPE | algorithm as CK_KEY_TYPE,
    }
}

fn yubihsm_algorithm_supported(algorithm: u8) -> bool {
    yubihsm_key_type(algorithm) < CKK_VENDOR_DEFINED as CK_KEY_TYPE
}

fn yubihsm_key_generation_mechanism(algorithm: u8) -> Option<CK_MECHANISM_TYPE> {
    if is_yubihsm_rsa(algorithm) {
        Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if is_yubihsm_x25519(algorithm) {
        Some(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if algorithm == YUBIHSM_ALGO_ED25519 {
        Some(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if is_yubihsm_ec(algorithm) {
        Some(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE)
    } else if matches!(
        algorithm,
        YUBIHSM_ALGO_AES128 | YUBIHSM_ALGO_AES192 | YUBIHSM_ALGO_AES256
    ) {
        Some(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE)
    } else if matches!(
        algorithm,
        YUBIHSM_ALGO_HMAC_SHA1
            | YUBIHSM_ALGO_HMAC_SHA256
            | YUBIHSM_ALGO_HMAC_SHA384
            | YUBIHSM_ALGO_HMAC_SHA512
    ) {
        Some(CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE)
    } else {
        None
    }
}

fn yubihsm_remote_material(info: &YubiHsmObjectInfo, public_key: Vec<u8>) -> KeyMaterial {
    KeyMaterial::YubiHsm {
        id: info.id,
        object_type: info.object_type,
        algorithm: info.algorithm,
        length: info.length as usize,
        domains: info.domains,
        capabilities: info.capabilities,
        delegated_capabilities: info.delegated_capabilities,
        public_key,
        value: Rc::new(RefCell::new(None)),
    }
}

fn yubihsm_token_objects(
    slot_id: CK_SLOT_ID,
    info: YubiHsmObjectInfo,
    public_key: Option<YubiHsmPublicKey>,
) -> Result<Vec<TokenObject>, Error> {
    let key_type = yubihsm_key_type(info.algorithm);
    let label = info
        .label
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
        .to_vec();
    if info.object_type == YUBIHSM_OPAQUE
        && info.algorithm == YUBIHSM_ALGO_OPAQUE_DATA
        && label.starts_with(b"Meta object")
    {
        return Ok(Vec::new());
    }
    let id = info.id.to_be_bytes().to_vec();
    let unique = format!("yubihsm-{:02x}-{:04x}", info.object_type, info.id);
    let generated = info.origin & 0x01 != 0;
    let algorithm_supported = yubihsm_algorithm_supported(info.algorithm);
    let authentication_key = info.object_type == YUBIHSM_AUTHENTICATION_KEY;
    let montgomery = is_montgomery_key_type(key_type);
    let sign = !authentication_key
        && (info.object_type == YUBIHSM_ASYMMETRIC_KEY
            || (info.object_type == YUBIHSM_HMAC_KEY && is_hmac_key_type(key_type)))
        && algorithm_supported
        && !is_yubihsm_x25519(info.algorithm)
        && (yubihsm_capability(&info.capabilities, 0x05)
            || yubihsm_capability(&info.capabilities, 0x06)
            || yubihsm_capability(&info.capabilities, 0x07)
            || yubihsm_capability(&info.capabilities, 0x08)
            || yubihsm_capability(&info.capabilities, 0x16));
    let decrypt = !authentication_key
        && !montgomery
        && algorithm_supported
        && (yubihsm_capability(&info.capabilities, 0x09)
            || yubihsm_capability(&info.capabilities, 0x0a)
            || yubihsm_capability(&info.capabilities, 0x32)
            || yubihsm_capability(&info.capabilities, 0x34));
    let encrypt = !authentication_key
        && !montgomery
        && algorithm_supported
        && (yubihsm_capability(&info.capabilities, 0x33)
            || yubihsm_capability(&info.capabilities, 0x35));
    let derive = !authentication_key
        && algorithm_supported
        && (is_yubihsm_ec(info.algorithm) || is_yubihsm_x25519(info.algorithm))
        && yubihsm_capability(&info.capabilities, 0x0b);
    let material = yubihsm_remote_material(
        &info,
        public_key
            .as_ref()
            .map(|key| key.key.clone())
            .unwrap_or_default(),
    );
    let class = match info.object_type {
        YUBIHSM_OPAQUE if info.algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE => {
            CKO_CERTIFICATE as CK_OBJECT_CLASS
        }
        YUBIHSM_OPAQUE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_ASYMMETRIC_KEY => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        YUBIHSM_PUBLIC_WRAP_KEY => CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        YUBIHSM_TEMPLATE => CKO_DATA as CK_OBJECT_CLASS,
        YUBIHSM_AUTHENTICATION_KEY
        | YUBIHSM_WRAP_KEY
        | YUBIHSM_HMAC_KEY
        | YUBIHSM_SYMMETRIC_KEY
        | YUBIHSM_OTP_AEAD_KEY => CKO_SECRET_KEY as CK_OBJECT_CLASS,
        _ => CKO_DATA as CK_OBJECT_CLASS,
    };
    let private =
        class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS && class != CKO_DATA as CK_OBJECT_CLASS;
    let mut objects = vec![TokenObject {
        slot_id: Some(slot_id),
        unique_id: unique.as_bytes().to_vec(),
        class,
        key_type,
        label: label.clone(),
        id: id.clone(),
        token: true,
        private,
        encrypt,
        decrypt,
        sign,
        verify: false,
        derive,
        sensitive: private,
        extractable: yubihsm_capability(&info.capabilities, 0x10)
            && class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            && class != CKO_SECRET_KEY as CK_OBJECT_CLASS,
        always_sensitive: private,
        never_extractable: class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || class == CKO_SECRET_KEY as CK_OBJECT_CLASS
            || !yubihsm_capability(&info.capabilities, 0x10),
        local: generated,
        key_gen_mechanism: generated
            .then(|| yubihsm_key_generation_mechanism(info.algorithm))
            .flatten(),
        owner_session: None,
        material,
    }];

    if info.object_type == YUBIHSM_ASYMMETRIC_KEY {
        let public_key = public_key.ok_or(CKR_DEVICE_ERROR)?;
        if public_key.algorithm != info.algorithm {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let public_material = if is_yubihsm_rsa(info.algorithm) {
            let modulus = BigNum::from_slice(&public_key.key).map_err(Error::from)?;
            let exponent = BigNum::from_u32(65537).map_err(Error::from)?;
            KeyMaterial::RsaPublic(
                Rsa::from_public_components(modulus, exponent).map_err(Error::from)?,
            )
        } else {
            yubihsm_remote_material(&info, public_key.key)
        };
        objects.push(TokenObject {
            slot_id: Some(slot_id),
            unique_id: format!("{unique}-public").into_bytes(),
            class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            key_type,
            label,
            id,
            token: true,
            private: false,
            encrypt: algorithm_supported && is_yubihsm_rsa(info.algorithm),
            decrypt: false,
            sign: false,
            verify: algorithm_supported && sign,
            derive: false,
            sensitive: false,
            extractable: true,
            always_sensitive: false,
            never_extractable: false,
            local: generated,
            key_gen_mechanism: objects[0].key_gen_mechanism,
            owner_session: None,
            material: public_material,
        });
    }
    Ok(objects)
}

#[derive(Debug)]
struct PivSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    slot_description: Option<String>,
    authenticated: Rc<Cell<bool>>,
    version: piv::Version,
    serial: String,
    keys: Vec<PivKey>,
    certificates: Vec<PivCertificate>,
}

#[derive(Clone, Debug)]
struct PivKey {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    public_key: PivPublicKey,
    attestation: Rc<RefCell<Option<Vec<u8>>>>,
    attestation_attempted: Rc<Cell<bool>>,
    pin_policy: u8,
    touch_policy: u8,
}

#[derive(Clone, Debug)]
struct PivCertificate {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    value: Vec<u8>,
    attestation: bool,
}

#[derive(Clone, Debug)]
enum PivPublicKey {
    Rsa(Rsa<Public>),
    Ec(Vec<u8>),
    Raw(Vec<u8>),
}

impl PivPublicKey {
    fn key_type(&self, algorithm: piv::Algorithm) -> CK_KEY_TYPE {
        match algorithm {
            piv::Algorithm::Rsa1024
            | piv::Algorithm::Rsa2048
            | piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096 => CKK_RSA as CK_KEY_TYPE,
            piv::Algorithm::Ed25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
            piv::Algorithm::X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => CKK_EC as CK_KEY_TYPE,
        }
    }
}

fn piv_ec_parameters(algorithm: piv::Algorithm) -> Option<&'static [u8]> {
    match algorithm {
        piv::Algorithm::EccP256 => {
            Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
        }
        piv::Algorithm::EccP384 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        piv::Algorithm::Ed25519 => Some(&[
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        piv::Algorithm::X25519 => Some(&[
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        _ => None,
    }
}

fn piv_algorithm_supported(version: piv::Version, algorithm: piv::Algorithm) -> bool {
    !matches!(
        algorithm,
        piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096
            | piv::Algorithm::Ed25519
            | piv::Algorithm::X25519
    ) || (version.major, version.minor) >= (5, 7)
}

fn piv_effective_pin_policy(slot: piv::Slot, policy: u8) -> u8 {
    if policy != 0 {
        return policy;
    }
    match slot {
        piv::Slot::Signature => 3,
        piv::Slot::CardAuthentication => 1,
        _ => 2,
    }
}

fn piv_policy_requires_login(slot: piv::Slot, policy: u8) -> bool {
    piv_effective_pin_policy(slot, policy) != 1
}

fn piv_slot_label(slot: piv::Slot, certificate: bool, attestation: bool) -> Vec<u8> {
    let kind = if attestation {
        "Attestation certificate"
    } else if certificate {
        "Certificate"
    } else {
        "PIV slot"
    };
    format!("{kind} {:02X}", slot as u8).into_bytes()
}

fn piv_public_key_from_metadata(
    algorithm: piv::Algorithm,
    metadata: MetadataPublicKey,
) -> Result<PivPublicKey, Error> {
    match (algorithm, metadata) {
        (
            piv::Algorithm::Rsa1024
            | piv::Algorithm::Rsa2048
            | piv::Algorithm::Rsa3072
            | piv::Algorithm::Rsa4096,
            MetadataPublicKey::Rsa { modulus, exponent },
        ) => {
            let modulus = BigNum::from_slice(&modulus).map_err(Error::from)?;
            let exponent = BigNum::from_slice(&exponent).map_err(Error::from)?;
            let public_key = Rsa::from_public_components(modulus, exponent).map_err(Error::from)?;
            if public_key.size() as usize != algorithm.rsa_input_length().unwrap_or_default() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Rsa(public_key))
        }
        (piv::Algorithm::EccP256 | piv::Algorithm::EccP384, MetadataPublicKey::Ec(point)) => {
            let coordinate_length = piv_ec_coordinate_length(algorithm).unwrap_or_default();
            if point.len() != coordinate_length * 2 + 1 || point[0] != 0x04 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PivPublicKey::Ec(point[1..].to_vec()))
        }
        (piv::Algorithm::Ed25519 | piv::Algorithm::X25519, MetadataPublicKey::Raw(key)) => {
            if key.len() != 32 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(PivPublicKey::Raw(key))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn piv_algorithm_from_certificate(certificate: &[u8]) -> Option<piv::Algorithm> {
    let certificate = openssl::x509::X509::from_der(certificate).ok()?;
    let key = certificate.public_key().ok()?;
    match key.id() {
        Id::RSA => match key.rsa().ok()?.size() {
            128 => Some(piv::Algorithm::Rsa1024),
            256 => Some(piv::Algorithm::Rsa2048),
            384 => Some(piv::Algorithm::Rsa3072),
            512 => Some(piv::Algorithm::Rsa4096),
            _ => None,
        },
        Id::EC => {
            let curve = key.ec_key().ok()?.group().curve_name()?;
            match curve {
                Nid::X9_62_PRIME256V1 => Some(piv::Algorithm::EccP256),
                Nid::SECP384R1 => Some(piv::Algorithm::EccP384),
                _ => None,
            }
        }
        Id::ED25519 => Some(piv::Algorithm::Ed25519),
        Id::X25519 => Some(piv::Algorithm::X25519),
        _ => None,
    }
}

fn piv_public_key_from_certificate(
    algorithm: piv::Algorithm,
    certificate_der: &[u8],
) -> Result<PivPublicKey, Error> {
    let certificate = openssl::x509::X509::from_der(certificate_der).map_err(Error::from)?;
    let certificate_key = certificate.public_key().map_err(Error::from)?;
    match algorithm {
        piv::Algorithm::Rsa1024
        | piv::Algorithm::Rsa2048
        | piv::Algorithm::Rsa3072
        | piv::Algorithm::Rsa4096 => {
            let public_key = certificate_key.rsa().map_err(Error::from)?;
            if public_key.size() as usize != algorithm.rsa_input_length().unwrap_or_default() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Rsa(public_key))
        }
        piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => {
            let public_key = certificate_key.ec_key().map_err(Error::from)?;
            let coordinate_length = piv_ec_coordinate_length(algorithm).unwrap_or_default();
            let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
            let point = public_key
                .public_key()
                .to_bytes(
                    public_key.group(),
                    PointConversionForm::UNCOMPRESSED,
                    &mut context,
                )
                .map_err(Error::from)?;
            if point.len() != coordinate_length * 2 + 1 || point[0] != 0x04 {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Ec(point[1..].to_vec()))
        }
        piv::Algorithm::Ed25519 | piv::Algorithm::X25519 => {
            if !matches!(
                (algorithm, certificate_key.id()),
                (piv::Algorithm::Ed25519, Id::ED25519) | (piv::Algorithm::X25519, Id::X25519)
            ) {
                return Err(CKR_DATA_INVALID.into());
            }
            let public_key = certificate_key.raw_public_key().map_err(Error::from)?;
            if public_key.len() != 32 {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Ok(PivPublicKey::Raw(public_key))
        }
    }
}

fn piv_ec_coordinate_length(algorithm: piv::Algorithm) -> Option<usize> {
    match algorithm {
        piv::Algorithm::EccP256 => Some(32),
        piv::Algorithm::EccP384 => Some(48),
        _ => None,
    }
}

fn piv_sign_mechanism_supported(algorithm: piv::Algorithm, mechanism: CK_MECHANISM_TYPE) -> bool {
    match algorithm {
        piv::Algorithm::Rsa1024
        | piv::Algorithm::Rsa2048
        | piv::Algorithm::Rsa3072
        | piv::Algorithm::Rsa4096 => matches!(
            mechanism,
            x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                || x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        ),
        piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => {
            matches!(
                mechanism,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
            )
        }
        piv::Algorithm::Ed25519 => mechanism == CKM_EDDSA as CK_MECHANISM_TYPE,
        piv::Algorithm::X25519 => false,
    }
}

fn openpgp_sign_mechanism_supported(
    algorithm: OpenPgpAlgorithm,
    mechanism: CK_MECHANISM_TYPE,
) -> bool {
    match algorithm {
        OpenPgpAlgorithm::Rsa { .. } => matches!(
            mechanism,
            x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
        ),
        OpenPgpAlgorithm::Ecdsa(_) => {
            matches!(
                mechanism,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
            )
        }
        OpenPgpAlgorithm::Ed25519 => mechanism == CKM_EDDSA as CK_MECHANISM_TYPE,
        OpenPgpAlgorithm::Ecdh(_) => false,
    }
}

fn openpgp_ec_coordinate_length(algorithm: OpenPgpAlgorithm) -> Option<usize> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => curve.coordinate_length(),
        OpenPgpAlgorithm::Ed25519 => Some(32),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

fn openpgp_ec_params(algorithm: OpenPgpAlgorithm) -> Option<Vec<u8>> {
    match algorithm {
        OpenPgpAlgorithm::Ecdsa(curve) | OpenPgpAlgorithm::Ecdh(curve) => {
            Some(curve.oid().to_vec())
        }
        OpenPgpAlgorithm::Ed25519 => Some(openpgp::Curve::Ed25519.oid().to_vec()),
        OpenPgpAlgorithm::Rsa { .. } => None,
    }
}

fn openpgp_signature(signature: &[u8], coordinate_length: usize) -> Result<Vec<u8>, Error> {
    if signature.len() == coordinate_length * 2 {
        return Ok(signature.to_vec());
    }
    piv_ecdsa_signature(signature, coordinate_length)
}

fn piv_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<MessageDigest> {
    match mechanism {
        x if x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha1())
        }
        x if x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha224())
        }
        x if x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha256())
        }
        x if x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha384())
        }
        x if x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha512())
        }
        x if x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_224())
        }
        x if x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_256())
        }
        x if x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_384())
        }
        x if x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
            || x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE =>
        {
            Some(MessageDigest::sha3_512())
        }
        _ => None,
    }
}

fn piv_is_pss_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE
        || mechanism == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE
}

fn piv_is_hashed_rsa_pkcs(mechanism: CK_MECHANISM_TYPE) -> bool {
    piv_hash_mechanism(mechanism).is_some()
        && !piv_is_pss_mechanism(mechanism)
        && mechanism != CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
        && mechanism != CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
        && mechanism < CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
}

fn piv_is_hashed_ecdsa(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
        || mechanism == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
}

fn piv_digest_info(mechanism: CK_MECHANISM_TYPE, digest: &[u8]) -> Option<Vec<u8>> {
    let prefix: &[u8] = match mechanism {
        x if x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
        ],
        x if x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00,
        ],
        x if x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00,
        ],
        x if x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00,
        ],
        x if x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x07, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00,
        ],
        x if x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00,
        ],
        _ => return None,
    };
    let mut result = prefix.to_vec();
    result.extend_from_slice(digest);
    Some(result)
}

fn digest_for_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
    match mechanism {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha1()),
        x if x == CKM_SHA224 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha224()),
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha256()),
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha384()),
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha512()),
        x if x == CKM_SHA3_224 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_224()),
        x if x == CKM_SHA3_256 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_256()),
        x if x == CKM_SHA3_384 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_384()),
        x if x == CKM_SHA3_512 as CK_MECHANISM_TYPE => Ok(MessageDigest::sha3_512()),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

fn pss_hash_mechanism(mechanism: CK_MECHANISM_TYPE) -> Result<CK_MECHANISM_TYPE, Error> {
    match mechanism {
        x if x == CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE => Ok(CKM_SHA_1 as CK_MECHANISM_TYPE),
        x if x == CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA224 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA256 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA384 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA512 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_224 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_256_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_256 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_384_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_384 as CK_MECHANISM_TYPE)
        }
        x if x == CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
            Ok(CKM_SHA3_512 as CK_MECHANISM_TYPE)
        }
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

fn mgf_digest(mgf: u8, hash: CK_MECHANISM_TYPE) -> Result<MessageDigest, Error> {
    match mgf {
        0 => digest_for_hash_mechanism(hash),
        32 => Ok(MessageDigest::sha1()),
        33 => Ok(MessageDigest::sha256()),
        34 => Ok(MessageDigest::sha384()),
        35 => Ok(MessageDigest::sha512()),
        36 => Ok(MessageDigest::sha224()),
        37 => Ok(MessageDigest::sha3_224()),
        38 => Ok(MessageDigest::sha3_256()),
        39 => Ok(MessageDigest::sha3_384()),
        40 => Ok(MessageDigest::sha3_512()),
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

fn mgf1(seed: &[u8], length: usize, digest: MessageDigest) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(length);
    let mut counter = 0u32;
    while output.len() < length {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        output.extend_from_slice(hash(digest, &input)?.as_ref());
        counter = counter.checked_add(1).ok_or(CKR_DATA_LEN_RANGE)?;
    }
    output.truncate(length);
    Ok(output)
}

fn encode_rsa_pss(
    digest: &[u8],
    modulus_size: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<Vec<u8>, Error> {
    let hash_digest = digest_for_hash_mechanism(hash_mechanism)?;
    if digest.len() != hash_digest.size() || salt_length > modulus_size {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let em_bits = modulus_size
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(1))
        .ok_or(CKR_KEY_SIZE_RANGE)?;
    let em_len = em_bits.div_ceil(8);
    if em_len < hash_digest.size() + salt_length + 2 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut salt = vec![0; salt_length];
    openssl::rand::rand_bytes(&mut salt).map_err(|_| CKR_RANDOM_NO_RNG)?;
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    let h = hash(hash_digest, &m_prime)?;
    let mut db = vec![0; em_len - salt_length - h.len() - 2];
    db.push(1);
    db.extend_from_slice(&salt);
    let mask = mgf1(
        h.as_ref(),
        em_len - h.len() - 1,
        mgf_digest(mgf_code, hash_mechanism)?,
    )?;
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    let mut encoded = db;
    encoded.extend_from_slice(h.as_ref());
    encoded.push(0xbc);
    if encoded.len() < modulus_size {
        let mut padded = vec![0; modulus_size - encoded.len()];
        padded.extend_from_slice(&encoded);
        encoded = padded;
    }
    Ok(encoded)
}

fn piv_ec_public_key(algorithm: piv::Algorithm, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match algorithm {
        piv::Algorithm::EccP256 => Nid::X9_62_PRIME256V1,
        piv::Algorithm::EccP384 => Nid::SECP384R1,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn openpgp_ec_public_key(curve: openpgp::Curve, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match curve {
        openpgp::Curve::P256 => Nid::X9_62_PRIME256V1,
        openpgp::Curve::P384 => Nid::SECP384R1,
        openpgp::Curve::P521 => Nid::SECP521R1,
        openpgp::Curve::BrainpoolP256 => Nid::BRAINPOOL_P256R1,
        openpgp::Curve::BrainpoolP384 => Nid::BRAINPOOL_P384R1,
        openpgp::Curve::BrainpoolP512 => Nid::BRAINPOOL_P512R1,
        openpgp::Curve::Secp256k1 => Nid::SECP256K1,
        openpgp::Curve::Ed25519 | openpgp::Curve::X25519 => {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into())
        }
    };
    let coordinate_length = curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    if point.len() != coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn yubihsm_ec_public_key(algorithm: u8, point: &[u8]) -> Result<EcKey<Public>, Error> {
    let nid = match algorithm {
        YUBIHSM_ALGO_EC_P224 => Nid::SECP224R1,
        YUBIHSM_ALGO_EC_P256 => Nid::X9_62_PRIME256V1,
        YUBIHSM_ALGO_EC_P384 => Nid::SECP384R1,
        YUBIHSM_ALGO_EC_P521 => Nid::SECP521R1,
        YUBIHSM_ALGO_EC_K256 => Nid::SECP256K1,
        YUBIHSM_ALGO_EC_BP256 => Nid::BRAINPOOL_P256R1,
        YUBIHSM_ALGO_EC_BP384 => Nid::BRAINPOOL_P384R1,
        YUBIHSM_ALGO_EC_BP512 => Nid::BRAINPOOL_P512R1,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    let coordinate_length = yubihsm_ec_coordinate_length(algorithm)?;
    if point.len() != coordinate_length * 2 {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    let group = EcGroup::from_curve_name(nid).map_err(Error::from)?;
    let mut context = openssl::bn::BigNumContext::new().map_err(Error::from)?;
    let point = EcPoint::from_bytes(&group, &point_with_prefix(point), &mut context)
        .map_err(Error::from)?;
    EcKey::from_public_key(&group, &point).map_err(Error::from)
}

fn verify_ed25519(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let key = PKey::public_key_from_raw_bytes(public_key, Id::ED25519).map_err(Error::from)?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(Error::from)?;
    if verifier
        .verify_oneshot(signature, data)
        .map_err(Error::from)?
    {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

fn point_with_prefix(point: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(point.len() + 1);
    encoded.push(0x04);
    encoded.extend_from_slice(point);
    encoded
}

fn verify_rsa_pss(
    encoded: &[u8],
    digest: &[u8],
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_code: u8,
    salt_length: usize,
) -> Result<bool, Error> {
    let hash_digest = digest_for_hash_mechanism(hash_mechanism)?;
    if digest.len() != hash_digest.size() || encoded.len() < hash_digest.size() + salt_length + 2 {
        return Ok(false);
    }
    let em_bits = encoded.len() * 8 - 1;
    let em_len = em_bits.div_ceil(8);
    let encoded = if encoded.len() > em_len {
        &encoded[encoded.len() - em_len..]
    } else {
        encoded
    };
    if encoded.last() != Some(&0xbc) {
        return Ok(false);
    }
    let h_offset = encoded.len() - hash_digest.size() - 1;
    let masked_db = &encoded[..h_offset];
    let h = &encoded[h_offset..h_offset + hash_digest.size()];
    if masked_db.first().is_some_and(|value| *value & 0x80 != 0) {
        return Ok(false);
    }
    let mask = mgf1(h, masked_db.len(), mgf_digest(mgf_code, hash_mechanism)?)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0x7f;
    let separator = db.len() - salt_length - 1;
    if db.get(separator) != Some(&1) || db[..separator].iter().any(|value| *value != 0) {
        return Ok(false);
    }
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&db[separator + 1..]);
    Ok(hash(hash_digest, &m_prime)?.as_ref() == h)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CcidApplication {
    Piv,
    OpenPgp,
    HsmAuth,
    GlobalPlatform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CcidConfiguration {
    application: CcidApplication,
    secure_channel: Option<SecureChannelProtocol>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureChannelProtocol {
    Scp03,
    Scp11a,
    Scp11b,
}

fn configured_ccid_configurations() -> Result<Vec<CcidConfiguration>, Error> {
    let secure_channel = configured_secure_channel_optional()?;
    let applications = match std::env::var("PKCS11RS_CCID_APPLICATIONS") {
        Ok(value) => parse_ccid_application_list(&value)?,
        Err(std::env::VarError::NotPresent) => default_ccid_applications(),
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };

    applications
        .into_iter()
        .map(|application| {
            let secure_channel = match application {
                CcidApplication::Piv
                | CcidApplication::OpenPgp
                | CcidApplication::HsmAuth
                | CcidApplication::GlobalPlatform => secure_channel,
            };
            Ok(CcidConfiguration {
                application,
                secure_channel,
            })
        })
        .collect()
}

fn parse_ccid_application_list(value: &str) -> Result<Vec<CcidApplication>, Error> {
    let mut applications = Vec::new();
    for application in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let application = parse_ccid_application(application)?;
        if !applications.contains(&application) {
            applications.push(application);
        }
    }
    if applications.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(applications)
}

fn default_ccid_applications() -> Vec<CcidApplication> {
    vec![
        CcidApplication::Piv,
        CcidApplication::OpenPgp,
        CcidApplication::HsmAuth,
        CcidApplication::GlobalPlatform,
    ]
}

fn parse_ccid_application(value: &str) -> Result<CcidApplication, Error> {
    match value.to_ascii_lowercase().as_str() {
        "piv" => Ok(CcidApplication::Piv),
        "openpgp" | "pgp" => Ok(CcidApplication::OpenPgp),
        "hsmauth" | "yubihsm-auth" => Ok(CcidApplication::HsmAuth),
        "globalplatform" | "global-platform" | "gp" => Ok(CcidApplication::GlobalPlatform),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn ccid_application_label(application: CcidApplication) -> &'static str {
    match application {
        CcidApplication::Piv => "PIV",
        CcidApplication::OpenPgp => "OpenPGP",
        CcidApplication::HsmAuth => "YubiHSM Auth",
        CcidApplication::GlobalPlatform => "Issuer SD",
    }
}

fn ccid_application_aid(
    application: CcidApplication,
    _secure_channel: Option<SecureChannelProtocol>,
) -> Result<Vec<u8>, Error> {
    let (name, default) = match application {
        CcidApplication::Piv => ("PKCS11RS_PIV_AID", &piv::PIV_AID[..]),
        CcidApplication::OpenPgp => ("PKCS11RS_OPENPGP_AID", &openpgp::OPENPGP_AID[..]),
        CcidApplication::HsmAuth => (
            "PKCS11RS_HSMAUTH_AID",
            &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01][..],
        ),
        CcidApplication::GlobalPlatform => (
            "PKCS11RS_GLOBALPLATFORM_AID",
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID[..],
        ),
    };
    configured_ccid_aid(name, default)
}

fn configured_ccid_aid(name: &str, default: &[u8]) -> Result<Vec<u8>, Error> {
    let aid = match std::env::var(name) {
        Ok(value) => parse_hex(&value)?,
        Err(std::env::VarError::NotPresent) => default.to_vec(),
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(aid)
}

fn configured_secure_channel_optional() -> Result<Option<SecureChannelProtocol>, Error> {
    match std::env::var("PKCS11RS_CCID_SECURE_CHANNEL") {
        Ok(value) if value.eq_ignore_ascii_case("scp03") => Ok(Some(SecureChannelProtocol::Scp03)),
        Ok(value) if value.eq_ignore_ascii_case("scp11a") => {
            Ok(Some(SecureChannelProtocol::Scp11a))
        }
        Ok(value)
            if value.eq_ignore_ascii_case("scp11") || value.eq_ignore_ascii_case("scp11b") =>
        {
            Ok(Some(SecureChannelProtocol::Scp11b))
        }
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(CKR_ARGUMENTS_BAD.into()),
        Err(std::env::VarError::NotPresent) => Ok(None),
    }
}

impl PivSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let version = connector
            .firmware_version()
            .map(|(major, minor, patch)| piv::Version {
                major,
                minor,
                patch,
            })
            .unwrap_or(piv::Version {
                major: 0,
                minor: 0,
                patch: 0,
            });
        let serial = connector.serial().to_owned();
        Self {
            connector,
            application_aid,
            slot_description: None,
            authenticated: Rc::new(Cell::new(false)),
            version,
            serial,
            keys: Vec::new(),
            certificates: Vec::new(),
        }
    }

    fn update_device_info(&mut self, info: PivDeviceInfo) {
        self.version = info.version;
        let serial = info.serial.map(|serial| serial.to_string());
        self.connector.set_device_identity(
            Some((info.version.major, info.version.minor, info.version.patch)),
            serial.as_deref(),
        );
        if let Some(serial) = serial {
            self.serial = serial;
        }
    }

    fn reported_version(&self) -> piv::Version {
        if self.version
            != (piv::Version {
                major: 0,
                minor: 0,
                patch: 0,
            })
        {
            return self.version;
        }
        self.connector
            .firmware_version()
            .map(|(major, minor, patch)| piv::Version {
                major,
                minor,
                patch,
            })
            .unwrap_or(self.version)
    }
}

impl Slot for PivSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.slot_description
            .clone()
            .unwrap_or_else(|| format!("{} PIV", self.connector.name()))
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiKey PIV"
    }
    fn serial(&self) -> &str {
        if self.serial == "0" || self.serial.is_empty() {
            self.connector.serial()
        } else {
            &self.serial
        }
    }
    fn major(&self) -> u8 {
        self.version.major
    }
    fn minor(&self) -> u8 {
        self.version.minor
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        if let Err(error) = self.connector.refresh() {
            self.authenticated.set(false);
            return Err(error);
        }
        Ok(())
    }
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PivSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            authenticated: self.authenticated.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = PivClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_device_info(info);
            let only_never = !self.keys.is_empty()
                && self
                    .keys
                    .iter()
                    .all(|key| !piv_policy_requires_login(key.slot, key.pin_policy));
            if pin.is_empty() && only_never {
                self.authenticated.set(true);
            } else {
                PivClient.verify_pin(self.connector.as_ref(), pin)?;
            }
            self.authenticated.set(true);
            Ok(())
        })();
        if result.is_err() {
            self.connector.clear_secure_channel();
        }
        result
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        let result = PivClient.select(self.connector.as_ref(), &self.application_aid);
        if let Ok(info) = result.as_ref() {
            self.version = info.version;
            self.serial = info.serial.unwrap_or_default().to_string();
        }
        self.connector.clear_secure_channel();
        result.map(|_| ())
    }
    fn login_context_specific(&mut self, pin: &[u8], _extended: bool) -> Result<(), Error> {
        PivClient.verify_pin(self.connector.as_ref(), pin)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        let info = PivClient.select(self.connector.as_ref(), &self.application_aid)?;
        self.update_device_info(info);
        self.keys.clear();
        self.certificates.clear();
        for slot in piv::Slot::all().iter().copied() {
            let metadata = if slot == piv::Slot::Attestation {
                None
            } else {
                PivClient.metadata(self.connector.as_ref(), slot).ok()
            };
            let metadata_key = metadata.as_ref().and_then(|metadata| {
                let algorithm = metadata
                    .algorithm
                    .and_then(piv::Algorithm::from_id)
                    .filter(|algorithm| piv_algorithm_supported(self.version, *algorithm))?;
                let public_key = metadata
                    .public_key
                    .as_deref()
                    .and_then(|encoded| piv::parse_metadata_public_key(algorithm, encoded).ok())
                    .and_then(|key| piv_public_key_from_metadata(algorithm, key).ok())?;
                Some((algorithm, public_key, metadata.clone()))
            });
            let certificate = PivClient.certificate(self.connector.as_ref(), slot).ok();
            let certificate_algorithm = certificate
                .as_deref()
                .and_then(piv_algorithm_from_certificate);
            if let (Some(algorithm), Some(value)) = (certificate_algorithm, certificate.clone()) {
                if piv_algorithm_supported(self.version, algorithm) {
                    self.certificates.push(PivCertificate {
                        slot,
                        algorithm,
                        value,
                        attestation: slot == piv::Slot::Attestation,
                    });
                }
            }
            if slot == piv::Slot::Attestation {
                continue;
            }
            let (algorithm, public_key, metadata) = if let Some(key) = metadata_key {
                (key.0, key.1, key.2)
            } else if let (Some(certificate), Some(algorithm)) =
                (certificate.as_deref(), certificate_algorithm)
            {
                if !piv_algorithm_supported(self.version, algorithm) {
                    continue;
                }
                let Ok(public_key) = piv_public_key_from_certificate(algorithm, certificate) else {
                    continue;
                };
                let metadata = metadata.unwrap_or(piv::Metadata {
                    algorithm: None,
                    pin_policy: None,
                    touch_policy: None,
                    origin: None,
                    public_key: None,
                });
                (algorithm, public_key, metadata)
            } else {
                continue;
            };
            self.keys.push(PivKey {
                slot,
                algorithm,
                public_key,
                attestation: Rc::new(RefCell::new(None)),
                attestation_attempted: Rc::new(Cell::new(false)),
                pin_policy: metadata.pin_policy.unwrap_or(0),
                touch_policy: metadata.touch_policy.unwrap_or(0),
            });
        }
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        let version = self.reported_version();
        info.firmwareVersion.major = version.major;
        info.firmwareVersion.minor = version.minor.saturating_mul(10) + version.patch;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        info.ulMaxPinLen = 8;
        info.ulMinPinLen = 6;
        let version = self.reported_version();
        info.firmwareVersion.major = version.major;
        info.firmwareVersion.minor = version.minor.saturating_mul(10) + version.patch;
        Ok(())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        let mut mechanisms = Vec::new();
        let rsa_sizes = [1024, 2048, 3072, 4096];
        let ec_sizes = [256, 384];
        let mut add = |type_, min_key_size, max_key_size, flags| {
            mechanisms.push(MechanismDetails {
                type_,
                min_key_size,
                max_key_size,
                flags,
            });
        };
        for type_ in [
            CKM_RSA_X_509,
            CKM_RSA_PKCS,
            CKM_RSA_PKCS_OAEP,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS,
            CKM_SHA224_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA3_224_RSA_PKCS,
            CKM_SHA3_256_RSA_PKCS,
            CKM_SHA3_384_RSA_PKCS,
            CKM_SHA3_512_RSA_PKCS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA224_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
            CKM_SHA3_224_RSA_PKCS_PSS,
            CKM_SHA3_256_RSA_PKCS_PSS,
            CKM_SHA3_384_RSA_PKCS_PSS,
            CKM_SHA3_512_RSA_PKCS_PSS,
        ] {
            let flags = if type_ == CKM_RSA_PKCS {
                (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            } else if type_ == CKM_RSA_PKCS_OAEP {
                (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS
            } else if type_ == CKM_RSA_X_509 {
                (CKF_ENCRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            } else {
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
            };
            add(
                type_ as CK_MECHANISM_TYPE,
                rsa_sizes[0],
                rsa_sizes[3],
                flags,
            );
        }
        for type_ in [
            CKM_ECDSA,
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA224,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
        ] {
            add(
                type_ as CK_MECHANISM_TYPE,
                ec_sizes[0],
                ec_sizes[1],
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            );
        }
        mechanisms.push(MechanismDetails {
            type_: CKM_EDDSA as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 255,
            flags: (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        });
        mechanisms.push(MechanismDetails {
            type_: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 384,
            flags: CKF_DERIVE as CK_FLAGS,
        });
        mechanisms.push(MechanismDetails {
            type_: CKM_ECDH1_COFACTOR_DERIVE as CK_MECHANISM_TYPE,
            min_key_size: 255,
            max_key_size: 384,
            flags: CKF_DERIVE as CK_FLAGS,
        });
        mechanisms
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = Vec::with_capacity(self.keys.len() * 2 + self.certificates.len() + 4);
        for key in &self.keys {
            if key.slot == piv::Slot::Attestation {
                continue;
            }
            let id = vec![key.slot as u8];
            let label = format!("PIV slot {:02X}", key.slot as u8).into_bytes();
            let key_type = key.public_key.key_type(key.algorithm);
            let is_rsa = key.algorithm.rsa_input_length().is_some();
            let can_sign = !matches!(key.algorithm, piv::Algorithm::X25519);
            let private = piv_policy_requires_login(key.slot, key.pin_policy);
            let can_decrypt = is_rsa
                && matches!(
                    key.slot,
                    piv::Slot::KeyManagement
                        | piv::Slot::Retired1
                        | piv::Slot::Retired2
                        | piv::Slot::Retired3
                        | piv::Slot::Retired4
                        | piv::Slot::Retired5
                        | piv::Slot::Retired6
                        | piv::Slot::Retired7
                        | piv::Slot::Retired8
                        | piv::Slot::Retired9
                        | piv::Slot::Retired10
                        | piv::Slot::Retired11
                        | piv::Slot::Retired12
                        | piv::Slot::Retired13
                        | piv::Slot::Retired14
                        | piv::Slot::Retired15
                        | piv::Slot::Retired16
                        | piv::Slot::Retired17
                        | piv::Slot::Retired18
                        | piv::Slot::Retired19
                        | piv::Slot::Retired20
                );
            let public_material = match &key.public_key {
                PivPublicKey::Rsa(public_key) => KeyMaterial::RsaPublic(public_key.clone()),
                PivPublicKey::Ec(public_key) | PivPublicKey::Raw(public_key) => {
                    KeyMaterial::PivPublic {
                        algorithm: key.algorithm,
                        public_key: public_key.clone(),
                    }
                }
            };
            let (modulus, public_exponent) = match &key.public_key {
                PivPublicKey::Rsa(public_key) => (public_key.n().to_vec(), public_key.e().to_vec()),
                _ => (Vec::new(), Vec::new()),
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-public", key.slot as u8).into_bytes(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type,
                label: label.clone(),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: is_rsa,
                decrypt: false,
                sign: false,
                verify: can_sign,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: public_material,
            });
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-private", key.slot as u8).into_bytes(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type,
                label,
                id,
                token: true,
                private,
                encrypt: false,
                decrypt: can_decrypt,
                sign: can_sign,
                verify: false,
                derive: matches!(
                    key.algorithm,
                    piv::Algorithm::EccP256 | piv::Algorithm::EccP384 | piv::Algorithm::X25519
                ),
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::PivPrivate {
                    slot: key.slot,
                    algorithm: key.algorithm,
                    modulus,
                    public_exponent,
                    pin_policy: key.pin_policy,
                    touch_policy: key.touch_policy,
                },
            });
        }
        for certificate in &self.certificates {
            let key_type = match certificate.algorithm {
                piv::Algorithm::Rsa1024
                | piv::Algorithm::Rsa2048
                | piv::Algorithm::Rsa3072
                | piv::Algorithm::Rsa4096 => CKK_RSA as CK_KEY_TYPE,
                piv::Algorithm::EccP256 | piv::Algorithm::EccP384 => CKK_EC as CK_KEY_TYPE,
                piv::Algorithm::Ed25519 => CKK_EC_EDWARDS as CK_KEY_TYPE,
                piv::Algorithm::X25519 => CKK_EC_MONTGOMERY as CK_KEY_TYPE,
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!(
                    "piv-{:02x}-{}certificate",
                    certificate.slot as u8,
                    if certificate.attestation {
                        "attestation-"
                    } else {
                        ""
                    }
                )
                .into_bytes(),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type,
                label: piv_slot_label(certificate.slot, true, certificate.attestation),
                id: vec![certificate.slot as u8],
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::PivCertificate {
                    algorithm: certificate.algorithm,
                    value: certificate.value.clone(),
                    attestation: certificate.attestation,
                },
            });
        }
        for key in &self.keys {
            if key.slot == piv::Slot::Attestation {
                continue;
            }
            let key_type = key.public_key.key_type(key.algorithm);
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-attestation", key.slot as u8).into_bytes(),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type,
                label: piv_slot_label(key.slot, true, true),
                id: vec![key.slot as u8],
                token: false,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::PivAttestation {
                    connector: self.connector.clone(),
                    slot: key.slot,
                    algorithm: key.algorithm,
                    value: key.attestation.clone(),
                    attempted: key.attestation_attempted.clone(),
                },
            });
        }
        Ok(objects)
    }

    fn session_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(self
            .token_objects(slot_id)?
            .into_iter()
            .filter(|object| !object.token)
            .collect())
    }
}

#[derive(Debug)]
struct OpenPgpSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Rc<Cell<bool>>,
    version: (u8, u8),
    serial: String,
    pin_min: u8,
    pin_max: u8,
    kdf: Option<openpgp::KdfParams>,
    keys: Vec<openpgp::KeyInfo>,
    certificates: Vec<OpenPgpCertificate>,
}

#[derive(Clone, Debug)]
struct OpenPgpCertificate {
    key_ref: OpenPgpKeyRef,
    key_type: CK_KEY_TYPE,
    value: Vec<u8>,
}

impl OpenPgpSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let serial = connector.serial().to_owned();
        let version = connector
            .firmware_version()
            .map(|(major, minor, _patch)| (major, minor))
            .unwrap_or((0, 0));
        Self {
            connector,
            application_aid,
            authenticated: Rc::new(Cell::new(false)),
            version,
            serial,
            pin_min: 6,
            pin_max: 127,
            kdf: None,
            keys: Vec::new(),
            certificates: Vec::new(),
        }
    }

    fn update_info(&mut self, info: &openpgp::ApplicationInfo) {
        self.version = info.version;
        self.serial = info.serial.clone();
        self.connector.set_device_identity(None, Some(&info.serial));
        self.pin_min = info.pin_min;
        self.pin_max = info.pin_max;
        self.kdf = info.kdf.clone();
    }

    fn reported_version(&self) -> (u8, u8) {
        if self.version != (0, 0) {
            return self.version;
        }
        self.connector
            .firmware_version()
            .map(|(major, minor, _patch)| (major, minor))
            .unwrap_or(self.version)
    }
}

fn openpgp_public_material(key: &OpenPgpPublicKey) -> Vec<u8> {
    match key {
        OpenPgpPublicKey::Rsa(key) => key.n().to_vec(),
        OpenPgpPublicKey::Ec { point, .. } | OpenPgpPublicKey::Raw { key: point, .. } => {
            point.clone()
        }
    }
}

fn openpgp_rsa_components(key: &OpenPgpPublicKey) -> (Vec<u8>, Vec<u8>) {
    match key {
        OpenPgpPublicKey::Rsa(key) => (key.n().to_vec(), key.e().to_vec()),
        _ => (Vec::new(), Vec::new()),
    }
}

fn openpgp_key_can_sign(key_ref: OpenPgpKeyRef, algorithm: OpenPgpAlgorithm) -> bool {
    matches!(
        key_ref,
        OpenPgpKeyRef::Signature | OpenPgpKeyRef::Authentication
    ) && !matches!(algorithm, OpenPgpAlgorithm::Ecdh(_))
}

fn openpgp_signature_requires_context_specific_login(
    key_ref: OpenPgpKeyRef,
    pin_policy: u8,
) -> bool {
    key_ref == OpenPgpKeyRef::Signature && pin_policy == openpgp::PW1_ONE_SIGNATURE
}

impl Slot for OpenPgpSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} OpenPGP", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiKey OpenPGP"
    }
    fn serial(&self) -> &str {
        if self.serial == "0" {
            self.connector.serial()
        } else {
            &self.serial
        }
    }
    fn major(&self) -> u8 {
        self.version.0
    }
    fn minor(&self) -> u8 {
        self.version.1
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(OpenPgpSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            authenticated: self.authenticated.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        let result = (|| {
            let info = OpenPgpClient.select(self.connector.as_ref(), &self.application_aid)?;
            self.update_info(&info);
            let pin = self
                .kdf
                .as_ref()
                .map(|kdf| kdf.derive_user_pin(pin))
                .transpose()?
                .unwrap_or_else(|| pin.to_vec());
            OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, true)?;
            if info.pin_policy == openpgp::PW1_MULTIPLE_SIGNATURES {
                OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, false)?;
            }
            self.authenticated.set(true);
            Ok(())
        })();
        if result.is_err() {
            self.connector.clear_secure_channel();
        }
        result
    }
    fn login_context_specific(&mut self, pin: &[u8], extended: bool) -> Result<(), Error> {
        let pin = self
            .kdf
            .as_ref()
            .map(|kdf| kdf.derive_user_pin(pin))
            .transpose()?
            .unwrap_or_else(|| pin.to_vec());
        OpenPgpClient.unverify(self.connector.as_ref(), extended);
        OpenPgpClient.verify_pin(self.connector.as_ref(), &pin, extended)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        OpenPgpClient.unverify(self.connector.as_ref(), false);
        OpenPgpClient.unverify(self.connector.as_ref(), true);
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let info = OpenPgpClient
            .select(self.connector.as_ref(), &self.application_aid)
            .map_err(|error| {
                log!(
                    1,
                    "OpenPGP application metadata discovery failed: {:?}",
                    error
                );
                error
            })?;
        self.update_info(&info);
        self.keys.clear();
        self.certificates.clear();
        for key_ref in OpenPgpKeyRef::ALL {
            let Some(algorithm) = info.algorithm(key_ref) else {
                log!(
                    1,
                    "OpenPGP key reference {:?} has no supported algorithm",
                    key_ref
                );
                continue;
            };
            let public_key =
                match OpenPgpClient.public_key(self.connector.as_ref(), key_ref, algorithm) {
                    Ok(public_key) => public_key,
                    Err(error) => {
                        log!(
                            1,
                            "OpenPGP public-key discovery failed for {:?}: {:?}",
                            key_ref,
                            error
                        );
                        continue;
                    }
                };
            self.keys.push(openpgp::KeyInfo {
                key_ref,
                algorithm,
                public_key,
                pin_policy: info.pin_policy,
            });
            if let Ok(value) = OpenPgpClient.certificate(self.connector.as_ref(), key_ref) {
                self.certificates.push(OpenPgpCertificate {
                    key_ref,
                    key_type: algorithm.key_type() as CK_KEY_TYPE,
                    value,
                });
            }
        }
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        if let Some((major, minor)) = self.connector.hardware_version() {
            info.hardwareVersion.major = major;
            info.hardwareVersion.minor = minor;
        }
        let (major, minor) = self.reported_version();
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        let (major, minor) = self.reported_version();
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor;
        info.ulMinPinLen = self.pin_min as CK_ULONG;
        info.ulMaxPinLen = self.pin_max as CK_ULONG;
        Ok(())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        let mut mechanisms = Vec::new();
        let mut add = |type_, min_key_size, max_key_size, flags| {
            mechanisms.push(MechanismDetails {
                type_,
                min_key_size,
                max_key_size,
                flags,
            });
        };
        for type_ in [
            CKM_RSA_X_509,
            CKM_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
        ] {
            add(
                type_ as CK_MECHANISM_TYPE,
                2048,
                4096,
                (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
            );
        }
        for type_ in [CKM_RSA_PKCS, CKM_RSA_X_509] {
            add(
                type_ as CK_MECHANISM_TYPE,
                2048,
                4096,
                (CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
            );
        }
        add(
            CKM_ECDSA as CK_MECHANISM_TYPE,
            256,
            521,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        );
        add(
            CKM_EDDSA as CK_MECHANISM_TYPE,
            255,
            255,
            (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        );
        if self
            .keys
            .iter()
            .any(|key| matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)))
        {
            add(
                CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
                255,
                521,
                CKF_DERIVE as CK_FLAGS,
            );
        }
        mechanisms
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = Vec::with_capacity(self.keys.len() * 2 + self.certificates.len());
        for key in &self.keys {
            let public_bytes = openpgp_public_material(&key.public_key);
            let key_type = key.algorithm.key_type() as CK_KEY_TYPE;
            let (modulus, public_exponent) = openpgp_rsa_components(&key.public_key);
            let can_sign = openpgp_key_can_sign(key.key_ref, key.algorithm);
            let can_decrypt = key.key_ref == OpenPgpKeyRef::Decipher && key.algorithm.is_rsa();
            let label = format!("OpenPGP {:?} key", key.key_ref).into_bytes();
            let id = vec![key.key_ref as u8];
            let public_material = match &key.public_key {
                OpenPgpPublicKey::Rsa(public_key) => KeyMaterial::RsaPublic(public_key.clone()),
                OpenPgpPublicKey::Ec { curve, point } => KeyMaterial::OpenPgpPublic {
                    algorithm: if matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)) {
                        OpenPgpAlgorithm::Ecdh(*curve)
                    } else {
                        OpenPgpAlgorithm::Ecdsa(*curve)
                    },
                    public_key: point.clone(),
                },
                OpenPgpPublicKey::Raw { curve, key } => KeyMaterial::OpenPgpPublic {
                    algorithm: if *curve == openpgp::Curve::Ed25519 {
                        OpenPgpAlgorithm::Ed25519
                    } else {
                        OpenPgpAlgorithm::Ecdh(*curve)
                    },
                    public_key: key.clone(),
                },
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-public", key.key_ref as u8).into_bytes(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type,
                label: label.clone(),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: key.key_ref == OpenPgpKeyRef::Decipher && key.algorithm.is_rsa(),
                decrypt: false,
                sign: false,
                verify: can_sign,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: public_material,
            });
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-private", key.key_ref as u8).into_bytes(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type,
                label,
                id,
                token: true,
                private: true,
                encrypt: false,
                decrypt: can_decrypt,
                sign: can_sign,
                verify: false,
                derive: key.key_ref == OpenPgpKeyRef::Decipher
                    && matches!(key.algorithm, OpenPgpAlgorithm::Ecdh(_)),
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::OpenPgpPrivate {
                    key_ref: key.key_ref,
                    algorithm: key.algorithm,
                    modulus,
                    public_exponent,
                    public_key: public_bytes,
                    pin_policy: key.pin_policy,
                },
            });
        }
        for certificate in &self.certificates {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("openpgp-{:02x}-certificate", certificate.key_ref as u8)
                    .into_bytes(),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type: certificate.key_type,
                label: format!("OpenPGP {:?} certificate", certificate.key_ref).into_bytes(),
                id: vec![certificate.key_ref as u8],
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::OpenPgpCertificate {
                    value: certificate.value.clone(),
                },
            });
        }
        Ok(objects)
    }
}

impl Slot for YubiHsmSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.connector.name()
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        self.connector.product()
    }
    fn serial(&self) -> &str {
        self.connector.serial()
    }
    fn major(&self) -> u8 {
        self.connector.major()
    }
    fn minor(&self) -> u8 {
        self.connector.minor()
    }
    fn hardware_major(&self) -> u8 {
        self.connector
            .hardware_version()
            .map(|(major, _)| major)
            .unwrap_or(1)
    }
    fn hardware_minor(&self) -> u8 {
        self.connector
            .hardware_version()
            .map(|(_, minor)| minor)
            .unwrap_or(0)
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(YubiHsmSession {
            slotID,
            flags,
            connector: self.connector.clone(),
            session: self.session.clone(),
        })
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        *self.session.try_borrow_mut()? = None;
        let (authkey_id, password) = parse_yubihsm_pin(pin)?;
        let session =
            YubiHsmSecureSession::authenticate(self.connector.as_ref(), authkey_id, password)?;
        *self.session.try_borrow_mut()? = Some(session);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        let mut session = self.session.try_borrow_mut()?.take();
        match session.as_mut() {
            Some(session) => session
                .send_command(self.connector.as_ref(), &YubiHsmCommand::close_session())
                .map(|_| ()),
            None => Err(CKR_USER_NOT_LOGGED_IN.into()),
        }
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.version = (device_info.major, device_info.minor, device_info.patch);
        self.algorithms = device_info.algorithms;
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        info.firmwareVersion.major = self.version.0;
        info.firmwareVersion.minor = self.version.1.saturating_mul(10) + self.version.2;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.format_token_info(info);
        str_pad(&device_info.serial.to_string(), &mut info.serialNumber);
        info.firmwareVersion.major = device_info.major;
        info.firmwareVersion.minor = device_info.minor.saturating_mul(10) + device_info.patch;
        info.ulMaxPinLen = 64;
        info.ulMinPinLen = 8;
        Ok(())
    }
    fn clear_session(&mut self) {
        *self.session.borrow_mut() = None;
    }
    fn login_is_active(&self) -> bool {
        self.session.borrow().is_some()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let listed = send_yubihsm_secure_command(
            self.connector.as_ref(),
            self.session.as_ref(),
            &YubiHsmCommand::list_objects(&[])?,
        )?;
        let mut objects = Vec::new();
        for entry in parse_yubihsm_object_list(&listed)? {
            let info = YubiHsmObjectInfo::parse(&send_yubihsm_secure_command(
                self.connector.as_ref(),
                self.session.as_ref(),
                &YubiHsmCommand::get_object_info(entry.id, entry.object_type),
            )?)?;
            if info.id != entry.id || info.object_type != entry.object_type {
                return Err(CKR_DEVICE_ERROR.into());
            }
            let public_key = if matches!(
                info.object_type,
                YUBIHSM_ASYMMETRIC_KEY | YUBIHSM_WRAP_KEY | YUBIHSM_PUBLIC_WRAP_KEY
            ) {
                Some(YubiHsmPublicKey::parse(&send_yubihsm_secure_command(
                    self.connector.as_ref(),
                    self.session.as_ref(),
                    &YubiHsmCommand::get_public_key(info.id, Some(info.object_type)),
                )?)?)
            } else {
                None
            };
            objects.extend(yubihsm_token_objects(slot_id, info, public_key)?);
        }
        Ok(objects)
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        yubihsm_mechanisms(&self.algorithms)
    }
    fn is_yubihsm(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct GenericPcscSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    label: &'static str,
    authenticated: Cell<bool>,
}

impl GenericPcscSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>, label: &'static str) -> Self {
        Self {
            connector,
            application_aid,
            label,
            authenticated: Cell::new(false),
        }
    }
}

impl Slot for GenericPcscSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} {}", self.connector.name(), self.label)
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        self.label
    }
    fn serial(&self) -> &str {
        self.connector.serial()
    }
    fn major(&self) -> u8 {
        self.connector.major()
    }
    fn minor(&self) -> u8 {
        self.connector.minor()
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PcscAppletSession {
            slotID: slot_id,
            flags,
            connector: self.connector.clone(),
        })
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        select_application(self.connector.as_ref(), &self.application_aid)
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        if let Some((major, minor, patch)) = self.connector.firmware_version() {
            info.firmwareVersion.major = major;
            info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
        }
        Ok(())
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }
}

#[derive(Debug)]
struct GlobalPlatformSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Cell<bool>,
}

impl Slot for GlobalPlatformSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} Issuer SD", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "Issuer SD"
    }
    fn model(&self) -> &str {
        "Issuer SD"
    }
    fn serial(&self) -> &str {
        self.connector.serial()
    }
    fn major(&self) -> u8 {
        self.connector.major()
    }
    fn minor(&self) -> u8 {
        self.connector.minor()
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PcscAppletSession {
            slotID,
            flags,
            connector: self.connector.clone(),
        })
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        select_application(self.connector.as_ref(), &self.application_aid)
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        if let Some((major, minor, patch)) = self.connector.firmware_version() {
            info.firmwareVersion.major = major;
            info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PcscAppletSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
}

impl Session for PcscAppletSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let response = scp03::transmit(
                self.connector.as_ref(),
                &CommandApdu {
                    cla: 0,
                    ins: 0x84,
                    p1: 0,
                    p2: 0,
                    data: Vec::new(),
                    le: Some(chunk.len() as u32),
                    extended: false,
                },
            )?;
            if response.status != 0x9000 || response.data.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&response.data);
        }
        Ok(())
    }
}

trait Session {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn slotID(&self) -> CK_SLOT_ID;
    fn flags(&self) -> CK_FLAGS;
    #[allow(dead_code)]
    fn get_session_info(&self) -> Result<(), Error>;
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        openssl::rand::rand_bytes(output).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))
    }
    fn piv_sign(
        &self,
        _slot: piv::Slot,
        _algorithm: piv::Algorithm,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_decipher(
        &self,
        _slot: piv::Slot,
        _algorithm: piv::Algorithm,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_sign(
        &self,
        _key_ref: OpenPgpKeyRef,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_decipher(&self, _input: &[u8], _raw: bool) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_derive(
        &self,
        _key_ref: OpenPgpKeyRef,
        _algorithm: OpenPgpAlgorithm,
        _public_key: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn yubihsm_command(&self, _command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
}

fn session_state(flags: CK_FLAGS, logged_in: bool) -> CK_STATE {
    match (flags & CKF_RW_SESSION as CK_FLAGS != 0, logged_in) {
        (false, false) => CKS_RO_PUBLIC_SESSION as CK_STATE,
        (false, true) => CKS_RO_USER_FUNCTIONS as CK_STATE,
        (true, false) => CKS_RW_PUBLIC_SESSION as CK_STATE,
        (true, true) => CKS_RW_USER_FUNCTIONS as CK_STATE,
    }
}

impl std::fmt::Debug for dyn Session + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

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
#[derive(Debug)]
struct AbiTestSlot;

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
struct AbiTestSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

#[cfg(feature = "abi-tests")]
impl Slot for AbiTestSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        String::from("PKCS11RS ABI test slot")
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        "ABI test token"
    }

    fn serial(&self) -> &str {
        "ABI00001"
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

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(AbiTestSession { slot_id, flags })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        Ok(())
    }

    fn logout(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        Ok(())
    }
}

#[cfg(feature = "abi-tests")]
impl Session for AbiTestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(feature = "abi-tests")]
// ABI fixtures exercise slot/session dispatch without touching host hardware.
// Protocol handshakes and cryptographic vectors remain covered by module tests.
#[derive(Debug)]
struct AbiPivConnector;

#[cfg(feature = "abi-tests")]
impl Connector for AbiPivConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        "YubiKey"
    }

    fn serial(&self) -> &str {
        "PIV00001"
    }

    fn major(&self) -> u8 {
        5
    }

    fn minor(&self) -> u8 {
        7
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        4096
    }

    fn transmit<'a>(
        &self,
        command: &[u8],
        receive: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = match command.get(1).copied() {
            Some(0xa4) | Some(0x20) => vec![0x90, 0x00],
            Some(0xfd) => vec![5, 7, 0, 0x90, 0x00],
            Some(0xf8) => vec![0, 0, 0, 1, 0x90, 0x00],
            Some(0x87) => {
                let mut response = vec![0x7c, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00];
                response.extend(std::iter::repeat_n(0, 256));
                response.extend([0x90, 0x00]);
                response
            }
            _ => vec![0x6d, 0x00],
        };
        if response.len() > receive.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive[..response.len()].copy_from_slice(&response);
        Ok(&receive[..response.len()])
    }
}

#[cfg(feature = "abi-tests")]
fn abi_test_piv_slot() -> Result<PivSlot, Error> {
    let public_key = Rsa::generate(2048)?;
    let public_key =
        Rsa::from_public_components(public_key.n().to_owned()?, public_key.e().to_owned()?)?;
    let connector: Rc<dyn Connector> = Rc::new(AbiPivConnector);
    Ok(PivSlot {
        connector,
        application_aid: piv::PIV_AID.to_vec(),
        slot_description: Some(String::from("PKCS11RS ABI PIV test slot")),
        authenticated: Rc::new(Cell::new(false)),
        version: piv::Version {
            major: 5,
            minor: 7,
            patch: 0,
        },
        serial: String::from("PIV00001"),
        keys: vec![PivKey {
            slot: piv::Slot::Signature,
            algorithm: piv::Algorithm::Rsa2048,
            public_key: PivPublicKey::Rsa(public_key),
            attestation: Rc::new(RefCell::new(None)),
            attestation_attempted: Rc::new(Cell::new(false)),
            pin_policy: 2,
            touch_policy: 1,
        }],
        certificates: Vec::new(),
    })
}

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
struct AbiScp03Connector {
    protocol: &'static str,
}

#[cfg(feature = "abi-tests")]
impl Connector for AbiScp03Connector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        if self.protocol == "SCP03" {
            "ABI SCP03"
        } else {
            "ABI SCP11"
        }
    }

    fn serial(&self) -> &str {
        if self.protocol == "SCP03" {
            "SCP03001"
        } else {
            "SCP11001"
        }
    }

    fn major(&self) -> u8 {
        5
    }

    fn minor(&self) -> u8 {
        7
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        4096
    }

    fn transmit<'a>(
        &self,
        command: &[u8],
        receive: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = if command.get(1) == Some(&0x84) {
            let length = command.last().copied().unwrap_or(0);
            let length = if length == 0 { 256 } else { length as usize };
            let mut response = vec![0; length];
            response.extend([0x90, 0x00]);
            response
        } else {
            vec![0x90, 0x00]
        };
        if response.len() > receive.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive[..response.len()].copy_from_slice(&response);
        Ok(&receive[..response.len()])
    }
}

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
struct AbiScp03Slot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
    protocol: &'static str,
}

#[cfg(feature = "abi-tests")]
impl AbiScp03Slot {
    fn new(protocol: &'static str) -> Result<Self, Error> {
        Ok(Self {
            connector: Rc::new(AbiScp03Connector { protocol }),
            session: Rc::new(RefCell::new(Some(Scp03Session::from_session_keys(
                vec![0; 16],
                vec![0; 16],
                vec![0; 16],
                [0; 16],
                0,
            )?))),
            protocol,
        })
    }
}

#[cfg(feature = "abi-tests")]
impl Slot for AbiScp03Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        format!("PKCS11RS ABI {} test slot", self.protocol)
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        self.connector.product()
    }

    fn model(&self) -> &str {
        if self.protocol == "SCP03" {
            "ABI SCP03"
        } else {
            "ABI SCP11"
        }
    }

    fn serial(&self) -> &str {
        self.connector.serial()
    }

    fn major(&self) -> u8 {
        5
    }

    fn minor(&self) -> u8 {
        7
    }

    fn is_present(&self) -> bool {
        true
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(GlobalPlatformSession {
            slotID: slot_id,
            flags,
            connector: self.connector.clone(),
            session: self.session.clone(),
        })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        *self.session.try_borrow_mut()? = Some(Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            [0; 16],
            0,
        )?);
        Ok(())
    }

    fn logout(&mut self) -> Result<(), Error> {
        *self.session.try_borrow_mut()? = None;
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        Ok(())
    }

    fn clear_session(&mut self) {
        *self.session.borrow_mut() = None;
    }

    fn login_is_active(&self) -> bool {
        self.session.borrow().is_some()
    }
}

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
struct AbiYubiHsmSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

#[cfg(feature = "abi-tests")]
impl Session for AbiYubiHsmSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }

    fn yubihsm_command(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        const NIST_AES_KEY_ID: u16 = 3;
        const NIST_AES_128_KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = command.data();
        let id = data
            .get(..2)
            .and_then(|value| value.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        let key = if id == NIST_AES_KEY_ID {
            &NIST_AES_128_KEY
        } else {
            &[0; 16]
        };
        let (cipher, mode, iv, input) = match command.code() {
            YubiHsmCommandCode::GetOpaque => {
                return match id {
                    ABI_YUBIHSM_OPAQUE_DATA_ID => Ok(ABI_YUBIHSM_OPAQUE_DATA.to_vec()),
                    ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID => {
                        Ok(ABI_YUBIHSM_OPAQUE_CERTIFICATE.to_vec())
                    }
                    _ => Err(CKR_OBJECT_HANDLE_INVALID.into()),
                };
            }
            YubiHsmCommandCode::EncryptEcb => {
                (Cipher::aes_128_ecb(), Mode::Encrypt, None, data.get(2..))
            }
            YubiHsmCommandCode::DecryptEcb => {
                (Cipher::aes_128_ecb(), Mode::Decrypt, None, data.get(2..))
            }
            YubiHsmCommandCode::EncryptCbc => (
                Cipher::aes_128_cbc(),
                Mode::Encrypt,
                data.get(2..18),
                data.get(18..),
            ),
            YubiHsmCommandCode::DecryptCbc => (
                Cipher::aes_128_cbc(),
                Mode::Decrypt,
                data.get(2..18),
                data.get(18..),
            ),
            _ => return Ok(vec![0x5a; 256]),
        };
        let input = input.ok_or(CKR_DATA_LEN_RANGE)?;
        if !input.len().is_multiple_of(AES_BLOCK_LENGTH) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut crypter = Crypter::new(cipher, mode, key, iv)?;
        crypter.pad(false);
        let mut output = vec![0; input.len() + AES_BLOCK_LENGTH];
        let written = crypter.update(input, &mut output)?;
        let final_written = crypter.finalize(&mut output[written..])?;
        output.truncate(written + final_written);
        Ok(output)
    }
}

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
struct AbiYubiHsmSlot;

#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA_ID: u16 = 5;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID: u16 = 6;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA: &[u8] = b"ABI opaque data";
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_CERTIFICATE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_object(slot_id: CK_SLOT_ID) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: b"abi-yubihsm-rsa".to_vec(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: b"ABI YubiHSM RSA key".to_vec(),
        id: 1u16.to_be_bytes().to_vec(),
        token: true,
        private: true,
        encrypt: false,
        decrypt: true,
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
        material: KeyMaterial::YubiHsm {
            id: 1,
            object_type: YUBIHSM_ASYMMETRIC_KEY,
            algorithm: YUBIHSM_ALGO_RSA_2048,
            length: 256,
            domains: 0xffff,
            capabilities: yubihsm_capabilities(&[5]),
            delegated_capabilities: [0; 8],
            public_key: Vec::new(),
            value: Rc::new(RefCell::new(None)),
        },
    }
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: b"abi-yubihsm-aes".to_vec(),
        class: CKO_SECRET_KEY as CK_OBJECT_CLASS,
        key_type: CKK_AES as CK_KEY_TYPE,
        label: b"ABI YubiHSM AES key".to_vec(),
        id: 2u16.to_be_bytes().to_vec(),
        token: true,
        private: true,
        encrypt: true,
        decrypt: true,
        sign: false,
        verify: false,
        derive: false,
        sensitive: true,
        extractable: false,
        always_sensitive: true,
        never_extractable: true,
        local: true,
        key_gen_mechanism: Some(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE),
        owner_session: None,
        material: KeyMaterial::YubiHsm {
            id: 2,
            object_type: YUBIHSM_SYMMETRIC_KEY,
            algorithm: YUBIHSM_ALGO_AES128,
            length: 16,
            domains: 0xffff,
            capabilities: yubihsm_capabilities(&[0x32, 0x33]),
            delegated_capabilities: [0; 8],
            public_key: Vec::new(),
            value: Rc::new(RefCell::new(None)),
        },
    }
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_nist_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    const NIST_AES_KEY_ID: u16 = 3;
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = b"abi-yubihsm-aes-nist".to_vec();
    object.label = b"ABI YubiHSM NIST AES key".to_vec();
    object.id = NIST_AES_KEY_ID.to_be_bytes().to_vec();
    if let KeyMaterial::YubiHsm {
        id, capabilities, ..
    } = &mut object.material
    {
        *id = NIST_AES_KEY_ID;
        *capabilities = yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]);
    }
    object
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_authentication_objects(slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
    [
        (
            4,
            32,
            YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            b"symmetric-auth".as_slice(),
        ),
        (
            7,
            64,
            YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            b"asymmetric-auth".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(id, length, algorithm, name)| {
        let mut label = [0; 40];
        label[..name.len()].copy_from_slice(name);
        let info = YubiHsmObjectInfo {
            capabilities: yubihsm_capabilities(&[0x05, 0x09, 0x0b, 0x32, 0x33]),
            id,
            length,
            domains: 1,
            object_type: YUBIHSM_AUTHENTICATION_KEY,
            algorithm,
            sequence: 1,
            origin: 1,
            label,
            delegated_capabilities: yubihsm_capabilities(&[0x04, 0x32]),
        };
        yubihsm_token_objects(slot_id, info, None)?
            .pop()
            .ok_or(CKR_DEVICE_ERROR.into())
    })
    .collect()
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_opaque_objects(slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
    let definitions = [
        (
            ABI_YUBIHSM_OPAQUE_DATA_ID,
            YUBIHSM_ALGO_OPAQUE_DATA,
            b"opaque-data".as_slice(),
            ABI_YUBIHSM_OPAQUE_DATA.len(),
        ),
        (
            ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID,
            YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            b"opaque-cert".as_slice(),
            ABI_YUBIHSM_OPAQUE_CERTIFICATE.len(),
        ),
    ];
    definitions
        .into_iter()
        .map(|(id, algorithm, name, length)| {
            let mut label = [0; 40];
            label[..name.len()].copy_from_slice(name);
            let info = YubiHsmObjectInfo {
                capabilities: [0; 8],
                id,
                length: length as u16,
                domains: 1,
                object_type: YUBIHSM_OPAQUE,
                algorithm,
                sequence: 1,
                origin: 1,
                label,
                delegated_capabilities: [0; 8],
            };
            yubihsm_token_objects(slot_id, info, None)?
                .pop()
                .ok_or(CKR_DEVICE_ERROR.into())
        })
        .collect()
}

#[cfg(feature = "abi-tests")]
impl Slot for AbiYubiHsmSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        String::from("PKCS11RS ABI YubiHSM test slot")
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        "ABI YubiHSM"
    }

    fn model(&self) -> &str {
        "ABI YubiHSM"
    }

    fn serial(&self) -> &str {
        "HSM00001"
    }

    fn major(&self) -> u8 {
        2
    }

    fn minor(&self) -> u8 {
        4
    }

    fn is_present(&self) -> bool {
        true
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(AbiYubiHsmSession { slot_id, flags })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        if pin == b"1234" {
            Ok(())
        } else {
            Err(CKR_PIN_INCORRECT.into())
        }
    }

    fn logout(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        Ok(())
    }

    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = vec![
            abi_test_yubihsm_object(slot_id),
            abi_test_yubihsm_aes_object(slot_id),
            abi_test_yubihsm_nist_aes_object(slot_id),
        ];
        objects.extend(abi_test_yubihsm_authentication_objects(slot_id)?);
        objects.extend(abi_test_yubihsm_opaque_objects(slot_id)?);
        Ok(objects)
    }

    fn mechanisms(&self) -> Vec<MechanismDetails> {
        yubihsm_mechanisms(&[
            YUBIHSM_ALGO_RSA_PKCS1_SHA1,
            YUBIHSM_ALGO_RSA_2048,
            YUBIHSM_ALGO_AES128,
            YUBIHSM_ALGO_AES_ECB,
            YUBIHSM_ALGO_AES_CBC,
        ])
    }

    fn is_yubihsm(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct PivSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    authenticated: Rc<Cell<bool>>,
}

impl Session for PivSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        let retries = PivClient.pin_retries(self.connector.as_ref())?;
        if self.authenticated.get() && retries != u8::MAX {
            self.authenticated.set(false);
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        Ok(())
    }
    fn piv_sign(
        &self,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if piv_policy_requires_login(slot, pin_policy) && !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = PivClient.sign(self.connector.as_ref(), slot, algorithm, input);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn piv_decipher(
        &self,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if piv_policy_requires_login(slot, pin_policy) && !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = PivClient.decipher(self.connector.as_ref(), slot, algorithm, input);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
}

#[derive(Debug)]
struct OpenPgpSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    authenticated: Rc<Cell<bool>>,
}

impl Session for OpenPgpSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let random = OpenPgpClient.challenge(self.connector.as_ref(), chunk.len())?;
            chunk.copy_from_slice(&random);
        }
        Ok(())
    }
    fn openpgp_sign(
        &self,
        key_ref: OpenPgpKeyRef,
        input: &[u8],
        pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = OpenPgpClient.sign(self.connector.as_ref(), key_ref, input);
        if key_ref == OpenPgpKeyRef::Signature && pin_policy == openpgp::PW1_ONE_SIGNATURE {
            self.authenticated.set(false);
        }
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn openpgp_decipher(&self, input: &[u8], raw: bool) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = OpenPgpClient.decipher(self.connector.as_ref(), input, raw);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
    fn openpgp_derive(
        &self,
        key_ref: OpenPgpKeyRef,
        algorithm: OpenPgpAlgorithm,
        public_key: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if key_ref != OpenPgpKeyRef::Decipher {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let curve = match algorithm {
            OpenPgpAlgorithm::Ecdh(curve) => curve,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        let result = OpenPgpClient.ecdh(self.connector.as_ref(), curve, public_key);
        if matches!(&result, Err(Error::Generic(rv)) if *rv == CKR_USER_NOT_LOGGED_IN as _) {
            self.authenticated.set(false);
        }
        result
    }
}

#[derive(Debug)]
struct YubiHsmSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<YubiHsmSecureSession>>>,
}

impl Session for YubiHsmSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        self.send_secure_cmd(&YubiHsmCommand::get_storage_info())
            .map(|_| ())
    }
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(1024) {
            let random =
                self.send_secure_cmd(&YubiHsmCommand::get_pseudo_random(chunk.len() as u16))?;
            if random.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&random);
        }
        Ok(())
    }
    fn yubihsm_command(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        self.send_secure_cmd(command)
    }
}

impl YubiHsmSession {
    fn send_secure_cmd(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        send_yubihsm_secure_command(self.connector.as_ref(), self.session.as_ref(), command)
    }
}

#[derive(Debug)]
struct GlobalPlatformSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
}

impl Session for GlobalPlatformSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let response = self.send_apdu(
                &CommandApdu {
                    cla: 0x00,
                    ins: 0x84,
                    p1: 0x00,
                    p2: 0x00,
                    data: Vec::new(),
                    le: Some(chunk.len() as u32),
                    extended: false,
                },
                false,
            )?;
            if response.data.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&response.data);
        }
        Ok(())
    }
}

impl GlobalPlatformSession {
    fn send_apdu(&self, command: &CommandApdu, chained: bool) -> Result<ResponseApdu, Error> {
        let mut session_guard = self.session.try_borrow_mut()?;
        let result = {
            let session = session_guard.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
            if chained {
                session.transmit_chained(self.connector.as_ref(), command)
            } else {
                session.transmit(self.connector.as_ref(), command)
            }
        };
        if result.is_err() {
            *session_guard = None;
        }
        result
    }
}

trait Connector {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn hardware_version(&self) -> Option<(u8, u8)> {
        None
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn set_device_identity(&self, _firmware: Option<(u8, u8, u8)>, _serial: Option<&str>) {}
    fn is_present(&self) -> bool;
    fn buffer_size(&self) -> usize;
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error>;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }

    #[allow(dead_code)]
    fn set_applet_present(&self, _present: bool) {}
    fn set_discovery_error(&self, _error: &Error) {}
    fn clear_discovery_error(&self) {}

    fn establish_secure_channel(&self, _application_aid: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn clear_secure_channel(&self) {}

    fn name(&self) -> String {
        format!(
            "{} {} {}",
            self.manufacturer(),
            self.product(),
            self.serial()
        )
    }

    fn send(&self, send_buffer: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let mut receive_buffer = vec![0u8; self.buffer_size()];
        let slice = self.transmit(send_buffer, &mut receive_buffer, timeout)?;
        let len = slice.len();
        receive_buffer.truncate(len);
        Ok(receive_buffer)
    }
}

#[derive(Debug, Default)]
struct SecureChannelState {
    application_aid: Vec<u8>,
    session: Option<Scp03Session>,
}

#[derive(Debug)]
struct PcscAppletConnector {
    base: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    protocol: Option<SecureChannelProtocol>,
    state: Rc<RefCell<SecureChannelState>>,
    enabled: Cell<bool>,
    applet_present: Cell<bool>,
    discovery_error: RefCell<Option<String>>,
}

impl PcscAppletConnector {
    fn new(
        base: Rc<dyn Connector>,
        application_aid: &[u8],
        protocol: Option<SecureChannelProtocol>,
        state: Rc<RefCell<SecureChannelState>>,
    ) -> Self {
        let applet_present = base.is_present();
        Self {
            base,
            application_aid: application_aid.to_vec(),
            protocol,
            state,
            enabled: Cell::new(false),
            applet_present: Cell::new(applet_present),
            discovery_error: RefCell::new(None),
        }
    }

    fn ensure_selected(&self) -> Result<(), Error> {
        let mut state = self.state.try_borrow_mut()?;
        if state.application_aid != self.application_aid {
            state.session = None;
            state.application_aid.clear();
            select_application(self.base.as_ref(), &self.application_aid)?;
            state.application_aid = self.application_aid.clone();
        }

        if self.protocol.is_none() || !self.enabled.get() || state.session.is_some() {
            return Ok(());
        }

        let established = match self.protocol.ok_or(CKR_ARGUMENTS_BAD)? {
            SecureChannelProtocol::Scp03 => {
                let keys = Scp03KeySet::from_environment()?;
                let security_level = configured_security_level()?;
                Scp03Session::authenticate_selected(
                    self.base.as_ref(),
                    &keys,
                    security_level,
                    &self.application_aid,
                )?
            }
            SecureChannelProtocol::Scp11a => Scp11KeySet::from_environment(Scp11Variant::A)?
                .authenticate_selected(self.base.as_ref())?,
            SecureChannelProtocol::Scp11b => Scp11KeySet::from_environment(Scp11Variant::B)?
                .authenticate_selected(self.base.as_ref())?,
        };
        state.application_aid = self.application_aid.clone();
        state.session = Some(established);
        Ok(())
    }

    fn record_discovery_error(&self, error: &Error) {
        *self.discovery_error.borrow_mut() = Some(format!("{error:?}"));
    }

    fn forget_discovery_error(&self) {
        *self.discovery_error.borrow_mut() = None;
    }
}

impl Connector for PcscAppletConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        self.base.name()
    }

    fn manufacturer(&self) -> &str {
        self.base.manufacturer()
    }

    fn product(&self) -> &str {
        self.base.product()
    }

    fn serial(&self) -> &str {
        self.base.serial()
    }

    fn major(&self) -> u8 {
        self.base.major()
    }

    fn minor(&self) -> u8 {
        self.base.minor()
    }
    fn hardware_version(&self) -> Option<(u8, u8)> {
        self.base.hardware_version()
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.base.firmware_version()
    }
    fn set_device_identity(&self, firmware: Option<(u8, u8, u8)>, serial: Option<&str>) {
        self.base.set_device_identity(firmware, serial);
    }

    fn is_present(&self) -> bool {
        self.base.is_present() && self.applet_present.get()
    }

    fn buffer_size(&self) -> usize {
        self.base.buffer_size()
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.ensure_selected()?;
        if self.protocol.is_none() || !self.enabled.get() {
            return self.base.transmit(send_buffer, receive_buffer, timeout);
        }
        let mut state = self.state.try_borrow_mut()?;
        let channel = state.session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let result: Result<Vec<u8>, Error> = (|| {
            let command = CommandApdu::decode(send_buffer)?;
            let response = channel.transmit(self.base.as_ref(), &command)?;
            Ok(response.encode())
        })();
        if result.is_err() {
            state.session = None;
            state.application_aid.clear();
        }
        let encoded = result?;
        if encoded.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..encoded.len()].copy_from_slice(&encoded);
        Ok(&receive_buffer[..encoded.len()])
    }

    fn refresh(&self) -> Result<(), Error> {
        let result = self.base.refresh();
        if result.is_err() || !self.base.is_present() {
            self.applet_present.set(false);
            if let Err(error) = &result {
                self.record_discovery_error(error);
            } else {
                self.record_discovery_error(&Error::from(CKR_DEVICE_REMOVED));
            }
            self.clear_secure_channel();
            return result;
        }

        self.clear_secure_channel();
        match select_application(self.base.as_ref(), &self.application_aid) {
            Ok(()) => {
                if let Ok(mut state) = self.state.try_borrow_mut() {
                    state.session = None;
                    state.application_aid = self.application_aid.clone();
                }
                self.applet_present.set(true);
                self.forget_discovery_error();
                Ok(())
            }
            Err(error) => {
                self.applet_present.set(false);
                self.record_discovery_error(&error);
                Err(error)
            }
        }
    }

    fn set_applet_present(&self, present: bool) {
        self.applet_present.set(present);
        if !present {
            self.clear_secure_channel();
        }
    }

    fn set_discovery_error(&self, error: &Error) {
        self.record_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.forget_discovery_error();
    }

    fn establish_secure_channel(&self, application_aid: &[u8]) -> Result<(), Error> {
        if application_aid != self.application_aid {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        self.enabled.set(true);
        if let Err(error) = self.ensure_selected() {
            self.enabled.set(false);
            return Err(error);
        }
        Ok(())
    }

    fn clear_secure_channel(&self) {
        self.enabled.set(false);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            if state.application_aid == self.application_aid {
                state.session = None;
                state.application_aid.clear();
            }
        }
    }
}

impl std::fmt::Debug for dyn Connector + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[derive(Debug)]
struct UsbConnector {
    handle: rusb::DeviceHandle<rusb::Context>,
    version: rusb::Version,
    manufacturer: String,
    product: String,
    serial: String,
    packet_size: usize,
    claimed: bool,
}

impl Connector for UsbConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        &self.manufacturer
    }
    fn product(&self) -> &str {
        &self.product
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn major(&self) -> u8 {
        self.version.major()
    }
    fn minor(&self) -> u8 {
        self.version.minor()
    }
    fn hardware_version(&self) -> Option<(u8, u8)> {
        Some((self.version.major(), self.version.minor()))
    }
    fn is_present(&self) -> bool {
        self.claimed
    }
    fn buffer_size(&self) -> usize {
        3136 + self.packet_size
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let len = self.handle.write_bulk(0x01, send_buffer, timeout)?;
        log!(2, "libusb.write_bulk({:?}) -> {}", send_buffer, len);
        ensure_complete_write(len, send_buffer.len())?;
        if needs_zero_length_packet(len, self.packet_size) {
            // Write a ZLP if last packet is full
            let zlp = self.handle.write_bulk(0x01, &[], timeout)?;
            log!(2, "libusb.write_bulk'zlp() -> {}", zlp);
        }
        let len = self.handle.read_bulk(0x81, receive_buffer, timeout)?;
        log!(
            2,
            "libusb.read_bulk({:?}) -> {}",
            &receive_buffer[..len],
            len
        );
        Ok(&receive_buffer[..len])
    }
}

fn ensure_complete_write(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(CKR_DEVICE_ERROR.into())
    }
}

fn needs_zero_length_packet(length: usize, packet_size: usize) -> bool {
    packet_size != 0 && length.is_multiple_of(packet_size)
}

fn bulk_out_packet_size(device: &rusb::Device<rusb::Context>) -> Result<usize, Error> {
    let config = device.active_config_descriptor()?;
    for interface in config.interfaces() {
        for descriptor in interface.descriptors() {
            for endpoint in descriptor.endpoint_descriptors() {
                if endpoint.address() == 0x01
                    && endpoint.transfer_type() == rusb::TransferType::Bulk
                {
                    return Ok(endpoint.max_packet_size() as usize);
                }
            }
        }
    }
    Err(rusb::Error::NotFound.into())
}

impl UsbConnector {
    fn connect(&mut self) -> Result<(), Error> {
        self.handle.claim_interface(0)?;
        let mut stale = vec![0; self.buffer_size()];
        if let Ok(length) = self
            .handle
            .read_bulk(0x81, &mut stale, Duration::from_millis(1))
        {
            log!(2, "libusb drained {length} stale bytes");
        }
        self.claimed = true;
        Ok(())
    }
    fn _disconnect(&mut self) -> Result<(), Error> {
        self.handle.release_interface(0)?;
        self.claimed = false;
        Ok(())
    }
}

struct PcscConnector {
    reader: std::ffi::CString,
    context: Rc<pcsc::Context>,
    card: RefCell<Option<pcsc::Card>>,
    firmware_version: Cell<Option<(u8, u8, u8)>>,
    serial_number: OnceLock<String>,
}

impl std::fmt::Debug for PcscConnector {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("PcscConnector")
            .field("reader", &self.reader)
            .field("card", &self.card.borrow().as_ref().map(|_| "Card"))
            .finish_non_exhaustive()
    }
}

impl Connector for PcscConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        self.reader.to_string_lossy().to_string()
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "YubiKey"
    }
    fn serial(&self) -> &str {
        self.serial_number.get().map(String::as_str).unwrap_or("0")
    }
    fn major(&self) -> u8 {
        0
    }
    fn minor(&self) -> u8 {
        0
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.firmware_version.get()
    }
    fn set_device_identity(&self, firmware: Option<(u8, u8, u8)>, serial: Option<&str>) {
        if let Some(firmware) = firmware {
            self.firmware_version.set(Some(firmware));
        }
        if let Some(serial) = serial {
            let _ = self.serial_number.set(serial.to_string());
        }
    }
    fn is_present(&self) -> bool {
        self.card.borrow().is_some()
    }
    fn buffer_size(&self) -> usize {
        pcsc::MAX_BUFFER_SIZE_EXTENDED
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let card = self.card.borrow();
        match card.as_ref() {
            Some(card) => {
                let received = card.transmit(send_buffer, receive_buffer)?;
                log!(
                    2,
                    "pcsc.transmit({} bytes) -> {} bytes",
                    send_buffer.len(),
                    received.len()
                );
                Ok(received)
            }
            None => Err(Error::from(pcsc::Error::NoSmartcard)),
        }
    }
    fn refresh(&self) -> Result<(), Error> {
        if self
            .card
            .borrow()
            .as_ref()
            .is_some_and(|card| card.status2_owned().is_ok())
        {
            return Ok(());
        }
        *self.card.borrow_mut() = None;
        let card = self.context.connect(
            &self.reader,
            pcsc::ShareMode::Exclusive,
            pcsc::Protocols::T0 | pcsc::Protocols::T1,
        )?;
        *self.card.borrow_mut() = Some(card);
        Ok(())
    }
}

impl PcscConnector {
    fn _reconnect(&self) -> Result<(), Error> {
        match self.card.borrow_mut().as_mut() {
            Some(card) => card
                .reconnect(
                    pcsc::ShareMode::Exclusive,
                    pcsc::Protocols::T0 | pcsc::Protocols::T1,
                    pcsc::Disposition::ResetCard,
                )
                .map_err(|e| e.into()),
            None => Err(Error::from(pcsc::Error::NoSmartcard)),
        }
    }
    fn _disconnect(&self) -> Result<(), Error> {
        *self.card.borrow_mut() = None;
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct CurlConnector {
    serial: String,
    url: String,
    connected: bool,
    curl: RefCell<curl::easy::Easy>,
}

impl Connector for CurlConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "CurlConnector"
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn major(&self) -> u8 {
        0
    }
    fn minor(&self) -> u8 {
        1
    }
    fn is_present(&self) -> bool {
        self.connected
    }
    fn buffer_size(&self) -> usize {
        2048
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let mut write_len = 0usize;
        let mut read_len = 0usize;
        let mut curl = self.curl.try_borrow_mut()?;
        curl.post_field_size(send_buffer.len() as u64)?;
        {
            let mut transfer = curl.transfer();
            transfer.read_function(|mut slice| match slice.write(&send_buffer[read_len..]) {
                Ok(read) => {
                    read_len += read;
                    Ok(read)
                }
                Err(_) => Err(curl::easy::ReadError::Abort),
            })?;
            transfer.write_function(|slice| {
                let mut rslice = &mut receive_buffer[write_len..];
                match rslice.write(slice) {
                    Ok(writ) => {
                        write_len += writ;
                        Ok(writ)
                    }
                    Err(_) => Err(curl::easy::WriteError::Pause),
                }
            })?;
            transfer.perform()?;
        }
        let received = &receive_buffer[..write_len];
        log!(2, "curl.post({:?}) -> {:?}", send_buffer, received);
        Ok(received)
    }
}

impl CurlConnector {
    #[allow(dead_code)]
    fn connect(&mut self) -> Result<(), Error> {
        let mut received = Vec::new();
        let mut curl = self.curl.try_borrow_mut()?;
        curl.url(&format!("{}/connector/status", self.url))?;
        {
            let mut transfer = curl.transfer();
            transfer.write_function(|slice| {
                received.extend(slice);
                Ok(slice.len())
            })?;
            transfer.perform()?;
        }
        log!(
            2,
            "curl.get() -> {:?}",
            String::from_utf8_lossy(&received).to_string()
        );
        curl.url(&format!("{}/connector/api", self.url))?;
        curl.post(true)?;
        self.connected = true;
        Ok(())
    }
}

struct Context {
    libusb: Option<rusb::Context>,
    pcsc: Option<Rc<pcsc::Context>>,
    slots: HashMap<CK_SLOT_ID, Box<dyn Slot>>,
    dynamic_slots: HashSet<CK_SLOT_ID>,
    slots_discovered: bool,
    sessions: HashMap<CK_SESSION_HANDLE, Box<dyn Session>>,
    logged_in_slots: HashSet<CK_SLOT_ID>,
    objects: HashMap<CK_OBJECT_HANDLE, TokenObject>,
    next_object_handle: CK_OBJECT_HANDLE,
    find_operations: HashMap<CK_SESSION_HANDLE, FindOperation>,
    encrypt_operations: HashMap<CK_SESSION_HANDLE, CryptOperation>,
    decrypt_operations: HashMap<CK_SESSION_HANDLE, CryptOperation>,
    sign_operations: HashMap<CK_SESSION_HANDLE, SignatureOperation>,
    verify_operations: HashMap<CK_SESSION_HANDLE, SignatureOperation>,
}

#[derive(Debug, Clone)]
struct TokenObject {
    slot_id: Option<CK_SLOT_ID>,
    unique_id: Vec<u8>,
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    label: Vec<u8>,
    id: Vec<u8>,
    token: bool,
    private: bool,
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    derive: bool,
    sensitive: bool,
    extractable: bool,
    always_sensitive: bool,
    never_extractable: bool,
    local: bool,
    key_gen_mechanism: Option<CK_MECHANISM_TYPE>,
    owner_session: Option<CK_SESSION_HANDLE>,
    material: KeyMaterial,
}

#[derive(Clone)]
#[cfg_attr(not(any(test, feature = "abi-tests")), allow(dead_code))]
enum KeyMaterial {
    None,
    RsaPrivate(Rsa<Private>),
    RsaPublic(Rsa<Public>),
    PivPrivate {
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        pin_policy: u8,
        touch_policy: u8,
    },
    PivPublic {
        algorithm: piv::Algorithm,
        public_key: Vec<u8>,
    },
    OpenPgpPrivate {
        key_ref: OpenPgpKeyRef,
        algorithm: OpenPgpAlgorithm,
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        #[allow(dead_code)]
        public_key: Vec<u8>,
        pin_policy: u8,
    },
    OpenPgpPublic {
        algorithm: OpenPgpAlgorithm,
        public_key: Vec<u8>,
    },
    PivCertificate {
        algorithm: piv::Algorithm,
        value: Vec<u8>,
        attestation: bool,
    },
    PivAttestation {
        connector: Rc<dyn Connector>,
        slot: piv::Slot,
        algorithm: piv::Algorithm,
        value: Rc<RefCell<Option<Vec<u8>>>>,
        attempted: Rc<Cell<bool>>,
    },
    OpenPgpCertificate {
        value: Vec<u8>,
    },
    YubiHsm {
        id: u16,
        object_type: u8,
        algorithm: u8,
        length: usize,
        #[allow(dead_code)]
        domains: u16,
        capabilities: [u8; 8],
        #[allow(dead_code)]
        delegated_capabilities: [u8; 8],
        public_key: Vec<u8>,
        value: Rc<RefCell<Option<Vec<u8>>>>,
    },
    Secret(Zeroizing<Vec<u8>>),
    DerivedSecret(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => fmt.write_str("None"),
            Self::RsaPrivate(key) => fmt.debug_tuple("RsaPrivate").field(&key.size()).finish(),
            Self::RsaPublic(key) => fmt.debug_tuple("RsaPublic").field(&key.size()).finish(),
            Self::PivPrivate {
                slot,
                algorithm,
                modulus,
                public_exponent: _,
                touch_policy,
                ..
            } => fmt
                .debug_struct("PivPrivate")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("size", &modulus.len())
                .field("touch_policy", touch_policy)
                .finish(),
            Self::PivPublic {
                algorithm,
                public_key,
            } => fmt
                .debug_struct("PivPublic")
                .field("algorithm", algorithm)
                .field("size", &public_key.len())
                .finish(),
            Self::OpenPgpPrivate {
                key_ref,
                algorithm,
                modulus,
                pin_policy,
                ..
            } => fmt
                .debug_struct("OpenPgpPrivate")
                .field("key_ref", key_ref)
                .field("algorithm", algorithm)
                .field("size", &modulus.len())
                .field("pin_policy", pin_policy)
                .finish(),
            Self::OpenPgpPublic {
                algorithm,
                public_key,
            } => fmt
                .debug_struct("OpenPgpPublic")
                .field("algorithm", algorithm)
                .field("size", &public_key.len())
                .finish(),
            Self::YubiHsm {
                id,
                object_type,
                algorithm,
                length,
                ..
            } => fmt
                .debug_struct("YubiHsm")
                .field("id", id)
                .field("object_type", object_type)
                .field("algorithm", algorithm)
                .field("length", length)
                .finish(),
            Self::Secret(key) => fmt.debug_tuple("Secret").field(&key.len()).finish(),
            Self::DerivedSecret(key) => fmt.debug_tuple("DerivedSecret").field(&key.len()).finish(),
            Self::PivCertificate {
                value,
                algorithm,
                attestation,
            } => fmt
                .debug_struct("PivCertificate")
                .field("algorithm", algorithm)
                .field("attestation", attestation)
                .field("size", &value.len())
                .finish(),
            Self::PivAttestation {
                slot,
                algorithm,
                value,
                ..
            } => fmt
                .debug_struct("PivAttestation")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("cached", &value.borrow().is_some())
                .finish(),
            Self::OpenPgpCertificate { value } => fmt
                .debug_struct("OpenPgpCertificate")
                .field("size", &value.len())
                .finish(),
        }
    }
}

#[derive(Debug, Default)]
struct TokenObjectTemplate {
    class: Option<CK_OBJECT_CLASS>,
    key_type: Option<CK_KEY_TYPE>,
    label: Vec<u8>,
    id: Vec<u8>,
    token: bool,
    private: bool,
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    derive: bool,
    sensitive: Option<bool>,
    extractable: Option<bool>,
}

#[derive(Debug)]
struct FindOperation {
    objects: Vec<CK_OBJECT_HANDLE>,
    next: usize,
}

#[derive(Debug, Clone)]
struct SignatureOperation {
    key: KeyMaterial,
    slot_id: CK_SLOT_ID,
    requires_login: bool,
    context_specific_extended: bool,
    mechanism: CK_MECHANISM_TYPE,
    pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    piv_pin_policy: Option<u8>,
    buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
struct GcmParameters {
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag_bits: usize,
}

#[derive(Debug, Clone)]
struct CryptOperation {
    key: KeyMaterial,
    slot_id: CK_SLOT_ID,
    requires_login: bool,
    context_specific_extended: bool,
    mechanism: CK_MECHANISM_TYPE,
    iv: Option<[u8; 16]>,
    gcm: Option<GcmParameters>,
    oaep: Option<(u8, CK_MECHANISM_TYPE, Vec<u8>)>,
    piv_pin_policy: Option<u8>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("Context")
            .field("libusb", &self.libusb)
            .field("pcsc", &self.pcsc.as_ref().map(|_| "Context { .. }"))
            .field("slots", &self.slots)
            .field("sessions", &self.sessions)
            .field("objects", &self.objects)
            .field("find_operations", &self.find_operations)
            .field("encrypt_operations", &self.encrypt_operations)
            .field("decrypt_operations", &self.decrypt_operations)
            .field("sign_operations", &self.sign_operations)
            .field("verify_operations", &self.verify_operations)
            .finish()
    }
}

impl Context {
    #[allow(unused_mut)]
    fn new() -> Result<Context, Error> {
        #[cfg(feature = "abi-tests")]
        let slots = HashMap::from([
            (ABI_TEST_SLOT_ID, Box::new(AbiTestSlot) as Box<dyn Slot>),
            (
                ABI_TEST_PIV_SLOT_ID,
                Box::new(abi_test_piv_slot()?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP03_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP03")?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_YUBIHSM_SLOT_ID,
                Box::new(AbiYubiHsmSlot) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP11_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP11")?) as Box<dyn Slot>,
            ),
        ]);
        #[cfg(not(feature = "abi-tests"))]
        let slots = HashMap::new();

        let objects = default_objects()?;
        let next_object_handle = objects.keys().max().map(|handle| handle + 1).unwrap_or(1);
        let mut context = Context {
            #[cfg(feature = "abi-tests")]
            libusb: None,
            #[cfg(not(feature = "abi-tests"))]
            libusb: match rusb::Context::new() {
                Ok(context) => Some(context),
                Err(e) => {
                    log!(1, "libusb::Context::new: {}", e);
                    None
                }
            },
            #[cfg(feature = "abi-tests")]
            pcsc: None,
            #[cfg(not(feature = "abi-tests"))]
            pcsc: match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => Some(Rc::new(context)),
                Err(e) => {
                    log!(1, "pcsc::Context::establish: {}", e);
                    None
                }
            },
            slots,
            dynamic_slots: HashSet::new(),
            slots_discovered: false,
            sessions: HashMap::new(),
            logged_in_slots: HashSet::new(),
            objects,
            next_object_handle,
            find_operations: HashMap::new(),
            encrypt_operations: HashMap::new(),
            decrypt_operations: HashMap::new(),
            sign_operations: HashMap::new(),
            verify_operations: HashMap::new(),
        };
        #[cfg(all(feature = "abi-tests", not(test)))]
        add_abi_test_backend_objects(&mut context)?;
        log!(2, "Context.new {:?}", context);
        Ok(context)
    }
    fn get_info(&self, info: &mut CK_INFO) -> Result<(), Error> {
        info.cryptokiVersion.major = 3;
        info.cryptokiVersion.minor = 2;
        info.libraryVersion.major = 1;
        info.libraryVersion.minor = 0;
        info.flags = 0;
        str_pad(
            "YubiHSM & YubiKey PKCS#11 module",
            &mut info.libraryDescription,
        );
        str_pad("Yubico", &mut info.manufacturerID);
        Ok(())
    }
    fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        match self.slots.get(&slot_id) {
            Some(slot) => Ok(slot.as_ref()),
            None => Err(CKR_SLOT_ID_INVALID.into()),
        }
    }
    fn get_present_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        let slot = self.get_slot(slot_id)?;
        if slot.is_present() {
            Ok(slot)
        } else {
            Err(CKR_TOKEN_NOT_PRESENT.into())
        }
    }
    fn _get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> Result<&mut (dyn Slot + '_), Error> {
        match self.slots.get_mut(&slot_id) {
            Some(slot) => Ok(slot.as_mut()),
            None => Err(CKR_SLOT_ID_INVALID.into()),
        }
    }
    fn get_session_(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Option<(&(dyn Slot + '_), &(dyn Session + '_))> {
        let session = self.sessions.get(&session_handle)?;
        let slot = self.slots.get(&session.slotID())?;
        Some((slot.as_ref(), session.as_ref()))
    }
    fn _get_session(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(&(dyn Slot + '_), &(dyn Session + '_)), Error> {
        match self.get_session_(session_handle) {
            Some(ctx) => Ok(ctx),
            None => Err(CKR_SESSION_HANDLE_INVALID.into()),
        }
    }
    fn session_details(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(CK_SLOT_ID, CK_FLAGS, bool), Error> {
        let session = self._get_session(session_handle)?.1;
        let slot_id = session.slotID();
        Ok((slot_id, session.flags(), self.is_slot_logged_in(slot_id)))
    }

    fn is_slot_logged_in(&self, slot_id: CK_SLOT_ID) -> bool {
        self.logged_in_slots.contains(&slot_id)
            && self
                .slots
                .get(&slot_id)
                .is_some_and(|slot| slot.login_is_active())
    }

    fn reconcile_login_state(&mut self, slot_id: CK_SLOT_ID) {
        if self.logged_in_slots.contains(&slot_id) && !self.is_slot_logged_in(slot_id) {
            self.clear_login_state(slot_id);
        }
    }

    fn insert_object(&mut self, mut object: TokenObject) -> CK_OBJECT_HANDLE {
        let handle = self.next_object_handle;
        self.next_object_handle += 1;
        if object.unique_id.is_empty() {
            object.unique_id = handle.to_string().into_bytes();
        }
        self.objects.insert(handle, object);
        handle
    }

    fn refresh_slot_token_objects(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        let objects = self
            .slots
            .get(&slot_id)
            .ok_or(CKR_SLOT_ID_INVALID)?
            .token_objects(slot_id)?;
        self.objects
            .retain(|_, object| object.slot_id != Some(slot_id) || !object.token);
        for object in objects.into_iter().filter(|object| object.token) {
            self.insert_object(object);
        }
        Ok(())
    }

    fn insert_session_objects(
        &mut self,
        slot_id: CK_SLOT_ID,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        let objects = self
            .slots
            .get(&slot_id)
            .ok_or(CKR_SLOT_ID_INVALID)?
            .session_objects(slot_id)?;
        for mut object in objects.into_iter().filter(|object| !object.token) {
            if self.objects.values().any(|existing| {
                existing.owner_session == Some(session_handle)
                    && existing.slot_id == Some(slot_id)
                    && existing.unique_id == object.unique_id
            }) {
                continue;
            }
            object.set_owner(session_handle, slot_id);
            self.insert_object(object);
        }
        Ok(())
    }

    fn clear_login_state(&mut self, slot_id: CK_SLOT_ID) {
        self.logged_in_slots.remove(&slot_id);
        let slot_sessions: HashSet<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter(|(_handle, session)| session.slotID() == slot_id)
            .map(|(handle, _session)| *handle)
            .collect();
        self.find_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.encrypt_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.decrypt_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.sign_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.verify_operations
            .retain(|session, _operation| !slot_sessions.contains(session));

        self.objects
            .retain(|_, object| object.slot_id != Some(slot_id) || object.token || !object.private);
        let private_token_handles: Vec<CK_OBJECT_HANDLE> = self
            .objects
            .iter()
            .filter(|(_handle, object)| {
                object.slot_id == Some(slot_id) && object.token && object.private
            })
            .map(|(handle, _object)| *handle)
            .collect();
        for handle in private_token_handles {
            if let Some(object) = self.objects.remove(&handle) {
                self.insert_object(object);
            }
        }
    }

    fn logout_slot(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self._get_slot_mut(slot_id)?.logout()?;
        self.clear_login_state(slot_id);
        Ok(())
    }

    fn close_slot_state(&mut self, slot_id: CK_SLOT_ID, remove_token_objects: bool) {
        self.logged_in_slots.remove(&slot_id);
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.clear_session();
        }
        let sessions: HashSet<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.slotID() == slot_id)
            .map(|(handle, _)| *handle)
            .collect();
        self.sessions.retain(|handle, _| !sessions.contains(handle));
        self.find_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.encrypt_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.decrypt_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.sign_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.verify_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.objects.retain(|_, object| {
            object.slot_id != Some(slot_id) || (!remove_token_objects && object.token)
        });
    }

    #[allow(unreachable_code)]
    fn init(&mut self) {
        if self.slots_discovered {
            return;
        }
        self.slots_discovered = true;
        #[cfg(feature = "abi-tests")]
        {
            return;
        }
        let mut seen_dynamic_slots = HashSet::new();
        if let Some(context) = self.libusb.as_ref() {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(desc) = device.device_descriptor() {
                        //eprintln!("USB Bus {} Device {}: ID {}: {}", device.bus_number(), device.address(), desc.vendor_id(), desc.product_id());
                        if desc.vendor_id() == 0x1050 && desc.product_id() == 0x30 {
                            match device.open() {
                                Ok(handle) => {
                                    let version = desc.device_version();
                                    let packet_size = match bulk_out_packet_size(&device) {
                                        Ok(packet_size) => packet_size,
                                        Err(error) => {
                                            log!(1, "libusb bulk OUT endpoint: {:?}", error);
                                            continue;
                                        }
                                    };
                                    let manufacturer = handle
                                        .read_manufacturer_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let product =
                                        handle.read_product_string_ascii(&desc).unwrap_or_default();
                                    let serial = handle
                                        .read_serial_number_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let mut connector = UsbConnector {
                                        handle,
                                        version,
                                        manufacturer,
                                        product,
                                        serial,
                                        packet_size,
                                        claimed: false,
                                    };
                                    //let mut connector = CurlConnector { serial, url: String::from("http://127.0.0.1:12345"), connected: false, curl: RefCell::new(curl::easy::Easy::new()) };
                                    let name = connector.name();
                                    log!(2, "{}", name);
                                    if let Some(slot_id) =
                                        self.slots.iter().find_map(|(slot_id, slot)| {
                                            (slot.name() == name).then_some(*slot_id)
                                        })
                                    {
                                        if self.dynamic_slots.contains(&slot_id) {
                                            seen_dynamic_slots.insert(slot_id);
                                        }
                                        continue;
                                    }
                                    if let Err(error) = connector.connect() {
                                        log!(1, "libusb.claim_interface: {:?}", error);
                                        continue;
                                    }
                                    let slot_id = next_key(&self.slots, 0);
                                    let mut slot = Box::new(YubiHsmSlot {
                                        connector: Rc::new(connector),
                                        session: Rc::new(RefCell::new(None)),
                                        version: (0, 0, 0),
                                        algorithms: Vec::new(),
                                    });
                                    if let Err(error) = slot.init_slot() {
                                        log!(1, "YubiHSM GET DEVICE INFO: {:?}", error);
                                        continue;
                                    }
                                    self.slots.insert(slot_id, slot);
                                    self.dynamic_slots.insert(slot_id);
                                    seen_dynamic_slots.insert(slot_id);
                                }
                                Err(e) => {
                                    log!(1, "libusb.open: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(context) = self.pcsc.clone() {
            if let Ok(readers) = context.list_readers_owned() {
                for reader in readers {
                    let connector = PcscConnector {
                        reader,
                        context: context.clone(),
                        card: RefCell::new(None),
                        firmware_version: Cell::new(None),
                        serial_number: OnceLock::new(),
                    };
                    let name = connector.name();
                    log!(2, "{}", name);
                    if let Some(slot_id) = self
                        .slots
                        .iter()
                        .find_map(|(slot_id, slot)| (slot.name() == name).then_some(*slot_id))
                    {
                        if self.dynamic_slots.contains(&slot_id) {
                            seen_dynamic_slots.insert(slot_id);
                        }
                        let (was_present, is_present) = {
                            let slot = self.slots.get(&slot_id).unwrap();
                            let was_present = slot.is_present();
                            map(slot.refresh());
                            (was_present, slot.is_present())
                        };
                        if was_present && !is_present {
                            self.close_slot_state(slot_id, false);
                        } else if !was_present && is_present {
                            let initialized = self
                                .slots
                                .get_mut(&slot_id)
                                .ok_or_else(|| Error::from(CKR_SLOT_ID_INVALID))
                                .and_then(|slot| slot.init_slot());
                            if let Err(error) = initialized {
                                log!(
                                    1,
                                    "CCID application initialization failed for {}: {:?}",
                                    name,
                                    error
                                );
                                if let Some(slot) = self.slots.get(&slot_id) {
                                    slot.set_discovery_error(&error);
                                }
                            } else {
                                if let Some(slot) = self.slots.get(&slot_id) {
                                    slot.clear_discovery_error();
                                }
                                if let Err(error) = self.refresh_slot_token_objects(slot_id) {
                                    log!(2, "CCID object discovery: {:?}", error);
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.set_discovery_error(&error);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    if let Err(error) = connector.refresh() {
                        log!(1, "PCSC reader has no usable card: {:?}", error);
                        let reader_prefix = format!("{} ", name);
                        let known_slot_ids: Vec<CK_SLOT_ID> = self
                            .slots
                            .iter()
                            .filter(|(slot_id, slot)| {
                                self.dynamic_slots.contains(slot_id)
                                    && slot.name().starts_with(&reader_prefix)
                            })
                            .map(|(slot_id, _)| *slot_id)
                            .collect();
                        for slot_id in known_slot_ids {
                            seen_dynamic_slots.insert(slot_id);
                            let was_present = self
                                .slots
                                .get(&slot_id)
                                .is_some_and(|slot| slot.is_present());
                            if let Some(slot) = self.slots.get(&slot_id) {
                                map(slot.refresh());
                                if was_present && !slot.is_present() {
                                    self.close_slot_state(slot_id, false);
                                }
                            }
                        }
                        continue;
                    }
                    let configurations = match configured_ccid_configurations() {
                        Ok(configurations) => configurations,
                        Err(error) => {
                            log!(1, "CCID application configuration: {:?}", error);
                            continue;
                        }
                    };
                    let base_connector: Rc<dyn Connector> = Rc::new(connector);
                    let shared_state = Rc::new(RefCell::new(SecureChannelState::default()));
                    for configuration in configurations {
                        let application_label = ccid_application_label(configuration.application);
                        let name = format!("{} {}", base_connector.name(), application_label);
                        if let Some(slot_id) = self
                            .slots
                            .iter()
                            .find_map(|(slot_id, slot)| (slot.name() == name).then_some(*slot_id))
                        {
                            if self.dynamic_slots.contains(&slot_id) {
                                seen_dynamic_slots.insert(slot_id);
                            }
                            let (was_present, is_present) = {
                                let slot = self.slots.get(&slot_id).unwrap();
                                let was_present = slot.is_present();
                                map(slot.refresh());
                                (was_present, slot.is_present())
                            };
                            if was_present && !is_present {
                                self.close_slot_state(slot_id, false);
                            } else if !was_present && is_present {
                                let initialized = self
                                    .slots
                                    .get_mut(&slot_id)
                                    .ok_or_else(|| Error::from(CKR_SLOT_ID_INVALID))
                                    .and_then(|slot| slot.init_slot());
                                if let Err(error) = initialized {
                                    log!(
                                        1,
                                        "CCID application initialization failed for {}: {:?}",
                                        application_label,
                                        error
                                    );
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.set_discovery_error(&error);
                                    }
                                } else {
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.clear_discovery_error();
                                    }
                                    if let Err(error) = self.refresh_slot_token_objects(slot_id) {
                                        log!(2, "CCID object discovery: {:?}", error);
                                        if let Some(slot) = self.slots.get(&slot_id) {
                                            slot.set_discovery_error(&error);
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        let slot_id = next_key(&self.slots, 0);
                        let application_aid = match ccid_application_aid(
                            configuration.application,
                            configuration.secure_channel,
                        ) {
                            Ok(aid) => aid,
                            Err(error) => {
                                log!(1, "CCID application AID configuration: {:?}", error);
                                continue;
                            }
                        };
                        if let Err(error) =
                            select_application(base_connector.as_ref(), &application_aid)
                        {
                            log!(
                                1,
                                "CCID application AID selection for {}: {:?}",
                                application_label,
                                error
                            );
                            continue;
                        }
                        if let Ok(mut state) = shared_state.try_borrow_mut() {
                            state.session = None;
                            state.application_aid = application_aid.clone();
                        }
                        let application_connector: Rc<dyn Connector> =
                            Rc::new(PcscAppletConnector::new(
                                base_connector.clone(),
                                &application_aid,
                                configuration.secure_channel,
                                shared_state.clone(),
                            ));
                        let mut slot: Box<dyn Slot> = match configuration.application {
                            CcidApplication::Piv => Box::new(PivSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::HsmAuth => Box::new(GenericPcscSlot::new(
                                application_connector,
                                application_aid,
                                "YubiHSM Auth",
                            )),
                            CcidApplication::GlobalPlatform => Box::new(GlobalPlatformSlot {
                                connector: application_connector,
                                application_aid,
                                authenticated: Cell::new(false),
                            }),
                        };
                        if slot.is_present() {
                            if let Err(error) = slot.init_slot() {
                                log!(
                                    1,
                                    "CCID application initialization failed for reader {}, applet {}: {:?}",
                                    base_connector.name(),
                                    application_label,
                                    error
                                );
                                slot.set_discovery_error(&error);
                            } else {
                                slot.clear_discovery_error();
                            }
                        }
                        let token_objects = if slot.is_present() {
                            match slot.token_objects(slot_id) {
                                Ok(objects) => objects,
                                Err(error) => {
                                    log!(2, "CCID object discovery: {:?}", error);
                                    slot.set_discovery_error(&error);
                                    Vec::new()
                                }
                            }
                        } else {
                            Vec::new()
                        };
                        self.slots.insert(slot_id, slot);
                        for object in token_objects.into_iter().filter(|object| object.token) {
                            self.insert_object(object);
                        }
                        self.dynamic_slots.insert(slot_id);
                        seen_dynamic_slots.insert(slot_id);
                    }
                }
            }
        }
        let removed_slots: Vec<CK_SLOT_ID> = self
            .dynamic_slots
            .difference(&seen_dynamic_slots)
            .copied()
            .collect();
        for slot_id in removed_slots {
            self.close_slot_state(slot_id, true);
            self.slots.remove(&slot_id);
            self.dynamic_slots.remove(&slot_id);
        }
        log!(2, "Context.init {:?}", self);
    }
}

#[cfg(not(any(test, feature = "abi-tests")))]
fn default_objects() -> Result<HashMap<CK_OBJECT_HANDLE, TokenObject>, Error> {
    Ok(HashMap::new())
}

#[cfg(any(test, feature = "abi-tests"))]
fn default_objects() -> Result<HashMap<CK_OBJECT_HANDLE, TokenObject>, Error> {
    let private_key = Rsa::generate(2048)?;
    let public_key =
        Rsa::from_public_components(private_key.n().to_owned()?, private_key.e().to_owned()?)?;
    let objects = HashMap::from([
        (
            1,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: b"1".to_vec(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: b"Test RSA public key".to_vec(),
                id: vec![1],
                token: true,
                private: false,
                encrypt: true,
                decrypt: false,
                sign: false,
                verify: true,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::RsaPublic(public_key),
            },
        ),
        (
            2,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: b"2".to_vec(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: b"Test RSA private key".to_vec(),
                id: vec![1],
                token: true,
                private: true,
                encrypt: false,
                decrypt: true,
                sign: true,
                verify: false,
                derive: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::RsaPrivate(private_key),
            },
        ),
    ]);

    Ok(objects)
}

#[cfg(feature = "abi-tests")]
#[allow(dead_code)]
fn add_abi_test_backend_objects(context: &mut Context) -> Result<(), Error> {
    for object in abi_test_piv_slot()?.token_objects(ABI_TEST_PIV_SLOT_ID)? {
        context.insert_object(object);
    }
    context.insert_object(abi_test_yubihsm_object(ABI_TEST_YUBIHSM_SLOT_ID));
    context.insert_object(abi_test_yubihsm_aes_object(ABI_TEST_YUBIHSM_SLOT_ID));
    context.insert_object(abi_test_yubihsm_nist_aes_object(ABI_TEST_YUBIHSM_SLOT_ID));
    for object in abi_test_yubihsm_authentication_objects(ABI_TEST_YUBIHSM_SLOT_ID)? {
        context.insert_object(object);
    }
    for object in abi_test_yubihsm_opaque_objects(ABI_TEST_YUBIHSM_SLOT_ID)? {
        context.insert_object(object);
    }
    Ok(())
}

fn ulong_attribute(value: CK_ULONG) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn bool_attribute(value: bool) -> Vec<u8> {
    vec![if value {
        CK_TRUE as CK_BBOOL
    } else {
        CK_FALSE as CK_BBOOL
    }]
}

fn piv_certificate_attribute(value: &[u8], attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    match attribute_type {
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => Some(value.to_vec()),
        x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE => {
            Some(ulong_attribute(CKC_X_509 as CK_ULONG))
        }
        x if x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(0)),
        x if x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE => {
            Some(hash(MessageDigest::sha1(), value).ok()?.as_ref()[..3].to_vec())
        }
        x if x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE => openssl::x509::X509::from_der(value)
            .ok()?
            .subject_name()
            .to_der()
            .ok(),
        x if x == CKA_ISSUER as CK_ATTRIBUTE_TYPE => openssl::x509::X509::from_der(value)
            .ok()?
            .issuer_name()
            .to_der()
            .ok(),
        x if x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE => openssl::x509::X509::from_der(value)
            .ok()?
            .serial_number()
            .to_bn()
            .ok()
            .map(|serial| serial.to_vec()),
        x if x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE => openssl::x509::X509::from_der(value)
            .ok()?
            .public_key()
            .ok()?
            .public_key_to_der()
            .ok(),
        _ => None,
    }
}

fn is_certificate_attribute(attribute_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attribute_type,
        x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
            || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
            || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
            || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
            || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE
    )
}

fn lazy_piv_attestation_certificate(
    connector: &dyn Connector,
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    value: &RefCell<Option<Vec<u8>>>,
    attempted: &Cell<bool>,
) -> Option<Vec<u8>> {
    if attempted.replace(true) {
        return value.borrow().clone();
    }

    let certificate = PivClient.attestation(connector, slot).ok()?;
    if piv_algorithm_from_certificate(&certificate)? != algorithm {
        return None;
    }
    piv_public_key_from_certificate(algorithm, &certificate).ok()?;
    *value.borrow_mut() = Some(certificate.clone());
    Some(certificate)
}

impl TokenObject {
    fn has_sensitive_attributes(&self) -> bool {
        self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    fn is_visible_to(
        &self,
        session_handle: CK_SESSION_HANDLE,
        slot_id: CK_SLOT_ID,
        logged_in: bool,
    ) -> bool {
        self.slot_id == Some(slot_id)
            && (!self.private || logged_in)
            && self
                .owner_session
                .map(|owner| owner == session_handle)
                .unwrap_or(true)
    }

    fn set_owner(&mut self, session_handle: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID) {
        self.slot_id = Some(slot_id);
        self.owner_session = (!self.token).then_some(session_handle);
    }

    fn size(&self) -> CK_ULONG {
        let defer_certificate_attributes = matches!(
            &self.material,
            KeyMaterial::PivAttestation { attempted, .. } if !attempted.get()
        );
        [
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            CKA_LABEL as CK_ATTRIBUTE_TYPE,
            CKA_ID as CK_ATTRIBUTE_TYPE,
            CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE,
            CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            CKA_DERIVE as CK_ATTRIBUTE_TYPE,
            CKA_WRAP as CK_ATTRIBUTE_TYPE,
            CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
            CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE,
            CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE,
            CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE,
            CKA_COPYABLE as CK_ATTRIBUTE_TYPE,
            CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE,
            CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            CKA_VALUE_BITS as CK_ATTRIBUTE_TYPE,
            CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            CKA_MODULUS as CK_ATTRIBUTE_TYPE,
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
            CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
            CKA_EC_POINT as CK_ATTRIBUTE_TYPE,
            CKA_VALUE as CK_ATTRIBUTE_TYPE,
            CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE,
            CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE,
            CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE,
            CKA_SUBJECT as CK_ATTRIBUTE_TYPE,
            CKA_ISSUER as CK_ATTRIBUTE_TYPE,
            CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE,
            CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE,
            CKA_TRUSTED as CK_ATTRIBUTE_TYPE,
        ]
        .iter()
        .filter(|&&attribute_type| {
            !defer_certificate_attributes || !is_certificate_attribute(attribute_type)
        })
        .filter_map(|&attribute_type| self.attribute_value(attribute_type))
        .map(|value| value.len() as CK_ULONG)
        .sum()
    }

    fn attribute_value(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        match attribute_type {
            x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(self.class)),
            x if x == CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE => Some(self.unique_id.clone()),
            x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(ulong_attribute(self.key_type))
            }
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => Some(self.label.clone()),
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => Some(self.id.clone()),
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.token)),
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.private)),
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE
                && self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS =>
            {
                Some(bool_attribute(match &self.material {
                    KeyMaterial::PivPrivate {
                        slot, pin_policy, ..
                    } => piv_effective_pin_policy(*slot, *pin_policy) == 3,
                    KeyMaterial::OpenPgpPrivate {
                        key_ref,
                        pin_policy,
                        ..
                    } => openpgp_signature_requires_context_specific_login(*key_ref, *pin_policy),
                    _ => false,
                }))
            }
            x if x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.encrypt))
            }
            x if x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.decrypt))
            }
            x if x == CKA_SIGN as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.sign))
            }
            x if x == CKA_VERIFY as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.verify))
            }
            x if x == CKA_DERIVE as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.derive))
            }
            x if self.is_key_object()
                && (x == CKA_WRAP as CK_ATTRIBUTE_TYPE
                    || x == CKA_UNWRAP as CK_ATTRIBUTE_TYPE
                    || x == CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE
                    || x == CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE
                    || x == CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE) =>
            {
                Some(bool_attribute(false))
            }
            x if x == CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_MODIFIABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_COPYABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(bool_attribute(true))
            }
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE && self.is_immutable_object() => {
                Some(bool_attribute(false))
            }
            x if x == CKA_DESTROYABLE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(true)),
            x if x == CKA_TRUSTED as CK_ATTRIBUTE_TYPE
                && (self.is_certificate_object() || self.is_yubihsm_opaque()) =>
            {
                Some(bool_attribute(false))
            }
            x if x == CKA_APPLICATION as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(b"Opaque object".to_vec())
            }
            x if x == CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE && self.is_yubihsm_opaque() => {
                Some(Vec::new())
            }
            x if x == CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE && self.is_certificate_object() => {
                Some(ulong_attribute(CKC_X_509 as CK_ULONG))
            }
            x if x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::Secret(value) | KeyMaterial::DerivedSecret(value) => {
                    Some(ulong_attribute(value.len() as CK_ULONG))
                }
                KeyMaterial::YubiHsm { length, .. }
                    if self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS =>
                {
                    Some(ulong_attribute(*length as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_VALUE_BITS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::Secret(value) | KeyMaterial::DerivedSecret(value) => {
                    Some(ulong_attribute((value.len() * 8) as CK_ULONG))
                }
                KeyMaterial::YubiHsm { length, .. }
                    if self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS =>
                {
                    Some(ulong_attribute((*length * 8) as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(self.sensitive))
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(
                    self.extractable && !self.is_nonextractable_key_object(),
                ))
            }
            x if x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(self.always_sensitive))
            }
            x if x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(
                    self.never_extractable || self.is_nonextractable_key_object(),
                ))
            }
            x if x == CKA_LOCAL as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(bool_attribute(self.local))
            }
            x if x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE && self.is_key_object() => {
                Some(ulong_attribute(
                    self.key_gen_mechanism
                        .unwrap_or(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                ))
            }
            x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.n().to_vec()),
                KeyMaterial::RsaPublic(key) => Some(key.n().to_vec()),
                KeyMaterial::PivPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(modulus.clone())
                }
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(modulus.clone())
                }
                KeyMaterial::YubiHsm {
                    algorithm,
                    public_key,
                    ..
                } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                    Some(public_key.clone())
                }
                _ => None,
            },
            x if x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.e().to_vec()),
                KeyMaterial::RsaPublic(key) => Some(key.e().to_vec()),
                KeyMaterial::PivPrivate {
                    public_exponent, ..
                } if !public_exponent.is_empty() => Some(public_exponent.clone()),
                KeyMaterial::OpenPgpPrivate {
                    public_exponent, ..
                } if !public_exponent.is_empty() => Some(public_exponent.clone()),
                KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                    Some(vec![0x01, 0x00, 0x01])
                }
                _ => None,
            },
            x if x == CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(ulong_attribute((key.size() * 8) as CK_ULONG)),
                KeyMaterial::RsaPublic(key) => Some(ulong_attribute((key.size() * 8) as CK_ULONG)),
                KeyMaterial::PivPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(ulong_attribute((modulus.len() * 8) as CK_ULONG))
                }
                KeyMaterial::OpenPgpPrivate { modulus, .. } if !modulus.is_empty() => {
                    Some(ulong_attribute((modulus.len() * 8) as CK_ULONG))
                }
                KeyMaterial::YubiHsm {
                    algorithm,
                    public_key,
                    ..
                } if is_yubihsm_rsa(*algorithm) && !public_key.is_empty() => {
                    Some(ulong_attribute((public_key.len() * 8) as CK_ULONG))
                }
                _ => None,
            },
            x if x == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::YubiHsm { algorithm, .. } => {
                    yubihsm_ec_parameters(*algorithm).map(<[u8]>::to_vec)
                }
                KeyMaterial::PivPrivate { algorithm, .. }
                | KeyMaterial::PivPublic { algorithm, .. } => {
                    piv_ec_parameters(*algorithm).map(<[u8]>::to_vec)
                }
                KeyMaterial::OpenPgpPrivate { algorithm, .. }
                | KeyMaterial::OpenPgpPublic { algorithm, .. } => openpgp_ec_params(*algorithm),
                _ => None,
            },
            x if x == CKA_EC_POINT as CK_ATTRIBUTE_TYPE
                && self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS =>
            {
                match &self.material {
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if is_yubihsm_ec(*algorithm) && !public_key.is_empty() => {
                        let mut point = Vec::with_capacity(public_key.len() + 1);
                        point.push(0x04);
                        point.extend_from_slice(public_key);
                        der_octet_string(&point)
                    }
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if *algorithm == YUBIHSM_ALGO_ED25519 && !public_key.is_empty() => {
                        der_octet_string(public_key)
                    }
                    KeyMaterial::YubiHsm {
                        algorithm,
                        public_key,
                        ..
                    } if is_yubihsm_x25519(*algorithm) && !public_key.is_empty() => {
                        der_octet_string(public_key)
                    }
                    KeyMaterial::PivPublic {
                        algorithm,
                        public_key,
                    } if !public_key.is_empty() => {
                        let point = if piv_ec_coordinate_length(*algorithm).is_some() {
                            let mut point = Vec::with_capacity(public_key.len() + 1);
                            point.push(0x04);
                            point.extend_from_slice(public_key);
                            point
                        } else {
                            public_key.clone()
                        };
                        der_octet_string(&point)
                    }
                    KeyMaterial::OpenPgpPublic {
                        algorithm,
                        public_key,
                    } if !public_key.is_empty() => {
                        let point = if matches!(
                            algorithm,
                            OpenPgpAlgorithm::Ecdsa(_) | OpenPgpAlgorithm::Ecdh(_)
                        ) {
                            let mut point = Vec::with_capacity(public_key.len() + 1);
                            point.push(0x04);
                            point.extend_from_slice(public_key);
                            point
                        } else {
                            public_key.clone()
                        };
                        der_octet_string(&point)
                    }
                    _ => None,
                }
            }
            x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_CERTIFICATE_CATEGORY as CK_ATTRIBUTE_TYPE
                || x == CKA_CHECK_VALUE as CK_ATTRIBUTE_TYPE
                || x == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
                || x == CKA_ISSUER as CK_ATTRIBUTE_TYPE
                || x == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
                || x == CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE =>
            {
                match &self.material {
                    KeyMaterial::DerivedSecret(value) if x == CKA_VALUE as CK_ATTRIBUTE_TYPE => {
                        Some(value.to_vec())
                    }
                    KeyMaterial::PivCertificate { value, .. }
                    | KeyMaterial::OpenPgpCertificate { value } => {
                        piv_certificate_attribute(value, x)
                    }
                    KeyMaterial::PivAttestation {
                        connector,
                        slot,
                        algorithm,
                        value,
                        attempted,
                    } => lazy_piv_attestation_certificate(
                        connector.as_ref(),
                        *slot,
                        *algorithm,
                        value,
                        attempted,
                    )
                    .and_then(|value| piv_certificate_attribute(&value, x)),
                    KeyMaterial::YubiHsm {
                        object_type,
                        algorithm,
                        ..
                    } if *object_type == YUBIHSM_OPAQUE
                        && *algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE
                        && matches!(
                            x,
                            value if value == CKA_SUBJECT as CK_ATTRIBUTE_TYPE
                                || value == CKA_ISSUER as CK_ATTRIBUTE_TYPE
                                || value == CKA_SERIAL_NUMBER as CK_ATTRIBUTE_TYPE
                        ) =>
                    {
                        Some(Vec::new())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn is_key_object(&self) -> bool {
        self.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS
    }

    fn is_nonextractable_key_object(&self) -> bool {
        (self.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || self.class == CKO_SECRET_KEY as CK_OBJECT_CLASS)
            && !matches!(&self.material, KeyMaterial::DerivedSecret(_))
    }

    fn is_certificate_object(&self) -> bool {
        self.class == CKO_CERTIFICATE as CK_OBJECT_CLASS
    }

    fn is_yubihsm_opaque(&self) -> bool {
        matches!(
            self.material,
            KeyMaterial::YubiHsm {
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )
    }

    fn is_immutable_object(&self) -> bool {
        matches!(
            &self.material,
            KeyMaterial::PivPrivate { .. }
                | KeyMaterial::PivPublic { .. }
                | KeyMaterial::PivCertificate { .. }
                | KeyMaterial::PivAttestation { .. }
                | KeyMaterial::OpenPgpPrivate { .. }
                | KeyMaterial::OpenPgpPublic { .. }
                | KeyMaterial::OpenPgpCertificate { .. }
                | KeyMaterial::YubiHsm { .. }
                | KeyMaterial::DerivedSecret(_)
        )
    }

    fn set_attribute_value(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        let value = read_attribute_value(attribute)?;
        match attribute.type_ {
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => {
                self.label = value;
                Ok(())
            }
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => {
                self.id = value;
                Ok(())
            }
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE => {
                if !self.has_sensitive_attributes() {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
                let requested = read_bool_template_attribute(attribute)?;
                if self.sensitive && !requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                self.sensitive = requested;
                Ok(())
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE => {
                if !self.has_sensitive_attributes() {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV);
                }
                let requested = read_bool_template_attribute(attribute)?;
                if self.is_nonextractable_key_object() && requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                if !self.extractable && requested {
                    return Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV);
                }
                self.extractable = requested;
                Ok(())
            }
            x if self.attribute_value(x).is_some() => Err(CKR_ATTRIBUTE_READ_ONLY as CK_RV),
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    fn set_copy_attribute_value(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        match attribute.type_ {
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => {
                self.token = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => {
                self.private = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            _ => self.set_attribute_value(attribute),
        }
    }

    fn matches_template(&self, templ: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        templ.iter().all(|(type_, expected)| {
            self.attribute_value(*type_)
                .map(|value| expected == &value)
                .unwrap_or(false)
        })
    }
}

fn validate_new_object_access(
    object: &TokenObject,
    session_flags: CK_FLAGS,
    logged_in: bool,
) -> Result<(), Error> {
    if object.private && !logged_in {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }
    if object.token && session_flags & CKF_RW_SESSION as CK_FLAGS == 0 {
        return Err(CKR_SESSION_READ_ONLY.into());
    }
    Ok(())
}

impl TokenObjectTemplate {
    fn apply_attribute(&mut self, attribute: &CK_ATTRIBUTE) -> Result<(), CK_RV> {
        match attribute.type_ {
            x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE => {
                self.class = Some(read_ulong_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE => {
                self.key_type = Some(read_ulong_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => {
                self.label = read_attribute_value(attribute)?;
                Ok(())
            }
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => {
                self.id = read_attribute_value(attribute)?;
                Ok(())
            }
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => {
                self.token = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => {
                self.private = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE => {
                self.encrypt = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE => {
                self.decrypt = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_SIGN as CK_ATTRIBUTE_TYPE => {
                self.sign = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_VERIFY as CK_ATTRIBUTE_TYPE => {
                self.verify = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_DERIVE as CK_ATTRIBUTE_TYPE => {
                self.derive = read_bool_template_attribute(attribute)?;
                Ok(())
            }
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE => {
                self.sensitive = Some(read_bool_template_attribute(attribute)?);
                Ok(())
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE => {
                self.extractable = Some(read_bool_template_attribute(attribute)?);
                Ok(())
            }
            _ => Err(CKR_ATTRIBUTE_TYPE_INVALID as CK_RV),
        }
    }

    fn into_object(self) -> Result<TokenObject, CK_RV> {
        let sensitive = self.sensitive.unwrap_or(false);
        let class = self.class.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?;
        let nonextractable_key = class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || class == CKO_SECRET_KEY as CK_OBJECT_CLASS;
        let extractable = self.extractable.unwrap_or(!nonextractable_key);
        if nonextractable_key && extractable {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID as CK_RV);
        }
        Ok(TokenObject {
            slot_id: None,
            unique_id: Vec::new(),
            class,
            key_type: self.key_type.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?,
            label: self.label,
            id: self.id,
            token: self.token,
            private: self.private,
            encrypt: self.encrypt,
            decrypt: self.decrypt,
            sign: self.sign,
            verify: self.verify,
            derive: self.derive,
            sensitive,
            extractable,
            always_sensitive: sensitive,
            never_extractable: !extractable || nonextractable_key,
            local: false,
            key_gen_mechanism: None,
            owner_session: None,
            material: KeyMaterial::None,
        })
    }
}

// The PKCS#11 entry points serialize all access through G_CONTEXT. Some connector
// handles are not marked Send by their crates, so Context must not escape the
// mutex guard even though the global mutex itself may be touched by any caller
// thread.
unsafe impl Send for Context {}

static G_CONTEXT: Mutex<Option<Context>> = Mutex::new(None);

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

#[derive(Debug, Clone, Copy)]
struct MechanismDetails {
    type_: CK_MECHANISM_TYPE,
    min_key_size: CK_ULONG,
    max_key_size: CK_ULONG,
    flags: CK_FLAGS,
}

const MECHANISMS: [MechanismDetails; 5] = [
    MechanismDetails {
        type_: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 1024,
        max_key_size: 4096,
        flags: CKF_GENERATE_KEY_PAIR as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        min_key_size: 1024,
        max_key_size: 4096,
        flags: (CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP)
            as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 256,
        max_key_size: 521,
        flags: (CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDSA as CK_MECHANISM_TYPE,
        min_key_size: 256,
        max_key_size: 521,
        flags: (CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 4096,
        flags: CKF_GENERATE as CK_FLAGS,
    },
];

const YUBIHSM_MECHANISMS: [MechanismDetails; 19] = [
    MechanismDetails {
        type_: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
        min_key_size: 2048,
        max_key_size: 4096,
        flags: (CKF_HW | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDSA as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        min_key_size: 224,
        max_key_size: 521,
        flags: (CKF_HW | CKF_DERIVE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_EDDSA as CK_MECHANISM_TYPE,
        min_key_size: 255,
        max_key_size: 255,
        flags: (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_GENERATE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_ECB as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_CBC as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_AES_GCM as CK_MECHANISM_TYPE,
        min_key_size: 16,
        max_key_size: 32,
        flags: (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        min_key_size: 20,
        max_key_size: 64,
        flags: (CKF_HW | CKF_GENERATE) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA_1_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 64,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA256_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 64,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA384_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 128,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
    MechanismDetails {
        type_: CKM_SHA512_HMAC as CK_MECHANISM_TYPE,
        min_key_size: 1,
        max_key_size: 128,
        flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
    },
];

fn yubihsm_mechanisms(algorithms: &[u8]) -> Vec<MechanismDetails> {
    let any = |candidates: &[u8]| candidates.iter().any(|value| algorithms.contains(value));
    let has_rsa = any(&[
        YUBIHSM_ALGO_RSA_2048,
        YUBIHSM_ALGO_RSA_3072,
        YUBIHSM_ALGO_RSA_4096,
    ]);
    let has_ec = any(&[
        YUBIHSM_ALGO_EC_P224,
        YUBIHSM_ALGO_EC_P256,
        YUBIHSM_ALGO_EC_P384,
        YUBIHSM_ALGO_EC_P521,
        YUBIHSM_ALGO_EC_K256,
        YUBIHSM_ALGO_EC_BP256,
        YUBIHSM_ALGO_EC_BP384,
        YUBIHSM_ALGO_EC_BP512,
    ]);
    let has_x25519 = algorithms.contains(&YUBIHSM_ALGO_X25519);
    let has_ed25519 = algorithms.contains(&YUBIHSM_ALGO_ED25519);
    let rsa_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_RSA_2048 => Some(2048),
            YUBIHSM_ALGO_RSA_3072 => Some(3072),
            YUBIHSM_ALGO_RSA_4096 => Some(4096),
            _ => None,
        })
        .collect();
    let ec_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_EC_P224 => Some(224),
            YUBIHSM_ALGO_EC_P256 | YUBIHSM_ALGO_EC_K256 | YUBIHSM_ALGO_EC_BP256 => Some(256),
            YUBIHSM_ALGO_EC_P384 | YUBIHSM_ALGO_EC_BP384 => Some(384),
            YUBIHSM_ALGO_EC_BP512 => Some(512),
            YUBIHSM_ALGO_EC_P521 => Some(521),
            _ => None,
        })
        .collect();
    let x25519_sizes = [255 as CK_ULONG];
    let ed25519_sizes = [255 as CK_ULONG];
    let mut derive_sizes = ec_sizes.clone();
    if has_x25519 {
        derive_sizes.push(255);
    }
    let aes_sizes: Vec<CK_ULONG> = algorithms
        .iter()
        .filter_map(|algorithm| match *algorithm {
            YUBIHSM_ALGO_AES128 => Some(16),
            YUBIHSM_ALGO_AES192 => Some(24),
            YUBIHSM_ALGO_AES256 => Some(32),
            _ => None,
        })
        .collect();
    YUBIHSM_MECHANISMS
        .iter()
        .filter_map(|details| {
            let mut details = *details;
            let sizes: &[CK_ULONG] = match details.type_ {
                y if y == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                    || y == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE =>
                {
                    &rsa_sizes
                }
                y if y == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_ECDSA as CK_MECHANISM_TYPE =>
                {
                    &ec_sizes
                }
                y if y == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => &x25519_sizes,
                y if y == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE
                    || y == CKM_EDDSA as CK_MECHANISM_TYPE =>
                {
                    &ed25519_sizes
                }
                y if y == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE => &derive_sizes,
                y if y == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE
                    || y == CKM_AES_ECB as CK_MECHANISM_TYPE
                    || y == CKM_AES_CBC as CK_MECHANISM_TYPE
                    || y == CKM_AES_GCM as CK_MECHANISM_TYPE =>
                {
                    &aes_sizes
                }
                _ => &[],
            };
            if let (Some(minimum), Some(maximum)) = (sizes.iter().min(), sizes.iter().max()) {
                details.min_key_size = *minimum;
                details.max_key_size = *maximum;
            }
            let supported = match details.type_ {
                x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_rsa,
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => {
                    details.flags = (CKF_HW | CKF_ENCRYPT | CKF_VERIFY) as CK_FLAGS;
                    if any(&[
                        YUBIHSM_ALGO_RSA_PKCS1_SHA1,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA256,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA384,
                        YUBIHSM_ALGO_RSA_PKCS1_SHA512,
                    ]) {
                        details.flags |= CKF_SIGN as CK_FLAGS;
                    }
                    if algorithms.contains(&YUBIHSM_ALGO_RSA_PKCS1_DECRYPT) {
                        details.flags |= CKF_DECRYPT as CK_FLAGS;
                    }
                    has_rsa
                }
                x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE => {
                    has_rsa
                        && any(&[
                            YUBIHSM_ALGO_RSA_PSS_SHA1,
                            YUBIHSM_ALGO_RSA_PSS_SHA256,
                            YUBIHSM_ALGO_RSA_PSS_SHA384,
                            YUBIHSM_ALGO_RSA_PSS_SHA512,
                        ])
                }
                x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                    has_rsa
                        && any(&[
                            YUBIHSM_ALGO_RSA_OAEP_SHA1,
                            YUBIHSM_ALGO_RSA_OAEP_SHA256,
                            YUBIHSM_ALGO_RSA_OAEP_SHA384,
                            YUBIHSM_ALGO_RSA_OAEP_SHA512,
                        ])
                }
                x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_ec,
                x if x == CKM_ECDSA as CK_MECHANISM_TYPE => {
                    has_ec
                        && any(&[
                            YUBIHSM_ALGO_EC_ECDSA_SHA1,
                            YUBIHSM_ALGO_EC_ECDSA_SHA256,
                            YUBIHSM_ALGO_EC_ECDSA_SHA384,
                            YUBIHSM_ALGO_EC_ECDSA_SHA512,
                        ])
                }
                x if x == CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_x25519,
                x if x == CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => has_ed25519,
                x if x == CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE => has_ec || has_x25519,
                x if x == CKM_EDDSA as CK_MECHANISM_TYPE => has_ed25519,
                x if x == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE => any(&[
                    YUBIHSM_ALGO_AES128,
                    YUBIHSM_ALGO_AES192,
                    YUBIHSM_ALGO_AES256,
                ]),
                x if x == CKM_AES_ECB as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_AES_CBC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_CBC)
                }
                x if x == CKM_AES_GCM as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_AES_ECB)
                }
                x if x == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE => any(&[
                    YUBIHSM_ALGO_HMAC_SHA1,
                    YUBIHSM_ALGO_HMAC_SHA256,
                    YUBIHSM_ALGO_HMAC_SHA384,
                    YUBIHSM_ALGO_HMAC_SHA512,
                ]),
                x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA1)
                }
                x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA256)
                }
                x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA384)
                }
                x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE => {
                    algorithms.contains(&YUBIHSM_ALGO_HMAC_SHA512)
                }
                _ => false,
            };
            supported.then_some(details)
        })
        .collect()
}

fn mechanism_details(
    mechanisms: &[MechanismDetails],
    type_: CK_MECHANISM_TYPE,
) -> Result<MechanismDetails, Error> {
    mechanisms
        .iter()
        .copied()
        .find(|mechanism| mechanism.type_ == type_)
        .ok_or(CKR_MECHANISM_INVALID.into())
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    log!(
        2,
        "C_GetMechanismList called with {:?}",
        (slotID, mechanism_list, count)
    );
    map(get_mechanism_list(slotID, mechanism_list, count))
}

fn get_mechanism_list(
    slotID: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: CK_ULONG_PTR,
) -> Result<(), Error> {
    let count = as_mut(count)?;
    with_context_mut(|ctx| {
        let mechanisms = ctx.get_present_slot(slotID)?.mechanisms();

        let required = mechanisms.len() as CK_ULONG;
        if mechanism_list.is_null() {
            *count = required;
            log!(2, "C_GetMechanismList returning {:?}", *count);
            return Ok(());
        }
        if *count < required {
            *count = required;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let list = unsafe { slice::from_raw_parts_mut(mechanism_list, mechanisms.len()) };
        for (slot, mechanism) in list.iter_mut().zip(mechanisms) {
            *slot = mechanism.type_;
        }
        *count = required;
        log!(2, "C_GetMechanismList returning {:?}", list);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    log!(
        2,
        "C_GetMechanismInfo called with {:?}",
        (slotID, type_, info_ptr)
    );
    map(get_mechanism_info(slotID, type_, info_ptr))
}

fn get_mechanism_info(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: CK_MECHANISM_INFO_PTR,
) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        let mechanisms = ctx.get_present_slot(slotID)?.mechanisms();

        let mechanism = mechanism_details(&mechanisms, type_)?;
        info.ulMinKeySize = mechanism.min_key_size;
        info.ulMaxKeySize = mechanism.max_key_size;
        info.flags = mechanism.flags;
        log!(2, "C_GetMechanismInfo returning {:?}", info);
        Ok(())
    })
}

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
