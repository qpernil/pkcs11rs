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

#[derive(Clone, Copy)]
enum MessageDigest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl MessageDigest {
    const fn sha1() -> Self {
        Self::Sha1
    }
    const fn sha224() -> Self {
        Self::Sha224
    }
    const fn sha256() -> Self {
        Self::Sha256
    }
    const fn sha384() -> Self {
        Self::Sha384
    }
    const fn sha512() -> Self {
        Self::Sha512
    }
    const fn sha3_224() -> Self {
        Self::Sha3_224
    }
    const fn sha3_256() -> Self {
        Self::Sha3_256
    }
    const fn sha3_384() -> Self {
        Self::Sha3_384
    }
    const fn sha3_512() -> Self {
        Self::Sha3_512
    }
    const fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, Error> {
    use sha2::Digest;
    Ok(match digest {
        MessageDigest::Sha1 => sha1::Sha1::digest(data).to_vec(),
        MessageDigest::Sha224 => sha2::Sha224::digest(data).to_vec(),
        MessageDigest::Sha256 => sha2::Sha256::digest(data).to_vec(),
        MessageDigest::Sha384 => sha2::Sha384::digest(data).to_vec(),
        MessageDigest::Sha512 => sha2::Sha512::digest(data).to_vec(),
        MessageDigest::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
        MessageDigest::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        MessageDigest::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        MessageDigest::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
    })
}

static DEBUG_LEVEL: AtomicU8 = AtomicU8::new(0);

fn parse_debug_level(value: Option<&str>) -> Result<u8, CK_RV> {
    match value {
        None | Some("0") => Ok(0),
        Some("1") => Ok(1),
        Some("2") => Ok(2),
        Some(_) => Err(CKR_ARGUMENTS_BAD as CK_RV),
    }
}

fn initialize_debug_logging() -> Result<(), CK_RV> {
    let value = match std::env::var("PKCS11RS_DEBUG") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD as CK_RV),
    };
    let level = parse_debug_level(value.as_deref())?;
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
    Ok(())
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

mod pinentry;

mod yubico_kdf;
use yubico_kdf::yubico_password_kdf;

mod certificate_chain;

mod iso7816;
use iso7816::ApduCapabilities;

mod scp03;
use scp03::{
    configured_security_level, parse_hex, select_application, CommandApdu, ResponseApdu,
    Scp03KeySet, Scp03Session, DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
};

mod scp11;
use scp11::{Scp11CertificateCacheKey, Scp11KeySet, Scp11Variant};

mod security_domain;
use security_domain::{
    Client as SecurityDomainClient, Scp03ProvisioningKeys, Scp11Administration, SecurityDomainInfo,
};

mod hsmauth;
use hsmauth::{
    Administration as HsmAuthAdministration, Algorithm as HsmAuthAlgorithm,
    Client as HsmAuthClient, Credential as HsmAuthCredential, Info as HsmAuthInfo,
};

mod piv;
use piv::{Client as PivClient, DeviceInfo as PivDeviceInfo, MetadataPublicKey};

mod openpgp;
use openpgp::{
    Algorithm as OpenPgpAlgorithm, Client as OpenPgpClient, KeyRef as OpenPgpKeyRef,
    PublicKey as OpenPgpPublicKey,
};

mod yubihsm;
use yubihsm::{
    device_public_key_bytes as get_yubihsm_device_public_key,
    get_device_info as get_yubihsm_device_info, parse_object_id as parse_yubihsm_object_id,
    parse_object_list as parse_yubihsm_object_list, Command as YubiHsmCommand,
    CommandCode as YubiHsmCommandCode, ObjectInfo as YubiHsmObjectInfo,
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

const CKA_YUBICO_HSMAUTH_ALGORITHM: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE | 0x5901;
const CKA_YUBICO_HSMAUTH_RETRIES: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE | 0x5902;
const CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE | 0x5903;
const CKA_YUBICO_TOUCH_POLICY: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE + YUBICO_BASE_VENDOR + 1;
const CKA_YUBICO_PIN_POLICY: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE + YUBICO_BASE_VENDOR + 2;
const CKA_PKCS11RS_PIV_OBJECT_TAG: CK_ATTRIBUTE_TYPE =
    CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE | 0x5056;

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
    bulk_out_packet_size, Connector, CurlConnector, PcscAppletConnector, PcscConnector,
    SecureChannelState, UsbConnector,
};
#[cfg(test)]
pub(crate) use connector::{ensure_complete_write, needs_zero_length_packet};

include!("context.rs");

include!("object.rs");

include!("api/general.rs");

include!("mechanism.rs");

include!("api/session.rs");

include!("api/object.rs");

include!("api/crypt.rs");

include!("api/key.rs");

include!("api/security_domain.rs");

include!("api/yubihsm.rs");

include!("api/hsmauth.rs");

include!("api/interfaces.rs");
