#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate curl;
extern crate openssl;
extern crate pcsc;
extern crate rusb;

use openssl::{
    bn::BigNum,
    pkey::{Private, Public},
    rsa::{Padding, Rsa, RsaPrivateKeyBuilder},
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
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use zeroize::Zeroizing;

pub mod error;
use error::*;

mod scp03;
use scp03::{
    configured_application_aid, configured_security_level, select_application, CommandApdu,
    ResponseApdu, Scp03KeySet, Scp03Session,
};

mod piv;
use piv::{Client as PivClient, DeviceInfo as PivDeviceInfo};

mod yubihsm;
use yubihsm::{
    get_device_info as get_yubihsm_device_info, parse_pin as parse_yubihsm_pin,
    Command as YubiHsmCommand, SecureSession as YubiHsmSecureSession,
};

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
    fn is_present(&self) -> bool;
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session>;
    fn login(&mut self, pin: &[u8]) -> Result<(), Error>;
    fn logout(&mut self) -> Result<(), Error>;
    fn init_slot(&mut self) -> Result<(), Error>;
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error>;
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error>;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }
    fn clear_session(&mut self) {}
    fn token_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
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
        format!("{} #{}", self.product(), self.serial())
    }

    fn format_slot_info(&self, info: &mut CK_SLOT_INFO) {
        info.firmwareVersion.major = 1;
        info.firmwareVersion.minor = 0;
        info.hardwareVersion.major = 1;
        info.hardwareVersion.minor = 0;
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = self.flags();
    }

    fn format_token_info(&self, info: &mut CK_TOKEN_INFO) {
        str_pad(&self.label(), &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.product(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        info.flags =
            (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
                as CK_FLAGS;
        info.ulMaxSessionCount = 0;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 34;
        info.ulMinPinLen = 4;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.hardwareVersion.major = self.major();
        info.hardwareVersion.minor = self.minor();
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
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
}

#[derive(Debug)]
struct PivSlot {
    connector: Rc<dyn Connector>,
    authenticated: Rc<Cell<bool>>,
    version: piv::Version,
    serial: String,
    keys: Vec<PivKey>,
}

#[derive(Clone, Debug)]
struct PivKey {
    slot: piv::Slot,
    algorithm: piv::Algorithm,
    public_key: Rsa<Public>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YubiKeyBackend {
    Piv,
    Scp03,
}

fn configured_yubikey_backend() -> Result<YubiKeyBackend, Error> {
    match std::env::var("PKCS11RS_YUBIKEY_BACKEND") {
        Ok(value) if value.eq_ignore_ascii_case("piv") => Ok(YubiKeyBackend::Piv),
        Ok(value) if value.eq_ignore_ascii_case("scp03") => Ok(YubiKeyBackend::Scp03),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(CKR_ARGUMENTS_BAD.into()),
        Err(std::env::VarError::NotPresent) => Ok(YubiKeyBackend::Piv),
    }
}

impl PivSlot {
    fn new(connector: Rc<dyn Connector>) -> Self {
        Self {
            connector,
            authenticated: Rc::new(Cell::new(false)),
            version: piv::Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
            serial: String::from("0"),
            keys: Vec::new(),
        }
    }

    fn update_device_info(&mut self, info: PivDeviceInfo) {
        self.version = info.version;
        self.serial = info.serial.unwrap_or_default().to_string();
    }
}

impl Slot for PivSlot {
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
        "YubiKey PIV"
    }
    fn serial(&self) -> &str {
        &self.serial
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
        let info = PivClient.select(self.connector.as_ref())?;
        self.update_device_info(info);
        PivClient.verify_pin(self.connector.as_ref(), pin)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        let result = PivClient.select(self.connector.as_ref());
        if let Ok(info) = result.as_ref() {
            self.version = info.version;
            self.serial = info.serial.unwrap_or_default().to_string();
        }
        result.map(|_| ())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        let info = PivClient.select(self.connector.as_ref())?;
        self.update_device_info(info);
        self.keys.clear();
        for slot in [
            piv::Slot::Authentication,
            piv::Slot::Signature,
            piv::Slot::KeyManagement,
            piv::Slot::CardAuthentication,
        ] {
            let Ok(metadata) = PivClient.metadata(self.connector.as_ref(), slot) else {
                continue;
            };
            let Some(algorithm) = metadata.algorithm.and_then(piv::Algorithm::from_id) else {
                continue;
            };
            if algorithm.rsa_input_length().is_none() {
                continue;
            }
            let Ok(certificate) = PivClient.certificate(self.connector.as_ref(), slot) else {
                continue;
            };
            let Ok(certificate) = openssl::x509::X509::from_der(&certificate) else {
                continue;
            };
            let Ok(public_key) = certificate.public_key().and_then(|key| key.rsa()) else {
                continue;
            };
            if public_key.size() as usize != algorithm.rsa_input_length().unwrap_or_default() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            self.keys.push(PivKey {
                slot,
                algorithm,
                public_key,
            });
        }
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        info.firmwareVersion.major = self.version.major;
        info.firmwareVersion.minor = self.version.minor.saturating_mul(10) + self.version.patch;
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        info.ulMaxPinLen = 8;
        info.ulMinPinLen = 6;
        info.firmwareVersion.major = self.version.major;
        info.firmwareVersion.minor = self.version.minor.saturating_mul(10) + self.version.patch;
        Ok(())
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = Vec::with_capacity(self.keys.len() * 2);
        for key in &self.keys {
            let id = vec![key.slot as u8];
            let label = format!("PIV slot {:02X}", key.slot as u8).into_bytes();
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-public", key.slot as u8).into_bytes(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: label.clone(),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: true,
                decrypt: false,
                sign: false,
                verify: true,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::RsaPublic(key.public_key.clone()),
            });
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("piv-{:02x}-private", key.slot as u8).into_bytes(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label,
                id,
                token: true,
                private: true,
                encrypt: false,
                decrypt: key.slot == piv::Slot::KeyManagement,
                sign: true,
                verify: false,
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
                    modulus: key.public_key.n().to_vec(),
                    public_exponent: key.public_key.e().to_vec(),
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
        get_yubihsm_device_info(self.connector.as_ref()).map(|_| ())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let device_info = get_yubihsm_device_info(self.connector.as_ref())?;
        self.format_token_info(info);
        str_pad(&device_info.serial.to_string(), &mut info.serialNumber);
        info.ulMaxPinLen = 64;
        info.ulMinPinLen = 8;
        info.firmwareVersion.major = device_info.major;
        info.firmwareVersion.minor = device_info.minor.saturating_mul(10) + device_info.patch;
        Ok(())
    }
    fn clear_session(&mut self) {
        *self.session.borrow_mut() = None;
    }
    fn login_is_active(&self) -> bool {
        self.session.borrow().is_some()
    }
}

#[derive(Debug)]
struct YubiKeySlot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
}

impl Slot for YubiKeySlot {
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
        "12345678"
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        43
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn clear_session(&mut self) {
        *self.session.borrow_mut() = None;
    }
    fn login_is_active(&self) -> bool {
        self.session.borrow().is_some()
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(YubiKeySession {
            slotID,
            flags,
            connector: self.connector.clone(),
            session: self.session.clone(),
        })
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        *self.session.try_borrow_mut()? = None;
        let selected_aid = configured_application_aid()?;
        select_application(self.connector.as_ref(), &selected_aid)?;
        let keys = Scp03KeySet::from_environment()?;
        let security_level = configured_security_level()?;
        let session = Scp03Session::authenticate_selected(
            self.connector.as_ref(),
            &keys,
            security_level,
            &selected_aid,
        )?;
        *self.session.try_borrow_mut()? = Some(session);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        *self.session.try_borrow_mut()? = None;
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let selected_aid = configured_application_aid()?;
        select_application(self.connector.as_ref(), &selected_aid)
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
    ) -> Result<Vec<u8>, Error> {
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
    ) -> Result<Vec<u8>, Error> {
        if !self.authenticated.get() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let result = PivClient.sign(self.connector.as_ref(), slot, algorithm, input);
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
}

impl YubiHsmSession {
    fn send_secure_cmd(&self, command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        let mut session_guard = self.session.try_borrow_mut()?;
        let session = session_guard
            .as_mut()
            .ok_or_else(|| Error::from(CKR_USER_NOT_LOGGED_IN))?;
        YubiHsmSecureSession::validate_command(self.connector.as_ref(), command)?;
        let result = session.send_command(self.connector.as_ref(), command);
        if result.is_err() {
            *session_guard = None;
        }
        result
    }
}

#[derive(Debug)]
struct YubiKeySession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
}

impl Session for YubiKeySession {
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

impl YubiKeySession {
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
        eprintln!("libusb.write_bulk({:?}) -> {}", send_buffer, len);
        ensure_complete_write(len, send_buffer.len())?;
        if needs_zero_length_packet(len, self.packet_size) {
            // Write a ZLP if last packet is full
            let zlp = self.handle.write_bulk(0x01, &[], timeout)?;
            eprintln!("libusb.write_bulk'zlp() -> {}", zlp);
        }
        let len = self.handle.read_bulk(0x81, receive_buffer, timeout)?;
        eprintln!("libusb.read_bulk({:?}) -> {}", &receive_buffer[..len], len);
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
        "0"
    }
    fn major(&self) -> u8 {
        0
    }
    fn minor(&self) -> u8 {
        0
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
                eprintln!(
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
        eprintln!("curl.post({:?}) -> {:?}", send_buffer, received);
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
        eprintln!(
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
    sessions: HashMap<CK_SESSION_HANDLE, Box<dyn Session>>,
    logged_in_slots: HashSet<CK_SLOT_ID>,
    objects: HashMap<CK_OBJECT_HANDLE, TokenObject>,
    next_object_handle: CK_OBJECT_HANDLE,
    find_operations: HashMap<CK_SESSION_HANDLE, FindOperation>,
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
    },
    Secret(Zeroizing<Vec<u8>>),
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
            } => fmt
                .debug_struct("PivPrivate")
                .field("slot", slot)
                .field("algorithm", algorithm)
                .field("size", &modulus.len())
                .finish(),
            Self::Secret(key) => fmt.debug_tuple("Secret").field(&key.len()).finish(),
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
            .field("sign_operations", &self.sign_operations)
            .field("verify_operations", &self.verify_operations)
            .finish()
    }
}

impl Context {
    fn new() -> Result<Context, Error> {
        #[cfg(feature = "abi-tests")]
        let slots = HashMap::from([(ABI_TEST_SLOT_ID, Box::new(AbiTestSlot) as Box<dyn Slot>)]);
        #[cfg(not(feature = "abi-tests"))]
        let slots = HashMap::new();

        let objects = default_objects()?;
        let next_object_handle = objects.keys().max().map(|handle| handle + 1).unwrap_or(1);
        let context = Context {
            libusb: match rusb::Context::new() {
                Ok(context) => Some(context),
                Err(e) => {
                    eprintln!("libusb::Context::new: {}", e);
                    None
                }
            },
            pcsc: match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => Some(Rc::new(context)),
                Err(e) => {
                    eprintln!("pcsc::Context::establish: {}", e);
                    None
                }
            },
            slots,
            dynamic_slots: HashSet::new(),
            sessions: HashMap::new(),
            logged_in_slots: HashSet::new(),
            objects,
            next_object_handle,
            find_operations: HashMap::new(),
            sign_operations: HashMap::new(),
            verify_operations: HashMap::new(),
        };
        eprintln!("Context.new {:?}", context);
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
        for object in objects {
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
        self.sign_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.verify_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.objects.retain(|_, object| {
            object.slot_id != Some(slot_id) || (!remove_token_objects && object.token)
        });
    }

    fn init(&mut self) {
        let mut seen_dynamic_slots = HashSet::new();
        if let Some(context) = self.libusb.as_ref() {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(desc) = device.device_descriptor() {
                        //eprintln!("USB Bus {} Device {}: ID {}:{}", device.bus_number(), device.address(), desc.vendor_id(), desc.product_id());
                        if desc.vendor_id() == 0x1050 && desc.product_id() == 0x30 {
                            match device.open() {
                                Ok(handle) => {
                                    let version = desc.device_version();
                                    let packet_size = match bulk_out_packet_size(&device) {
                                        Ok(packet_size) => packet_size,
                                        Err(error) => {
                                            eprintln!("libusb bulk OUT endpoint: {:?}", error);
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
                                    eprintln!("{}", name);
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
                                        eprintln!("libusb.claim_interface: {:?}", error);
                                        continue;
                                    }
                                    let slot_id = next_key(&self.slots, 0);
                                    let mut slot = Box::new(YubiHsmSlot {
                                        connector: Rc::new(connector),
                                        session: Rc::new(RefCell::new(None)),
                                    });
                                    if let Err(error) = slot.init_slot() {
                                        eprintln!("YubiHSM GET DEVICE INFO: {:?}", error);
                                        continue;
                                    }
                                    self.slots.insert(slot_id, slot);
                                    self.dynamic_slots.insert(slot_id);
                                    seen_dynamic_slots.insert(slot_id);
                                }
                                Err(e) => {
                                    eprintln!("libusb.open: {}", e);
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
                    };
                    let name = connector.name();
                    eprintln!("{}", name);
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
                                eprintln!("YubiKey backend initialization: {:?}", error);
                            } else {
                                map(self.refresh_slot_token_objects(slot_id));
                            }
                        }
                        continue;
                    }
                    map(connector.refresh());
                    let slot_id = next_key(&self.slots, 0);
                    let connector: Rc<dyn Connector> = Rc::new(connector);
                    let mut slot: Box<dyn Slot> = match configured_yubikey_backend() {
                        Ok(YubiKeyBackend::Piv) => Box::new(PivSlot::new(connector)),
                        Ok(YubiKeyBackend::Scp03) => Box::new(YubiKeySlot {
                            connector,
                            session: Rc::new(RefCell::new(None)),
                        }),
                        Err(error) => {
                            eprintln!("PKCS11RS_YUBIKEY_BACKEND: {:?}", error);
                            continue;
                        }
                    };
                    if slot.is_present() {
                        if let Err(error) = slot.init_slot() {
                            eprintln!("YubiKey backend initialization: {:?}", error);
                            continue;
                        }
                    }
                    let token_objects = match slot.token_objects(slot_id) {
                        Ok(objects) => objects,
                        Err(error) => {
                            eprintln!("YubiKey object discovery: {:?}", error);
                            Vec::new()
                        }
                    };
                    self.slots.insert(slot_id, slot);
                    for object in token_objects {
                        self.insert_object(object);
                    }
                    self.dynamic_slots.insert(slot_id);
                    seen_dynamic_slots.insert(slot_id);
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
        eprintln!("Context.init {:?}", self);
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
    Ok(HashMap::from([
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
    ]))
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
        [
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            CKA_LABEL as CK_ATTRIBUTE_TYPE,
            CKA_ID as CK_ATTRIBUTE_TYPE,
            CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
            CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            CKA_MODULUS as CK_ATTRIBUTE_TYPE,
            CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
        ]
        .iter()
        .filter_map(|&attribute_type| self.attribute_value(attribute_type))
        .map(|value| value.len() as CK_ULONG)
        .sum()
    }

    fn attribute_value(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        match attribute_type {
            x if x == CKA_CLASS as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(self.class)),
            x if x == CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE => Some(self.unique_id.clone()),
            x if x == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(self.key_type)),
            x if x == CKA_LABEL as CK_ATTRIBUTE_TYPE => Some(self.label.clone()),
            x if x == CKA_ID as CK_ATTRIBUTE_TYPE => Some(self.id.clone()),
            x if x == CKA_TOKEN as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.token)),
            x if x == CKA_PRIVATE as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.private)),
            x if x == CKA_ENCRYPT as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.encrypt)),
            x if x == CKA_DECRYPT as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.decrypt)),
            x if x == CKA_SIGN as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.sign)),
            x if x == CKA_VERIFY as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.verify)),
            x if x == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::Secret(value) => Some(ulong_attribute(value.len() as CK_ULONG)),
                _ => None,
            },
            x if x == CKA_SENSITIVE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(self.sensitive))
            }
            x if x == CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE && self.has_sensitive_attributes() => {
                Some(bool_attribute(self.extractable))
            }
            x if x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(self.always_sensitive))
            }
            x if x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE
                && self.has_sensitive_attributes() =>
            {
                Some(bool_attribute(self.never_extractable))
            }
            x if x == CKA_LOCAL as CK_ATTRIBUTE_TYPE => Some(bool_attribute(self.local)),
            x if x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE => Some(ulong_attribute(
                self.key_gen_mechanism
                    .unwrap_or(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
            )),
            x if x == CKA_MODULUS as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.n().to_vec()),
                KeyMaterial::RsaPublic(key) => Some(key.n().to_vec()),
                KeyMaterial::PivPrivate { modulus, .. } => Some(modulus.clone()),
                _ => None,
            },
            x if x == CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE => match &self.material {
                KeyMaterial::RsaPrivate(key) => Some(key.e().to_vec()),
                KeyMaterial::RsaPublic(key) => Some(key.e().to_vec()),
                KeyMaterial::PivPrivate {
                    public_exponent, ..
                } => Some(public_exponent.clone()),
                _ => None,
            },
            _ => None,
        }
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
        let extractable = self.extractable.unwrap_or(true);
        Ok(TokenObject {
            slot_id: None,
            unique_id: Vec::new(),
            class: self.class.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?,
            key_type: self.key_type.ok_or(CKR_TEMPLATE_INCOMPLETE as CK_RV)?,
            label: self.label,
            id: self.id,
            token: self.token,
            private: self.private,
            encrypt: self.encrypt,
            decrypt: self.decrypt,
            sign: self.sign,
            verify: self.verify,
            sensitive,
            extractable,
            always_sensitive: sensitive,
            never_extractable: !extractable,
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
    eprintln!("C_Initialize called with {:?}", init_args);
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
    eprintln!("C_Finalize called with {:?}", pReserved);
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
        eprintln!("C_GetFunctionList called with {:?}", function_list);
        match function_list.as_mut() {
            Some(function_list) => {
                *function_list =
                    &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
                eprintln!("C_GetFunctionList returning {:?}", *function_list);
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
    eprintln!("C_GetInfo called with {:?}", info_ptr);
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
        eprintln!(
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
                        eprintln!("C_GetSlotList returning {:?}", (keys, *count));
                        Ok(CKR_OK as CK_RV)
                    } else {
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        eprintln!("C_GetSlotList returning {:?}", *count);
                        Ok(CKR_BUFFER_TOO_SMALL as CK_RV)
                    }
                }
                None => {
                    *count = keys.len() as ::std::os::raw::c_ulong;
                    eprintln!("C_GetSlotList returning {:?}", *count);
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
    with_context(|ctx| ctx.get_slot(slotID)?.get_slot_info(as_mut(info_ptr)?))
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_SLOT_INFO) -> CK_RV {
    eprintln!("C_GetSlotInfo called with {:?}", (slotID, info_ptr));
    map(get_slot_info(slotID, info_ptr))
}

fn get_token_info(slotID: CK_SLOT_ID, info_ptr: CK_TOKEN_INFO_PTR) -> Result<(), Error> {
    let info = as_mut(info_ptr)?;
    with_context_mut(|ctx| {
        ctx.init();
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
    eprintln!("C_GetTokenInfo called with {:?}", (slotID, info_ptr));
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

fn mechanism_details(type_: CK_MECHANISM_TYPE) -> Result<MechanismDetails, Error> {
    MECHANISMS
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
    eprintln!(
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
        ctx.init();
        ctx.get_present_slot(slotID)?;

        let required = MECHANISMS.len() as CK_ULONG;
        if mechanism_list.is_null() {
            *count = required;
            eprintln!("C_GetMechanismList returning {:?}", *count);
            return Ok(());
        }
        if *count < required {
            *count = required;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let list = unsafe { slice::from_raw_parts_mut(mechanism_list, MECHANISMS.len()) };
        for (slot, mechanism) in list.iter_mut().zip(MECHANISMS) {
            *slot = mechanism.type_;
        }
        *count = required;
        eprintln!("C_GetMechanismList returning {:?}", list);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    eprintln!(
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
        ctx.init();
        ctx.get_present_slot(slotID)?;

        let mechanism = mechanism_details(type_)?;
        info.ulMinKeySize = mechanism.min_key_size;
        info.ulMaxKeySize = mechanism.max_key_size;
        info.flags = mechanism.flags;
        eprintln!("C_GetMechanismInfo returning {:?}", info);
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
    eprintln!("C_OpenSession called with {:?}", (slotID, flags));
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

            ctx.init();
            match ctx.slots.get_mut(&slotID) {
                Some(slot) => {
                    let _ = slot.refresh();
                    eprintln!("{:?}", slot);
                    if slot.flags() & CKF_TOKEN_PRESENT as CK_FLAGS != 0 {
                        let k = next_key(&ctx.sessions, 1);
                        eprintln!("C_OpenSession sessions before {:?}", ctx.sessions);
                        ctx.sessions.insert(k, slot.open_session(slotID, flags));
                        eprintln!("C_OpenSession sessions after {:?}", ctx.sessions);
                        eprintln!("C_OpenSession returning {:?}", k);
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
    eprintln!("C_CloseSession called with {:?}", session_handle);
    match with_context_mut(|ctx| {
        eprintln!("C_CloseSession sessions before {:?}", ctx.sessions);
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
        ctx.sign_operations.remove(&session_handle);
        ctx.verify_operations.remove(&session_handle);
        ctx.objects
            .retain(|_, object| object.owner_session != Some(session_handle));
        eprintln!("C_CloseSession removed {:?}", (session_handle, session));
        eprintln!("C_CloseSession sessions after {:?}", ctx.sessions);
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
    eprintln!("C_CloseAllSessions called with {:?}", slotID);
    match with_context_mut(|ctx| {
        ctx.init();
        if !ctx.slots.contains_key(&slotID) {
            return Ok(CKR_SLOT_ID_INVALID as CK_RV);
        }
        eprintln!("C_CloseAllSessions sessions before {:?}", ctx.sessions);
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
        eprintln!("C_CloseAllSessions sessions after {:?}", ctx.sessions);
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
    eprintln!("C_GetSessionInfo called with {:?}", session_handle);
    unsafe {
        match with_context(|ctx| match ctx.get_session_(session_handle) {
            Some(session) => {
                eprintln!("C_GetSessionInfo {:?}", session);
                match info_ptr.as_mut() {
                    Some(info) => {
                        info.slotID = session.1.slotID();
                        info.state = session_state(
                            session.1.flags(),
                            ctx.is_slot_logged_in(session.1.slotID()),
                        );
                        info.flags = session.1.flags();
                        info.ulDeviceError = 0;
                        eprintln!("C_GetSessionInfo returning {:?}", info);
                        Ok(CKR_OK as CK_RV)
                    }
                    None => Ok(CKR_ARGUMENTS_BAD as CK_RV),
                }
            }
            None => Ok(CKR_SESSION_HANDLE_INVALID as CK_RV),
        }) {
            Ok(rv) => rv,
            Err(e) => e.into(),
        }
    }
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
    eprintln!(
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
    eprintln!("C_Logout called with {:?}", session_handle);
    map(logout(session_handle))
}

#[no_mangle]
pub extern "C" fn C_CreateObject(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!(
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
        object.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(object);
        *object_handle = handle;
        Ok(())
    })
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
                && key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE =>
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
    eprintln!(
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
    eprintln!("C_DestroyObject called with {:?}", (session_handle, object));
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
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if stored_object.token && flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
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
    eprintln!(
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
    eprintln!(
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
                    KeyMaterial::Secret(value) if !object.sensitive && object.extractable => {
                        if let Err(e) = write_attribute_value(attribute, value.as_slice()) {
                            rv = combine_attribute_rv(rv, e);
                        }
                    }
                    KeyMaterial::Secret(_) => {
                        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        rv = combine_attribute_rv(rv, CKR_ATTRIBUTE_SENSITIVE as CK_RV);
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
    eprintln!(
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
    eprintln!(
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
        eprintln!("C_FindObjectsInit template {:?}", templ);
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
    eprintln!(
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
        eprintln!("C_FindObjects returning {:?}", &output[..returned]);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("C_FindObjectsFinal called with {:?}", session_handle);
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
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    session_handle: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _encrypted_data: *mut ::std::os::raw::c_uchar,
    _encrypted_data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
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
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    session_handle: CK_SESSION_HANDLE,
    _encrypted_data: *mut ::std::os::raw::c_uchar,
    _encrypted_data_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
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
    eprintln!(
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
        if mechanism.mechanism != CKM_RSA_PKCS as CK_MECHANISM_TYPE {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }

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
        if object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || object.key_type != CKK_RSA as CK_KEY_TYPE
            || !matches!(
                object.material,
                KeyMaterial::RsaPrivate(_) | KeyMaterial::PivPrivate { .. }
            )
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }

        ctx.sign_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: object.private,
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
    eprintln!(
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
        let required = match &operation.key {
            KeyMaterial::RsaPrivate(key) => key.size() as usize,
            KeyMaterial::PivPrivate { modulus, .. } => modulus.len(),
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if data.len() > required.saturating_sub(11) {
            ctx.sign_operations.remove(&session_handle);
            return Err(CKR_DATA_LEN_RANGE.into());
        }

        if signature.is_null() {
            *signature_len = required as CK_ULONG;
            return Ok(());
        }
        if *signature_len < required as CK_ULONG {
            *signature_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let signature_result = match &operation.key {
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
                let encoded = encode_pkcs1_v1_5_signature_input(data, required)?;
                ctx._get_session(session_handle)?
                    .1
                    .piv_sign(*slot, *algorithm, &encoded)
            }
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
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

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    session_handle: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
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
    eprintln!(
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
        if mechanism.mechanism != CKM_RSA_PKCS as CK_MECHANISM_TYPE {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
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
            || object.key_type != CKK_RSA as CK_KEY_TYPE
            || !matches!(object.material, KeyMaterial::RsaPublic(_))
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }

        ctx.verify_operations.insert(
            session_handle,
            SignatureOperation {
                key: object.material.clone(),
                slot_id,
                requires_login: false,
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
    eprintln!(
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
        let signature = from_raw_parts(signature, signature_len as usize)?;
        let public_key = match &operation.key {
            KeyMaterial::RsaPublic(key) => key,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if signature.len() != public_key.size() as usize {
            return Err(CKR_SIGNATURE_LEN_RANGE.into());
        }
        let mut recovered = vec![0; public_key.size() as usize];
        let recovered_len =
            match public_key.public_decrypt(signature, &mut recovered, Padding::PKCS1) {
                Ok(len) => len,
                Err(_) => return Err(CKR_SIGNATURE_INVALID.into()),
            };
        recovered.truncate(recovered_len);
        if recovered != data {
            return Err(CKR_SIGNATURE_INVALID.into());
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    session_handle: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    session_handle: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    session_function_not_supported(session_handle)
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
    eprintln!(
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
        let mut key = generate_key_object(mechanism, templ)?;
        validate_new_object_access(&key, flags, logged_in)?;
        key.set_owner(session_handle, slot_id);
        let handle = ctx.insert_object(key);
        *key_handle = handle;
        Ok(())
    })
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
    let details = mechanism_details(mechanism.mechanism)?;
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
    _mechanism: *mut CK_MECHANISM,
    _public_key_template: *mut CK_ATTRIBUTE,
    _public_key_attribute_count: ::std::os::raw::c_ulong,
    _private_key_template: *mut CK_ATTRIBUTE,
    _private_key_attribute_count: ::std::os::raw::c_ulong,
    _public_key: *mut CK_OBJECT_HANDLE,
    _private_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
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
    _mechanism: *mut CK_MECHANISM,
    _base_key: CK_OBJECT_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _attribute_count: ::std::os::raw::c_ulong,
    _key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    session_function_not_supported(session_handle)
}

#[no_mangle]
pub extern "C" fn C_SeedRandom(
    session: CK_SESSION_HANDLE,
    _seed: *mut ::std::os::raw::c_uchar,
    _seed_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_SeedRandom called");
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
    eprintln!("C_GenerateRandom called");
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
