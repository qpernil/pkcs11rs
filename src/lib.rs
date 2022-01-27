#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate rusb;
extern crate pcsc;
extern crate curl;
extern crate openssl;

use std::{ptr, slice, collections::HashMap, time::Duration, rc::Rc, cell::{RefCell}, io::Write};
use rusb::UsbContext;

pub mod error;
use error::*;

pub mod pkcs11;
use pkcs11::*;

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

fn next_key<T>(map: &HashMap<u64, T>, min: u64) -> u64 {
    match map.keys().max() {
        Some(k) => k + 1,
        None => min
    }
}

fn get_ctx() -> Result<&'static Context, Error> {
    unsafe {
        if let Some(context) = G_CONTEXT.as_ref() {
            Ok(context)
        } else {
            Err(CKR_CRYPTOKI_NOT_INITIALIZED.into())
        }
    }
}

fn get_ctx_mut() -> Result<&'static mut Context, Error> {
    unsafe {
        if let Some(context) = G_CONTEXT.as_mut() {
            Ok(context)
        } else {
            Err(CKR_CRYPTOKI_NOT_INITIALIZED.into())
        }
    }
}

fn _as_ref<'a, T>(ptr: *const T) -> Result<&'a T, Error> {
    unsafe {
        if let Some(p) = ptr.as_ref() {
            Ok(p)
        } else {
            Err(CKR_ARGUMENTS_BAD.into())
        }
    }
}

fn as_mut<'a, T>(ptr: *mut T) -> Result<&'a mut T, Error> {
    unsafe {
        if let Some(p) = ptr.as_mut() {
            Ok(p)
        } else {
            Err(CKR_ARGUMENTS_BAD.into())
        }
    }
}

fn from_raw_parts<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], Error> {
    if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD.into())
    } else {
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

fn _from_raw_parts_mut<'a, T>(ptr: *mut T, len: usize) -> Result<&'a mut [T], Error> {
    if ptr.is_null() {
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
    fn init_slot(&mut self) -> Result<(), Error>;
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error>;
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error>;

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
}

impl std::fmt::Debug for dyn Slot {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[derive(Debug)]
struct YubiHsmSlot {
    connector: Rc<dyn Connector>
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
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(YubiHsmSession {slotID, flags, connector: self.connector.clone(), session: None })
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_cmd(6, &[], timeout)?;
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        info.firmwareVersion.major = 1;
        info.firmwareVersion.minor = 0;
        info.hardwareVersion.major = 1;
        info.hardwareVersion.minor = 0;
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = self.flags();
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_cmd(6, &[], timeout)?;
        str_pad(&self.label(), &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.product(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        info.flags = (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED) as CK_FLAGS;
        info.ulMaxSessionCount = 0;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 34;
        info.ulMinPinLen = 4;
        info.ulTotalPublicMemory = 0;
        info.ulFreePublicMemory = 0;
        info.ulTotalPrivateMemory = 0;
        info.ulFreePrivateMemory = 0;
        info.hardwareVersion.major = self.major();
        info.hardwareVersion.minor = self.minor();
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
        Ok(())
    }
}

impl YubiHsmSlot {
    fn compose_cmd(cmd: u8, data: &[u8]) -> Vec<u8> {
        let len = data.len() as u16;
        let mut vec = Vec::with_capacity(2048);
        vec.extend([cmd]);
        vec.extend(len.to_be_bytes());
        vec.extend(data);
        vec
    }
    fn send_cmd(&self, cmd: u8, data: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        self.connector.send(&YubiHsmSlot::compose_cmd(cmd, data), timeout)
    }
}

#[derive(Debug)]
struct YubiKeySlot {
    connector: Rc<dyn Connector>
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
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(YubiKeySession {slotID, flags, connector: self.connector.clone()})
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.connector.send(&send_buffer, timeout)?;
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        info.firmwareVersion.major = 1;
        info.firmwareVersion.minor = 0;
        info.hardwareVersion.major = 1;
        info.hardwareVersion.minor = 0;
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = self.flags();
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.connector.send(&send_buffer, timeout)?;
        str_pad(&self.label(), &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.product(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        info.flags = (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED) as CK_FLAGS;
        info.ulMaxSessionCount = 0;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 34;
        info.ulMinPinLen = 4;
        info.ulTotalPublicMemory = 0;
        info.ulFreePublicMemory = 0;
        info.ulTotalPrivateMemory = 0;
        info.ulFreePrivateMemory = 0;
        info.hardwareVersion.major = self.major();
        info.hardwareVersion.minor = self.minor();
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
        Ok(())
    }
}

trait Session {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn slotID(&self) -> CK_SLOT_ID;
    fn flags(&self) -> CK_FLAGS;
    fn state(&self) -> CK_STATE;
    fn login(&mut self, pin: &[u8]) -> Result<(), Error>;
    fn logout(&mut self) -> Result<(), Error>;
    fn get_session_info(&self) -> Result<(), Error>;
    fn generate(&self) -> Result<(), Error>;
}

impl std::fmt::Debug for dyn Session {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

#[derive(Debug)]
struct YubiHsmSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Option<Scp03Session>
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
    fn state(&self) -> CK_STATE {
        if self.session.is_some() {
            CKS_RW_USER_FUNCTIONS
        } else {
            CKS_RW_PUBLIC_SESSION
        }.into()
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_cmd(1, &[5; 100], timeout)?;
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv = Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        self.session = Some(Scp03Session {cipher: openssl::symm::Cipher::aes_128_cbc(), key, iv});
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_secure_cmd(1, &[6; 32], timeout)?;
        self.session = None;
        Ok(())
    }
    fn get_session_info(&self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_secure_cmd(1, &[7; 99], timeout)?;
        Ok(())
    }
    fn generate(&self) ->Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let _vec = self.send_secure_cmd(1, &[8; 72], timeout)?;
        Ok(())
    }
}

impl YubiHsmSession {
    fn send_cmd(&self, cmd: u8, data: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        self.connector.send(&YubiHsmSlot::compose_cmd(cmd, data), timeout)
    }
    fn send_secure_cmd(&self, cmd: u8, data: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        self.connector.send(&YubiHsmSlot::compose_cmd(cmd, data), timeout)
    }
}

#[derive(Debug)]
struct YubiKeySession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>
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
    fn state(&self) -> CK_STATE {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        if self.connector.send(&send_buffer, timeout).is_ok() {
            CKS_RW_USER_FUNCTIONS
        } else {
            CKS_RW_PUBLIC_SESSION
        }.into()
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        if self.connector.send(&send_buffer, timeout).is_ok() {
            Ok(())
        } else {
            Err(CKR_PIN_INCORRECT.into())
        }
    }
    fn logout(&mut self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.connector.send(&send_buffer, timeout).map(|_| ())
    }
    fn get_session_info(&self) -> Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.connector.send(&send_buffer, timeout).map(|_| ())
    }
    fn generate(&self) ->Result<(), Error> {
        let timeout = Duration::from_millis(100);
        let send_buffer = [1u8, 0u8, 61u8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.connector.send(&send_buffer, timeout).map(|_| ())
    }
}

trait Connector {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn name(&self) -> String;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn is_present(&self) -> bool;
    fn buffer_size(&self) -> usize;
    fn transmit<'a>(&self, send_buffer: &[u8], receive_buffer: &'a mut [u8], timeout: Duration) -> Result<&'a [u8], Error>;

    fn send(&self, send_buffer: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        let mut receive_buffer = vec![0u8; self.buffer_size()];
        let slice = self.transmit(send_buffer, &mut receive_buffer, timeout)?;
        let len = slice.len();
        receive_buffer.truncate(len);
        Ok(receive_buffer)
    }
}

impl std::fmt::Debug for dyn Connector {
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
    claimed: bool
}

impl Connector for UsbConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} {} {}", self.manufacturer, self.product, self.serial)
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
        2048 + self.packet_size
    }
    fn transmit<'a>(&self, send_buffer: &[u8], receive_buffer: &'a mut [u8], timeout: Duration) -> Result<&'a [u8], Error> {
        let len = self.handle.write_bulk(0x01, send_buffer, timeout)?;
        eprintln!("libusb.write_bulk({:?}) -> {}", send_buffer, len);
        if len % self.packet_size == 0 { // Write a ZLP if last packet is full
            let zlp = self.handle.write_bulk(0x01, &[], timeout)?;
            eprintln!("libusb.write_bulk'zlp() -> {}", zlp);
        }
        let len = self.handle.read_bulk(0x81, receive_buffer, timeout)?;
        eprintln!("libusb.read_bulk({:?}) -> {}", &receive_buffer[..len], len);
        Ok(&receive_buffer[..len])
    }
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

struct PcscConnector<'a> {
    reader: std::ffi::CString,
    context: &'a pcsc::Context,
    card: Option<pcsc::Card>,
}

impl std::fmt::Debug for PcscConnector<'_> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("PcscConnector")
            .field("reader", &self.reader)
            .field("card", &self.card.as_ref().map(|_| "Card"))
            .finish_non_exhaustive()
    }
}

impl Connector for PcscConnector<'_> {
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
        self.card.is_some()
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn transmit<'a>(&self, send_buffer: &[u8], receive_buffer: &'a mut [u8], _timeout: Duration) -> Result<&'a [u8], Error> {
        match self.card.as_ref() {
            Some(card) => {
                let received = card.transmit(send_buffer, receive_buffer)?;
                eprintln!("pcsc.transmit({:?}) -> {:?}", send_buffer, received);
                Ok(received)
            }
            None => {
                Err(Error::from(pcsc::Error::NoSmartcard))
            }
        }
    }
}

impl PcscConnector<'_> {
    fn connect(&mut self) -> Result<(), Error> {
        self.card = Some(self.context.connect(&self.reader, pcsc::ShareMode::Exclusive, pcsc::Protocols::T0 | pcsc::Protocols::T1)?);
        Ok(())
    }
    fn _reconnect(&mut self) -> Result<(), Error> {
        match self.card.as_mut() {
            Some(card) => {
                card.reconnect(pcsc::ShareMode::Exclusive, pcsc::Protocols::T0 | pcsc::Protocols::T1, pcsc::Disposition::ResetCard).map_err(|e| e .into())
            },
            None => {
                Err(Error::from(pcsc::Error::NoSmartcard))
            }
        }
    }
    fn _disconnect(&mut self) -> Result<(), Error> {
        self.card = None;
        Ok(())
    }
}

#[derive(Debug)]
struct CurlConnector {
    serial: String,
    url: String,
    connected: bool,
    curl: RefCell<curl::easy::Easy>
}

impl Connector for CurlConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        format!("{} {} {}", self.manufacturer(), self.product(), self.serial())
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

    fn transmit<'a>(&self, send_buffer: &[u8], receive_buffer: &'a mut [u8], _timeout: Duration) -> Result<&'a [u8], Error> {
        let mut write_len = 0usize;
        let mut read_len = 0usize;
        let mut curl = self.curl.try_borrow_mut()?;
        curl.post_field_size(send_buffer.len() as u64)?;
        {
            let mut transfer = curl.transfer();
            transfer.read_function(|mut slice| {
                let read = slice.write(&send_buffer[read_len..]).unwrap();
                read_len += read;
                Ok(read)
            })?;
            transfer.write_function(|slice| {
                let mut rslice = &mut receive_buffer[write_len..];
                let writ = rslice.write(slice).unwrap();
                write_len += writ;
                Ok(writ)
            })?;
            transfer.perform()?;
        }
        let received = &receive_buffer[..write_len];
        eprintln!("curl.post({:?}) -> {:?}", send_buffer, received);
        Ok(received)
    }
}

impl CurlConnector {
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
        eprintln!("curl.get() -> {:?}", String::from_utf8_lossy(&received).to_string());
        curl.url(&format!("{}/connector/api", self.url))?;
        curl.post(true)?;
        self.connected = true;
        Ok(())
    }
}

struct Scp03Session {
    cipher: openssl::symm::Cipher,
    key: Vec<u8>,
    iv: Option<Vec<u8>>
}

impl std::fmt::Debug for Scp03Session {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("Scp03Session")
            .field("cipher", &self.cipher.nid().short_name()?)
            .finish_non_exhaustive()
    }
}

impl Scp03Session {
    fn _encrypt(&self, data : &[u8]) -> Result<Vec<u8>, Error> {
        let iv = self.iv.as_ref().map(|v| &v[..]);
        let mut c = openssl::symm::Crypter::new(self.cipher, openssl::symm::Mode::Encrypt, &self.key, iv)?;
        //c.pad(false);
        let mut out = vec![0; data.len() + self.cipher.block_size()];
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }
    fn _decrypt(&self, data : &[u8]) -> Result<Vec<u8>, Error> {
        let iv = self.iv.as_ref().map(|v| &v[..]);
        let mut c = openssl::symm::Crypter::new(self.cipher, openssl::symm::Mode::Decrypt, &self.key, iv)?;
        //c.pad(false);
        let mut out = vec![0; data.len() + self.cipher.block_size()];
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }
}

struct Context {
    libusb: Option<rusb::Context>,
    pcsc: Option<pcsc::Context>,
    slots: HashMap<CK_SLOT_ID, Box<dyn Slot>>,
    sessions: HashMap<CK_SESSION_HANDLE, Box<dyn Session>>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("Context")
            .field("libusb", &self.libusb)
            .field("pcsc", &self.pcsc.as_ref().map(|_| "Context { .. }"))
            .field("slots", &self.slots)
            .field("sessions", &self.sessions)
            .finish()
    }
}

impl Context {
    fn new() -> Context {
        let context = Context {
            libusb: match rusb::Context::new() {
                Ok(context) => {
                    Some(context)
                },
                Err(e) => {
                    eprintln!("libusb::Context::new: {}", e);
                    None
                }
            },
            pcsc: match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => {
                    Some(context)
                },
                Err(e) => {
                    eprintln!("pcsc::Context::establish: {}", e);
                    None
                }
            },
            slots: HashMap::new(),
            sessions: HashMap::new(),
        };
        eprintln!("Context.new {:?}", context);
        context
    }
    fn get_info(&self, info: &mut CK_INFO) -> Result<(), Error> {
        info.cryptokiVersion.major = 2;
        info.cryptokiVersion.minor = 40;
        info.libraryVersion.major = 1;
        info.libraryVersion.minor = 0;
        info.flags = 0;
        str_pad("YubiHSM & YubiKey PKCS#11 module", &mut info.libraryDescription);
        str_pad("Yubico", &mut info.manufacturerID);
        Ok(())
    }
    fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&Box<dyn Slot>, Error> {
        match self.slots.get(&slot_id) {
            Some(slot) => Ok(slot),
            None => Err(CKR_SLOT_ID_INVALID.into())
        }
    }
    fn _get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> Result<&mut Box<dyn Slot>, Error> {
        match self.slots.get_mut(&slot_id) {
            Some(slot) => Ok(slot),
            None => Err(CKR_SLOT_ID_INVALID.into())
        }
    }
    fn get_session_(&self, session_handle: CK_SESSION_HANDLE) -> Option<(&Box<dyn Slot>, &Box<dyn Session>)> {
        let session = self.sessions.get(&session_handle)?;
        let slot = self.slots.get(&session.slotID())?;
        Some((slot, session))
    }
    fn _get_session(&self, session_handle: CK_SESSION_HANDLE) -> Result<(&Box<dyn Slot>, &Box<dyn Session>), Error> {
        match self.get_session_(session_handle) {
            Some(ctx) => Ok(ctx),
            None => Err(CKR_SESSION_HANDLE_INVALID.into())
        }
    }
    fn get_session_mut_(&mut self, session_handle: CK_SESSION_HANDLE) -> Option<(&Box<dyn Slot>, &mut Box<dyn Session>)> {
        let session = self.sessions.get_mut(&session_handle)?;
        let slot = self.slots.get(&session.slotID())?;
        Some((slot, session))
    }
    fn get_session_mut(&mut self, session_handle: CK_SESSION_HANDLE) -> Result<(&Box<dyn Slot>, &mut Box<dyn Session>), Error> {
        match self.get_session_mut_(session_handle) {
            Some(ctx) => Ok(ctx),
            None => Err(CKR_SESSION_HANDLE_INVALID.into())
        }
    }
    fn init(&'static mut self) {
        if let Some(context) = self.libusb.as_ref() {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(desc) = device.device_descriptor() {
                        //eprintln!("USB Bus {} Device {}: ID {}:{}", device.bus_number(), device.address(), desc.vendor_id(), desc.product_id());
                        if desc.vendor_id() == 0x1050 && desc.product_id() == 0x30 {
                            match device.open() {
                                Ok(handle) => {
                                    let version = desc.device_version();
                                    let packet_size = desc.max_packet_size() as usize;
                                    let manufacturer = handle.read_manufacturer_string_ascii(&desc).unwrap_or_default();
                                    let product = handle.read_product_string_ascii(&desc).unwrap_or_default();
                                    let serial = handle.read_serial_number_string_ascii(&desc).unwrap_or_default();
                                    let mut connector = UsbConnector {handle, version, manufacturer, product, serial, packet_size, claimed: false};
                                    //let mut connector = CurlConnector { serial, url: String::from("http://127.0.0.1:12345"), connected: false, curl: RefCell::new(curl::easy::Easy::new()) };
                                    let name = connector.name();
                                    eprintln!("{}", name);
                                    if !self.slots.values().any(|s| s.name() == name) {
                                        map(connector.connect());
                                        let k = next_key(&self.slots, 0);
                                        let mut v = Box::new(YubiHsmSlot { connector: Rc::new(connector) });
                                        map(v.init_slot());
                                        self.slots.insert(k, v);
                                    }
                                },
                                Err(e) => {
                                    eprintln!("libusb.open: {}", e);
                                }
                            }
                        }
                    }
                }
            } 
        }
        if let Some(context) = self.pcsc.as_ref() {
            if let Ok(readers) = context.list_readers_owned() {
                for reader in readers {
                    let mut connector = PcscConnector {reader, context, card: None};
                    let name = connector.name();
                    eprintln!("{}", name);
                    if !self.slots.values().any(|s| s.name() == name) {
                        map(connector.connect());
                        let k = next_key(&self.slots, 0);
                        let mut v = Box::new(YubiKeySlot { connector: Rc::new(connector) });
                        map(v.init_slot());
                        self.slots.insert(k, v);
                    }
                }
            }
        }
        eprintln!("Context.init {:?}", self);
    }
}

static mut G_CONTEXT: Option<Context> = None;

#[no_mangle]
pub extern "C" fn C_Initialize(init_args: *mut CK_C_INITIALIZE_ARGS) -> CK_RV {
    eprintln!("C_Initialize called with {:?}", init_args);
    unsafe {       
        match G_CONTEXT.as_mut() {
            Some(_) => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            None => {
                G_CONTEXT = Some(Context::new());
                CKR_OK
            }
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: *mut ::std::os::raw::c_void) -> CK_RV {
    eprintln!("C_Finalize called with {:?}", pReserved);
    unsafe {
        match G_CONTEXT.as_mut() {
            Some(_ctx) => {
                G_CONTEXT = None;
                CKR_OK
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    unsafe {
        eprintln!("C_GetFunctionList called with {:?}", (function_list, *function_list));
        *function_list = &G_FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
        eprintln!("C_GetFunctionList returning {:?}", *function_list);
        CKR_OK
    }.into()
}

fn get_info(
    info_ptr: CK_INFO_PTR
) -> Result<(), Error> {
    get_ctx()?.get_info(as_mut(info_ptr)?)
}

#[no_mangle]
pub extern "C" fn C_GetInfo(info_ptr: *mut CK_INFO) -> CK_RV {
    eprintln!("C_GetInfo called with {:?}", info_ptr);
    map(get_info(info_ptr))
}

#[no_mangle]
pub extern "C" fn C_GetSlotList(
    token_present: ::std::os::raw::c_uchar,
    slot_list: *mut CK_SLOT_ID,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    unsafe {
        eprintln!("C_GetSlotList called with {:?}", (token_present, slot_list, *count));
        if let Some(ctx) = G_CONTEXT.as_mut() {
            ctx.init();
        }
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                let mut keys: Vec<CK_SLOT_ID> = if token_present == 0 {
                    ctx.slots.keys().cloned().collect()
                } else {
                    ctx.slots.iter().filter(|s| s.1.flags() & (CKF_TOKEN_PRESENT as CK_FLAGS) != 0).map(|s| *s.0).collect()
                };
                match slot_list.as_mut() {
                    Some(_) => {
                        if *count >= keys.len() as ::std::os::raw::c_ulong {
                            keys.sort();
                            ptr::copy(keys.as_ptr(), slot_list, keys.len());
                            *count = keys.len() as ::std::os::raw::c_ulong;
                            eprintln!("C_GetSlotList returning {:?}", (keys, *count));
                            CKR_OK
                        } else {
                            *count = keys.len() as ::std::os::raw::c_ulong;
                            eprintln!("C_GetSlotList returning {:?}", *count);
                            CKR_BUFFER_TOO_SMALL
                        }
                    },
                    None => {
                        *count = keys.len() as ::std::os::raw::c_ulong;
                        eprintln!("C_GetSlotList returning {:?}", *count);
                        CKR_OK
                    }
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

fn get_slot_info(
    slotID: CK_SLOT_ID,
    info_ptr: CK_SLOT_INFO_PTR
) -> Result<(), Error> {
    get_ctx()?.get_slot(slotID)?.get_slot_info(as_mut(info_ptr)?)
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, info_ptr: *mut CK_SLOT_INFO) -> CK_RV {
    eprintln!("C_GetSlotInfo called with {:?}", (slotID, info_ptr));
    map(get_slot_info(slotID, info_ptr))
}

fn get_token_info(
    slotID: CK_SLOT_ID,
    info_ptr: CK_TOKEN_INFO_PTR
) -> Result<(), Error> {
    get_ctx()?.get_slot(slotID)?.get_token_info(as_mut(info_ptr)?)
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

#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    unsafe {
        eprintln!("C_GetMechanismList called with {:?}", (slotID, mechanism_list, *count));
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.slots.get(&slotID) {
                    Some(slot) => {
                        eprintln!("{:?}", slot);
                        match mechanism_list.as_mut() {
                            Some(_) => {
                                let list = slice::from_raw_parts_mut(mechanism_list, *count as usize);
                                for i in 0..*count {
                                    list[i as usize] = i;
                                }
                                eprintln!("C_GetMechanismList returning {:?}", list);
                                CKR_OK
                            },
                            None => {
                                eprintln!("C_GetMechanismList returning {:?}", 7);
                                *count = 7;
                                CKR_OK
                            }
                        }
                    }
                    None => CKR_SLOT_ID_INVALID
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info_ptr: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    eprintln!("C_GetMechanismInfo called with {:?}", (slotID, type_, info_ptr));
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.slots.get(&slotID) {
                    Some(slot) => {
                        eprintln!("{:?}", slot);
                        match info_ptr.as_mut() {
                            Some(info) => {
                                info.ulMinKeySize = 1024;
                                info.ulMaxKeySize = 4096;
                                info.flags = 0;
                                eprintln!("C_GetMechanismInfo returning {:?}", info);
                                CKR_OK
                            },
                            None => CKR_ARGUMENTS_BAD
                        }
                    }
                    None => CKR_SLOT_ID_INVALID
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
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
    _session: CK_SESSION_HANDLE,
    _pin: *mut ::std::os::raw::c_uchar,
    _pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SetPIN(
    _session: CK_SESSION_HANDLE,
    _old_pin: *mut ::std::os::raw::c_uchar,
    _old_len: ::std::os::raw::c_ulong,
    _new_pin: *mut ::std::os::raw::c_uchar,
    _new_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

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
        match G_CONTEXT.as_mut() {
            Some(ctx) => {
                match ctx.slots.get_mut(&slotID) {
                    Some(slot) => {
                        eprintln!("{:?}", slot);
                        if slot.flags() & CKF_TOKEN_PRESENT as CK_FLAGS != 0 {
                            let k = next_key(&ctx.sessions, 1);
                            eprintln!("C_OpenSession sessions before {:?}", ctx.sessions);
                            ctx.sessions.insert(k, slot.open_session(slotID, flags));
                            eprintln!("C_OpenSession sessions after {:?}", ctx.sessions);
                            eprintln!("C_OpenSession returning {:?}", k);
                            *session = k;
                            CKR_OK
                        } else {
                            CKR_TOKEN_NOT_PRESENT
                        }
                    }
                    None => CKR_SLOT_ID_INVALID
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_CloseSession(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("C_CloseSession called with {:?}", session_handle);
    unsafe {
        match G_CONTEXT.as_mut() {
            Some(ctx) => {
                eprintln!("C_CloseSession sessions before {:?}", ctx.sessions);
                match ctx.sessions.remove(&session_handle) {
                    Some(session) => {
                        eprintln!("C_CloseSession removed {:?}", (session_handle, session));
                        eprintln!("C_CloseSession sessions after {:?}", ctx.sessions);
                        CKR_OK
                    }
                    None => CKR_SESSION_HANDLE_INVALID
                }
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    eprintln!("C_CloseAllSessions called with {:?}", slotID);
    unsafe {
        match G_CONTEXT.as_mut() {
            Some(ctx) => {
                eprintln!("C_CloseAllSessions sessions before {:?}", ctx.sessions);
                ctx.sessions.retain(|_k, v| v.slotID() != slotID);
                eprintln!("C_CloseAllSessions sessions after {:?}", ctx.sessions);
                CKR_OK
            }
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_GetSessionInfo(session_handle: CK_SESSION_HANDLE, info_ptr: *mut CK_SESSION_INFO) -> CK_RV {
    eprintln!("C_GetSessionInfo called with {:?}", session_handle);
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.get_session_(session_handle) {
                    Some(session) => {
                        eprintln!("C_GetSessionInfo {:?}", session);
                        match info_ptr.as_mut() {
                            Some(info) => {
                                info.slotID = session.1.slotID();
                                info.state = session.1.state();
                                info.flags = session.1.flags();
                                info.ulDeviceError = 0;
                                eprintln!("C_GetSessionInfo returning {:?}", info);
                                CKR_OK
                            },
                            None => CKR_ARGUMENTS_BAD
                        }
                    }
                    None => CKR_SESSION_HANDLE_INVALID
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_GetOperationState(
    _session: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SetOperationState(
    _session: CK_SESSION_HANDLE,
    _operation_state: *mut ::std::os::raw::c_uchar,
    _operation_state_len: ::std::os::raw::c_ulong,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentiation_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

fn login(
    session_handle: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    pin: *const ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> Result<(), Error> {
    let session = get_ctx_mut()?.get_session_mut(session_handle)?;
    let pin = from_raw_parts(pin, pin_len as usize)?;
    eprintln!("login {:?} {:?}", session, pin);
    session.1.login(pin)
}

#[no_mangle]
pub extern "C" fn C_Login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *mut ::std::os::raw::c_uchar,
    pin_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_Login called with {:?}", (session_handle, user_type, pin, pin_len));
    map(login(session_handle, user_type, pin, pin_len))
}

#[no_mangle]
pub extern "C" fn C_Logout(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("C_Logout called with {:?}", session_handle);
    unsafe {
        match G_CONTEXT.as_mut() {
            Some(ctx) => {
                match ctx.get_session_mut_(session_handle) {
                    Some(session) => {
                        eprintln!("C_Logout {:?}", session);
                        map(session.1.logout())
                    }
                    None => CKR_SESSION_HANDLE_INVALID as CK_RV
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
        }
    }
}

#[no_mangle]
pub extern "C" fn C_CreateObject(
    _session: CK_SESSION_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _count: ::std::os::raw::c_ulong,
    _object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_CopyObject(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _count: ::std::os::raw::c_ulong,
    _new_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(_session: CK_SESSION_HANDLE, _object: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _size: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _count: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SetAttributeValue(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _count: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    session_handle: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_FindObjectsInit called with {:?}", (session_handle, templ, count));
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.get_session_(session_handle) {
                    Some(session) => {
                        eprintln!("C_FindObjectsInit {:?}", session);
                        match templ.as_ref() {
                            Some(_info) => { 
                                CKR_OK
                            },
                            None => {
                                CKR_OK
                            }
                        }
                    }
                    None => CKR_SESSION_HANDLE_INVALID
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    session_handle: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: ::std::os::raw::c_ulong,
    object_count: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_FindObjects called with {:?}", (session_handle, object, max_object_count, object_count));
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.get_session_(session_handle) {
                    Some(session) => {
                        eprintln!("C_FindObjects {:?}", session);
                        match object.as_mut() {
                            Some(_info) => {
                                eprintln!("C_FindObjects returning {:?}", 0);
                                *object_count = 0;
                                CKR_OK
                            },
                            None => CKR_ARGUMENTS_BAD
                        }
                    }
                    None => CKR_SESSION_HANDLE_INVALID
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("C_FindObjectsFinal called with {:?}", session_handle);
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.get_session_(session_handle) {
                    Some(session) => {
                        eprintln!("C_FindObjectsFinal {:?}", session);
                        CKR_OK
                    }
                    None => CKR_SESSION_HANDLE_INVALID
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }.into()
}

#[no_mangle]
pub extern "C" fn C_EncryptInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_Encrypt(
    _session: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _encrypted_data: *mut ::std::os::raw::c_uchar,
    _encrypted_data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    _session: CK_SESSION_HANDLE,
    _last_encrypted_part: *mut ::std::os::raw::c_uchar,
    _last_encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DecryptInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_Decrypt(
    _session: CK_SESSION_HANDLE,
    _encrypted_data: *mut ::std::os::raw::c_uchar,
    _encrypted_data_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    _session: CK_SESSION_HANDLE,
    _last_part: *mut ::std::os::raw::c_uchar,
    _last_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DigestInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_Digest(
    _session: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DigestKey(
    _session: CK_SESSION_HANDLE,
    _key: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DigestFinal(
    _session: CK_SESSION_HANDLE,
    _digest: *mut ::std::os::raw::c_uchar,
    _digest_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_Sign(
    _session: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    _session: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    _session: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_Verify(
    _session: CK_SESSION_HANDLE,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    _session: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_VerifyRecover(
    _session: CK_SESSION_HANDLE,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: ::std::os::raw::c_ulong,
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DigestEncryptUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DecryptDigestUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    _session: CK_SESSION_HANDLE,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: ::std::os::raw::c_ulong,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DecryptVerifyUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: *mut ::std::os::raw::c_uchar,
    _encrypted_part_len: ::std::os::raw::c_ulong,
    _part: *mut ::std::os::raw::c_uchar,
    _part_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_GenerateKey(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    templ: *mut CK_ATTRIBUTE,
    count: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("C_GenerateKey called with {:?}", (session_handle, mechanism, templ, count, key));
    unsafe {
        match G_CONTEXT.as_ref() {
            Some(ctx) => {
                match ctx.get_session_(session_handle) {
                    Some(session) => {
                        eprintln!("C_GenerateKey {:?}", session);
                        if let Some(mechanism) = mechanism.as_ref() {
                            eprintln!("C_GenerateKey {:?}", mechanism);
                            if let Some(_) = templ.as_ref() {
                                let templ = slice::from_raw_parts(templ, count as usize);
                                eprintln!("C_GenerateKey {:?}", templ);
                                *key = 99;
                                map(session.1.generate())
                            } else {
                                CKR_ARGUMENTS_BAD as CK_RV
                            }
                        } else {
                            CKR_ARGUMENTS_BAD as CK_RV
                        }
                    },
                    None => CKR_SESSION_HANDLE_INVALID as CK_RV
                }
            },
            None => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
        }
    }
}

#[no_mangle]
pub extern "C" fn C_GenerateKeyPair(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _public_key_template: *mut CK_ATTRIBUTE,
    _public_key_attribute_count: ::std::os::raw::c_ulong,
    _private_key_template: *mut CK_ATTRIBUTE,
    _private_key_attribute_count: ::std::os::raw::c_ulong,
    _public_key: *mut CK_OBJECT_HANDLE,
    _private_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_WrapKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _wrapping_key: CK_OBJECT_HANDLE,
    _key: CK_OBJECT_HANDLE,
    _wrapped_key: *mut ::std::os::raw::c_uchar,
    _wrapped_key_len: *mut ::std::os::raw::c_ulong,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_UnwrapKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _unwrapping_key: CK_OBJECT_HANDLE,
    _wrapped_key: *mut ::std::os::raw::c_uchar,
    _wrapped_key_len: ::std::os::raw::c_ulong,
    _templ: *mut CK_ATTRIBUTE,
    _attribute_count: ::std::os::raw::c_ulong,
    _key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_DeriveKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: *mut CK_MECHANISM,
    _base_key: CK_OBJECT_HANDLE,
    _templ: *mut CK_ATTRIBUTE,
    _attribute_count: ::std::os::raw::c_ulong,
    _key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_SeedRandom(
    _session: CK_SESSION_HANDLE,
    _seed: *mut ::std::os::raw::c_uchar,
    _seed_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_SeedRandom called");
    CKR_OK.into()
}

#[no_mangle]
pub extern "C" fn C_GenerateRandom(
    _session: CK_SESSION_HANDLE,
    _random_data: *mut ::std::os::raw::c_uchar,
    _random_len: ::std::os::raw::c_ulong,
) -> CK_RV {
    eprintln!("C_GenerateRandom called");
    CKR_OK.into()
}

#[no_mangle]
pub extern "C" fn C_GetFunctionStatus(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

#[no_mangle]
pub extern "C" fn C_CancelFunction(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED.into()
}

static G_FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version : CK_VERSION {major: 2, minor: 40},

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
};
