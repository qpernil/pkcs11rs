use super::*;

#[cfg(feature = "abi-tests")]
mod yubihsm_connector;

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
pub(super) struct AbiTestSlot;

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
    fn kind(&self) -> SlotKind {
        SlotKind::Synthetic
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

    fn login_so(&mut self, pin: &[u8]) -> Result<(), Error> {
        if pin != b"12345678" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        Ok(())
    }

    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        if old_pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        if new_pin.len() < 4 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn set_so_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        if old_pin != b"12345678" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        if new_pin.len() < 8 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        Ok(())
    }

    fn init_user_pin(&mut self, new_pin: &[u8]) -> Result<(), Error> {
        if new_pin.len() < 4 {
            return Err(CKR_PIN_LEN_RANGE.into());
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
struct AbiPivConnector {
    certificate_data: Vec<u8>,
}

#[cfg(feature = "abi-tests")]
fn abi_piv_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(tag);
    if value.len() < 0x80 {
        encoded.push(value.len() as u8);
    } else if value.len() <= u8::MAX as usize {
        encoded.extend([0x81, value.len() as u8]);
    } else if value.len() <= u16::MAX as usize {
        encoded.push(0x82);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    } else {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

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
        let command = CommandApdu::decode(command)?;
        let mut response = match command.ins {
            0xa4 | 0x20 => Vec::new(),
            0xfd => vec![5, 7, 0],
            0xf8 => vec![0, 0, 0, 1],
            0xf7 if command.p2 == piv::Slot::Signature as u8 => vec![
                0x01,
                0x01,
                piv::Algorithm::Rsa2048 as u8,
                0x02,
                0x02,
                2,
                1,
                0x03,
                0x01,
                piv::ORIGIN_GENERATED,
            ],
            0xcb if command.data == [0x5c, 0x03, 0x5f, 0xc1, 0x0a] => {
                abi_piv_tlv(0x53, &self.certificate_data)?
            }
            0x87 => {
                let mut response = vec![0x7c, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00];
                response.extend(std::iter::repeat_n(0, 256));
                response
            }
            _ => vec![0x6a, 0x82],
        };
        if response != [0x6a, 0x82] {
            response.extend([0x90, 0x00]);
        }
        if response.len() > receive.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive[..response.len()].copy_from_slice(&response);
        Ok(&receive[..response.len()])
    }
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_piv_slot() -> Result<PivSlot, Error> {
    static CERTIFICATE: OnceLock<Vec<u8>> = OnceLock::new();
    let private_key = certificate_builder::rsa_key();
    let public_key = RsaPublicKey::from(&private_key);
    let certificate = CERTIFICATE
        .get_or_init(|| {
            let signer = certificate_builder::p256_key();
            certificate_builder::p256_certificate_for_rsa(
                &public_key,
                &signer,
                "CN=PKCS11RS ABI PIV",
                "CN=PKCS11RS ABI test CA",
                1,
            )
        })
        .clone();
    let certificate_data = piv::encode_certificate_object(&certificate)?;
    let connector: Rc<dyn Connector> = Rc::new(AbiPivConnector { certificate_data });
    let mut slot = PivSlot::new(connector, piv::PIV_AID.to_vec());
    Slot::init_slot(&mut slot)?;
    Ok(slot)
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
        let decoded = CommandApdu::decode(command)?;
        let response = if decoded.ins == 0xd8 && decoded.p2 & 0x80 != 0 {
            abi_scp03_put_key_response(command)?
        } else if decoded.ins == 0xd8 {
            let mut response = vec![*decoded.data.first().ok_or(CKR_DATA_INVALID)?];
            response.extend([0x90, 0x00]);
            response
        } else if decoded.ins == 0xf1 {
            let mut response = vec![0xb0, 65];
            response.extend(crate::scp03::parse_hex(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            )?);
            response.extend([0x90, 0x00]);
            response
        } else if decoded.ins == 0x84 {
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
fn abi_scp03_put_key_response(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let command = CommandApdu::decode(encoded)?;
    let mut data = command.data.as_slice();
    let new_kvn = *data.first().ok_or(CKR_DATA_INVALID)?;
    data = &data[1..];
    let mut response = vec![new_kvn];
    for _ in 0..3 {
        if data.len() < 22 || data[..2] != [0x88, 0x10] || data[18] != 3 {
            return Ok(vec![0x6a, 0x80]);
        }
        let wrapped = &data[2..18];
        let key = crate::secure_channel_crypto::aes_cbc(
            &[0; 16],
            &[0; 16],
            wrapped,
            crate::secure_channel_crypto::Direction::Decrypt,
        )?;
        let encrypted_ones = crate::secure_channel_crypto::aes_encrypt_block(
            &key,
            &[1; crate::secure_channel_crypto::AES_BLOCK_SIZE],
        )?;
        if data[19..22] != encrypted_ones[..3] {
            return Ok(vec![0x6a, 0x80]);
        }
        response.extend_from_slice(&encrypted_ones[..3]);
        data = &data[22..];
    }
    if !data.is_empty() {
        return Ok(vec![0x6a, 0x80]);
    }
    response.extend_from_slice(&[0x90, 0x00]);
    Ok(response)
}

#[cfg(feature = "abi-tests")]
#[derive(Debug)]
pub(super) struct AbiScp03Slot {
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
    protocol: &'static str,
}

#[cfg(feature = "abi-tests")]
impl AbiScp03Slot {
    pub(super) fn new(protocol: &'static str) -> Result<Self, Error> {
        Ok(Self {
            connector: Rc::new(AbiScp03Connector { protocol }),
            session: Rc::new(RefCell::new(Some(Scp03Session::from_session_keys(
                vec![0; 16],
                vec![0; 16],
                vec![0; 16],
                (protocol == "SCP03").then(|| vec![0; 16]),
                protocol != "SCP11B",
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
    fn kind(&self) -> SlotKind {
        SlotKind::Ccid(CcidApplication::IssuerSecurityDomain)
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
        Box::new(IssuerSecurityDomainSession {
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
            (self.protocol == "SCP03").then(|| vec![0; 16]),
            self.protocol != "SCP11B",
            [0; 16],
            0,
        )?);
        Ok(())
    }
    fn login_without_pin(&mut self) -> Result<(), Error> {
        self.login(&[])
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
        info.ulMinPinLen = 0;
        info.ulMaxPinLen = 0;
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
fn abi_yubihsm_command(command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
    const NIST_AES_KEY_ID: u16 = 3;
    const NIST_AES_128_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const RFC5649_AES_192_KEY: [u8; 24] = [
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ];
    const RFC3610_AES_128_KEY: [u8; 16] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf,
    ];
    const NIST_GMAC_AES_128_KEY: [u8; 16] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    const RFC3394_AES_128_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let data = command.data();
    let id = data
        .get(..2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(CKR_DATA_LEN_RANGE)?;
    let key: &[u8] = match id {
        NIST_AES_KEY_ID => &NIST_AES_128_KEY,
        ABI_YUBIHSM_RFC5649_AES_KEY_ID => &RFC5649_AES_192_KEY,
        ABI_YUBIHSM_RFC3610_AES_KEY_ID => &RFC3610_AES_128_KEY,
        ABI_YUBIHSM_NIST_GMAC_AES_KEY_ID => &NIST_GMAC_AES_128_KEY,
        ABI_YUBIHSM_RFC3394_AES_KEY_ID => &RFC3394_AES_128_KEY,
        _ => &[0; 16],
    };
    let (direction, iv, input) = match command.code() {
        YubiHsmCommandCode::GetOpaque => {
            return match id {
                0 => abi_yubihsm_attestation_signer_certificate(),
                ABI_YUBIHSM_OPAQUE_DATA_ID => Ok(ABI_YUBIHSM_OPAQUE_DATA.to_vec()),
                ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID => abi_yubihsm_opaque_certificate(),
                _ => Err(CKR_OBJECT_HANDLE_INVALID.into()),
            };
        }
        YubiHsmCommandCode::SignAttestationCertificate => {
            if data != [0, 0, 0, 0] {
                return Err(CKR_OBJECT_HANDLE_INVALID.into());
            }
            return abi_yubihsm_device_attestation();
        }
        YubiHsmCommandCode::ExportWrapped
        | YubiHsmCommandCode::GetRsaWrappedKey
        | YubiHsmCommandCode::ExportRsaWrapped => {
            return Ok([b"ABI wrapped key:".as_slice(), data].concat());
        }
        YubiHsmCommandCode::ImportWrapped | YubiHsmCommandCode::ImportRsaWrapped => {
            return Ok(vec![YUBIHSM_SYMMETRIC_KEY, 0, 2]);
        }
        YubiHsmCommandCode::PutRsaWrappedKey => {
            let object_type = *data.get(2).ok_or(CKR_DATA_LEN_RANGE)?;
            return Ok(vec![object_type, 0, 2]);
        }
        YubiHsmCommandCode::SignHmac => {
            if id != ABI_YUBIHSM_HMAC_KEY_ID {
                return Err(CKR_OBJECT_HANDLE_INVALID.into());
            }
            return abi_yubihsm_hmac_sha256(data.get(2..).ok_or(CKR_DATA_LEN_RANGE)?);
        }
        YubiHsmCommandCode::VerifyHmac => {
            if id != ABI_YUBIHSM_HMAC_KEY_ID {
                return Err(CKR_OBJECT_HANDLE_INVALID.into());
            }
            let signature = data.get(2..34).ok_or(CKR_DATA_LEN_RANGE)?;
            let expected = abi_yubihsm_hmac_sha256(data.get(34..).ok_or(CKR_DATA_LEN_RANGE)?)?;
            return Ok(vec![u8::from(signature == expected)]);
        }
        YubiHsmCommandCode::EncryptEcb => (
            secure_channel_crypto::Direction::Encrypt,
            None,
            data.get(2..),
        ),
        YubiHsmCommandCode::DecryptEcb => (
            secure_channel_crypto::Direction::Decrypt,
            None,
            data.get(2..),
        ),
        YubiHsmCommandCode::EncryptCbc => (
            secure_channel_crypto::Direction::Encrypt,
            data.get(2..18),
            data.get(18..),
        ),
        YubiHsmCommandCode::DecryptCbc => (
            secure_channel_crypto::Direction::Decrypt,
            data.get(2..18),
            data.get(18..),
        ),
        _ => return Ok(vec![0x5a; 256]),
    };
    let input = input.ok_or(CKR_DATA_LEN_RANGE)?;
    if !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    if let Some(iv) = iv {
        secure_channel_crypto::aes_cbc(key, iv, input, direction)
    } else {
        secure_channel_crypto::aes_ecb(key, input, direction)
    }
}

#[cfg(feature = "abi-tests")]
#[derive(Debug, Default)]
struct AbiYubiHsmConcurrencyRound {
    arrived: usize,
    generation: usize,
}

#[cfg(feature = "abi-tests")]
#[derive(Debug, Default)]
struct AbiYubiHsmConcurrencyState {
    active_by_slot: [std::sync::atomic::AtomicBool; 2],
    changed: std::sync::Condvar,
    round: std::sync::Mutex<AbiYubiHsmConcurrencyRound>,
    verified: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "abi-tests")]
impl AbiYubiHsmConcurrencyState {
    fn overlap(&self, slot_index: usize) -> Result<(), Error> {
        use std::sync::atomic::Ordering;

        if self.verified.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.active_by_slot[slot_index].swap(true, Ordering::SeqCst) {
            return Err(CKR_CANT_LOCK.into());
        }
        struct ActiveGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for ActiveGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _active = ActiveGuard(&self.active_by_slot[slot_index]);

        let mut round = self.round.lock().map_err(|_| CKR_MUTEX_BAD)?;
        let generation = round.generation;
        round.arrived += 1;
        if round.arrived == 2 {
            round.arrived = 0;
            round.generation += 1;
            self.verified.store(true, Ordering::SeqCst);
            self.changed.notify_all();
            return Ok(());
        }

        let (mut round, timeout) = self
            .changed
            .wait_timeout_while(round, Duration::from_secs(2), |round| {
                round.generation == generation
            })
            .map_err(|_| CKR_MUTEX_BAD)?;
        if timeout.timed_out() && round.generation == generation {
            round.arrived = round.arrived.saturating_sub(1);
            return Err(CKR_FUNCTION_FAILED.into());
        }
        Ok(())
    }
}

#[cfg(feature = "abi-tests")]
type AbiSlot = (CK_SLOT_ID, Box<dyn Slot>);

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_slots() -> Result<Vec<AbiSlot>, Error> {
    let new_slot = |connector: Rc<dyn Connector>| -> Result<YubiHsmSlot, Error> {
        let public_discovery = configured_yubihsm_public_discovery_credential(Some(
            std::ffi::OsString::from("0001password"),
        ))?;
        let mut slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
            connector,
            (2, 4, 0),
            Vec::new(),
            Arc::new(HsmAuthProviderRegistry::default()),
            public_discovery,
        );
        Slot::init_slot(&mut slot)?;
        Ok(slot)
    };
    if std::env::var_os("PKCS11RS_ABI_CONCURRENCY_TEST").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        let connector: Rc<dyn Connector> = Rc::new(yubihsm_connector::AbiYubiHsmConnector::new(
            "HSM00001", None,
        )?);
        let slot = new_slot(connector)?;
        return Ok(vec![(
            ABI_TEST_YUBIHSM_SLOT_ID,
            Box::new(slot) as Box<dyn Slot>,
        )]);
    }

    let state = Arc::new(AbiYubiHsmConcurrencyState::default());
    [
        (ABI_TEST_YUBIHSM_SLOT_ID, "HSM00001", 0),
        (ABI_TEST_SECOND_YUBIHSM_SLOT_ID, "HSM00002", 1),
    ]
    .into_iter()
    .map(|(slot_id, serial, slot_index)| {
        let connector: Rc<dyn Connector> = Rc::new(yubihsm_connector::AbiYubiHsmConnector::new(
            serial,
            Some((state.clone(), slot_index)),
        )?);
        let slot = new_slot(connector)?;
        Ok((slot_id, Box::new(slot) as Box<dyn Slot>))
    })
    .collect()
}

#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA_ID: u16 = 5;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID: u16 = 6;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA: &[u8] = b"ABI opaque data";
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_HMAC_KEY_ID: u16 = 11;
const ABI_YUBIHSM_RFC5649_AES_KEY_ID: u16 = 12;
const ABI_YUBIHSM_RFC3610_AES_KEY_ID: u16 = 13;
const ABI_YUBIHSM_NIST_GMAC_AES_KEY_ID: u16 = 14;
const ABI_YUBIHSM_RFC3394_AES_KEY_ID: u16 = 15;

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_hmac_sha256(data: &[u8]) -> Result<Vec<u8>, Error> {
    use hmac::{Hmac, KeyInit, Mac};

    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[0x0b; 20])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_private_key(scalar: u32) -> Result<p256::ecdsa::SigningKey, Error> {
    let mut encoded = [0; 32];
    encoded[28..].copy_from_slice(&scalar.to_be_bytes());
    p256::SecretKey::from_slice(&encoded)
        .map(p256::ecdsa::SigningKey::from)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_public_key(key: &p256::ecdsa::SigningKey) -> p256::ecdsa::VerifyingKey {
    *key.verifying_key()
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_device_public_key() -> Result<Vec<u8>, Error> {
    let key = abi_yubihsm_private_key(1)?;
    Ok(certificate_builder::p256_public_point(key.verifying_key()))
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_certificate(
    public_key: &p256::ecdsa::VerifyingKey,
    signer: &p256::ecdsa::SigningKey,
    serial: u32,
) -> Result<Vec<u8>, Error> {
    Ok(certificate_builder::p256_certificate(
        public_key,
        signer,
        "CN=PKCS11RS ABI YubiHSM attestation",
        "CN=PKCS11RS ABI YubiHSM attestation",
        serial,
        false,
    ))
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_attestation_signer_certificate() -> Result<Vec<u8>, Error> {
    let signer = abi_yubihsm_private_key(2)?;
    abi_yubihsm_certificate(&abi_yubihsm_public_key(&signer), &signer, 1)
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_device_attestation() -> Result<Vec<u8>, Error> {
    let device = abi_yubihsm_private_key(1)?;
    let signer = abi_yubihsm_private_key(2)?;
    abi_yubihsm_certificate(&abi_yubihsm_public_key(&device), &signer, 2)
}

#[cfg(feature = "abi-tests")]
fn abi_yubihsm_opaque_certificate() -> Result<Vec<u8>, Error> {
    static CERTIFICATE: OnceLock<Vec<u8>> = OnceLock::new();
    if let Some(certificate) = CERTIFICATE.get() {
        return Ok(certificate.clone());
    }
    let signer = certificate_builder::p256_key();
    let certificate = certificate_builder::p256_certificate(
        signer.verifying_key(),
        &signer,
        "CN=PKCS11RS ABI YubiHSM",
        "CN=PKCS11RS ABI YubiHSM",
        0x80,
        true,
    );
    let _ = CERTIFICATE.set(certificate);
    CERTIFICATE.get().cloned().ok_or(CKR_DEVICE_ERROR.into())
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_object(slot_id: CK_SLOT_ID) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: "abi-yubihsm-rsa".to_owned(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "testrsa-pri".to_owned(),
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
        creator_session: None,
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
fn abi_test_yubihsm_public_object(slot_id: CK_SLOT_ID) -> TokenObject {
    let key = RsaPublicKey::from(&certificate_builder::rsa_key());
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: "abi-yubihsm-rsa-public".to_owned(),
        class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "testrsa-pub".to_owned(),
        id: 1u16.to_be_bytes().to_vec(),
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
        key_gen_mechanism: None,
        creator_session: None,
        material: KeyMaterial::YubiHsm {
            id: 1,
            object_type: YUBIHSM_PUBLIC_KEY,
            algorithm: YUBIHSM_ALGO_RSA_2048,
            length: key.size(),
            domains: 0xffff,
            capabilities: yubihsm_capabilities(&[5]),
            delegated_capabilities: [0; 8],
            public_key: key.n().to_bytes_be(),
            value: Rc::new(RefCell::new(None)),
        },
    }
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: "abi-yubihsm-aes".to_owned(),
        class: CKO_SECRET_KEY as CK_OBJECT_CLASS,
        key_type: CKK_AES as CK_KEY_TYPE,
        label: "ABI YubiHSM AES key".to_owned(),
        id: 2u16.to_be_bytes().to_vec(),
        token: true,
        private: true,
        encrypt: true,
        decrypt: true,
        sign: true,
        verify: true,
        derive: false,
        sensitive: true,
        extractable: true,
        always_sensitive: true,
        never_extractable: false,
        local: true,
        key_gen_mechanism: Some(CKM_AES_KEY_GEN as CK_MECHANISM_TYPE),
        creator_session: None,
        material: KeyMaterial::YubiHsm {
            id: 2,
            object_type: YUBIHSM_SYMMETRIC_KEY,
            algorithm: YUBIHSM_ALGO_AES128,
            length: 16,
            domains: 0xffff,
            capabilities: yubihsm_capabilities(&[0x10, 0x32, 0x33]),
            delegated_capabilities: [0; 8],
            public_key: Vec::new(),
            value: Rc::new(RefCell::new(None)),
        },
    }
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_nist_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    const NIST_AES_KEY_ID: u16 = 3;
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = "abi-yubihsm-aes-nist".to_owned();
    object.label = "ABI YubiHSM NIST AES key".to_owned();
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
fn abi_test_yubihsm_rfc5649_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = "abi-yubihsm-aes-rfc5649".to_owned();
    object.label = "ABI YubiHSM RFC 5649 AES key".to_owned();
    object.id = ABI_YUBIHSM_RFC5649_AES_KEY_ID.to_be_bytes().to_vec();
    if let KeyMaterial::YubiHsm {
        id,
        algorithm,
        length,
        capabilities,
        ..
    } = &mut object.material
    {
        *id = ABI_YUBIHSM_RFC5649_AES_KEY_ID;
        *algorithm = YUBIHSM_ALGO_AES192;
        *length = 24;
        *capabilities = yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]);
    }
    object
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_rfc3610_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = "abi-yubihsm-aes-rfc3610".to_owned();
    object.label = "ABI YubiHSM RFC 3610 AES key".to_owned();
    object.id = ABI_YUBIHSM_RFC3610_AES_KEY_ID.to_be_bytes().to_vec();
    if let KeyMaterial::YubiHsm {
        id, capabilities, ..
    } = &mut object.material
    {
        *id = ABI_YUBIHSM_RFC3610_AES_KEY_ID;
        *capabilities = yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]);
    }
    object
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_nist_gmac_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = "abi-yubihsm-aes-nist-gmac".to_owned();
    object.label = "ABI YubiHSM NIST GMAC AES key".to_owned();
    object.id = ABI_YUBIHSM_NIST_GMAC_AES_KEY_ID.to_be_bytes().to_vec();
    if let KeyMaterial::YubiHsm {
        id, capabilities, ..
    } = &mut object.material
    {
        *id = ABI_YUBIHSM_NIST_GMAC_AES_KEY_ID;
        *capabilities = yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]);
    }
    object
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_rfc3394_aes_object(slot_id: CK_SLOT_ID) -> TokenObject {
    let mut object = abi_test_yubihsm_aes_object(slot_id);
    object.unique_id = "abi-yubihsm-aes-rfc3394".to_owned();
    object.label = "ABI YubiHSM RFC 3394 AES key".to_owned();
    object.id = ABI_YUBIHSM_RFC3394_AES_KEY_ID.to_be_bytes().to_vec();
    if let KeyMaterial::YubiHsm {
        id, capabilities, ..
    } = &mut object.material
    {
        *id = ABI_YUBIHSM_RFC3394_AES_KEY_ID;
        *capabilities = yubihsm_capabilities(&[0x32, 0x33, 0x34, 0x35]);
    }
    object
}

#[cfg(feature = "abi-tests")]
fn abi_test_yubihsm_hmac_object(slot_id: CK_SLOT_ID) -> Result<TokenObject, Error> {
    let info = YubiHsmObjectInfo {
        capabilities: yubihsm_capabilities(&[0x16, 0x17]),
        id: ABI_YUBIHSM_HMAC_KEY_ID,
        length: 20,
        domains: 1,
        object_type: YUBIHSM_HMAC_KEY,
        algorithm: YUBIHSM_ALGO_HMAC_SHA256,
        sequence: 1,
        origin: 1,
        label: "RFC 4231 HMAC key".to_owned(),
        delegated_capabilities: [0; 8],
    };
    yubihsm_token_objects(slot_id, info, None)?
        .pop()
        .ok_or(CKR_DEVICE_ERROR.into())
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_authentication_objects(
    slot_id: CK_SLOT_ID,
) -> Result<Vec<TokenObject>, Error> {
    [
        (
            1,
            32,
            YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            b"default-auth".as_slice(),
        ),
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
        let label = std::str::from_utf8(name)
            .map_err(|_| Error::from(CKR_DATA_INVALID))?
            .to_owned();
        let info = YubiHsmObjectInfo {
            capabilities: yubihsm_capabilities(&[0x00, 0x05, 0x09, 0x0b, 0x32, 0x33]),
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
fn abi_test_yubihsm_wrap_objects(slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
    let wrap_info = |id, object_type, algorithm, length, capabilities, name: &[u8]| {
        let label = std::str::from_utf8(name)
            .map_err(|_| Error::from(CKR_DATA_INVALID))?
            .to_owned();
        Ok::<_, Error>(YubiHsmObjectInfo {
            capabilities: yubihsm_capabilities(capabilities),
            id,
            length,
            domains: 1,
            object_type,
            algorithm,
            sequence: 1,
            origin: 1,
            label,
            delegated_capabilities: [0; 8],
        })
    };
    let mut objects = yubihsm_token_objects(
        slot_id,
        wrap_info(
            8,
            YUBIHSM_WRAP_KEY,
            YUBIHSM_ALGO_AES128_CCM_WRAP,
            16,
            &[0x0c, 0x0d, 0x25, 0x26],
            b"ccm-wrap",
        )?,
        None,
    )?;
    let rsa_public = YubiHsmPublicKey {
        algorithm: YUBIHSM_ALGO_RSA_2048,
        key: vec![0xa5; 256],
    };
    objects.extend(yubihsm_token_objects(
        slot_id,
        wrap_info(
            9,
            YUBIHSM_WRAP_KEY,
            YUBIHSM_ALGO_RSA_2048,
            256,
            &[0x0c, 0x0d],
            b"rsa-wrap",
        )?,
        Some(rsa_public.clone()),
    )?);
    objects.extend(yubihsm_token_objects(
        slot_id,
        wrap_info(
            10,
            YUBIHSM_PUBLIC_WRAP_KEY,
            YUBIHSM_ALGO_RSA_2048,
            256,
            &[0x0c],
            b"public-wrap",
        )?,
        Some(rsa_public),
    )?);
    Ok(objects)
}

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_opaque_objects(
    slot_id: CK_SLOT_ID,
) -> Result<Vec<TokenObject>, Error> {
    let definitions = [
        (
            ABI_YUBIHSM_OPAQUE_DATA_ID,
            YUBIHSM_ALGO_OPAQUE_DATA,
            b"Mozilla Builtin Roots".as_slice(),
            ABI_YUBIHSM_OPAQUE_DATA.len(),
        ),
        (
            ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID,
            YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            b"opaque-cert".as_slice(),
            abi_yubihsm_opaque_certificate()?.len(),
        ),
    ];
    definitions
        .into_iter()
        .map(|(id, algorithm, name, length)| {
            let label = std::str::from_utf8(name)
                .map_err(|_| Error::from(CKR_DATA_INVALID))?
                .to_owned();
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
            let mut object = yubihsm_token_objects(slot_id, info, None)?
                .pop()
                .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))?;
            if algorithm == YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE {
                object.id = 1u16.to_be_bytes().to_vec();
            }
            Ok(object)
        })
        .collect()
}
