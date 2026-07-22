use super::*;

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
pub(super) fn abi_test_piv_slot() -> Result<PivSlot, Error> {
    let private_key = Rsa::generate(2048)?;
    let public_key =
        Rsa::from_public_components(private_key.n().to_owned()?, private_key.e().to_owned()?)?;
    let certificate_key = openssl::pkey::PKey::from_rsa(private_key)?;
    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_text("CN", "PKCS11RS ABI PIV")?;
    let name = name.build();
    let mut certificate = openssl::x509::X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&certificate_key)?;
    certificate.set_not_before(openssl::asn1::Asn1Time::days_from_now(0)?.as_ref())?;
    certificate.set_not_after(openssl::asn1::Asn1Time::days_from_now(1)?.as_ref())?;
    certificate.sign(&certificate_key, openssl::hash::MessageDigest::sha256())?;
    let certificate = certificate.build().to_der()?;
    let certificate_data = piv::encode_certificate_object(&certificate)?;
    let connector: Rc<dyn Connector> = Rc::new(AbiPivConnector);
    Ok(PivSlot {
        connector,
        application_aid: piv::PIV_AID.to_vec(),
        slot_description: Some(String::from("PKCS11RS ABI PIV test slot")),
        authenticated: Rc::new(Cell::new(false)),
        management_authenticated: Rc::new(Cell::new(false)),
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
            origin: piv::ORIGIN_GENERATED,
        }],
        certificates: vec![PivCertificate {
            slot: piv::Slot::Signature,
            algorithm: piv::Algorithm::Rsa2048,
            value: certificate,
            attestation: false,
        }],
        data_objects: vec![PivDataObject {
            object_id: piv::Slot::Signature.certificate_object(),
            value: certificate_data,
        }],
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
pub(super) struct AbiYubiHsmSlot;

#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA_ID: u16 = 5;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID: u16 = 6;
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_DATA: &[u8] = b"ABI opaque data";
#[cfg(feature = "abi-tests")]
const ABI_YUBIHSM_OPAQUE_CERTIFICATE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

#[cfg(feature = "abi-tests")]
pub(super) fn abi_test_yubihsm_object(slot_id: CK_SLOT_ID) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: "abi-yubihsm-rsa".to_owned(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: "ABI YubiHSM RSA key".to_owned(),
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
pub(super) fn abi_test_yubihsm_authentication_objects(
    slot_id: CK_SLOT_ID,
) -> Result<Vec<TokenObject>, Error> {
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
        let label = std::str::from_utf8(name).unwrap().to_owned();
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
fn abi_test_yubihsm_wrap_objects(slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
    let wrap_info = |id, object_type, algorithm, length, capabilities, name: &[u8]| {
        let label = std::str::from_utf8(name).unwrap().to_owned();
        YubiHsmObjectInfo {
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
        }
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
        ),
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
        ),
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
        ),
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
            let label = std::str::from_utf8(name).unwrap().to_owned();
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
        objects.extend(abi_test_yubihsm_wrap_objects(slot_id)?);
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
