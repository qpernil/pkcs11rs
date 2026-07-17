#[cfg(test)]
use crate::pkcs11::*;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TEST_SLOT_LOGGED_IN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static TEST_SLOT_LOGIN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_CONTEXT_LOGIN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_SLOT_LOGOUT_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static TEST_SLOT_FAIL_LOGOUT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
const LEGACY_FUNCTION_COUNT: usize = 68;
const PKCS11_3_0_FUNCTION_COUNT: usize = 24;
const PKCS11_3_2_FUNCTION_COUNT: usize = 12;
const TEST_SLOT_ID: CK_SLOT_ID = 77;
const TEST_SESSION_HANDLE: CK_SESSION_HANDLE = 88;

#[test]
fn debug_level_configuration_has_three_modes() {
    assert_eq!(crate::parse_debug_level(None), 0);
    assert_eq!(crate::parse_debug_level(Some("0")), 0);
    assert_eq!(crate::parse_debug_level(Some("1")), 1);
    assert_eq!(crate::parse_debug_level(Some("2")), 2);
    assert_eq!(crate::parse_debug_level(Some("enabled")), 2);
}

fn finalize_for_test() {
    let _ = crate::C_Finalize(::std::ptr::null_mut());
}

#[test]
fn yubihsm_abi_operations_emit_authenticated_device_commands() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    const SLOT_ID: CK_SLOT_ID = 99;
    let (slot, commands, corrupt_response_mac) = crate::yubihsm::tests::make_yubihsm_test_slot();
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(SLOT_ID, slot);
    }

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let mut public_info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::C_GetSessionInfo(session, &mut public_info),
        CKR_OK as CK_RV
    );
    assert_eq!(public_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);
    assert!(commands.borrow().is_empty());
    let mut mechanism_count = 0;
    assert_eq!(
        crate::C_GetMechanismList(SLOT_ID, ::std::ptr::null_mut(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    let mut mechanisms = vec![0; mechanism_count as usize];
    assert_eq!(
        crate::C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut mechanism_count),
        CKR_OK as CK_RV
    );
    assert!(mechanisms.contains(&(CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE)));
    assert!(mechanisms.contains(&(CKM_AES_CBC as CK_MECHANISM_TYPE)));
    let mut mechanism_info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(
            SLOT_ID,
            CKM_AES_CBC as CK_MECHANISM_TYPE,
            &mut mechanism_info
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        (mechanism_info.ulMinKeySize, mechanism_info.ulMaxKeySize),
        (16, 32)
    );
    assert_ne!(mechanism_info.flags & CKF_HW as CK_FLAGS, 0);
    let mut pin = *b"0001password";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut find_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_FindObjectsInit(session, find_template.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    let mut private_key = 0;
    let mut found = 0;
    assert_eq!(
        crate::C_FindObjects(session, &mut private_key, 1, &mut found),
        CKR_OK as CK_RV
    );
    assert_eq!(found, 1);
    assert_eq!(crate::C_FindObjectsFinal(session), CKR_OK as CK_RV);

    let mut public_class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    find_template[0].pValue = (&mut public_class as *mut CK_OBJECT_CLASS).cast();
    assert_eq!(
        crate::C_FindObjectsInit(session, find_template.as_mut_ptr(), 1),
        CKR_OK as CK_RV
    );
    let mut public_key = 0;
    assert_eq!(
        crate::C_FindObjects(session, &mut public_key, 1, &mut found),
        CKR_OK as CK_RV
    );
    assert_eq!(found, 1);
    assert_eq!(crate::C_FindObjectsFinal(session), CKR_OK as CK_RV);

    let mut rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut plaintext = *b"secret";
    let mut ciphertext = [0u8; 256];
    let mut ciphertext_len = ciphertext.len() as CK_ULONG;
    assert_eq!(
        crate::C_EncryptInit(session, &mut rsa_mechanism, public_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(ciphertext_len, 256);
    let mut decrypted = [0u8; 32];
    let mut decrypted_len = decrypted.len() as CK_ULONG;
    assert_eq!(
        crate::C_DecryptInit(session, &mut rsa_mechanism, private_key),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&decrypted[..decrypted_len as usize], b"plaintext");

    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(session, &mut sign_mechanism, private_key),
        CKR_OK as CK_RV
    );
    let mut message = *b"message";
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);
    assert!(signature.iter().all(|byte| *byte == 0x5a));

    let mut modulus_bits = 2048 as CK_ULONG;
    let mut token = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut public_template = [
        CK_ATTRIBUTE {
            type_: CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
            pValue: (&mut modulus_bits as *mut CK_ULONG).cast(),
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut token as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: (&mut verify as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut sensitive = CK_TRUE as CK_BBOOL;
    let mut private_template = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut token as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sign as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: (&mut sensitive as *mut CK_BBOOL).cast(),
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut generate_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut generated_public = 0;
    let mut generated_private = 0;
    assert_eq!(
        crate::C_GenerateKeyPair(
            session,
            &mut generate_mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as CK_ULONG,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut generated_public,
            &mut generated_private,
        ),
        CKR_OK as CK_RV
    );
    assert_ne!(generated_public, generated_private);
    assert_eq!(
        crate::C_DestroyObject(session, generated_private),
        CKR_OK as CK_RV
    );

    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(crate::C_GetSessionInfo(session, &mut info), CKR_OK as CK_RV);
    let command_codes: Vec<u8> = commands
        .borrow()
        .iter()
        .map(|(command, _)| *command)
        .collect();
    for command in [
        crate::yubihsm::CommandCode::ListObjects as u8,
        crate::yubihsm::CommandCode::GetObjectInfo as u8,
        crate::yubihsm::CommandCode::GetPublicKey as u8,
        crate::yubihsm::CommandCode::SignPkcs1 as u8,
        crate::yubihsm::CommandCode::DecryptPkcs1 as u8,
        crate::yubihsm::CommandCode::GenerateAsymmetricKey as u8,
        crate::yubihsm::CommandCode::DeleteObject as u8,
        crate::yubihsm::CommandCode::GetStorageInfo as u8,
    ] {
        assert!(
            command_codes.contains(&command),
            "missing command {command:#04x}"
        );
    }

    corrupt_response_mac.set(true);
    assert_eq!(
        crate::C_GetSessionInfo(session, &mut info),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert_eq!(crate::C_Logout(session), CKR_USER_NOT_LOGGED_IN as CK_RV);
    finalize_for_test();
}

#[test]
fn yubihsm_ec_discovery_exposes_named_curve_and_der_encoded_point() {
    let mut label = [0u8; 40];
    label[..8].copy_from_slice(b"p521-key");
    let info = crate::yubihsm::ObjectInfo {
        capabilities: crate::yubihsm_capabilities(&[0x07]),
        id: 0x1234,
        length: 66,
        domains: 1,
        object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
        algorithm: crate::YUBIHSM_ALGO_EC_P521,
        sequence: 1,
        origin: 1,
        label,
        delegated_capabilities: [0; 8],
    };
    let public_key = crate::yubihsm::PublicKey {
        algorithm: crate::YUBIHSM_ALGO_EC_P521,
        key: vec![0x5a; 132],
    };
    let objects = crate::yubihsm_token_objects(99, info, Some(public_key)).unwrap();
    let public = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(
        public.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
        Some(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23])
    );
    let point = public
        .attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(&point[..4], &[0x04, 0x81, 0x85, 0x04]);
    assert_eq!(point.len(), 136);
}

#[test]
fn piv_ec_objects_expose_named_curve_and_der_encoded_point() {
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: b"piv-9c-public".to_vec(),
        class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: b"PIV slot 9C".to_vec(),
        id: vec![0x9c],
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: true,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: true,
        key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
        owner_session: None,
        material: crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::EccP256,
            public_key: vec![0x11; 64],
        },
    };
    assert_eq!(
        object.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
        Some(vec![
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        ])
    );
    let point = object
        .attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE)
        .unwrap();
    assert_eq!(point[0], 0x04);
    assert_eq!(point[1], 65);
    assert_eq!(point[2], 0x04);
    assert_eq!(point.len(), 67);
}

#[test]
fn piv_edwards_and_montgomery_parameters_match_ykcs11() {
    assert_eq!(
        crate::piv_ec_parameters(crate::piv::Algorithm::Ed25519),
        Some(
            [0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,]
                .as_slice()
        )
    );
    assert_eq!(
        crate::piv_ec_parameters(crate::piv::Algorithm::X25519),
        Some([0x13, 0x0b, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39].as_slice())
    );
    assert_eq!(
        crate::piv_effective_pin_policy(crate::piv::Slot::CardAuthentication, 0),
        1
    );
    for slot in crate::piv::Slot::all() {
        assert!(!crate::piv_policy_requires_login(*slot, 1));
        assert!(crate::piv_policy_requires_login(*slot, 2));
    }
}

#[test]
fn piv_ecdsa_signatures_are_converted_to_fixed_width_values() {
    let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let signature = crate::piv_ecdsa_signature(&der, 32).unwrap();
    assert_eq!(signature.len(), 64);
    assert_eq!(&signature[31..32], &[1]);
    assert_eq!(&signature[63..64], &[2]);
}

#[test]
fn yubihsm_mechanisms_follow_enabled_device_algorithms() {
    let mechanisms = crate::yubihsm_mechanisms(&[
        crate::YUBIHSM_ALGO_RSA_2048,
        crate::YUBIHSM_ALGO_AES128,
        crate::YUBIHSM_ALGO_HMAC_SHA1,
        crate::YUBIHSM_ALGO_HMAC_SHA512,
        53,
    ]);
    let mechanism = |type_| {
        mechanisms
            .iter()
            .find(|mechanism| mechanism.type_ == type_)
            .copied()
    };
    let rsa = mechanism(CKM_RSA_PKCS as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((rsa.min_key_size, rsa.max_key_size), (2048, 2048));
    assert_ne!(rsa.flags & CKF_ENCRYPT as CK_FLAGS, 0);
    assert_eq!(rsa.flags & (CKF_SIGN | CKF_DECRYPT) as CK_FLAGS, 0);
    let aes = mechanism(CKM_AES_ECB as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((aes.min_key_size, aes.max_key_size), (16, 16));
    let hmac = mechanism(CKM_SHA_1_HMAC as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((hmac.min_key_size, hmac.max_key_size), (1, 64));
    let hmac = mechanism(CKM_SHA512_HMAC as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((hmac.min_key_size, hmac.max_key_size), (1, 128));
    let generated = mechanism(CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE).unwrap();
    assert_eq!((generated.min_key_size, generated.max_key_size), (20, 64));
    assert!(mechanism(CKM_AES_CBC as CK_MECHANISM_TYPE).is_none());
    assert!(mechanism(CKM_ECDSA as CK_MECHANISM_TYPE).is_none());
}

#[derive(Debug)]
struct TestSlot {
    present: std::cell::Cell<bool>,
    remove_on_refresh: bool,
    login_active: Option<std::rc::Rc<std::cell::Cell<bool>>>,
}

#[derive(Debug)]
struct TestSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

#[derive(Debug)]
struct PivSigningTestSession {
    slot_id: CK_SLOT_ID,
    captured: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
}

#[derive(Debug)]
struct FailingConnector;

impl crate::Connector for FailingConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Failing connector"
    }

    fn serial(&self) -> &str {
        "FAIL0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        false
    }

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        Err(rusb::Error::NoDevice.into())
    }
}

#[derive(Debug)]
struct SelectableConnector {
    present: std::cell::Cell<bool>,
    select_ok: std::cell::Cell<bool>,
    serial: &'static str,
}

impl crate::Connector for SelectableConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Selectable connector"
    }

    fn serial(&self) -> &str {
        self.serial
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        Some((5, 7, 0))
    }

    fn is_present(&self) -> bool {
        self.present.get()
    }

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        if !self.present.get() {
            return Err(rusb::Error::NoDevice.into());
        }
        if send_buffer.get(1) == Some(&0xa4) && !self.select_ok.get() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..2].copy_from_slice(&[0x90, 0x00]);
        Ok(&receive_buffer[..2])
    }
}

#[derive(Debug)]
struct CountingConnector {
    transmissions: std::rc::Rc<std::cell::Cell<usize>>,
}

impl crate::Connector for CountingConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Counting connector"
    }

    fn serial(&self) -> &str {
        "COUNT0001"
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

    fn buffer_size(&self) -> usize {
        16
    }

    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> Result<&'a [u8], crate::error::Error> {
        self.transmissions.set(self.transmissions.get() + 1);
        Err(CKR_DEVICE_ERROR.into())
    }
}

unsafe extern "C" fn test_create_mutex(_mutex: CK_VOID_PTR_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_destroy_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_lock_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

unsafe extern "C" fn test_unlock_mutex(_mutex: CK_VOID_PTR) -> CK_RV {
    CKR_OK as CK_RV
}

impl crate::Session for TestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }
}

impl crate::Session for PivSigningTestSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        CKF_SERIAL_SESSION as CK_FLAGS
    }

    fn get_session_info(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn piv_sign(
        &self,
        slot: crate::piv::Slot,
        algorithm: crate::piv::Algorithm,
        input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, crate::error::Error> {
        assert_eq!(slot, crate::piv::Slot::Signature);
        assert_eq!(algorithm, crate::piv::Algorithm::Rsa1024);
        *self.captured.borrow_mut() = input.to_vec();
        Ok(vec![0x5a; 128])
    }
}

impl crate::Slot for TestSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn name(&self) -> String {
        String::from("Test Slot")
    }

    fn manufacturer(&self) -> &str {
        "Test"
    }

    fn product(&self) -> &str {
        "Test Token"
    }

    fn serial(&self) -> &str {
        "TEST0001"
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        self.present.get()
    }

    fn refresh(&self) -> Result<(), crate::error::Error> {
        if self.remove_on_refresh {
            self.present.set(false);
        }
        Ok(())
    }

    fn login_is_active(&self) -> bool {
        self.login_active.as_ref().is_none_or(|active| active.get())
    }

    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn crate::Session> {
        Box::new(TestSession {
            slot_id: slotID,
            flags,
        })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), crate::error::Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        TEST_SLOT_LOGGED_IN.store(true, std::sync::atomic::Ordering::SeqCst);
        TEST_SLOT_LOGIN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn login_context_specific(
        &mut self,
        pin: &[u8],
        _extended: bool,
    ) -> Result<(), crate::error::Error> {
        if pin != b"1234" {
            return Err(CKR_PIN_INCORRECT.into());
        }
        TEST_CONTEXT_LOGIN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn logout(&mut self) -> Result<(), crate::error::Error> {
        TEST_SLOT_LOGOUT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if TEST_SLOT_FAIL_LOGOUT.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        TEST_SLOT_LOGGED_IN.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), crate::error::Error> {
        self.format_slot_info(info);
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), crate::error::Error> {
        self.format_token_info(info);
        Ok(())
    }
}

fn test_slot(present: bool) -> TestSlot {
    TestSlot {
        present: std::cell::Cell::new(present),
        remove_on_refresh: false,
        login_active: None,
    }
}

fn install_test_slot(slot_id: CK_SLOT_ID) {
    let mut context = crate::lock_context().unwrap();
    context
        .as_mut()
        .unwrap()
        .slots
        .insert(slot_id, Box::new(test_slot(true)));
}

fn install_test_session(slot_id: CK_SLOT_ID, session_handle: CK_SESSION_HANDLE) {
    install_test_session_with_state(
        slot_id,
        session_handle,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
        true,
    );
}

fn install_public_test_session(slot_id: CK_SLOT_ID, session_handle: CK_SESSION_HANDLE) {
    install_test_session_with_state(
        slot_id,
        session_handle,
        CKF_SERIAL_SESSION as CK_FLAGS,
        false,
    );
}

fn install_test_session_with_state(
    slot_id: CK_SLOT_ID,
    session_handle: CK_SESSION_HANDLE,
    flags: CK_FLAGS,
    logged_in: bool,
) {
    let mut context = crate::lock_context().unwrap();
    let context = context.as_mut().unwrap();
    context.slots.insert(slot_id, Box::new(test_slot(true)));
    context
        .sessions
        .insert(session_handle, Box::new(TestSession { slot_id, flags }));
    if logged_in {
        context.logged_in_slots.insert(slot_id);
    }
}

fn assert_function_slots_present<T>(function_list: *const T, function_count: usize) {
    assert!(!function_list.is_null());
    let first_function_offset = ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize);
    let pointer_size = ::std::mem::size_of::<*const ::std::os::raw::c_void>();

    for index in 0..function_count {
        let slot = unsafe {
            (function_list as *const u8).add(first_function_offset + index * pointer_size)
                as *const *const ::std::os::raw::c_void
        };
        assert!(
            !unsafe { *slot }.is_null(),
            "function slot {index} should be stubbed"
        );
    }
}

fn assert_unsupported_session_stubs_return(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let mut data = [0u8; 8];
    let mut data_len = data.len() as CK_ULONG;
    let mut object = 0;
    let mut second_object = 0;
    let mut flags = 0;
    let mut async_data = CK_ASYNC_DATA {
        ulVersion: 0,
        pValue: ::std::ptr::null_mut(),
        ulValue: 0,
        hObject: 0,
        hAdditionalObject: 0,
    };

    macro_rules! assert_stub {
        ($name:literal, $call:expr) => {
            assert_eq!($call, expected, "{} should behave as a stub", $name);
        };
    }

    assert_stub!(
        "C_InitPIN",
        crate::C_InitPIN(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_SetPIN",
        crate::C_SetPIN(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_GetOperationState",
        crate::C_GetOperationState(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SetOperationState",
        crate::C_SetOperationState(session, data.as_mut_ptr(), data.len() as CK_ULONG, 0, 0)
    );
    assert_stub!(
        "C_CreateObject",
        crate::C_CreateObject(session, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!(
        "C_CopyObject",
        crate::C_CopyObject(session, 0, ::std::ptr::null_mut(), 0, &mut object)
    );
    assert_stub!("C_DestroyObject", crate::C_DestroyObject(session, 0));
    assert_stub!(
        "C_GetObjectSize",
        crate::C_GetObjectSize(session, 0, &mut data_len)
    );
    assert_stub!(
        "C_GetAttributeValue",
        crate::C_GetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SetAttributeValue",
        crate::C_SetAttributeValue(session, 0, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptInit",
        crate::C_EncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Encrypt",
        crate::C_Encrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptUpdate",
        crate::C_EncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptFinal",
        crate::C_EncryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DecryptInit",
        crate::C_DecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Decrypt",
        crate::C_Decrypt(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptUpdate",
        crate::C_DecryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptFinal",
        crate::C_DecryptFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_DigestInit",
        crate::C_DigestInit(session, ::std::ptr::null_mut())
    );
    assert_stub!(
        "C_Digest",
        crate::C_Digest(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestUpdate",
        crate::C_DigestUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!("C_DigestKey", crate::C_DigestKey(session, 0));
    assert_stub!(
        "C_DigestFinal",
        crate::C_DigestFinal(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_SignInit",
        crate::C_SignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Sign",
        crate::C_Sign(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignRecoverInit",
        crate::C_SignRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignRecover",
        crate::C_SignRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_VerifyInit",
        crate::C_VerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_Verify",
        crate::C_Verify(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyRecoverInit",
        crate::C_VerifyRecoverInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyRecover",
        crate::C_VerifyRecover(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DigestEncryptUpdate",
        crate::C_DigestEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptDigestUpdate",
        crate::C_DecryptDigestUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignEncryptUpdate",
        crate::C_SignEncryptUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptVerifyUpdate",
        crate::C_DecryptVerifyUpdate(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_GenerateKeyPair",
        crate::C_GenerateKeyPair(
            session,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object,
            &mut second_object
        )
    );
    assert_stub!(
        "C_WrapKey",
        crate::C_WrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKey",
        crate::C_UnwrapKey(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            &mut object
        )
    );
    assert_eq!(
        crate::C_DeriveKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            &mut object
        ),
        CKR_ARGUMENTS_BAD as CK_RV,
        "C_DeriveKey validates its mechanism arguments"
    );
    assert_stub!("C_GetFunctionStatus", crate::C_GetFunctionStatus(session));
    assert_stub!("C_CancelFunction", crate::C_CancelFunction(session));
    assert_stub!(
        "C_LoginUser",
        crate::C_LoginUser(
            session,
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_SessionCancel", crate::C_SessionCancel(session, 0));
    assert_stub!(
        "C_MessageEncryptInit",
        crate::C_MessageEncryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_EncryptMessage",
        crate::C_EncryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_EncryptMessageBegin",
        crate::C_EncryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_EncryptMessageNext",
        crate::C_EncryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageEncryptFinal",
        crate::C_MessageEncryptFinal(session)
    );
    assert_stub!(
        "C_MessageDecryptInit",
        crate::C_MessageDecryptInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_DecryptMessage",
        crate::C_DecryptMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_DecryptMessageBegin",
        crate::C_DecryptMessageBegin(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_DecryptMessageNext",
        crate::C_DecryptMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
            0
        )
    );
    assert_stub!(
        "C_MessageDecryptFinal",
        crate::C_MessageDecryptFinal(session)
    );
    assert_stub!(
        "C_MessageSignInit",
        crate::C_MessageSignInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessage",
        crate::C_SignMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_SignMessageBegin",
        crate::C_SignMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_SignMessageNext",
        crate::C_SignMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!("C_MessageSignFinal", crate::C_MessageSignFinal(session));
    assert_stub!(
        "C_MessageVerifyInit",
        crate::C_MessageVerifyInit(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessage",
        crate::C_VerifyMessage(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifyMessageBegin",
        crate::C_VerifyMessageBegin(session, ::std::ptr::null_mut(), 0)
    );
    assert_stub!(
        "C_VerifyMessageNext",
        crate::C_VerifyMessageNext(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!("C_MessageVerifyFinal", crate::C_MessageVerifyFinal(session));
    assert_stub!(
        "C_EncapsulateKey",
        crate::C_EncapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            &mut data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_DecapsulateKey",
        crate::C_DecapsulateKey(
            session,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data_len,
            &mut object
        )
    );
    assert_stub!(
        "C_VerifySignatureInit",
        crate::C_VerifySignatureInit(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_VerifySignature",
        crate::C_VerifySignature(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureUpdate",
        crate::C_VerifySignatureUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG)
    );
    assert_stub!(
        "C_VerifySignatureFinal",
        crate::C_VerifySignatureFinal(session)
    );
    assert_stub!(
        "C_GetSessionValidationFlags",
        crate::C_GetSessionValidationFlags(session, 0, &mut flags)
    );
    assert_stub!(
        "C_AsyncComplete",
        crate::C_AsyncComplete(session, data.as_mut_ptr(), &mut async_data)
    );
    assert_stub!(
        "C_AsyncGetID",
        crate::C_AsyncGetID(session, data.as_mut_ptr(), &mut data_len)
    );
    assert_stub!(
        "C_AsyncJoin",
        crate::C_AsyncJoin(
            session,
            data.as_mut_ptr(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG
        )
    );
    assert_stub!(
        "C_WrapKeyAuthenticated",
        crate::C_WrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len
        )
    );
    assert_stub!(
        "C_UnwrapKeyAuthenticated",
        crate::C_UnwrapKeyAuthenticated(
            session,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            &mut object
        )
    );
}

#[test]
pub fn bindgen_test_layout_CK_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_INFO>(),
        88usize,
        concat!("Size of: ", stringify!(CK_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, cryptokiVersion),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(cryptokiVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, manufacturerID),
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, flags),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryDescription),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(libraryDescription)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_INFO, libraryVersion),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_INFO),
            "::",
            stringify!(libraryVersion)
        )
    );
}

#[test]
pub fn all_legacy_function_list_entries_are_stubbed() {
    let mut function_list: CK_FUNCTION_LIST_PTR = ::std::ptr::null_mut();

    assert_eq!(
        crate::C_GetFunctionList(&mut function_list),
        CKR_OK as CK_RV
    );
    assert_eq!(unsafe { (*function_list).version.major }, 2);
    assert_eq!(unsafe { (*function_list).version.minor }, 40);
    assert_function_slots_present(function_list, LEGACY_FUNCTION_COUNT);
}

#[test]
pub fn all_supported_interfaces_are_discoverable() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut count = 0;
    assert_eq!(
        crate::C_GetInterfaceList(::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 4);

    let empty_interface = CK_INTERFACE {
        pInterfaceName: ::std::ptr::null_mut(),
        pFunctionList: ::std::ptr::null_mut(),
        flags: 0,
    };
    let mut interfaces = [empty_interface; 4];
    assert_eq!(
        crate::C_GetInterfaceList(interfaces.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 4);
    for interface in &interfaces {
        assert!(!interface.pInterfaceName.is_null());
        assert!(!interface.pFunctionList.is_null());
    }
    let versions: Vec<(u8, u8)> = interfaces
        .iter()
        .map(|interface| {
            let version = unsafe { &*(interface.pFunctionList as *const CK_VERSION) };
            (version.major, version.minor)
        })
        .collect();
    assert_eq!(versions, [(2, 40), (3, 0), (3, 1), (3, 2)]);

    let function_list = interfaces[3].pFunctionList as CK_FUNCTION_LIST_3_2_PTR;
    assert_eq!(unsafe { (*function_list).version.major }, 3);
    assert_eq!(unsafe { (*function_list).version.minor }, 2);
    assert!(unsafe { (*function_list).C_GetInterface.is_some() });
    assert!(unsafe { (*function_list).C_EncapsulateKey.is_some() });
    assert_function_slots_present(
        function_list,
        LEGACY_FUNCTION_COUNT + PKCS11_3_0_FUNCTION_COUNT + PKCS11_3_2_FUNCTION_COUNT,
    );
}

#[test]
pub fn get_info_reports_cryptoki_3_2() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32usize],
        flags: 0,
        libraryDescription: [0; 32usize],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    assert_eq!(crate::C_GetInfo(&mut info), CKR_OK as CK_RV);
    assert_eq!(info.cryptokiVersion.major, 3);
    assert_eq!(info.cryptokiVersion.minor, 2);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn initialize_and_finalize_reject_reserved_args() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut init_args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: 1 as CK_VOID_PTR,
    };

    assert_eq!(
        crate::C_Initialize(&mut init_args as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Finalize(1 as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}

#[test]
pub fn finalize_clears_context_after_device_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_Finalize(::std::ptr::null_mut()),
        CKR_FUNCTION_FAILED as CK_RV
    );
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn initialize_validates_mutex_callback_configuration() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut partial_callbacks = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(test_create_mutex),
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut partial_callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut os_locking = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK as CK_FLAGS,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut os_locking as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut callbacks = CK_C_INITIALIZE_ARGS {
        CreateMutex: Some(test_create_mutex),
        DestroyMutex: Some(test_destroy_mutex),
        LockMutex: Some(test_lock_mutex),
        UnlockMutex: Some(test_unlock_mutex),
        flags: 0,
        pReserved: ::std::ptr::null_mut(),
    };
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_CANT_LOCK as CK_RV
    );

    callbacks.flags = CKF_OS_LOCKING_OK as CK_FLAGS;
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    callbacks.flags = 1 << 31;
    assert_eq!(
        crate::C_Initialize(&mut callbacks as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}

#[test]
pub fn short_usb_writes_are_device_errors() {
    assert!(crate::ensure_complete_write(64, 64).is_ok());
    let rv: CK_RV = crate::ensure_complete_write(63, 64).unwrap_err().into();
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
}

#[test]
pub fn usb_zlp_is_only_required_on_nonzero_packet_boundaries() {
    assert!(crate::needs_zero_length_packet(64, 64));
    assert!(crate::needs_zero_length_packet(128, 64));
    assert!(!crate::needs_zero_length_packet(63, 64));
    assert!(!crate::needs_zero_length_packet(0, 0));
}

#[test]
pub fn yubikey_login_preserves_connector_errors() {
    let base: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let mut slot = crate::GlobalPlatformSlot {
        connector: std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        )),
        application_aid,
        authenticated: std::cell::Cell::new(false),
    };

    let rv: CK_RV = crate::Slot::login(&mut slot, b"1234").unwrap_err().into();
    assert_eq!(rv, CKR_DEVICE_ERROR as CK_RV);
}

#[test]
fn applet_configuration_rejects_removed_transport_aliases() {
    assert_eq!(
        crate::parse_ccid_application("globalplatform").unwrap(),
        crate::CcidApplication::GlobalPlatform
    );
    assert!(crate::parse_ccid_application("scp03").is_err());
}

#[test]
fn ccid_application_discovery_defaults_to_supported_applets() {
    assert_eq!(
        crate::default_ccid_applications(),
        vec![
            crate::CcidApplication::Piv,
            crate::CcidApplication::OpenPgp,
            crate::CcidApplication::HsmAuth,
            crate::CcidApplication::GlobalPlatform,
        ]
    );
}

#[test]
fn pcsc_applet_presence_requires_a_successful_aid_select() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
    );

    assert_eq!(
        crate::Connector::name(&connector),
        crate::Connector::name(base.as_ref())
    );
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    base.select_ok.set(false);
    assert!(crate::Connector::refresh(&connector).is_err());
    assert!(!crate::Connector::is_present(&connector));
    assert!(connector
        .discovery_error
        .borrow()
        .as_deref()
        .is_some_and(|reason| reason.contains("Generic")));
    base.select_ok.set(true);
    assert!(crate::Connector::refresh(&connector).is_ok());
    assert!(crate::Connector::is_present(&connector));
    assert!(connector.discovery_error.borrow().is_none());
}

#[test]
fn pcsc_applet_connector_reuses_selected_aid() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector = crate::PcscAppletConnector::new(
        base.clone(),
        &aid,
        None,
        std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
    );
    let mut receive = [0; 16];

    assert!(crate::Connector::transmit(
        &connector,
        &[0x00, 0x00],
        &mut receive,
        std::time::Duration::from_secs(1),
    )
    .is_ok());
    base.select_ok.set(false);
    assert!(crate::Connector::transmit(
        &connector,
        &[0x00, 0x00],
        &mut receive,
        std::time::Duration::from_secs(1),
    )
    .is_ok());
}

#[test]
fn openpgp_slot_info_reports_application_version_and_serial() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let mut slot = crate::OpenPgpSlot::new(connector, aid);
    slot.version = (3, 4);
    slot.serial = String::from("12345678");

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.hardwareVersion.major,
            slot_info.hardwareVersion.minor
        ),
        (1, 0)
    );
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (3, 4)
    );
    assert_eq!(crate::Slot::serial(&slot), "12345678");
}

#[test]
fn openpgp_slot_uses_shared_serial_before_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::OpenPgpSlot::new(connector, aid);

    assert_eq!(crate::Slot::serial(&slot), "12345678");
}

#[test]
fn openpgp_slot_uses_shared_firmware_before_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::OpenPgpSlot::new(connector, aid);

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (5, 7)
    );
}

#[test]
fn openpgp_metadata_failure_does_not_hide_selected_applet() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = vec![0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let mut slot = crate::OpenPgpSlot::new(connector, aid);

    assert!(crate::Slot::is_present(&slot));
    assert!(crate::Slot::init_slot(&mut slot).is_err());
    assert!(crate::Slot::is_present(&slot));
}

#[test]
fn openpgp_pw1_policy_maps_sign_once_to_context_specific_login() {
    assert!(crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Signature,
        crate::openpgp::PW1_ONE_SIGNATURE,
    ));
    assert!(!crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Signature,
        crate::openpgp::PW1_MULTIPLE_SIGNATURES,
    ));
    assert!(!crate::openpgp_signature_requires_context_specific_login(
        crate::openpgp::KeyRef::Authentication,
        crate::openpgp::PW1_ONE_SIGNATURE,
    ));

    let mut object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: b"openpgp-private".to_vec(),
        class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: b"OpenPGP signature key".to_vec(),
        id: vec![1],
        token: true,
        private: true,
        encrypt: false,
        decrypt: false,
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
        material: crate::KeyMaterial::OpenPgpPrivate {
            key_ref: crate::openpgp::KeyRef::Signature,
            algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
            modulus: vec![0; 256],
            public_exponent: vec![1, 0, 1],
            public_key: vec![0; 256],
            pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
        },
    };
    assert!(object
        .attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE)
        .is_some());
    object.material = crate::KeyMaterial::OpenPgpPrivate {
        key_ref: crate::openpgp::KeyRef::Authentication,
        algorithm: crate::OpenPgpAlgorithm::Rsa { bits: 2048 },
        modulus: vec![0; 256],
        public_exponent: vec![1, 0, 1],
        public_key: vec![0; 256],
        pin_policy: crate::openpgp::PW1_ONE_SIGNATURE,
    };
    assert!(object
        .attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE)
        .is_none());
}

#[test]
fn openpgp_always_authenticate_expires_after_one_signature() {
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "OPENPGP001",
    });
    let authenticated = std::rc::Rc::new(std::cell::Cell::new(true));
    let session = crate::OpenPgpSession {
        slotID: TEST_SLOT_ID,
        flags: CKF_SERIAL_SESSION as CK_FLAGS,
        connector,
        authenticated: authenticated.clone(),
    };

    let _ = crate::Session::openpgp_sign(
        &session,
        crate::openpgp::KeyRef::Signature,
        &[],
        crate::openpgp::PW1_ONE_SIGNATURE,
    );
    assert!(!authenticated.get());
}

#[test]
fn piv_slot_uses_shared_metadata_before_piv_metadata_is_loaded() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "12345678",
    });
    let aid = crate::piv::PIV_AID.to_vec();
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::PivSlot::new(connector, aid);

    assert_eq!(crate::Slot::serial(&slot), "12345678");
    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert!(crate::Slot::get_slot_info(&slot, &mut slot_info).is_ok());
    assert_eq!(
        (
            slot_info.firmwareVersion.major,
            slot_info.firmwareVersion.minor
        ),
        (5, 70)
    );
}

#[test]
fn globalplatform_token_model_identifies_the_applet() {
    let base = std::rc::Rc::new(SelectableConnector {
        present: std::cell::Cell::new(true),
        select_ok: std::cell::Cell::new(true),
        serial: "SELECT0001",
    });
    let aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &aid,
            None,
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    let slot = crate::GlobalPlatformSlot {
        connector,
        application_aid: aid,
        authenticated: std::cell::Cell::new(false),
    };

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    assert!(crate::Slot::get_token_info(&slot, &mut token_info).is_ok());
    assert_eq!(&token_info.model[..9], b"Issuer SD");
    assert_eq!(&token_info.label[..21], b"Issuer SD #SELECT0001");
}

#[test]
fn yubikey_application_list_is_an_allowlist() {
    assert_eq!(
        crate::parse_ccid_application_list("openpgp, piv, openpgp").unwrap(),
        vec![crate::CcidApplication::OpenPgp, crate::CcidApplication::Piv,]
    );
    assert!(crate::parse_ccid_application_list(", ,").is_err());
}

#[test]
pub fn missing_scp_session_invalidates_pkcs11_login_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let base: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(FailingConnector);
    let application_aid = vec![0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
    let connector: std::rc::Rc<dyn crate::Connector> =
        std::rc::Rc::new(crate::PcscAppletConnector::new(
            base,
            &application_aid,
            Some(crate::SecureChannelProtocol::Scp03),
            std::rc::Rc::new(std::cell::RefCell::new(crate::SecureChannelState::default())),
        ));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.slots.insert(
            TEST_SLOT_ID,
            Box::new(crate::GlobalPlatformSlot {
                connector: connector.clone(),
                application_aid,
                authenticated: std::cell::Cell::new(false),
            }),
        );
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(crate::PcscAppletSession {
                slotID: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
                connector,
            }),
        );
        context.logged_in_slots.insert(TEST_SLOT_ID);
    }

    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_DEVICE_ERROR as CK_RV
    );
    let context = crate::lock_context().unwrap();
    assert!(!context
        .as_ref()
        .unwrap()
        .logged_in_slots
        .contains(&TEST_SLOT_ID));
    drop(context);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn authentication_loss_cancels_active_private_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let login_active = std::rc::Rc::new(std::cell::Cell::new(true));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.slots.insert(
            TEST_SLOT_ID,
            Box::new(TestSlot {
                present: std::cell::Cell::new(true),
                remove_on_refresh: false,
                login_active: Some(login_active.clone()),
            }),
        );
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(TestSession {
                slot_id: TEST_SLOT_ID,
                flags: CKF_SERIAL_SESSION as CK_FLAGS,
            }),
        );
        context.logged_in_slots.insert(TEST_SLOT_ID);
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    login_active.set(false);
    let mut data = *b"test";
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn login_controls_private_object_visibility_and_signing() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_public_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE + 1,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut private_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_SO as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_TYPE_INVALID as CK_RV
    );
    let mut bad_pin = *b"9999";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            bad_pin.as_mut_ptr(),
            bad_pin.len() as CK_ULONG
        ),
        CKR_PIN_INCORRECT as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!((count, objects[0]), (1, 2));
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Logout(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetSessionInfo(TEST_SESSION_HANDLE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(
        crate::C_Logout(TEST_SESSION_HANDLE),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn context_specific_login_authenticates_an_always_authenticate_operation() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    {
        let mut context = crate::lock_context().unwrap();
        let object = context.as_mut().unwrap().objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            modulus: vec![0; 128],
            public_exponent: vec![1, 0, 1],
            pin_policy: 3,
            touch_policy: 1,
        };
        object.private = true;
        object.sign = true;
        object.decrypt = false;
        object.sensitive = true;
        object.extractable = false;
        assert_eq!(
            object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_TRUE as CK_BBOOL])
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        TEST_CONTEXT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn context_specific_login_does_not_require_always_authenticate_attribute() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_CONTEXT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    {
        let mut context = crate::lock_context().unwrap();
        let object = context.as_mut().unwrap().objects.get_mut(&2).unwrap();
        object.material = crate::KeyMaterial::PivPrivate {
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::Rsa1024,
            modulus: vec![0; 128],
            public_exponent: vec![1, 0, 1],
            pin_policy: 2,
            touch_policy: 1,
        };
        object.private = true;
        object.sign = true;
        object.decrypt = false;
        object.sensitive = true;
        object.extractable = false;
        assert_eq!(
            object.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_FALSE as CK_BBOOL])
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            TEST_SESSION_HANDLE,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        TEST_CONTEXT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn login_is_shared_and_logout_invalidates_private_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut ro_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut rw_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut ro_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut rw_session
        ),
        CKR_OK as CK_RV
    );

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            rw_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_USER_ALREADY_LOGGED_IN as CK_RV
    );

    let mut ro_info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    let mut rw_info = ro_info;
    assert_eq!(
        crate::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(rw_session, &mut rw_info),
        CKR_OK as CK_RV
    );
    assert_eq!(ro_info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);
    assert_eq!(rw_info.state, CKS_RW_USER_FUNCTIONS as CK_STATE);

    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(ro_session, &mut sign_mechanism, 2),
        CKR_OK as CK_RV
    );

    let mut generate_mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut private_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut private_session_key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            rw_session,
            &mut generate_mechanism,
            private_template.as_mut_ptr(),
            private_template.len() as CK_ULONG,
            &mut private_session_key
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Logout(rw_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetSessionInfo(ro_session, &mut ro_info),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetSessionInfo(rw_session, &mut rw_info),
        CKR_OK as CK_RV
    );
    assert_eq!(ro_info.state, CKS_RO_PUBLIC_SESSION as CK_STATE);
    assert_eq!(rw_info.state, CKS_RW_PUBLIC_SESSION as CK_STATE);

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            ro_session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::C_Login(
            ro_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut object_size = 0;
    assert_eq!(
        crate::C_GetObjectSize(ro_session, 2, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(ro_session, private_session_key, &mut object_size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut find_template = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut new_private_handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            ro_session,
            find_template.as_mut_ptr(),
            find_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(ro_session, &mut new_private_handle, 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_ne!(new_private_handle, 2);
    assert_ne!(new_private_handle, private_session_key);
    assert_eq!(crate::C_FindObjectsFinal(ro_session), CKR_OK as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn token_authentication_survives_initiating_session_and_logs_out_on_last_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_LOGGED_IN.store(false, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGIN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    TEST_SLOT_LOGOUT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);
    let mut first_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut second_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    for session in [&mut first_session, &mut second_session] {
        assert_eq!(
            crate::C_OpenSession(
                TEST_SLOT_ID,
                CKF_SERIAL_SESSION as CK_FLAGS,
                ::std::ptr::null_mut(),
                None,
                session
            ),
            CKR_OK as CK_RV
        );
    }

    let mut pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            first_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert!(TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGIN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(crate::C_CloseSession(first_session), CKR_OK as CK_RV);
    assert!(TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let mut info = unsafe { ::std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        crate::C_GetSessionInfo(second_session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS as CK_STATE);

    assert_eq!(crate::C_CloseSession(second_session), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut close_all_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut close_all_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            close_all_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseAllSessions(TEST_SLOT_ID), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    let mut final_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut final_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Login(
            final_session,
            CKU_USER as CK_USER_TYPE,
            pin.as_mut_ptr(),
            pin.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert!(!TEST_SLOT_LOGGED_IN.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        TEST_SLOT_LOGOUT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        3
    );
}

#[test]
pub fn token_info_reports_current_session_counts() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut read_only_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    let mut read_write_session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_only_session
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut read_write_session
        ),
        CKR_OK as CK_RV
    );

    let mut info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE as CK_ULONG);
    assert_eq!(info.ulSessionCount, 2);
    assert_eq!(
        info.ulMaxRwSessionCount,
        CK_EFFECTIVELY_INFINITE as CK_ULONG
    );
    assert_eq!(info.ulRwSessionCount, 1);
    assert_eq!(
        info.ulTotalPublicMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulFreePublicMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulTotalPrivateMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );
    assert_eq!(
        info.ulFreePrivateMemory,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    assert_eq!(crate::C_CloseSession(read_write_session), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulSessionCount, 1);
    assert_eq!(info.ulRwSessionCount, 0);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn session_stub_entry_points_validate_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    assert_unsupported_session_stubs_return(999, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_unsupported_session_stubs_return(999, CKR_SESSION_HANDLE_INVALID as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn non_session_stub_entry_points_report_unsupported() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut slot = 0;

    assert_eq!(
        crate::C_InitToken(0, ::std::ptr::null_mut(), 0, ::std::ptr::null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(
        crate::C_WaitForSlotEvent(0, &mut slot, ::std::ptr::null_mut()),
        CKR_FUNCTION_NOT_SUPPORTED as CK_RV
    );
}

#[test]
pub fn slot_and_mechanism_calls_validate_slot_ids() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    let mut count = 0;
    let mut mechanism_info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };

    assert_eq!(crate::C_CloseAllSessions(999), CKR_SLOT_ID_INVALID as CK_RV);
    assert_eq!(
        crate::C_GetMechanismList(999, ::std::ptr::null_mut(), &mut count),
        CKR_SLOT_ID_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(999, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut mechanism_info),
        CKR_SLOT_ID_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn token_and_mechanism_queries_require_a_present_token() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(false)));
    }

    let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    let mut count = 0;
    let mut mechanism_info = unsafe { ::std::mem::zeroed::<CK_MECHANISM_INFO>() };
    assert_eq!(
        crate::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(
        crate::C_GetTokenInfo(TEST_SLOT_ID, &mut token_info),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), &mut count),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            &mut mechanism_info
        ),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn open_session_validates_session_flags() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;

    assert_eq!(
        crate::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);
    assert_eq!(
        crate::C_OpenSession(TEST_SLOT_ID, 0, ::std::ptr::null_mut(), None, &mut session),
        CKR_SESSION_PARALLEL_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            (CKF_SERIAL_SESSION | CKF_ASYNC_SESSION) as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_SESSION_ASYNC_NOT_SUPPORTED as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    for flags in [
        CKF_SERIAL_SESSION as CK_FLAGS,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
    ] {
        assert_eq!(
            crate::C_OpenSession(
                TEST_SLOT_ID,
                flags,
                ::std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_OK as CK_RV
        );
        assert_ne!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);
        assert_eq!(crate::C_CloseSession(session), CKR_OK as CK_RV);
        session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn open_session_refreshes_token_presence() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().slots.insert(
            TEST_SLOT_ID,
            Box::new(TestSlot {
                present: std::cell::Cell::new(true),
                remove_on_refresh: true,
                login_active: None,
            }),
        );
    }

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_TOKEN_NOT_PRESENT as CK_RV
    );
    assert_eq!(session, CK_INVALID_HANDLE as CK_SESSION_HANDLE);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn close_cleans_local_state_after_logout_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_DEVICE_ERROR as CK_RV
    );
    assert_eq!(
        crate::C_CloseSession(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    {
        let context = crate::lock_context().unwrap();
        let context = context.as_ref().unwrap();
        assert!(!context.logged_in_slots.contains(&TEST_SLOT_ID));
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
    }

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);
    TEST_SLOT_FAIL_LOGOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        crate::C_CloseAllSessions(TEST_SLOT_ID),
        CKR_DEVICE_ERROR as CK_RV
    );
    {
        let context = crate::lock_context().unwrap();
        let context = context.as_ref().unwrap();
        assert!(!context.logged_in_slots.contains(&TEST_SLOT_ID));
        assert!(context
            .sessions
            .values()
            .all(|session| session.slotID() != TEST_SLOT_ID));
    }

    TEST_SLOT_FAIL_LOGOUT.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn read_only_sessions_cannot_mutate_token_or_private_objects() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut session = CK_INVALID_HANDLE as CK_SESSION_HANDLE;
    assert_eq!(
        crate::C_OpenSession(
            TEST_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );

    let mut label = *b"read only";
    let mut label_attribute = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(session, 1, &mut label_attribute, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(session, 1),
        CKR_SESSION_READ_ONLY as CK_RV
    );
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(session, 1, ::std::ptr::null_mut(), 0, &mut copied),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut token_true = CK_TRUE as CK_BBOOL;
    let mut token_false = CK_FALSE as CK_BBOOL;
    let mut private_true = CK_TRUE as CK_BBOOL;
    let mut private_false = CK_FALSE as CK_BBOOL;
    let mut value = [0x22u8; 16];
    let mut base_template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut token_object_template = [
        base_template[0],
        base_template[1],
        base_template[2],
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            session,
            token_object_template.as_mut_ptr(),
            token_object_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut private_object_template = [
        base_template[0],
        base_template[1],
        base_template[2],
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token_false as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_CreateObject(
            session,
            private_object_template.as_mut_ptr(),
            private_object_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let value_len_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let mut token_key_template = [
        value_len_attribute,
        token_object_template[3],
        token_object_template[4],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            session,
            &mut mechanism,
            token_key_template.as_mut_ptr(),
            token_key_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_READ_ONLY as CK_RV
    );

    let mut private_key_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        private_object_template[3],
        private_object_template[4],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            session,
            &mut mechanism,
            private_key_template.as_mut_ptr(),
            private_key_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_USER_NOT_LOGGED_IN as CK_RV
    );

    assert_eq!(
        crate::C_CreateObject(
            session,
            base_template.as_mut_ptr(),
            base_template.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_DestroyObject(session, object), CKR_OK as CK_RV);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn mechanism_list_reports_supported_mechanisms() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let expected = [
        CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        CKM_ECDSA as CK_MECHANISM_TYPE,
        CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
    ];
    let mut count = 0;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut too_small = [0; 1];
    count = too_small.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, too_small.as_mut_ptr(), &mut count),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);

    let mut mechanisms = [0; 5];
    count = mechanisms.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, mechanisms.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, expected.len() as CK_ULONG);
    assert_eq!(mechanisms, expected);

    assert_eq!(
        crate::C_GetMechanismList(TEST_SLOT_ID, ::std::ptr::null_mut(), ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn mechanism_info_reports_supported_mechanism_details() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_slot(TEST_SLOT_ID);

    let mut info = CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    };
    assert_eq!(
        crate::C_GetMechanismInfo(TEST_SLOT_ID, CKM_RSA_PKCS as CK_MECHANISM_TYPE, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1024);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & (CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        (CKF_SIGN | CKF_VERIFY) as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(info.ulMinKeySize, 1);
    assert_eq!(info.ulMaxKeySize, 4096);
    assert_eq!(
        info.flags & CKF_GENERATE as CK_FLAGS,
        CKF_GENERATE as CK_FLAGS
    );

    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_VENDOR_DEFINED as CK_MECHANISM_TYPE,
            &mut info
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetMechanismInfo(
            TEST_SLOT_ID,
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_tracks_empty_search_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 999;

    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OPERATION_ACTIVE as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 2);
    assert_eq!(objects, [1, 2]);

    count = 999;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);

    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_tracks_single_part_operation_lifecycle() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature_len = 0;

    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);

    let mut small_signature = [0u8; 4];
    signature_len = small_signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            small_signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(signature_len, 256);

    let mut signature = [0u8; 256];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature_len, 256);
    assert!(signature.iter().any(|byte| *byte != 0));
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_and_verify_update_final_buffer_multipart_data() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut first = *b"ab";
    let mut second = *b"cd";
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignUpdate(
            TEST_SESSION_HANDLE,
            first.as_mut_ptr(),
            first.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignUpdate(
            TEST_SESSION_HANDLE,
            second.as_mut_ptr(),
            second.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut signature_len = 0;
    assert_eq!(
        crate::C_SignFinal(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    let mut signature = vec![0; signature_len as usize];
    signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_SignFinal(
            TEST_SESSION_HANDLE,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            first.as_mut_ptr(),
            first.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyUpdate(
            TEST_SESSION_HANDLE,
            second.as_mut_ptr(),
            second.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyFinal(TEST_SESSION_HANDLE, signature.as_mut_ptr(), signature_len,),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn piv_rsa_signing_encodes_ckm_rsa_pkcs_input() {
    let encoded = crate::encode_pkcs1_v1_5_signature_input(b"abc", 16).unwrap();
    assert_eq!(
        encoded,
        [0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, b'a', b'b', b'c']
    );
    assert!(crate::encode_pkcs1_v1_5_signature_input(&[0; 6], 16).is_err());
}

#[test]
pub fn piv_rsa_pss_hash_mapping_preserves_sha3_variants() {
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA224_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA224 as CK_MECHANISM_TYPE
    );
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA3_224_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA3_224 as CK_MECHANISM_TYPE
    );
    assert_eq!(
        crate::pss_hash_mechanism(CKM_SHA3_512_RSA_PKCS_PSS as CK_MECHANISM_TYPE).unwrap(),
        CKM_SHA3_512 as CK_MECHANISM_TYPE
    );
}

#[test]
pub fn piv_rsa_padding_round_trips_through_raw_rsa() {
    let private = openssl::rsa::Rsa::generate(2048).unwrap();
    let public = openssl::rsa::Rsa::from_public_components(
        private.n().to_owned().unwrap(),
        private.e().to_owned().unwrap(),
    )
    .unwrap();
    let data = b"padding test";
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();
    let pss = crate::encode_rsa_pss(
        digest.as_ref(),
        private.size() as usize,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        33,
        32,
    )
    .unwrap();
    let mut signature = vec![0; private.size() as usize];
    let written = private
        .private_encrypt(&pss, &mut signature, openssl::rsa::Padding::NONE)
        .unwrap();
    signature.truncate(written);
    let mut recovered = vec![0; public.size() as usize];
    let recovered_len = public
        .public_decrypt(&signature, &mut recovered, openssl::rsa::Padding::NONE)
        .unwrap();
    assert!(crate::verify_rsa_pss(
        &recovered[..recovered_len],
        digest.as_ref(),
        CKM_SHA256 as CK_MECHANISM_TYPE,
        33,
        32,
    )
    .unwrap());

    let label = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), b"").unwrap();
    let encoded = crate::rsa_oaep_pad(
        data,
        private.size() as usize,
        33,
        CKM_SHA256 as CK_MECHANISM_TYPE,
        label.as_ref(),
    )
    .unwrap();
    assert_eq!(
        crate::rsa_oaep_unpad(
            &encoded,
            33,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            label.as_ref(),
        )
        .unwrap(),
        data
    );
    let mut ciphertext = vec![0; public.size() as usize];
    let written = public
        .public_encrypt(&encoded, &mut ciphertext, openssl::rsa::Padding::NONE)
        .unwrap();
    ciphertext.truncate(written);
    let mut plaintext = vec![0; private.size() as usize];
    let written = private
        .private_decrypt(&ciphertext, &mut plaintext, openssl::rsa::Padding::NONE)
        .unwrap();
    plaintext.truncate(written);
    if plaintext.len() < private.size() as usize {
        let mut padded = vec![0; private.size() as usize - plaintext.len()];
        padded.extend_from_slice(&plaintext);
        plaintext = padded;
    }
    assert_eq!(
        crate::rsa_oaep_unpad(
            &plaintext,
            33,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            label.as_ref(),
        )
        .unwrap(),
        data
    );
}

#[test]
pub fn piv_private_objects_route_rsa_signing_to_the_card_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(true)));
        context.sessions.insert(
            TEST_SESSION_HANDLE,
            Box::new(PivSigningTestSession {
                slot_id: TEST_SLOT_ID,
                captured: captured.clone(),
            }),
        );
        context.logged_in_slots.insert(TEST_SLOT_ID);
        context.objects.insert(
            42,
            crate::TokenObject {
                slot_id: Some(TEST_SLOT_ID),
                unique_id: b"piv-9c-private".to_vec(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: b"PIV slot 9C".to_vec(),
                id: vec![0x9c],
                token: true,
                private: true,
                encrypt: false,
                decrypt: false,
                sign: true,
                verify: false,
                derive: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE),
                owner_session: None,
                material: crate::KeyMaterial::PivPrivate {
                    slot: crate::piv::Slot::Signature,
                    algorithm: crate::piv::Algorithm::Rsa1024,
                    modulus: vec![0x80; 128],
                    public_exponent: vec![1, 0, 1],
                    pin_policy: 0,
                    touch_policy: 0,
                },
            },
        );
    }

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 42),
        CKR_OK as CK_RV
    );
    let mut data = *b"abc";
    let mut signature = [0u8; 128];
    let mut signature_len = signature.len() as CK_ULONG;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(signature, [0x5a; 128]);
    assert_eq!(
        *captured.borrow(),
        crate::encode_pkcs1_v1_5_signature_input(b"abc", 128).unwrap()
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_terminal_errors_clear_the_operation() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut oversized_data = [0u8; 246];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            oversized_data.as_mut_ptr(),
            oversized_data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_DATA_LEN_RANGE as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            oversized_data.as_mut_ptr(),
            oversized_data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    let mut data = [1u8];
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_init_reports_key_and_mechanism_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_SignInit(999, &mut mechanism, 2),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 2),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut unsupported, 2),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 999),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OPERATION_ACTIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn sign_operation_is_cleared_when_session_closes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);

    let mut data = [1u8];
    let mut signature_len = 0;
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ::std::ptr::null_mut(),
            &mut signature_len
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_accepts_matching_rsa_signature() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            1,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_accepts_piv_and_openpgp_ecdsa_public_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = openssl::ec::EcKey::generate(&group).unwrap();
    let mut context = openssl::bn::BigNumContext::new().unwrap();
    let point = signing_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .unwrap();
    let public_key = point[1..].to_vec();
    let data = b"hardware-backed signature";
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();
    let signature = openssl::ecdsa::EcdsaSig::sign(&digest, &signing_key)
        .unwrap()
        .to_der()
        .unwrap();
    let signature = crate::piv_ecdsa_signature(&signature, 32).unwrap();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = data.to_vec();
    let mut signature = signature;

    for material in [
        crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::EccP256,
            public_key: public_key.clone(),
        },
        crate::KeyMaterial::OpenPgpPublic {
            algorithm: crate::OpenPgpAlgorithm::Ecdsa(crate::openpgp::Curve::P256),
            public_key,
        },
    ] {
        {
            let mut context = crate::lock_context().unwrap();
            let object = context.as_mut().unwrap().objects.get_mut(&1).unwrap();
            object.key_type = CKK_EC as CK_KEY_TYPE;
            object.verify = true;
            object.material = material;
        }
        assert_eq!(
            crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_Verify(
                TEST_SESSION_HANDLE,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
    }

    let signing_key =
        openssl::pkey::PKey::private_key_from_raw_bytes(&[0x42; 32], openssl::pkey::Id::ED25519)
            .unwrap();
    let mut signer = openssl::sign::Signer::new_without_digest(&signing_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&data).unwrap();
    let public_key = signing_key.raw_public_key().unwrap();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    for material in [
        crate::KeyMaterial::PivPublic {
            algorithm: crate::piv::Algorithm::Ed25519,
            public_key: public_key.clone(),
        },
        crate::KeyMaterial::OpenPgpPublic {
            algorithm: crate::OpenPgpAlgorithm::Ed25519,
            public_key,
        },
    ] {
        {
            let mut context = crate::lock_context().unwrap();
            let object = context.as_mut().unwrap().objects.get_mut(&1).unwrap();
            object.key_type = CKK_EC_EDWARDS as CK_KEY_TYPE;
            object.verify = true;
            object.material = material;
        }
        assert_eq!(
            crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_Verify(
                TEST_SESSION_HANDLE,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                signature.as_ptr() as *mut u8,
                signature.len() as CK_ULONG,
            ),
            CKR_OK as CK_RV
        );
    }

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
fn piv_attestation_certificate_supplies_public_key_for_metadata_fallback() {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = openssl::ec::EcKey::generate(&group).unwrap();
    let signing_key = openssl::pkey::PKey::from_ec_key(signing_key).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "PIV attestation test")
        .unwrap();
    let name = name.build();
    let mut builder = openssl::x509::X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&signing_key).unwrap();
    builder
        .set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(openssl::asn1::Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();
    builder
        .sign(&signing_key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let attestation = builder.build().to_der().unwrap();

    let parsed =
        crate::piv_public_key_from_certificate(crate::piv::Algorithm::EccP256, &attestation)
            .unwrap();
    let crate::PivPublicKey::Ec(parsed) = parsed else {
        panic!("expected an EC public key");
    };
    let mut context = openssl::bn::BigNumContext::new().unwrap();
    let expected = signing_key
        .ec_key()
        .unwrap()
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .unwrap();
    assert_eq!(parsed, expected[1..]);
}

#[test]
fn piv_dynamic_attestation_objects_fetch_only_deferred_attributes() {
    let transmissions = std::rc::Rc::new(std::cell::Cell::new(0));
    let connector: std::rc::Rc<dyn crate::Connector> = std::rc::Rc::new(CountingConnector {
        transmissions: transmissions.clone(),
    });
    let object = crate::TokenObject {
        slot_id: Some(1),
        unique_id: b"piv-attestation".to_vec(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type: CKK_EC as CK_KEY_TYPE,
        label: b"PIV attestation".to_vec(),
        id: vec![0x9c],
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
        owner_session: Some(2),
        material: crate::KeyMaterial::PivAttestation {
            connector,
            slot: crate::piv::Slot::Signature,
            algorithm: crate::piv::Algorithm::EccP256,
            value: std::rc::Rc::new(std::cell::RefCell::new(None)),
            attempted: std::rc::Rc::new(std::cell::Cell::new(false)),
        },
    };

    assert!(object
        .attribute_value(CKA_LABEL as CK_ATTRIBUTE_TYPE)
        .is_some());
    assert_eq!(
        object.attribute_value(CKA_CERTIFICATE_TYPE as CK_ATTRIBUTE_TYPE),
        Some(crate::ulong_attribute(CKC_X_509 as CK_ULONG))
    );
    assert_eq!(transmissions.get(), 0);
    let _ = object.size();
    assert_eq!(transmissions.get(), 0);
    assert!(object
        .attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE)
        .is_none());
    assert_eq!(transmissions.get(), 1);
    assert!(object
        .attribute_value(CKA_SUBJECT as CK_ATTRIBUTE_TYPE)
        .is_none());
    assert_eq!(transmissions.get(), 1);
}

#[test]
fn piv_attestation_slot_is_not_exposed_as_a_dynamic_key() {
    let private_key = openssl::rsa::Rsa::generate(2048).unwrap();
    let public_key = openssl::rsa::Rsa::from_public_components(
        private_key.n().to_owned().unwrap(),
        private_key.e().to_owned().unwrap(),
    )
    .unwrap();
    let slot = crate::PivSlot {
        connector: std::rc::Rc::new(FailingConnector),
        application_aid: crate::piv::PIV_AID.to_vec(),
        slot_description: None,
        authenticated: std::rc::Rc::new(std::cell::Cell::new(false)),
        version: crate::piv::Version {
            major: 5,
            minor: 7,
            patch: 0,
        },
        serial: String::from("TEST0001"),
        keys: vec![crate::PivKey {
            slot: crate::piv::Slot::Attestation,
            algorithm: crate::piv::Algorithm::Rsa2048,
            public_key: crate::PivPublicKey::Rsa(public_key),
            attestation: std::rc::Rc::new(std::cell::RefCell::new(None)),
            attestation_attempted: std::rc::Rc::new(std::cell::Cell::new(false)),
            pin_policy: 0,
            touch_policy: 0,
        }],
        certificates: Vec::new(),
    };

    assert!(crate::Slot::token_objects(&slot, 1)
        .unwrap()
        .iter()
        .all(|object| object.token));
}

#[test]
pub fn verify_reports_signature_mismatches() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut data = [1u8, 2, 3, 4];
    let mut signature = [0u8; 256];
    let mut signature_len = signature.len() as CK_ULONG;

    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Sign(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len
        ),
        CKR_OK as CK_RV
    );

    let mut short_signature = [0u8; 4];
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            short_signature.as_mut_ptr(),
            short_signature.len() as CK_ULONG
        ),
        CKR_SIGNATURE_LEN_RANGE as CK_RV
    );

    signature[0] ^= 0xff;
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len
        ),
        CKR_SIGNATURE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_init_reports_key_and_mechanism_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_VerifyInit(999, &mut mechanism, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut unsupported, 1),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 999),
        CKR_KEY_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 2),
        CKR_KEY_FUNCTION_NOT_PERMITTED as CK_RV
    );

    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OPERATION_ACTIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn verify_operation_is_cleared_when_session_closes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_VerifyInit(TEST_SESSION_HANDLE, &mut mechanism, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);

    let mut data = [1u8];
    let mut signature = [0u8; 32];
    assert_eq!(
        crate::C_Verify(
            TEST_SESSION_HANDLE,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_filters_by_attribute_template() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut templ = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_matches_empty_attributes_exactly() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut value = [0x33u8; 16];
    let mut create_template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut empty_label_object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            create_template.as_mut_ptr(),
            create_template.len() as CK_ULONG,
            &mut empty_label_object
        ),
        CKR_OK as CK_RV
    );

    let mut empty_label_template = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            empty_label_template.as_mut_ptr(),
            empty_label_template.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 3];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], empty_label_object);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    empty_label_template[0].ulValueLen = 1;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            empty_label_template.as_mut_ptr(),
            empty_label_template.len() as CK_ULONG
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OPERATION_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn find_objects_validates_sessions_and_cleans_up_on_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    let mut count = 0;

    assert_eq!(
        crate::C_FindObjectsInit(999, ::std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(999, ::std::ptr::null_mut(), 0, &mut count),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsFinal(999),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_removes_object_from_store_and_search() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 2];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(
            TEST_SESSION_HANDLE,
            objects.as_mut_ptr(),
            objects.len() as CK_ULONG,
            &mut count
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 2);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn destroy_object_updates_active_search_results() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_FindObjectsInit(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0),
        CKR_OK as CK_RV
    );
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], 1);

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, 2),
        CKR_OK as CK_RV
    );
    count = 999;
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 0);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_adds_readable_findable_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Created public key";
    let mut id = [4u8, 5, 6];
    let mut value = [0xabu8; 16];
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(object, 3);

    let mut read_label = [0u8; 18];
    let mut read_verify = CK_FALSE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Created public key");
    assert_eq!(read_verify, CK_TRUE as CK_BBOOL);

    let mut search_label = *b"Created public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], object);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(
        crate::C_DestroyObject(TEST_SESSION_HANDLE, object),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, read_attrs.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_preserves_all_supported_template_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Created private key";
    let mut id = [7u8, 8, 9, 10];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_FALSE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_FALSE as CK_BBOOL;
    let mut value = [0xcdu8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut read_class = 0 as CK_OBJECT_CLASS;
    let mut read_key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 19];
    let mut read_id = [0u8; 4];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_private = CK_FALSE as CK_BBOOL;
    let mut read_encrypt = CK_TRUE as CK_BBOOL;
    let mut read_decrypt = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_verify = CK_TRUE as CK_BBOOL;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(read_class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(read_key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Created private key");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_private, CK_TRUE as CK_BBOOL);
    assert_eq!(read_encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(read_decrypt, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);
    assert_eq!(read_verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_defaults_optional_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut value = [0x11u8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    let mut id_attr = CK_ATTRIBUTE {
        type_: CKA_ID as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 999,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(label_attr.ulValueLen, 0);
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object, &mut id_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(id_attr.ulValueLen, 0);

    let mut token = CK_TRUE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut encrypt = CK_TRUE as CK_BBOOL;
    let mut decrypt = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut verify = CK_TRUE as CK_BBOOL;
    let mut bool_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut encrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT as CK_ATTRIBUTE_TYPE,
            pValue: &mut decrypt as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            object,
            bool_attrs.as_mut_ptr(),
            bool_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(token, CK_FALSE as CK_BBOOL);
    assert_eq!(private, CK_FALSE as CK_BBOOL);
    assert_eq!(encrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(decrypt, CK_FALSE as CK_BBOOL);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);
    assert_eq!(verify, CK_FALSE as CK_BBOOL);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_reports_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 0, &mut object),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(TEST_SESSION_HANDLE, ::std::ptr::null_mut(), 1, &mut object),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut incomplete = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            incomplete.as_mut_ptr(),
            incomplete.len() as CK_ULONG,
            &mut object
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    let mut bad_class = [0u8; 1];
    let mut invalid_class_len = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: bad_class.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: bad_class.len() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_class_len.as_mut_ptr(),
            invalid_class_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut invalid_bool_len = [CK_ATTRIBUTE {
        type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            invalid_bool_len.as_mut_ptr(),
            invalid_bool_len.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut null_class_value = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            null_class_value.as_mut_ptr(),
            null_class_value.len() as CK_ULONG,
            &mut object
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CreateObject(
            999,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut object
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn object_templates_reject_duplicates_and_updates_are_atomic() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut duplicate_class = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
    ];
    let mut handle = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            duplicate_class.as_mut_ptr(),
            duplicate_class.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut label = *b"not committed";
    let mut update = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            update.as_mut_ptr(),
            update.len() as CK_ULONG
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );
    let mut original_label = [0u8; 19];
    let mut read_label = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: original_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut read_label, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&original_label, b"Test RSA public key");

    let duplicate_label = [update[0], update[0]];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            duplicate_label.as_ptr() as CK_ATTRIBUTE_PTR,
            duplicate_label.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut generate_template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        update[0],
        update[0],
    ];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            generate_template.as_mut_ptr(),
            generate_template.len() as CK_ULONG,
            &mut handle
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn create_object_requires_and_imports_real_key_material() {
    let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
    let mut public_class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut private_class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_RSA as CK_KEY_TYPE;
    let mut modulus = rsa.n().to_vec();
    let mut public_exponent = rsa.e().to_vec();
    let mut private_exponent = rsa.d().to_vec();
    let class_attribute = |class: &mut CK_OBJECT_CLASS| CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    let key_type_attribute = CK_ATTRIBUTE {
        type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
        pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
    };
    let modulus_attribute = CK_ATTRIBUTE {
        type_: CKA_MODULUS as CK_ATTRIBUTE_TYPE,
        pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: modulus.len() as CK_ULONG,
    };
    let public_exponent_attribute = CK_ATTRIBUTE {
        type_: CKA_PUBLIC_EXPONENT as CK_ATTRIBUTE_TYPE,
        pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: public_exponent.len() as CK_ULONG,
    };

    let public_template = [
        class_attribute(&mut public_class),
        key_type_attribute,
        modulus_attribute,
        public_exponent_attribute,
    ];
    assert!(matches!(
        crate::parse_create_object_template(&public_template)
            .unwrap()
            .material,
        crate::KeyMaterial::RsaPublic(_)
    ));

    let incomplete = [class_attribute(&mut public_class), key_type_attribute];
    assert!(matches!(
        crate::parse_create_object_template(&incomplete),
        Err(crate::error::Error::Generic(rv)) if rv == CKR_TEMPLATE_INCOMPLETE as CK_RV
    ));

    let private_template = [
        class_attribute(&mut private_class),
        key_type_attribute,
        modulus_attribute,
        public_exponent_attribute,
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE_EXPONENT as CK_ATTRIBUTE_TYPE,
            pValue: private_exponent.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: private_exponent.len() as CK_ULONG,
        },
    ];
    let imported = crate::parse_create_object_template(&private_template).unwrap();
    assert!(matches!(
        imported.material,
        crate::KeyMaterial::RsaPrivate(_)
    ));
    assert!(!imported.local);
    assert_eq!(imported.key_gen_mechanism, None);
}

#[test]
pub fn copy_object_clones_and_overrides_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Copied public key";
    let mut id = [8u8, 6, 4, 2];
    let mut token = CK_FALSE as CK_BBOOL;
    let mut private = CK_TRUE as CK_BBOOL;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut copied
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied, 3);

    let mut copied_class = 0 as CK_OBJECT_CLASS;
    let mut copied_key_type = 999 as CK_KEY_TYPE;
    let mut copied_label = [0u8; 17];
    let mut copied_id = [0u8; 4];
    let mut copied_verify = CK_FALSE as CK_BBOOL;
    let mut copied_token = CK_TRUE as CK_BBOOL;
    let mut copied_private = CK_FALSE as CK_BBOOL;
    let mut copied_unique_id = [0u8; 8];
    let mut copied_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: copied_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: copied_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_verify as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE,
            pValue: &mut copied_private as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            pValue: copied_unique_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: copied_unique_id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            copied,
            copied_attrs.as_mut_ptr(),
            copied_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(copied_class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(copied_key_type, CKK_RSA as CK_KEY_TYPE);
    assert_eq!(&copied_label, b"Copied public key");
    assert_eq!(copied_id, id);
    assert_eq!(copied_verify, CK_TRUE as CK_BBOOL);
    assert_eq!(copied_token, CK_FALSE as CK_BBOOL);
    assert_eq!(copied_private, CK_TRUE as CK_BBOOL);
    let copied_unique_id_len = copied_attrs[7].ulValueLen as usize;

    let mut original_label = [0u8; 19];
    let mut original_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: original_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut original_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&original_label, b"Test RSA public key");
    let mut original_unique_id = [0u8; 8];
    let mut original_unique_id_attr = CK_ATTRIBUTE {
        type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
        pValue: original_unique_id.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: original_unique_id.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut original_unique_id_attr, 1),
        CKR_OK as CK_RV
    );
    assert_ne!(
        &copied_unique_id[..copied_unique_id_len],
        &original_unique_id[..original_unique_id_attr.ulValueLen as usize]
    );

    let mut search_label = *b"Copied public key";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], copied);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn copy_object_reports_template_and_handle_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut copied = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            999,
            ::std::ptr::null_mut(),
            0,
            &mut copied
        ),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            ::std::ptr::null_mut(),
            1,
            &mut copied
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut class = CKO_PRIVATE_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            readonly_attr.as_mut_ptr(),
            readonly_attr.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut unknown = [CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        crate::C_CopyObject(
            TEST_SESSION_HANDLE,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_CopyObject(
            999,
            1,
            unknown.as_mut_ptr(),
            unknown.len() as CK_ULONG,
            &mut copied
        ),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, unknown.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_attribute_storage_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>()
            + b"Test RSA public key".len()
            + 2
            + 7
            + 256
            + 3
            + 1
            + 8) as CK_ULONG
    );

    let mut label = *b"Short";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 1, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 1 + 7 + 256 + 3 + 1 + 8)
            as CK_ULONG
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_object_size_reports_created_object_size_and_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
    let mut key_type = CKK_GENERIC_SECRET as CK_KEY_TYPE;
    let mut label = *b"Sized key";
    let mut id = [1u8, 2, 3, 4, 5];
    let mut value = [0x44u8; 16];
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
            pValue: value.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_CreateObject(
            TEST_SESSION_HANDLE,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut object
        ),
        CKR_OK as CK_RV
    );

    let mut size = 0;
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, &mut size),
        CKR_OK as CK_RV
    );
    assert_eq!(
        size,
        (4 * ::std::mem::size_of::<CK_ULONG>() + label.len() + id.len() + 1 + 11 + 1 + 16)
            as CK_ULONG
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, 999, &mut size),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(999, object, &mut size),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetObjectSize(TEST_SESSION_HANDLE, object, ::std::ptr::null_mut()),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_sizes_and_values() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        label_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut label = [0u8; 19];
    label_attr.pValue = label.as_mut_ptr() as CK_VOID_PTR;
    label_attr.ulValueLen = label.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut label_attr, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(&label, b"Test RSA public key");

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_PUBLIC_KEY as CK_OBJECT_CLASS);
    assert_eq!(sign, CK_FALSE as CK_BBOOL);

    let mut wrap = CK_FALSE as CK_BBOOL;
    let mut unwrap = CK_FALSE as CK_BBOOL;
    let mut sign_recover = CK_FALSE as CK_BBOOL;
    let mut verify_recover = CK_FALSE as CK_BBOOL;
    let mut wrap_with_trusted = CK_FALSE as CK_BBOOL;
    let mut operation_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_WRAP as CK_ATTRIBUTE_TYPE,
            pValue: &mut wrap as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNWRAP as CK_ATTRIBUTE_TYPE,
            pValue: &mut unwrap as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN_RECOVER as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign_recover as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VERIFY_RECOVER as CK_ATTRIBUTE_TYPE,
            pValue: &mut verify_recover as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_WRAP_WITH_TRUSTED as CK_ATTRIBUTE_TYPE,
            pValue: &mut wrap_with_trusted as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            operation_attrs.as_mut_ptr(),
            operation_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        (
            wrap,
            unwrap,
            sign_recover,
            verify_recover,
            wrap_with_trusted
        ),
        (
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL,
            CK_FALSE as CK_BBOOL
        )
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reads_certificate_values() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let certificate = b"synthetic certificate".to_vec();
    let object = crate::TokenObject {
        slot_id: Some(TEST_SLOT_ID),
        unique_id: b"openpgp-certificate".to_vec(),
        class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
        key_type: CKK_RSA as CK_KEY_TYPE,
        label: b"OpenPGP certificate".to_vec(),
        id: vec![1],
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
        material: crate::KeyMaterial::OpenPgpCertificate {
            value: certificate.clone(),
        },
    };
    let object_handle = {
        let mut context = crate::lock_context().unwrap();
        context.as_mut().unwrap().insert_object(object)
    };

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object_handle, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value_attribute.ulValueLen, certificate.len() as CK_ULONG);

    let mut value = vec![0; certificate.len()];
    value_attribute.pValue = value.as_mut_ptr() as CK_VOID_PTR;
    value_attribute.ulValueLen = value.len() as CK_ULONG;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, object_handle, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value, certificate);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn get_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut small_label = [0u8; 4];
    let mut small_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: small_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: small_label.len() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut small_attr, 1),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(
        small_attr.ulValueLen,
        b"Test RSA public key".len() as CK_ULONG
    );

    let mut unknown_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, &mut unknown_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );
    assert_eq!(
        unknown_attr.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 999, &mut unknown_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(999, 1, &mut unknown_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_updates_mutable_attributes() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut label = *b"Renamed public key";
    let mut id = [9u8, 8, 7];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            attrs.as_mut_ptr(),
            attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );

    let mut read_label = [0u8; 18];
    let mut read_id = [0u8; 3];
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
    ];

    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            1,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(&read_label, b"Renamed public key");
    assert_eq!(read_id, id);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn set_attribute_value_reports_attribute_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut readonly_attr = CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut readonly_attr, 1),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut invalid_attr = CK_ATTRIBUTE {
        type_: CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut invalid_attr, 1),
        CKR_ATTRIBUTE_TYPE_INVALID as CK_RV
    );

    let mut bad_attr = CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 1,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, &mut bad_attr, 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 999, &mut invalid_attr, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(999, 1, &mut invalid_attr, 1),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, 1, ::std::ptr::null_mut(), 1),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_key_creates_secret_key_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut label = *b"Generated secret";
    let mut id = [3u8, 1, 4];
    let mut token = CK_TRUE as CK_BBOOL;
    let mut sign = CK_TRUE as CK_BBOOL;
    let mut value_len = 32 as CK_ULONG;
    let mut templ = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            templ.as_mut_ptr(),
            templ.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(key, 3);

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut key_type = 999 as CK_KEY_TYPE;
    let mut read_label = [0u8; 16];
    let mut read_id = [0u8; 3];
    let mut read_token = CK_FALSE as CK_BBOOL;
    let mut read_sign = CK_FALSE as CK_BBOOL;
    let mut read_value_len = 0 as CK_ULONG;
    let mut read_sensitive = CK_FALSE as CK_BBOOL;
    let mut read_extractable = CK_TRUE as CK_BBOOL;
    let mut read_always_sensitive = CK_FALSE as CK_BBOOL;
    let mut read_never_extractable = CK_FALSE as CK_BBOOL;
    let mut read_unique_id = [0u8; 8];
    let mut read_local = CK_FALSE as CK_BBOOL;
    let mut read_key_gen_mechanism = CK_UNAVAILABLE_INFORMATION as CK_MECHANISM_TYPE;
    let mut read_attrs = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE,
            pValue: &mut key_type as *mut CK_KEY_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: read_label.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_token as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sign as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_always_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_never_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID as CK_ATTRIBUTE_TYPE,
            pValue: read_unique_id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: read_unique_id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LOCAL as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_local as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE,
            pValue: &mut read_key_gen_mechanism as *mut CK_MECHANISM_TYPE as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_MECHANISM_TYPE>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            read_attrs.as_mut_ptr(),
            read_attrs.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(class, CKO_SECRET_KEY as CK_OBJECT_CLASS);
    assert_eq!(key_type, CKK_GENERIC_SECRET as CK_KEY_TYPE);
    assert_eq!(&read_label, b"Generated secret");
    assert_eq!(read_id, id);
    assert_eq!(read_token, CK_TRUE as CK_BBOOL);
    assert_eq!(read_sign, CK_TRUE as CK_BBOOL);
    assert_eq!(read_value_len, value_len);
    assert_eq!(read_sensitive, CK_TRUE as CK_BBOOL);
    assert_eq!(read_extractable, CK_FALSE as CK_BBOOL);
    assert_eq!(read_always_sensitive, CK_TRUE as CK_BBOOL);
    assert_eq!(read_never_extractable, CK_TRUE as CK_BBOOL);
    assert_eq!(&read_unique_id[..read_attrs[11].ulValueLen as usize], b"3");
    assert_eq!(read_local, CK_TRUE as CK_BBOOL);
    assert_eq!(
        read_key_gen_mechanism,
        CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE
    );
    {
        let context = crate::lock_context().unwrap();
        let object = context.as_ref().unwrap().objects.get(&key).unwrap();
        match &object.material {
            crate::KeyMaterial::Secret(value) => {
                assert_eq!(value.len(), value_len as usize);
                assert!(value.iter().any(|byte| *byte != 0));
            }
            material => panic!("expected generated secret material, got {material:?}"),
        }
    }

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );
    assert_eq!(
        value_attribute.ulValueLen,
        CK_UNAVAILABLE_INFORMATION as CK_ULONG
    );

    let mut rsa_mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_SignInit(TEST_SESSION_HANDLE, &mut rsa_mechanism, key),
        CKR_KEY_TYPE_INCONSISTENT as CK_RV
    );

    let mut search_label = *b"Generated secret";
    let mut search_templ = [CK_ATTRIBUTE {
        type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
        pValue: search_label.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: search_label.len() as CK_ULONG,
    }];
    let mut objects = [CK_INVALID_HANDLE as CK_OBJECT_HANDLE; 1];
    let mut count = 0;
    assert_eq!(
        crate::C_FindObjectsInit(
            TEST_SESSION_HANDLE,
            search_templ.as_mut_ptr(),
            search_templ.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_FindObjects(TEST_SESSION_HANDLE, objects.as_mut_ptr(), 1, &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(count, 1);
    assert_eq!(objects[0], key);
    assert_eq!(
        crate::C_FindObjectsFinal(TEST_SESSION_HANDLE),
        CKR_OK as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generated_secret_key_enforces_sensitivity_policy() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 24 as CK_ULONG;
    let mut sensitive = CK_FALSE as CK_BBOOL;
    let mut extractable = CK_TRUE as CK_BBOOL;
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
            pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );

    let mut value_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE as CK_ATTRIBUTE_TYPE,
        pValue: ::std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(value_attribute.ulValueLen, value_len);
    let mut value = vec![0; value_len as usize];
    value_attribute.pValue = value.as_mut_ptr() as CK_VOID_PTR;
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_OK as CK_RV
    );
    assert!(value.iter().any(|byte| *byte != 0));

    sensitive = CK_TRUE as CK_BBOOL;
    extractable = CK_FALSE as CK_BBOOL;
    let mut harden = [
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            harden.as_mut_ptr(),
            harden.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );

    let mut make_non_sensitive = CK_FALSE as CK_BBOOL;
    let mut make_non_sensitive_attribute = CK_ATTRIBUTE {
        type_: CKA_SENSITIVE as CK_ATTRIBUTE_TYPE,
        pValue: &mut make_non_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            &mut make_non_sensitive_attribute,
            1
        ),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );
    let mut make_extractable = CK_TRUE as CK_BBOOL;
    let mut make_extractable_attribute = CK_ATTRIBUTE {
        type_: CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
        pValue: &mut make_extractable as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_SetAttributeValue(TEST_SESSION_HANDLE, key, &mut make_extractable_attribute, 1),
        CKR_ATTRIBUTE_READ_ONLY as CK_RV
    );

    let mut always_sensitive = CK_TRUE as CK_BBOOL;
    let mut never_extractable = CK_TRUE as CK_BBOOL;
    let mut history = [
        CK_ATTRIBUTE {
            type_: CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE,
            pValue: &mut always_sensitive as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
            pValue: &mut never_extractable as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    assert_eq!(
        crate::C_GetAttributeValue(
            TEST_SESSION_HANDLE,
            key,
            history.as_mut_ptr(),
            history.len() as CK_ULONG
        ),
        CKR_OK as CK_RV
    );
    assert_eq!(always_sensitive, CK_FALSE as CK_BBOOL);
    assert_eq!(never_extractable, CK_FALSE as CK_BBOOL);

    value_attribute.pValue = ::std::ptr::null_mut();
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut value_attribute, 1),
        CKR_ATTRIBUTE_SENSITIVE as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn session_objects_are_private_to_their_owner_and_removed_on_close() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE + 1);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut value_len = 16 as CK_ULONG;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut value_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK as CK_RV
    );

    let mut class = 0 as CK_OBJECT_CLASS;
    let mut class_attribute = CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, key, &mut class_attribute, 1),
        CKR_OK as CK_RV
    );
    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE + 1, key, &mut class_attribute, 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_CloseSession(TEST_SESSION_HANDLE), CKR_OK as CK_RV);
    let context = crate::lock_context().unwrap();
    assert!(!context.as_ref().unwrap().objects.contains_key(&key));
    drop(context);

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn removing_a_dynamic_slot_clears_its_runtime_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context.dynamic_slots.insert(TEST_SLOT_ID);
        let mut session_object = context.objects.get(&1).unwrap().clone();
        session_object.unique_id.clear();
        session_object.token = false;
        session_object.owner_session = Some(TEST_SESSION_HANDLE);
        let object_handle = context.insert_object(session_object);
        context.find_operations.insert(
            TEST_SESSION_HANDLE,
            crate::FindOperation {
                objects: vec![object_handle],
                next: 0,
            },
        );

        context.close_slot_state(TEST_SLOT_ID, true);
        context.slots.remove(&TEST_SLOT_ID);
        context.dynamic_slots.remove(&TEST_SLOT_ID);
        assert!(!context.sessions.contains_key(&TEST_SESSION_HANDLE));
        assert!(!context.find_operations.contains_key(&TEST_SESSION_HANDLE));
        assert!(!context.logged_in_slots.contains(&TEST_SLOT_ID));
        assert!(context
            .objects
            .values()
            .all(|object| object.slot_id != Some(TEST_SLOT_ID)));
    }
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn slot_info_does_not_rescan_dynamic_slots() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    {
        let mut context = crate::lock_context().unwrap();
        let context = context.as_mut().unwrap();
        context
            .slots
            .insert(TEST_SLOT_ID, Box::new(test_slot(false)));
        context.dynamic_slots.insert(TEST_SLOT_ID);
    }

    let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
    assert_eq!(
        crate::C_GetSlotInfo(TEST_SLOT_ID, &mut slot_info),
        CKR_OK as CK_RV
    );
    assert_eq!(slot_info.flags & CKF_TOKEN_PRESENT as CK_FLAGS, 0);
    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_key_reports_mechanism_and_template_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );

    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    install_test_session(TEST_SLOT_ID, TEST_SESSION_HANDLE);

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_TEMPLATE_INCOMPLETE as CK_RV
    );

    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            ::std::ptr::null_mut(),
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            ::std::ptr::null_mut()
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(999, &mut mechanism, ::std::ptr::null_mut(), 0, &mut key),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            1,
            &mut key
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );

    let mut unsupported = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS as CK_MECHANISM_TYPE,
        pParameter: ::std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut unsupported,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_INVALID as CK_RV
    );

    let mut parameter = 1u8;
    mechanism.pParameter = &mut parameter as *mut u8 as CK_VOID_PTR;
    mechanism.ulParameterLen = 1;
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            ::std::ptr::null_mut(),
            0,
            &mut key
        ),
        CKR_MECHANISM_PARAM_INVALID as CK_RV
    );
    mechanism.pParameter = ::std::ptr::null_mut();
    mechanism.ulParameterLen = 0;

    let mut class = CKO_PUBLIC_KEY as CK_OBJECT_CLASS;
    let mut inconsistent = [CK_ATTRIBUTE {
        type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
        pValue: &mut class as *mut CK_OBJECT_CLASS as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            inconsistent.as_mut_ptr(),
            inconsistent.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    let mut bad_bool = 2 as CK_BBOOL;
    let mut invalid_bool = [CK_ATTRIBUTE {
        type_: CKA_SIGN as CK_ATTRIBUTE_TYPE,
        pValue: &mut bad_bool as *mut CK_BBOOL as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            invalid_bool.as_mut_ptr(),
            invalid_bool.len() as CK_ULONG,
            &mut key
        ),
        CKR_ATTRIBUTE_VALUE_INVALID as CK_RV
    );

    let mut zero_len = 0 as CK_ULONG;
    let mut zero_len_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut zero_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            zero_len_template.as_mut_ptr(),
            zero_len_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );

    let mut oversized_len = 513 as CK_ULONG;
    let mut oversized_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut oversized_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            oversized_template.as_mut_ptr(),
            oversized_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_KEY_SIZE_RANGE as CK_RV
    );

    let mut duplicate_len = 16 as CK_ULONG;
    let duplicate_attribute = CK_ATTRIBUTE {
        type_: CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE,
        pValue: &mut duplicate_len as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: ::std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let mut duplicate_template = [duplicate_attribute, duplicate_attribute];
    assert_eq!(
        crate::C_GenerateKey(
            TEST_SESSION_HANDLE,
            &mut mechanism,
            duplicate_template.as_mut_ptr(),
            duplicate_template.len() as CK_ULONG,
            &mut key
        ),
        CKR_TEMPLATE_INCONSISTENT as CK_RV
    );

    assert_eq!(
        crate::C_GetAttributeValue(TEST_SESSION_HANDLE, 3, invalid_bool.as_mut_ptr(), 1),
        CKR_OBJECT_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn generate_random_validates_initialization_and_session() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    let mut random_data = [0u8; 16];

    assert_eq!(
        crate::C_GenerateRandom(1, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
    );
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);
    assert_eq!(
        crate::C_GenerateRandom(999, random_data.as_mut_ptr(), random_data.len() as CK_ULONG),
        CKR_SESSION_HANDLE_INVALID as CK_RV
    );

    assert_eq!(crate::C_Finalize(::std::ptr::null_mut()), CKR_OK as CK_RV);
}

#[test]
pub fn interface_list_checks_buffer_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut count = 0;
    let mut interface = CK_INTERFACE {
        pInterfaceName: ::std::ptr::null_mut(),
        pFunctionList: ::std::ptr::null_mut(),
        flags: 0,
    };

    assert_eq!(
        crate::C_GetInterfaceList(&mut interface, &mut count),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(count, 4);
}

fn assert_get_interface_returns_requested_table(version: CK_VERSION) {
    let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
    let mut version = version;
    let name = b"PKCS 11\0";

    assert_eq!(
        crate::C_GetInterface(
            name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_OK as CK_RV
    );
    assert!(!interface.is_null());

    match (version.major, version.minor) {
        (2, 40) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 2);
            assert_eq!(unsafe { (*function_list).version.minor }, 40);
            assert!(unsafe { (*function_list).C_GetFunctionList.is_some() });
        }
        (3, 0) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_0_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 0);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_MessageEncryptInit.is_some() });
        }
        (3, 1) => {
            // PKCS #11 3.2 headers have no CK_FUNCTION_LIST_3_1 type; 3.1 uses
            // the 3.0-shaped function list while reporting version 3.1.
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_0_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 1);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_MessageEncryptInit.is_some() });
        }
        (3, 2) => {
            let function_list = unsafe { (*interface).pFunctionList as CK_FUNCTION_LIST_3_2_PTR };
            assert!(!function_list.is_null());
            assert_eq!(unsafe { (*function_list).version.major }, 3);
            assert_eq!(unsafe { (*function_list).version.minor }, 2);
            assert!(unsafe { (*function_list).C_GetInterface.is_some() });
            assert!(unsafe { (*function_list).C_EncapsulateKey.is_some() });
            assert!(unsafe { (*function_list).C_UnwrapKeyAuthenticated.is_some() });
        }
        _ => panic!("unexpected supported version"),
    }
}

#[test]
pub fn get_interface_returns_requested_version_and_documented_table_layout() {
    let _guard = TEST_LOCK.lock().unwrap();
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 2 });
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 1 });
    assert_get_interface_returns_requested_table(CK_VERSION { major: 3, minor: 0 });
    assert_get_interface_returns_requested_table(CK_VERSION {
        major: 2,
        minor: 40,
    });
}

#[test]
pub fn get_interface_rejects_wrong_version_and_name() {
    let _guard = TEST_LOCK.lock().unwrap();
    let name = b"PKCS 11\0";
    let wrong_name = b"NOT PKCS\0";
    let short_name = b"X\0";

    for rejected_version in [
        CK_VERSION {
            major: 2,
            minor: 39,
        },
        CK_VERSION { major: 3, minor: 3 },
        CK_VERSION { major: 3, minor: 4 },
    ] {
        let mut version = rejected_version;
        let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
        assert_eq!(
            crate::C_GetInterface(
                name.as_ptr() as *mut CK_BYTE,
                &mut version,
                &mut interface,
                0
            ),
            CKR_ARGUMENTS_BAD as CK_RV
        );
    }

    let mut version = CK_VERSION { major: 3, minor: 2 };
    let mut interface: CK_INTERFACE_PTR = ::std::ptr::null_mut();
    assert_eq!(
        crate::C_GetInterface(
            wrong_name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GetInterface(
            short_name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            0
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
    assert_eq!(
        crate::C_GetInterface(
            name.as_ptr() as *mut CK_BYTE,
            &mut version,
            &mut interface,
            CKF_INTERFACE_FORK_SAFE as CK_FLAGS
        ),
        CKR_ARGUMENTS_BAD as CK_RV
    );
}
#[test]
pub fn bindgen_test_layout_CK_SLOT_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_SLOT_INFO>(),
        112usize,
        concat!("Size of: ", stringify!(CK_SLOT_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_SLOT_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_SLOT_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, slotDescription),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(slotDescription)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, manufacturerID),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, flags),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, hardwareVersion),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SLOT_INFO, firmwareVersion),
        106usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SLOT_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_TOKEN_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_TOKEN_INFO>(),
        208usize,
        concat!("Size of: ", stringify!(CK_TOKEN_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_TOKEN_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_TOKEN_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, label),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(label)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, manufacturerID),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(manufacturerID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, model),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(model)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, serialNumber),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(serialNumber)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, flags),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxSessionCount),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulSessionCount),
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxRwSessionCount),
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxRwSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulRwSessionCount),
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulRwSessionCount)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMaxPinLen),
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMaxPinLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulMinPinLen),
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulMinPinLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPublicMemory),
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPublicMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulFreePublicMemory),
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePublicMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPrivateMemory),
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulTotalPrivateMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, ulFreePrivateMemory),
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(ulFreePrivateMemory)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, hardwareVersion),
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(hardwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, firmwareVersion),
        186usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(firmwareVersion)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_TOKEN_INFO, utcTime),
        188usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_TOKEN_INFO),
            "::",
            stringify!(utcTime)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_SESSION_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_SESSION_INFO>(),
        32usize,
        concat!("Size of: ", stringify!(CK_SESSION_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_SESSION_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_SESSION_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, slotID),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(slotID)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, state),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, flags),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_SESSION_INFO, ulDeviceError),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_SESSION_INFO),
            "::",
            stringify!(ulDeviceError)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_ATTRIBUTE() {
    assert_eq!(
        ::std::mem::size_of::<CK_ATTRIBUTE>(),
        24usize,
        concat!("Size of: ", stringify!(CK_ATTRIBUTE))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_ATTRIBUTE>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_ATTRIBUTE))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, type_),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, pValue),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(pValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ATTRIBUTE, ulValueLen),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ATTRIBUTE),
            "::",
            stringify!(ulValueLen)
        )
    );
}
#[test]
pub fn bindgen_test_layout_CK_DATE() {
    assert_eq!(
        ::std::mem::size_of::<CK_DATE>(),
        8usize,
        concat!("Size of: ", stringify!(CK_DATE))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_DATE>(),
        1usize,
        concat!("Alignment of ", stringify!(CK_DATE))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, year),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(year)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, month),
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(month)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_DATE, day),
        6usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_DATE),
            "::",
            stringify!(day)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_MECHANISM() {
    assert_eq!(
        ::std::mem::size_of::<CK_MECHANISM>(),
        24usize,
        concat!("Size of: ", stringify!(CK_MECHANISM))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_MECHANISM>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_MECHANISM))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, mechanism),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(mechanism)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, pParameter),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(pParameter)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM, ulParameterLen),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM),
            "::",
            stringify!(ulParameterLen)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_MECHANISM_INFO() {
    assert_eq!(
        ::std::mem::size_of::<CK_MECHANISM_INFO>(),
        24usize,
        concat!("Size of: ", stringify!(CK_MECHANISM_INFO))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_MECHANISM_INFO>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_MECHANISM_INFO))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, ulMinKeySize),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
            "::",
            stringify!(ulMinKeySize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, ulMaxKeySize),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
            "::",
            stringify!(ulMaxKeySize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_MECHANISM_INFO, flags),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_MECHANISM_INFO),
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
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, kdf),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(kdf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulSharedDataLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, pSharedData),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(pSharedData)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, ulPublicDataLen),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_ECDH1_DERIVE_PARAMS),
            "::",
            stringify!(ulPublicDataLen)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_ECDH1_DERIVE_PARAMS, pPublicData),
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
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(source)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_OAEP_PARAMS),
            "::",
            stringify!(pSourceData)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
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
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, hashAlg),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(hashAlg)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, mgf),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_RSA_PKCS_PSS_PARAMS),
            "::",
            stringify!(mgf)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, sLen),
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
fn bindgen_test_layout_CK_VERSION() {
    assert_eq!(
        ::std::mem::size_of::<CK_VERSION>(),
        2usize,
        concat!("Size of: ", stringify!(CK_VERSION))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_VERSION>(),
        1usize,
        concat!("Alignment of ", stringify!(CK_VERSION))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_VERSION, major),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_VERSION),
            "::",
            stringify!(major)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_VERSION, minor),
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_VERSION),
            "::",
            stringify!(minor)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_C_INITIALIZE_ARGS() {
    assert_eq!(
        ::std::mem::size_of::<CK_C_INITIALIZE_ARGS>(),
        48usize,
        concat!("Size of: ", stringify!(CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_C_INITIALIZE_ARGS>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_C_INITIALIZE_ARGS))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, CreateMutex),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(CreateMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, DestroyMutex),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(DestroyMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, LockMutex),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(LockMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, UnlockMutex),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(UnlockMutex)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, flags),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_C_INITIALIZE_ARGS, pReserved),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_C_INITIALIZE_ARGS),
            "::",
            stringify!(pReserved)
        )
    );
}
#[test]
fn bindgen_test_layout_CK_FUNCTION_LIST() {
    assert_eq!(
        ::std::mem::size_of::<CK_FUNCTION_LIST>(),
        552usize,
        concat!("Size of: ", stringify!(CK_FUNCTION_LIST))
    );
    assert_eq!(
        ::std::mem::align_of::<CK_FUNCTION_LIST>(),
        8usize,
        concat!("Alignment of ", stringify!(CK_FUNCTION_LIST))
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, version),
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize),
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Initialize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Finalize),
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Finalize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetInfo),
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetFunctionList),
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotList),
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotInfo),
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSlotInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetTokenInfo),
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetTokenInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismList),
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismList)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismInfo),
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetMechanismInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_InitToken),
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitToken)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_InitPIN),
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_InitPIN)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetPIN),
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetPIN)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_OpenSession),
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_OpenSession)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CloseSession),
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseSession)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CloseAllSessions),
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CloseAllSessions)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSessionInfo),
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetSessionInfo)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetOperationState),
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetOperationState)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetOperationState),
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetOperationState)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Login),
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Login)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Logout),
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Logout)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CreateObject),
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CreateObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CopyObject),
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CopyObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DestroyObject),
        184usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DestroyObject)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetObjectSize),
        192usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetObjectSize)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetAttributeValue),
        200usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetAttributeValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SetAttributeValue),
        208usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SetAttributeValue)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsInit),
        216usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjects),
        224usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjects)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsFinal),
        232usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_FindObjectsFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptInit),
        240usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Encrypt),
        248usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Encrypt)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptUpdate),
        256usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptFinal),
        264usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_EncryptFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptInit),
        272usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Decrypt),
        280usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Decrypt)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptUpdate),
        288usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptFinal),
        296usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestInit),
        304usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Digest),
        312usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Digest)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestUpdate),
        320usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestKey),
        328usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestFinal),
        336usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignInit),
        344usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Sign),
        352usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Sign)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignUpdate),
        360usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignFinal),
        368usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignRecoverInit),
        376usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecoverInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignRecover),
        384usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignRecover)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyInit),
        392usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_Verify),
        400usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_Verify)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyUpdate),
        408usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyFinal),
        416usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyFinal)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyRecoverInit),
        424usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecoverInit)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyRecover),
        432usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_VerifyRecover)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DigestEncryptUpdate),
        440usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DigestEncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptDigestUpdate),
        448usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptDigestUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SignEncryptUpdate),
        456usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SignEncryptUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptVerifyUpdate),
        464usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DecryptVerifyUpdate)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateKey),
        472usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateKeyPair),
        480usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateKeyPair)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_WrapKey),
        488usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_WrapKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_UnwrapKey),
        496usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_UnwrapKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_DeriveKey),
        504usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_DeriveKey)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_SeedRandom),
        512usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_SeedRandom)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateRandom),
        520usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GenerateRandom)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_GetFunctionStatus),
        528usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_GetFunctionStatus)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_CancelFunction),
        536usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_CancelFunction)
        )
    );
    assert_eq!(
        ::std::mem::offset_of!(CK_FUNCTION_LIST, C_WaitForSlotEvent),
        544usize,
        concat!(
            "Offset of field: ",
            stringify!(CK_FUNCTION_LIST),
            "::",
            stringify!(C_WaitForSlotEvent)
        )
    );
}

#[cfg(feature = "abi-tests")]
#[test]
fn abi_test_slots_are_hardware_free_and_reach_backend_sessions() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut count = 0;
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    assert_eq!(
        slots,
        vec![
            crate::ABI_TEST_SLOT_ID,
            crate::ABI_TEST_PIV_SLOT_ID,
            crate::ABI_TEST_SCP03_SLOT_ID,
            crate::ABI_TEST_YUBIHSM_SLOT_ID,
            crate::ABI_TEST_SCP11_SLOT_ID,
        ]
    );

    for slot_id in &slots {
        let mut slot_info = unsafe { ::std::mem::zeroed::<CK_SLOT_INFO>() };
        assert_eq!(
            crate::C_GetSlotInfo(*slot_id, &mut slot_info),
            CKR_OK as CK_RV
        );
        let description = String::from_utf8_lossy(&slot_info.slotDescription);
        assert!(!description.to_ascii_lowercase().contains("token"));
        if *slot_id == crate::ABI_TEST_PIV_SLOT_ID {
            assert_eq!(
                &slot_info.slotDescription[..b"PKCS11RS ABI PIV test slot".len()],
                b"PKCS11RS ABI PIV test slot"
            );
        }
    }

    for (slot_id, label, serial) in [
        (
            crate::ABI_TEST_SLOT_ID,
            b"ABI test token #ABI00001".as_slice(),
            b"ABI00001".as_slice(),
        ),
        (
            crate::ABI_TEST_PIV_SLOT_ID,
            b"YubiKey PIV #PIV00001".as_slice(),
            b"PIV00001".as_slice(),
        ),
        (
            crate::ABI_TEST_SCP03_SLOT_ID,
            b"ABI SCP03 #SCP03001".as_slice(),
            b"SCP03001".as_slice(),
        ),
        (
            crate::ABI_TEST_YUBIHSM_SLOT_ID,
            b"ABI YubiHSM #HSM00001".as_slice(),
            b"HSM00001".as_slice(),
        ),
        (
            crate::ABI_TEST_SCP11_SLOT_ID,
            b"ABI SCP11 #SCP11001".as_slice(),
            b"SCP11001".as_slice(),
        ),
    ] {
        let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
        assert_eq!(&token_info.label[..label.len()], label);
        assert_eq!(&token_info.serialNumber[..serial.len()], serial);
    }

    for (slot_id, model) in [
        (crate::ABI_TEST_SLOT_ID, b"ABI test token".as_slice()),
        (crate::ABI_TEST_PIV_SLOT_ID, b"YubiKey PIV".as_slice()),
        (crate::ABI_TEST_SCP03_SLOT_ID, b"ABI SCP03".as_slice()),
        (crate::ABI_TEST_YUBIHSM_SLOT_ID, b"ABI YubiHSM".as_slice()),
        (crate::ABI_TEST_SCP11_SLOT_ID, b"ABI SCP11".as_slice()),
    ] {
        let mut token_info = unsafe { ::std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
        assert_eq!(&token_info.model[..model.len()], model);
        assert!(token_info.model[model.len()..]
            .iter()
            .all(|byte| *byte == b' '));
    }

    let mut session = 0;
    assert_eq!(
        crate::C_OpenSession(
            crate::ABI_TEST_SCP03_SLOT_ID,
            CKF_SERIAL_SESSION as CK_FLAGS,
            ::std::ptr::null_mut(),
            None,
            &mut session,
        ),
        CKR_OK as CK_RV
    );
    let pin = *b"1234";
    assert_eq!(
        crate::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            pin.as_ptr() as *mut CK_BYTE,
            pin.len() as CK_ULONG,
        ),
        CKR_OK as CK_RV
    );
    let mut random = [0; 16];
    assert_eq!(
        crate::C_GenerateRandom(session, random.as_mut_ptr(), random.len() as CK_ULONG),
        CKR_OK as CK_RV
    );
    assert_eq!(random, [0; 16]);

    finalize_for_test();
}

#[cfg(not(feature = "abi-tests"))]
#[test]
#[ignore = "requires a live YubiKey or YubiHSM"]
fn live_hardware_slots_report_metadata() {
    let _guard = TEST_LOCK.lock().unwrap();
    finalize_for_test();
    assert_eq!(crate::C_Initialize(::std::ptr::null_mut()), CKR_OK as CK_RV);

    let mut count = 0;
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, ::std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut slots = vec![0; count as usize];
    assert_eq!(
        crate::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count),
        CKR_OK as CK_RV
    );
    slots.truncate(count as usize);
    for slot_id in slots {
        let mut slot_info = CK_SLOT_INFO {
            slotDescription: [0; 64],
            manufacturerID: [0; 32],
            flags: 0,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
        };
        let mut token_info = CK_TOKEN_INFO {
            label: [0; 32],
            manufacturerID: [0; 32],
            model: [0; 16],
            serialNumber: [0; 16],
            flags: 0,
            ulMaxSessionCount: 0,
            ulSessionCount: 0,
            ulMaxRwSessionCount: 0,
            ulRwSessionCount: 0,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: 0,
            ulFreePublicMemory: 0,
            ulTotalPrivateMemory: 0,
            ulFreePrivateMemory: 0,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
            utcTime: [0; 16],
        };
        assert_eq!(
            crate::C_GetSlotInfo(slot_id, &mut slot_info),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK as CK_RV
        );
    }
    finalize_for_test();
}
