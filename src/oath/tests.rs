use super::*;
#[test]
fn utc_times_and_periods() {
    assert_eq!(parse_time(b"19700101000059").unwrap(), 59);
    assert_eq!(parse_time(b"20090213233130").unwrap(), 1234567890);
    assert!(parse_time(b"20260229000000").is_err());
    assert_eq!(
        Credential::from_name(b"60/test:account".to_vec(), 0x21)
            .unwrap()
            .period,
        60
    );
}

use std::collections::VecDeque;
#[derive(Debug)]
struct Script {
    steps: RefCell<VecDeque<(u8, Vec<u8>, ResponseApdu)>>,
    calls: Cell<usize>,
    epoch: Cell<u64>,
    role: Cell<CcidLoginState>,
    inventory: Option<Vec<u8>>,
    calculations: Cell<u32>,
}
impl Script {
    fn new(steps: Vec<(u8, Vec<u8>, ResponseApdu)>) -> Rc<Self> {
        Rc::new(Self {
            steps: RefCell::new(steps.into()),
            calls: Cell::new(0),
            epoch: Cell::new(0),
            role: Cell::new(CcidLoginState::Public),
            inventory: None,
            calculations: Cell::new(0),
        })
    }
    fn done(&self) {
        assert!(self.steps.borrow().is_empty());
    }
}
impl Connector for Script {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Test"
    }
    fn product(&self) -> &str {
        "OATH"
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
    fn connection_epoch(&self) -> u64 {
        self.epoch.get()
    }
    fn ccid_login_state(&self) -> Option<CcidLoginState> {
        Some(self.role.get())
    }
    fn set_ccid_login_state(&self, role: CcidLoginState) -> Result<(), Error> {
        self.role.set(role);
        Ok(())
    }
    fn transmit<'a>(&self, b: &[u8], out: &'a mut [u8], _: Duration) -> Result<&'a [u8], Error> {
        self.calls.set(self.calls.get() + 1);
        let command = CommandApdu::decode(b)?;
        // A passwordless device can answer LIST directly. This fixture lets
        // exported-API tests verify that the provider still gates discovery.
        if let Some(inventory) = &self.inventory {
            let data = match command.ins {
                0xa4 => selection(),
                0xa1 => inventory.clone(),
                0xa2 => {
                    self.calculations.set(self.calculations.get() + 1);
                    vec![0x76, 5, 6, 0, 0, 0, 1]
                }
                _ => panic!("unexpected OATH instruction {:02x}", command.ins),
            };
            let bytes = ok(data).encode();
            out[..bytes.len()].copy_from_slice(&bytes);
            return Ok(&out[..bytes.len()]);
        }
        let (ins, data, response) = self
            .steps
            .borrow_mut()
            .pop_front()
            .expect("unexpected APDU");
        assert_eq!(command.ins, ins);
        assert_eq!(command.data, data);
        let bytes = response.encode();
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(&out[..bytes.len()])
    }
}
fn ok(data: Vec<u8>) -> ResponseApdu {
    ResponseApdu {
        data,
        status: 0x9000,
    }
}
fn selection() -> Vec<u8> {
    vec![0x79, 3, 5, 7, 4, 0x71, 8, 1, 2, 3, 4, 5, 6, 7, 8]
}
#[test]
fn list_uses_oath_continuation_without_calculating() {
    let c = Script::new(vec![
        (
            0xa1,
            vec![],
            ResponseApdu {
                data: vec![0x72, 4, 0x21, b'a'],
                status: 0x6100,
            },
        ),
        (0xa5, vec![], ok(vec![b'b', b'c', 0x72, 2, 0x11, b'd'])),
    ]);
    let credentials = list(c.as_ref()).unwrap();
    c.done();
    assert_eq!(credentials.len(), 2);
    assert!(credentials[0].totp);
    assert!(!credentials[1].totp);
    assert_eq!(c.calls.get(), 2);
}
#[test]
fn malformed_tlv_and_duplicate_list_entries_fail() {
    for data in [
        vec![0x72],
        vec![0x72, 0x82, 0, 1, 0],
        vec![0x72, 2, 0x21, b'a', 0x72, 2, 0x21, b'a'],
        vec![0x72, 2, 0x24, b'a'],
    ] {
        let c = Script::new(vec![(0xa1, vec![], ok(data))]);
        assert!(list(c.as_ref()).is_err());
        c.done();
    }
}
#[test]
fn calculation_sends_time_step_and_formats_leading_zeros() {
    let c = Script::new(vec![(
        0xa2,
        vec![0x71, 1, b'x', 0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1],
        ok(vec![0x76, 5, 6, 0, 0, 0, 1]),
    )]);
    let credential = Credential::from_name(b"x".to_vec(), 0x21).unwrap();
    assert_eq!(
        calculate(c.as_ref(), &credential, Some(59)).unwrap(),
        b"000001"
    );
    c.done();
}
#[test]
fn transport_failure_never_replays_hotp() {
    let c = Script::new(vec![(
        0xa2,
        vec![0x71, 1, b'x', 0x74, 0],
        ResponseApdu {
            data: vec![],
            status: 0x6581,
        },
    )]);
    let credential = Credential::from_name(b"x".to_vec(), 0x11).unwrap();
    assert!(calculate(c.as_ref(), &credential, None).is_err());
    assert_eq!(c.calls.get(), 1);
    c.done();
}
#[test]
fn password_key_matches_yubico_derivation() {
    let info = Info {
        version: [5, 7, 4],
        salt: b"12345678".to_vec(),
        challenge: Some(vec![1; 8]),
    };
    let key = access_key(&info, b"password").unwrap();
    // Independent PBKDF2-HMAC-SHA1 fixture (1000 iterations, 16 bytes).
    assert_eq!(
        key.as_slice(),
        &[
            0xf5, 0x31, 0x15, 0x4d, 0x46, 0xd1, 0xbd, 0xbb, 0xcc, 0x1f, 0xcc, 0xe0, 0x2d, 0x6b,
            0x4c, 0x93
        ]
    );
}
#[test]
fn failed_password_and_forged_mutual_response_are_rejected() {
    #[derive(Debug)]
    struct Auth {
        status: u16,
        response: bool,
    }
    impl Connector for Auth {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Test"
        }
        fn product(&self) -> &str {
            "Test"
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
            1024
        }
        fn transmit<'a>(
            &self,
            b: &[u8],
            out: &'a mut [u8],
            _: Duration,
        ) -> Result<&'a [u8], Error> {
            let command = CommandApdu::decode(b)?;
            assert_eq!(command.ins, 0xa3);
            let fields = parse(&command.data)?;
            let host = field(&fields, 0x74)?.unwrap();
            let info = Info {
                version: [5, 7, 4],
                salt: b"12345678".to_vec(),
                challenge: Some(vec![1; 8]),
            };
            let key = access_key(&info, b"password")?;
            assert_eq!(
                field(&fields, 0x75)?.unwrap(),
                mac(&key, &[1; 8])?.as_slice()
            );
            let response_mac = mac(&key, host)?;
            let mut data = vec![];
            tlv(
                0x75,
                if self.response {
                    &response_mac
                } else {
                    &[0; 20]
                },
                &mut data,
            )?;
            let bytes = ResponseApdu {
                data,
                status: self.status,
            }
            .encode();
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(&out[..bytes.len()])
        }
    }
    let info = Info {
        version: [5, 7, 4],
        salt: b"12345678".to_vec(),
        challenge: Some(vec![1; 8]),
    };
    assert!(
        authenticate(
            &Auth {
                status: 0x9000,
                response: true
            },
            &info,
            b"password"
        )
        .is_ok()
    );
    assert!(
        authenticate(
            &Auth {
                status: 0x9000,
                response: false
            },
            &info,
            b"password"
        )
        .is_err()
    );
    assert!(
        authenticate(
            &Auth {
                status: 0x6a80,
                response: false
            },
            &info,
            b"password"
        )
        .is_err()
    );
    // Authentication state consists only of a connector epoch. Passwords and
    // derived keys are local temporaries in authenticate, never slot fields.
}
#[test]
fn password_protected_slot_hides_inventory_without_login() {
    let mut response = selection();
    response.extend([0x74, 8, 1, 1, 1, 1, 1, 1, 1, 1]);
    let c = Script::new(vec![(0xa4, AID.to_vec(), ok(response))]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let mut slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    slot.init_slot().unwrap();
    assert!(slot.backend_token_objects(1).unwrap().is_empty());
    assert!(!slot.login_is_active());
    c.done();
}

#[test]
fn passwordless_slot_requires_login_for_inventory_and_device_operations() {
    let c = Script::new(vec![
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa1, vec![], ok(vec![0x72, 2, 0x11, b'x'])),
        (
            0xa2,
            vec![0x71, 1, b'x', 0x74, 0],
            ok(vec![0x76, 5, 6, 0, 0, 0, 1]),
        ),
    ]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let mut slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    let credential = Credential::from_name(b"x".to_vec(), 0x11).unwrap();
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    slot.get_token_info(&mut info).unwrap();
    assert_ne!(info.flags & CKF_LOGIN_REQUIRED as CK_FLAGS, 0);
    assert_ne!(info.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS, 0);
    assert_eq!(info.ulMinPinLen, 0);
    assert!(slot.backend_token_objects(1).unwrap().is_empty());
    assert!(
        matches!(slot.oath_calculate(&credential, None), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    assert!(
        matches!(slot.oath_delete(b"x"), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    let prompt = pinentry::Pinentry::unconfigured();
    assert!(
        matches!(slot.login(Some(b"wrong"), &prompt), Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as CK_RV)
    );
    assert!(!slot.login_is_active());
    slot.login(Some(b""), &prompt).unwrap();
    slot.set_login_role(Some(LoginRole::User)).unwrap();
    let keys = slot.backend_token_objects(1).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .all(|key| key.private && key.sensitive && !key.extractable)
    );
    assert_eq!(slot.oath_calculate(&credential, None).unwrap(), b"000001");
    slot.logout().unwrap();
    assert!(slot.backend_token_objects(1).unwrap().is_empty());
    assert!(
        matches!(slot.oath_calculate(&credential, None), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    assert!(
        matches!(slot.oath_delete(b"x"), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    c.done();
}

#[test]
fn otp_signing_and_import_require_user_authorization_even_without_a_device_password() {
    let c = Script::new(vec![(0xa4, AID.to_vec(), ok(selection()))]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    let mut ctx = SlotContext::new(
        1,
        Box::new(slot),
        Vec::new(),
        Arc::new(crate::HandleCounters::new()),
        Arc::new(pinentry::Pinentry::unconfigured()),
        Arc::new(crate::yubihsm::trust::TrustStore::new_with_prefix(
            std::ffi::OsString::new(),
        )),
    )
    .unwrap();
    let backend = ctx
        .slot
        .open_session(1, (CKF_RW_SESSION | CKF_SERIAL_SESSION) as _);
    ctx.sessions
        .insert(1, crate::context::SessionContext::new(backend));
    let credential = Credential::from_name(b"test".to_vec(), 0x11).unwrap();
    let key = ctx.insert_object(object(1, credential)).unwrap();
    let mechanism = CK_MECHANISM {
        mechanism: CKM_HOTP as _,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert!(
        matches!(sign_init(&mut ctx, 1, &mechanism, key), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    fn attr<T>(type_: CK_ATTRIBUTE_TYPE, value: &T) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_,
            pValue: ptr::from_ref(value).cast_mut().cast(),
            ulValueLen: std::mem::size_of::<T>() as _,
        }
    }
    let class = CKO_OTP_KEY as CK_OBJECT_CLASS;
    let kind = CKK_HOTP as CK_KEY_TYPE;
    let token = CK_TRUE as CK_BBOOL;
    let private = CK_FALSE as CK_BBOOL;
    let mut template = vec![
        attr(CKA_CLASS as _, &class),
        attr(CKA_KEY_TYPE as _, &kind),
        attr(CKA_TOKEN as _, &token),
        attr(CKA_LABEL as _, b"new"),
        attr(CKA_VALUE as _, b"12345678901234567890"),
    ];
    {
        let SlotContext { slot, state } = &mut ctx;
        assert!(
            matches!(slot.create_object(state, 1, &template), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
        );
    }
    ctx.slot
        .login(Some(b""), &pinentry::Pinentry::unconfigured())
        .unwrap();
    ctx.slot.set_login_role(Some(LoginRole::User)).unwrap();
    ctx.set_login_role_state(1, Some(LoginRole::User), "test login");
    sign_init(&mut ctx, 1, &mechanism, key).unwrap();
    template.push(attr(CKA_PRIVATE as _, &private));
    {
        let SlotContext { slot, state } = &mut ctx;
        assert!(
            matches!(slot.create_object(state, 1, &template), Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCONSISTENT as CK_RV)
        );
    }
    let operation = ctx
        .get_session_context(1)
        .unwrap()
        .sign_operation
        .clone()
        .unwrap();
    // Losing the connection between SignInit and Sign must prevent CALCULATE,
    // even if the PKCS #11 role has not yet been reconciled.
    c.epoch.set(1);
    let mut output = [0u8; 128];
    let mut length = output.len() as CK_ULONG;
    assert!(
        matches!(sign(&mut ctx, &operation, &[], output.as_mut_ptr(), &mut length), Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as CK_RV)
    );
    c.done();
}
#[test]
fn inventory_lookup_reuses_list_until_refresh_and_rejects_a_lost_login() {
    let c = Script::new(vec![
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa1, vec![], ok(vec![0x72, 2, 0x11, b'x'])),
        (0xa1, vec![], ok(vec![0x72, 2, 0x22, b'y'])),
    ]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let mut slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    slot.login(Some(b""), &pinentry::Pinentry::unconfigured())
        .unwrap();
    slot.set_login_role(Some(LoginRole::User)).unwrap();
    let original = slot.backend_token_objects(1).unwrap();
    assert_eq!(original.len(), 2); // The two SHA1 HOTP views.
    let calls = c.calls.get();
    for object in &original {
        assert!(
            slot.backend_token_object(1, &object.unique_id)
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(c.calls.get(), calls);
    let refreshed = slot.backend_token_objects(1).unwrap();
    assert_eq!(refreshed.len(), 1);
    for object in original {
        assert!(
            slot.backend_token_object(1, &object.unique_id)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        slot.backend_token_object(1, &refreshed[0].unique_id)
            .unwrap()
            .is_some()
    );
    c.epoch.set(1);
    assert!(
        slot.backend_token_object(1, &refreshed[0].unique_id)
            .unwrap()
            .is_none()
    );
    c.done();
}

#[test]
fn public_api_oath_inventory_and_signing_follow_token_wide_user_login() {
    use crate::pkcs11_auth::Pkcs11Auth;
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};

    let mut connector = Script::new(Vec::new());
    Rc::get_mut(&mut connector).unwrap().inventory =
        Some(vec![0x72, 2, 0x11, b'x', 0x72, 2, 0x22, b't']);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(
        connector.as_ref(),
    ));
    let slot = crate::backend::OathSlot::new(connector.clone(), AID.to_vec(), device);
    let provider = Pkcs11Provider::new(Box::new(slot)).unwrap();
    let first = ProviderSession::open(provider.clone()).unwrap();
    let second = ProviderSession::open(provider.clone()).unwrap();
    let class = (CKO_OTP_KEY as CK_OBJECT_CLASS).to_ne_bytes();
    let find = |session: &ProviderSession| session.find(&[(CKA_CLASS, &class)]).unwrap();
    assert!(find(&first).is_empty());
    assert!(find(&second).is_empty());
    let mut empty = [0u8];
    assert_eq!(
        first.call(|| crate::api::C_LoginUser(
            first.handle,
            CKU_USER as _,
            empty.as_mut_ptr(),
            0,
            ptr::null_mut(),
            0,
        )),
        CKR_OK as CK_RV
    );
    let keys = find(&second);
    assert_eq!(keys.len(), 3); // SHA1 HOTP has two views, plus SHA256 TOTP.
    let inventory_calls = connector.calls.get();
    for key in &keys {
        assert_eq!(
            second.attribute(*key, CKA_PRIVATE).unwrap().as_slice(),
            &[1]
        );
        assert_eq!(
            second.attribute(*key, CKA_SENSITIVE).unwrap().as_slice(),
            &[1]
        );
        assert_eq!(
            second.attribute(*key, CKA_EXTRACTABLE).unwrap().as_slice(),
            &[0]
        );
        assert!(
            !second
                .attribute(*key, CKA_PKCS11RS_OATH_HASH as _)
                .unwrap()
                .is_empty()
        );
        assert!(
            !second
                .attribute(*key, CKA_ALLOWED_MECHANISMS)
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        connector.calls.get(),
        inventory_calls,
        "Reading OATH inventory attributes must not issue more APDUs"
    );
    let key = second
        .find(&[
            (CKA_CLASS, &class),
            (CKA_KEY_TYPE, &(CKK_HOTP as CK_KEY_TYPE).to_ne_bytes()),
        ])
        .unwrap()[0];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_HOTP as _,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        second.call(|| crate::api::C_SignInit(second.handle, &mut mechanism, key)),
        CKR_OK as CK_RV
    );
    let mut length = 0;
    assert_eq!(
        second.call(|| crate::api::C_Sign(
            second.handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut length
        )),
        CKR_OK as CK_RV
    );
    assert_eq!(connector.calculations.get(), 0);
    assert_eq!(
        first.call(|| crate::api::C_Logout(first.handle)),
        CKR_OK as CK_RV
    );
    assert!(find(&first).is_empty());
    assert!(find(&second).is_empty());
    let mut output = [0u8; 128];
    length = output.len() as _;
    assert_ne!(
        second.call(|| crate::api::C_Sign(
            second.handle,
            ptr::null_mut(),
            0,
            output.as_mut_ptr(),
            &mut length
        )),
        CKR_OK as CK_RV
    );
    assert_eq!(connector.calculations.get(), 0);
    first.login(&[]).unwrap();
    let key = second
        .find(&[(CKA_KEY_TYPE, &(CKK_HOTP as CK_KEY_TYPE).to_ne_bytes())])
        .unwrap()[0];
    assert_eq!(
        second.call(|| crate::api::C_SignInit(second.handle, &mut mechanism, key)),
        CKR_OK as CK_RV
    );
    assert_eq!(
        second.call(|| crate::api::C_Sign(
            second.handle,
            ptr::null_mut(),
            0,
            output.as_mut_ptr(),
            &mut length
        )),
        CKR_OK as CK_RV
    );
    assert_eq!(connector.calculations.get(), 1);
    drop(first);
    drop(second); // Last-session close clears authorization too.
    let reopened = ProviderSession::open(provider).unwrap();
    assert!(find(&reopened).is_empty());
}

#[test]
fn otp_attributes_are_sensitive_and_restrict_mechanisms() {
    let c = Credential::from_name(b"issuer:account".to_vec(), 0x11).unwrap();
    let key = object(1, c);
    assert!(key.is_key_object());
    assert_eq!(key.attribute_value(CKA_PRIVATE as _), Some(vec![1]));
    assert!(!key.is_visible_to(false));
    assert!(key.is_visible_to(true));
    assert!(key.attribute_is_sensitive(CKA_VALUE as _));
    assert_eq!(key.attribute_value(CKA_EXTRACTABLE as _), Some(vec![0]));
    assert_eq!(key.attribute_value(CKA_DESTROYABLE as _), Some(vec![1]));
    assert_eq!(
        crate::key_mechanisms::operations(&key, CKM_HOTP as _),
        CKF_SIGN as CK_FLAGS
    );
    assert_eq!(
        crate::key_mechanisms::operations(&key, CKM_SHA_1_HMAC as _),
        0
    );
}
#[test]
fn discovered_hotp_keys_separate_standard_sha1_and_vendor_sha2_mechanisms() {
    for (hash, key_type, mechanism) in [
        (1, CKK_HOTP as CK_KEY_TYPE, CKM_HOTP as CK_MECHANISM_TYPE),
        (2, CKK_PKCS11RS_HOTP, CKM_PKCS11RS_HOTP),
        (3, CKK_PKCS11RS_HOTP, CKM_PKCS11RS_HOTP),
    ] {
        let credential = Credential::from_name(b"existing".to_vec(), 0x10 | hash).unwrap();
        let key = object(1, credential);
        assert_eq!(key.key_type, key_type);
        assert!(key.sign);
        assert_eq!(key.allowed_mechanisms, Some(vec![mechanism]));
        for candidate in [
            CKM_HOTP as CK_MECHANISM_TYPE,
            CKM_PKCS11RS_HOTP,
            CKM_PKCS11RS_TOTP,
        ] {
            assert_eq!(
                crate::key_mechanisms::operations(&key, candidate),
                if candidate == mechanism {
                    CKF_SIGN as CK_FLAGS
                } else {
                    0
                }
            );
        }
    }
}

fn import_hotp(kind: CK_KEY_TYPE, hash: Option<CK_MECHANISM_TYPE>) -> Result<Credential, Error> {
    fn attr<T>(type_: CK_ATTRIBUTE_TYPE, value: &T) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_,
            pValue: ptr::from_ref(value).cast_mut().cast(),
            ulValueLen: std::mem::size_of::<T>() as CK_ULONG,
        }
    }
    let class = CKO_OTP_KEY as CK_OBJECT_CLASS;
    let token = CK_TRUE as CK_BBOOL;
    let secret = *b"12345678901234567890";
    let name = *b"test";
    let mut template = vec![
        attr(CKA_CLASS as _, &class),
        attr(CKA_KEY_TYPE as _, &kind),
        attr(CKA_TOKEN as _, &token),
        attr(CKA_LABEL as _, &name),
        attr(CKA_VALUE as _, &secret),
    ];
    if let Some(hash) = hash.as_ref() {
        template.push(attr(CKA_PKCS11RS_OATH_HASH, hash));
    }
    import_template(&template).map(|(credential, _, _)| credential)
}

#[test]
fn extended_hotp_import_accepts_all_hashes_with_an_explicit_hash_attribute() {
    for (hash, algorithm) in [
        (CKM_SHA_1 as CK_MECHANISM_TYPE, 1),
        (CKM_SHA256 as _, 2),
        (CKM_SHA512 as _, 3),
    ] {
        let credential = import_hotp(CKK_PKCS11RS_HOTP, Some(hash)).unwrap();
        assert!(!credential.totp);
        assert_eq!(credential.hash, algorithm);
        assert_eq!(credential.mechanism(), CKM_PKCS11RS_HOTP);
        assert_eq!(credential.key_type(), CKK_PKCS11RS_HOTP);
        if algorithm != 1 {
            assert!(
                matches!(import_hotp(CKK_HOTP as _, Some(hash)), Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCONSISTENT as CK_RV)
            );
        }
    }
    assert!(
        matches!(import_hotp(CKK_PKCS11RS_HOTP, None), Err(Error::Generic(rv)) if rv == CKR_TEMPLATE_INCOMPLETE as CK_RV)
    );
    let standard = import_hotp(CKK_HOTP as _, None).unwrap();
    assert_eq!(standard.hash, 1);
    assert_eq!(standard.key_type(), CKK_HOTP as CK_KEY_TYPE);
    assert_eq!(standard.mechanism(), CKM_HOTP as CK_MECHANISM_TYPE);
}

#[test]
fn vendor_hotp_ignores_time_without_using_the_host_clock() {
    let mut item = CK_OTP_PARAM {
        type_: CK_OTP_TIME as _,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    };
    let mut params = CK_OTP_PARAMS {
        pParams: &mut item,
        ulCount: 1,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_PKCS11RS_HOTP,
        pParameter: ptr::from_mut(&mut params).cast(),
        ulParameterLen: std::mem::size_of_val(&params) as _,
    };
    assert_eq!(parameters(&mechanism).unwrap(), None);
}

#[test]
fn standard_parameters_ignore_parameters_marked_ignored() {
    let mut params = CK_OTP_PARAMS {
        pParams: ptr::null_mut(),
        ulCount: 0,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_HOTP as _,
        pParameter: (&mut params as *mut CK_OTP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of_val(&params) as _,
    };
    assert_eq!(parameters(&mechanism).unwrap(), None);
    let mut counter = [0u8; 8];
    let mut item = CK_OTP_PARAM {
        type_: CK_OTP_COUNTER as _,
        pValue: counter.as_mut_ptr().cast(),
        ulValueLen: 8,
    };
    params.pParams = &mut item;
    params.ulCount = 1;
    let mechanism = CK_MECHANISM {
        pParameter: (&mut params as *mut CK_OTP_PARAMS).cast(),
        ..mechanism
    };
    assert_eq!(parameters(&mechanism).unwrap(), None);
}

#[test]
fn login_state_does_not_survive_applet_deselection_reconnection_or_logout() {
    let c = Script::new(vec![
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa4, AID.to_vec(), ok(selection())),
    ]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let mut slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    let prompt = pinentry::Pinentry::unconfigured();
    slot.login(Some(b""), &prompt).unwrap();
    slot.set_login_role(Some(LoginRole::User)).unwrap();
    assert!(slot.login_is_active());
    c.role.set(CcidLoginState::Public);
    assert!(!slot.login_is_active());
    slot.clear_lost_login();
    slot.login(Some(b""), &prompt).unwrap();
    slot.set_login_role(Some(LoginRole::User)).unwrap();
    assert!(slot.login_is_active());
    c.epoch.set(1);
    assert!(!slot.login_is_active());
    slot.logout().unwrap();
    assert!(!slot.login_is_active());
    c.done();
}

#[test]
fn sha1_hotp_discovery_offers_standard_and_extended_views_of_one_credential() {
    let c = Script::new(vec![
        (0xa4, AID.to_vec(), ok(selection())),
        (0xa1, vec![], ok(vec![0x72, 2, 0x11, b'x'])),
    ]);
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(c.as_ref()));
    let mut slot = crate::backend::OathSlot::new(c.clone(), AID.to_vec(), device);
    slot.login(Some(b""), &pinentry::Pinentry::unconfigured())
        .unwrap();
    slot.set_login_role(Some(LoginRole::User)).unwrap();
    let objects = slot.backend_token_objects(1).unwrap();
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].id, objects[1].id);
    assert_eq!(objects[0].label, objects[1].label);
    assert_ne!(objects[0].unique_id, objects[1].unique_id);
    assert_eq!(objects[0].key_type, CKK_HOTP as CK_KEY_TYPE);
    assert_eq!(
        objects[0].allowed_mechanisms,
        Some(vec![CKM_HOTP as CK_MECHANISM_TYPE])
    );
    assert_eq!(objects[1].key_type, CKK_PKCS11RS_HOTP);
    assert_eq!(objects[1].allowed_mechanisms, Some(vec![CKM_PKCS11RS_HOTP]));
    c.done();
}
