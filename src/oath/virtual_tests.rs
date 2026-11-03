//! Interoperability with the actual shared card core, never physical hardware.
use super::*;
use crate::embedded_virtual_yubikey::EmbeddedVirtualYubiKeyConnector;
use crate::pkcs11_auth::Pkcs11Auth;
use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
use crate::scp03::{Scp03KeySet, Scp03Session, YUBIKEY_SECURITY_LEVEL};
use crate::scp11::Scp11KeySet;
use crate::security_domain::KeyRef;
use virtual_yubikey_core::{AppletConfiguration, DeviceProfile, ISSUER_SECURITY_DOMAIN_AID};

#[derive(Debug)]
struct Channel {
    base: EmbeddedVirtualYubiKeyConnector,
    session: RefCell<Option<Scp03Session>>,
}
impl Connector for Channel {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Test"
    }
    fn product(&self) -> &str {
        "Embedded OATH"
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        8
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn transmit<'a>(
        &self,
        data: &[u8],
        out: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        self.base.transmit(data, out, timeout)
    }
    fn send_oath_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
        match self.session.borrow_mut().as_mut() {
            Some(session) => session.transmit_oath(&self.base, command),
            None => self.base.send_oath_apdu(command),
        }
    }
}
fn credential(name: &[u8], hash: u8, totp: bool) -> Credential {
    let mut c =
        Credential::from_name(name.to_vec(), (if totp { 0x20 } else { 0x10 }) | hash).unwrap();
    c.digits = Some(if totp { 8 } else { 6 });
    c.touch = Some(false);
    c
}
const TIMES: [u64; 6] = [
    59,
    1111111109,
    1111111111,
    1234567890,
    2000000000,
    20000000000,
];
const TOTP: [[&[u8]; 6]; 3] = [
    [
        b"94287082",
        b"07081804",
        b"14050471",
        b"89005924",
        b"69279037",
        b"65353130",
    ],
    [
        b"46119246",
        b"68084774",
        b"67062674",
        b"91819424",
        b"90698825",
        b"77737706",
    ],
    [
        b"90693936",
        b"25091201",
        b"99943326",
        b"93441116",
        b"38618901",
        b"47863826",
    ],
];
const HOTP: [[&[u8]; 10]; 3] = [
    [
        b"755224", b"287082", b"359152", b"969429", b"338314", b"254676", b"287922", b"162583",
        b"399871", b"520489",
    ],
    [
        b"875740", b"247374", b"254785", b"496144", b"480556", b"697997", b"191609", b"579288",
        b"895912", b"184989",
    ],
    [
        b"125165", b"342147", b"730102", b"778726", b"937510", b"848329", b"266680", b"588359",
        b"039399", b"643409",
    ],
];
fn secret(hash: u8) -> &'static [u8] {
    match hash {
        1 => b"12345678901234567890",
        2 => b"12345678901234567890123456789012",
        _ => b"1234567890123456789012345678901234567890123456789012345678901234",
    }
}

#[test]
fn embedded_oath_vectors_password_and_continuation_plain_scp03_scp11b() {
    for mode in 0..3 {
        let base = EmbeddedVirtualYubiKeyConnector::new().unwrap();
        let scp11 = if mode == 2 {
            select_application(&base, &ISSUER_SECURITY_DOMAIN_AID).unwrap();
            let certs = SecurityDomainClient
                .get_certificate_bundle(&base, KeyRef { kid: 0x13, kvn: 1 })
                .unwrap();
            Some(Scp11KeySet::scp11b_from_certificates(1, &certs[1..], &certs[..1]).unwrap())
        } else {
            None
        };
        let info = select(&base, &AID).unwrap();
        change_password(&base, &info, b"test password").unwrap();
        let info = select(&base, &AID).unwrap();
        let session = match mode {
            1 => Some(
                Scp03Session::authenticate_selected(
                    &base,
                    &Scp03KeySet::yubikey_factory(),
                    YUBIKEY_SECURITY_LEVEL,
                    &AID,
                )
                .unwrap(),
            ),
            2 => Some(scp11.unwrap().authenticate_selected(&base).unwrap()),
            _ => None,
        };
        let channel = Channel {
            base,
            session: RefCell::new(session),
        };
        assert!(list(&channel).is_err());
        authenticate(&channel, &info, b"test password").unwrap();
        qualify_channel(&channel);
        change_password(&channel, &info, b"").unwrap();
    }
}

fn provider(connector: Rc<dyn Connector>) -> Arc<Pkcs11Provider> {
    let device = Arc::new(crate::device::DeviceContext::from_endpoint(
        connector.as_ref(),
    ));
    Pkcs11Provider::new(Box::new(crate::backend::OathSlot::new(
        connector,
        AID.to_vec(),
        device,
    )))
    .unwrap()
}
fn create(
    session: &ProviderSession,
    name: &[u8],
    hash: u8,
    totp: bool,
    touch: bool,
) -> CK_OBJECT_HANDLE {
    let mut values = [
        (
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            (CKO_OTP_KEY as CK_ULONG).to_ne_bytes().to_vec(),
        ),
        (
            CKA_KEY_TYPE as _,
            (if totp {
                CKK_PKCS11RS_TOTP
            } else {
                CKK_PKCS11RS_HOTP
            })
            .to_ne_bytes()
            .to_vec(),
        ),
        (CKA_TOKEN as _, vec![1]),
        (CKA_LABEL as _, name.to_vec()),
        (
            CKA_VALUE as _,
            if totp {
                secret(hash).to_vec()
            } else {
                b"12345678901234567890".to_vec()
            },
        ),
        (
            CKA_OTP_LENGTH as _,
            (if totp { 8 as CK_ULONG } else { 6 })
                .to_ne_bytes()
                .to_vec(),
        ),
        (
            CKA_PKCS11RS_OATH_HASH,
            (match hash {
                1 => CKM_SHA_1 as CK_ULONG,
                2 => CKM_SHA256 as _,
                _ => CKM_SHA512 as _,
            })
            .to_ne_bytes()
            .to_vec(),
        ),
        (CKA_PKCS11RS_OATH_TOUCH_REQUIRED, vec![u8::from(touch)]),
    ];
    let mut attrs: Vec<_> = values
        .iter_mut()
        .map(|(kind, value)| CK_ATTRIBUTE {
            type_: *kind,
            pValue: value.as_mut_ptr().cast(),
            ulValueLen: value.len() as _,
        })
        .collect();
    let mut handle = 0;
    assert_eq!(
        session.call(|| api::C_CreateObject(
            session.handle,
            attrs.as_mut_ptr(),
            attrs.len() as _,
            &mut handle
        )),
        CKR_OK as CK_RV
    );
    handle
}
fn sign(
    session: &ProviderSession,
    key: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    time: Option<&[u8]>,
) -> Vec<u8> {
    let mut param = CK_OTP_PARAM {
        type_: CK_OTP_TIME as _,
        pValue: time.map_or(ptr::null_mut(), |v| v.as_ptr().cast_mut().cast()),
        ulValueLen: time.map_or(0, |v| v.len()) as _,
    };
    let mut params = CK_OTP_PARAMS {
        pParams: &mut param,
        ulCount: u64::from(time.is_some()) as _,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism,
        pParameter: (&mut params as *mut CK_OTP_PARAMS).cast(),
        ulParameterLen: std::mem::size_of_val(&params) as _,
    };
    assert_eq!(
        session.call(|| api::C_SignInit(session.handle, &mut mechanism, key)),
        CKR_OK as CK_RV
    );
    let mut len = 0;
    for _ in 0..3 {
        assert_eq!(
            session.call(|| api::C_Sign(
                session.handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut len
            )),
            CKR_OK as CK_RV
        );
    }
    let mut out = vec![0; len as usize];
    let mut short = len - 1;
    assert_eq!(
        session.call(|| api::C_Sign(
            session.handle,
            ptr::null_mut(),
            0,
            out.as_mut_ptr(),
            &mut short
        )),
        CKR_BUFFER_TOO_SMALL as CK_RV
    );
    assert_eq!(
        session.call(|| api::C_Sign(
            session.handle,
            ptr::null_mut(),
            0,
            out.as_mut_ptr(),
            &mut len
        )),
        CKR_OK as CK_RV
    );
    let info = unsafe { ptr::read_unaligned(out.as_ptr().cast::<CK_OTP_SIGNATURE_INFO>()) };
    assert_eq!(info.ulCount, 1);
    let param = unsafe { ptr::read_unaligned(info.pParams) };
    assert_eq!(param.type_, CK_OTP_VALUE as CK_ULONG);
    unsafe { std::slice::from_raw_parts(param.pValue.cast::<u8>(), param.ulValueLen as usize) }
        .to_vec()
}

#[test]
fn embedded_oath_pkcs11_import_visibility_vectors_shared_views_and_deletion() {
    let base = Rc::new(EmbeddedVirtualYubiKeyConnector::new().unwrap());
    let provider = provider(base.clone());
    let session = ProviderSession::open(provider.clone()).unwrap();
    let class = (CKO_OTP_KEY as CK_ULONG).to_ne_bytes();
    assert!(session.find(&[(CKA_CLASS, &class)]).unwrap().is_empty());
    session.login(b"").unwrap();
    let dates = [
        b"19700101000059",
        b"20050318015829",
        b"20050318015831",
        b"20090213233130",
        b"20330518033320",
        b"26031011113320",
    ];
    for hash in 1..=3 {
        let hotp = create(&session, &[b'h', hash], hash, false, false);
        for expected in HOTP[hash as usize - 1] {
            assert_eq!(sign(&session, hotp, CKM_PKCS11RS_HOTP, None), expected);
        }
        let totp = create(&session, &[b't', hash], hash, true, false);
        for (date, expected) in dates.into_iter().zip(TOTP[hash as usize - 1]) {
            assert_eq!(
                sign(&session, totp, CKM_PKCS11RS_TOTP, Some(date)),
                expected
            );
        }
        assert_eq!(
            session.attribute(totp, CKA_PRIVATE).unwrap().as_slice(),
            [1]
        );
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_VALUE as _,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            session.call(|| api::C_GetAttributeValue(session.handle, totp, &mut attr, 1)),
            CKR_ATTRIBUTE_SENSITIVE as CK_RV
        );
    }
    assert_eq!(session.find(&[(CKA_CLASS, &class)]).unwrap().len(), 7);
    let id = [b'h', 1];
    let views = session.find(&[(CKA_ID, &id)]).unwrap();
    assert_eq!(views.len(), 2);
    // Both logical SHA1 views consume the one persistent card counter (10, 11).
    let legacy = session
        .find(&[
            (CKA_ID, &id),
            (CKA_KEY_TYPE, &(CKK_HOTP as CK_KEY_TYPE).to_ne_bytes()),
        ])
        .unwrap()[0];
    let extended = session
        .find(&[
            (CKA_ID, &id),
            (CKA_KEY_TYPE, &CKK_PKCS11RS_HOTP.to_ne_bytes()),
        ])
        .unwrap()[0];
    assert_eq!(sign(&session, legacy, CKM_HOTP as _, None), b"403154");
    assert_eq!(sign(&session, extended, CKM_PKCS11RS_HOTP, None), b"481090");
    assert_eq!(
        session.call(|| api::C_DestroyObject(session.handle, legacy)),
        CKR_OK as CK_RV
    );
    assert!(session.find(&[(CKA_ID, &id)]).unwrap().is_empty());
    assert_eq!(
        session.call(|| api::C_Logout(session.handle)),
        CKR_OK as CK_RV
    );
    assert!(session.find(&[(CKA_CLASS, &class)]).unwrap().is_empty());
    session.login(b"").unwrap();
    assert_eq!(session.find(&[(CKA_CLASS, &class)]).unwrap().len(), 5);
    drop(session);
    let reopened = ProviderSession::open(provider).unwrap();
    assert!(reopened.find(&[(CKA_CLASS, &class)]).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn embedded_oath_persistent_reader_password_and_hotp_survive_restart() {
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!("pkcs11-oath-{:x}", u64::from_ne_bytes(nonce)));
    let open = || {
        EmbeddedVirtualYubiKeyConnector::configured(
            "OATH test".into(),
            42,
            AppletConfiguration::yubikey_5_8_preview_sign(),
            Some(root.clone()),
        )
        .unwrap()
    };
    {
        let base = Rc::new(open());
        let info = select(base.as_ref(), &AID).unwrap();
        change_password(base.as_ref(), &info, b"first password").unwrap();
        let provider = provider(base.clone());
        let session = ProviderSession::open(provider).unwrap();
        assert!(session.login(b"wrong").is_err());
        session.login(b"first password").unwrap();
        let key = create(&session, b"persistent", 1, false, false);
        assert_eq!(sign(&session, key, CKM_PKCS11RS_HOTP, None), b"755224");
        let mut persisted =
            virtual_yubikey_core::VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
        persisted
            .restore_oath_persistent_state(&std::fs::read(root.join("oath-42.cbor")).unwrap())
            .unwrap();
        let persisted = EmbeddedVirtualYubiKeyConnector::from_device(persisted);
        let info = select(&persisted, &AID).unwrap();
        authenticate(&persisted, &info, b"first password").unwrap();
        assert_eq!(
            calculate(&persisted, &credential(b"persistent", 1, false), None).unwrap(),
            b"287082"
        );
        assert_eq!(
            session.call(|| api::C_SetPIN(
                session.handle,
                b"first password".as_ptr().cast_mut(),
                14,
                b"second password".as_ptr().cast_mut(),
                15
            )),
            CKR_OK as CK_RV
        );
        assert!(session.login(b"first password").is_err());
        session.login(b"second password").unwrap();
    }
    {
        let base = Rc::new(open());
        let provider = provider(base);
        let session = ProviderSession::open(provider).unwrap();
        assert!(session.find(&[(CKA_ID, b"persistent")]).unwrap().is_empty());
        session.login(b"second password").unwrap();
        let key = session
            .find(&[
                (CKA_ID, b"persistent"),
                (CKA_KEY_TYPE, &CKK_PKCS11RS_HOTP.to_ne_bytes()),
            ])
            .unwrap()[0];
        assert_eq!(sign(&session, key, CKM_PKCS11RS_HOTP, None), b"287082");
        assert_eq!(
            session.call(|| api::C_SetPIN(
                session.handle,
                b"second password".as_ptr().cast_mut(),
                15,
                b"".as_ptr().cast_mut(),
                0
            )),
            CKR_OK as CK_RV
        );
        session.login(b"").unwrap();
        assert_eq!(
            session.call(|| api::C_DestroyObject(session.handle, key)),
            CKR_OK as CK_RV
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

const INITIAL: [&[u8]; 3] = [b"78611215", b"35189769", b"56006630"];

fn qualify_channel(channel: &dyn Connector) {
    for hash in 1..=3 {
        let c = credential(&[b't', hash], hash, true);
        put(channel, &c, secret(hash), 0).unwrap();
        for (time, expected) in TIMES.into_iter().zip(TOTP[hash as usize - 1]) {
            assert_eq!(
                calculate(channel, &c, Some(time)).unwrap(),
                expected,
                "hash {hash}"
            );
        }
        let c = credential(&[b'h', hash], hash, false);
        put(channel, &c, b"12345678901234567890", 0).unwrap();
        for expected in HOTP[hash as usize - 1] {
            assert_eq!(calculate(channel, &c, None).unwrap(), expected);
        }
        let mut c = c.clone();
        c.digits = Some(8);
        put(channel, &c, b"12345678901234567890", 12345).unwrap();
        assert_eq!(
            calculate(channel, &c, None).unwrap(),
            INITIAL[hash as usize - 1]
        );
    }
    // A logical response spanning several APDUs must be collected before R-MAC verification.
    for index in 0..20 {
        let name = format!("continuation-{index:02}-{}", "x".repeat(40));
        put(channel, &credential(name.as_bytes(), 1, true), &[3; 14], 0).unwrap();
    }
    assert_eq!(list(channel).unwrap().len(), 26);
    let mut touch = credential(b"touch", 1, false);
    touch.touch = Some(true);
    put(channel, &touch, &[2; 14], 0).unwrap();
    assert!(
        matches!(calculate(channel, &touch, None), Err(Error::Generic(rv)) if rv == CKR_FUNCTION_CANCELED as CK_RV)
    );
    // CALCULATE ALL also fragments and must leave HOTP/touch credentials untouched.
    let mut request = Vec::new();
    tlv(0x74, &1u64.to_be_bytes(), &mut request).unwrap();
    let result = command(channel, 0xa4, 0, 1, request).unwrap();
    let fields = parse(&result).unwrap();
    assert_eq!(fields.iter().filter(|(tag, _)| *tag == 0x71).count(), 27);
    assert_eq!(fields.iter().filter(|(tag, _)| *tag == 0x77).count(), 4);
    delete(channel, b"touch").unwrap();
    for c in list(channel).unwrap() {
        delete(channel, &c.name).unwrap();
    }
    assert!(list(channel).unwrap().is_empty());
}

pub(crate) fn qualify_scp11(base: EmbeddedVirtualYubiKeyConnector, keys: &Scp11KeySet) {
    let info = select(&base, &AID).unwrap();
    change_password(&base, &info, b"test password").unwrap();
    let info = select(&base, &AID).unwrap();
    let session = keys.authenticate_selected(&base).unwrap();
    let channel = Channel {
        base,
        session: RefCell::new(Some(session)),
    };
    authenticate(&channel, &info, b"test password").unwrap();
    qualify_channel(&channel);
    change_password(&channel, &info, b"").unwrap();
}

#[test]
fn embedded_oath_provider_uses_common_scp_login_password_change_and_deselection() {
    for protocol in [SecureChannelProtocol::Scp03, SecureChannelProtocol::Scp11b] {
        let device = virtual_yubikey_core::VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(1));
        let public = device.scp11b_public_key();
        let base = Arc::new(EmbeddedVirtualYubiKeyConnector::from_device(device));
        let info = select(base.as_ref(), &AID).unwrap();
        change_password(base.as_ref(), &info, b"test password").unwrap();
        let mut configuration = SecureChannelConfiguration::for_test();
        configuration.scp11.trust =
            crate::configuration::Scp11TrustConfiguration::PublicKey(public);
        let state = Arc::new(PcscReaderState::default());
        let connector = PcscAppletConnector::new_configured(
            base.clone(),
            &AID,
            Some(protocol),
            state.clone(),
            Arc::new(configuration),
            Arc::new(pinentry::Pinentry::unconfigured()),
        );
        let provider = provider(Rc::new(connector.clone()));
        let session = ProviderSession::open(provider).unwrap();
        assert!(session.login(b"wrong password").is_err());
        session.login(b"test password").unwrap();
        let key = create(&session, b"common-login", 1, false, false);
        assert_eq!(sign(&session, key, CKM_PKCS11RS_HOTP, None), b"755224");
        assert_eq!(
            session.call(|| api::C_SetPIN(
                session.handle,
                b"test password".as_ptr().cast_mut(),
                13,
                b"new password".as_ptr().cast_mut(),
                12
            )),
            CKR_OK as CK_RV
        );
        session.login(b"new password").unwrap();
        let key = session
            .find(&[
                (CKA_ID, b"common-login"),
                (CKA_KEY_TYPE, &CKK_PKCS11RS_HOTP.to_ne_bytes()),
            ])
            .unwrap()[0];
        assert_eq!(sign(&session, key, CKM_PKCS11RS_HOTP, None), b"287082");
        let other = PcscAppletConnector::new(base, &ISSUER_SECURITY_DOMAIN_AID, None, state);
        select_application(&other, &ISSUER_SECURITY_DOMAIN_AID).unwrap();
        assert!(
            session
                .find(&[(CKA_ID, b"common-login")])
                .unwrap()
                .is_empty()
        );
        session.login(b"new password").unwrap();
        let key = session
            .find(&[
                (CKA_ID, b"common-login"),
                (CKA_KEY_TYPE, &CKK_PKCS11RS_HOTP.to_ne_bytes()),
            ])
            .unwrap()[0];
        assert_eq!(sign(&session, key, CKM_PKCS11RS_HOTP, None), b"359152");
    }
}
