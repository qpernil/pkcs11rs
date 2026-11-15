//! Card-level regressions through the provider and the real virtual card core.
use crate::embedded_virtual_yubikey::EmbeddedVirtualYubiKeyConnector;
use crate::pkcs11_auth::Pkcs11Auth;
use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
use crate::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use virtual_yubikey_core::{DeviceProfile, ISSUER_SECURITY_DOMAIN_AID as SD, VirtualYubiKey};

#[derive(Debug)]
struct Card {
    inner: EmbeddedVirtualYubiKeyConnector,
    commands: Mutex<Vec<CommandApdu>>,
    epoch: AtomicU64,
    fail_select: AtomicBool,
    fail_handshake: AtomicBool,
}
impl Card {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: EmbeddedVirtualYubiKeyConnector::from_device(VirtualYubiKey::new(
                DeviceProfile::yubikey_5_8_ccid(42),
            )),
            commands: Mutex::new(Vec::new()),
            epoch: AtomicU64::new(0),
            fail_select: AtomicBool::new(false),
            fail_handshake: AtomicBool::new(false),
        })
    }
    fn take(&self) -> Vec<CommandApdu> {
        std::mem::take(&mut *self.commands.lock().unwrap())
    }
}
impl Connector for Card {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Test"
    }
    fn product(&self) -> &str {
        "Selection test card"
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
        65536
    }
    fn stable_applet_topology(&self) -> bool {
        true
    }
    fn connection_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }
    fn transmit<'a>(
        &self,
        input: &[u8],
        output: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let command = CommandApdu::decode(input)?;
        let fail = (command.ins == 0xa4 && self.fail_select.load(Ordering::Relaxed))
            || (command.ins == 0x88 && self.fail_handshake.load(Ordering::Relaxed));
        self.commands.lock().unwrap().push(command);
        if fail {
            output[..2].copy_from_slice(&[0x6a, 0x82]);
            return Ok(&output[..2]);
        }
        self.inner.transmit(input, output, timeout)
    }
}

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pkcs11rs-selection-{:x}",
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scp11_configuration(card: &Card) -> (SecureChannelConfiguration, Directory) {
    select_application(&card.inner, &SD).unwrap();
    let certificates = SecurityDomainClient
        .get_certificate_bundle(
            &card.inner,
            crate::security_domain::KeyRef { kid: 0x13, kvn: 1 },
        )
        .unwrap();
    let directory = Directory::new();
    let root = directory.0.join("root.der");
    std::fs::write(&root, &certificates[0]).unwrap();
    let mut configuration = SecureChannelConfiguration::for_test();
    configuration.scp11.trust = crate::configuration::Scp11TrustConfiguration::CaCertificate(root);
    (configuration, directory)
}

fn prepare(
    card: Arc<Card>,
    state: Arc<PcscReaderState>,
    app: CcidApplication,
    protocol: Option<SecureChannelProtocol>,
    configuration: SecureChannelConfiguration,
) -> (Arc<Pkcs11Provider>, Rc<PcscAppletConnector>) {
    let aid = match app {
        CcidApplication::Piv => piv::PIV_AID.as_slice(),
        CcidApplication::OpenPgp => openpgp::OPENPGP_AID.as_slice(),
        CcidApplication::Oath => &oath::AID,
        CcidApplication::HsmAuth => &hsmauth::AID,
        CcidApplication::IssuerSecurityDomain => &SD,
        CcidApplication::Fido2 => &ctap::FIDO2_AID,
    };
    let connector = Rc::new(PcscAppletConnector::new_configured(
        card,
        aid,
        protocol,
        state.clone(),
        Arc::new(configuration),
        Arc::new(pinentry::Pinentry::unconfigured()),
    ));
    let mut slot: Box<dyn Slot> = match app {
        CcidApplication::Piv => Box::new(PivSlot::new_with_device(
            connector.clone(),
            aid.to_vec(),
            state.device.clone(),
        )),
        CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new_with_device(
            connector.clone(),
            aid.to_vec(),
            state.device.clone(),
        )),
        CcidApplication::Oath => Box::new(crate::backend::OathSlot::new(
            connector.clone(),
            aid.to_vec(),
            state.device.clone(),
        )),
        CcidApplication::HsmAuth => Box::new(HsmAuthSlot::new_with_device(
            connector.clone(),
            aid.to_vec(),
            state.device.clone(),
        )),
        CcidApplication::IssuerSecurityDomain => {
            Box::new(IssuerSecurityDomainSlot::new_with_device(
                connector.clone(),
                aid.to_vec(),
                state.device.clone(),
            ))
        }
        CcidApplication::Fido2 => Box::new(Fido2Slot::new_with_device(
            connector.clone(),
            aid.to_vec(),
            state.device.clone(),
        )),
    };
    slot.init_slot().unwrap();
    let provider = Pkcs11Provider::new(slot).unwrap();
    provider
        .call(|| with_slot_context_mut(1, |ctx| ctx.refresh_slot_token_objects(1)))
        .unwrap();
    (provider, connector)
}

fn login(owner: &ProviderSession, role: CK_USER_TYPE, pin: &[u8]) -> Result<(), Error> {
    owner.call(|| api::rust::login(owner.handle, role, pin.as_ptr(), pin.len() as _))
}
fn selections(commands: &[CommandApdu]) -> Vec<&[u8]> {
    commands
        .iter()
        .filter(|c| c.ins == 0xa4)
        .map(|c| c.data.as_slice())
        .collect()
}

#[test]
fn select_response_belongs_only_to_the_active_selection() {
    let card = Card::new();
    let info = oath::select(&card.inner, &oath::AID).unwrap();
    oath::change_password(&card.inner, &info, b"test password").unwrap();
    let state = Arc::new(PcscReaderState::default());
    let oath = PcscAppletConnector::new(card.clone(), &oath::AID, None, state.clone());
    let piv = PcscAppletConnector::new(card.clone(), &piv::PIV_AID, None, state);
    let first = oath.select_application(&oath::AID).unwrap();
    assert_eq!(first, oath.select_application(&oath::AID).unwrap());
    assert_eq!(selections(&card.take()), [&oath::AID[..]]);

    piv.select_application(&piv::PIV_AID).unwrap();
    let next = oath.select_application(&oath::AID).unwrap();
    assert_ne!(
        next.data, first.data,
        "reselection must replace the OATH challenge"
    );
    assert_eq!(
        selections(&card.take()),
        [&piv::PIV_AID[..], &oath::AID[..]]
    );

    let select = CommandApdu {
        cla: 0,
        ins: 0xa4,
        p1: 4,
        p2: 0,
        data: oath::AID.to_vec(),
        le: Some(256),
        extended: false,
    };
    let explicit = oath.send_apdu(&select).unwrap();
    assert_ne!(explicit.data, next.data);
    assert_eq!(explicit, oath.select_application(&oath::AID).unwrap());
    assert_eq!(selections(&card.take()), [&oath::AID[..]]);

    card.epoch.fetch_add(1, Ordering::Relaxed);
    assert_ne!(next.data, oath.select_application(&oath::AID).unwrap().data);
    assert_eq!(selections(&card.take()), [&oath::AID[..]]);

    card.fail_select.store(true, Ordering::Relaxed);
    assert!(piv.select_application(&piv::PIV_AID).is_err());
    card.fail_select.store(false, Ordering::Relaxed);
    oath.select_application(&oath::AID).unwrap();
    assert_eq!(
        selections(&card.take()),
        [&piv::PIV_AID[..], &oath::AID[..]]
    );
}

#[test]
fn oath_first_scp11_login_uses_the_final_selection_challenge() {
    let card = Card::new();
    let (config, _directory) = scp11_configuration(&card);
    let info = oath::select(&card.inner, &oath::AID).unwrap();
    oath::change_password(&card.inner, &info, b"test password").unwrap();
    let (provider, _) = prepare(
        card.clone(),
        Arc::new(PcscReaderState::default()),
        CcidApplication::Oath,
        Some(SecureChannelProtocol::Scp11b),
        config,
    );
    let owner = ProviderSession::open(provider).unwrap();
    card.take();
    login(&owner, CKU_USER as _, b"test password").unwrap();
    let commands = card.take();
    assert_eq!(
        selections(&commands),
        [&oath::AID[..], &SD[..], &oath::AID[..]]
    );
    assert_eq!(commands.iter().filter(|c| c.ins == 0x88).count(), 1);

    assert_eq!(owner.call(|| api::C_Logout(owner.handle)), CKR_OK as CK_RV);
    login(&owner, CKU_USER as _, b"wrong password").unwrap_err();
    login(&owner, CKU_USER as _, b"test password").unwrap();
}

#[test]
fn discovered_security_domain_certificates_avoid_the_scp11_detour() {
    let card = Card::new();
    let (config, _directory) = scp11_configuration(&card);
    let state = Arc::new(PcscReaderState::default());
    let (_sd, _) = prepare(
        card.clone(),
        state.clone(),
        CcidApplication::IssuerSecurityDomain,
        Some(SecureChannelProtocol::Scp11b),
        config.clone(),
    );
    let (provider, _) = prepare(
        card.clone(),
        state,
        CcidApplication::Oath,
        Some(SecureChannelProtocol::Scp11b),
        config,
    );
    let owner = ProviderSession::open(provider).unwrap();
    card.take();
    login(&owner, CKU_USER as _, b"").unwrap();
    let commands = card.take();
    assert_eq!(selections(&commands), [&oath::AID[..]]);
    assert_eq!(commands.iter().filter(|c| c.ins == 0x88).count(), 1);
    assert!(!commands.iter().any(|c| c.ins == 0xca));
}

#[test]
fn first_scp11_login_on_security_domain_selects_it_once() {
    let card = Card::new();
    let (config, _directory) = scp11_configuration(&card);
    let connector = PcscAppletConnector::new_configured(
        card.clone(),
        &SD,
        Some(SecureChannelProtocol::Scp11b),
        Arc::new(PcscReaderState::default()),
        Arc::new(config),
        Arc::new(pinentry::Pinentry::unconfigured()),
    );
    connector.establish_secure_channel(&SD).unwrap();
    let commands = card.take();
    assert_eq!(selections(&commands), [&SD[..]]);
    assert_eq!(commands.iter().filter(|c| c.ins == 0x88).count(), 1);
}

#[test]
fn discovered_certificates_must_match_the_selected_scp11_trust() {
    let card = Card::new();
    let (mut config, directory) = scp11_configuration(&card);
    let state = Arc::new(PcscReaderState::default());
    let (_sd, _) = prepare(
        card.clone(),
        state.clone(),
        CcidApplication::IssuerSecurityDomain,
        Some(SecureChannelProtocol::Scp11b),
        config.clone(),
    );
    let key = crate::certificate_builder::p256_key();
    let foreign_root = crate::certificate_builder::p256_certificate(
        key.verifying_key(),
        &key,
        "CN=Unrelated test CA",
        "CN=Unrelated test CA",
        1,
        true,
    );
    let root = directory.0.join("unrelated.der");
    std::fs::write(&root, foreign_root).unwrap();
    config.scp11.trust = crate::configuration::Scp11TrustConfiguration::CaCertificate(root);
    let (provider, _) = prepare(
        card.clone(),
        state,
        CcidApplication::Oath,
        Some(SecureChannelProtocol::Scp11b),
        config,
    );
    let owner = ProviderSession::open(provider).unwrap();
    card.take();
    assert!(login(&owner, CKU_USER as _, b"").is_err());
    let commands = card.take();
    assert!(!commands.iter().any(|c| matches!(c.ins, 0x88 | 0xa3)));
    assert_eq!(selections(&commands), [&oath::AID[..]]);
}

#[test]
fn failed_scp11_with_discovery_certificates_reloads_once_before_authentication() {
    let card = Card::new();
    let (config, _directory) = scp11_configuration(&card);
    let state = Arc::new(PcscReaderState::default());
    let (_sd, _) = prepare(
        card.clone(),
        state.clone(),
        CcidApplication::IssuerSecurityDomain,
        Some(SecureChannelProtocol::Scp11b),
        config.clone(),
    );
    let (provider, _) = prepare(
        card.clone(),
        state,
        CcidApplication::Oath,
        Some(SecureChannelProtocol::Scp11b),
        config,
    );
    let owner = ProviderSession::open(provider).unwrap();
    card.take();
    card.fail_handshake.store(true, Ordering::Relaxed);
    assert!(login(&owner, CKU_USER as _, b"").is_err());
    let commands = card.take();
    assert_eq!(commands.iter().filter(|c| c.ins == 0x88).count(), 2);
    assert_eq!(
        selections(&commands),
        [&oath::AID[..], &SD[..], &oath::AID[..]]
    );
    assert!(!commands.iter().any(|c| matches!(c.ins, 0xa1 | 0xa3)));
}

#[test]
fn last_hsmauth_session_close_releases_the_channel() {
    let card = Card::new();
    let (config, _directory) = scp11_configuration(&card);
    let (provider, connector) = prepare(
        card,
        Arc::new(PcscReaderState::default()),
        CcidApplication::HsmAuth,
        Some(SecureChannelProtocol::Scp11b),
        config,
    );
    let owner = ProviderSession::open(provider).unwrap();
    owner
        .call(|| {
            with_slot_context_mut(1, |ctx| {
                ctx.slot.hsmauth_administration(
                    &[0; 16],
                    HsmAuthAdministration::ChangeManagementKey {
                        new_management_key: &[3; 16],
                    },
                )
            })
        })
        .unwrap();
    assert_eq!(
        connector.secure_channel_protocol().unwrap(),
        Some(SecureChannelProtocol::Scp11b)
    );
    drop(owner);
    assert_eq!(connector.secure_channel_protocol().unwrap(), None);
}

#[test]
fn oath_find_refreshes_once_and_attribute_reads_use_the_snapshot() {
    let card = Card::new();
    oath::select(&card.inner, &oath::AID).unwrap();
    let mut credential = oath::Credential::from_name(b"test OTP".to_vec(), 0x21).unwrap();
    credential.digits = Some(6);
    credential.touch = Some(false);
    oath::put(&card.inner, &credential, b"test credential secret", 0).unwrap();
    let (provider, _) = prepare(
        card.clone(),
        Arc::new(PcscReaderState::default()),
        CcidApplication::Oath,
        Some(SecureChannelProtocol::Scp03),
        SecureChannelConfiguration::for_test(),
    );
    let owner = ProviderSession::open(provider).unwrap();
    login(&owner, CKU_USER as _, b"").unwrap();
    card.take();
    let objects = owner
        .find(&[(CKA_CLASS, &(CKO_OTP_KEY as CK_ULONG).to_ne_bytes())])
        .unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(
        owner.attribute(objects[0], CKA_LABEL).unwrap().as_slice(),
        b"test OTP"
    );
    let commands = card.take();
    assert_eq!(commands.iter().filter(|c| c.ins == 0xa1).count(), 1);
    assert!(selections(&commands).is_empty());
    assert!(!commands.iter().any(|c| c.ins == 0x50));
}

#[test]
fn openpgp_provisioning_preserves_its_authenticated_selection() {
    let card = Card::new();
    let (provider, connector) = prepare(
        card.clone(),
        Arc::new(PcscReaderState::default()),
        CcidApplication::OpenPgp,
        Some(SecureChannelProtocol::Scp03),
        SecureChannelConfiguration::for_test(),
    );
    let owner = ProviderSession::open(provider).unwrap();
    login(&owner, CKU_SO as _, b"12345678").unwrap();
    card.take();
    owner
        .call(|| {
            with_slot_context_mut(1, |ctx| {
                ctx.slot
                    .openpgp_generate_key_pair(
                        OpenPgpKeyRef::Signature,
                        OpenPgpAlgorithm::Rsa { bits: 2048 },
                    )
                    .expect("generation");
                ctx.slot
                    .openpgp_set_touch_policy(OpenPgpKeyRef::Signature, 1)
                    .expect("touch policy");
                ctx.refresh_slot_token_objects(1)
            })
        })
        .unwrap();
    assert_eq!(connector.ccid_login_state(), Some(CcidLoginState::So));
    let commands = card.take();
    assert!(selections(&commands).is_empty());
    assert!(!commands.iter().any(|c| c.ins == 0x50));

    let select = CommandApdu {
        cla: 0,
        ins: 0xa4,
        p1: 4,
        p2: 0,
        data: openpgp::OPENPGP_AID.to_vec(),
        le: Some(256),
        extended: false,
    };
    assert_eq!(connector.send_apdu(&select).unwrap().status, 0x9000);
    assert_eq!(connector.ccid_login_state(), Some(CcidLoginState::Public));
    assert_eq!(connector.secure_channel_protocol().unwrap(), None);
    assert_eq!(selections(&card.take()), [&openpgp::OPENPGP_AID[..]]);
}

#[test]
fn native_hsmauth_protects_credential_requests_and_fails_closed() {
    for fail in [false, true] {
        let card = Card::new();
        select_application(&card.inner, &hsmauth::AID).unwrap();
        HsmAuthClient
            .put_symmetric_credential(
                &card.inner,
                &[0; 16],
                "test",
                hsmauth::SymmetricCredentialKeys {
                    enc: &[1; 16],
                    mac: &[2; 16],
                },
                b"test password",
                false,
            )
            .unwrap();
        let (config, _directory) = scp11_configuration(&card);
        let (provider, _) = prepare(
            card.clone(),
            Arc::new(PcscReaderState::default()),
            CcidApplication::HsmAuth,
            Some(SecureChannelProtocol::Scp11b),
            config,
        );
        let owner = ProviderSession::open(provider).unwrap();
        let objects = owner
            .find(&[(CKA_CLASS, &(CKO_SECRET_KEY as CK_ULONG).to_ne_bytes())])
            .unwrap();
        assert_eq!(objects.len(), 1);
        card.take();
        card.fail_handshake.store(fail, Ordering::Relaxed);
        // This target deliberately rejects CREATE SESSION, after the source
        // challenge request. The source transport must already be protected.
        assert!(
            owner
                .hsmauth_authenticate(objects[0], &card.inner, 1, b"test password", None)
                .is_err()
        );
        let commands = card.take();
        assert_eq!(commands.iter().filter(|c| c.ins == 0x88).count(), 1);
        assert!(!commands.iter().any(|c| c.ins == 4 && c.cla == 0));
        assert!(
            !commands
                .iter()
                .any(|c| c.data.windows(13).any(|v| v == b"test password"))
        );
        assert_eq!(
            commands
                .iter()
                .filter(|c| c.ins == 4 && c.cla & 4 != 0)
                .count(),
            usize::from(!fail)
        );
    }
}
