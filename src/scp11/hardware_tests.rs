//! Opt-in physical qualification with an independently recoverable SCP03 administrator.
use super::*;
use crate::security_domain::{KeyRef, Scp11Administration as Op};
use crate::{SecurityDomainClient, select_application};
use spki::EncodePublicKey;
#[path = "hardware_hsm_host.rs"]
mod hsm_host;

fn administer(
    connector: &dyn Connector,
    session: &mut Scp03Session,
    operation: Op,
) -> Result<Vec<u8>, Error> {
    let prepared = SecurityDomainClient.prepare_scp11_administration(session, &operation)?;
    SecurityDomainClient.execute_scp11_administration(connector, session, prepared)
}

// Catch assertions before releasing the device guard so cleanup can still use
// the device lock. No production lock-poisoning policy is changed for tests.
fn transaction<T>(device: &crate::device::DeviceContext, f: impl FnOnce() -> T) -> T {
    let guard = device
        .lock_operation(crate::device::DeviceOperationKind::Ccid)
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    drop(guard);
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[derive(Debug)]
struct Diagnostics<'a>(&'a dyn Connector);
impl Connector for Diagnostics<'_> {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        self.0.manufacturer()
    }
    fn product(&self) -> &str {
        self.0.product()
    }
    fn major(&self) -> u8 {
        self.0.major()
    }
    fn minor(&self) -> u8 {
        self.0.minor()
    }
    fn is_present(&self) -> bool {
        self.0.is_present()
    }
    fn buffer_size(&self) -> usize {
        self.0.buffer_size()
    }
    fn transmit<'a>(
        &self,
        send: &[u8],
        receive: &'a mut [u8],
        timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = self.0.transmit(send, receive, timeout)?;
        if response.len() >= 2
            && response[response.len() - 2] != 0x61
            && !matches!(&response[response.len() - 2..], [0x90, 0] | [0x6a, 0x88])
        {
            eprintln!(
                "APDU header {:02x?} returned status {:02x?}",
                &send[..send.len().min(4)],
                &response[response.len() - 2..]
            );
        }
        Ok(response)
    }
}

#[test]
#[ignore = "creates and removes temporary SCP11a/b and host-CA keys; requires a saved custom SCP03 recovery configuration"]
fn physical_scp11_coexistence() {
    qualify_card(None);
}

#[test]
#[ignore = "generates a native HSM host credential and temporary card SCP keys; requires explicit serials, source PIN and saved SCP03 recovery"]
fn physical_scp11a_with_yubihsm_host() {
    let source = std::env::var("PKCS11RS_TEST_SCP_HOST_HSM").expect("source HSM serial required");
    qualify_card(Some(&source));
}

fn qualify_card(hsm_serial: Option<&str>) {
    let serial = std::env::var("PKCS11RS_TEST_ISSUER_SD_SOURCE")
        .expect("select one physical YubiKey serial");
    let path = std::env::var("PKCS11RS_TEST_SCP_RECOVERY_CONFIG")
        .expect("provide a saved custom SCP03 configuration");
    let encoded = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let mut json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    json["hardware"] = serde_json::json!({"discovery": true});
    let mut serials = vec![serial.clone()];
    if let Some(source) = hsm_serial {
        serials.push(source.to_owned());
    }
    json["slots"] = serde_json::json!({"serials": serials});
    json["ccid"] = serde_json::json!({"applications": ["issuer-sd", "hsmauth"]});
    json["software"] = serde_json::json!({"slots": []});
    json["platform"] = serde_json::json!({"enabled": false});
    json["yubihsm"] = serde_json::json!({"urls": [], "public_discovery": null});
    let configuration =
        crate::ModuleConfiguration::resolve(Some(serde_json::from_value(json).unwrap())).unwrap();
    assert!(
        configuration
            .ccid_configurations
            .iter()
            .all(|c| c.secure_channel.is_none()),
        "unset PKCS11RS_CCID_SECURE_CHANNEL"
    );
    let admin_kvn = configuration.secure_channels.scp03.key_version;
    assert_ne!(
        admin_kvn, 0xff,
        "factory SCP03 is not a persistent recovery credential"
    );
    let admin_keys =
        crate::Scp03KeySet::from_configuration(&configuration.secure_channels.scp03).unwrap();
    let context = crate::ModuleContext::new_with_configuration(configuration).unwrap();
    context.init().unwrap();
    context.refresh_discovery().unwrap();
    let (base, device) = {
        let slots = context.slot_contexts.read().unwrap();
        let matches: Vec<_> = slots
            .values()
            .filter_map(|child| {
                let child = child.lock().unwrap();
                if child.slot.serial() != serial || !child.slot.is_present() {
                    return None;
                }
                Some((
                    child.slot.security_domain_provisioning_connector()?,
                    child.device.clone()?,
                ))
            })
            .collect();
        assert_eq!(matches.len(), 1, "expected the selected physical Issuer SD");
        matches.into_iter().next().unwrap()
    };
    let connector = &Diagnostics(base.as_ref());
    let sd = crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID;
    let before = transaction(&device, || {
        select_application(connector, &sd).unwrap();
        SecurityDomainClient.discover(connector).unwrap()
    });
    assert!(
        before.keys.iter().any(|k| k.key_ref
            == KeyRef {
                kid: 1,
                kvn: admin_kvn
            }),
        "custom SCP03 recovery credential must already be installed"
    );
    // Verify recovery before any mutation, independently of the new credentials.
    transaction(&device, || {
        select_application(connector, &sd).unwrap();
        Scp03Session::authenticate_selected(connector, &admin_keys, 0x33, &sd).unwrap();
    });
    let fresh = |kid| {
        (1..0x80)
            .map(|kvn| KeyRef { kid, kvn })
            .find(|r| !before.keys.iter().any(|k| k.key_ref == *r))
            .unwrap()
    };
    let card_a = fresh(0x11);
    let card_b = fresh(0x13);
    let ca_ref = fresh(0x10);
    let refs = [card_a, card_b, ca_ref];
    let ca = crate::certificate_builder::p256_key();
    let mut hsm_host =
        hsm_serial.map(|serial| hsm_host::HsmHost::generate(&context, serial).unwrap());
    let (credential, host_public) = if let Some(source) = hsm_host.as_ref() {
        (source.credential().unwrap(), source.public_key().unwrap())
    } else {
        let host = crate::certificate_builder::p256_key();
        let credential = protect_p256(
            SoftwareSigningKey::from_serialized_for_kind(
                KeyKind::Ec(EcCurve::P256),
                &host.to_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        (credential, *host.verifying_key())
    };
    let ca_name = "CN=pkcs11rs temporary SCP11 CA";
    let root = crate::certificate_builder::p256_certificate(
        ca.verifying_key(),
        &ca,
        ca_name,
        ca_name,
        1,
        true,
    );
    let host_certificate = crate::certificate_builder::p256_scp11_oce_certificate(
        &host_public,
        &ca,
        "CN=pkcs11rs temporary SCP11 host",
        ca_name,
        2,
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transaction(&device, || {
            select_application(connector, &sd).unwrap();
            let mut admin =
                Scp03Session::authenticate_selected(connector, &admin_keys, 0x33, &sd).unwrap();
            for (reference, certificate_serial) in [(card_b, 4), (card_a, 3)] {
                let public = administer(
                    connector,
                    &mut admin,
                    Op::GenerateKey {
                        key_ref: reference,
                        replace_kvn: 0,
                        curve: 0,
                    },
                )
                .unwrap();
                let card_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).unwrap();
                let leaf = crate::certificate_builder::p256_certificate(
                    &card_key,
                    &ca,
                    "CN=pkcs11rs temporary SCP11 card",
                    ca_name,
                    certificate_serial,
                    false,
                );
                administer(
                    connector,
                    &mut admin,
                    Op::StoreCertificateChain {
                        key_ref: reference,
                        certificates: vec![root.clone(), leaf],
                    },
                )
                .unwrap();
            }
        });
        transaction(&device, || {
            select_application(connector, &sd).unwrap();
            let inventory = SecurityDomainClient.get_key_information(connector).unwrap();
            for reference in [card_a, card_b] {
                assert!(inventory.iter().any(|k| k.key_ref == reference));
            }
            for old in &before.keys {
                assert!(inventory.contains(old));
            }
            eprintln!(
                "{serial}: simultaneous key references {:?}",
                inventory.iter().map(|k| k.key_ref).collect::<Vec<_>>()
            );
        });
        let mut failures = Vec::new();
        for (variant, reference) in [(Scp11Variant::B, card_b), (Scp11Variant::A, card_a)] {
            if variant == Scp11Variant::A {
                // The recovery set, two card keys, and CA would require four
                // entries. Release the test-owned B key before installing CA.
                transaction(&device, || {
                    select_application(connector, &sd).unwrap();
                    let mut admin =
                        Scp03Session::authenticate_selected(connector, &admin_keys, 0x33, &sd)
                            .unwrap();
                    administer(
                        connector,
                        &mut admin,
                        Op::DeleteKey {
                            key_ref: card_b,
                            delete_last: false,
                        },
                    )
                    .unwrap();
                    administer(
                        connector,
                        &mut admin,
                        Op::PutPublicKey {
                            key_ref: ca_ref,
                            replace_kvn: 0,
                            encoded: ca
                                .verifying_key()
                                .to_public_key_der()
                                .unwrap()
                                .as_bytes()
                                .to_vec(),
                        },
                    )
                    .unwrap();
                    administer(
                        connector,
                        &mut admin,
                        Op::StoreCaIssuer {
                            key_ref: ca_ref,
                            subject_key_identifier: software_key_core::digest::HashAlgorithm::Sha1
                                .digest(ca.verifying_key().to_sec1_point(false).as_bytes()),
                        },
                    )
                    .unwrap();
                });
            }
            let keys = Scp11KeySet {
                variant,
                key_version: reference.kvn,
                card_public_key: None,
                certificate_trust: Some(
                    crate::certificate_chain::CertificateTrust::new(std::slice::from_ref(&root))
                        .unwrap(),
                ),
                host: (variant == Scp11Variant::A).then(|| Scp11aHostCredentials {
                    key_id: ca_ref.kid,
                    key_version: ca_ref.kvn,
                    private_key: credential.clone(),
                    certificates: vec![host_certificate.clone()],
                }),
            };
            for attempt in 0..3 {
                let outcome = transaction(&device, || -> Result<(), Error> {
                    select_application(connector, &sd)?;
                    let (mut channel, _) =
                        keys.authenticate_application(connector, &sd, &sd, None)?;
                    let command = CommandApdu {
                        cla: 0,
                        ins: 0xca,
                        p1: 0,
                        p2: 0xe0,
                        data: vec![],
                        le: Some(256),
                        extended: false,
                    };
                    let response = channel
                        .transmit(connector, &command)?
                        .require_success(&command)?;
                    assert!(!response.data.is_empty());
                    Ok(())
                });
                if let Err(error) = outcome {
                    eprintln!("SCP11{variant:?} handshake failed: {error:?}");
                    failures.push((variant, error));
                    break;
                }
                eprintln!(
                    "SCP11{variant:?} {:02x}:{:02x}: handshake and protected read {} passed",
                    reference.kid,
                    reference.kvn,
                    attempt + 1
                );
            }
        }
        assert!(
            failures.is_empty(),
            "hardware authentication failures: {failures:?}"
        );
    }));
    transaction(&device, || {
        select_application(connector, &sd).unwrap();
        let current = SecurityDomainClient.get_key_information(connector).unwrap();
        let mut admin =
            Scp03Session::authenticate_selected(connector, &admin_keys, 0x33, &sd).unwrap();
        for key_ref in refs {
            if current.iter().any(|key| key.key_ref == key_ref) {
                administer(
                    connector,
                    &mut admin,
                    Op::DeleteKey {
                        key_ref,
                        delete_last: false,
                    },
                )
                .unwrap_or_else(|e| panic!("cleanup required for {key_ref:?}: {e:?}"));
            }
        }
        select_application(connector, &sd).unwrap();
        assert_eq!(
            SecurityDomainClient.discover(connector).unwrap(),
            before,
            "original inventory must be restored"
        );
    });
    eprintln!(
        "{serial}: temporary keys removed; original inventory and recovery credential preserved"
    );
    if let Some(source) = hsm_host.as_mut() {
        source.cleanup().unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
