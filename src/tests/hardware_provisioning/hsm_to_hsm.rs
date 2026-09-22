//! Opt-in authentication between two explicitly selected physical YubiHSMs.
use super::*;

#[test]
#[cfg(unix)]
#[ignore = "trusted maintenance of an explicitly selected persisted virtual YubiHSM"]
fn configure_persisted_virtual_client_path_capabilities() {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use virtual_yubihsm_core::{Capability, Device, DeviceConfig, ObjectType};

    let path = required("PKCS11RS_VIRTUAL_STATE_PATH");
    let serial = required("PKCS11RS_VIRTUAL_STATE_SERIAL")
        .parse::<u32>()
        .expect("PKCS11RS_VIRTUAL_STATE_SERIAL must be decimal");
    let config = DeviceConfig {
        serial,
        ..DeviceConfig::default()
    };
    let encoded = fs::read(&path).expect("read persistent virtual YubiHSM state");
    let mut device = Device::from_persistent_state(config.clone(), &encoded)
        .expect("decode persistent virtual YubiHSM state");

    for object in device.objects().filter(|object| {
        matches!(
            object.info.object_type,
            ObjectType::AuthenticationKey | ObjectType::AsymmetricKey
        )
    }) {
        eprintln!(
            "persisted object {:04x} {:?} algorithm {} label {:?} capabilities {:02x?}",
            object.info.id,
            object.info.object_type,
            object.info.algorithm,
            String::from_utf8_lossy(&object.info.label),
            object.info.capabilities.to_bytes()
        );
    }

    if std::env::var("PKCS11RS_VIRTUAL_NATIVE_KDF_APPLY").as_deref() != Ok("1") {
        eprintln!("preflight complete; persistent state was not changed");
        return;
    }

    let native_private_id = hex_u16(
        "PKCS11RS_VIRTUAL_NATIVE_KDF_PRIVATE_ID",
        &required("PKCS11RS_VIRTUAL_NATIVE_KDF_PRIVATE_ID"),
    );
    let emulated_private_id = std::env::var("PKCS11RS_VIRTUAL_EMULATED_KDF_PRIVATE_ID")
        .ok()
        .map(|id| hex_u16("PKCS11RS_VIRTUAL_EMULATED_KDF_PRIVATE_ID", &id));
    assert_ne!(
        Some(native_private_id),
        emulated_private_id,
        "native and emulated paths require distinct private keys"
    );
    let authorization_ids: Vec<_> = required("PKCS11RS_VIRTUAL_NATIVE_KDF_AUTHORIZATION_IDS")
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| hex_u16("PKCS11RS_VIRTUAL_NATIVE_KDF_AUTHORIZATION_IDS", id))
        .collect();
    assert!(!authorization_ids.is_empty());
    let mut unique_authorization_ids = authorization_ids.clone();
    unique_authorization_ids.sort_unstable();
    unique_authorization_ids.dedup();
    assert_eq!(
        authorization_ids, unique_authorization_ids,
        "authorization IDs must be unique and sorted"
    );

    let mut native_private = device
        .objects()
        .find(|object| {
            object.info.id == native_private_id
                && object.info.object_type == ObjectType::AsymmetricKey
        })
        .unwrap_or_else(|| panic!("asymmetric key {native_private_id:04x} is absent"))
        .clone();
    let native_private_before = native_private.clone();
    native_private
        .info
        .capabilities
        .insert(Capability::DeriveEcdhKdf);

    let emulated_private = emulated_private_id.map(|id| {
        let mut object = device
            .objects()
            .find(|object| {
                object.info.id == id && object.info.object_type == ObjectType::AsymmetricKey
            })
            .unwrap_or_else(|| panic!("asymmetric key {id:04x} is absent"))
            .clone();
        let before = object.clone();
        object.info.capabilities =
            without_capability(object.info.capabilities, Capability::DeriveEcdhKdf);
        object.info.capabilities.insert(Capability::DeriveEcdh);
        (before, object)
    });
    let authorizations: Vec<_> = authorization_ids
        .iter()
        .map(|id| {
            let mut object = device
                .objects()
                .find(|object| {
                    object.info.id == *id
                        && object.info.object_type == ObjectType::AuthenticationKey
                })
                .unwrap_or_else(|| panic!("Authentication Key {id:04x} is absent"))
                .clone();
            let before = object.clone();
            for capability in [
                Capability::GetPseudoRandom,
                Capability::DeriveEcdh,
                Capability::DeriveEcdhKdf,
                Capability::SessionObjects,
            ] {
                object.info.capabilities.insert(capability);
            }
            (before, object)
        })
        .collect();

    let mut replacements = vec![(native_private_before, native_private)];
    if let Some(pair) = emulated_private {
        replacements.push(pair);
    }
    replacements.extend(authorizations);
    for (_, replacement) in &replacements {
        device
            .provision_object(replacement.clone())
            .expect("replace persisted object metadata");
    }
    assert!(
        device
            .take_persistent_change()
            .expect("advance persistent-state epoch")
    );
    let replacement = device
        .persistent_state()
        .expect("encode updated persistent state");
    let restored = Device::from_persistent_state(config, &replacement)
        .expect("validate updated persistent state");
    for (before, expected) in &replacements {
        let actual = restored
            .objects()
            .find(|object| object.info.key() == expected.info.key())
            .expect("updated object survived persistence round trip");
        assert_eq!(actual.material, before.material, "key material changed");
        assert_eq!(actual.info, expected.info, "unexpected metadata change");
    }
    assert!(
        replacements[0]
            .1
            .info
            .capabilities
            .contains(Capability::DeriveEcdhKdf)
    );
    if let Some(emulated_private_id) = emulated_private_id {
        let emulated = restored
            .objects()
            .find(|object| {
                object.info.id == emulated_private_id
                    && object.info.object_type == ObjectType::AsymmetricKey
            })
            .expect("emulated-path key survived persistence round trip");
        assert!(emulated.info.capabilities.contains(Capability::DeriveEcdh));
        assert!(
            !emulated
                .info
                .capabilities
                .contains(Capability::DeriveEcdhKdf)
        );
    }
    for authorization_id in &authorization_ids {
        let authorization = restored
            .objects()
            .find(|object| {
                object.info.id == *authorization_id
                    && object.info.object_type == ObjectType::AuthenticationKey
            })
            .expect("authorizing Authentication Key survived persistence round trip");
        for capability in [
            Capability::GetPseudoRandom,
            Capability::DeriveEcdh,
            Capability::DeriveEcdhKdf,
            Capability::SessionObjects,
        ] {
            assert!(authorization.info.capabilities.contains(capability));
        }
    }

    let state_path = Path::new(&path);
    let metadata = fs::metadata(state_path).expect("read persistent-state metadata");
    let temporary = state_path.with_extension(format!("cbor.native-kdf-{}", std::process::id()));
    struct RemoveTemporary<'a>(&'a Path);
    impl Drop for RemoveTemporary<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0);
        }
    }
    let _remove_temporary = RemoveTemporary(&temporary);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(std::os::unix::fs::PermissionsExt::mode(
            &metadata.permissions(),
        ))
        .open(&temporary)
        .expect("create replacement persistent state");
    output
        .write_all(&replacement)
        .expect("write replacement persistent state");
    output
        .sync_all()
        .expect("sync replacement persistent state");
    drop(output);
    fs::rename(&temporary, state_path).expect("atomically replace persistent state");
    fs::File::open(state_path.parent().expect("state path has no parent"))
        .and_then(|directory| directory.sync_all())
        .expect("sync persistent-state directory");
    let installed = fs::read(state_path).expect("read installed persistent state");
    Device::from_persistent_state(
        DeviceConfig {
            serial,
            ..DeviceConfig::default()
        },
        &installed,
    )
    .expect("validate installed persistent state");
    eprintln!(
        "configured native key {native_private_id:04x}, emulated key {emulated_private_id:04x?}, and authorizers {authorization_ids:04x?}; all key material was preserved"
    );
}

#[cfg(unix)]
fn without_capability(
    capabilities: virtual_yubihsm_core::CapabilitySet,
    capability: virtual_yubihsm_core::Capability,
) -> virtual_yubihsm_core::CapabilitySet {
    let mut bytes = capabilities.to_bytes();
    let bit = capability as usize;
    bytes[7 - bit / 8] &= !(1 << (bit % 8));
    virtual_yubihsm_core::CapabilitySet::from_bytes(bytes)
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn command(
    session: CK_SESSION_HANDLE,
    command: &crate::YubiHsmCommand,
) -> Result<Vec<u8>, crate::Error> {
    crate::with_session_context(session, |ctx| {
        ctx._get_session(session)?.1.yubihsm_command(command)
    })
}

fn inventory(session: CK_SESSION_HANDLE) -> Vec<(u16, u8, u8)> {
    let response = command(session, &crate::YubiHsmCommand::list_objects(&[]).unwrap()).unwrap();
    let mut objects: Vec<_> = crate::parse_yubihsm_object_list(&response)
        .unwrap()
        .into_iter()
        .map(|object| (object.id, object.object_type, object.sequence))
        .collect();
    objects.sort_unstable();
    objects
}

fn open(serial: &str) -> CK_SESSION_HANDLE {
    let slot = crate::with_context(|context| {
        let slots = context
            .slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        let matches: Vec<_> = slots
            .iter()
            .filter_map(|(id, child)| {
                let child = child.lock().ok()?;
                (child.slot.serial() == serial
                    && child.slot.is_present()
                    && child.slot.supports_yubihsm_management())
                .then_some(*id)
            })
            .collect();
        if matches.len() != 1 {
            return Err(CKR_SLOT_ID_INVALID.into());
        }
        Ok(matches[0])
    })
    .unwrap_or_else(|e| panic!("expected one HSM with serial {serial}: {e:?}"));
    let mut session = 0;
    assert_eq!(
        crate::api::C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
            std::ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK as CK_RV
    );
    session
}

fn login(session: CK_SESSION_HANDLE, pin: &str, description: &str) {
    login_with_password(session, pin, description, None);
}

fn login_with_password(
    session: CK_SESSION_HANDLE,
    pin: &str,
    description: &str,
    shared_password: Option<&mut [u8]>,
) {
    let mut pin = crate::Zeroizing::new(pin.as_bytes().to_vec());
    let result = match (pin.starts_with(b"pkcs11:"), shared_password) {
        (true, Some(password)) => crate::api::C_LoginUser(
            session,
            CKU_USER as _,
            password.as_mut_ptr(),
            password.len() as _,
            pin.as_mut_ptr(),
            pin.len() as _,
        ),
        (true, None) => crate::api::C_LoginUser(
            session,
            CKU_USER as _,
            std::ptr::null_mut(),
            0,
            pin.as_mut_ptr(),
            pin.len() as _,
        ),
        (false, Some(password)) => crate::api::C_Login(
            session,
            CKU_USER as _,
            password.as_mut_ptr(),
            password.len() as _,
        ),
        (false, None) => {
            crate::api::C_Login(session, CKU_USER as _, pin.as_mut_ptr(), pin.len() as _)
        }
    };
    assert_eq!(
        result, CKR_OK as CK_RV,
        "bootstrap login failed for {description}"
    );
}

fn shared_qualification_password() -> crate::Zeroizing<Vec<u8>> {
    let pinentry = crate::pinentry::Pinentry::from_configuration(Some(
        std::env::var_os("PKCS11RS_PINENTRY")
            .expect("PKCS11RS_PINENTRY is required for the shared prompt"),
    ))
    .expect("configure shared password prompt");
    pinentry
        .request(crate::pinentry::Prompt {
            title: "Virtual YubiHSM path qualification",
            description: "Enter the shared password used by the qualification credentials.",
            label: "Authentication password:",
        })
        .expect("obtain shared qualification password")
}

fn authenticated_credential(session: CK_SESSION_HANDLE) -> String {
    let mut length = 0;
    assert_eq!(
        crate::api::PKCS11RS_GetAuthenticatedCredential(session, std::ptr::null_mut(), &mut length,),
        CKR_OK as CK_RV
    );
    let mut value = vec![0; length as usize];
    assert_eq!(
        crate::api::PKCS11RS_GetAuthenticatedCredential(session, value.as_mut_ptr(), &mut length,),
        CKR_OK as CK_RV
    );
    String::from_utf8(value).expect("authenticated credential URI is not UTF-8")
}

fn assert_user_login(session: CK_SESSION_HANDLE) {
    let mut info = CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    };
    assert_eq!(
        crate::api::C_GetSessionInfo(session, &mut info),
        CKR_OK as CK_RV
    );
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS as CK_STATE);
}

fn initialize_hsms(
    mut serials: Vec<String>,
    recreate_sessions: bool,
    public_discovery: Option<&str>,
) {
    if let Ok(helpers) = std::env::var("PKCS11RS_CROSS_HSM_HELPERS") {
        serials.extend(
            helpers
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
    }
    let urls: Vec<_> = std::env::var("PKCS11RS_CROSS_HSM_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect();
    finalize_for_test();
    assert_eq!(
        initialize_with_configuration(serde_json::json!({
            "version": 1, "hardware": {"discovery": true},
            "slots": {"serials": serials}, "ccid": {"applications": ["hsmauth"]},
            "software": {"slots": []}, "platform": {"enabled": true},
            "yubihsm": {"urls": urls, "public_discovery": public_discovery, "recreate_sessions": recreate_sessions}
        })),
        CKR_OK as CK_RV
    );
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as _, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
}

fn initialize_remote_hsms(serials: Vec<String>, public_discovery: &str) {
    let urls: Vec<_> = required("PKCS11RS_MIRROR_HSM_URLS")
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!urls.is_empty(), "PKCS11RS_MIRROR_HSM_URLS is empty");
    finalize_for_test();
    assert_eq!(
        initialize_with_configuration(serde_json::json!({
            "version": 1,
            "hardware": {"discovery": true},
            "slots": {"serials": serials},
            "ccid": {"applications": ["hsmauth"]},
            "software": {"slots": []},
            "platform": {"enabled": false},
            "yubihsm": {
                "urls": urls,
                "public_discovery": public_discovery,
                "recreate_sessions": false
            }
        })),
        CKR_OK as CK_RV
    );
    let mut count = 0;
    assert_eq!(
        crate::api::C_GetSlotList(CK_TRUE as _, std::ptr::null_mut(), &mut count),
        CKR_OK as CK_RV
    );
    let mut discovered = crate::with_context(|context| {
        let slots = context
            .slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?;
        Ok(slots
            .values()
            .filter_map(|child| {
                let child = child.lock().ok()?;
                (child.slot.is_present() && child.slot.supports_yubihsm_management())
                    .then(|| child.slot.serial().to_owned())
            })
            .collect::<Vec<_>>())
    })
    .expect("failed to inspect the remote HSM inventory");
    discovered.sort();
    let mut expected = serials;
    expected.sort();
    assert_eq!(
        discovered, expected,
        "the remote HSM inventory did not exactly match the requested serials"
    );
}

#[derive(Clone, Debug)]
struct MirroredAuthenticationKey {
    info: crate::YubiHsmObjectInfo,
    public_key: crate::SoftwarePublicKey,
}

fn read_authentication_key_for_mirror(
    session: CK_SESSION_HANDLE,
    id: u16,
) -> MirroredAuthenticationKey {
    let info = crate::YubiHsmObjectInfo::parse(
        &command(
            session,
            &crate::YubiHsmCommand::get_object_info(id, crate::YUBIHSM_AUTHENTICATION_KEY),
        )
        .unwrap_or_else(|error| {
            panic!("reference Authentication Key {id:04x} is unreadable: {error:?}")
        }),
    )
    .unwrap_or_else(|error| {
        panic!("reference Authentication Key {id:04x} has invalid metadata: {error:?}")
    });
    assert_eq!(
        info.algorithm,
        crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
        "reference Authentication Key {id:04x} is not asymmetric P-256"
    );
    let public = find_hardware_object(session, CKO_PUBLIC_KEY as _, &id.to_be_bytes())
        .unwrap_or_else(|| {
            panic!("reference Authentication Key {id:04x} has no public projection")
        });
    assert_eq!(
        read_hardware_attribute(session, public, CKA_LABEL as _),
        info.label.as_bytes(),
        "reference Authentication Key {id:04x} and its projection have different labels"
    );
    let public_key = p256_public_key(session, public);
    MirroredAuthenticationKey { info, public_key }
}

fn inspect_target_authentication_key(
    session: CK_SESSION_HANDLE,
    expected: &MirroredAuthenticationKey,
) -> Option<crate::YubiHsmObjectInfo> {
    let listed = command(
        session,
        &crate::YubiHsmCommand::list_objects(&[
            crate::yubihsm::ObjectFilter::Id(expected.info.id),
            crate::yubihsm::ObjectFilter::Type(crate::YUBIHSM_AUTHENTICATION_KEY),
        ])
        .unwrap(),
    )
    .and_then(|response| crate::parse_yubihsm_object_list(&response))
    .expect("target authentication-key inventory is unreadable");
    match listed.as_slice() {
        [] => None,
        [entry] => Some(
            crate::YubiHsmObjectInfo::parse(
                &command(
                    session,
                    &crate::YubiHsmCommand::get_object_info(entry.id, entry.object_type),
                )
                .expect("target Authentication Key metadata is unreadable"),
            )
            .expect("target Authentication Key metadata is invalid"),
        ),
        _ => panic!(
            "target contains duplicate Authentication Key {:04x}",
            expected.info.id
        ),
    }
}

fn assert_matching_authentication_key(
    target: &str,
    actual: &crate::YubiHsmObjectInfo,
    expected: &crate::YubiHsmObjectInfo,
) {
    assert_eq!(actual.id, expected.id, "{target}: ID differs");
    assert_eq!(actual.label, expected.label, "{target}: label differs");
    assert_eq!(actual.domains, expected.domains, "{target}: domains differ");
    assert_eq!(
        actual.algorithm, expected.algorithm,
        "{target}: algorithm differs"
    );
    assert_eq!(
        actual.capabilities, expected.capabilities,
        "{target}: capabilities differ"
    );
    assert_eq!(
        actual.delegated_capabilities, expected.delegated_capabilities,
        "{target}: delegated capabilities differ"
    );
}

fn is_restricted_public_discovery(info: &crate::YubiHsmObjectInfo) -> bool {
    info.id == 1
        && info.label == "pkcs11rs public discovery"
        && info.domains == u16::MAX
        && info.algorithm == crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION
        && info.capabilities == crate::yubihsm_capabilities(&[0x00])
        && info.delegated_capabilities == [0; 8]
}

#[test]
#[ignore = "persistent mirroring of explicitly selected YubiHSM authentication identities"]
fn mirrors_yubihsm_authentication_inventory() {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_MIRROR_SOURCE");
    let targets: Vec<_> = required("PKCS11RS_MIRROR_TARGETS")
        .split(',')
        .map(str::trim)
        .filter(|serial| !serial.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!targets.is_empty(), "PKCS11RS_MIRROR_TARGETS is empty");
    assert!(!targets.contains(&source), "source is also a target");
    let mut unique_targets = targets.clone();
    unique_targets.sort();
    unique_targets.dedup();
    assert_eq!(targets, unique_targets, "targets must be unique and sorted");
    let ids: Vec<_> = required("PKCS11RS_MIRROR_AUTHENTICATION_KEY_IDS")
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| hex_u16("PKCS11RS_MIRROR_AUTHENTICATION_KEY_IDS", id))
        .collect();
    assert!(!ids.is_empty(), "no Authentication Key IDs were selected");
    assert!(
        !ids.contains(&1),
        "Authentication Key 0001 is reserved for discovery"
    );
    let mut unique_ids = ids.clone();
    unique_ids.sort_unstable();
    unique_ids.dedup();
    assert_eq!(
        ids, unique_ids,
        "Authentication Key IDs must be unique and sorted"
    );

    let discovery_password = crate::Zeroizing::new(
        std::env::var("PKCS11RS_MIRROR_DISCOVERY_PASSWORD")
            .unwrap_or_else(|_| "password".to_owned()),
    );
    let bootstrap_password = crate::Zeroizing::new(
        std::env::var("PKCS11RS_MIRROR_BOOTSTRAP_PASSWORD")
            .unwrap_or_else(|_| "password".to_owned()),
    );
    let discovery_pin = format!("0001{}", discovery_password.as_str());
    let bootstrap_pin = format!("0001{}", bootstrap_password.as_str());
    let mut serials = vec![source.clone()];
    serials.extend(targets.iter().cloned());
    initialize_remote_hsms(serials.clone(), &discovery_pin);

    let source_session = open(&source);
    let mirrored = ids
        .iter()
        .map(|id| read_authentication_key_for_mirror(source_session, *id))
        .collect::<Vec<_>>();
    for key in &mirrored {
        eprintln!(
            "reference {:04x} {:?}: domains {:04x}, capabilities {:02x?}, delegated {:02x?}",
            key.info.id,
            key.info.label,
            key.info.domains,
            key.info.capabilities,
            key.info.delegated_capabilities
        );
    }
    assert_eq!(crate::api::C_CloseSession(source_session), CKR_OK as CK_RV);

    let mut target_sessions = Vec::with_capacity(targets.len());
    for target in &targets {
        let session = open(target);
        login(session, &bootstrap_pin, &format!("target {target}"));
        let discovery = crate::YubiHsmObjectInfo::parse(
            &command(
                session,
                &crate::YubiHsmCommand::get_object_info(1, crate::YUBIHSM_AUTHENTICATION_KEY),
            )
            .expect("target discovery Authentication Key is unreadable"),
        )
        .expect("target discovery Authentication Key metadata is invalid");
        let discovery_is_restricted = is_restricted_public_discovery(&discovery);
        for key in &mirrored {
            if let Some(actual) = inspect_target_authentication_key(session, key) {
                assert_matching_authentication_key(target, &actual, &key.info);
            }
        }
        target_sessions.push((target, session, discovery_is_restricted));
    }
    if std::env::var("PKCS11RS_MIRROR_APPLY").as_deref() != Ok("1") {
        eprintln!("preflight complete; no objects were written");
        for (_, session, _) in target_sessions {
            assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
            assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        }
        finalize_for_test();
        return;
    }

    for (target, session, _) in &target_sessions {
        for key in &mirrored {
            let result = crate::api::platform_credential::provision_platform_credential(
                *session,
                &key.info.label,
                key.info.id,
                &key.info.label,
                key.info.domains,
                key.info.capabilities,
                key.info.delegated_capabilities,
                &key.public_key,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "failed to mirror Authentication Key {:04x} to {target}: {error:?}",
                    key.info.id
                )
            });
            let actual = inspect_target_authentication_key(*session, key)
                .expect("mirrored Authentication Key is absent");
            assert_matching_authentication_key(target, &actual, &key.info);
            eprintln!(
                "{target}: Authentication Key {:04x} {:?} result {result}",
                key.info.id, key.info.label
            );
        }
    }

    let discovery_static_keys = crate::yubico_password_kdf(discovery_password.as_bytes())
        .expect("failed to derive public-discovery authentication keys");
    for (target, session, already_restricted) in &target_sessions {
        if *already_restricted {
            eprintln!("{target}: public discovery is already restricted");
            continue;
        }
        command(
            *session,
            &crate::YubiHsmCommand::delete_object(1, crate::YUBIHSM_AUTHENTICATION_KEY),
        )
        .unwrap_or_else(|error| panic!("failed to remove factory key from {target}: {error:?}"));
        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id: 1,
                label: "pkcs11rs public discovery",
                domains: u16::MAX,
                capabilities: crate::yubihsm_capabilities(&[0x00]),
                algorithm: crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: [0; 8],
        };
        let installed = command(
            *session,
            &crate::YubiHsmCommand::put_delegated_object(
                crate::YubiHsmCommandCode::PutAuthenticationKey,
                &parameters,
                discovery_static_keys.as_slice(),
            )
            .expect("failed to encode public-discovery Authentication Key"),
        )
        .and_then(|response| crate::parse_yubihsm_object_id(&response))
        .unwrap_or_else(|error| {
            panic!("failed to create restricted public-discovery key on {target}: {error:?}")
        });
        assert_eq!(installed, 1);
        eprintln!("{target}: replaced factory key with restricted public discovery");
    }
    for (_, session, _) in target_sessions {
        assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
    }

    finalize_for_test();
    initialize_remote_hsms(serials, &discovery_pin);
    for target in &targets {
        let session = open(target);
        let objects = inventory(session);
        for id in &ids {
            assert!(
                objects.iter().any(|(object_id, object_type, _)| {
                    object_id == id && *object_type == crate::YUBIHSM_AUTHENTICATION_KEY
                }),
                "{target}: mirrored Authentication Key {id:04x} is absent"
            );
        }
        let discovery = crate::YubiHsmObjectInfo::parse(
            &command(
                session,
                &crate::YubiHsmCommand::get_object_info(1, crate::YUBIHSM_AUTHENTICATION_KEY),
            )
            .expect("public-discovery metadata is unreadable"),
        )
        .expect("public-discovery metadata is invalid");
        assert!(is_restricted_public_discovery(&discovery));
        assert!(
            command(session, &crate::YubiHsmCommand::get_pseudo_random(1)).is_err(),
            "{target}: public-discovery credential unexpectedly generated random data"
        );
        assert_eq!(crate::api::C_CloseSession(session), CKR_OK as CK_RV);
        eprintln!("{target}: verified mirrored inventory and restricted discovery");
    }
    finalize_for_test();
}

fn initialize_cross_hsm(source: &str, target: &str, recreate_sessions: bool) {
    initialize_hsms(
        vec![source.to_owned(), target.to_owned()],
        recreate_sessions,
        None,
    );
}

fn p256_public_key(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> crate::SoftwarePublicKey {
    let encoded = read_hardware_attribute(session, object, CKA_EC_POINT as _);
    let point = crate::der_octet_string_value(&encoded).expect("P-256 point is not DER encoded");
    assert_eq!(point.len(), 65, "P-256 point has the wrong length");
    assert_eq!(point[0], 4, "P-256 point is not uncompressed");
    let key = crate::SoftwarePublicKey::Ec {
        curve: crate::EcCurve::P256,
        uncompressed: point.to_vec(),
    };
    key.validate().expect("P-256 point is invalid");
    key
}

fn find_named_key_pair(
    session: CK_SESSION_HANDLE,
    id: u16,
    label: &str,
) -> Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    let id = id.to_be_bytes();
    let public = find_hardware_object(session, CKO_PUBLIC_KEY as _, &id);
    let private = find_hardware_object(session, CKO_PRIVATE_KEY as _, &id);
    match (public, private) {
        (None, None) => None,
        (Some(public), Some(private)) => {
            for object in [public, private] {
                assert_eq!(
                    read_hardware_attribute(session, object, CKA_LABEL as _),
                    label.as_bytes(),
                    "existing source object {id:02x?} has a different label"
                );
            }
            Some((public, private))
        }
        _ => panic!("source key pair {id:02x?} is incomplete"),
    }
}

fn generate_p256_client_key(
    session: CK_SESSION_HANDLE,
    id: u16,
    label: &str,
    allowed_mechanisms: Option<&mut [CK_MECHANISM_TYPE]>,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    if let Some(pair) = find_named_key_pair(session, id, label) {
        return pair;
    }
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN as _,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut yes = CK_TRUE as CK_BBOOL;
    let mut no = CK_FALSE as CK_BBOOL;
    let mut id = id.to_be_bytes();
    let mut parameters = crate::ec_curve_parameters(crate::EcCurve::P256).to_vec();
    let mut public_label = label.as_bytes().to_vec();
    let mut private_label = public_label.clone();
    let mut public_template = [
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        bytes_attribute(CKA_ID as _, &mut id),
        bytes_attribute(CKA_LABEL as _, &mut public_label),
        bytes_attribute(CKA_EC_PARAMS as _, &mut parameters),
    ];
    let mut private_template = vec![
        scalar_attribute(CKA_TOKEN as _, &mut yes),
        scalar_attribute(CKA_PRIVATE as _, &mut yes),
        scalar_attribute(CKA_SENSITIVE as _, &mut yes),
        scalar_attribute(CKA_EXTRACTABLE as _, &mut no),
        scalar_attribute(CKA_DERIVE as _, &mut yes),
        scalar_attribute(CKA_SIGN as _, &mut no),
        bytes_attribute(CKA_ID as _, &mut id),
        bytes_attribute(CKA_LABEL as _, &mut private_label),
    ];
    if let Some(allowed) = allowed_mechanisms {
        private_template.push(CK_ATTRIBUTE {
            type_: CKA_ALLOWED_MECHANISMS as _,
            pValue: allowed.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(allowed) as _,
        });
    }
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    assert_eq!(
        crate::api::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_template.as_mut_ptr(),
            public_template.len() as _,
            private_template.as_mut_ptr(),
            private_template.len() as _,
            &mut public,
            &mut private,
        ),
        CKR_OK as CK_RV,
        "virtual client key generation failed"
    );
    (public, private)
}

fn provision_authentication_key(
    session: CK_SESSION_HANDLE,
    id: u16,
    label: &str,
    domains: u16,
    public_key: &crate::SoftwarePublicKey,
) -> CK_ULONG {
    let capabilities = crate::yubihsm_capabilities(&[0x13]); // get-pseudo-random
    crate::api::platform_credential::provision_platform_credential(
        session,
        label,
        id,
        label,
        domains,
        capabilities,
        [0; 8],
        public_key,
    )
    .expect("Authentication Key provisioning failed")
}

#[test]
#[ignore = "persistent additive provisioning for one virtual client and explicit physical targets"]
fn provisions_virtual_yubihsm_client_for_targets() {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_VIRTUAL_CLIENT_SOURCE");
    let targets: Vec<_> = required("PKCS11RS_VIRTUAL_CLIENT_TARGETS")
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!targets.is_empty());
    assert!(!targets.contains(&source));
    let mut unique_targets = targets.clone();
    unique_targets.sort();
    unique_targets.dedup();
    assert_eq!(targets.len(), unique_targets.len(), "duplicate targets");
    let source_pin = crate::Zeroizing::new(required("PKCS11RS_VIRTUAL_CLIENT_SOURCE_PIN"));
    let target_pin = crate::Zeroizing::new(required("PKCS11RS_VIRTUAL_CLIENT_TARGET_PIN"));
    let public_discovery = std::env::var("PKCS11RS_VIRTUAL_CLIENT_PUBLIC_DISCOVERY")
        .ok()
        .map(crate::Zeroizing::new);
    let mut shared_password =
        if std::env::var("PKCS11RS_VIRTUAL_CLIENT_SHARED_PINENTRY").as_deref() == Ok("1") {
            Some(shared_qualification_password())
        } else {
            None
        };
    let label = required("PKCS11RS_VIRTUAL_CLIENT_LABEL");
    assert!(!label.is_empty() && label.len() <= 40);
    let id = hex_u16(
        "PKCS11RS_VIRTUAL_CLIENT_ID",
        &required("PKCS11RS_VIRTUAL_CLIENT_ID"),
    );
    let platform_ids: Vec<_> = required("PKCS11RS_VIRTUAL_CLIENT_PLATFORM_IDS")
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| hex_u16("PKCS11RS_VIRTUAL_CLIENT_PLATFORM_IDS", id))
        .collect();
    assert!(!platform_ids.contains(&id));

    let mut serials = vec![source.clone()];
    serials.extend(targets.iter().cloned());
    assert!(
        platform_ids.is_empty() || public_discovery.is_some(),
        "platform projection discovery requires PKCS11RS_VIRTUAL_CLIENT_PUBLIC_DISCOVERY"
    );
    initialize_hsms(
        serials,
        true,
        public_discovery.as_deref().map(String::as_str),
    );
    let source_session = open(&source);
    login_with_password(
        source_session,
        &source_pin,
        &format!("source {source}"),
        shared_password
            .as_mut()
            .map(|password| password.as_mut_slice()),
    );
    let target_sessions: Vec<_> = targets
        .iter()
        .map(|target| {
            let session = open(target);
            login_with_password(
                session,
                &target_pin,
                &format!("target {target}"),
                shared_password.as_mut().map(|password| password.as_mut_slice()),
            );
            let credential = authenticated_credential(session);
            let authkey_id = crate::pkcs11_uri::ClientAuthUri::parse(credential.as_bytes())
                .expect("bootstrap credential description is not a PKCS #11 URI")
                .authkey_id
                .expect("bootstrap credential does not identify an Authentication Key");
            let info = crate::YubiHsmObjectInfo::parse(
                &command(
                    session,
                    &crate::YubiHsmCommand::get_object_info(
                        authkey_id,
                        crate::YUBIHSM_AUTHENTICATION_KEY,
                    ),
                )
                .unwrap_or_else(|_| panic!("{target}: bootstrap Authentication Key is unreadable")),
            )
            .unwrap_or_else(|_| panic!("{target}: bootstrap Authentication Key info is invalid"));
            assert!(
                crate::yubihsm_capability(&info.capabilities, 0x02),
                "target {target} bootstrap credential {credential} cannot provision Authentication Keys"
            );
            eprintln!("bootstrap target {target} with {credential}");
            (target, session)
        })
        .collect();

    let source_pair = find_named_key_pair(source_session, id, &label);
    let source_domains = crate::YubiHsmObjectInfo::parse(
        &command(
            source_session,
            &crate::YubiHsmCommand::get_object_info(1, crate::YUBIHSM_AUTHENTICATION_KEY),
        )
        .expect("source discovery Authentication Key is unreadable"),
    )
    .expect("source discovery Authentication Key info is invalid")
    .domains;
    let platform_credentials: Vec<_> = platform_ids
        .iter()
        .map(|platform_id| {
            let object = find_hardware_object(
                target_sessions[0].1,
                CKO_PUBLIC_KEY as _,
                &platform_id.to_be_bytes(),
            )
            .unwrap_or_else(|| panic!("target projection {platform_id:04x} is missing"));
            let label = String::from_utf8(read_hardware_attribute(
                target_sessions[0].1,
                object,
                CKA_LABEL as _,
            ))
            .expect("target projection label is not UTF-8");
            (
                *platform_id,
                label,
                p256_public_key(target_sessions[0].1, object),
            )
        })
        .collect();
    let target_domains: Vec<_> = target_sessions
        .iter()
        .map(|(target, session)| {
            let domains = crate::YubiHsmObjectInfo::parse(
                &command(
                    *session,
                    &crate::YubiHsmCommand::get_object_info(1, crate::YUBIHSM_AUTHENTICATION_KEY),
                )
                .unwrap_or_else(|_| panic!("{target}: discovery Authentication Key is unreadable")),
            )
            .unwrap_or_else(|_| panic!("{target}: discovery Authentication Key info is invalid"))
            .domains;
            (*target, domains)
        })
        .collect();
    eprintln!(
        "preflight: virtual source {source} domains {source_domains:04x}, client {id:04x} {label:?}, targets {:?}, platform keys {:?}",
        target_domains
            .iter()
            .map(|(target, domains)| format!("{target} domains {domains:04x}"))
            .collect::<Vec<_>>(),
        platform_credentials
            .iter()
            .map(|(id, label, _)| format!("{id:04x} {label:?}"))
            .collect::<Vec<_>>()
    );
    let apply = std::env::var("PKCS11RS_VIRTUAL_CLIENT_APPLY").as_deref() == Ok("1");
    if !apply && source_pair.is_none() {
        eprintln!(
            "preflight complete; the virtual source key is absent and no objects were written"
        );
        finalize_for_test();
        return;
    }

    let policy = std::env::var("PKCS11RS_VIRTUAL_CLIENT_KEY_POLICY")
        .unwrap_or_else(|_| "unrestricted".to_owned());
    let mut allowed = match policy.as_str() {
        "unrestricted" => None,
        "prefixed" => Some(vec![crate::CKM_PKCS11RS_PREFIXED_ECDH_DERIVE]),
        "graph" => Some(vec![CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE]),
        _ => panic!("PKCS11RS_VIRTUAL_CLIENT_KEY_POLICY must be unrestricted, prefixed, or graph"),
    };
    let (public, private) = source_pair.unwrap_or_else(|| {
        generate_p256_client_key(source_session, id, &label, allowed.as_deref_mut())
    });
    if let Some(expected) = &allowed {
        let encoded = read_hardware_attribute(source_session, private, CKA_ALLOWED_MECHANISMS as _);
        let actual = encoded
            .as_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>()
            .0
            .iter()
            .map(|bytes| CK_MECHANISM_TYPE::from_ne_bytes(*bytes))
            .collect::<Vec<_>>();
        assert_eq!(&actual, expected, "source key policy differs");
    }
    let public_key = p256_public_key(source_session, public);
    let source_uri = String::from_utf8(read_hardware_attribute(
        source_session,
        private,
        crate::CKA_PKCS11RS_URI,
    ))
    .expect("source URI is not UTF-8");
    if apply {
        for ((target, session), (_, domains)) in target_sessions.iter().zip(&target_domains) {
            let result = provision_authentication_key(*session, id, &label, *domains, &public_key);
            eprintln!("{target}: client Authentication Key {id:04x} result {result}");
        }
        for (platform_id, platform_label, platform_key) in &platform_credentials {
            let result = provision_authentication_key(
                source_session,
                *platform_id,
                platform_label,
                source_domains,
                platform_key,
            );
            eprintln!(
                "{source}: platform Authentication Key {platform_id:04x} {platform_label:?} result {result}"
            );
        }
    } else {
        eprintln!("qualification only; no objects written");
    }

    for (target, session) in &target_sessions {
        assert_eq!(crate::api::C_Logout(*session), CKR_OK as CK_RV);
        if std::env::var("PKCS11RS_VIRTUAL_CLIENT_SKIP_WILDCARD").as_deref() != Ok("1") {
            let mut wildcard = b"pkcs11:".to_vec();
            assert_eq!(
                crate::api::C_LoginUser(
                    *session,
                    CKU_USER as _,
                    std::ptr::null_mut(),
                    0,
                    wildcard.as_mut_ptr(),
                    wildcard.len() as _,
                ),
                CKR_OK as CK_RV,
                "wildcard failed to select the virtual client for {target}"
            );
            let selected_uri = authenticated_credential(*session);
            let selected = crate::pkcs11_uri::ClientAuthUri::parse(selected_uri.as_bytes())
                .expect("selected credential description is not a PKCS #11 URI");
            assert_eq!(
                selected.token.as_deref(),
                Some(format!("YubiHSM #{source}").as_bytes())
            );
            assert_eq!(selected.authkey_id, Some(id));
            eprintln!(
                "verified wildcard selected virtual source {source} => target {target}: {selected_uri}"
            );
            assert_eq!(crate::api::C_Logout(*session), CKR_OK as CK_RV);
        }
        assert_user_login(source_session);
        let mut selector = crate::pkcs11_uri::authentication_uri(&source_uri, id).into_bytes();
        assert_eq!(
            crate::api::C_LoginUser(
                *session,
                CKU_USER as _,
                std::ptr::null_mut(),
                0,
                selector.as_mut_ptr(),
                selector.len() as _,
            ),
            CKR_OK as CK_RV,
            "new virtual client failed to authenticate to {target}"
        );
        let mut random = [0u8; 32];
        assert_eq!(
            crate::api::C_GenerateRandom(*session, random.as_mut_ptr(), random.len() as _),
            CKR_OK as CK_RV
        );
        eprintln!("verified virtual client {source_uri} => target {target}");
    }
    finalize_for_test();
}

#[test]
#[ignore = "read-only qualification of explicitly provisioned virtual-client paths"]
fn qualifies_persisted_virtual_client_paths() {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_VIRTUAL_CLIENT_SOURCE");
    let targets: Vec<_> = required("PKCS11RS_VIRTUAL_CLIENT_TARGETS")
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!targets.is_empty());
    assert!(!targets.contains(&source));
    let keys: Vec<_> = required("PKCS11RS_VIRTUAL_CLIENT_KEYS")
        .split(',')
        .map(|specification| {
            let mut fields = specification.splitn(3, '=');
            let id = fields.next().expect("each key must be ID=PATH=LABEL");
            let path = fields.next().expect("each key must be ID=PATH=LABEL");
            let label = fields.next().expect("each key must be ID=PATH=LABEL");
            assert!(matches!(
                path,
                "native-protected-graph"
                    | "native-prefix-derive"
                    | "module-prefix-derive"
                    | "basic-ecdh"
            ));
            let label = label.trim().to_owned();
            assert!(!label.is_empty() && label.len() <= 40);
            (
                hex_u16("PKCS11RS_VIRTUAL_CLIENT_KEYS", id.trim()),
                path.to_owned(),
                label,
            )
        })
        .collect();
    assert!(!keys.is_empty());
    let source_pin = crate::Zeroizing::new(required("PKCS11RS_VIRTUAL_CLIENT_SOURCE_PIN"));
    let public_discovery =
        crate::Zeroizing::new(required("PKCS11RS_VIRTUAL_CLIENT_PUBLIC_DISCOVERY"));
    let mut password = shared_qualification_password();

    let mut serials = vec![source.clone()];
    serials.extend(targets.iter().cloned());
    initialize_hsms(serials, true, Some(public_discovery.as_str()));
    let source_session = open(&source);
    login_with_password(
        source_session,
        &source_pin,
        &format!("source {source}"),
        Some(password.as_mut_slice()),
    );
    assert_user_login(source_session);
    let sources: Vec<_> = keys
        .iter()
        .map(|(id, path, label)| {
            let (_, private) = find_named_key_pair(source_session, *id, label)
                .unwrap_or_else(|| panic!("source key {id:04x} {label:?} is absent"));
            let uri = String::from_utf8(read_hardware_attribute(
                source_session,
                private,
                crate::CKA_PKCS11RS_URI,
            ))
            .expect("source URI is not UTF-8");
            (*id, path, label, uri)
        })
        .collect();

    for target in &targets {
        let session = open(target);
        for (id, expected_path, label, source_uri) in &sources {
            let mut selector = crate::pkcs11_uri::authentication_uri(source_uri, *id).into_bytes();
            crate::key_scope::take_authentication_paths();
            assert_eq!(
                crate::api::C_LoginUser(
                    session,
                    CKU_USER as _,
                    std::ptr::null_mut(),
                    0,
                    selector.as_mut_ptr(),
                    selector.len() as _,
                ),
                CKR_OK as CK_RV,
                "{label:?} failed to authenticate to target {target}"
            );
            let paths = crate::key_scope::take_authentication_paths();
            assert!(
                paths.contains(&expected_path.as_str()),
                "{label:?} did not exercise {expected_path}; observed {paths:?}"
            );
            match expected_path.as_str() {
                "native-protected-graph" => {
                    assert!(!paths.contains(&"literal-prefix-derive"));
                    assert!(!paths.contains(&"basic-ecdh"));
                }
                "native-prefix-derive" => {
                    assert!(paths.contains(&"literal-prefix-derive"));
                    assert!(!paths.contains(&"module-prefix-derive"));
                    assert!(!paths.contains(&"basic-ecdh"));
                }
                "module-prefix-derive" => {
                    assert!(paths.contains(&"literal-prefix-derive"));
                    assert!(!paths.contains(&"native-prefix-derive"));
                    assert!(!paths.contains(&"basic-ecdh"));
                }
                "basic-ecdh" => {
                    assert!(!paths.contains(&"literal-prefix-derive"));
                    assert!(!paths.contains(&"native-prefix-derive"));
                    assert!(!paths.contains(&"module-prefix-derive"));
                }
                _ => unreachable!(),
            }
            let mut random = [0u8; 32];
            assert_eq!(
                crate::api::C_GenerateRandom(session, random.as_mut_ptr(), random.len() as _),
                CKR_OK as CK_RV,
                "authenticated command failed for {label:?} on target {target}"
            );
            let selected = authenticated_credential(session);
            assert_eq!(selected, String::from_utf8(selector).unwrap());
            eprintln!(
                "qualified {expected_path} with {label:?} from {source} => {target}; events {paths:?}; credential {selected}"
            );
            assert_eq!(crate::api::C_Logout(session), CKR_OK as CK_RV);
            assert_user_login(source_session);
        }
    }
    finalize_for_test();
}

fn verify_hardware_recreation(session: CK_SESSION_HANDLE, before: &[u8; 64]) {
    eprintln!("waiting 35 seconds without HSM traffic for the hardware session timeout");
    std::thread::sleep(std::time::Duration::from_secs(35));
    let mut after = [0u8; 64];
    assert_eq!(
        crate::api::C_GenerateRandom(session, after.as_mut_ptr(), after.len() as _),
        CKR_OK as CK_RV,
        "the first request after hardware expiry must recreate the session"
    );
    assert_ne!(*before, after);
    assert_eq!(
        hardware_session_state(session),
        CKS_RW_USER_FUNCTIONS as CK_STATE
    );
    let echo = b"encrypted traffic after hardware session recreation";
    assert_eq!(
        command(session, &crate::YubiHsmCommand::echo(echo).unwrap()).unwrap(),
        echo
    );
}

#[test]
#[ignore = "creates and removes temporary HSM keys; requires two explicit serials and bootstrap PINs"]
fn yubihsm_to_yubihsm_asymmetric_authentication() {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_CROSS_HSM_SOURCE");
    let target = required("PKCS11RS_CROSS_HSM_TARGET");
    assert_ne!(source, target, "source and target must differ");
    let source_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_SOURCE_PIN"));
    let target_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_TARGET_PIN"));
    initialize_cross_hsm(&source, &target, true);
    let source_session = open(&source);
    let target_session = open(&target);
    login(source_session, &source_pin, &format!("source {source}"));
    login(target_session, &target_pin, &format!("target {target}"));
    let source_before = inventory(source_session);
    let target_before = inventory(target_session);
    eprintln!(
        "source {source}: {} native objects; target {target}: {} native objects",
        source_before.len(),
        target_before.len()
    );
    let label = format!(
        "p11-cross-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut public = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut private = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
    let mut auth_id = None;
    // Always attempt cleanup after an assertion failure as well as success.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as _,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut yes = CK_TRUE as CK_BBOOL;
        let mut no = CK_FALSE as CK_BBOOL;
        let mut parameters = crate::ec_curve_parameters(crate::EcCurve::P256).to_vec();
        let mut public_label = label.as_bytes().to_vec();
        let mut private_label = public_label.clone();
        let mut public_template = [
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            bytes_attribute(CKA_LABEL as _, &mut public_label),
            bytes_attribute(CKA_EC_PARAMS as _, &mut parameters),
        ];
        let mut private_template = [
            scalar_attribute(CKA_TOKEN as _, &mut yes),
            scalar_attribute(CKA_PRIVATE as _, &mut yes),
            scalar_attribute(CKA_SENSITIVE as _, &mut yes),
            scalar_attribute(CKA_EXTRACTABLE as _, &mut no),
            scalar_attribute(CKA_DERIVE as _, &mut yes),
            scalar_attribute(CKA_SIGN as _, &mut no),
            bytes_attribute(CKA_LABEL as _, &mut private_label),
        ];
        assert_eq!(
            crate::api::C_GenerateKeyPair(
                source_session,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as _,
                private_template.as_mut_ptr(),
                private_template.len() as _,
                &mut public,
                &mut private
            ),
            CKR_OK as CK_RV,
            "source token key generation failed"
        );
        let point = read_hardware_attribute(source_session, public, CKA_EC_POINT as _);
        assert_eq!(
            &point[..3],
            &[4, 65, 4],
            "expected DER-wrapped uncompressed P-256 public point"
        );
        assert_eq!(point.len(), 67);
        let mut hidden = CK_ATTRIBUTE {
            type_: CKA_VALUE as _,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            crate::api::C_GetAttributeValue(source_session, private, &mut hidden, 1),
            CKR_ATTRIBUTE_SENSITIVE as CK_RV,
            "source private scalar must stay unreadable"
        );
        let source_id = read_hardware_attribute(source_session, private, CKA_ID as _);
        assert_eq!(
            source_id,
            read_hardware_attribute(source_session, public, CKA_ID as _)
        );
        let source_uri = read_hardware_attribute(source_session, private, crate::CKA_PKCS11RS_URI);
        let source_uri = std::str::from_utf8(&source_uri).expect("generated object URI is UTF-8");
        let allowed = read_hardware_attribute(source_session, private, CKA_ALLOWED_MECHANISMS as _);
        let allowed: Vec<_> = allowed
            .as_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>()
            .0
            .iter()
            .map(|bytes| CK_MECHANISM_TYPE::from_ne_bytes(*bytes))
            .collect();
        assert!(allowed.contains(&(CKM_ECDH1_DERIVE as _)));
        assert!(allowed.contains(&crate::CKM_PKCS11RS_PREFIXED_ECDH_DERIVE));
        let parameters = crate::yubihsm::DelegatedObjectParameters {
            object: crate::YubiHsmObjectParameters {
                id: 0,
                label: &label,
                domains: 1,
                capabilities: crate::yubihsm_capabilities(&[0x00, 0x13]), // get-opaque, get-pseudo-random
                algorithm: crate::YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
            },
            delegated_capabilities: [0; 8],
        };
        let put = crate::YubiHsmCommand::put_delegated_object(
            crate::YubiHsmCommandCode::PutAuthenticationKey,
            &parameters,
            &point[3..],
        )
        .unwrap();
        let id = crate::parse_yubihsm_object_id(&command(target_session, &put).unwrap()).unwrap();
        auth_id = Some(id);
        eprintln!("created temporary source key {label:?} and target Authentication Key {id:04x}");
        assert!(
            !target_before
                .iter()
                .any(|(old, kind, _)| *old == id && *kind == crate::YUBIHSM_AUTHENTICATION_KEY)
        );
        assert_eq!(crate::api::C_Logout(target_session), CKR_OK as CK_RV);
        let mut selector = crate::pkcs11_uri::authentication_uri(source_uri, id).into_bytes();
        // The source's existing USER session supplies authorization. No source
        // password or private scalar is passed to the target login.
        assert_eq!(
            crate::api::C_LoginUser(
                target_session,
                CKU_USER as _,
                std::ptr::null_mut(),
                0,
                selector.as_mut_ptr(),
                selector.len() as _
            ),
            CKR_OK as CK_RV,
            "cross-HSM login through the PKCS #11 source slot failed"
        );
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        assert_eq!(
            crate::api::C_GenerateRandom(target_session, first.as_mut_ptr(), first.len() as _),
            CKR_OK as CK_RV
        );
        assert_eq!(
            crate::api::C_GenerateRandom(target_session, second.as_mut_ptr(), second.len() as _),
            CKR_OK as CK_RV
        );
        assert_ne!(first, second);
        let echo = b"pkcs11rs physical HSM source authentication";
        assert_eq!(
            command(target_session, &crate::YubiHsmCommand::echo(echo).unwrap()).unwrap(),
            echo
        );
        eprintln!(
            "verified {source} -> {target}: protected source P-256, PKCS #11 login, two random requests and encrypted echo"
        );
        verify_hardware_recreation(target_session, &first);
        eprintln!("asymmetric recreation and protected traffic passed");
    }));
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rv = crate::api::C_Logout(target_session);
        assert!(rv == CKR_OK as CK_RV || rv == CKR_USER_NOT_LOGGED_IN as CK_RV);
        login(
            target_session,
            &target_pin,
            &format!("target {target} cleanup"),
        );
        if let Some(id) = auth_id {
            let response = command(
                target_session,
                &crate::YubiHsmCommand::delete_object(id, crate::YUBIHSM_AUTHENTICATION_KEY),
            )
            .unwrap();
            assert!(response.is_empty());
        }
        if public != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            assert_eq!(
                crate::api::C_DestroyObject(source_session, public),
                CKR_OK as CK_RV
            );
        }
        if private != CK_INVALID_HANDLE as CK_OBJECT_HANDLE {
            assert_eq!(
                crate::api::C_DestroyObject(source_session, private),
                CKR_OK as CK_RV
            );
        }
        assert_eq!(
            inventory(source_session),
            source_before,
            "source inventory differs after cleanup"
        );
        assert_eq!(
            inventory(target_session),
            target_before,
            "target inventory differs after cleanup"
        );
        eprintln!(
            "temporary objects removed; both native inventories match their pre-test snapshots"
        );
    }));
    finalize_for_test();
    if let Err(error) = cleanup {
        std::panic::resume_unwind(error);
    }
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[derive(Clone, Copy, Debug)]
enum SymmetricPath {
    Counter,
    Cbc,
    Ecb,
}

fn assert_symmetric_source_path(session: CK_SESSION_HANDLE, label: &str, expected: SymmetricPath) {
    use crate::key_scope::{CounterKdfPath, Pkcs11KeyScope, SymmetricCredential};
    use crate::pkcs11_provider::{Pkcs11Provider, ProviderSession};
    let slot = crate::with_session_context(session, |ctx| Ok(ctx.slot_id)).unwrap();
    let child = crate::with_context(|ctx| {
        ctx.slot_contexts
            .read()
            .map_err(|_| crate::Error::from(CKR_MUTEX_BAD))?
            .get(&slot)
            .cloned()
            .ok_or(CKR_SLOT_ID_INVALID.into())
    })
    .unwrap();
    let owner = ProviderSession::open(Pkcs11Provider::from_slot(child).unwrap()).unwrap();
    let pair = SymmetricCredential::find(owner, &format!("{label}.enc"), true).unwrap();
    let mut scope = Pkcs11KeyScope::for_key(&pair.enc).unwrap();
    for key in [&pair.enc, &pair.mac] {
        let base = scope.bind(key).unwrap();
        let path = scope.counter_kdf_path(&base).unwrap();
        assert!(
            matches!(
                (expected, path),
                (SymmetricPath::Counter, CounterKdfPath::Derive)
                    | (SymmetricPath::Cbc, CounterKdfPath::AesCbc)
                    | (SymmetricPath::Ecb, CounterKdfPath::AesEcb)
            ),
            "source key policy did not select {expected:?}"
        );
    }
}

fn symmetric_cross_hsm(path: SymmetricPath) {
    let _guard = TEST_LOCK.lock().unwrap();
    let source = required("PKCS11RS_CROSS_HSM_SOURCE");
    let target = required("PKCS11RS_CROSS_HSM_TARGET");
    assert_ne!(source, target);
    let source_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_SOURCE_PIN"));
    let target_pin = crate::Zeroizing::new(required("PKCS11RS_CROSS_HSM_TARGET_PIN"));
    initialize_cross_hsm(&source, &target, true);
    let source_session = open(&source);
    let target_session = open(&target);
    login(source_session, &source_pin, &format!("source {source}"));
    login(target_session, &target_pin, &format!("target {target}"));
    let source_before = inventory(source_session);
    let target_before = inventory(target_session);
    let label = format!(
        "p11-sym-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut handles = Vec::new();
    let mut auth_id = None;
    eprintln!(
        "{path:?}: source {source}: {} objects; target {target}: {} objects",
        source_before.len(),
        target_before.len()
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Provision the same random ENC/MAC pair on both devices, then discard
        // every local copy before authentication or recreation uses the keys.
        {
            let mut material = crate::Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut material[..]).unwrap();
            for (role, value) in ["enc", "mac"]
                .into_iter()
                .zip(material.as_chunks_mut::<16>().0)
            {
                let mut class = CKO_SECRET_KEY as CK_OBJECT_CLASS;
                let mut key_type = CKK_AES as CK_KEY_TYPE;
                let mut yes = CK_TRUE as CK_BBOOL;
                let mut no = CK_FALSE as CK_BBOOL;
                let mut derive = u8::from(matches!(path, SymmetricPath::Counter));
                let mut encrypt = u8::from(!matches!(path, SymmetricPath::Counter));
                let mut key_label = format!("{label}.{role}").into_bytes();
                let mut allowed: Vec<CK_MECHANISM_TYPE> = match path {
                    SymmetricPath::Counter => vec![CKM_SP800_108_COUNTER_KDF as _],
                    SymmetricPath::Cbc => vec![CKM_AES_ECB as _, CKM_AES_CBC as _],
                    SymmetricPath::Ecb => vec![CKM_AES_ECB as _],
                };
                let allowed = CK_ATTRIBUTE {
                    type_: CKA_ALLOWED_MECHANISMS as _,
                    pValue: allowed.as_mut_ptr().cast(),
                    ulValueLen: std::mem::size_of_val(allowed.as_slice()) as _,
                };
                let mut template = [
                    scalar_attribute(CKA_CLASS as _, &mut class),
                    scalar_attribute(CKA_KEY_TYPE as _, &mut key_type),
                    scalar_attribute(CKA_TOKEN as _, &mut yes),
                    scalar_attribute(CKA_PRIVATE as _, &mut yes),
                    scalar_attribute(CKA_SENSITIVE as _, &mut yes),
                    scalar_attribute(CKA_EXTRACTABLE as _, &mut no),
                    scalar_attribute(CKA_ENCRYPT as _, &mut encrypt),
                    scalar_attribute(CKA_DECRYPT as _, &mut no),
                    scalar_attribute(CKA_SIGN as _, &mut no),
                    scalar_attribute(CKA_VERIFY as _, &mut no),
                    scalar_attribute(CKA_DERIVE as _, &mut derive),
                    bytes_attribute(CKA_LABEL as _, &mut key_label),
                    bytes_attribute(CKA_VALUE as _, value),
                    allowed,
                ];
                let mut key = CK_INVALID_HANDLE as CK_OBJECT_HANDLE;
                assert_eq!(
                    crate::api::C_CreateObject(
                        source_session,
                        template.as_mut_ptr(),
                        template.len() as _,
                        &mut key
                    ),
                    CKR_OK as CK_RV
                );
                handles.push(key);
                let mut hidden = CK_ATTRIBUTE {
                    type_: CKA_VALUE as _,
                    pValue: std::ptr::null_mut(),
                    ulValueLen: 0,
                };
                assert_eq!(
                    crate::api::C_GetAttributeValue(source_session, key, &mut hidden, 1),
                    CKR_ATTRIBUTE_SENSITIVE as CK_RV
                );
                let id = read_hardware_attribute(source_session, key, CKA_ID as _);
                let native_id = u16::from_be_bytes(id.as_slice().try_into().unwrap());
                assert!(
                    !source_before
                        .iter()
                        .any(|(id, kind, _)| *id == native_id
                            && *kind == crate::YUBIHSM_SYMMETRIC_KEY)
                );
                let info = crate::YubiHsmObjectInfo::parse(
                    &command(
                        source_session,
                        &crate::YubiHsmCommand::get_object_info(
                            native_id,
                            crate::YUBIHSM_SYMMETRIC_KEY,
                        ),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(info.algorithm, crate::YUBIHSM_ALGO_AES128);
                assert!(
                    !crate::yubihsm_capability(&info.capabilities, 0x10),
                    "native key must not be exportable under wrap"
                );
                assert!(crate::yubihsm_capability(&info.capabilities, 0x33));
                if matches!(path, SymmetricPath::Cbc) {
                    assert!(crate::yubihsm_capability(&info.capabilities, 0x35));
                }
            }
            let params = crate::yubihsm::DelegatedObjectParameters {
                object: crate::YubiHsmObjectParameters {
                    id: 0,
                    label: &label,
                    domains: 1,
                    capabilities: crate::yubihsm_capabilities(&[0x00, 0x13]),
                    algorithm: crate::YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION,
                },
                delegated_capabilities: [0; 8],
            };
            let put = crate::YubiHsmCommand::put_delegated_object(
                crate::YubiHsmCommandCode::PutAuthenticationKey,
                &params,
                &material[..],
            )
            .unwrap();
            let id =
                crate::parse_yubihsm_object_id(&command(target_session, &put).unwrap()).unwrap();
            auth_id = Some(id);
            assert!(
                !target_before
                    .iter()
                    .any(|(old, kind, _)| *old == id && *kind == crate::YUBIHSM_AUTHENTICATION_KEY)
            );
        }
        assert_symmetric_source_path(source_session, &label, path);
        assert_eq!(crate::api::C_Logout(target_session), CKR_OK as CK_RV);
        let mut selector = format!(":{:04x}{label}@{source}", auth_id.unwrap()).into_bytes();
        assert_eq!(
            crate::api::C_LoginUser(
                target_session,
                CKU_USER as _,
                std::ptr::null_mut(),
                0,
                selector.as_mut_ptr(),
                selector.len() as _
            ),
            CKR_OK as CK_RV,
            "{path:?} login through source AES token keys failed"
        );
        let mut before_expiry = [0u8; 64];
        assert_eq!(
            crate::api::C_GenerateRandom(
                target_session,
                before_expiry.as_mut_ptr(),
                before_expiry.len() as _
            ),
            CKR_OK as CK_RV
        );
        let echo = b"physical symmetric HSM source authentication";
        assert_eq!(
            command(target_session, &crate::YubiHsmCommand::echo(echo).unwrap()).unwrap(),
            echo
        );
        eprintln!(
            "{path:?}: authenticated {source} -> {target}; waiting 35 seconds for hardware session expiry"
        );
        verify_hardware_recreation(target_session, &before_expiry);
        eprintln!("{path:?}: recreation and protected traffic passed");
    }));
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rv = crate::api::C_Logout(target_session);
        assert!(rv == CKR_OK as CK_RV || rv == CKR_USER_NOT_LOGGED_IN as CK_RV);
        login(
            target_session,
            &target_pin,
            &format!("target {target} cleanup"),
        );
        if let Some(id) = auth_id {
            assert!(
                command(
                    target_session,
                    &crate::YubiHsmCommand::delete_object(id, crate::YUBIHSM_AUTHENTICATION_KEY)
                )
                .unwrap()
                .is_empty()
            );
        }
        for handle in handles {
            assert_eq!(
                crate::api::C_DestroyObject(source_session, handle),
                CKR_OK as CK_RV
            );
        }
        assert_eq!(
            inventory(source_session),
            source_before,
            "source inventory differs after cleanup"
        );
        assert_eq!(
            inventory(target_session),
            target_before,
            "target inventory differs after cleanup"
        );
        eprintln!("{path:?}: temporary objects removed; both inventories restored");
    }));
    finalize_for_test();
    if let Err(error) = cleanup {
        std::panic::resume_unwind(error);
    }
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[ignore = "provisions temporary HSM keys and waits for hardware session expiry"]
fn yubihsm_to_yubihsm_symmetric_counter() {
    symmetric_cross_hsm(SymmetricPath::Counter);
}

#[test]
#[ignore = "provisions temporary HSM keys and waits for hardware session expiry"]
fn yubihsm_to_yubihsm_symmetric_cbc() {
    symmetric_cross_hsm(SymmetricPath::Cbc);
}

#[test]
#[ignore = "provisions temporary HSM keys and waits for hardware session expiry"]
fn yubihsm_to_yubihsm_symmetric_ecb() {
    symmetric_cross_hsm(SymmetricPath::Ecb);
}
