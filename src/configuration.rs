use crate::{
    CKR_ARGUMENTS_BAD, CcidApplication, CcidConfiguration, Error,
    logging::LogLevel,
    scp03::{parse_hex, validate_security_level},
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsString, c_char},
    path::PathBuf,
    time::Duration,
};
use zeroize::Zeroizing;

pub(crate) const MAX_CONFIGURATION_STRING_BYTES: usize = 64 * 1024;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonConfiguration {
    version: u32,
    #[serde(default)]
    logging: JsonLoggingConfiguration,
    pinentry: Option<String>,
    #[serde(default)]
    hardware: JsonHardwareConfiguration,
    #[serde(default)]
    discovery: JsonDiscoveryConfiguration,
    #[serde(default)]
    slots: JsonSlotsConfiguration,
    #[serde(default)]
    storage: JsonStorageConfiguration,
    #[serde(default)]
    software: JsonSoftwareConfiguration,
    #[serde(default)]
    embedded: JsonEmbeddedConfiguration,
    #[serde(default)]
    platform: JsonPlatformConfiguration,
    #[serde(default)]
    yubihsm: JsonYubiHsmConfiguration,
    #[serde(default)]
    ccid: JsonCcidConfiguration,
    #[serde(default)]
    nfc: JsonNfcConfiguration,
    #[serde(default)]
    scp03: JsonScp03Configuration,
    #[serde(default)]
    scp11: JsonScp11Configuration,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonLoggingConfiguration {
    level: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonHardwareConfiguration {
    discovery: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDiscoveryConfiguration {
    refresh_interval_ms: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSlotsConfiguration {
    serials: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonStorageConfiguration {
    tokens: Option<String>,
    fido2_compatibility: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSoftwareConfiguration {
    slots: Option<Vec<JsonSoftwareSlotConfiguration>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSoftwareSlotConfiguration {
    name: String,
    discovery_pin: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEmbeddedConfiguration {
    readers: Option<Vec<JsonEmbeddedReaderConfiguration>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEmbeddedReaderConfiguration {
    id: String,
    name: String,
    serial: u32,
    #[serde(default)]
    persistent: bool,
    applets: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonPlatformConfiguration {
    enabled: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonYubiHsmConfiguration {
    urls: Option<Vec<String>>,
    recreate_sessions: Option<bool>,
    public_discovery: Option<String>,
    device_trust_prefix: Option<String>,
    #[serde(default)]
    tls: JsonYubiHsmTlsConfiguration,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonYubiHsmTlsConfiguration {
    client_certificate_bundle: Option<String>,
    client_private_key: Option<String>,
    ca_certificate_bundle: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonCcidConfiguration {
    applications: Option<Vec<String>>,
    secure_channel: Option<String>,
    client_uri: Option<String>,
    recreate_sessions: Option<bool>,
    #[serde(default)]
    aids: JsonCcidAidConfiguration,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonNfcConfiguration {
    discovery: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonCcidAidConfiguration {
    piv: Option<String>,
    openpgp: Option<String>,
    hsmauth: Option<String>,
    issuer_sd: Option<String>,
    fido2: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonScp03Configuration {
    bmk: Option<String>,
    enc_key: Option<String>,
    mac_key: Option<String>,
    dek_key: Option<String>,
    key_version: Option<u8>,
    key_id: Option<u8>,
    security_level: Option<u8>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonScp11Configuration {
    sd_public_key: Option<String>,
    sd_ca_certificate: Option<String>,
    sd_intermediate_bundle: Option<String>,
    key_version: Option<u8>,
    oce_private_key: Option<String>,
    oce_intermediate_bundle: Option<String>,
    oce_certificate_bundle: Option<String>,
    oce_key_version: Option<u8>,
    oce_key_id: Option<u8>,
}

#[derive(Clone)]
pub(crate) enum Scp03KeyMaterialConfiguration {
    Factory,
    Direct {
        enc: Zeroizing<Vec<u8>>,
        mac: Zeroizing<Vec<u8>>,
        dek: Option<Zeroizing<Vec<u8>>>,
    },
    YubicoBatchMasterKey(Zeroizing<Vec<u8>>),
}

#[derive(Clone)]
pub(crate) struct Scp03Configuration {
    pub(crate) key_material: Scp03KeyMaterialConfiguration,
    pub(crate) key_version: u8,
    pub(crate) key_id: u8,
    pub(crate) security_level: u8,
}

#[derive(Clone)]
pub(crate) enum Scp11TrustConfiguration {
    Yubico,
    PublicKey(Vec<u8>),
    CaCertificate(PathBuf),
}

#[derive(Clone)]
pub(crate) struct Scp11OceConfiguration {
    pub(crate) private_key: PathBuf,
    pub(crate) certificate_bundle: PathBuf,
    pub(crate) key_version: u8,
    pub(crate) key_id: u8,
}

#[derive(Clone)]
pub(crate) struct Scp11Configuration {
    pub(crate) trust: Scp11TrustConfiguration,
    pub(crate) sd_intermediates: Vec<Vec<u8>>,
    pub(crate) key_version: u8,
    pub(crate) oce: Option<Scp11OceConfiguration>,
    pub(crate) issuer_sd_aid: Vec<u8>,
    pub(crate) oce_intermediates: Vec<Vec<u8>>,
    pub(crate) oce_key_version: u8,
    pub(crate) oce_key_id: u8,
}

#[derive(Clone)]
pub(crate) struct SecureChannelConfiguration {
    pub(crate) recreate_sessions: bool,
    pub(crate) client_uri: Option<Vec<u8>>,
    pub(crate) scp03: Scp03Configuration,
    pub(crate) scp11: Scp11Configuration,
}

#[cfg(test)]
impl SecureChannelConfiguration {
    pub(crate) fn for_test() -> Self {
        Self {
            recreate_sessions: true,
            client_uri: None,
            scp03: Scp03Configuration {
                key_material: Scp03KeyMaterialConfiguration::Factory,
                key_version: 255,
                key_id: 0,
                security_level: 0x33,
            },
            scp11: Scp11Configuration {
                trust: Scp11TrustConfiguration::Yubico,
                sd_intermediates: Vec::new(),
                key_version: 1,
                oce: None,
                oce_intermediates: Vec::new(),
                oce_key_version: 0,
                oce_key_id: 0,
                issuer_sd_aid: crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID.to_vec(),
            },
        }
    }
}

pub(crate) struct ModuleConfiguration {
    pub(crate) logging_level: Option<LogLevel>,
    pub(crate) pinentry: Option<OsString>,
    pub(crate) hardware_discovery: bool,
    pub(crate) discovery_refresh_interval: Duration,
    pub(crate) slot_serials: Option<HashSet<String>>,
    pub(crate) token_storage: Option<OsString>,
    pub(crate) fido2_storage: Option<OsString>,
    pub(crate) software_slots: Vec<String>,
    #[cfg_attr(not(feature = "embedded-virtual-yubikey"), allow(dead_code))]
    pub(crate) embedded_readers: Vec<EmbeddedReaderConfiguration>,
    pub(crate) platform_enabled: bool,
    pub(crate) software_discovery_pins: HashMap<String, Zeroizing<Vec<u8>>>,
    pub(crate) yubihsm_urls: Vec<String>,
    pub(crate) yubihsm_recreate_sessions: bool,
    pub(crate) yubihsm_public_discovery: Option<OsString>,
    pub(crate) yubihsm_device_trust_prefix: OsString,
    pub(crate) yubihsm_tls_client_certificate_bundle: Option<OsString>,
    pub(crate) yubihsm_tls_client_private_key: Option<OsString>,
    pub(crate) yubihsm_tls_ca_certificate_bundle: Option<OsString>,
    pub(crate) ccid_configurations: Vec<CcidConfiguration>,
    pub(crate) ccid_aids: CcidAidConfiguration,
    pub(crate) nfc_discovery: bool,
    pub(crate) secure_channels: SecureChannelConfiguration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedReaderConfiguration {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) serial: u32,
    pub(crate) persistent: bool,
    pub(crate) applets: Vec<CcidApplication>,
}

pub(crate) struct CcidAidConfiguration {
    piv: Vec<u8>,
    openpgp: Vec<u8>,
    hsmauth: Vec<u8>,
    issuer_sd: Vec<u8>,
    fido2: Vec<u8>,
}

impl CcidAidConfiguration {
    pub(crate) fn for_application(&self, application: CcidApplication) -> &[u8] {
        match application {
            CcidApplication::Piv => &self.piv,
            CcidApplication::OpenPgp => &self.openpgp,
            CcidApplication::HsmAuth => &self.hsmauth,
            CcidApplication::IssuerSecurityDomain => &self.issuer_sd,
            CcidApplication::Fido2 => &self.fido2,
        }
    }
}

impl JsonConfiguration {
    pub(crate) fn from_bytes(encoded: &[u8]) -> Result<Option<Self>, Error> {
        let encoded = std::str::from_utf8(encoded).map_err(|_| CKR_ARGUMENTS_BAD)?;
        if encoded.trim().is_empty() {
            return Ok(None);
        }
        if !encoded.trim_start().starts_with('{') {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let configuration: Self = serde_json::from_str(encoded).map_err(|_| CKR_ARGUMENTS_BAD)?;
        if configuration.version != 1 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Some(configuration))
    }

    pub(crate) unsafe fn from_reserved(
        reserved: *mut std::ffi::c_void,
    ) -> Result<ReservedConfiguration, Error> {
        if reserved.is_null() {
            return Ok(ReservedConfiguration::Empty);
        }
        // Reject small integer sentinels before inspecting configuration text.
        // They are invalid pointers, not the valid NULL/default-config input.
        if reserved.addr() <= u8::MAX as usize {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let pointer = reserved.cast::<c_char>().cast::<u8>();
        let mut length = None;
        for offset in 0..MAX_CONFIGURATION_STRING_BYTES {
            if unsafe { pointer.add(offset).read() } == 0 {
                length = Some(offset);
                break;
            }
        }
        let Some(length) = length else {
            return Err(CKR_ARGUMENTS_BAD.into());
        };
        if length == 0 {
            return Ok(ReservedConfiguration::Empty);
        }
        let encoded = unsafe { std::slice::from_raw_parts(pointer, length) };
        let encoded = std::str::from_utf8(encoded).map_err(|_| CKR_ARGUMENTS_BAD)?;
        if encoded.trim().is_empty() {
            return Ok(ReservedConfiguration::Empty);
        }
        if !encoded.trim_start().starts_with('{') {
            return Ok(ReservedConfiguration::Opaque);
        }
        Ok(ReservedConfiguration::Json(Box::new(
            Self::from_bytes(encoded.as_bytes())?.ok_or(CKR_ARGUMENTS_BAD)?,
        )))
    }
}

pub(crate) enum ReservedConfiguration {
    Empty,
    Opaque,
    Json(Box<JsonConfiguration>),
}

impl ModuleConfiguration {
    /// Isolated, in-memory provider configuration. Never consult application
    /// configuration, environment variables, storage paths, or device discovery.
    pub(crate) fn private_software() -> Result<Self, Error> {
        let mut explicit = JsonConfiguration::default();
        explicit.hardware.discovery = Some(false);
        let mut configuration = Self::resolve_with(Some(explicit), |_| Ok(None))?;
        configuration.software_slots = vec!["private authentication".to_owned()];
        Ok(configuration)
    }

    pub(crate) fn resolve(explicit: Option<JsonConfiguration>) -> Result<Self, Error> {
        Self::resolve_with(explicit, |name| Ok(std::env::var_os(name)))
    }

    fn resolve_with(
        explicit: Option<JsonConfiguration>,
        mut environment: impl FnMut(&str) -> Result<Option<OsString>, Error>,
    ) -> Result<Self, Error> {
        let explicit = explicit.unwrap_or_default();
        let logging_level = match explicit.logging.level {
            Some(level) => Some(LogLevel::parse(&level).ok_or(CKR_ARGUMENTS_BAD)?),
            None => environment_text("PKCS11RS_LOG", &mut environment)?
                .map(|level| LogLevel::parse(&level).ok_or(CKR_ARGUMENTS_BAD))
                .transpose()?,
        };

        let discovery_refresh_interval =
            Duration::from_millis(match explicit.discovery.refresh_interval_ms {
                Some(interval) => interval,
                None => {
                    environment_text("PKCS11RS_DISCOVERY_REFRESH_INTERVAL_MS", &mut environment)?
                        .map(|value| value.parse::<u64>().map_err(|_| CKR_ARGUMENTS_BAD))
                        .transpose()?
                        .unwrap_or(500)
                }
            });
        let slot_serials = match explicit.slots.serials {
            Some(serials) => Some(serials),
            None => environment_text("PKCS11RS_SLOTS_SERIALS", &mut environment)?.map(|value| {
                if value.trim().is_empty() {
                    Vec::new()
                } else {
                    value.split(',').map(str::to_owned).collect()
                }
            }),
        }
        .map(|serials| {
            serials
                .into_iter()
                .map(|serial| {
                    let serial = serial.trim();
                    if serial.is_empty() || serial.contains(',') {
                        Err(CKR_ARGUMENTS_BAD)
                    } else {
                        Ok(serial.to_owned())
                    }
                })
                .collect::<Result<HashSet<_>, _>>()
        })
        .transpose()?;
        let hardware_discovery = explicit
            .hardware
            .discovery
            .or(environment_switch(
                "PKCS11RS_HARDWARE_DISCOVERY",
                &mut environment,
            )?)
            .unwrap_or(true);
        let platform_enabled = explicit
            .platform
            .enabled
            .or(environment_switch(
                "PKCS11RS_PLATFORM_ENABLED",
                &mut environment,
            )?)
            .unwrap_or(false);
        let token_storage = resolve_os(
            explicit.storage.tokens,
            "PKCS11RS_TOKEN_STORAGE",
            &mut environment,
        )?;
        let fido2_storage = resolve_os(
            explicit.storage.fido2_compatibility,
            "PKCS11RS_FIDO2_STORAGE",
            &mut environment,
        )?;
        let yubihsm_recreate_sessions = explicit
            .yubihsm
            .recreate_sessions
            .or(environment_switch(
                "PKCS11RS_YUBIHSM_RECREATE_SESSIONS",
                &mut environment,
            )?)
            .unwrap_or(false);

        let software_slots = resolve_software_slots(explicit.software.slots, &mut environment)?;
        let software_discovery_pins = software_slots
            .iter()
            .filter_map(|slot| {
                slot.discovery_pin
                    .as_ref()
                    .map(|pin| (slot.name.clone(), Zeroizing::new(pin.as_bytes().to_vec())))
            })
            .collect();
        let software_slots = software_slots.into_iter().map(|slot| slot.name).collect();
        let embedded_readers = resolve_embedded_readers(explicit.embedded.readers)?;
        if !embedded_readers.is_empty() && !cfg!(feature = "embedded-virtual-yubikey") {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if embedded_readers.iter().any(|reader| reader.persistent) && token_storage.is_none() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        let yubihsm_urls = match explicit.yubihsm.urls {
            Some(urls) => validate_urls(urls)?,
            None => environment_text("PKCS11RS_YUBIHSM_URLS", &mut environment)?
                .map(|urls| split_list(&urls, false))
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|url| url.trim_end_matches('/').to_owned())
                .collect(),
        };

        let protocol = match explicit.ccid.secure_channel {
            Some(protocol) => Some(crate::parse_secure_channel(&protocol)?),
            None => environment_text("PKCS11RS_CCID_SECURE_CHANNEL", &mut environment)?
                .map(|protocol| crate::parse_secure_channel(&protocol))
                .transpose()?,
        };
        let client_uri = match explicit.ccid.client_uri {
            Some(uri) => Some(uri),
            None => environment_text("PKCS11RS_CCID_CLIENT_URI", &mut environment)?,
        }
        .map(|uri| {
            crate::ccid_auth::selection(uri.as_bytes(), protocol)?;
            Ok::<_, Error>(uri.into_bytes())
        })
        .transpose()?;
        let applications = match explicit.ccid.applications {
            Some(applications) => parse_applications(applications)?,
            None => environment_text("PKCS11RS_CCID_APPLICATIONS", &mut environment)?
                .map(|applications| crate::parse_ccid_application_list(&applications))
                .transpose()?
                .unwrap_or_else(crate::default_ccid_applications),
        };
        let ccid_configurations = applications
            .into_iter()
            .map(|application| CcidConfiguration {
                application,
                secure_channel: protocol,
            })
            .collect();

        let ccid_aids = CcidAidConfiguration {
            piv: resolve_aid(
                explicit.ccid.aids.piv,
                "PKCS11RS_PIV_AID",
                &crate::piv::PIV_AID,
                &mut environment,
            )?,
            openpgp: resolve_aid(
                explicit.ccid.aids.openpgp,
                "PKCS11RS_OPENPGP_AID",
                &crate::openpgp::OPENPGP_AID,
                &mut environment,
            )?,
            hsmauth: resolve_aid(
                explicit.ccid.aids.hsmauth,
                "PKCS11RS_HSMAUTH_AID",
                &crate::hsmauth::AID,
                &mut environment,
            )?,
            issuer_sd: resolve_aid(
                explicit.ccid.aids.issuer_sd,
                "PKCS11RS_ISSUER_SD_AID",
                &crate::scp03::DEFAULT_ISSUER_SECURITY_DOMAIN_AID,
                &mut environment,
            )?,
            fido2: resolve_aid(
                explicit.ccid.aids.fido2,
                "PKCS11RS_FIDO2_AID",
                &crate::ctap::FIDO2_AID,
                &mut environment,
            )?,
        };

        let nfc_discovery = explicit
            .nfc
            .discovery
            .or(environment_switch(
                "PKCS11RS_NFC_DISCOVERY",
                &mut environment,
            )?)
            .unwrap_or(false);

        let ccid_recreate_sessions = explicit
            .ccid
            .recreate_sessions
            .or(environment_switch(
                "PKCS11RS_CCID_RECREATE_SESSIONS",
                &mut environment,
            )?)
            .unwrap_or(true);
        let scp03 = resolve_scp03(explicit.scp03, &mut environment)?;
        let scp11 = resolve_scp11(
            explicit.scp11,
            ccid_aids.issuer_sd.clone(),
            &mut environment,
        )?;

        Ok(Self {
            logging_level,
            pinentry: resolve_os(explicit.pinentry, "PKCS11RS_PINENTRY", &mut environment)?,
            hardware_discovery,
            discovery_refresh_interval,
            slot_serials,
            token_storage,
            fido2_storage,
            software_slots,
            embedded_readers,
            platform_enabled,
            software_discovery_pins,
            yubihsm_urls,
            yubihsm_recreate_sessions,
            yubihsm_public_discovery: resolve_os(
                explicit.yubihsm.public_discovery,
                "PKCS11RS_YUBIHSM_DISCOVERY",
                &mut environment,
            )?,
            yubihsm_device_trust_prefix: resolve_os(
                explicit.yubihsm.device_trust_prefix,
                "PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX",
                &mut environment,
            )?
            .unwrap_or_default(),
            yubihsm_tls_client_certificate_bundle: resolve_os(
                explicit.yubihsm.tls.client_certificate_bundle,
                "PKCS11RS_YUBIHSM_TLS_CLIENT_CERTIFICATE_BUNDLE",
                &mut environment,
            )?,
            yubihsm_tls_client_private_key: resolve_os(
                explicit.yubihsm.tls.client_private_key,
                "PKCS11RS_YUBIHSM_TLS_CLIENT_PRIVATE_KEY",
                &mut environment,
            )?,
            yubihsm_tls_ca_certificate_bundle: resolve_os(
                explicit.yubihsm.tls.ca_certificate_bundle,
                "PKCS11RS_YUBIHSM_TLS_CA_CERTIFICATE_BUNDLE",
                &mut environment,
            )?,
            ccid_configurations,
            ccid_aids,
            nfc_discovery,
            secure_channels: SecureChannelConfiguration {
                recreate_sessions: ccid_recreate_sessions,
                client_uri,
                scp03,
                scp11,
            },
        })
    }
}

fn resolve_embedded_readers(
    explicit: Option<Vec<JsonEmbeddedReaderConfiguration>>,
) -> Result<Vec<EmbeddedReaderConfiguration>, Error> {
    let readers = explicit.unwrap_or_default();
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut serials = HashSet::new();
    readers
        .into_iter()
        .map(|reader| {
            let id = reader.id.trim();
            let name = reader.name.trim();
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || name.is_empty()
                || name.len() > 128
                || reader.serial == 0
                || !ids.insert(id.to_owned())
                || !names.insert(name.to_owned())
                || !serials.insert(reader.serial)
            {
                return Err(CKR_ARGUMENTS_BAD.into());
            }
            let applets = parse_applications(reader.applets)?;
            Ok(EmbeddedReaderConfiguration {
                id: id.to_owned(),
                name: name.to_owned(),
                serial: reader.serial,
                persistent: reader.persistent,
                applets,
            })
        })
        .collect()
}

struct ResolvedSoftwareSlot {
    name: String,
    discovery_pin: Option<String>,
}

fn resolve_software_slots(
    explicit: Option<Vec<JsonSoftwareSlotConfiguration>>,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Vec<ResolvedSoftwareSlot>, Error> {
    let slots = match explicit {
        Some(slots) => slots,
        None => environment_text("PKCS11RS_SOFTWARE_SLOTS", environment)?
            .map(|slots| split_list(&slots, true))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|name| JsonSoftwareSlotConfiguration {
                name,
                discovery_pin: None,
            })
            .collect(),
    };
    let mut resolved = Vec::with_capacity(slots.len());
    for slot in slots {
        if slot.name.is_empty()
            || slot.name.len() > 32
            || resolved
                .iter()
                .any(|configured: &ResolvedSoftwareSlot| configured.name == slot.name)
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let variable = format!(
            "PKCS11RS_SOFTWARE_DISCOVERY_{}",
            encode_path_component(slot.name.as_bytes()).to_ascii_uppercase()
        );
        let discovery_pin = match slot.discovery_pin {
            Some(pin) => Some(pin),
            None => environment_text(&variable, environment)?,
        };
        if let Some(pin) = discovery_pin.as_deref() {
            crate::software_storage::validate_software_pin(pin.as_bytes())?;
        }
        resolved.push(ResolvedSoftwareSlot {
            name: slot.name,
            discovery_pin,
        });
    }
    Ok(resolved)
}

fn resolve_scp03(
    explicit: JsonScp03Configuration,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Scp03Configuration, Error> {
    let bmk = resolve_secret_hex(explicit.bmk, "PKCS11RS_SCP03_BMK", environment)?;
    let enc = resolve_secret_hex(explicit.enc_key, "PKCS11RS_SCP03_ENC_KEY", environment)?;
    let mac = resolve_secret_hex(explicit.mac_key, "PKCS11RS_SCP03_MAC_KEY", environment)?;
    let dek = resolve_secret_hex(explicit.dek_key, "PKCS11RS_SCP03_DEK_KEY", environment)?;
    let any_direct = enc.is_some() || mac.is_some() || dek.is_some();
    if bmk.is_some() && any_direct {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let key_material = if let Some(bmk) = bmk {
        Scp03KeyMaterialConfiguration::YubicoBatchMasterKey(bmk)
    } else if any_direct {
        Scp03KeyMaterialConfiguration::Direct {
            enc: enc.ok_or(CKR_ARGUMENTS_BAD)?,
            mac: mac.ok_or(CKR_ARGUMENTS_BAD)?,
            dek,
        }
    } else {
        Scp03KeyMaterialConfiguration::Factory
    };
    let key_version = explicit
        .key_version
        .or(environment_byte("PKCS11RS_SCP03_KEY_VERSION", environment)?)
        .unwrap_or(255);
    let key_id = explicit
        .key_id
        .or(environment_byte("PKCS11RS_SCP03_KEY_ID", environment)?)
        .unwrap_or(0);
    if matches!(key_material, Scp03KeyMaterialConfiguration::Factory)
        && (key_version != 255 || key_id != 0)
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let security_level = explicit
        .security_level
        .or(environment_byte(
            "PKCS11RS_SCP03_SECURITY_LEVEL",
            environment,
        )?)
        .unwrap_or(0x33);
    validate_security_level(security_level)?;
    Ok(Scp03Configuration {
        key_material,
        key_version,
        key_id,
        security_level,
    })
}

fn resolve_scp11(
    explicit: JsonScp11Configuration,
    issuer_sd_aid: Vec<u8>,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Scp11Configuration, Error> {
    let point = match explicit.sd_public_key {
        Some(point) => Some(parse_hex(&point)?),
        None => environment_text("PKCS11RS_SCP11_SD_PUBLIC_KEY", environment)?
            .map(|point| parse_hex(&point))
            .transpose()?,
    };
    let ca = resolve_os(
        explicit.sd_ca_certificate,
        "PKCS11RS_SCP11_SD_CA_CERTIFICATE",
        environment,
    )?
    .map(PathBuf::from);
    let trust = match (point, ca) {
        (None, None) => Scp11TrustConfiguration::Yubico,
        (Some(point), None) => Scp11TrustConfiguration::PublicKey(point),
        (None, Some(ca)) => Scp11TrustConfiguration::CaCertificate(ca),
        (Some(_), Some(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    let sd_intermediates = resolve_os(
        explicit.sd_intermediate_bundle,
        "PKCS11RS_SCP11_SD_INTERMEDIATE_BUNDLE",
        environment,
    )?
    .map(|path| {
        let bytes = std::fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        crate::certificate_chain::decode_intermediate_bundle(&bytes)
    })
    .transpose()?
    .unwrap_or_default();
    if matches!(trust, Scp11TrustConfiguration::PublicKey(_)) && !sd_intermediates.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let key_version = explicit
        .key_version
        .or(environment_byte("PKCS11RS_SCP11_KEY_VERSION", environment)?)
        .unwrap_or(1);
    if key_version & 0x80 != 0 {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let oce_intermediates = resolve_os(
        explicit.oce_intermediate_bundle,
        "PKCS11RS_SCP11_OCE_INTERMEDIATE_BUNDLE",
        environment,
    )?
    .map(|path| {
        let bytes = std::fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        crate::certificate_chain::decode_bundle(&bytes)
    })
    .transpose()?
    .unwrap_or_default();
    let oce_key_version = explicit
        .oce_key_version
        .or(environment_byte(
            "PKCS11RS_SCP11_OCE_KEY_VERSION",
            environment,
        )?)
        .unwrap_or(0);
    let oce_key_id = explicit
        .oce_key_id
        .or(environment_byte("PKCS11RS_SCP11_OCE_KEY_ID", environment)?)
        .unwrap_or(0);
    if oce_key_version & 0x80 != 0 || oce_key_id & 0x80 != 0 {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let private_key = resolve_os(
        explicit.oce_private_key,
        "PKCS11RS_SCP11_OCE_PRIVATE_KEY",
        environment,
    )?;
    let certificate_bundle = resolve_os(
        explicit.oce_certificate_bundle,
        "PKCS11RS_SCP11_OCE_CERTIFICATE_BUNDLE",
        environment,
    )?;
    let oce = match (private_key, certificate_bundle) {
        (None, None) => None,
        (Some(private_key), Some(certificate_bundle)) => {
            let key_version = oce_key_version;
            let key_id = oce_key_id;
            Some(Scp11OceConfiguration {
                private_key: PathBuf::from(private_key),
                certificate_bundle: PathBuf::from(certificate_bundle),
                key_version,
                key_id,
            })
        }
        _ => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    Ok(Scp11Configuration {
        sd_intermediates,
        oce_intermediates,
        oce_key_version,
        oce_key_id,
        trust,
        key_version,
        oce,
        issuer_sd_aid,
    })
}

fn resolve_aid(
    explicit: Option<String>,
    name: &str,
    default: &[u8],
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Vec<u8>, Error> {
    let aid = match explicit {
        Some(aid) => parse_hex(&aid)?,
        None => environment_text(name, environment)?
            .map(|aid| parse_hex(&aid))
            .transpose()?
            .unwrap_or_else(|| default.to_vec()),
    };
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(aid)
}

fn parse_applications(values: Vec<String>) -> Result<Vec<CcidApplication>, Error> {
    if values.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mut applications = Vec::new();
    for value in values {
        let application = crate::parse_ccid_application(&value)?;
        if !applications.contains(&application) {
            applications.push(application);
        }
    }
    Ok(applications)
}

fn validate_urls(urls: Vec<String>) -> Result<Vec<String>, Error> {
    if urls.iter().any(|url| url.trim().is_empty()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(urls
        .into_iter()
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .collect())
}

fn split_list(value: &str, unique: bool) -> Result<Vec<String>, Error> {
    let mut values = Vec::new();
    for value in value.split(',') {
        let value = value.trim();
        if value.is_empty() || (unique && values.iter().any(|item| item == value)) {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        values.push(value.to_owned());
    }
    Ok(values)
}

fn resolve_secret_hex(
    explicit: Option<String>,
    name: &str,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    match explicit {
        Some(value) => parse_hex(&Zeroizing::new(value))
            .map(Zeroizing::new)
            .map(Some),
        None => environment_text(name, environment)?
            .map(|value| parse_hex(&Zeroizing::new(value)).map(Zeroizing::new))
            .transpose(),
    }
}

fn environment_byte(
    name: &str,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Option<u8>, Error> {
    environment_text(name, environment)?
        .as_deref()
        .map(parse_byte)
        .transpose()
}

fn parse_byte(value: &str) -> Result<u8, Error> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u8::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse())
        .map_err(|_| CKR_ARGUMENTS_BAD.into())
}

fn environment_switch(
    name: &str,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Option<bool>, Error> {
    match environment_text(name, environment)?.as_deref() {
        None => Ok(None),
        Some("0") => Ok(Some(false)),
        Some("1") => Ok(Some(true)),
        Some(_) => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn resolve_os(
    explicit: Option<String>,
    name: &str,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Option<OsString>, Error> {
    match explicit {
        Some(value) => Ok(Some(OsString::from(value))),
        None => environment(name),
    }
}

fn environment_text(
    name: &str,
    environment: &mut impl FnMut(&str) -> Result<Option<OsString>, Error>,
) -> Result<Option<String>, Error> {
    environment(name)?
        .map(|value| value.into_string().map_err(|_| CKR_ARGUMENTS_BAD.into()))
        .transpose()
}

fn encode_path_component(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn configured_ccid_client_uri_validates_protocol_and_json_precedence() {
        const ENV: &str = "PKCS11RS_CCID_CLIENT_URI";
        const URI: &str = "pkcs11:object=client;type=private";
        assert!(
            resolve(None, &[])
                .unwrap()
                .secure_channels
                .client_uri
                .is_none()
        );
        assert_eq!(
            resolve(None, &[(ENV, URI)])
                .unwrap()
                .secure_channels
                .client_uri
                .as_deref(),
            Some(URI.as_bytes())
        );
        let explicit = serde_json::from_value(
            serde_json::json!({"version":1,"ccid":{"secure_channel":"scp11c", "client_uri":URI}}),
        )
        .unwrap();
        assert_eq!(
            resolve(Some(explicit), &[(ENV, "invalid")])
                .unwrap()
                .secure_channels
                .client_uri
                .as_deref(),
            Some(URI.as_bytes())
        );
        for invalid in [
            "",
            "invalid",
            "pkcs11:?pin-value=secret",
            "pkcs11:?pkcs11rs-direct=secret&pkcs11rs-authkey=0001",
            "pkcs11:object=client;type=private?pkcs11rs-scp=scp11c",
        ] {
            assert!(resolve(None, &[(ENV, invalid)]).is_err());
        }
        assert!(
            resolve(
                None,
                &[(ENV, URI), ("PKCS11RS_CCID_SECURE_CHANNEL", "scp11b")]
            )
            .is_err()
        );
        assert!(
            resolve(
                None,
                &[(ENV, URI), ("PKCS11RS_CCID_SECURE_CHANNEL", "scp03")]
            )
            .is_err()
        );
    }

    #[test]
    fn card_intermediate_bundle_respects_precedence_and_trust_boundaries() {
        let path = std::env::temp_dir().join(format!(
            "pkcs11rs-card-intermediates-{}.cbor",
            std::process::id()
        ));
        let issuer = include_bytes!("fixtures/yubikey-scp11b-issuer.der").to_vec();
        std::fs::write(
            &path,
            crate::certificate_chain::encode_bundle(std::slice::from_ref(&issuer)).unwrap(),
        )
        .unwrap();
        let path_text = path.to_str().unwrap();
        let env = "PKCS11RS_SCP11_SD_INTERMEDIATE_BUNDLE";
        let from_env = resolve(None, &[(env, path_text)]).unwrap();
        assert_eq!(
            from_env.secure_channels.scp11.sd_intermediates,
            vec![issuer.clone()]
        );
        assert!(from_env.secure_channels.scp11.oce_intermediates.is_empty());
        let explicit = serde_json::from_value(
            serde_json::json!({"version":1, "scp11":{"sd_intermediate_bundle":path_text}}),
        )
        .unwrap();
        assert_eq!(
            resolve(Some(explicit), &[(env, "/missing/intermediates.cbor")])
                .unwrap()
                .secure_channels
                .scp11
                .sd_intermediates,
            vec![issuer]
        );
        assert!(resolve(None, &[(env, "/missing/intermediates.cbor")]).is_err());
        assert!(
            resolve(
                None,
                &[(env, path_text), ("PKCS11RS_SCP11_SD_PUBLIC_KEY", "04")]
            )
            .is_err()
        );
        let root = include_bytes!("../certificates/yubikey/yubico-attestation-root-1.der").to_vec();
        std::fs::write(
            &path,
            crate::certificate_chain::encode_bundle(&[root]).unwrap(),
        )
        .unwrap();
        assert!(resolve(None, &[(env, path_text)]).is_err());
        std::fs::write(&path, b"invalid bundle").unwrap();
        assert!(resolve(None, &[(env, path_text)]).is_err());
        std::fs::remove_file(path).unwrap();
    }

    fn json(value: &str) -> JsonConfiguration {
        serde_json::from_str(value).unwrap()
    }

    fn resolve(
        explicit: Option<JsonConfiguration>,
        environment: &[(&str, &str)],
    ) -> Result<ModuleConfiguration, Error> {
        let environment = environment
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect::<HashMap<_, _>>();
        ModuleConfiguration::resolve_with(explicit, |name| Ok(environment.get(name).cloned()))
    }

    #[test]
    fn platform_slot_is_opt_in_and_json_overrides_environment() {
        const ENV: &str = "PKCS11RS_PLATFORM_ENABLED";
        assert!(!resolve(None, &[]).unwrap().platform_enabled);
        assert!(resolve(None, &[(ENV, "1")]).unwrap().platform_enabled);
        for enabled in [false, true] {
            let explicit = serde_json::from_value(serde_json::json!({
                "version": 1, "platform": { "enabled": enabled }
            }))
            .unwrap();
            assert_eq!(
                resolve(Some(explicit), &[(ENV, if enabled { "0" } else { "1" })])
                    .unwrap()
                    .platform_enabled,
                enabled
            );
        }
        assert!(
            !ModuleConfiguration::private_software()
                .unwrap()
                .platform_enabled
        );
        assert!(resolve(None, &[(ENV, "invalid")]).is_err());
    }

    #[test]
    fn discovery_refresh_interval_defaults_and_overrides() {
        const ENV: &str = "PKCS11RS_DISCOVERY_REFRESH_INTERVAL_MS";
        assert_eq!(
            resolve(None, &[]).unwrap().discovery_refresh_interval,
            Duration::from_millis(500)
        );
        for interval in [0, 1200, u64::MAX] {
            let value = interval.to_string();
            assert_eq!(
                resolve(None, &[(ENV, &value)])
                    .unwrap()
                    .discovery_refresh_interval,
                Duration::from_millis(interval)
            );
            let explicit = serde_json::from_value(serde_json::json!({
                "version": 1, "discovery": {"refresh_interval_ms": interval}
            }))
            .unwrap();
            assert_eq!(
                resolve(Some(explicit), &[(ENV, "invalid")])
                    .unwrap()
                    .discovery_refresh_interval,
                Duration::from_millis(interval)
            );
        }
        for value in ["", "-1", "0.5", "invalid", "18446744073709551616"] {
            assert!(
                matches!(resolve(None, &[(ENV, value)]), Err(Error::Generic(rv)) if rv == CKR_ARGUMENTS_BAD as crate::CK_RV)
            );
        }
        for value in ["-1", "0.5", "\"500\"", "18446744073709551616"] {
            assert!(
                serde_json::from_str::<JsonConfiguration>(&format!(
                    r#"{{"version":1,"discovery":{{"refresh_interval_ms":{value}}}}}"#
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn slot_serial_allowlist_defaults_overrides_and_validation() {
        const ENV: &str = "PKCS11RS_SLOTS_SERIALS";
        assert!(resolve(None, &[]).unwrap().slot_serials.is_none());
        let expected = HashSet::from(["00123".to_owned(), "TEST0001".to_owned()]);
        assert_eq!(
            resolve(None, &[(ENV, "00123, TEST0001,00123")])
                .unwrap()
                .slot_serials,
            Some(expected.clone())
        );
        assert_eq!(
            resolve(
                Some(json(
                    r#"{"version":1,"slots":{"serials":["00123","TEST0001"]}}"#
                )),
                &[(ENV, ",")]
            )
            .unwrap()
            .slot_serials,
            Some(expected)
        );
        assert_eq!(
            resolve(None, &[(ENV, "")]).unwrap().slot_serials,
            Some(HashSet::new())
        );
        assert_eq!(
            resolve(
                Some(json(r#"{"version":1,"slots":{"serials":[]}}"#)),
                &[(ENV, "123")]
            )
            .unwrap()
            .slot_serials,
            Some(HashSet::new())
        );
        for value in [",", "123,", "123,,456"] {
            assert!(
                matches!(resolve(None, &[(ENV, value)]), Err(Error::Generic(rv)) if rv == CKR_ARGUMENTS_BAD as crate::CK_RV)
            );
        }
        for serial in ["", " ", "123,456"] {
            let explicit = serde_json::from_value(
                serde_json::json!({"version":1,"slots":{"serials":[serial]}}),
            )
            .unwrap();
            assert!(resolve(Some(explicit), &[]).is_err());
        }
    }

    #[test]
    fn null_configuration_uses_environment_and_defaults() {
        let configuration = resolve(
            None,
            &[
                ("PKCS11RS_LOG", "trace"),
                ("PKCS11RS_HARDWARE_DISCOVERY", "0"),
                ("PKCS11RS_YUBIHSM_URLS", "http://one/,http://two"),
            ],
        )
        .unwrap();
        assert_eq!(configuration.logging_level, Some(LogLevel::Trace));
        assert!(!configuration.hardware_discovery);
        assert!(!configuration.yubihsm_recreate_sessions);
        assert!(configuration.secure_channels.recreate_sessions);
        assert_eq!(configuration.yubihsm_urls, ["http://one", "http://two"]);
        assert!(!configuration.nfc_discovery);
        assert_eq!(configuration.secure_channels.scp03.security_level, 0x33);
    }

    #[test]
    fn ccid_recreation_can_be_disabled_and_json_overrides_environment() {
        assert!(
            !resolve(None, &[("PKCS11RS_CCID_RECREATE_SESSIONS", "0")])
                .unwrap()
                .secure_channels
                .recreate_sessions
        );
        assert!(
            resolve(
                Some(json(r#"{"version":1,"ccid":{"recreate_sessions":true}}"#)),
                &[("PKCS11RS_CCID_RECREATE_SESSIONS", "0")]
            )
            .unwrap()
            .secure_channels
            .recreate_sessions
        );
        assert!(
            !resolve(
                Some(json(r#"{"version":1,"ccid":{"recreate_sessions":false}}"#)),
                &[]
            )
            .unwrap()
            .secure_channels
            .recreate_sessions
        );
    }

    #[test]
    fn json_overrides_environment_and_missing_fields_fall_back() {
        let configuration = resolve(
            Some(json(
                r#"{
                    "version": 1,
                    "logging": {"level": "warn"},
                    "yubihsm": {
                        "urls": ["http://json/"],
                        "recreate_sessions": true
                    },
                    "ccid": {"applications": ["hsmauth"]},
                    "nfc": {"discovery": true}
                }"#,
            )),
            &[
                ("PKCS11RS_LOG", "trace"),
                ("PKCS11RS_HARDWARE_DISCOVERY", "0"),
                ("PKCS11RS_YUBIHSM_URLS", "http://environment"),
                ("PKCS11RS_YUBIHSM_RECREATE_SESSIONS", "0"),
            ],
        )
        .unwrap();
        assert_eq!(configuration.logging_level, Some(LogLevel::Warn));
        assert!(!configuration.hardware_discovery);
        assert!(configuration.yubihsm_recreate_sessions);
        assert!(configuration.nfc_discovery);
        assert_eq!(configuration.yubihsm_urls, ["http://json"]);
        assert_eq!(configuration.ccid_configurations.len(), 1);
        assert_eq!(
            configuration.ccid_configurations[0].application,
            CcidApplication::HsmAuth
        );
    }

    #[test]
    fn structured_software_slots_replace_dynamic_environment_shape() {
        let configuration = resolve(
            Some(json(
                r#"{
                    "version": 1,
                    "software": {"slots": [
                        {"name": "build signing", "discovery_pin": "a sufficiently long pin"}
                    ]}
                }"#,
            )),
            &[],
        )
        .unwrap();
        assert_eq!(configuration.software_slots, ["build signing"]);
        assert_eq!(
            configuration.software_discovery_pins["build signing"].as_slice(),
            b"a sufficiently long pin"
        );
    }

    #[cfg(feature = "embedded-virtual-yubikey")]
    #[test]
    fn embedded_readers_are_explicit_and_validate_identity_and_persistence() {
        let configuration = resolve(
            Some(json(
                r#"{
                    "version": 1,
                    "storage": {"tokens": "/tmp/pkcs11rs-embedded-test"},
                    "embedded": {"readers": [
                        {"id": "phone", "name": "Embedded CCID 0", "serial": 1,
                         "persistent": true, "applets": ["piv", "fido2"]},
                        {"id": "test-2", "name": "Embedded CCID 1", "serial": 2,
                         "applets": ["openpgp", "hsmauth", "issuer-sd"]}
                    ]}
                }"#,
            )),
            &[],
        )
        .unwrap();
        assert_eq!(configuration.embedded_readers.len(), 2);
        assert_eq!(
            configuration.embedded_readers[0].applets,
            [CcidApplication::Piv, CcidApplication::Fido2]
        );
        assert!(configuration.embedded_readers[0].persistent);

        for encoded in [
            r#"{"version":1,"embedded":{"readers":[{"id":"bad/id","name":"reader","serial":1,"applets":["piv"]}]}}"#,
            r#"{"version":1,"embedded":{"readers":[{"id":"one","name":"reader","serial":0,"applets":["piv"]}]}}"#,
            r#"{"version":1,"embedded":{"readers":[{"id":"one","name":"reader","serial":1,"persistent":true,"applets":["piv"]}]}}"#,
            r#"{"version":1,"embedded":{"readers":[{"id":"one","name":"reader","serial":1,"applets":[]}]}}"#,
        ] {
            assert!(resolve(Some(json(encoded)), &[]).is_err());
        }
    }

    #[cfg(not(feature = "embedded-virtual-yubikey"))]
    #[test]
    fn embedded_reader_configuration_requires_compile_time_support() {
        assert!(
            resolve(
                Some(json(
                    r#"{"version":1,"embedded":{"readers":[{"id":"one","name":"reader","serial":1,"applets":["piv"]}]}}"#,
                )),
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_json_fields_and_invalid_combinations_fail() {
        assert!(
            serde_json::from_str::<JsonConfiguration>(r#"{"version":1,"unknown":true}"#).is_err()
        );
        assert!(
            serde_json::from_str::<JsonConfiguration>(r#"{"version":1,"yubihsm":{"usb":false}}"#)
                .is_err()
        );
        assert!(
            resolve(
                Some(json(
                    r#"{
                    "version": 1,
                    "scp03": {"bmk": "00", "enc_key": "00", "mac_key": "00"}
                }"#,
                )),
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reserved_string_distinguishes_empty_opaque_and_json_values() {
        assert!(matches!(
            unsafe { JsonConfiguration::from_reserved(std::ptr::null_mut()) }.unwrap(),
            ReservedConfiguration::Empty
        ));
        let mut empty = [0u8];
        assert!(matches!(
            unsafe { JsonConfiguration::from_reserved(empty.as_mut_ptr().cast()) }.unwrap(),
            ReservedConfiguration::Empty
        ));
        let mut opaque = b"provider-specific init args\0".to_vec();
        assert!(matches!(
            unsafe { JsonConfiguration::from_reserved(opaque.as_mut_ptr().cast()) }.unwrap(),
            ReservedConfiguration::Opaque
        ));
        let mut invalid = b"{not json\0".to_vec();
        assert!(unsafe { JsonConfiguration::from_reserved(invalid.as_mut_ptr().cast()) }.is_err());
    }

    #[test]
    fn reserved_integer_sentinels_are_rejected_without_dereferencing() {
        for address in 1..=255 {
            assert!(matches!(
                unsafe { JsonConfiguration::from_reserved(std::ptr::without_provenance_mut(address)) },
                Err(Error::Generic(rv)) if rv == CKR_ARGUMENTS_BAD as crate::CK_RV
            ));
        }
    }

    #[test]
    fn unterminated_bounded_string_is_rejected() {
        let mut encoded = vec![b'x'; MAX_CONFIGURATION_STRING_BYTES];
        assert!(unsafe { JsonConfiguration::from_reserved(encoded.as_mut_ptr().cast()) }.is_err());
    }
}
