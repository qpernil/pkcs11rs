use crate::*;
use std::{collections::BTreeMap, fmt::Write};

pub(crate) const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

const INS_READ_DEVICE_INFO: u8 = 0x1d;
const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_AUTO_EJECT_TIMEOUT: u8 = 0x06;
const TAG_CHALLENGE_RESPONSE_TIMEOUT: u8 = 0x07;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIGURATION_LOCK: u8 = 0x0a;
const TAG_NFC_SUPPORTED: u8 = 0x0d;
const TAG_NFC_ENABLED: u8 = 0x0e;
const TAG_MORE_DATA: u8 = 0x10;
const TAG_PART_NUMBER: u8 = 0x13;
const TAG_FIPS_CAPABLE: u8 = 0x14;
const TAG_FIPS_APPROVED: u8 = 0x15;
const TAG_PIN_COMPLEXITY: u8 = 0x16;
const TAG_NFC_RESTRICTED: u8 = 0x17;
const TAG_RESET_BLOCKED: u8 = 0x18;
const TAG_VERSION_QUALIFIER: u8 = 0x19;
const TAG_FPS_VERSION: u8 = 0x20;
const TAG_STM_VERSION: u8 = 0x21;

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VersionQualifier {
    pub(crate) version: (u8, u8, u8),
    pub(crate) release_type: u8,
    pub(crate) iteration: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceInfo {
    pub(crate) serial: Option<String>,
    pub(crate) version: Option<(u8, u8, u8)>,
    pub(crate) version_qualifier: Option<VersionQualifier>,
    pub(crate) form_factor: Option<u8>,
    pub(crate) usb_supported: Option<u64>,
    pub(crate) usb_enabled: Option<u64>,
    pub(crate) nfc_supported: Option<u64>,
    pub(crate) nfc_enabled: Option<u64>,
    pub(crate) configuration_locked: bool,
    pub(crate) auto_eject_timeout: Option<u64>,
    pub(crate) challenge_response_timeout: Option<u64>,
    pub(crate) device_flags: Option<u64>,
    pub(crate) nfc_restricted: bool,
    pub(crate) part_number: Option<String>,
    pub(crate) fips_capable: Option<u64>,
    pub(crate) fips_approved: Option<u64>,
    pub(crate) pin_complexity: bool,
    pub(crate) reset_blocked: Option<u64>,
    pub(crate) fps_version: Option<(u8, u8, u8)>,
    pub(crate) stm_version: Option<(u8, u8, u8)>,
    pub(crate) raw_tlvs: Vec<(u8, Vec<u8>)>,
}

pub(crate) struct Client;

impl Client {
    pub(crate) fn discover(&self, connector: &dyn Connector) -> Result<DeviceInfo, Error> {
        log!(
            2,
            "YubiKey Management device-information discovery started on {}",
            connector.name()
        );
        let select = CommandApdu {
            cla: 0,
            ins: 0xa4,
            p1: 0x04,
            p2: 0,
            data: MANAGEMENT_AID.to_vec(),
            le: Some(256),
            extended: false,
        };
        let mut selected = connector.send_apdu(&select)?.require_success(&select)?.data;
        if selected.ends_with(&[0x90, 0x00]) {
            selected.truncate(selected.len() - 2);
        }
        let select_version = parse_select_version(&selected);

        let mut raw_tlvs = Vec::new();
        let mut page = 0u8;
        loop {
            let command = CommandApdu {
                cla: 0,
                ins: INS_READ_DEVICE_INFO,
                p1: page,
                p2: 0,
                data: Vec::new(),
                le: Some(256),
                extended: false,
            };
            let response = connector
                .send_apdu(&command)?
                .require_success(&command)?
                .data;
            let body = response.get(1..).ok_or(CKR_DATA_INVALID)?;
            if usize::from(response[0]) != body.len() {
                return Err(CKR_DATA_INVALID.into());
            }
            let page_tlvs = parse_tlvs(body)?;
            let more = page_tlvs
                .iter()
                .rev()
                .find(|(tag, _)| *tag == TAG_MORE_DATA)
                .map(|(_, value)| parse_integer(value))
                .transpose()?
                .unwrap_or(0);
            raw_tlvs.extend(page_tlvs);
            if more == 0 {
                break;
            }
            page = page.checked_add(1).ok_or(CKR_DATA_LEN_RANGE)?;
        }

        let info = DeviceInfo::parse(select_version, raw_tlvs)?;
        log!(
            2,
            "YubiKey Management device information on {}:\n{}",
            connector.name(),
            info.diagnostic()
        );
        Ok(info)
    }
}

impl DeviceInfo {
    fn parse(
        select_version: Option<(u8, u8, u8)>,
        raw_tlvs: Vec<(u8, Vec<u8>)>,
    ) -> Result<Self, Error> {
        let fields = raw_tlvs
            .iter()
            .map(|(tag, value)| (*tag, value.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let integer = |tag| {
            fields
                .get(&tag)
                .map(|value| parse_integer(value))
                .transpose()
        };
        let version = |tag| {
            fields
                .get(&tag)
                .map(|value| parse_version(value))
                .transpose()
        };
        let form_factor = integer(TAG_FORM_FACTOR)?
            .map(u8::try_from)
            .transpose()
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
        let serial = integer(TAG_SERIAL)?
            .filter(|serial| *serial != 0)
            .map(|serial| serial.to_string());
        let version_qualifier = fields
            .get(&TAG_VERSION_QUALIFIER)
            .map(|value| parse_version_qualifier(value))
            .transpose()?;
        let mut firmware_version = version(TAG_VERSION)?.or(select_version);
        if version_qualifier
            .as_ref()
            .is_some_and(|qualifier| qualifier.release_type != 2)
        {
            firmware_version = version_qualifier
                .as_ref()
                .map(|qualifier| qualifier.version);
        }

        Ok(Self {
            serial,
            version: firmware_version,
            version_qualifier,
            form_factor,
            usb_supported: integer(TAG_USB_SUPPORTED)?,
            usb_enabled: integer(TAG_USB_ENABLED)?,
            nfc_supported: integer(TAG_NFC_SUPPORTED)?,
            nfc_enabled: integer(TAG_NFC_ENABLED)?,
            configuration_locked: fields.get(&TAG_CONFIGURATION_LOCK) == Some(&&[1][..]),
            auto_eject_timeout: integer(TAG_AUTO_EJECT_TIMEOUT)?,
            challenge_response_timeout: integer(TAG_CHALLENGE_RESPONSE_TIMEOUT)?,
            device_flags: integer(TAG_DEVICE_FLAGS)?,
            nfc_restricted: fields.get(&TAG_NFC_RESTRICTED) == Some(&&[1][..]),
            part_number: fields
                .get(&TAG_PART_NUMBER)
                .and_then(|value| std::str::from_utf8(value).ok())
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            fips_capable: integer(TAG_FIPS_CAPABLE)?,
            fips_approved: integer(TAG_FIPS_APPROVED)?,
            pin_complexity: fields.get(&TAG_PIN_COMPLEXITY) == Some(&&[1][..]),
            reset_blocked: integer(TAG_RESET_BLOCKED)?,
            fps_version: version(TAG_FPS_VERSION)?.filter(|value| *value != (0, 0, 0)),
            stm_version: version(TAG_STM_VERSION)?.filter(|value| *value != (0, 0, 0)),
            raw_tlvs,
        })
    }

    fn diagnostic(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(
            output,
            "  serial: {}",
            self.serial.as_deref().unwrap_or("not reported")
        );
        let _ = writeln!(output, "  firmware: {}", display_version(self.version));
        if let Some(qualifier) = &self.version_qualifier {
            let _ = writeln!(
                output,
                "  release: {}",
                release_name(qualifier.release_type)
            );
        }
        let _ = writeln!(
            output,
            "  part number: {}",
            self.part_number.as_deref().unwrap_or("not reported")
        );
        let _ = writeln!(
            output,
            "  form factor: {}",
            display_form_factor(self.form_factor)
        );
        let _ = writeln!(
            output,
            "  USB supported: {}",
            display_capabilities(self.usb_supported)
        );
        let _ = writeln!(
            output,
            "  USB enabled: {}",
            display_capabilities(self.usb_enabled)
        );
        let _ = writeln!(
            output,
            "  NFC supported: {}",
            display_capabilities(self.nfc_supported)
        );
        let _ = writeln!(
            output,
            "  NFC enabled: {}",
            display_capabilities(self.nfc_enabled)
        );
        let _ = writeln!(
            output,
            "  configuration locked: {}",
            self.configuration_locked
        );
        let _ = writeln!(
            output,
            "  auto-eject timeout: {}",
            display_integer(self.auto_eject_timeout)
        );
        let _ = writeln!(
            output,
            "  challenge-response timeout: {}",
            display_integer(self.challenge_response_timeout)
        );
        let _ = writeln!(
            output,
            "  device flags: {}",
            display_device_flags(self.device_flags)
        );
        let _ = writeln!(output, "  NFC restricted: {}", self.nfc_restricted);
        let _ = writeln!(
            output,
            "  FIPS capable: {}",
            display_fips_capabilities(self.fips_capable)
        );
        let _ = writeln!(
            output,
            "  FIPS approved: {}",
            display_fips_capabilities(self.fips_approved)
        );
        let _ = writeln!(output, "  PIN complexity enabled: {}", self.pin_complexity);
        let _ = writeln!(
            output,
            "  reset blocked: {}",
            display_capabilities(self.reset_blocked)
        );
        let _ = writeln!(
            output,
            "  fingerprint sensor: {}",
            display_version(self.fps_version)
        );
        let _ = writeln!(output, "  STM: {}", display_version(self.stm_version));
        for (tag, value) in &self.raw_tlvs {
            if !typed_tag(*tag) {
                match raw_tag_name(*tag) {
                    Some(name) => {
                        let _ = writeln!(output, "  {name} (TLV 0x{tag:02x}): {}", hex(value));
                    }
                    None => {
                        let _ = writeln!(output, "  unknown TLV 0x{tag:02x}: {}", hex(value));
                    }
                }
            }
        }
        output.trim_end().to_owned()
    }
}

fn parse_select_version(encoded: &[u8]) -> Option<(u8, u8, u8)> {
    let mut parts = std::str::from_utf8(encoded).ok()?.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn parse_version(encoded: &[u8]) -> Result<(u8, u8, u8), Error> {
    match encoded {
        [major, minor, patch] => Ok((*major, *minor, *patch)),
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

fn parse_integer(encoded: &[u8]) -> Result<u64, Error> {
    if encoded.len() > std::mem::size_of::<u64>() {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(encoded
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
}

fn parse_version_qualifier(encoded: &[u8]) -> Result<VersionQualifier, Error> {
    let fields = parse_tlvs(encoded)?.into_iter().collect::<BTreeMap<_, _>>();
    Ok(VersionQualifier {
        version: parse_version(fields.get(&1).ok_or(CKR_DATA_INVALID)?)?,
        release_type: u8::try_from(parse_integer(fields.get(&2).ok_or(CKR_DATA_INVALID)?)?)
            .map_err(|_| Error::from(CKR_DATA_INVALID))?,
        iteration: parse_integer(fields.get(&3).ok_or(CKR_DATA_INVALID)?)?,
    })
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut tlvs = Vec::new();
    while !encoded.is_empty() {
        if encoded.len() < 2 {
            return Err(CKR_DATA_INVALID.into());
        }
        let length = usize::from(encoded[1]);
        if encoded.len() < 2 + length {
            return Err(CKR_DATA_INVALID.into());
        }
        tlvs.push((encoded[0], encoded[2..2 + length].to_vec()));
        encoded = &encoded[2 + length..];
    }
    Ok(tlvs)
}

fn display_version(version: Option<(u8, u8, u8)>) -> String {
    version.map_or_else(
        || "not reported".to_owned(),
        |(major, minor, patch)| format!("{major}.{minor}.{patch}"),
    )
}

fn display_integer(value: Option<u64>) -> String {
    value.map_or_else(|| "not reported".to_owned(), |value| value.to_string())
}

fn display_capabilities(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "not reported".to_owned();
    };
    let names = [
        (0x01, "OTP"),
        (0x02, "U2F"),
        (0x04, "CCID"),
        (0x08, "OpenPGP"),
        (0x10, "PIV"),
        (0x20, "OATH"),
        (0x100, "YubiHSM Auth"),
        (0x200, "FIDO2"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (value & bit != 0).then_some(name))
    .collect::<Vec<_>>();
    format!("{} (0x{value:x})", names.join(", "))
}

fn display_fips_capabilities(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "not reported".to_owned();
    };
    let names = ["FIDO2", "PIV", "OpenPGP", "OATH", "YubiHSM Auth"]
        .into_iter()
        .enumerate()
        .filter_map(|(bit, name)| (value & (1 << bit) != 0).then_some(name))
        .collect::<Vec<_>>();
    format!("{} (0x{value:x})", names.join(", "))
}

fn display_device_flags(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "not reported".to_owned();
    };
    let names = [(0x40, "remote wakeup"), (0x80, "eject")]
        .into_iter()
        .filter_map(|(bit, name)| (value & bit != 0).then_some(name))
        .collect::<Vec<_>>();
    format!("{} (0x{value:x})", names.join(", "))
}

fn display_form_factor(value: Option<u8>) -> String {
    let Some(value) = value else {
        return "not reported".to_owned();
    };
    let name = match value & 0x3f {
        0 => "undefined",
        1 => "USB-A keychain",
        2 => "USB-A nano",
        3 => "USB-C keychain",
        4 => "USB-C nano",
        5 => "USB-C/Lightning keychain",
        6 => "USB-A Bio",
        7 => "USB-C Bio",
        _ => "unknown",
    };
    let mut qualifiers = Vec::new();
    if value & 0x40 != 0 {
        qualifiers.push("Security Key");
    }
    if value & 0x80 != 0 {
        qualifiers.push("FIPS");
    }
    if qualifiers.is_empty() {
        format!("{name} (0x{value:02x})")
    } else {
        format!("{name}, {} (0x{value:02x})", qualifiers.join(", "))
    }
}

fn release_name(value: u8) -> &'static str {
    match value {
        0 | 1 => "pre-release",
        2 => "final",
        _ => "unknown",
    }
}

fn typed_tag(tag: u8) -> bool {
    matches!(
        tag,
        TAG_USB_SUPPORTED
            | TAG_SERIAL
            | TAG_USB_ENABLED
            | TAG_FORM_FACTOR
            | TAG_VERSION
            | TAG_AUTO_EJECT_TIMEOUT
            | TAG_CHALLENGE_RESPONSE_TIMEOUT
            | TAG_DEVICE_FLAGS
            | TAG_CONFIGURATION_LOCK
            | TAG_NFC_SUPPORTED
            | TAG_NFC_ENABLED
            | TAG_PART_NUMBER
            | TAG_FIPS_CAPABLE
            | TAG_FIPS_APPROVED
            | TAG_PIN_COMPLEXITY
            | TAG_NFC_RESTRICTED
            | TAG_RESET_BLOCKED
            | TAG_VERSION_QUALIFIER
            | TAG_FPS_VERSION
            | TAG_STM_VERSION
    )
}

fn raw_tag_name(tag: u8) -> Option<&'static str> {
    match tag {
        0x09 => Some("application versions"),
        0x0b => Some("configuration unlock"),
        0x0c => Some("reboot"),
        0x0f => Some("iAP detection"),
        TAG_MORE_DATA => Some("more data"),
        0x11 => Some("free-form data"),
        0x12 => Some("HID initialization delay"),
        _ => None,
    }
}

fn hex(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Debug)]
    struct ManagementConnector {
        responses: RefCell<VecDeque<Vec<u8>>>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl Connector for ManagementConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
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
            true
        }
        fn buffer_size(&self) -> usize {
            1024
        }
        fn transmit<'a>(
            &self,
            send_buffer: &[u8],
            receive_buffer: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(send_buffer.to_vec());
            let response = self
                .responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR)?;
            receive_buffer[..response.len()].copy_from_slice(&response);
            Ok(&receive_buffer[..response.len()])
        }
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag, value.len() as u8];
        encoded.extend_from_slice(value);
        encoded
    }

    fn response(tlvs: &[Vec<u8>]) -> Vec<u8> {
        let body = tlvs.concat();
        let mut response = vec![body.len() as u8];
        response.extend(body);
        response.extend_from_slice(&[0x90, 0x00]);
        response
    }

    #[test]
    fn management_device_information_is_fully_parsed_across_pages() {
        let qualifier = [tlv(1, &[1, 2, 3]), tlv(2, &[0]), tlv(3, &[7])].concat();
        let connector = ManagementConnector {
            responses: RefCell::new(VecDeque::from([
                [b"5.7.2".as_slice(), &[0x90, 0x00]].concat(),
                response(&[
                    tlv(TAG_USB_SUPPORTED, &[0x03, 0x3f]),
                    tlv(TAG_SERIAL, &[0x51, 0x45, 0xd3, 0x0c]),
                    tlv(TAG_MORE_DATA, &[1]),
                ]),
                response(&[
                    tlv(TAG_USB_ENABLED, &[0x03, 0x3d]),
                    tlv(TAG_FORM_FACTOR, &[0x43]),
                    tlv(TAG_VERSION, &[5, 7, 2]),
                    tlv(TAG_AUTO_EJECT_TIMEOUT, &[0, 15]),
                    tlv(TAG_CHALLENGE_RESPONSE_TIMEOUT, &[20]),
                    tlv(TAG_DEVICE_FLAGS, &[0x40]),
                    tlv(TAG_CONFIGURATION_LOCK, &[1]),
                    tlv(TAG_NFC_SUPPORTED, &[0x03, 0x3f]),
                    tlv(TAG_NFC_ENABLED, &[0x00, 0x30]),
                    tlv(TAG_PART_NUMBER, b"5060401"),
                    tlv(TAG_FIPS_CAPABLE, &[0, 0x10]),
                    tlv(TAG_FIPS_APPROVED, &[0, 0x10]),
                    tlv(TAG_PIN_COMPLEXITY, &[1]),
                    tlv(TAG_NFC_RESTRICTED, &[1]),
                    tlv(TAG_RESET_BLOCKED, &[0, 0x20]),
                    tlv(TAG_VERSION_QUALIFIER, &qualifier),
                    tlv(TAG_FPS_VERSION, &[1, 2, 3]),
                    tlv(TAG_STM_VERSION, &[4, 5, 6]),
                    tlv(0x7f, &[0xaa, 0xbb]),
                ]),
            ])),
            commands: RefCell::new(Vec::new()),
        };

        let info = Client.discover(&connector).unwrap();
        assert_eq!(info.serial.as_deref(), Some("1363530508"));
        assert_eq!(info.version, Some((1, 2, 3)));
        assert_eq!(info.form_factor, Some(0x43));
        assert_eq!(info.usb_supported, Some(0x033f));
        assert_eq!(info.usb_enabled, Some(0x033d));
        assert_eq!(info.nfc_supported, Some(0x033f));
        assert_eq!(info.nfc_enabled, Some(0x0030));
        assert!(info.configuration_locked);
        assert_eq!(info.auto_eject_timeout, Some(15));
        assert_eq!(info.challenge_response_timeout, Some(20));
        assert_eq!(info.device_flags, Some(0x40));
        assert!(info.nfc_restricted);
        assert_eq!(info.part_number.as_deref(), Some("5060401"));
        assert_eq!(info.fips_capable, Some(0x10));
        assert_eq!(info.fips_approved, Some(0x10));
        assert!(info.pin_complexity);
        assert_eq!(info.reset_blocked, Some(0x20));
        assert_eq!(info.fps_version, Some((1, 2, 3)));
        assert_eq!(info.stm_version, Some((4, 5, 6)));
        assert!(info.diagnostic().contains("release: pre-release"));
        assert!(!info.diagnostic().contains("iteration"));
        assert!(info.diagnostic().contains("unknown TLV 0x7f: aabb"));

        let commands = connector.commands.borrow();
        assert_eq!(
            commands[0],
            [vec![0, 0xa4, 0x04, 0, 8], MANAGEMENT_AID.to_vec(), vec![0]].concat()
        );
        assert_eq!(commands[1], vec![0, INS_READ_DEVICE_INFO, 0, 0, 0]);
        assert_eq!(commands[2], vec![0, INS_READ_DEVICE_INFO, 1, 0, 0]);
    }

    #[test]
    fn management_device_information_rejects_malformed_lengths() {
        let connector = ManagementConnector {
            responses: RefCell::new(VecDeque::from([
                [b"5.7.2".as_slice(), &[0x90, 0x00]].concat(),
                vec![3, TAG_SERIAL, 4, 0, 0x90, 0],
            ])),
            commands: RefCell::new(Vec::new()),
        };
        assert!(Client.discover(&connector).is_err());
    }
}
