use crate::{
    CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CommandApdu, Connector, Error,
    ResponseApdu, scp03,
};

const COMMAND_CHAINING_CLA: u8 = 0x10;
const GET_RESPONSE: u8 = yubikey_apdu::iso7816::GET_RESPONSE.ins;
const MAX_SHORT_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_SHORT_RESPONSE_LENGTH: u32 = 1 << 8;
const MAX_RESPONSE_LENGTH: usize = 1 << 16;
const MAX_RESPONSE_SEGMENTS: usize = MAX_RESPONSE_LENGTH / MAX_SHORT_RESPONSE_LENGTH as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApduCapabilities {
    pub(crate) command_chaining: bool,
    pub(crate) extended: bool,
    pub(crate) max_command_data: usize,
    pub(crate) max_response_data: u32,
    pub(crate) max_command_bytes: usize,
}

impl ApduCapabilities {
    pub(crate) const SHORT_ONLY: Self = Self {
        command_chaining: true,
        extended: false,
        max_command_data: 255,
        max_response_data: 256,
        max_command_bytes: 261,
    };

    pub(crate) const EXTENDED: Self = Self {
        command_chaining: true,
        extended: true,
        max_command_data: 65535,
        max_response_data: 65536,
        max_command_bytes: 65544,
    };

    fn fits(&self, command: &CommandApdu) -> Result<bool, Error> {
        // Use the shared codec so length-form accounting has one definition.
        let encoded = zeroize::Zeroizing::new(command.encode()?);
        let extended = command
            .as_shared()
            .uses_extended_length(command.data.len())
            .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
        Ok((!extended || self.extended)
            && command.data.len() <= self.max_command_data
            && command.le.is_none_or(|le| le <= self.max_response_data)
            && encoded.len() <= self.max_command_bytes)
    }
}

pub(crate) fn transmit<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
) -> Result<ResponseApdu, Error> {
    transmit_with_capabilities(connector, command, connector.apdu_capabilities())
}

pub(crate) fn transmit_short<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
) -> Result<ResponseApdu, Error> {
    let limits = connector.apdu_capabilities();
    transmit_with_capabilities(
        connector,
        command,
        ApduCapabilities {
            command_chaining: limits.command_chaining,
            max_command_data: limits.max_command_data.min(255),
            max_response_data: limits.max_response_data.min(256),
            max_command_bytes: limits.max_command_bytes.min(261),
            ..ApduCapabilities::SHORT_ONLY
        },
    )
}

fn transmit_with_capabilities<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
    capabilities: ApduCapabilities,
) -> Result<ResponseApdu, Error> {
    let response = transmit_command(connector, command, capabilities)?;
    collect_response_chain(connector, response)
}

/// Correct one wire APDU's Le without rebuilding its secure-messaging envelope
/// or resending preceding command fragments. ISO 7816-4 defines 6Cxx for both
/// T=0 and T=1; any procedure already handled by the reader is invisible here.
fn transmit_with_le_correction<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
) -> Result<ResponseApdu, Error> {
    if !connector.apdu_capabilities().fits(command)? {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let response = scp03::transmit(connector, command)?;
    if response.status & 0xff00 != 0x6c00
        || !response.data.is_empty()
        || command.le.is_none()
        || command.cla & COMMAND_CHAINING_CLA != 0
    {
        return Ok(response);
    }

    let mut corrected = command.clone();
    // Keep the original Lc encoding, which can be covered by a command MAC,
    // even when reducing an extended Le would otherwise select short encoding.
    corrected.extended = command
        .as_shared()
        .uses_extended_length(command.data.len())
        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
    corrected.le = Some(match response.status as u8 {
        0 => MAX_SHORT_RESPONSE_LENGTH,
        length => u32::from(length),
    });
    if !connector.apdu_capabilities().fits(&corrected)? {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    scp03::transmit(connector, &corrected)
}

/// Send one logical command, including ISO fragmentation and wire Le correction.
fn transmit_command<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
    capabilities: ApduCapabilities,
) -> Result<ResponseApdu, Error> {
    let operation = crate::logging::Operation::trace(tracing::trace_span!(
        target: "pkcs11rs::transport",
        "iso7816.transmit",
        connector = %connector.name(),
        instruction = command.ins,
        request_bytes = command.data.len(),
        expected_response_bytes = command.le.unwrap_or_default()
    ));
    let _entered = operation.enter();
    let needs_extended = command.extended
        || command.data.len() > MAX_SHORT_DATA_LENGTH
        || command
            .le
            .is_some_and(|length| length > MAX_SHORT_RESPONSE_LENGTH);

    let mut encoded = command.clone();
    // Le is outside SCP protection. Reduce the requested wire response size
    // to the reader's limit, retaining the original length form for the MAC.
    encoded.extended = needs_extended;
    encoded.le = command.le.map(|le| le.min(capabilities.max_response_data));
    if (!needs_extended || capabilities.extended) && capabilities.fits(&encoded)? {
        return transmit_with_le_correction(connector, &encoded);
    }

    if needs_extended && command.data.len() <= MAX_SHORT_DATA_LENGTH {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    if !capabilities.command_chaining
        || command.data.is_empty()
        || command.cla & COMMAND_CHAINING_CLA != 0
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let chunk_length = capabilities
        .max_command_bytes
        .saturating_sub(5 + usize::from(command.le.is_some()))
        .min(MAX_SHORT_DATA_LENGTH)
        .min(capabilities.max_command_data);
    if chunk_length == 0 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut chunks = command.data.chunks(chunk_length).peekable();
    while let Some(data) = chunks.next() {
        let last = chunks.peek().is_none();
        let segment = CommandApdu {
            cla: if last {
                command.cla
            } else {
                command.cla | COMMAND_CHAINING_CLA
            },
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data: data.to_vec(),
            le: last
                .then_some(encoded.le.map(|le| le.min(MAX_SHORT_RESPONSE_LENGTH)))
                .flatten(),
            extended: false,
        };
        let response = transmit_with_le_correction(connector, &segment)?;
        if last {
            return Ok(response);
        }
        if response.status != 0x9000 || !response.data.is_empty() {
            return Err(CKR_DEVICE_ERROR.into());
        }
    }
    Err(CKR_DEVICE_ERROR.into())
}

/// Collect with the continuation instruction supplied by the owning protocol.
/// Under SCP, collect the envelope before MAC verification/decryption.
pub(crate) fn transmit_with_continuation<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
    instruction: u8,
) -> Result<ResponseApdu, Error> {
    let response = transmit_command(connector, command, connector.apdu_capabilities())?;
    collect_response_chain_with_instruction(connector, response, instruction)
}

pub(crate) fn collect_response_chain<C: Connector + ?Sized>(
    connector: &C,
    response: ResponseApdu,
) -> Result<ResponseApdu, Error> {
    collect_response_chain_with_instruction(connector, response, GET_RESPONSE)
}

fn collect_response_chain_with_instruction<C: Connector + ?Sized>(
    connector: &C,
    mut response: ResponseApdu,
    instruction: u8,
) -> Result<ResponseApdu, Error> {
    let mut data = Vec::new();
    let mut segments = 0usize;
    while response.status & 0xff00 == 0x6100 {
        segments += 1;
        if segments > MAX_RESPONSE_SEGMENTS || (segments > 1 && response.data.is_empty()) {
            return Err(CKR_DEVICE_ERROR.into());
        }
        append_response_data(&mut data, &response.data)?;

        let available = (response.status & 0xff) as u32;
        let get_response = CommandApdu {
            cla: 0,
            ins: instruction,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(if available == 0 {
                MAX_SHORT_RESPONSE_LENGTH
            } else {
                available
            }),
            extended: false,
        };
        response = transmit_with_le_correction(connector, &get_response)?;
    }
    append_response_data(&mut data, &response.data)?;
    Ok(ResponseApdu {
        data,
        status: response.status,
    })
}

fn append_response_data(output: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
    let length = output
        .len()
        .checked_add(data.len())
        .filter(|length| *length <= MAX_RESPONSE_LENGTH)
        .ok_or(CKR_DEVICE_ERROR)?;
    output.reserve(length - output.len());
    output.extend_from_slice(data);
    Ok(())
}

pub(crate) fn atr_apdu_capabilities(atr: &[u8]) -> Option<ApduCapabilities> {
    let historical = atr_historical_bytes(atr)?;
    let mut offset = 1usize;
    while offset < historical.len() {
        let descriptor = historical[offset];
        let tag = descriptor >> 4;
        let length = (descriptor & 0x0f) as usize;
        let end = offset.checked_add(1 + length)?;
        if end > historical.len() {
            return None;
        }
        if tag == 7 && length == 3 {
            let flags = historical[offset + 3];
            return Some(ApduCapabilities {
                command_chaining: flags & 0x80 != 0,
                extended: flags & 0x40 != 0,
                ..if flags & 0x40 != 0 {
                    ApduCapabilities::EXTENDED
                } else {
                    ApduCapabilities::SHORT_ONLY
                }
            });
        }
        offset = end;
    }
    None
}

fn atr_historical_bytes(atr: &[u8]) -> Option<&[u8]> {
    let t0 = *atr.get(1)?;
    let historical_length = (t0 & 0x0f) as usize;
    let mut interface_flags = t0 >> 4;
    let mut offset = 2usize;

    loop {
        for flag in [0x01, 0x02, 0x04] {
            if interface_flags & flag != 0 {
                offset = offset.checked_add(1)?;
            }
        }
        if interface_flags & 0x08 == 0 {
            break;
        }
        let td = *atr.get(offset)?;
        offset = offset.checked_add(1)?;
        interface_flags = td >> 4;
    }

    let end = offset.checked_add(historical_length)?;
    atr.get(offset..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        capabilities: ApduCapabilities,
        responses: RefCell<VecDeque<Vec<u8>>>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl ScriptedConnector {
        fn new(capabilities: ApduCapabilities, statuses: &[u16]) -> Self {
            Self {
                capabilities,
                responses: RefCell::new(
                    statuses
                        .iter()
                        .map(|status| status.to_be_bytes().to_vec())
                        .collect(),
                ),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiKey"
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
        fn apdu_capabilities(&self) -> ApduCapabilities {
            self.capabilities
        }
        fn transmit<'a>(
            &self,
            command: &[u8],
            receive: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(command.to_vec());
            let response = self.responses.borrow_mut().pop_front().unwrap();
            receive[..response.len()].copy_from_slice(&response);
            Ok(&receive[..response.len()])
        }
    }

    fn long_command() -> CommandApdu {
        CommandApdu {
            cla: 0,
            ins: 0xda,
            p1: 0x01,
            p2: 0x02,
            data: vec![0x5a; 300],
            le: None,
            extended: false,
        }
    }

    #[test]
    fn uses_extended_apdu_when_supported() {
        let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x9000]);
        transmit(&connector, &long_command()).unwrap();
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 1);
        assert_eq!(&commands[0][4..7], &[0, 1, 44]);
    }

    #[test]
    fn explicit_extended_encoding_is_preserved_or_rejected_before_io() {
        let command = CommandApdu {
            data: vec![0x5a; 8],
            le: Some(8),
            extended: true,
            ..long_command()
        };
        let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x6c10, 0x9000]);
        transmit(&connector, &command).unwrap();
        let commands = connector.commands.borrow();
        assert_eq!(commands[0], command.encode().unwrap());
        assert_eq!(&commands[1][4..7], &[0, 0, 8]);
        assert_eq!(&commands[1][commands[1].len() - 2..], &[0, 16]);

        let short = ScriptedConnector::new(ApduCapabilities::SHORT_ONLY, &[]);
        assert!(transmit(&short, &command).is_err());
        assert!(short.commands.borrow().is_empty());
    }

    #[test]
    fn uses_iso_command_chaining_without_extended_apdus() {
        let connector = ScriptedConnector::new(ApduCapabilities::SHORT_ONLY, &[0x9000, 0x9000]);
        transmit(&connector, &long_command()).unwrap();
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], COMMAND_CHAINING_CLA);
        assert_eq!(commands[0][4], 255);
        assert_eq!(commands[1][0], 0);
        assert_eq!(commands[1][4], 45);
    }

    #[test]
    fn explicit_short_mode_uses_chaining_on_extended_connectors() {
        let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x9000, 0x9000]);
        transmit_short(&connector, &long_command()).unwrap();
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], COMMAND_CHAINING_CLA);
        assert_eq!(commands[0][4], 255);
        assert_eq!(commands[1][0], 0);
        assert_eq!(commands[1][4], 45);
    }

    #[test]
    fn length_correction_changes_only_le_in_plain_and_protected_frames() {
        for cla in [0, 4, 0x0c, 0x44, 0x60, 0x80] {
            let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x6c10, 0x9000]);
            let command = CommandApdu {
                cla,
                ins: 0x84,
                p1: 0x81,
                p2: 2,
                data: vec![0x5a; 24],
                le: Some(8),
                extended: false,
            };
            assert_eq!(transmit(&connector, &command).unwrap().status, 0x9000);
            let commands = connector.commands.borrow();
            assert_eq!(commands.len(), 2);
            let mut corrected = commands[0].clone();
            *corrected.last_mut().unwrap() = 16;
            assert_eq!(commands[1], corrected);
        }
    }

    #[test]
    fn length_correction_preserves_extended_encoding_and_handles_6c00() {
        for (le, status, corrected_le) in
            [(1, 0x6c00, 256), (65536, 0x6c08, 8), (65536, 0x6c00, 256)]
        {
            let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[status, 0x9000]);
            let command = CommandApdu {
                le: Some(le),
                data: vec![0x5a; 24],
                ..long_command()
            };
            transmit(&connector, &command).unwrap();
            let commands = connector.commands.borrow();
            let width = if le > 256 { 2 } else { 1 };
            let prefix_len = commands[0].len() - width;
            assert_eq!(commands[0][..prefix_len], commands[1][..prefix_len]);
            let corrected = CommandApdu::decode(&commands[1]).unwrap();
            assert_eq!(corrected.le, Some(corrected_le));
            assert_eq!(corrected.extended, le > 256);
        }
    }

    #[test]
    fn length_correction_is_bounded_and_requires_a_bare_status_and_le() {
        for (le, cla, body) in [
            (Some(8), 0, vec![]),
            (None, 0, vec![]),
            (Some(8), 0, vec![1]),
            (Some(8), 0x10, vec![]),
        ] {
            let connector = ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x6c10, 0x6c20]);
            connector
                .responses
                .borrow_mut()
                .front_mut()
                .unwrap()
                .splice(0..0, body.clone());
            let command = CommandApdu {
                le,
                cla,
                data: vec![0x5a; 24],
                ..long_command()
            };
            let should_correct = le.is_some() && body.is_empty() && cla == 0;
            let response = transmit(&connector, &command).unwrap();
            assert_eq!(
                response.status,
                if should_correct { 0x6c20 } else { 0x6c10 }
            );
            assert_eq!(
                connector.commands.borrow().len(),
                if should_correct { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn length_correction_does_not_repeat_preceding_command_fragments() {
        let connector =
            ScriptedConnector::new(ApduCapabilities::SHORT_ONLY, &[0x9000, 0x6c10, 0x9000]);
        let command = CommandApdu {
            le: Some(8),
            ..long_command()
        };
        transmit(&connector, &command).unwrap();
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0][0], 0x10);
        let mut corrected = commands[1].clone();
        *corrected.last_mut().unwrap() = 16;
        assert_eq!(commands[2], corrected);
    }

    #[test]
    fn continuation_length_correction_does_not_repeat_the_application_command() {
        for instruction in [GET_RESPONSE, 0xa5] {
            let connector =
                ScriptedConnector::new(ApduCapabilities::EXTENDED, &[0x6101, 0x6c08, 0x9000]);
            *connector.responses.borrow_mut().back_mut().unwrap() = vec![1, 2, 0x90, 0];
            let command = CommandApdu {
                le: Some(8),
                data: vec![0x5a],
                ..long_command()
            };
            let response = transmit_with_continuation(&connector, &command, instruction).unwrap();
            assert_eq!(response.data, [1, 2]);
            let commands = connector.commands.borrow();
            assert_eq!(commands.len(), 3);
            assert_eq!(commands[0], command.encode().unwrap());
            assert_eq!(commands[1], [0, instruction, 0, 0, 1]);
            assert_eq!(commands[2], [0, instruction, 0, 0, 8]);
        }
    }

    #[test]
    fn reader_command_and_data_limits_trigger_iso_chaining() {
        for capabilities in [
            ApduCapabilities {
                max_command_bytes: 128,
                ..ApduCapabilities::SHORT_ONLY
            },
            ApduCapabilities {
                max_command_data: 257,
                ..ApduCapabilities::EXTENDED
            },
        ] {
            let count = if capabilities.extended { 2 } else { 3 };
            let connector = ScriptedConnector::new(capabilities, &vec![0x9000; count]);
            let command = CommandApdu {
                le: Some(8),
                ..long_command()
            };
            transmit(&connector, &command).unwrap();
            let commands = connector.commands.borrow();
            assert_eq!(commands.len(), count);
            let mut data = Vec::new();
            for raw in commands.iter() {
                assert!(raw.len() <= capabilities.max_command_bytes);
                let fragment = CommandApdu::decode(raw).unwrap();
                assert_eq!((fragment.p1, fragment.p2), (command.p1, command.p2));
                data.extend_from_slice(&fragment.data);
            }
            assert_eq!(data, command.data);
        }
    }

    #[test]
    fn reader_response_limit_reduces_le_without_changing_length_form() {
        let capabilities = ApduCapabilities {
            max_response_data: 512,
            ..ApduCapabilities::EXTENDED
        };
        let connector = ScriptedConnector::new(capabilities, &[0x6101, 0x9000]);
        let command = CommandApdu {
            data: vec![0x5a; 24],
            le: Some(65536),
            ..long_command()
        };
        transmit(&connector, &command).unwrap();
        let commands = connector.commands.borrow();
        let original = command.encode().unwrap();
        assert_eq!(
            commands[0][..original.len() - 2],
            original[..original.len() - 2]
        );
        let sent = CommandApdu::decode(&commands[0]).unwrap();
        assert_eq!(sent.le, Some(512));
        assert!(sent.extended);
        assert_eq!(commands[1], [0, GET_RESPONSE, 0, 0, 1]);
    }

    #[test]
    fn explicit_short_mode_retains_reader_limits_and_chaining_policy() {
        for command_chaining in [false, true] {
            let limits = ApduCapabilities {
                command_chaining,
                max_command_bytes: 128,
                ..ApduCapabilities::EXTENDED
            };
            let connector = ScriptedConnector::new(limits, &[0x9000; 3]);
            let command = CommandApdu {
                le: Some(8),
                ..long_command()
            };
            if command_chaining {
                transmit_short(&connector, &command).unwrap();
                assert_eq!(connector.commands.borrow().len(), 3);
                assert!(
                    connector
                        .commands
                        .borrow()
                        .iter()
                        .all(|raw| raw.len() <= 128)
                );
            } else {
                assert!(transmit_short(&connector, &command).is_err());
                assert!(connector.commands.borrow().is_empty());
            }
        }
    }

    #[test]
    fn parses_yubikey_atr_apdu_capabilities() {
        let atr = [
            0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0,
            0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
        ];
        assert_eq!(
            atr_apdu_capabilities(&atr),
            Some(ApduCapabilities::EXTENDED)
        );
    }
}
