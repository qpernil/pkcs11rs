use crate::{
    scp03, CommandApdu, Connector, Error, ResponseApdu, CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
};

const COMMAND_CHAINING_CLA: u8 = 0x10;
const GET_RESPONSE: u8 = 0xc0;
const MAX_SHORT_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_SHORT_RESPONSE_LENGTH: u32 = 1 << 8;
const MAX_RESPONSE_LENGTH: usize = 1 << 16;
const MAX_RESPONSE_SEGMENTS: usize = MAX_RESPONSE_LENGTH / MAX_SHORT_RESPONSE_LENGTH as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApduCapabilities {
    pub(crate) command_chaining: bool,
    pub(crate) extended: bool,
}

impl ApduCapabilities {
    pub(crate) const SHORT_ONLY: Self = Self {
        command_chaining: true,
        extended: false,
    };

    pub(crate) const EXTENDED: Self = Self {
        command_chaining: true,
        extended: true,
    };
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
    transmit_with_capabilities(connector, command, ApduCapabilities::SHORT_ONLY)
}

fn transmit_with_capabilities<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
    capabilities: ApduCapabilities,
) -> Result<ResponseApdu, Error> {
    let mut command = command.clone();
    let mut response = transmit_command(connector, &command, capabilities)?;
    if response.status & 0xff00 == 0x6c00 {
        command.le = Some(match response.status as u8 {
            0 => MAX_SHORT_RESPONSE_LENGTH,
            length => length as u32,
        });
        response = transmit_command(connector, &command, capabilities)?;
    }
    collect_response_chain(connector, response)
}

fn transmit_command<C: Connector + ?Sized>(
    connector: &C,
    command: &CommandApdu,
    capabilities: ApduCapabilities,
) -> Result<ResponseApdu, Error> {
    let needs_extended = command.data.len() > MAX_SHORT_DATA_LENGTH
        || command
            .le
            .is_some_and(|length| length > MAX_SHORT_RESPONSE_LENGTH);

    if !needs_extended || capabilities.extended {
        let mut encoded = command.clone();
        encoded.extended = needs_extended && capabilities.extended;
        return scp03::transmit(connector, &encoded);
    }

    if command
        .le
        .is_some_and(|length| length > MAX_SHORT_RESPONSE_LENGTH)
    {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    if !capabilities.command_chaining
        || command.data.is_empty()
        || command.cla & COMMAND_CHAINING_CLA != 0
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let mut chunks = command.data.chunks(MAX_SHORT_DATA_LENGTH).peekable();
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
            le: last.then_some(command.le).flatten(),
            extended: false,
        };
        let response = scp03::transmit(connector, &segment)?;
        if last {
            return Ok(response);
        }
        if response.status != 0x9000 || !response.data.is_empty() {
            return Err(CKR_DEVICE_ERROR.into());
        }
    }
    Err(CKR_DEVICE_ERROR.into())
}

pub(crate) fn collect_response_chain<C: Connector + ?Sized>(
    connector: &C,
    mut response: ResponseApdu,
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
            ins: GET_RESPONSE,
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
        response = scp03::transmit(connector, &get_response)?;
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
        fn serial(&self) -> &str {
            "1"
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
