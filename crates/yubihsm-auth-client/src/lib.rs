//! Transport-independent YubiHSM Auth session-key operations.
//!
//! This crate owns the APDU and TLV vocabulary shared by PKCS #11 and
//! qualification clients. Hardware discovery and transport policy remain in
//! their callers.

use std::{error::Error as StdError, fmt};
use zeroize::{Zeroize, Zeroizing};

pub const APPLICATION_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];

const TAG_LABEL: u8 = 0x71;
const TAG_CREDENTIAL_PASSWORD: u8 = 0x73;
const TAG_CONTEXT: u8 = 0x77;
const TAG_RESPONSE: u8 = 0x78;
const TAG_PUBLIC_KEY: u8 = 0x7c;

const INS_CALCULATE: u8 = 0x03;
const INS_GET_CHALLENGE: u8 = 0x04;
const STATUS_SUCCESS: u16 = 0x9000;
const MAX_LABEL_LENGTH: usize = 64;
const CREDENTIAL_PASSWORD_LENGTH: usize = 16;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const SESSION_KEY_LENGTH: usize = 16;
const SESSION_KEYS_LENGTH: usize = SESSION_KEY_LENGTH * 3;

#[derive(Clone, Eq, PartialEq)]
pub struct Command {
    pub cla: u8,
    pub instruction: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Command")
            .field("cla", &self.cla)
            .field("instruction", &self.instruction)
            .field("p1", &self.p1)
            .field("p2", &self.p2)
            .field("data_length", &self.data.len())
            .finish()
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Response {
    pub data: Vec<u8>,
    pub status: u16,
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("data_length", &self.data.len())
            .field("status", &format_args!("{:04x}", self.status))
            .finish()
    }
}

/// A transport for semantic short APDUs. Implementations perform ISO 7816
/// command chaining when `data` exceeds one short APDU.
pub trait Transport {
    type Error;

    fn exchange(&self, command: &Command) -> Result<Response, Self::Error>;
}

#[derive(Debug)]
pub enum Error<E> {
    Transport(E),
    InvalidLabel,
    InvalidPassword,
    InvalidPublicKey,
    DataTooLong,
    MalformedResponse,
    Status(u16),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
            Self::InvalidLabel => formatter.write_str("invalid YubiHSM Auth credential label"),
            Self::InvalidPassword => {
                formatter.write_str("YubiHSM Auth credential password exceeds 16 bytes")
            }
            Self::InvalidPublicKey => formatter.write_str("invalid P-256 public key"),
            Self::DataTooLong => formatter.write_str("YubiHSM Auth APDU data is too long"),
            Self::MalformedResponse => formatter.write_str("malformed YubiHSM Auth response"),
            Self::Status(status) => write!(formatter, "YubiHSM Auth status {status:04x}"),
        }
    }
}

impl<E: StdError + 'static> StdError for Error<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

pub struct SessionKeys {
    pub enc: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
    pub mac: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
    pub rmac: Zeroizing<[u8; SESSION_KEY_LENGTH]>,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionKeys")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Client;

impl Client {
    pub fn select<T: Transport>(&self, transport: &T) -> Result<(), Error<T::Error>> {
        let command = Command {
            cla: 0,
            instruction: 0xa4,
            p1: 0x04,
            p2: 0,
            data: APPLICATION_AID.to_vec(),
        };
        self.exchange(transport, &command).map(|_| ())
    }

    pub fn get_challenge<T: Transport>(
        &self,
        transport: &T,
        label: &str,
        credential_password: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        if let Some(password) = credential_password {
            let password = padded_password(password)?;
            data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_ref())?);
        }
        self.command(transport, INS_GET_CHALLENGE, 0, 0, data)
    }

    pub fn calculate_session_keys_symmetric<T: Transport>(
        &self,
        transport: &T,
        label: &str,
        context: &[u8],
        card_cryptogram: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error<T::Error>> {
        self.calculate_session_keys(
            transport,
            label,
            context,
            None,
            card_cryptogram,
            credential_password,
        )
    }

    pub fn calculate_session_keys_asymmetric<T: Transport>(
        &self,
        transport: &T,
        label: &str,
        context: &[u8],
        device_public_key: &[u8],
        receipt: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error<T::Error>> {
        if device_public_key.len() != P256_PUBLIC_KEY_LENGTH || device_public_key[0] != 0x04 {
            return Err(Error::InvalidPublicKey);
        }
        self.calculate_session_keys(
            transport,
            label,
            context,
            Some(device_public_key),
            receipt,
            credential_password,
        )
    }

    fn calculate_session_keys<T: Transport>(
        &self,
        transport: &T,
        label: &str,
        context: &[u8],
        public_key: Option<&[u8]>,
        response: &[u8],
        credential_password: &[u8],
    ) -> Result<SessionKeys, Error<T::Error>> {
        let mut data = encode_tlv(TAG_LABEL, validate_label(label)?)?;
        data.extend(encode_tlv(TAG_CONTEXT, context)?);
        if let Some(public_key) = public_key {
            data.extend(encode_tlv(TAG_PUBLIC_KEY, public_key)?);
        }
        data.extend(encode_tlv(TAG_RESPONSE, response)?);
        let password = padded_password(credential_password)?;
        data.extend(encode_tlv(TAG_CREDENTIAL_PASSWORD, password.as_ref())?);
        let response = Zeroizing::new(self.command(transport, INS_CALCULATE, 0, 0, data)?);
        if response.len() != SESSION_KEYS_LENGTH {
            return Err(Error::MalformedResponse);
        }
        Ok(SessionKeys {
            enc: Zeroizing::new(response[..16].try_into().unwrap()),
            mac: Zeroizing::new(response[16..32].try_into().unwrap()),
            rmac: Zeroizing::new(response[32..].try_into().unwrap()),
        })
    }

    fn command<T: Transport>(
        &self,
        transport: &T,
        instruction: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let mut data = Zeroizing::new(data);
        let command = Command {
            cla: 0,
            instruction,
            p1,
            p2,
            data: data.to_vec(),
        };
        data.zeroize();
        self.exchange(transport, &command)
    }

    fn exchange<T: Transport>(
        &self,
        transport: &T,
        command: &Command,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let response = transport.exchange(command).map_err(Error::Transport)?;
        if response.status != STATUS_SUCCESS {
            return Err(Error::Status(response.status));
        }
        Ok(response.data)
    }
}

fn validate_label<E>(label: &str) -> Result<&[u8], Error<E>> {
    if label.is_empty() || label.len() > MAX_LABEL_LENGTH || label.chars().any(char::is_control) {
        return Err(Error::InvalidLabel);
    }
    Ok(label.as_bytes())
}

fn padded_password<E>(password: &[u8]) -> Result<Zeroizing<[u8; 16]>, Error<E>> {
    if password.len() > CREDENTIAL_PASSWORD_LENGTH {
        return Err(Error::InvalidPassword);
    }
    let mut padded = Zeroizing::new([0; CREDENTIAL_PASSWORD_LENGTH]);
    padded[..password.len()].copy_from_slice(password);
    Ok(padded)
}

fn encode_tlv<E>(tag: u8, value: &[u8]) -> Result<Vec<u8>, Error<E>> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(tag);
    match value.len() {
        0..=0x7f => encoded.push(value.len() as u8),
        0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(Error::DataTooLong),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, io};

    struct ScriptedTransport {
        commands: RefCell<Vec<Command>>,
        responses: RefCell<Vec<Response>>,
    }

    impl Transport for ScriptedTransport {
        type Error = io::Error;

        fn exchange(&self, command: &Command) -> Result<Response, Self::Error> {
            self.commands.borrow_mut().push(command.clone());
            Ok(self.responses.borrow_mut().remove(0))
        }
    }

    #[test]
    fn asymmetric_session_commands_have_canonical_tlv_layout() {
        let transport = ScriptedTransport {
            commands: RefCell::new(Vec::new()),
            responses: RefCell::new(vec![
                Response {
                    data: vec![0x04; 65],
                    status: 0x9000,
                },
                Response {
                    data: vec![0x55; 48],
                    status: 0x9000,
                },
            ]),
        };
        let challenge = Client
            .get_challenge(&transport, "credential", Some(b"password"))
            .unwrap();
        assert_eq!(challenge, vec![0x04; 65]);
        let keys = Client
            .calculate_session_keys_asymmetric(
                &transport,
                "credential",
                &[0x11; 130],
                &[0x04; 65],
                &[0x22; 16],
                b"password",
            )
            .unwrap();
        assert_eq!(&keys.enc[..], &[0x55; 16]);
        let commands = transport.commands.borrow();
        assert_eq!(commands[0].instruction, INS_GET_CHALLENGE);
        assert_eq!(commands[0].data.len(), 30);
        assert_eq!(commands[1].instruction, INS_CALCULATE);
        assert_eq!(commands[1].data.len(), 248);
    }

    #[test]
    fn status_and_malformed_responses_are_preserved() {
        let transport = ScriptedTransport {
            commands: RefCell::new(Vec::new()),
            responses: RefCell::new(vec![Response {
                data: Vec::new(),
                status: 0x6a88,
            }]),
        };
        assert!(matches!(
            Client.get_challenge(&transport, "missing", None),
            Err(Error::Status(0x6a88))
        ));
    }
}
