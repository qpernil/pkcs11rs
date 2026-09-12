use super::protocol::*;
use crate::{CKR_DATA_LEN_RANGE, CKR_MECHANISM_PARAM_INVALID, Error};
use software_key_core::counter_kdf::{CounterKdfField, LengthMethod};
use zeroize::Zeroizing;

const GENERATE_P256: u8 = 1;
const ECDH: u8 = 2;
const APPEND_KEY: u8 = 3;
const APPEND_DATA: u8 = 4;
const EXTRACT: u8 = 5;
const SHA256: u8 = 6;
const COUNTER: u8 = 7;

pub(crate) const FLAG_READABLE: u8 = 1 << 0;
pub(crate) const FLAG_DERIVE: u8 = 1 << 1;
pub(crate) const FLAG_VERIFY: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SessionObjectKind {
    GenericSecret = 1,
    Aes = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionObjectSource {
    Volatile(u64),
    PersistentAsymmetric(u16),
    PersistentSymmetric(u16),
}

fn header(
    operation: u8,
    flags: u8,
    kind: SessionObjectKind,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(length).map_err(|_| CKR_DATA_LEN_RANGE)?;
    Ok(vec![
        operation,
        flags,
        kind as u8,
        length.to_be_bytes()[0],
        length.to_be_bytes()[1],
    ])
}

fn source(data: &mut Vec<u8>, value: SessionObjectSource) {
    match value {
        SessionObjectSource::Volatile(handle) => {
            data.push(0);
            data.extend_from_slice(&handle.to_be_bytes());
        }
        SessionObjectSource::PersistentAsymmetric(id) => {
            data.push(1);
            data.extend_from_slice(&id.to_be_bytes());
        }
        SessionObjectSource::PersistentSymmetric(id) => {
            data.push(2);
            data.extend_from_slice(&id.to_be_bytes());
        }
    }
}

impl Command {
    pub(crate) fn generate_session_p256(flags: u8) -> Result<Self, Error> {
        Self::from_vec(CommandCode::DeriveSessionObject, vec![GENERATE_P256, flags])
    }

    pub(crate) fn derive_session_ecdh(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        base: SessionObjectSource,
        peer: &[u8],
    ) -> Result<Self, Error> {
        let peer_length = u16::try_from(peer.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let mut data = header(ECDH, flags, kind, length)?;
        source(&mut data, base);
        data.extend_from_slice(&peer_length.to_be_bytes());
        data.extend_from_slice(peer);
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn derive_session_append_key(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        left: u64,
        right: u64,
    ) -> Result<Self, Error> {
        let mut data = header(APPEND_KEY, flags, kind, length)?;
        data.extend_from_slice(&left.to_be_bytes());
        data.extend_from_slice(&right.to_be_bytes());
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn derive_session_append_data(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        base: u64,
        suffix: &[u8],
    ) -> Result<Self, Error> {
        let mut data = header(APPEND_DATA, flags, kind, length)?;
        data.extend_from_slice(&base.to_be_bytes());
        data.extend_from_slice(suffix);
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn derive_session_extract(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        base: u64,
        offset_bits: usize,
    ) -> Result<Self, Error> {
        let offset = u16::try_from(offset_bits).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        let mut data = header(EXTRACT, flags, kind, length)?;
        data.extend_from_slice(&base.to_be_bytes());
        data.extend_from_slice(&offset.to_be_bytes());
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn derive_session_sha256(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        base: u64,
    ) -> Result<Self, Error> {
        let mut data = header(SHA256, flags, kind, length)?;
        data.extend_from_slice(&base.to_be_bytes());
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn derive_session_counter(
        flags: u8,
        kind: SessionObjectKind,
        length: usize,
        base: SessionObjectSource,
        fields: &[CounterKdfField<'_>],
    ) -> Result<Self, Error> {
        let count = u8::try_from(fields.len()).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        if count == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        let mut data = header(COUNTER, flags, kind, length)?;
        source(&mut data, base);
        data.push(count);
        for field in fields {
            match field {
                CounterKdfField::Bytes(value) => {
                    let length = u16::try_from(value.len())
                        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
                    data.push(0);
                    data.extend_from_slice(&length.to_be_bytes());
                    data.extend_from_slice(value);
                }
                CounterKdfField::Counter(format) => {
                    data.extend_from_slice(&[1, format.width_bits, u8::from(format.little_endian)]);
                }
                CounterKdfField::Length(format, method) => {
                    data.extend_from_slice(&[
                        2,
                        format.width_bits,
                        u8::from(format.little_endian),
                        match method {
                            LengthMethod::Key => 0,
                            LengthMethod::Segments => 1,
                        },
                    ]);
                }
            }
        }
        Self::from_vec(CommandCode::DeriveSessionObject, data)
    }

    pub(crate) fn read_session_object(handle: u64) -> Self {
        Self {
            code: CommandCode::ReadSessionObject,
            data: Zeroizing::new(handle.to_be_bytes().to_vec()),
        }
    }

    pub(crate) fn verify_session_object(
        handle: u64,
        signature: &[u8],
        data: &[u8],
    ) -> Result<Self, Error> {
        let signature_length = u8::try_from(signature.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        if !(1..=16).contains(&signature_length) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut input = Vec::with_capacity(9 + signature.len() + data.len());
        input.extend_from_slice(&handle.to_be_bytes());
        input.push(signature_length);
        input.extend_from_slice(signature);
        input.extend_from_slice(data);
        Self::from_vec(CommandCode::VerifySessionObject, input)
    }

    pub(crate) fn delete_session_object(handle: u64) -> Self {
        Self {
            code: CommandCode::DeleteSessionObject,
            data: Zeroizing::new(handle.to_be_bytes().to_vec()),
        }
    }
}
