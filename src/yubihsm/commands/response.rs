#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageInfo {
    pub(crate) total_records: u16,
    pub(crate) free_records: u16,
    pub(crate) total_pages: u16,
    pub(crate) free_pages: u16,
    pub(crate) page_size: u16,
}

impl StorageInfo {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 10 {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(Self {
            total_records: read_u16(data, 0)?,
            free_records: read_u16(data, 2)?,
            total_pages: read_u16(data, 4)?,
            free_pages: read_u16(data, 6)?,
            page_size: read_u16(data, 8)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectInfo {
    pub(crate) capabilities: [u8; CAPABILITIES_LENGTH],
    pub(crate) id: u16,
    pub(crate) length: u16,
    pub(crate) domains: u16,
    pub(crate) object_type: u8,
    pub(crate) algorithm: u8,
    pub(crate) sequence: u8,
    pub(crate) origin: u8,
    pub(crate) label: String,
    pub(crate) delegated_capabilities: [u8; CAPABILITIES_LENGTH],
}

impl ObjectInfo {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 66 {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(Self {
            capabilities: data[0..8].try_into().map_err(|_| CKR_DATA_INVALID)?,
            id: read_u16(data, 8)?,
            length: read_u16(data, 10)?,
            domains: read_u16(data, 12)?,
            object_type: data[14],
            algorithm: data[15],
            sequence: data[16],
            origin: data[17],
            label: {
                let encoded = data[18..58]
                    .split(|byte| *byte == 0)
                    .next()
                    .unwrap_or_default();
                std::str::from_utf8(encoded)
                    .map_err(|_| CKR_DATA_INVALID)?
                    .to_owned()
            },
            delegated_capabilities: data[58..66].try_into().map_err(|_| CKR_DATA_INVALID)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectEntry {
    pub(crate) id: u16,
    pub(crate) object_type: u8,
    pub(crate) sequence: u8,
}

pub(crate) fn parse_object_list(data: &[u8]) -> Result<Vec<ObjectEntry>, Error> {
    if !crate::is_multiple_of(data.len(), 4) || data.len() / 4 > MAX_OBJECT_COUNT {
        return Err(CKR_DATA_INVALID.into());
    }
    data.chunks_exact(4)
        .map(|item| {
            Ok(ObjectEntry {
                id: read_u16(item, 0)?,
                object_type: item[2],
                sequence: item[3],
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LogEntry {
    pub(crate) number: u16,
    pub(crate) command: u8,
    pub(crate) length: u16,
    pub(crate) session_key: u16,
    pub(crate) target_key: u16,
    pub(crate) second_key: u16,
    pub(crate) result: u8,
    pub(crate) systick: u32,
    pub(crate) digest: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LogEntries {
    pub(crate) unlogged_boot: u16,
    pub(crate) unlogged_authentication: u16,
    pub(crate) entries: Vec<LogEntry>,
}

impl LogEntries {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        const HEADER_LENGTH: usize = 5;
        const ENTRY_LENGTH: usize = 32;
        if data.len() < HEADER_LENGTH
            || data[4] as usize > MAX_LOG_ENTRY_COUNT
            || data.len() - HEADER_LENGTH != data[4] as usize * ENTRY_LENGTH
        {
            return Err(CKR_DATA_INVALID.into());
        }
        let entries = data[HEADER_LENGTH..]
            .chunks_exact(ENTRY_LENGTH)
            .map(|entry| {
                Ok(LogEntry {
                    number: read_u16(entry, 0)?,
                    command: entry[2],
                    length: read_u16(entry, 3)?,
                    session_key: read_u16(entry, 5)?,
                    target_key: read_u16(entry, 7)?,
                    second_key: read_u16(entry, 9)?,
                    result: entry[11],
                    systick: read_u32(entry, 12)?,
                    digest: entry[16..32].try_into().map_err(|_| CKR_DATA_INVALID)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self {
            unlogged_boot: read_u16(data, 0)?,
            unlogged_authentication: read_u16(data, 2)?,
            entries,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImportedObject {
    pub(crate) object_type: u8,
    pub(crate) id: u16,
}

impl ImportedObject {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 3 {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(Self {
            object_type: data[0],
            id: read_u16(data, 1)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicKey {
    pub(crate) algorithm: u8,
    pub(crate) key: Vec<u8>,
}

impl PublicKey {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        let (&algorithm, key) = data.split_first().ok_or(CKR_DATA_INVALID)?;
        Ok(Self {
            algorithm,
            key: key.to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OtpDecryption {
    pub(crate) use_counter: u16,
    pub(crate) session_counter: u8,
    pub(crate) timestamp_high: u8,
    pub(crate) timestamp_low: u16,
}

impl OtpDecryption {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 6 {
            return Err(CKR_DATA_INVALID.into());
        }
        // OTP counters use the Yubico OTP little-endian representation.
        Ok(Self {
            use_counter: u16::from_le_bytes([data[0], data[1]]),
            session_counter: data[2],
            timestamp_high: data[3],
            timestamp_low: u16::from_le_bytes([data[4], data[5]]),
        })
    }
}

pub(crate) fn parse_object_id(data: &[u8]) -> Result<u16, Error> {
    if data.len() != 2 {
        return Err(CKR_DATA_INVALID.into());
    }
    read_u16(data, 0)
}

pub(crate) fn require_empty(data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(CKR_DATA_INVALID.into())
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    data.get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| CKR_DATA_INVALID.into())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, Error> {
    data.get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| CKR_DATA_INVALID.into())
}
