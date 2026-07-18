use crate::{error::Error, CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE};
use zeroize::Zeroizing;

const LABEL_LENGTH: usize = 40;
const CAPABILITIES_LENGTH: usize = 8;
const MAX_COMMAND_DATA_LENGTH: usize = 3133;
const MAX_OBJECT_COUNT: usize = 256;
const MAX_LOG_ENTRY_COUNT: usize = 64;
const ALGORITHM_AES128_YUBICO_OTP: u8 = 37;
const ALGORITHM_AES128_YUBICO_AUTHENTICATION: u8 = 38;
const ALGORITHM_AES192_YUBICO_OTP: u8 = 39;
const ALGORITHM_AES256_YUBICO_OTP: u8 = 40;
const ALGORITHM_EC_P256_YUBICO_AUTHENTICATION: u8 = 49;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CommandCode {
    Echo = 0x01,
    CreateSession = 0x03,
    AuthenticateSession = 0x04,
    SessionMessage = 0x05,
    GetDeviceInfo = 0x06,
    ResetDevice = 0x08,
    GetDevicePublicKey = 0x0a,
    CloseSession = 0x40,
    GetStorageInfo = 0x41,
    PutOpaque = 0x42,
    GetOpaque = 0x43,
    PutAuthenticationKey = 0x44,
    PutAsymmetricKey = 0x45,
    GenerateAsymmetricKey = 0x46,
    SignPkcs1 = 0x47,
    ListObjects = 0x48,
    DecryptPkcs1 = 0x49,
    ExportWrapped = 0x4a,
    ImportWrapped = 0x4b,
    PutWrapKey = 0x4c,
    GetLogEntries = 0x4d,
    GetObjectInfo = 0x4e,
    SetOption = 0x4f,
    GetOption = 0x50,
    GetPseudoRandom = 0x51,
    PutHmacKey = 0x52,
    SignHmac = 0x53,
    GetPublicKey = 0x54,
    SignPss = 0x55,
    SignEcdsa = 0x56,
    DeriveEcdh = 0x57,
    DeleteObject = 0x58,
    DecryptOaep = 0x59,
    GenerateHmacKey = 0x5a,
    GenerateWrapKey = 0x5b,
    VerifyHmac = 0x5c,
    SignSshCertificate = 0x5d,
    PutTemplate = 0x5e,
    GetTemplate = 0x5f,
    DecryptOtp = 0x60,
    CreateOtpAead = 0x61,
    RandomizeOtpAead = 0x62,
    RewrapOtpAead = 0x63,
    SignAttestationCertificate = 0x64,
    PutOtpAeadKey = 0x65,
    GenerateOtpAeadKey = 0x66,
    SetLogIndex = 0x67,
    WrapData = 0x68,
    UnwrapData = 0x69,
    SignEddsa = 0x6a,
    BlinkDevice = 0x6b,
    ChangeAuthenticationKey = 0x6c,
    PutSymmetricKey = 0x6d,
    GenerateSymmetricKey = 0x6e,
    DecryptEcb = 0x6f,
    EncryptEcb = 0x70,
    DecryptCbc = 0x71,
    EncryptCbc = 0x72,
    PutPublicWrapKey = 0x73,
    GetRsaWrappedKey = 0x74,
    PutRsaWrappedKey = 0x75,
    ExportRsaWrapped = 0x76,
    ImportRsaWrapped = 0x77,
}

pub(crate) const ALL_COMMAND_CODES: &[CommandCode] = &[
    CommandCode::Echo,
    CommandCode::CreateSession,
    CommandCode::AuthenticateSession,
    CommandCode::SessionMessage,
    CommandCode::GetDeviceInfo,
    CommandCode::ResetDevice,
    CommandCode::GetDevicePublicKey,
    CommandCode::CloseSession,
    CommandCode::GetStorageInfo,
    CommandCode::PutOpaque,
    CommandCode::GetOpaque,
    CommandCode::PutAuthenticationKey,
    CommandCode::PutAsymmetricKey,
    CommandCode::GenerateAsymmetricKey,
    CommandCode::SignPkcs1,
    CommandCode::ListObjects,
    CommandCode::DecryptPkcs1,
    CommandCode::ExportWrapped,
    CommandCode::ImportWrapped,
    CommandCode::PutWrapKey,
    CommandCode::GetLogEntries,
    CommandCode::GetObjectInfo,
    CommandCode::SetOption,
    CommandCode::GetOption,
    CommandCode::GetPseudoRandom,
    CommandCode::PutHmacKey,
    CommandCode::SignHmac,
    CommandCode::GetPublicKey,
    CommandCode::SignPss,
    CommandCode::SignEcdsa,
    CommandCode::DeriveEcdh,
    CommandCode::DeleteObject,
    CommandCode::DecryptOaep,
    CommandCode::GenerateHmacKey,
    CommandCode::GenerateWrapKey,
    CommandCode::VerifyHmac,
    CommandCode::SignSshCertificate,
    CommandCode::PutTemplate,
    CommandCode::GetTemplate,
    CommandCode::DecryptOtp,
    CommandCode::CreateOtpAead,
    CommandCode::RandomizeOtpAead,
    CommandCode::RewrapOtpAead,
    CommandCode::SignAttestationCertificate,
    CommandCode::PutOtpAeadKey,
    CommandCode::GenerateOtpAeadKey,
    CommandCode::SetLogIndex,
    CommandCode::WrapData,
    CommandCode::UnwrapData,
    CommandCode::SignEddsa,
    CommandCode::BlinkDevice,
    CommandCode::ChangeAuthenticationKey,
    CommandCode::PutSymmetricKey,
    CommandCode::GenerateSymmetricKey,
    CommandCode::DecryptEcb,
    CommandCode::EncryptEcb,
    CommandCode::DecryptCbc,
    CommandCode::EncryptCbc,
    CommandCode::PutPublicWrapKey,
    CommandCode::GetRsaWrappedKey,
    CommandCode::PutRsaWrappedKey,
    CommandCode::ExportRsaWrapped,
    CommandCode::ImportRsaWrapped,
];

impl TryFrom<u8> for CommandCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ALL_COMMAND_CODES
            .iter()
            .copied()
            .find(|command| *command as u8 == value)
            .ok_or_else(|| CKR_DATA_INVALID.into())
    }
}

impl CommandCode {
    pub(crate) fn is_bare(self) -> bool {
        matches!(
            self,
            Self::Echo | Self::GetDeviceInfo | Self::GetDevicePublicKey
        )
    }

    pub(crate) fn is_session_protocol(self) -> bool {
        matches!(
            self,
            Self::CreateSession | Self::AuthenticateSession | Self::SessionMessage
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Command {
    code: CommandCode,
    data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Command")
            .field("code", &self.code)
            .field("data_length", &self.data.len())
            .finish()
    }
}

impl Command {
    pub(crate) fn raw(code: CommandCode, data: &[u8]) -> Result<Self, Error> {
        Self::from_vec(code, data.to_vec())
    }

    fn from_vec(code: CommandCode, data: Vec<u8>) -> Result<Self, Error> {
        if data.len() > MAX_COMMAND_DATA_LENGTH {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        Ok(Self {
            code,
            data: Zeroizing::new(data),
        })
    }

    pub(crate) fn code(&self) -> CommandCode {
        self.code
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn empty(code: CommandCode) -> Self {
        Self {
            code,
            data: Zeroizing::new(Vec::new()),
        }
    }
}

fn prefixed_u16(value: u16, tail: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + tail.len());
    data.extend_from_slice(&value.to_be_bytes());
    data.extend_from_slice(tail);
    data
}

fn ensure_code(code: CommandCode, allowed: &[CommandCode]) -> Result<(), Error> {
    if allowed.contains(&code) {
        Ok(())
    } else {
        Err(CKR_DATA_INVALID.into())
    }
}

fn require_digest_length(digest: &[u8]) -> Result<(), Error> {
    if matches!(digest.len(), 20 | 32 | 48 | 64) {
        Ok(())
    } else {
        Err(CKR_DATA_LEN_RANGE.into())
    }
}
