use crate::{error::Error, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE};
use zeroize::Zeroizing;

const LABEL_LENGTH: usize = 40;
const CAPABILITIES_LENGTH: usize = 8;

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
        if data.len() > u16::MAX as usize {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        Ok(Self {
            code,
            data: Zeroizing::new(data.to_vec()),
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

    pub(crate) fn echo(data: &[u8]) -> Result<Self, Error> {
        Self::raw(CommandCode::Echo, data)
    }

    pub(crate) fn get_device_info(page: Option<u8>) -> Self {
        Self {
            code: CommandCode::GetDeviceInfo,
            data: Zeroizing::new(page.into_iter().collect()),
        }
    }

    pub(crate) fn get_device_public_key() -> Self {
        Self::empty(CommandCode::GetDevicePublicKey)
    }

    pub(crate) fn reset_device() -> Self {
        Self::empty(CommandCode::ResetDevice)
    }

    pub(crate) fn close_session() -> Self {
        Self::empty(CommandCode::CloseSession)
    }

    pub(crate) fn get_storage_info() -> Self {
        Self::empty(CommandCode::GetStorageInfo)
    }

    pub(crate) fn get_log_entries() -> Self {
        Self::empty(CommandCode::GetLogEntries)
    }

    pub(crate) fn put_object(
        code: CommandCode,
        parameters: &ObjectParameters,
        value: &[u8],
    ) -> Result<Self, Error> {
        ensure_code(
            code,
            &[
                CommandCode::PutOpaque,
                CommandCode::PutAsymmetricKey,
                CommandCode::PutHmacKey,
                CommandCode::PutTemplate,
                CommandCode::PutSymmetricKey,
            ],
        )?;
        let mut data = parameters.encode()?;
        data.extend_from_slice(value);
        Self::raw(code, &data)
    }

    pub(crate) fn generate_object(
        code: CommandCode,
        parameters: &ObjectParameters,
    ) -> Result<Self, Error> {
        ensure_code(
            code,
            &[
                CommandCode::GenerateAsymmetricKey,
                CommandCode::GenerateHmacKey,
                CommandCode::GenerateSymmetricKey,
            ],
        )?;
        Self::raw(code, &parameters.encode()?)
    }

    pub(crate) fn put_delegated_object(
        code: CommandCode,
        parameters: &DelegatedObjectParameters,
        value: &[u8],
    ) -> Result<Self, Error> {
        ensure_code(
            code,
            &[
                CommandCode::PutAuthenticationKey,
                CommandCode::PutWrapKey,
                CommandCode::PutPublicWrapKey,
            ],
        )?;
        let mut data = parameters.encode()?;
        data.extend_from_slice(value);
        Self::raw(code, &data)
    }

    pub(crate) fn generate_wrap_key(parameters: &DelegatedObjectParameters) -> Result<Self, Error> {
        Self::raw(CommandCode::GenerateWrapKey, &parameters.encode()?)
    }

    pub(crate) fn get_object(code: CommandCode, id: u16) -> Result<Self, Error> {
        ensure_code(code, &[CommandCode::GetOpaque, CommandCode::GetTemplate])?;
        Self::raw(code, &id.to_be_bytes())
    }

    pub(crate) fn key_data(code: CommandCode, key_id: u16, value: &[u8]) -> Result<Self, Error> {
        ensure_code(
            code,
            &[
                CommandCode::SignPkcs1,
                CommandCode::DecryptPkcs1,
                CommandCode::SignHmac,
                CommandCode::SignEcdsa,
                CommandCode::DeriveEcdh,
                CommandCode::SignEddsa,
                CommandCode::WrapData,
                CommandCode::UnwrapData,
                CommandCode::DecryptEcb,
                CommandCode::EncryptEcb,
            ],
        )?;
        if matches!(code, CommandCode::DecryptEcb | CommandCode::EncryptEcb)
            && !value.len().is_multiple_of(16)
        {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        Self::raw(code, &prefixed_u16(key_id, value))
    }

    pub(crate) fn crypt_cbc(
        code: CommandCode,
        key_id: u16,
        iv: &[u8; 16],
        value: &[u8],
    ) -> Result<Self, Error> {
        ensure_code(code, &[CommandCode::DecryptCbc, CommandCode::EncryptCbc])?;
        if !value.len().is_multiple_of(16) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut data = prefixed_u16(key_id, iv);
        data.extend_from_slice(value);
        Self::raw(code, &data)
    }

    pub(crate) fn sign_pss(
        key_id: u16,
        mgf1_algorithm: u8,
        salt_length: u16,
        digest: &[u8],
    ) -> Result<Self, Error> {
        require_digest_length(digest)?;
        let mut data = prefixed_u16(key_id, &[mgf1_algorithm]);
        data.extend_from_slice(&salt_length.to_be_bytes());
        data.extend_from_slice(digest);
        Self::raw(CommandCode::SignPss, &data)
    }

    pub(crate) fn decrypt_oaep(
        key_id: u16,
        mgf1_algorithm: u8,
        ciphertext: &[u8],
        label_digest: &[u8],
    ) -> Result<Self, Error> {
        if !matches!(ciphertext.len(), 256 | 384 | 512) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        require_digest_length(label_digest)?;
        let mut data = prefixed_u16(key_id, &[mgf1_algorithm]);
        data.extend_from_slice(ciphertext);
        data.extend_from_slice(label_digest);
        Self::raw(CommandCode::DecryptOaep, &data)
    }

    pub(crate) fn verify_hmac(key_id: u16, signature: &[u8], data: &[u8]) -> Result<Self, Error> {
        require_digest_length(signature)?;
        let mut encoded = prefixed_u16(key_id, signature);
        encoded.extend_from_slice(data);
        Self::raw(CommandCode::VerifyHmac, &encoded)
    }

    pub(crate) fn list_objects(filters: &[ObjectFilter<'_>]) -> Result<Self, Error> {
        let mut data = Vec::new();
        for filter in filters {
            filter.encode(&mut data)?;
        }
        Self::raw(CommandCode::ListObjects, &data)
    }

    pub(crate) fn get_object_info(id: u16, object_type: u8) -> Self {
        let mut data = id.to_be_bytes().to_vec();
        data.push(object_type);
        Self {
            code: CommandCode::GetObjectInfo,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn get_public_key(id: u16, object_type: Option<u8>) -> Self {
        let mut data = id.to_be_bytes().to_vec();
        data.extend(object_type);
        Self {
            code: CommandCode::GetPublicKey,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn delete_object(id: u16, object_type: u8) -> Self {
        Self::get_object_info(id, object_type).with_code(CommandCode::DeleteObject)
    }

    pub(crate) fn export_wrapped(
        wrapping_key_id: u16,
        object_type: u8,
        object_id: u16,
        format: Option<u8>,
    ) -> Self {
        let mut data = wrapping_key_id.to_be_bytes().to_vec();
        data.push(object_type);
        data.extend_from_slice(&object_id.to_be_bytes());
        data.extend(format);
        Self {
            code: CommandCode::ExportWrapped,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn import_wrapped(wrapping_key_id: u16, wrapped: &[u8]) -> Result<Self, Error> {
        Self::raw(
            CommandCode::ImportWrapped,
            &prefixed_u16(wrapping_key_id, wrapped),
        )
    }

    pub(crate) fn set_option(option: u8, value: &[u8]) -> Result<Self, Error> {
        let length = u16::try_from(value.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let mut data = vec![option];
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(value);
        Self::raw(CommandCode::SetOption, &data)
    }

    pub(crate) fn get_option(option: u8) -> Self {
        Self {
            code: CommandCode::GetOption,
            data: Zeroizing::new(vec![option]),
        }
    }

    pub(crate) fn get_pseudo_random(length: u16) -> Self {
        Self {
            code: CommandCode::GetPseudoRandom,
            data: Zeroizing::new(length.to_be_bytes().to_vec()),
        }
    }

    pub(crate) fn sign_ssh_certificate(
        key_id: u16,
        template_id: u16,
        algorithm: u8,
        request: &[u8],
    ) -> Result<Self, Error> {
        let mut data = key_id.to_be_bytes().to_vec();
        data.extend_from_slice(&template_id.to_be_bytes());
        data.push(algorithm);
        data.extend_from_slice(request);
        Self::raw(CommandCode::SignSshCertificate, &data)
    }

    pub(crate) fn decrypt_otp(key_id: u16, aead: &[u8; 36], otp: &[u8; 16]) -> Self {
        let mut data = prefixed_u16(key_id, aead);
        data.extend_from_slice(otp);
        Self {
            code: CommandCode::DecryptOtp,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn create_otp_aead(key_id: u16, otp_key: &[u8; 16], private_id: &[u8; 6]) -> Self {
        let mut data = prefixed_u16(key_id, otp_key);
        data.extend_from_slice(private_id);
        Self {
            code: CommandCode::CreateOtpAead,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn randomize_otp_aead(key_id: u16) -> Self {
        Self {
            code: CommandCode::RandomizeOtpAead,
            data: Zeroizing::new(key_id.to_be_bytes().to_vec()),
        }
    }

    pub(crate) fn rewrap_otp_aead(from: u16, to: u16, aead: &[u8; 36]) -> Self {
        let mut data = from.to_be_bytes().to_vec();
        data.extend_from_slice(&to.to_be_bytes());
        data.extend_from_slice(aead);
        Self {
            code: CommandCode::RewrapOtpAead,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn sign_attestation_certificate(key_id: u16, attestation_id: u16) -> Self {
        let mut data = key_id.to_be_bytes().to_vec();
        data.extend_from_slice(&attestation_id.to_be_bytes());
        Self {
            code: CommandCode::SignAttestationCertificate,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn otp_aead_key(
        code: CommandCode,
        parameters: &ObjectParameters,
        nonce_id: u32,
        key: &[u8],
    ) -> Result<Self, Error> {
        ensure_code(
            code,
            &[CommandCode::PutOtpAeadKey, CommandCode::GenerateOtpAeadKey],
        )?;
        let mut data = parameters.encode()?;
        data.extend_from_slice(&nonce_id.to_le_bytes());
        match code {
            CommandCode::PutOtpAeadKey if !matches!(key.len(), 16 | 24 | 32) => {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            CommandCode::GenerateOtpAeadKey if !key.is_empty() => {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            _ => {}
        }
        data.extend_from_slice(key);
        Self::raw(code, &data)
    }

    pub(crate) fn set_log_index(index: u16) -> Self {
        Self {
            code: CommandCode::SetLogIndex,
            data: Zeroizing::new(index.to_be_bytes().to_vec()),
        }
    }

    pub(crate) fn blink_device(seconds: u8) -> Self {
        Self {
            code: CommandCode::BlinkDevice,
            data: Zeroizing::new(vec![seconds]),
        }
    }

    pub(crate) fn change_authentication_key(
        id: u16,
        algorithm: u8,
        key: &[u8],
    ) -> Result<Self, Error> {
        if !matches!(key.len(), 32 | 64) {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut data = prefixed_u16(id, &[algorithm]);
        data.extend_from_slice(key);
        Self::raw(CommandCode::ChangeAuthenticationKey, &data)
    }

    pub(crate) fn rsa_wrap(
        code: CommandCode,
        parameters: &RsaWrapParameters<'_>,
    ) -> Result<Self, Error> {
        ensure_code(
            code,
            &[CommandCode::GetRsaWrappedKey, CommandCode::ExportRsaWrapped],
        )?;
        require_digest_length(parameters.label_digest)?;
        let mut data = parameters.wrapping_key_id.to_be_bytes().to_vec();
        data.push(parameters.object_type);
        data.extend_from_slice(&parameters.object_id.to_be_bytes());
        data.extend_from_slice(&[
            parameters.aes_algorithm,
            parameters.hash_algorithm,
            parameters.mgf1_algorithm,
        ]);
        data.extend_from_slice(parameters.label_digest);
        Self::raw(code, &data)
    }

    pub(crate) fn put_rsa_wrapped_key(
        wrapping_key_id: u16,
        object_type: u8,
        parameters: &ObjectParameters,
        hash_algorithm: u8,
        mgf1_algorithm: u8,
        wrapped: &[u8],
        label_digest: &[u8],
    ) -> Result<Self, Error> {
        require_digest_length(label_digest)?;
        let mut data = wrapping_key_id.to_be_bytes().to_vec();
        data.push(object_type);
        data.extend_from_slice(&parameters.encode()?);
        data.extend_from_slice(&[hash_algorithm, mgf1_algorithm]);
        data.extend_from_slice(wrapped);
        data.extend_from_slice(label_digest);
        Self::raw(CommandCode::PutRsaWrappedKey, &data)
    }

    pub(crate) fn import_rsa_wrapped(
        wrapping_key_id: u16,
        hash_algorithm: u8,
        mgf1_algorithm: u8,
        wrapped: &[u8],
        label_digest: &[u8],
    ) -> Result<Self, Error> {
        require_digest_length(label_digest)?;
        let mut data = wrapping_key_id.to_be_bytes().to_vec();
        data.extend_from_slice(&[hash_algorithm, mgf1_algorithm]);
        data.extend_from_slice(wrapped);
        data.extend_from_slice(label_digest);
        Self::raw(CommandCode::ImportRsaWrapped, &data)
    }

    fn with_code(mut self, code: CommandCode) -> Self {
        self.code = code;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RsaWrapParameters<'a> {
    pub(crate) wrapping_key_id: u16,
    pub(crate) object_type: u8,
    pub(crate) object_id: u16,
    pub(crate) aes_algorithm: u8,
    pub(crate) hash_algorithm: u8,
    pub(crate) mgf1_algorithm: u8,
    pub(crate) label_digest: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectParameters<'a> {
    pub(crate) id: u16,
    pub(crate) label: &'a [u8],
    pub(crate) domains: u16,
    pub(crate) capabilities: [u8; CAPABILITIES_LENGTH],
    pub(crate) algorithm: u8,
}

impl ObjectParameters<'_> {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.label.len() > LABEL_LENGTH {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut data = Vec::with_capacity(2 + LABEL_LENGTH + 2 + CAPABILITIES_LENGTH + 1);
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(self.label);
        data.resize(2 + LABEL_LENGTH, 0);
        data.extend_from_slice(&self.domains.to_be_bytes());
        data.extend_from_slice(&self.capabilities);
        data.push(self.algorithm);
        Ok(data)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DelegatedObjectParameters<'a> {
    pub(crate) object: ObjectParameters<'a>,
    pub(crate) delegated_capabilities: [u8; CAPABILITIES_LENGTH],
}

impl DelegatedObjectParameters<'_> {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = self.object.encode()?;
        data.extend_from_slice(&self.delegated_capabilities);
        Ok(data)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectFilter<'a> {
    Id(u16),
    Type(u8),
    Domains(u16),
    Capabilities([u8; CAPABILITIES_LENGTH]),
    Algorithm(u8),
    Label(&'a [u8]),
}

impl ObjectFilter<'_> {
    fn encode(&self, data: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Id(id) => {
                data.push(1);
                data.extend_from_slice(&id.to_be_bytes());
            }
            Self::Type(object_type) => data.extend_from_slice(&[2, *object_type]),
            Self::Domains(domains) => {
                data.push(3);
                data.extend_from_slice(&domains.to_be_bytes());
            }
            Self::Capabilities(capabilities) => {
                data.push(4);
                data.extend_from_slice(capabilities);
            }
            Self::Algorithm(algorithm) => data.extend_from_slice(&[5, *algorithm]),
            Self::Label(label) => {
                if label.len() > LABEL_LENGTH {
                    return Err(CKR_DATA_LEN_RANGE.into());
                }
                data.push(6);
                data.extend_from_slice(label);
                data.resize(data.len() + LABEL_LENGTH - label.len(), 0);
            }
        }
        Ok(())
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
    pub(crate) label: [u8; LABEL_LENGTH],
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
            label: data[18..58].try_into().map_err(|_| CKR_DATA_INVALID)?,
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
    if !data.len().is_multiple_of(4) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn object<'a>(label: &'a [u8]) -> ObjectParameters<'a> {
        ObjectParameters {
            id: 0x1234,
            label,
            domains: 0x5678,
            capabilities: [0x11; 8],
            algorithm: 0x22,
        }
    }

    fn delegated<'a>(label: &'a [u8]) -> DelegatedObjectParameters<'a> {
        DelegatedObjectParameters {
            object: object(label),
            delegated_capabilities: [0x33; 8],
        }
    }

    fn all_sample_commands() -> Vec<Command> {
        let aead = [0x44; 36];
        let otp = [0x55; 16];
        let private_id = [0x66; 6];
        let iv = [0x77; 16];
        let mut commands = vec![
            Command::echo(b"echo").unwrap(),
            Command::raw(CommandCode::CreateSession, b"session").unwrap(),
            Command::raw(CommandCode::AuthenticateSession, b"auth").unwrap(),
            Command::raw(CommandCode::SessionMessage, b"message").unwrap(),
            Command::get_device_info(None),
            Command::reset_device(),
            Command::get_device_public_key(),
            Command::close_session(),
            Command::get_storage_info(),
            Command::put_object(CommandCode::PutOpaque, &object(b"opaque"), b"value").unwrap(),
            Command::get_object(CommandCode::GetOpaque, 1).unwrap(),
            Command::put_delegated_object(
                CommandCode::PutAuthenticationKey,
                &delegated(b"auth"),
                &[0; 32],
            )
            .unwrap(),
            Command::put_object(
                CommandCode::PutAsymmetricKey,
                &object(b"asymmetric"),
                &[0; 32],
            )
            .unwrap(),
            Command::generate_object(CommandCode::GenerateAsymmetricKey, &object(b"asym-gen"))
                .unwrap(),
            Command::key_data(CommandCode::SignPkcs1, 1, b"digest").unwrap(),
            Command::list_objects(&[
                ObjectFilter::Id(1),
                ObjectFilter::Type(2),
                ObjectFilter::Domains(3),
                ObjectFilter::Capabilities([4; 8]),
                ObjectFilter::Algorithm(5),
                ObjectFilter::Label(b"label"),
            ])
            .unwrap(),
            Command::key_data(CommandCode::DecryptPkcs1, 1, b"ciphertext").unwrap(),
            Command::export_wrapped(1, 2, 3, None),
            Command::import_wrapped(1, b"wrapped").unwrap(),
            Command::put_delegated_object(CommandCode::PutWrapKey, &delegated(b"wrap"), &[0; 16])
                .unwrap(),
            Command::get_log_entries(),
            Command::get_object_info(1, 2),
            Command::set_option(1, &[2]).unwrap(),
            Command::get_option(1),
            Command::get_pseudo_random(32),
            Command::put_object(CommandCode::PutHmacKey, &object(b"hmac"), &[0; 32]).unwrap(),
            Command::key_data(CommandCode::SignHmac, 1, b"data").unwrap(),
            Command::get_public_key(1, None),
            Command::sign_pss(1, 32, 32, &[0; 32]).unwrap(),
            Command::key_data(CommandCode::SignEcdsa, 1, &[0; 32]).unwrap(),
            Command::key_data(CommandCode::DeriveEcdh, 1, &[0; 65]).unwrap(),
            Command::delete_object(1, 2),
            Command::decrypt_oaep(1, 32, &[0; 256], &[0; 32]).unwrap(),
            Command::generate_object(CommandCode::GenerateHmacKey, &object(b"hmac-gen")).unwrap(),
            Command::generate_wrap_key(&delegated(b"wrap-gen")).unwrap(),
            Command::verify_hmac(1, &[0; 32], b"data").unwrap(),
            Command::sign_ssh_certificate(1, 2, 3, b"request").unwrap(),
            Command::put_object(CommandCode::PutTemplate, &object(b"template"), b"template")
                .unwrap(),
            Command::get_object(CommandCode::GetTemplate, 1).unwrap(),
            Command::decrypt_otp(1, &aead, &otp),
            Command::create_otp_aead(1, &otp, &private_id),
            Command::randomize_otp_aead(1),
            Command::rewrap_otp_aead(1, 2, &aead),
            Command::sign_attestation_certificate(1, 2),
            Command::otp_aead_key(CommandCode::PutOtpAeadKey, &object(b"otp"), 4, &[0; 16])
                .unwrap(),
            Command::otp_aead_key(CommandCode::GenerateOtpAeadKey, &object(b"otp-gen"), 4, &[])
                .unwrap(),
            Command::set_log_index(1),
            Command::key_data(CommandCode::WrapData, 1, b"data").unwrap(),
            Command::key_data(CommandCode::UnwrapData, 1, b"wrapped").unwrap(),
            Command::key_data(CommandCode::SignEddsa, 1, b"data").unwrap(),
            Command::blink_device(10),
            Command::change_authentication_key(1, 38, &[0; 32]).unwrap(),
            Command::put_object(
                CommandCode::PutSymmetricKey,
                &object(b"symmetric"),
                &[0; 16],
            )
            .unwrap(),
            Command::generate_object(CommandCode::GenerateSymmetricKey, &object(b"symmetric-gen"))
                .unwrap(),
            Command::key_data(CommandCode::DecryptEcb, 1, &[0; 16]).unwrap(),
            Command::key_data(CommandCode::EncryptEcb, 1, &[0; 16]).unwrap(),
            Command::crypt_cbc(CommandCode::DecryptCbc, 1, &iv, &[0; 16]).unwrap(),
            Command::crypt_cbc(CommandCode::EncryptCbc, 1, &iv, &[0; 16]).unwrap(),
            Command::put_delegated_object(
                CommandCode::PutPublicWrapKey,
                &delegated(b"public-wrap"),
                &[0; 256],
            )
            .unwrap(),
            Command::rsa_wrap(
                CommandCode::GetRsaWrappedKey,
                &RsaWrapParameters {
                    wrapping_key_id: 1,
                    object_type: 3,
                    object_id: 2,
                    aes_algorithm: 50,
                    hash_algorithm: 26,
                    mgf1_algorithm: 33,
                    label_digest: &[0; 32],
                },
            )
            .unwrap(),
            Command::put_rsa_wrapped_key(1, 3, &object(b"rsa-wrapped"), 26, 33, b"key", &[0; 32])
                .unwrap(),
            Command::rsa_wrap(
                CommandCode::ExportRsaWrapped,
                &RsaWrapParameters {
                    wrapping_key_id: 1,
                    object_type: 3,
                    object_id: 2,
                    aes_algorithm: 50,
                    hash_algorithm: 26,
                    mgf1_algorithm: 33,
                    label_digest: &[0; 32],
                },
            )
            .unwrap(),
            Command::import_rsa_wrapped(1, 26, 33, b"object", &[0; 32]).unwrap(),
        ];
        commands.sort_by_key(|command| command.code() as u8);
        commands
    }

    #[test]
    fn every_official_command_has_a_typed_request() {
        let commands = all_sample_commands();
        assert_eq!(commands.len(), 63);
        assert_eq!(commands.len(), ALL_COMMAND_CODES.len());
        assert_eq!(
            commands
                .iter()
                .map(|command| command.code() as u8)
                .collect::<BTreeSet<_>>(),
            ALL_COMMAND_CODES
                .iter()
                .map(|command| *command as u8)
                .collect()
        );
        assert_eq!(
            ALL_COMMAND_CODES
                .iter()
                .filter(|command| (**command as u8) >= 0x40)
                .map(|command| *command as u8)
                .collect::<Vec<_>>(),
            (0x40..=0x77).collect::<Vec<_>>()
        );
    }

    #[test]
    fn object_parameters_match_the_documented_wire_layout() {
        let encoded = object(b"abc").encode().unwrap();
        assert_eq!(encoded.len(), 53);
        assert_eq!(&encoded[0..2], &[0x12, 0x34]);
        assert_eq!(&encoded[2..5], b"abc");
        assert!(encoded[5..42].iter().all(|byte| *byte == 0));
        assert_eq!(&encoded[42..44], &[0x56, 0x78]);
        assert_eq!(&encoded[44..52], &[0x11; 8]);
        assert_eq!(encoded[52], 0x22);
        assert!(object(&[0; 41]).encode().is_err());
    }

    #[test]
    fn structured_response_parsers_reject_bad_lengths() {
        assert_eq!(
            StorageInfo::parse(&[0, 1, 0, 2, 0, 3, 0, 4, 0, 5]).unwrap(),
            StorageInfo {
                total_records: 1,
                free_records: 2,
                total_pages: 3,
                free_pages: 4,
                page_size: 5,
            }
        );
        assert!(StorageInfo::parse(&[0; 9]).is_err());
        assert_eq!(parse_object_id(&[0x12, 0x34]).unwrap(), 0x1234);
        assert!(parse_object_list(&[0; 3]).is_err());
        assert!(LogEntries::parse(&[0, 0, 0, 0, 1]).is_err());
        assert!(require_empty(&[1]).is_err());
    }
}
