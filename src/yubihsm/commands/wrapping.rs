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

impl Command {
    pub(crate) fn generate_wrap_key(parameters: &DelegatedObjectParameters) -> Result<Self, Error> {
        Self::from_vec(CommandCode::GenerateWrapKey, parameters.encode()?)
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
        if let Some(format) = format.filter(|value| *value != 0) {
            data.push(format);
        }
        Self {
            code: CommandCode::ExportWrapped,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn import_wrapped(wrapping_key_id: u16, wrapped: &[u8]) -> Result<Self, Error> {
        Self::from_vec(
            CommandCode::ImportWrapped,
            prefixed_u16(wrapping_key_id, wrapped),
        )
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
        Self::from_vec(code, data)
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
        Self::from_vec(CommandCode::PutRsaWrappedKey, data)
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
        Self::from_vec(CommandCode::ImportRsaWrapped, data)
    }
}
