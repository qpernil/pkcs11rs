#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectParameters<'a> {
    pub(crate) id: u16,
    pub(crate) label: &'a str,
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
        data.extend_from_slice(self.label.as_bytes());
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

impl Command {
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
        Self::from_vec(code, data)
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
        Self::from_vec(code, parameters.encode()?)
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
        Self::from_vec(code, data)
    }

    pub(crate) fn get_object(code: CommandCode, id: u16) -> Result<Self, Error> {
        ensure_code(code, &[CommandCode::GetOpaque, CommandCode::GetTemplate])?;
        Self::raw(code, &id.to_be_bytes())
    }

    pub(crate) fn list_objects(filters: &[ObjectFilter<'_>]) -> Result<Self, Error> {
        let mut data = Vec::new();
        for filter in filters {
            filter.encode(&mut data)?;
        }
        Self::from_vec(CommandCode::ListObjects, data)
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
        if let Some(object_type) = object_type
            .map(|value| value & !0x80)
            .filter(|value| *value != 3)
        {
            data.push(object_type);
        }
        Self {
            code: CommandCode::GetPublicKey,
            data: Zeroizing::new(data),
        }
    }

    pub(crate) fn delete_object(id: u16, object_type: u8) -> Self {
        Self::get_object_info(id, object_type).with_code(CommandCode::DeleteObject)
    }

    fn with_code(mut self, code: CommandCode) -> Self {
        self.code = code;
        self
    }
}
