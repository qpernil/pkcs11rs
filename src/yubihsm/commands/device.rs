impl Command {
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

    pub(crate) fn set_option(option: u8, value: &[u8]) -> Result<Self, Error> {
        let length = u16::try_from(value.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let mut data = vec![option];
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(value);
        Self::from_vec(CommandCode::SetOption, data)
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
        let expected_key_length = match algorithm {
            ALGORITHM_AES128_YUBICO_AUTHENTICATION => 32,
            ALGORITHM_EC_P256_YUBICO_AUTHENTICATION => 64,
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
        };
        if key.len() != expected_key_length {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let mut data = prefixed_u16(id, &[algorithm]);
        data.extend_from_slice(key);
        Self::from_vec(CommandCode::ChangeAuthenticationKey, data)
    }
}
