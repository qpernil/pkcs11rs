impl Command {
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
        let expected_key_length = match parameters.algorithm {
            ALGORITHM_AES128_YUBICO_OTP => 16,
            ALGORITHM_AES192_YUBICO_OTP => 24,
            ALGORITHM_AES256_YUBICO_OTP => 32,
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
        };
        match code {
            CommandCode::PutOtpAeadKey if key.len() != expected_key_length => {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            CommandCode::GenerateOtpAeadKey if !key.is_empty() => {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            _ => {}
        }
        data.extend_from_slice(key);
        Self::from_vec(code, data)
    }
}
