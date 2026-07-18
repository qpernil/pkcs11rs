impl Command {
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
        Self::from_vec(code, prefixed_u16(key_id, value))
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
        Self::from_vec(code, data)
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
        Self::from_vec(CommandCode::SignPss, data)
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
        Self::from_vec(CommandCode::DecryptOaep, data)
    }

    pub(crate) fn verify_hmac(key_id: u16, signature: &[u8], data: &[u8]) -> Result<Self, Error> {
        require_digest_length(signature)?;
        let mut encoded = prefixed_u16(key_id, signature);
        encoded.extend_from_slice(data);
        Self::from_vec(CommandCode::VerifyHmac, encoded)
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
        Self::from_vec(CommandCode::SignSshCertificate, data)
    }

    pub(crate) fn sign_attestation_certificate(key_id: u16, attestation_id: u16) -> Self {
        let mut data = key_id.to_be_bytes().to_vec();
        data.extend_from_slice(&attestation_id.to_be_bytes());
        Self {
            code: CommandCode::SignAttestationCertificate,
            data: Zeroizing::new(data),
        }
    }
}
