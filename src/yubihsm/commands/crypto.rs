use super::protocol::*;
use crate::{CKR_DATA_LEN_RANGE, error::Error};
use zeroize::Zeroizing;

impl Command {
    pub(crate) fn derive_ecdh_kdf(
        key_id: u16,
        hash: u8,
        output_length: usize,
        public_data: &[u8],
        prefix_data: &[u8],
        shared_data: &[u8],
    ) -> Result<Self, Error> {
        let output_length = u16::try_from(output_length).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let public_length = u16::try_from(public_data.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let prefix_length = u16::try_from(prefix_data.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let shared_length = u16::try_from(shared_data.len()).map_err(|_| CKR_DATA_LEN_RANGE)?;
        let mut data = Vec::with_capacity(
            11_usize
                .saturating_add(public_data.len())
                .saturating_add(prefix_data.len())
                .saturating_add(shared_data.len()),
        );
        data.extend_from_slice(&key_id.to_be_bytes());
        data.push(hash);
        data.extend_from_slice(&output_length.to_be_bytes());
        data.extend_from_slice(&public_length.to_be_bytes());
        data.extend_from_slice(&prefix_length.to_be_bytes());
        data.extend_from_slice(&shared_length.to_be_bytes());
        data.extend_from_slice(public_data);
        data.extend_from_slice(prefix_data);
        data.extend_from_slice(shared_data);
        Self::from_vec(CommandCode::DeriveEcdhKdf, data)
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
            && !crate::is_multiple_of(value.len(), 16)
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
        if !crate::is_multiple_of(value.len(), 16) {
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
