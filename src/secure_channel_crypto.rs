use crate::{CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, error::Error};
use software_key_core::{
    secure_channel::{
        SecureChannelCryptoError, pad_iso7816 as shared_pad_iso7816, scp03_kdf as shared_scp03_kdf,
        unpad_iso7816 as shared_unpad_iso7816,
    },
    software_symmetric::{
        SoftwareSymmetricError, aes_cmac as shared_aes_cmac, decrypt_aes_cbc, decrypt_aes_ecb,
        encrypt_aes_block, encrypt_aes_cbc, encrypt_aes_ecb,
    },
};

pub(crate) use software_key_core::software_symmetric::AES_BLOCK_SIZE;

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

fn map_symmetric_error(error: SoftwareSymmetricError) -> Error {
    match error {
        SoftwareSymmetricError::InvalidKeyLength | SoftwareSymmetricError::InvalidIvLength => {
            CKR_ARGUMENTS_BAD.into()
        }
        SoftwareSymmetricError::InvalidDataLength => CKR_DATA_LEN_RANGE.into(),
        SoftwareSymmetricError::AuthenticationFailed => CKR_ENCRYPTED_DATA_INVALID.into(),
    }
}

fn map_secure_channel_error(error: SecureChannelCryptoError) -> Error {
    match error {
        SecureChannelCryptoError::InvalidDataLength
        | SecureChannelCryptoError::KeyDerivationFailed => CKR_ARGUMENTS_BAD.into(),
        SecureChannelCryptoError::InvalidPadding => CKR_ENCRYPTED_DATA_INVALID.into(),
        SecureChannelCryptoError::OutputTooLong => CKR_DATA_LEN_RANGE.into(),
        SecureChannelCryptoError::Symmetric(error) => map_symmetric_error(error),
    }
}

pub(crate) fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    shared_aes_cmac(key, data).map_err(map_symmetric_error)
}

pub(crate) fn aes_encrypt_block(
    key: &[u8],
    block: &[u8; AES_BLOCK_SIZE],
) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    encrypt_aes_block(key, block).map_err(map_symmetric_error)
}

pub(crate) fn aes_ecb(key: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, Error> {
    match direction {
        Direction::Encrypt => encrypt_aes_ecb(key, data),
        Direction::Decrypt => decrypt_aes_ecb(key, data),
    }
    .map_err(map_symmetric_error)
}

pub(crate) fn aes_cbc(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    match direction {
        Direction::Encrypt => encrypt_aes_cbc(key, iv, data),
        Direction::Decrypt => decrypt_aes_cbc(key, iv, data),
    }
    .map_err(map_symmetric_error)
}

pub(crate) fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    shared_pad_iso7816(data)
}

pub(crate) fn unpad_iso7816(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    shared_unpad_iso7816(data).map_err(map_secure_channel_error)
}

pub(crate) fn scp03_kdf(
    key: &[u8],
    constant: u8,
    context: &[u8],
    output_bits: u16,
) -> Result<Vec<u8>, Error> {
    shared_scp03_kdf(key, constant, context, output_bits).map_err(map_secure_channel_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .split_whitespace()
            .flat_map(|word| {
                (0..word.len())
                    .step_by(2)
                    .map(|offset| u8::from_str_radix(&word[offset..offset + 2], 16).unwrap())
            })
            .collect()
    }

    #[test]
    fn shared_aes_primitives_match_nist_vectors() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            aes_cmac(&key, &plaintext).unwrap().as_slice(),
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
        assert_eq!(
            aes_encrypt_block(&key, plaintext.as_slice().try_into().unwrap()).unwrap(),
            hex("3ad77bb40d7a3660a89ecaf32466ef97").as_slice()
        );
        assert_eq!(
            aes_cbc(
                &key,
                &hex("000102030405060708090a0b0c0d0e0f"),
                &plaintext,
                Direction::Encrypt,
            )
            .unwrap(),
            hex("7649abac8119b246cee98e9b12e9197d")
        );
    }

    #[test]
    fn shared_padding_and_kdf_match_secure_channel_layouts() {
        let plaintext = b"secure channel";
        assert_eq!(unpad_iso7816(pad_iso7816(plaintext)).unwrap(), plaintext);
        assert!(unpad_iso7816(vec![0; AES_BLOCK_SIZE]).is_err());

        assert_eq!(
            scp03_kdf(
                &hex("404142434445464748494a4b4c4d4e4f"),
                0x04,
                &hex("0102030405060708 1112131415161718"),
                128,
            )
            .unwrap(),
            hex("d99675d4a95c58de629225730cddb758")
        );
    }
}
