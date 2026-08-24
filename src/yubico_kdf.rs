use crate::{CKR_FUNCTION_FAILED, Error};
use p256::SecretKey;
use software_key_core::secure_channel::{
    yubico_password_kdf as shared_yubico_password_kdf,
    yubico_password_p256_key as shared_yubico_password_p256_key,
};
use zeroize::Zeroizing;

const OUTPUT_LENGTH: usize = 32;

pub(crate) fn yubico_password_kdf(
    password: &[u8],
) -> Result<Zeroizing<[u8; OUTPUT_LENGTH]>, Error> {
    Ok(shared_yubico_password_kdf(password))
}

pub(crate) fn yubico_password_p256_key(password: &[u8]) -> Result<SecretKey, Error> {
    shared_yubico_password_p256_key(password).map_err(|_| CKR_FUNCTION_FAILED.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_yubico_default_password_key_material() {
        assert_eq!(
            yubico_password_kdf(b"password").unwrap().as_slice(),
            [
                0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
                0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                0x05, 0xd2, 0xce, 0x0a,
            ]
        );
    }

    #[test]
    fn derives_a_stable_p256_key_from_the_yubico_default_password() {
        let key = yubico_password_p256_key(b"password").unwrap();
        assert_eq!(
            &key.to_bytes()[..],
            [
                0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
                0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                0x05, 0xd2, 0xce, 0x0a,
            ]
        );
    }
}
