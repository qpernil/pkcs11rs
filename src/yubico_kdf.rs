use crate::{Error, CKR_FUNCTION_FAILED};
use p256::SecretKey;
use sha2::Sha256;
use zeroize::Zeroizing;

const SALT: &[u8] = b"Yubico";
const ITERATIONS: usize = 10_000;
const OUTPUT_LENGTH: usize = 32;

pub(crate) fn yubico_password_kdf(
    password: &[u8],
) -> Result<Zeroizing<[u8; OUTPUT_LENGTH]>, Error> {
    let mut output = Zeroizing::new([0; OUTPUT_LENGTH]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password, SALT, ITERATIONS as u32, output.as_mut());
    Ok(output)
}

pub(crate) fn yubico_password_p256_key(password: &[u8]) -> Result<SecretKey, Error> {
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    input.extend_from_slice(password);
    input.push(0);
    for counter in 0..=u8::MAX {
        *input.last_mut().ok_or(CKR_FUNCTION_FAILED)? = counter;
        let private = yubico_password_kdf(&input)?;
        if let Ok(key) = SecretKey::from_slice(private.as_slice()) {
            return Ok(key);
        }
    }
    Err(CKR_FUNCTION_FAILED.into())
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
