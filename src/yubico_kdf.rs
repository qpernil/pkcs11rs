use crate::Error;
use openssl::hash::MessageDigest;
use zeroize::Zeroizing;

const SALT: &[u8] = b"Yubico";
const ITERATIONS: usize = 10_000;
const OUTPUT_LENGTH: usize = 32;

pub(crate) fn yubico_password_kdf(
    password: &[u8],
) -> Result<Zeroizing<[u8; OUTPUT_LENGTH]>, Error> {
    let mut output = Zeroizing::new([0; OUTPUT_LENGTH]);
    openssl::pkcs5::pbkdf2_hmac(
        password,
        SALT,
        ITERATIONS,
        MessageDigest::sha256(),
        output.as_mut(),
    )?;
    Ok(output)
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
}
