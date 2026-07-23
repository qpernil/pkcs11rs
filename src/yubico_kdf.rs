use crate::{Error, CKR_FUNCTION_FAILED};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
};
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

pub(crate) fn yubico_password_p256_key(password: &[u8]) -> Result<EcKey<Private>, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    input.extend_from_slice(password);
    input.push(0);
    for counter in 0..=u8::MAX {
        *input.last_mut().ok_or(CKR_FUNCTION_FAILED)? = counter;
        let private = yubico_password_kdf(&input)?;
        if let Ok(key) = p256_private_key(&group, private.as_slice()) {
            return Ok(key);
        }
    }
    Err(CKR_FUNCTION_FAILED.into())
}

pub(crate) fn p256_private_key(group: &EcGroup, private: &[u8]) -> Result<EcKey<Private>, Error> {
    let private = BigNum::from_slice(private)?;
    let mut context = BigNumContext::new()?;
    let mut public = EcPoint::new(group)?;
    public.mul_generator2(group, &private, &mut context)?;
    let key = EcKey::from_private_components(group, &private, &public)?;
    key.check_key()?;
    Ok(key)
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
            key.private_key().to_vec(),
            [
                0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
                0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                0x05, 0xd2, 0xce, 0x0a,
            ]
        );
    }
}
