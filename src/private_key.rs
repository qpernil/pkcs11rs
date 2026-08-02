use crate::{pinentry, Error, CKR_ARGUMENTS_BAD};
use zeroize::Zeroizing;

pub(crate) fn decrypt_file(
    encoded: &[u8],
    pinentry: &pinentry::Pinentry,
    description: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let password = pinentry.request(pinentry::Prompt {
        title: "pkcs11rs private key",
        description,
        label: "Password:",
    })?;
    decrypt(encoded, &password)
}

pub(crate) fn decrypt(encoded: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    crate::encrypted_private_key::decrypt(encoded, password)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use pkcs8::PrivateKeyInfoRef;

    #[test]
    fn decrypts_canonical_encrypted_pkcs8() {
        let encrypted = include_bytes!("fixtures/test-rsa-private-key.der");
        let decrypted = decrypt(encrypted, b"test fixture").unwrap();
        PrivateKeyInfoRef::from_der(&decrypted).unwrap();
    }

    #[test]
    fn rejects_wrong_password_and_trailing_data() {
        let encrypted = include_bytes!("fixtures/test-rsa-private-key.der");
        assert!(decrypt(encrypted, b"wrong").is_err());
        let mut trailing = encrypted.to_vec();
        trailing.push(0);
        assert!(decrypt(&trailing, b"test fixture").is_err());
    }
}
