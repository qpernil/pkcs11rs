use der::{Decode, Encode};
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use std::{error, fmt};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid canonical encrypted PKCS #8 private key or password")
    }
}

impl error::Error for FormatError {}

pub(crate) fn decrypt(encoded: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let encrypted = EncryptedPrivateKeyInfoRef::from_der(encoded).map_err(|_| FormatError)?;
    if encrypted.to_der().map_err(|_| FormatError)? != encoded {
        return Err(FormatError);
    }
    let decrypted = encrypted.decrypt(password).map_err(|_| FormatError)?;
    let private_key = PrivateKeyInfoRef::from_der(decrypted.as_bytes()).map_err(|_| FormatError)?;
    if private_key.to_der().map_err(|_| FormatError)? != decrypted.as_bytes() {
        return Err(FormatError);
    }
    Ok(Zeroizing::new(decrypted.as_bytes().to_vec()))
}
