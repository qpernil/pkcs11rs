use crate::*;
use software_key_core::software_key_agreement::derive_with_signing_key;

pub(crate) fn software_ecdh(
    key: &SoftwarePrivateKeyMaterial,
    public_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match key {
        SoftwarePrivateKeyMaterial::Signing(key) => derive_with_signing_key(key, public_data)
            .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID)),
        SoftwarePrivateKeyMaterial::Montgomery(key) => key
            .derive(public_data)
            .map_err(|_| Error::from(CKR_ATTRIBUTE_VALUE_INVALID)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}
