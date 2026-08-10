mod digest;
mod encrypt;
mod shared;
mod sign;
mod verify;

pub(crate) use digest::DigestOperation;
pub use digest::{C_Digest, C_DigestFinal, C_DigestInit, C_DigestKey, C_DigestUpdate};
#[cfg(feature = "abi-tests")]
pub(crate) use encrypt::AES_BLOCK_LENGTH;
pub(crate) use encrypt::aes_gcm;
#[cfg(test)]
pub(crate) use encrypt::parse_gcm_parameters;
pub use encrypt::{
    C_Decrypt, C_DecryptFinal, C_DecryptInit, C_DecryptUpdate, C_Encrypt, C_EncryptFinal,
    C_EncryptInit, C_EncryptUpdate,
};
pub(crate) use encrypt::{
    aes_key_wrap_transform, aes_kwp_transform, parse_key_wrap_iv, software_crypt_ecb_blocks,
};
#[cfg(test)]
pub(crate) use shared::encode_pkcs1_v1_5_signature_input;
pub use shared::{
    C_DecryptDigestUpdate, C_DecryptVerifyUpdate, C_DigestEncryptUpdate, C_SignEncryptUpdate,
};
pub(crate) use shared::{
    RsaOaepParameters, parse_rsa_oaep_parameters, rsa_oaep_pad, rsa_oaep_unpad,
    rsa_pkcs1_v1_5_unpad, yubihsm_ec_coordinate_length,
};
pub use sign::{C_Sign, C_SignFinal, C_SignInit, C_SignRecover, C_SignRecoverInit, C_SignUpdate};
pub use verify::{
    C_Verify, C_VerifyFinal, C_VerifyInit, C_VerifyRecover, C_VerifyRecoverInit, C_VerifyUpdate,
};
