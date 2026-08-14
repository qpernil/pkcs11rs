macro_rules! session_unsupported_stub {
    ($name:ident ( $($arg:ident : $typ:ty),* $(,)? )) => {
        ffi_entry_point! {
            pub fn $name(session_handle: CK_SESSION_HANDLE, $($arg: $typ),*) -> CK_RV {
                $(let _ = $arg;)*
                crate::api::general::session_function_not_supported(session_handle)
            }
        }
    };
}

macro_rules! non_session_unsupported_stub {
    ($name:ident ( $($arg:ident : $typ:ty),* $(,)? )) => {
        ffi_entry_point! {
            pub fn $name($($arg: $typ),*) -> CK_RV {
                $(let _ = $arg;)*
                CKR_FUNCTION_NOT_SUPPORTED.into()
            }
        }
    };
}

mod crypt;
mod general;
mod hsmauth;
mod interfaces;
mod kem;
mod key;
mod object;
mod security_domain;
mod session;
mod software;
mod wrap;
mod yubihsm;

pub use crypt::*;
pub use general::*;
pub use interfaces::*;
pub use kem::*;
pub use key::*;
pub use object::*;
pub use session::*;
pub use wrap::*;

#[cfg(test)]
pub(crate) use hsmauth::*;

#[cfg(feature = "abi-tests")]
pub(crate) use crypt::AES_BLOCK_LENGTH;
pub(crate) use crypt::DigestOperation;
pub(crate) use crypt::aes_gcm;
#[cfg(test)]
pub(crate) use crypt::{
    encode_pkcs1_v1_5_signature_input, parse_gcm_parameters, rsa_oaep_pad, rsa_oaep_unpad,
    rsa_pkcs1_v1_5_unpad, software_crypt_ecb_blocks,
};
#[cfg(test)]
pub(crate) use key::{
    hkdf_key_material, openpgp_generate_key_pair_parameters, x963_kdf, yubihsm_ec_algorithm,
    yubihsm_generate_key_pair_command,
};
#[cfg(test)]
pub(crate) use object::{openpgp_private_import, parse_create_object_template};
#[cfg(test)]
pub(crate) use wrap::parse_yubihsm_wrap_mechanism;
#[cfg(test)]
pub(crate) use yubihsm::{YubiHsmEnrollment, yubihsm_enroll_device};
