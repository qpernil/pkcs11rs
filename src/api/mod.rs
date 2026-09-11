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

mod crypt;
mod general;
mod hsmauth;
mod interfaces;
mod kem;
mod key;
mod object;
pub(crate) mod platform_credential;
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
#[cfg(test)]
pub(crate) use software::PKCS11RS_SoftwareExportPrivateKey;

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

/// The same Rust handlers used by the C entry points. Callers own the ABI-shaped
/// input buffers and select a module instance before invoking these operations.
/// Session routing, object policy, and mechanism execution remain in the handlers.
pub(crate) mod rust {
    pub(crate) use super::crypt::{verify, verify_init};
    pub(crate) use super::general::{get_slot_list, get_token_info};
    pub(crate) use super::hsmauth::hsmauth_authenticate;
    pub(crate) use super::key::{derive_key, generate_key_pair};
    pub(crate) use super::object::{
        copy_object, create_object, destroy_object, find_objects, find_objects_final,
        find_objects_init, get_attribute_value,
    };
    pub(crate) use super::session::{close_session, get_session_info, login, open_session};
}

/// Backend object implementations; entry points invoke the selected slot's
/// object API instead of switching on its backend kind.
pub(crate) mod native {
    pub(crate) use super::key::{
        generate_openpgp_token_pair_in_slot, generate_piv_token_pair_in_slot,
        generate_software_token_key_in_slot, generate_yubihsm_token_key_in_slot,
        generate_yubihsm_token_pair_in_slot,
    };
    pub(crate) use super::object::{
        create_openpgp_object_in_slot, create_piv_object_in_slot,
        create_preview_sign_object_in_slot, import_yubihsm_token_object_in_slot,
        store_common_data_in_slot, store_common_token_key_in_slot, store_yubihsm_data_in_slot,
        store_yubihsm_token_key_in_slot,
    };
}
