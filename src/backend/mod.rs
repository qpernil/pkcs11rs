mod ccid;
#[cfg(not(target_os = "ios"))]
#[path = "pcsc.rs"]
mod ccid_provider;
mod crypto;
mod ctap;
mod openpgp;
mod piv;
mod software;
mod traits;
mod yubihsm;

#[cfg(target_os = "ios")]
pub(crate) use crate::apple::cryptotokenkit::{CcidProvider, CcidReader};
pub(crate) use ccid::{
    CcidApplication, CcidConfiguration, HsmAuthSlot, IssuerSecurityDomainSlot,
    SecureChannelProtocol, ccid_application_label, default_ccid_applications,
    parse_ccid_application, parse_ccid_application_list, parse_secure_channel,
};
#[cfg(not(target_os = "ios"))]
pub(crate) use ccid_provider::{CcidProvider, CcidReader};
pub(crate) use crypto::{
    digest_for_hash_mechanism, ec_curve_from_parameters, ec_curve_parameters, ec_parameters,
    ecdsa_der_to_raw, encode_rsa_pss, openpgp_ec_coordinate_length, openpgp_ec_params,
    openpgp_sign_mechanism_supported, openpgp_signature, piv_digest_info, piv_hash_mechanism,
    piv_is_hashed_ecdsa, piv_is_hashed_rsa_pkcs, piv_is_pss_mechanism, pss_hash_mechanism,
    rsa_pkcs1_encrypt, rsa_private_operation, rsa_public_operation, shared_rsa_hash_algorithm,
    shared_rsa_pss_parameters, validate_ec_public_point, verify_ecdsa, verify_ed25519,
};
#[cfg(test)]
pub(crate) use crypto::{mgf_digest, rsa_pkcs1_sign, verify_rsa_pss};
#[cfg(all(test, feature = "mock-yubikey"))]
pub(crate) use ctap::CcidCtapTransport;
#[cfg(feature = "native-hardware")]
pub(crate) use ctap::HidFidoEndpoint;
pub(crate) use ctap::{Fido2Slot, SwitchableFidoEndpoint, project_cose_public_key};
pub(crate) use openpgp::{OpenPgpSlot, openpgp_signature_requires_context_specific_login};
pub(crate) use piv::{
    PivPublicKey, PivSlot, piv_algorithm_from_certificate, piv_ec_parameters,
    piv_effective_pin_policy, piv_policy_requires_login, piv_public_key_from_certificate,
    piv_sign_mechanism_supported, piv_slot_label,
};
pub(crate) use software::SoftwareSlot;
pub(crate) use traits::{BackendSession, Slot, SlotKind, apply_device_versions, session_state};
pub(crate) use yubihsm::{
    HsmAuthProvider, HsmAuthProviderRegistry, YubiHsmPublicDiscoveryConfig, YubiHsmSessionState,
    YubiHsmSlot, send_yubihsm_secure_command,
};

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) use yubihsm::configured_yubihsm_public_discovery_credential;
#[cfg(any(test, not(feature = "abi-tests")))]
pub(crate) use yubihsm::configured_yubihsm_public_discovery_credential_with_pinentry;
#[cfg(test)]
pub(crate) use yubihsm::{YubiHsmDiscoveryCache, YubiHsmObjectKey};

#[cfg(test)]
pub(crate) use ccid::{
    PcscAppletSession, hsmauth_token_objects, issuer_security_domain_token_objects,
};
#[cfg(test)]
pub(crate) use crypto::{EcPointValue, ec_multiply};
#[cfg(test)]
pub(crate) use openpgp::{
    OpenPgpCertificate, OpenPgpSession, openpgp_key_generation_mechanism,
    openpgp_private_key_template, openpgp_touch_policy,
};
#[cfg(test)]
pub(crate) use traits::profile_token_objects;
#[cfg(test)]
pub(crate) use yubihsm::{
    HsmAuthWildcardLogin, YubiHsmLoginUsername, YubiHsmPkcs11Metadata, YubiHsmSessionRole,
    parse_hsmauth_username, parse_yubihsm_login_username, parse_yubihsm_pkcs11_metadata,
    split_yubihsm_login, yubihsm_object_has_public_key, yubihsm_object_label,
    yubihsm_token_objects_with_generation,
};

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) use ccid::IssuerSecurityDomainSession;
#[cfg(test)]
pub(crate) use piv::piv_object_fingerprint;
#[cfg(test)]
pub(crate) use piv::{PivDataObject, PivKey};
#[cfg(feature = "abi-tests")]
pub(crate) use yubihsm::yubihsm_abi_public_projection_metadata;
#[cfg(any(test, feature = "abi-tests"))]
pub(crate) use yubihsm::yubihsm_token_objects;
