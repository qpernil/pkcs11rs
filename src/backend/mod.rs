mod ccid;
mod crypto;
mod ctap;
mod openpgp;
mod piv;
mod traits;
mod yubihsm;

pub(crate) use ccid::{
    ccid_application_aid, ccid_application_label, configured_ccid_configurations,
    configured_issuer_security_domain_aid, CcidApplication, HsmAuthSlot, IssuerSecurityDomainSlot,
    SecureChannelProtocol,
};
pub(crate) use crypto::{
    digest_for_hash_mechanism, ec_curve_from_parameters, ec_parameters, ecdsa_der_to_raw,
    encode_rsa_pss, mgf1, mgf_digest, openpgp_ec_coordinate_length, openpgp_ec_params,
    openpgp_sign_mechanism_supported, openpgp_signature, piv_digest_info, piv_hash_mechanism,
    piv_is_hashed_ecdsa, piv_is_hashed_rsa_pkcs, piv_is_pss_mechanism, pss_hash_mechanism,
    rsa_pkcs1_encrypt, rsa_pkcs1_recover, rsa_pkcs1_sign, rsa_public_operation,
    validate_ec_public_point, verify_ecdsa, verify_ed25519, verify_rsa_pss, EcCurve,
};
#[cfg(all(test, feature = "mock-yubikey"))]
pub(crate) use ctap::CcidCtapTransport;
pub(crate) use ctap::{project_cose_public_key, Fido2Slot, HidFidoEndpoint};
pub(crate) use openpgp::{openpgp_signature_requires_context_specific_login, OpenPgpSlot};
pub(crate) use piv::{
    piv_algorithm_from_certificate, piv_ec_coordinate_length, piv_ec_parameters,
    piv_effective_pin_policy, piv_policy_requires_login, piv_public_key_from_certificate,
    piv_sign_mechanism_supported, piv_slot_label, PivPublicKey, PivSlot,
};
pub(crate) use traits::{apply_device_versions, session_state, BackendSession, Slot, SlotKind};
pub(crate) use yubihsm::{
    send_yubihsm_secure_command, HsmAuthProvider, HsmAuthProviderRegistry,
    YubiHsmPublicDiscoveryConfig, YubiHsmSessionState, YubiHsmSlot,
};

#[cfg(any(test, feature = "abi-tests"))]
pub(crate) use yubihsm::configured_yubihsm_public_discovery_credential;
#[cfg(not(feature = "abi-tests"))]
pub(crate) use yubihsm::{
    configured_yubihsm_public_discovery_credential_with_pinentry, YUBIHSM_DISCOVERY_ENV,
};
#[cfg(test)]
pub(crate) use yubihsm::{YubiHsmDiscoveryCache, YubiHsmObjectKey};

#[cfg(test)]
pub(crate) use ccid::{
    default_ccid_applications, hsmauth_token_objects, issuer_security_domain_token_objects,
    parse_ccid_application, parse_ccid_application_list, parse_secure_channel, PcscAppletSession,
};
#[cfg(test)]
pub(crate) use crypto::{ec_multiply, rsa_private_operation, EcPointValue};
#[cfg(test)]
pub(crate) use openpgp::{
    openpgp_key_generation_mechanism, openpgp_private_key_template, openpgp_touch_policy,
    OpenPgpCertificate, OpenPgpSession,
};
#[cfg(test)]
pub(crate) use traits::profile_token_objects;
#[cfg(test)]
pub(crate) use yubihsm::{
    parse_hsmauth_username, parse_yubihsm_login_username, parse_yubihsm_pkcs11_metadata,
    split_yubihsm_login, yubihsm_object_has_public_key, yubihsm_object_label,
    yubihsm_token_objects_with_generation, YubiHsmLoginUsername, YubiHsmPkcs11Metadata,
    YubiHsmSessionRole,
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
