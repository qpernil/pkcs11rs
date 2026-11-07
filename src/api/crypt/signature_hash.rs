//! Streaming hashes for composite signature mechanisms. Device operations
//! consume a digest (or RSA DigestInfo), never the original message.
use crate::*;
use software_key_core::{digest::HashContext, post_quantum::MlDsaPrehashContext};

#[derive(Clone)]
pub(crate) enum SignatureHashContext {
    Digest(HashContext),
    MlDsa(MlDsaPrehashContext),
}

impl std::fmt::Debug for SignatureHashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignatureHashContext { .. }")
    }
}

impl SignatureHashContext {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Digest(hash) => hash.update(data),
            Self::MlDsa(hash) => hash.update(data),
        }
    }
    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Self::Digest(hash) => hash.finalize(),
            Self::MlDsa(hash) => hash.finalize(),
        }
    }
}

pub(super) fn context(mechanism: CK_MECHANISM_TYPE) -> Option<SignatureHashContext> {
    if let Some(hash) = ml_dsa_module_prehash(mechanism) {
        return Some(SignatureHashContext::MlDsa(hash.context()));
    }
    piv_hash_mechanism(mechanism).map(|hash| SignatureHashContext::Digest(HashContext::new(hash)))
}

/// Determine the normalized input size using a bounded, non-secret digest
/// placeholder. Length queries never hash the caller's message or clone state.
pub(super) fn input_length(
    mut mechanism: CK_MECHANISM_TYPE,
    message_length: usize,
) -> Result<(CK_MECHANISM_TYPE, usize), Error> {
    if let Some(hash) = ml_dsa_module_prehash(mechanism) {
        return Ok((mechanism, hash.digest_length()));
    }
    if let Some(hash) = piv_hash_mechanism(mechanism) {
        let mut digest = vec![0; hash.size()];
        normalize(&mut mechanism, &mut digest)?;
        return Ok((mechanism, digest.len()));
    }
    Ok((mechanism, message_length))
}

pub(super) fn normalize(
    mechanism: &mut CK_MECHANISM_TYPE,
    digest: &mut Vec<u8>,
) -> Result<(), Error> {
    if piv_is_hashed_rsa_pkcs(*mechanism) {
        *digest = piv_digest_info(*mechanism, digest).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        *mechanism = CKM_RSA_PKCS as _;
    } else if HASHED_RSA_PSS_MECHANISMS.contains(mechanism) {
        *mechanism = CKM_RSA_PKCS_PSS as _;
    } else if piv_is_hashed_ecdsa(*mechanism) {
        *mechanism = CKM_ECDSA as _;
    }
    Ok(())
}
