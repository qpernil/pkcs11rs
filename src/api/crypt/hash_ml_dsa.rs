//! PKCS #11 HashML-DSA parameters. The shared core owns FIPS 204 encoding.
use crate::*;
use software_key_core::post_quantum::{
    MlDsaParameterSet, MlDsaPrehash, MlDsaRandomization, verify_ml_dsa_prehash,
};

pub(super) fn parameters(
    mechanism: &CK_MECHANISM,
    verifying: bool,
) -> Result<MlDsaSignatureParameters, Error> {
    if let Some(hash) = ml_dsa_module_prehash(mechanism.mechanism) {
        let mut parameters = super::sign::ml_dsa_context_parameters(mechanism, verifying)?;
        parameters.prehash = Some(hash);
        return Ok(parameters);
    }
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize
            != std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let p = unsafe {
        _as_ref(
            mechanism
                .pParameter
                .cast::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(),
        )
    }?;
    let id = match p.hash {
        x if x == CKM_SHA224 as CK_MECHANISM_TYPE => 4,
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => 1,
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => 2,
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => 3,
        x if x == CKM_SHA3_224 as CK_MECHANISM_TYPE => 7,
        x if x == CKM_SHA3_256 as CK_MECHANISM_TYPE => 8,
        x if x == CKM_SHA3_384 as CK_MECHANISM_TYPE => 9,
        x if x == CKM_SHA3_512 as CK_MECHANISM_TYPE => 10,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    // Reuse the pure mechanism's context and hedge validation.
    let mut context = CK_SIGN_ADDITIONAL_CONTEXT {
        hedgeVariant: if verifying {
            CKH_HEDGE_PREFERRED as _
        } else {
            p.hedgeVariant
        },
        pContext: p.pContext,
        ulContextLen: p.ulContextLen,
    };
    let pure = CK_MECHANISM {
        mechanism: CKM_ML_DSA as _,
        pParameter: (&mut context as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast(),
        ulParameterLen: std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() as _,
    };
    let mut parameters = super::sign::ml_dsa_context_parameters(&pure, verifying)?;
    parameters.prehash = MlDsaPrehash::from_id(id);
    Ok(parameters)
}

pub(super) fn sign(
    key: &software_key_core::post_quantum::MlDsaPrivateKey,
    parameters: &MlDsaSignatureParameters,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let hash = parameters.prehash.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    if data.len() != hash.digest_length() {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mode = match parameters.hedge_variant {
        x if x == CKH_DETERMINISTIC_REQUIRED as CK_HEDGE_TYPE => MlDsaRandomization::Deterministic,
        x if x == CKH_HEDGE_REQUIRED as CK_HEDGE_TYPE => MlDsaRandomization::Randomized,
        _ => MlDsaRandomization::HedgePreferred,
    };
    key.sign_prehash(data, &parameters.context, hash, mode)
        .map_err(|error| match error {
            software_key_core::post_quantum::MlDsaError::RandomnessUnavailable => {
                CKR_RANDOM_NO_RNG.into()
            }
            _ => CKR_FUNCTION_FAILED.into(),
        })
}

pub(super) fn verify(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    parameters: &MlDsaSignatureParameters,
    data: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let hash = parameters.prehash.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    if data.len() != hash.digest_length() {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    verify_ml_dsa_prehash(
        parameter_set,
        public_key,
        data,
        &parameters.context,
        signature,
        hash,
    )
    .map_err(|_| CKR_SIGNATURE_INVALID.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_hash_ml_dsa_uses_optional_context_parameters() {
        for mechanism_type in HASH_ML_DSA_MECHANISMS {
            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            let parsed = parameters(&mechanism, false).unwrap();
            assert!(parsed.context.is_empty());
            assert_eq!(parsed.hedge_variant, CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE);
            assert!(parsed.prehash.is_some());
            let mut context = [0; 256];
            let mut additional = CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: CK_ULONG::MAX,
                pContext: context.as_mut_ptr(),
                ulContextLen: 255,
            };
            mechanism.pParameter = (&mut additional as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast();
            mechanism.ulParameterLen = std::mem::size_of_val(&additional) as _;
            assert!(parameters(&mechanism, false).is_err());
            assert_eq!(parameters(&mechanism, true).unwrap().context.len(), 255);
            additional.ulContextLen = 256;
            assert_eq!(additional.ulContextLen, 256);
            assert!(parameters(&mechanism, true).is_err());
            // Generic prehash parameters have a different layout.
            mechanism.ulParameterLen = std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>() as _;
            assert!(parameters(&mechanism, true).is_err());
        }
    }

    #[test]
    fn hash_ml_dsa_parameters_require_hash_and_bound_context() {
        let mut context = [0x61; 256];
        let mut additional = CK_HASH_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED as _,
            pContext: context.as_mut_ptr(),
            ulContextLen: 0,
            hash: CKM_SHA256 as _,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_HASH_ML_DSA as _,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert!(parameters(&mechanism, false).is_err());
        mechanism.pParameter = (&mut additional as *mut CK_HASH_SIGN_ADDITIONAL_CONTEXT).cast();
        mechanism.ulParameterLen = std::mem::size_of_val(&additional) as _;
        for length in [0, 255] {
            additional.ulContextLen = length;
            assert_eq!(additional.ulContextLen, length);
            assert_eq!(
                parameters(&mechanism, false).unwrap().context.len(),
                length as usize
            );
        }
        additional.ulContextLen = 256;
        assert_eq!(additional.ulContextLen, 256);
        assert!(parameters(&mechanism, false).is_err());
        additional.ulContextLen = 0;
        additional.pContext = std::ptr::null_mut();
        assert!(additional.pContext.is_null());
        assert!(parameters(&mechanism, false).unwrap().context.is_empty());
        additional.hedgeVariant = CK_ULONG::MAX;
        assert_eq!(additional.hedgeVariant, CK_ULONG::MAX);
        assert!(parameters(&mechanism, false).is_err());
        assert!(parameters(&mechanism, true).is_ok());
        mechanism.ulParameterLen -= 1;
        assert!(parameters(&mechanism, true).is_err());
    }
}
