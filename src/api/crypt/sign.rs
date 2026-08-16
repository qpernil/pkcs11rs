use super::{
    encrypt::{
        aes_gcm, parse_gcm_parameters, software_crypt_ecb_blocks, yubihsm_encrypt_ecb_blocks,
    },
    shared::{
        encode_pkcs1_v1_5_signature_input, yubihsm_ec_coordinate_length, yubihsm_ecdsa_signature,
    },
};
use crate::*;
use virtual_yubikey_crypto::{
    post_quantum::{MlDsaError, MlDsaParameterSet, MlDsaPrivateKey, MlDsaRandomization},
    software_signing::{
        SoftwareSigningAlgorithm as SharedSigningAlgorithm, SoftwareSigningKey as SharedSigningKey,
    },
};

const AES_CMAC_LENGTH: usize = 16;

fn yubihsm_mgf1_algorithm(hash: CK_MECHANISM_TYPE) -> Result<u8, Error> {
    match hash {
        x if x == CKM_SHA_1 as CK_MECHANISM_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA1),
        x if x == CKM_SHA256 as CK_MECHANISM_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA256),
        x if x == CKM_SHA384 as CK_MECHANISM_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA384),
        x if x == CKM_SHA512 as CK_MECHANISM_TYPE => Ok(YUBIHSM_ALGO_MGF1_SHA512),
        _ => Err(CKR_MECHANISM_INVALID.into()),
    }
}

fn yubihsm_asymmetric_signature_command(
    mechanism: CK_MECHANISM_TYPE,
    pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    key_id: u16,
    data: &[u8],
) -> Result<YubiHsmCommand, Error> {
    let digest = piv_hash_mechanism(mechanism)
        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
        .transpose()?;
    if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE || piv_is_hashed_rsa_pkcs(mechanism) {
        let input = if piv_is_hashed_rsa_pkcs(mechanism) {
            piv_digest_info(
                mechanism,
                digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
            )
            .ok_or(CKR_MECHANISM_PARAM_INVALID)?
        } else {
            data.to_vec()
        };
        YubiHsmCommand::key_data(YubiHsmCommandCode::SignPkcs1, key_id, &input)
    } else if piv_is_pss_mechanism(mechanism) {
        let (mgf, salt_length, hash_mechanism) = pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        let mgf = if mgf == 0 {
            yubihsm_mgf1_algorithm(hash_mechanism)?
        } else {
            mgf
        };
        YubiHsmCommand::sign_pss(key_id, mgf, salt_length, digest.as_deref().unwrap_or(data))
    } else if mechanism == CKM_EDDSA as CK_MECHANISM_TYPE {
        YubiHsmCommand::key_data(YubiHsmCommandCode::SignEddsa, key_id, data)
    } else {
        YubiHsmCommand::key_data(
            YubiHsmCommandCode::SignEcdsa,
            key_id,
            digest.as_deref().unwrap_or(data),
        )
    }
}

fn software_sign_mechanism_supported(
    key: &SoftwarePrivateKeyMaterial,
    mechanism: CK_MECHANISM_TYPE,
) -> bool {
    match key {
        SoftwarePrivateKeyMaterial::Rsa(_) => {
            mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                || mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                || piv_is_hashed_rsa_pkcs(mechanism)
                || piv_is_pss_mechanism(mechanism)
        }
        SoftwarePrivateKeyMaterial::Ed25519(_) => mechanism == CKM_EDDSA as CK_MECHANISM_TYPE,
        SoftwarePrivateKeyMaterial::X25519(_) => false,
        SoftwarePrivateKeyMaterial::MlDsa44(_)
        | SoftwarePrivateKeyMaterial::MlDsa65(_)
        | SoftwarePrivateKeyMaterial::MlDsa87(_) => mechanism == CKM_ML_DSA as CK_MECHANISM_TYPE,
        _ => mechanism == CKM_ECDSA as CK_MECHANISM_TYPE || piv_is_hashed_ecdsa(mechanism),
    }
}

fn software_signature_length(key: &SoftwarePrivateKeyMaterial) -> Result<usize, Error> {
    match key {
        SoftwarePrivateKeyMaterial::Rsa(key) => Ok(key.size()),
        SoftwarePrivateKeyMaterial::Ed25519(_) => Ok(64),
        SoftwarePrivateKeyMaterial::X25519(_) => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        SoftwarePrivateKeyMaterial::MlDsa44(_) => Ok(2420),
        SoftwarePrivateKeyMaterial::MlDsa65(_) => Ok(3309),
        SoftwarePrivateKeyMaterial::MlDsa87(_) => Ok(4627),
        _ => Ok(
            ec_parameters(key.weierstrass_curve().ok_or(CKR_KEY_TYPE_INCONSISTENT)?)?
                .coordinate_length
                * 2,
        ),
    }
}

fn software_sign(
    key: &SoftwarePrivateKeyMaterial,
    mechanism: CK_MECHANISM_TYPE,
    pss: Option<(u8, u16, CK_MECHANISM_TYPE)>,
    ml_dsa: Option<&MlDsaSignatureParameters>,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    macro_rules! sign_ecdsa {
        ($key:expr, $curve:ty, $signature:ty) => {{
            let digest = piv_hash_mechanism(mechanism)
                .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                .transpose()?
                .unwrap_or_else(|| data.to_vec());
            let signing_key = ecdsa::SigningKey::<$curve>::from($key.clone());
            let signature: $signature =
                signature::hazmat::PrehashSigner::sign_prehash(&signing_key, &digest)
                    .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
            Ok(signature.to_bytes().to_vec())
        }};
    }
    fn shared_prehash(
        algorithm: SharedSigningAlgorithm,
        serialized: &[u8],
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = SharedSigningKey::from_serialized(algorithm, serialized)
            .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
        key.sign_prehash(algorithm, digest)
            .map(|signature| signature.into_bytes())
            .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))
    }
    let digest = || {
        piv_hash_mechanism(mechanism)
            .map(|digest| hash(digest, data).map(|value| value.to_vec()))
            .transpose()
            .map(|digest| digest.unwrap_or_else(|| data.to_vec()))
    };
    match key {
        SoftwarePrivateKeyMaterial::Rsa(key) => {
            let digest = piv_hash_mechanism(mechanism)
                .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                .transpose()?;
            if piv_is_pss_mechanism(mechanism) {
                let (mgf, salt_length, hash_mechanism) = pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                let digest = digest.as_deref().unwrap_or(data);
                let encoded = encode_rsa_pss(
                    digest,
                    key.size(),
                    hash_mechanism,
                    mgf,
                    salt_length as usize,
                )?;
                rsa_private_operation(key, &encoded)
            } else if piv_is_hashed_rsa_pkcs(mechanism) {
                let digest = digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                let digest_info =
                    piv_digest_info(mechanism, digest).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                rsa_pkcs1_sign(key, &digest_info)
            } else if mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                rsa_pkcs1_sign(key, data)
            } else if mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                if data.len() > key.size() {
                    return Err(CKR_DATA_LEN_RANGE.into());
                }
                let mut encoded = vec![0; key.size() - data.len()];
                encoded.extend_from_slice(data);
                rsa_private_operation(key, &encoded)
            } else {
                Err(CKR_MECHANISM_INVALID.into())
            }
        }
        SoftwarePrivateKeyMaterial::P224(key) => {
            sign_ecdsa!(key, p224::NistP224, p224::ecdsa::Signature)
        }
        SoftwarePrivateKeyMaterial::P256(key) => shared_prehash(
            SharedSigningAlgorithm::EcdsaP256Sha256,
            key.to_bytes().as_ref(),
            &digest()?,
        ),
        SoftwarePrivateKeyMaterial::P384(key) => shared_prehash(
            SharedSigningAlgorithm::EcdsaP384Sha384,
            key.to_bytes().as_ref(),
            &digest()?,
        ),
        SoftwarePrivateKeyMaterial::P521(key) => shared_prehash(
            SharedSigningAlgorithm::EcdsaP521Sha512,
            key.to_bytes().as_ref(),
            &digest()?,
        ),
        SoftwarePrivateKeyMaterial::K256(key) => shared_prehash(
            SharedSigningAlgorithm::EcdsaSecp256k1Sha256,
            key.to_bytes().as_ref(),
            &digest()?,
        ),
        SoftwarePrivateKeyMaterial::BrainpoolP256(key) => {
            sign_ecdsa!(
                key,
                bp256::BrainpoolP256r1,
                ecdsa::Signature<bp256::BrainpoolP256r1>
            )
        }
        SoftwarePrivateKeyMaterial::BrainpoolP384(key) => {
            sign_ecdsa!(
                key,
                bp384::BrainpoolP384r1,
                ecdsa::Signature<bp384::BrainpoolP384r1>
            )
        }
        SoftwarePrivateKeyMaterial::BrainpoolP512(key) => {
            sign_ecdsa!(
                key,
                crate::brainpool512::BrainpoolP512r1,
                crate::brainpool512::Signature
            )
        }
        SoftwarePrivateKeyMaterial::Ed25519(key) => {
            let algorithm = SharedSigningAlgorithm::Ed25519;
            let key = SharedSigningKey::from_serialized(algorithm, &key.to_bytes())
                .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
            key.sign_message(algorithm, data)
                .map(|signature| signature.into_bytes())
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))
        }
        SoftwarePrivateKeyMaterial::X25519(_) => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        SoftwarePrivateKeyMaterial::MlDsa44(_)
        | SoftwarePrivateKeyMaterial::MlDsa65(_)
        | SoftwarePrivateKeyMaterial::MlDsa87(_) => shared_ml_dsa_sign(key, ml_dsa, data),
        SoftwarePrivateKeyMaterial::MlKem512(_)
        | SoftwarePrivateKeyMaterial::MlKem768(_)
        | SoftwarePrivateKeyMaterial::MlKem1024(_) => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn shared_ml_dsa_sign(
    key: &SoftwarePrivateKeyMaterial,
    parameters: Option<&MlDsaSignatureParameters>,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let (parameter_set, seed) = match key {
        SoftwarePrivateKeyMaterial::MlDsa44(key) => {
            (MlDsaParameterSet::MlDsa44, key.as_seed().to_vec())
        }
        SoftwarePrivateKeyMaterial::MlDsa65(key) => {
            (MlDsaParameterSet::MlDsa65, key.as_seed().to_vec())
        }
        SoftwarePrivateKeyMaterial::MlDsa87(key) => {
            (MlDsaParameterSet::MlDsa87, key.as_seed().to_vec())
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    let parameters = parameters.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    let randomization = match parameters.hedge_variant {
        x if x == CKH_DETERMINISTIC_REQUIRED as CK_HEDGE_TYPE => MlDsaRandomization::Deterministic,
        x if x == CKH_HEDGE_REQUIRED as CK_HEDGE_TYPE => MlDsaRandomization::Randomized,
        x if x == CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE => MlDsaRandomization::HedgePreferred,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };
    MlDsaPrivateKey::from_seed_slice(parameter_set, &seed)
        .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?
        .sign(data, &parameters.context, randomization)
        .map_err(|error| match error {
            MlDsaError::RandomnessUnavailable => Error::from(CKR_RANDOM_NO_RNG),
            MlDsaError::InvalidContext => Error::from(CKR_MECHANISM_PARAM_INVALID),
            MlDsaError::InvalidSeedLength => Error::from(CKR_KEY_TYPE_INCONSISTENT),
            MlDsaError::InvalidPublicKey
            | MlDsaError::InvalidSignature
            | MlDsaError::SigningFailed => Error::from(CKR_FUNCTION_FAILED),
        })
}

#[cfg(test)]
fn ml_dsa_sign_with_randomizer<P: ml_dsa::MlDsaParams>(
    key: &ml_dsa::SigningKey<P>,
    parameters: Option<&MlDsaSignatureParameters>,
    data: &[u8],
    randomized: impl FnOnce(&ml_dsa::ExpandedSigningKey<P>, &[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let parameters = parameters.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    let expanded = key.expanded_key();
    let deterministic = || {
        expanded
            .sign_deterministic(data, &parameters.context)
            .map(|signature| signature.encode().to_vec())
            .map_err(|_| Error::from(CKR_FUNCTION_FAILED))
    };
    match parameters.hedge_variant {
        x if x == CKH_DETERMINISTIC_REQUIRED as CK_HEDGE_TYPE => deterministic(),
        x if x == CKH_HEDGE_REQUIRED as CK_HEDGE_TYPE => {
            randomized(expanded, data, &parameters.context)
        }
        x if x == CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE => {
            randomized(expanded, data, &parameters.context).or_else(|_| deterministic())
        }
        _ => Err(CKR_MECHANISM_PARAM_INVALID.into()),
    }
}

pub(super) fn ml_dsa_parameters(
    mechanism: &CK_MECHANISM,
) -> Result<Option<MlDsaSignatureParameters>, Error> {
    if mechanism.mechanism != CKM_ML_DSA as CK_MECHANISM_TYPE {
        return Ok(None);
    }
    if mechanism.pParameter.is_null() && mechanism.ulParameterLen == 0 {
        return Ok(Some(MlDsaSignatureParameters {
            hedge_variant: CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE,
            context: Vec::new(),
        }));
    }
    if mechanism.pParameter.is_null()
        || mechanism.ulParameterLen as usize != std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>()
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe {
        _as_ref(mechanism.pParameter.cast::<CK_SIGN_ADDITIONAL_CONTEXT>())
            .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?
    };
    if !matches!(
        parameters.hedgeVariant,
        x if x == CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE
            || x == CKH_HEDGE_REQUIRED as CK_HEDGE_TYPE
            || x == CKH_DETERMINISTIC_REQUIRED as CK_HEDGE_TYPE
    ) || parameters.ulContextLen > 255
        || (parameters.pContext.is_null() && parameters.ulContextLen != 0)
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let context = unsafe {
        from_raw_parts(parameters.pContext, parameters.ulContextLen as usize)
            .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?
            .to_vec()
    };
    Ok(Some(MlDsaSignatureParameters {
        hedge_variant: parameters.hedgeVariant,
        context,
    }))
}

pub(crate) fn hmac_key_type_and_length(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<(CK_KEY_TYPE, usize)> {
    match mechanism {
        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA_1_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA_1_HMAC as CK_KEY_TYPE, 20))
        }
        x if x == CKM_SHA224_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA224_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA224_HMAC as CK_KEY_TYPE, 28))
        }
        x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA256_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA256_HMAC as CK_KEY_TYPE, 32))
        }
        x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA384_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA384_HMAC as CK_KEY_TYPE, 48))
        }
        x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA512_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            Some((CKK_SHA512_HMAC as CK_KEY_TYPE, 64))
        }
        _ => None,
    }
}

pub(crate) fn hmac_output_length(mechanism: &CK_MECHANISM) -> Result<Option<usize>, Error> {
    let Some((_, full_length)) = hmac_key_type_and_length(mechanism.mechanism) else {
        return Ok(None);
    };
    let general = matches!(
        mechanism.mechanism,
        x if x == CKM_SHA_1_HMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_SHA224_HMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_SHA256_HMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_SHA384_HMAC_GENERAL as CK_MECHANISM_TYPE
            || x == CKM_SHA512_HMAC_GENERAL as CK_MECHANISM_TYPE
    );
    if !general {
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        return Ok(Some(full_length));
    }
    if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_ULONG>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let length = *unsafe { _as_ref(mechanism.pParameter.cast::<CK_ULONG>()) }
        .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))? as usize;
    if length > full_length {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(Some(length))
}

pub(crate) fn software_hmac(
    key: &[u8],
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    macro_rules! calculate {
        ($digest:ty) => {{
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<$digest> as hmac::digest::KeyInit>::new_from_slice(key)
                .map_err(|_| Error::from(CKR_KEY_SIZE_RANGE))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match mechanism {
        x if x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA_1_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            calculate!(sha1::Sha1)
        }
        x if x == CKM_SHA224_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA224_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            calculate!(sha2::Sha224)
        }
        x if x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA256_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            calculate!(sha2::Sha256)
        }
        x if x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA384_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            calculate!(sha2::Sha384)
        }
        x if x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
            || x == CKM_SHA512_HMAC_GENERAL as CK_MECHANISM_TYPE =>
        {
            calculate!(sha2::Sha512)
        }
        _ => Err(CKR_MECHANISM_INVALID.into()),
    }
}

pub(crate) fn aes_cmac_length(mechanism: &CK_MECHANISM) -> Result<Option<usize>, Error> {
    match mechanism.mechanism {
        x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Ok(Some(AES_CMAC_LENGTH))
        }
        x if x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE => {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_ULONG>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let length = *unsafe { _as_ref(mechanism.pParameter.cast::<CK_ULONG>()) }
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?
                as usize;
            if length > AES_CMAC_LENGTH {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Ok(Some(length))
        }
        _ => Ok(None),
    }
}

pub(crate) fn aes_gmac_parameters(
    mechanism: &CK_MECHANISM,
) -> Result<Option<GcmParameters>, Error> {
    if mechanism.mechanism != CKM_AES_GMAC as CK_MECHANISM_TYPE {
        return Ok(None);
    }
    let mut parameters = parse_gcm_parameters(mechanism)?;
    parameters.aad.clear();
    Ok(Some(parameters))
}

fn aes_cmac_double(mut block: [u8; AES_CMAC_LENGTH]) -> [u8; AES_CMAC_LENGTH] {
    let carry = block[0] >> 7;
    for index in 0..AES_CMAC_LENGTH - 1 {
        block[index] = (block[index] << 1) | (block[index + 1] >> 7);
    }
    block[AES_CMAC_LENGTH - 1] <<= 1;
    block[AES_CMAC_LENGTH - 1] ^= 0x87 & 0u8.wrapping_sub(carry);
    block
}

fn aes_cmac_with_encryptor(
    data: &[u8],
    mut encrypt: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let encrypted_zero = encrypt(&[0; AES_CMAC_LENGTH])?;
    let subkey = encrypted_zero
        .as_slice()
        .try_into()
        .map(aes_cmac_double)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let complete = !data.is_empty() && crate::is_multiple_of(data.len(), AES_CMAC_LENGTH);
    let last_subkey = if complete {
        subkey
    } else {
        aes_cmac_double(subkey)
    };
    let block_count = std::cmp::max(1, data.len().div_ceil(AES_CMAC_LENGTH));
    let mut state = [0; AES_CMAC_LENGTH];

    for block_index in 0..block_count {
        let start = block_index * AES_CMAC_LENGTH;
        let available = data.len().saturating_sub(start).min(AES_CMAC_LENGTH);
        let mut block = [0; AES_CMAC_LENGTH];
        block[..available].copy_from_slice(&data[start..start + available]);
        if block_index + 1 == block_count {
            if !complete {
                block[available] = 0x80;
            }
            for (value, subkey) in block.iter_mut().zip(last_subkey) {
                *value ^= subkey;
            }
        }
        for (value, previous) in block.iter_mut().zip(state) {
            *value ^= previous;
        }
        let encrypted = encrypt(&block)?;
        state = encrypted
            .as_slice()
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    Ok(state.to_vec())
}

pub(crate) fn yubihsm_aes_cmac(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    aes_cmac_with_encryptor(data, |block| {
        yubihsm_encrypt_ecb_blocks(ctx, session_handle, key_id, block)
    })
}

pub(crate) fn yubihsm_aes_gmac(
    ctx: &mut SlotContext,
    session_handle: CK_SESSION_HANDLE,
    key_id: u16,
    parameters: &GcmParameters,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut parameters = parameters.clone();
    parameters.aad = data.to_vec();
    aes_gcm(&parameters, &[], true, |blocks| {
        yubihsm_encrypt_ecb_blocks(ctx, session_handle, key_id, blocks)
    })
}

pub(crate) fn software_aes_cmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    aes_cmac_with_encryptor(data, |block| software_crypt_ecb_blocks(key, block, true))
}

pub(crate) fn software_aes_gmac(
    key: &[u8],
    parameters: &GcmParameters,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut parameters = parameters.clone();
    parameters.aad = data.to_vec();
    aes_gcm(&parameters, &[], true, |blocks| {
        software_crypt_ecb_blocks(key, blocks, true)
    })
}

ffi_entry_point! {
    pub fn C_SignInit(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        log!(
            2,
            "C_SignInit called with {:?}",
            (session_handle, mechanism, key)
        );
        map(sign_init(session_handle, mechanism, key))
    }
}

fn sign_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, _flags, logged_in) = ctx.session_details(session_handle)?;

        if ctx
            .get_session_context(session_handle)?
            .sign_operation
            .is_some()
        {
            return Err(CKR_OPERATION_ACTIVE.into());
        }

        let mechanism = unsafe { _as_ref(mechanism) }?;
        require_slot_mechanism(ctx, slot_id, mechanism.mechanism, CKF_SIGN as CK_FLAGS)?;
        let gmac = aes_gmac_parameters(mechanism)?;
        let aes_mac_length = match &gmac {
            Some(parameters) => Some(parameters.tag_bits.div_ceil(8)),
            None => aes_cmac_length(mechanism)?,
        };
        let hmac_length = hmac_output_length(mechanism)?;
        let mac_length = hmac_length.or(aes_mac_length);
        let ml_dsa = ml_dsa_parameters(mechanism)?;
        let pss = if mac_length.is_some() || ml_dsa.is_some() {
            None
        } else if mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let parameters =
                unsafe { _as_ref(mechanism.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR) }?;
            let mgf = match parameters.mgf {
                x if x == CKG_MGF1_SHA1 as CK_RSA_PKCS_MGF_TYPE => 32,
                x if x == CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE => 33,
                x if x == CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE => 34,
                x if x == CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE => 35,
                x if x == CKG_MGF1_SHA224 as CK_RSA_PKCS_MGF_TYPE => 36,
                x if x == CKG_MGF1_SHA3_224 as CK_RSA_PKCS_MGF_TYPE => 37,
                x if x == CKG_MGF1_SHA3_256 as CK_RSA_PKCS_MGF_TYPE => 38,
                x if x == CKG_MGF1_SHA3_384 as CK_RSA_PKCS_MGF_TYPE => 39,
                x if x == CKG_MGF1_SHA3_512 as CK_RSA_PKCS_MGF_TYPE => 40,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
            };
            let salt_length = u16::try_from(parameters.sLen)
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
            Some((mgf, salt_length, parameters.hashAlg))
        } else if piv_is_pss_mechanism(mechanism.mechanism) {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            let digest =
                piv_hash_mechanism(mechanism.mechanism).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let hash = pss_hash_mechanism(mechanism.mechanism)?;
            Some((0, digest.size() as u16, hash))
        } else {
            if !matches!(
                mechanism.mechanism,
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_RSA_X_509 as CK_MECHANISM_TYPE
                    || x == CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_224_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_256_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_384_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_SHA3_512_RSA_PKCS as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_224 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_256 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_384 as CK_MECHANISM_TYPE
                    || x == CKM_ECDSA_SHA3_512 as CK_MECHANISM_TYPE
                    || x == CKM_EDDSA as CK_MECHANISM_TYPE
                    || x == CKM_ML_DSA as CK_MECHANISM_TYPE
                    || x == CKM_SHA_1_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA256_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA384_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_SHA512_HMAC as CK_MECHANISM_TYPE
                    || x == CKM_AES_CMAC as CK_MECHANISM_TYPE
                    || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
                    || x == CKM_AES_GMAC as CK_MECHANISM_TYPE
                    || x == CKM_PKCS11RS_PREVIEW_SIGN
                    || x == CKM_PKCS11RS_FIDO_ASSERTION
            ) {
                return Err(CKR_MECHANISM_INVALID.into());
            }
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            None
        };

        let object = ctx.resolve_object(key)?.ok_or(CKR_KEY_HANDLE_INVALID)?;
        if object.private && !logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        if !object.is_visible_to(logged_in) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        require_key_mechanism(&object, mechanism.mechanism)?;
        if !object.sign {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let expected_key_type = match mechanism.mechanism {
            x if x == CKM_ECDSA as CK_MECHANISM_TYPE || piv_is_hashed_ecdsa(x) => {
                CKK_EC as CK_KEY_TYPE
            }
            x if x == CKM_PKCS11RS_PREVIEW_SIGN => CKK_EC as CK_KEY_TYPE,
            x if x == CKM_PKCS11RS_FIDO_ASSERTION => 0,
            x if x == CKM_EDDSA as CK_MECHANISM_TYPE => CKK_EC_EDWARDS as CK_KEY_TYPE,
            x if x == CKM_ML_DSA as CK_MECHANISM_TYPE => CKK_ML_DSA as CK_KEY_TYPE,
            x if x == CKM_AES_CMAC as CK_MECHANISM_TYPE
                || x == CKM_AES_CMAC_GENERAL as CK_MECHANISM_TYPE
                || x == CKM_AES_GMAC as CK_MECHANISM_TYPE =>
            {
                CKK_AES as CK_KEY_TYPE
            }
            _ => CKK_RSA as CK_KEY_TYPE,
        };
        let expected_key_type = hmac_key_type_and_length(mechanism.mechanism)
            .map(|(key_type, _)| key_type)
            .unwrap_or(expected_key_type);
        let secret_key_material = (is_hmac_key_type(expected_key_type)
            || expected_key_type == CKK_AES as CK_KEY_TYPE)
            && matches!(
                object.material,
                KeyMaterial::YubiHsm { .. } | KeyMaterial::SoftwareSecret(_)
            );
        let software_generic_hmac = is_hmac_key_type(expected_key_type)
            && object.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE
            && matches!(object.material, KeyMaterial::SoftwareSecret(_));
        if ((!secret_key_material && object.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            || (secret_key_material && object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS))
            || (mechanism.mechanism != CKM_PKCS11RS_FIDO_ASSERTION
                && object.key_type != expected_key_type
                && !software_generic_hmac)
            || !matches!(
                object.material,
                KeyMaterial::SoftwarePrivate(_)
                    | KeyMaterial::PivPrivate { .. }
                    | KeyMaterial::OpenPgpPrivate { .. }
                    | KeyMaterial::YubiHsm { .. }
                    | KeyMaterial::SoftwareSecret(_)
                    | KeyMaterial::PreviewSignDerived { .. }
                    | KeyMaterial::FidoResidentPrivate { .. }
            )
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let piv_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::PivPrivate { algorithm, .. }
                if piv_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        let openpgp_mechanism_supported = matches!(
            &object.material,
            KeyMaterial::OpenPgpPrivate { algorithm, .. }
                if openpgp_sign_mechanism_supported(*algorithm, mechanism.mechanism)
        );
        let preview_sign_mechanism_supported = matches!(
            object.material,
            KeyMaterial::PreviewSignDerived { .. }
                if mechanism.mechanism == CKM_PKCS11RS_PREVIEW_SIGN
        );
        let fido_assertion_mechanism_supported = matches!(
            object.material,
            KeyMaterial::FidoResidentPrivate { .. }
                if mechanism.mechanism == CKM_PKCS11RS_FIDO_ASSERTION
        );
        let software_mechanism_supported = match &object.material {
            KeyMaterial::SoftwarePrivate(key) => {
                key.key_type() == expected_key_type
                    && software_sign_mechanism_supported(key, mechanism.mechanism)
            }
            KeyMaterial::SoftwareSecret(_) => {
                (object.key_type == CKK_AES as CK_KEY_TYPE && aes_mac_length.is_some())
                    || hmac_key_type_and_length(mechanism.mechanism).is_some_and(|(key_type, _)| {
                        key_type == object.key_type
                            || object.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE
                    })
            }
            _ => false,
        };
        let yubihsm_mechanism_supported = matches!(object.material, KeyMaterial::YubiHsm { .. })
            && ctx
                .get_slot(slot_id)?
                .backend_mechanisms()
                .iter()
                .any(|details| {
                    details.type_ == mechanism.mechanism
                        && details.flags & CKF_SIGN as CK_FLAGS != 0
                });
        if !yubihsm_mechanism_supported
            && !piv_mechanism_supported
            && !openpgp_mechanism_supported
            && !preview_sign_mechanism_supported
            && !fido_assertion_mechanism_supported
            && !software_mechanism_supported
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        if matches!(object.material, KeyMaterial::YubiHsm { .. })
            && mechanism.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE
        {
            return Err(CKR_MECHANISM_INVALID.into());
        }
        let context_specific_rp_id =
            matches!(object.material, KeyMaterial::FidoResidentPrivate { .. })
                .then(|| object.rp_id.clone())
                .flatten();
        ctx.get_session_context_mut(session_handle)?.sign_operation = Some(SignatureOperation {
            key: object.material.clone(),
            public_key: object.public_key.clone(),
            slot_id,
            requires_login: object.private
                && ctx.get_slot(slot_id)?.private_objects_require_login(),
            context_specific_extended: false,
            context_specific_rp_id,
            fido_authorization: None,
            mechanism: mechanism.mechanism,
            mac_length,
            gmac,
            pss,
            ml_dsa,
            piv_pin_policy: match &object.material {
                KeyMaterial::PivPrivate { pin_policy, .. } => Some(*pin_policy),
                _ => None,
            },
            buffer: Vec::new(),
            result: None,
        });
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_Sign(
        session_handle: CK_SESSION_HANDLE,
        data: *mut ::std::os::raw::c_uchar,
        data_len: ::std::os::raw::c_ulong,
        signature: *mut ::std::os::raw::c_uchar,
        signature_len: *mut ::std::os::raw::c_ulong,
    ) -> CK_RV {
        log!(
            2,
            "C_Sign called with {:?}",
            (session_handle, data, data_len, signature, signature_len)
        );
        map(sign(
            session_handle,
            data,
            data_len,
            signature,
            signature_len,
        ))
    }
}

fn sign(
    session_handle: CK_SESSION_HANDLE,
    data: *const ::std::os::raw::c_uchar,
    data_len: CK_ULONG,
    signature: *mut ::std::os::raw::c_uchar,
    signature_len: CK_ULONG_PTR,
) -> Result<(), Error> {
    if signature_len.is_null() {
        let _ = with_session_context_mut(session_handle, |ctx| {
            if let Ok(session) = ctx.get_session_context_mut(session_handle) {
                session.sign_operation = None;
            }
            Ok(())
        });
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let signature_len = unsafe { as_mut(signature_len) }?;
    with_session_context_mut(session_handle, |ctx| {
        let operation = ctx
            .get_session_context(session_handle)?
            .sign_operation
            .as_ref()
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if operation.requires_login && !ctx.is_slot_user_logged_in(operation.slot_id) {
            ctx.reconcile_login_state(operation.slot_id);
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let data = match unsafe { from_raw_parts(data, data_len as usize) } {
            Ok(data) => data,
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(error);
            }
        };
        if let KeyMaterial::FidoResidentPrivate { credential_id } = &operation.key {
            let rp_id = operation
                .context_specific_rp_id
                .as_deref()
                .ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
            if data.len() != 32 || (!operation.buffer.is_empty() && operation.buffer != data) {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            let response = if let Some(response) = operation.result {
                response
            } else {
                let authorization = ctx
                    .get_session_context_mut(session_handle)?
                    .sign_operation
                    .as_mut()
                    .and_then(|operation| operation.fido_authorization.take())
                    .ok_or(CKR_USER_NOT_LOGGED_IN)?;
                let client_data_hash: &[u8; 32] = data
                    .try_into()
                    .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
                let result = match ctx._get_slot_mut(operation.slot_id) {
                    Ok(slot) => slot.fido_get_assertion(
                        &authorization,
                        rp_id,
                        credential_id,
                        client_data_hash,
                    ),
                    Err(error) => Err(error),
                };
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                        return Err(error);
                    }
                };
                let active = ctx
                    .get_session_context_mut(session_handle)?
                    .sign_operation
                    .as_mut()
                    .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
                active.buffer = data.to_vec();
                active.result = Some(response.clone());
                response
            };
            if signature.is_null() {
                *signature_len = response.len() as CK_ULONG;
                return Ok(());
            }
            if *signature_len < response.len() as CK_ULONG {
                *signature_len = response.len() as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL.into());
            }
            unsafe {
                ptr::copy_nonoverlapping(response.as_ptr(), signature, response.len());
            }
            *signature_len = response.len() as CK_ULONG;
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Ok(());
        }
        let mut buffered_data = operation.buffer;
        buffered_data.extend_from_slice(data);
        let data = buffered_data.as_slice();
        let required = match &operation.key {
            KeyMaterial::SoftwarePrivate(key) => software_signature_length(key)?,
            KeyMaterial::SoftwareSecret(_) => operation
                .mac_length
                .or_else(|| hmac_key_type_and_length(operation.mechanism).map(|(_, length)| length))
                .ok_or(CKR_KEY_TYPE_INCONSISTENT)?,
            KeyMaterial::PivPrivate { algorithm, .. } => match algorithm {
                piv::Algorithm::Rsa1024
                | piv::Algorithm::Rsa2048
                | piv::Algorithm::Rsa3072
                | piv::Algorithm::Rsa4096 => match &operation.public_key {
                    Some(PublicKeyMaterial::Rsa(key)) => key.size(),
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                },
                piv::Algorithm::EccP256 => 64,
                piv::Algorithm::EccP384 => 96,
                piv::Algorithm::Ed25519 => 64,
                piv::Algorithm::X25519 => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::OpenPgpPrivate { algorithm, .. } => match algorithm {
                OpenPgpAlgorithm::Rsa { .. } => match &operation.public_key {
                    Some(PublicKeyMaterial::Rsa(key)) => key.size(),
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                },
                OpenPgpAlgorithm::Ecdsa(_) => {
                    openpgp_ec_coordinate_length(*algorithm).ok_or(CKR_KEY_TYPE_INCONSISTENT)? * 2
                }
                OpenPgpAlgorithm::Ed25519 => 64,
                OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_rsa(*algorithm) => {
                match *algorithm {
                    YUBIHSM_ALGO_RSA_2048 => 256,
                    YUBIHSM_ALGO_RSA_3072 => 384,
                    YUBIHSM_ALGO_RSA_4096 => 512,
                    _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                }
            }
            KeyMaterial::YubiHsm { algorithm, .. } if is_yubihsm_ec(*algorithm) => {
                yubihsm_ec_coordinate_length(*algorithm)? * 2
            }
            KeyMaterial::YubiHsm {
                algorithm: YUBIHSM_ALGO_ED25519,
                ..
            } => 64,
            KeyMaterial::YubiHsm { .. } if operation.mac_length.is_some() => {
                operation.mac_length.ok_or(CKR_KEY_TYPE_INCONSISTENT)?
            }
            KeyMaterial::YubiHsm { algorithm, .. } => match *algorithm {
                YUBIHSM_ALGO_HMAC_SHA1 => 20,
                YUBIHSM_ALGO_HMAC_SHA256 => 32,
                YUBIHSM_ALGO_HMAC_SHA384 => 48,
                YUBIHSM_ALGO_HMAC_SHA512 => 64,
                _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            },
            KeyMaterial::PreviewSignDerived { .. } => 64,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        };
        if matches!(operation.key, KeyMaterial::PreviewSignDerived { .. }) && data.len() != 32 {
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE
            && data.len() > required.saturating_sub(11)
        {
            ctx.get_session_context_mut(session_handle)?.sign_operation = None;
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        if operation.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE {
            let Some((_mgf, _salt, hash)) = operation.pss else {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            };
            let expected = digest_for_hash_mechanism(hash)?.size();
            if data.len() != expected {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_DATA_LEN_RANGE.into());
            }
        }

        if signature.is_null() {
            *signature_len = required as CK_ULONG;
            return Ok(());
        }
        if *signature_len < required as CK_ULONG {
            *signature_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }

        let signature_result = (|| -> Result<Vec<u8>, Error> {
            match &operation.key {
                KeyMaterial::SoftwarePrivate(key) => software_sign(
                    key,
                    operation.mechanism,
                    operation.pss,
                    operation.ml_dsa.as_ref(),
                    data,
                ),
                KeyMaterial::SoftwareSecret(key) => {
                    if hmac_key_type_and_length(operation.mechanism).is_some() {
                        let mut mac = software_hmac(key, operation.mechanism, data)?;
                        mac.truncate(required);
                        return Ok(mac);
                    }
                    if let Some(parameters) = &operation.gmac {
                        return software_aes_gmac(key, parameters, data);
                    }
                    if operation.mac_length.is_some() {
                        let mut mac = software_aes_cmac(key, data)?;
                        mac.truncate(required);
                        return Ok(mac);
                    }
                    software_hmac(key, operation.mechanism, data)
                }
                KeyMaterial::PivPrivate {
                    slot, algorithm, ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()?;
                    let input = if piv_is_pss_mechanism(operation.mechanism) {
                        let (mgf, salt_length, hash_mechanism) =
                            operation.pss.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        let digest = digest.as_deref().unwrap_or(data);
                        encode_rsa_pss(digest, required, hash_mechanism, mgf, salt_length as usize)?
                    } else if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                        let digest = digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                        encode_pkcs1_v1_5_signature_input(
                            &piv_digest_info(operation.mechanism, digest)
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                            required,
                        )?
                    } else if operation.mechanism == CKM_RSA_PKCS as CK_MECHANISM_TYPE {
                        encode_pkcs1_v1_5_signature_input(data, required)?
                    } else if operation.mechanism == CKM_RSA_X_509 as CK_MECHANISM_TYPE {
                        if data.len() > required {
                            return Err(CKR_DATA_LEN_RANGE.into());
                        }
                        let mut input = vec![0; required - data.len()];
                        input.extend_from_slice(data);
                        input
                    } else if piv_is_hashed_ecdsa(operation.mechanism) {
                        digest.ok_or(CKR_MECHANISM_PARAM_INVALID)?
                    } else {
                        data.to_vec()
                    };
                    let response = ctx._get_session(session_handle)?.1.piv_sign(
                        *slot,
                        *algorithm,
                        &input,
                        operation.piv_pin_policy.unwrap_or(0),
                    )?;
                    match algorithm {
                        piv::Algorithm::EccP256 => piv_ecdsa_signature(&response, 32),
                        piv::Algorithm::EccP384 => piv_ecdsa_signature(&response, 48),
                        _ => Ok(response),
                    }
                }
                KeyMaterial::OpenPgpPrivate {
                    key_ref,
                    algorithm,
                    pin_policy,
                    ..
                } => {
                    let digest = piv_hash_mechanism(operation.mechanism)
                        .map(|digest| hash(digest, data).map(|value| value.to_vec()))
                        .transpose()?;
                    let input = match algorithm {
                        OpenPgpAlgorithm::Rsa { .. } => {
                            if piv_is_hashed_rsa_pkcs(operation.mechanism) {
                                piv_digest_info(
                                    operation.mechanism,
                                    digest.as_deref().ok_or(CKR_MECHANISM_PARAM_INVALID)?,
                                )
                                .ok_or(CKR_MECHANISM_PARAM_INVALID)?
                            } else {
                                data.to_vec()
                            }
                        }
                        OpenPgpAlgorithm::Ecdsa(_) => digest.unwrap_or_else(|| data.to_vec()),
                        OpenPgpAlgorithm::Ed25519 => data.to_vec(),
                        OpenPgpAlgorithm::Ecdh(_) => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
                    };
                    let response = ctx._get_session(session_handle)?.1.openpgp_sign(
                        *key_ref,
                        &input,
                        *pin_policy,
                    )?;
                    match algorithm {
                        OpenPgpAlgorithm::Ecdsa(curve) => openpgp_signature(
                            &response,
                            curve.coordinate_length().ok_or(CKR_KEY_TYPE_INCONSISTENT)?,
                        ),
                        _ => Ok(response),
                    }
                }
                KeyMaterial::YubiHsm { id, algorithm, .. } => {
                    if hmac_key_type_and_length(operation.mechanism).is_some() {
                        let command =
                            YubiHsmCommand::key_data(YubiHsmCommandCode::SignHmac, *id, data)?;
                        let mut response = ctx
                            ._get_session(session_handle)?
                            .1
                            .yubihsm_command(&command)?;
                        response.truncate(required);
                        return Ok(response);
                    }
                    if let Some(parameters) = &operation.gmac {
                        return yubihsm_aes_gmac(ctx, session_handle, *id, parameters, data);
                    }
                    if operation.mac_length.is_some() {
                        let mut mac = yubihsm_aes_cmac(ctx, session_handle, *id, data)?;
                        mac.truncate(required);
                        return Ok(mac);
                    }
                    let command = yubihsm_asymmetric_signature_command(
                        operation.mechanism,
                        operation.pss,
                        *id,
                        data,
                    )?;
                    let response = ctx
                        ._get_session(session_handle)?
                        .1
                        .yubihsm_command(&command)?;
                    if operation.mechanism == CKM_ECDSA as CK_MECHANISM_TYPE
                        || piv_is_hashed_ecdsa(operation.mechanism)
                    {
                        yubihsm_ecdsa_signature(
                            &response,
                            yubihsm_ec_coordinate_length(*algorithm)?,
                        )
                    } else {
                        Ok(response)
                    }
                }
                KeyMaterial::PreviewSignDerived {
                    registration,
                    derived,
                    ..
                } => {
                    let arguments = derived
                        .additional_args_cbor()
                        .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    ctx._get_slot_mut(operation.slot_id)?.fido_preview_sign(
                        registration,
                        data,
                        arguments,
                    )
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
            }
        })();
        let signature_bytes = match signature_result {
            Ok(signature) if signature.len() == required => signature,
            Ok(_) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(CKR_DEVICE_ERROR.into());
            }
            Err(error) => {
                ctx.get_session_context_mut(session_handle)?.sign_operation = None;
                return Err(error);
            }
        };

        unsafe {
            ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
        }
        *signature_len = required as CK_ULONG;
        ctx.get_session_context_mut(session_handle)?.sign_operation = None;
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_SignUpdate(
        session_handle: CK_SESSION_HANDLE,
        part: *mut ::std::os::raw::c_uchar,
        part_len: ::std::os::raw::c_ulong,
    ) -> CK_RV {
        map(with_session_context_mut(session_handle, |ctx| {
            let part = unsafe { from_raw_parts(part, part_len as usize) }?.to_vec();
            let session = ctx.get_session_context_mut(session_handle)?;
            let operation = session
                .sign_operation
                .as_mut()
                .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            if operation.mechanism == CKM_PKCS11RS_FIDO_ASSERTION {
                session.sign_operation = None;
                return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
            }
            operation.buffer.extend_from_slice(&part);
            Ok(())
        }))
    }
}

ffi_entry_point! {
    pub fn C_SignFinal(
        session_handle: CK_SESSION_HANDLE,
        signature: *mut ::std::os::raw::c_uchar,
        signature_len: *mut ::std::os::raw::c_ulong,
    ) -> CK_RV {
        map(sign(
            session_handle,
            ptr::null(),
            0,
            signature,
            signature_len,
        ))
    }
}

session_unsupported_stub!(C_SignRecoverInit(
    _mechanism: *mut CK_MECHANISM,
    _key: CK_OBJECT_HANDLE,
));

session_unsupported_stub!(C_SignRecover(
    _data: *mut ::std::os::raw::c_uchar,
    _data_len: ::std::os::raw::c_ulong,
    _signature: *mut ::std::os::raw::c_uchar,
    _signature_len: *mut ::std::os::raw::c_ulong,
));

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Keypair;

    const MESSAGE: &[u8] = b"software-assisted hardware signature";
    const KEY_ID: u16 = 0x1234;

    fn digest(mechanism: CK_MECHANISM_TYPE) -> Vec<u8> {
        hash(piv_hash_mechanism(mechanism).unwrap(), MESSAGE)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn yubihsm_hashes_every_advertised_rsa_pkcs_composite_before_transport() {
        for mechanism in [
            CKM_SHA1_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
        ] {
            let mechanism = mechanism as CK_MECHANISM_TYPE;
            let command =
                yubihsm_asymmetric_signature_command(mechanism, None, KEY_ID, MESSAGE).unwrap();
            assert_eq!(command.code(), YubiHsmCommandCode::SignPkcs1);
            let expected = piv_digest_info(mechanism, &digest(mechanism)).unwrap();
            assert_eq!(&command.data()[..2], &KEY_ID.to_be_bytes());
            assert_eq!(&command.data()[2..], expected);
        }
    }

    #[test]
    fn yubihsm_hashes_every_advertised_rsa_pss_composite_before_transport() {
        for (mechanism, hash_mechanism, mgf) in [
            (CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1, YUBIHSM_ALGO_MGF1_SHA1),
            (
                CKM_SHA256_RSA_PKCS_PSS,
                CKM_SHA256,
                YUBIHSM_ALGO_MGF1_SHA256,
            ),
            (
                CKM_SHA384_RSA_PKCS_PSS,
                CKM_SHA384,
                YUBIHSM_ALGO_MGF1_SHA384,
            ),
            (
                CKM_SHA512_RSA_PKCS_PSS,
                CKM_SHA512,
                YUBIHSM_ALGO_MGF1_SHA512,
            ),
        ] {
            let mechanism = mechanism as CK_MECHANISM_TYPE;
            let hash_mechanism = hash_mechanism as CK_MECHANISM_TYPE;
            let expected = digest(mechanism);
            let command = yubihsm_asymmetric_signature_command(
                mechanism,
                Some((0, expected.len() as u16, hash_mechanism)),
                KEY_ID,
                MESSAGE,
            )
            .unwrap();
            assert_eq!(command.code(), YubiHsmCommandCode::SignPss);
            assert_eq!(&command.data()[..2], &KEY_ID.to_be_bytes());
            assert_eq!(command.data()[2], mgf);
            assert_eq!(
                &command.data()[3..5],
                &(expected.len() as u16).to_be_bytes()
            );
            assert_eq!(&command.data()[5..], expected);
        }
    }

    #[test]
    fn yubihsm_hashes_every_advertised_ecdsa_composite_before_transport() {
        for mechanism in [
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
        ] {
            let mechanism = mechanism as CK_MECHANISM_TYPE;
            let command =
                yubihsm_asymmetric_signature_command(mechanism, None, KEY_ID, MESSAGE).unwrap();
            assert_eq!(command.code(), YubiHsmCommandCode::SignEcdsa);
            assert_eq!(&command.data()[..2], &KEY_ID.to_be_bytes());
            assert_eq!(&command.data()[2..], digest(mechanism));
        }
    }

    #[test]
    fn ml_dsa_hedge_required_reports_rng_failure_without_fallback() {
        let key = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from([7; 32]));
        let parameters = MlDsaSignatureParameters {
            hedge_variant: CKH_HEDGE_REQUIRED as CK_HEDGE_TYPE,
            context: b"required".to_vec(),
        };

        let error = ml_dsa_sign_with_randomizer(
            &key,
            Some(&parameters),
            MESSAGE,
            |_expanded, _data, _context| Err(CKR_RANDOM_NO_RNG.into()),
        )
        .unwrap_err();

        assert_eq!(CK_RV::from(error), CKR_RANDOM_NO_RNG as CK_RV);
    }

    #[test]
    fn ml_dsa_hedge_preferred_rng_failure_returns_valid_deterministic_signature() {
        let key = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from([7; 32]));
        let parameters = MlDsaSignatureParameters {
            hedge_variant: CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE,
            context: b"preferred".to_vec(),
        };

        let encoded = ml_dsa_sign_with_randomizer(
            &key,
            Some(&parameters),
            MESSAGE,
            |_expanded, _data, _context| Err(CKR_RANDOM_NO_RNG.into()),
        )
        .unwrap();
        let signature = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(encoded.as_slice()).unwrap();

        assert!(
            key.verifying_key()
                .verify_with_context(MESSAGE, &parameters.context, &signature)
        );
        assert_eq!(
            encoded,
            key.expanded_key()
                .sign_deterministic(MESSAGE, &parameters.context)
                .unwrap()
                .encode()
                .to_vec()
        );
    }
}
