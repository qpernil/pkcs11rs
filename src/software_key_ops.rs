//! Software key operations shared by public PKCS #11 operations and private scopes.
//! Callers authorize object access before invoking these primitive operations.
use crate::*;
pub(crate) mod agreement;
pub(crate) mod composition;
const AES_BLOCK_LENGTH: usize = 16;

pub(crate) fn software_crypt_ecb_blocks(
    key: &[u8],
    blocks: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    use software_key_core::software_symmetric::{
        SoftwareSymmetricError, decrypt_aes_ecb, encrypt_aes_ecb,
    };
    let result = if encrypting {
        encrypt_aes_ecb(key, blocks)
    } else {
        decrypt_aes_ecb(key, blocks)
    };
    result.map_err(|error| match error {
        SoftwareSymmetricError::InvalidKeyLength => CKR_KEY_SIZE_RANGE.into(),
        SoftwareSymmetricError::InvalidDataLength => CKR_DATA_LEN_RANGE.into(),
        _ => CKR_FUNCTION_FAILED.into(),
    })
}

pub(crate) fn software_aes_cbc(
    key: &[u8],
    iv: &[u8; AES_BLOCK_LENGTH],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    if !crate::is_multiple_of(input.len(), AES_BLOCK_LENGTH) {
        return Err(if encrypting {
            CKR_DATA_LEN_RANGE.into()
        } else {
            CKR_ENCRYPTED_DATA_LEN_RANGE.into()
        });
    }
    let mut output = Vec::with_capacity(input.len());
    let mut previous = *iv;
    for input_block in input.as_chunks::<AES_BLOCK_LENGTH>().0 {
        if encrypting {
            let block = Zeroizing::new(
                input_block
                    .iter()
                    .zip(previous)
                    .map(|(value, previous)| value ^ previous)
                    .collect::<Vec<_>>(),
            );
            let encrypted = software_crypt_ecb_blocks(key, &block, true)?;
            previous.copy_from_slice(&encrypted);
            output.extend_from_slice(&encrypted);
        } else {
            let decrypted = Zeroizing::new(software_crypt_ecb_blocks(key, input_block, false)?);
            output.extend(
                decrypted
                    .iter()
                    .zip(previous)
                    .map(|(value, previous)| value ^ previous),
            );
            previous.copy_from_slice(input_block);
        }
    }
    Ok(output)
}

pub(crate) fn software_aes_cmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    software_key_core::software_symmetric::aes_cmac(key, data)
        .map(|mac| mac.to_vec())
        .map_err(|_| CKR_KEY_SIZE_RANGE.into())
}

pub(crate) fn cmac_with_encryptor(
    data: &[u8],
    encrypt: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    software_key_core::software_symmetric::cmac_with(AES_BLOCK_LENGTH, data, encrypt)
        .map_err(cmac_error)
}

pub(crate) fn cmac_with_cbc_encryptor(
    data: &[u8],
    encrypt_block: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
    encrypt_cbc: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    software_key_core::software_symmetric::cmac_with_cbc(
        AES_BLOCK_LENGTH,
        data,
        encrypt_block,
        encrypt_cbc,
    )
    .map_err(cmac_error)
}

fn cmac_error(error: software_key_core::software_symmetric::BlockCipherModeError<Error>) -> Error {
    use software_key_core::software_symmetric::BlockCipherModeError;
    match error {
        BlockCipherModeError::BlockOperation(error) => error,
        _ => CKR_DEVICE_ERROR.into(),
    }
}

pub(crate) fn counter_kdf_with(
    fields: &[software_key_core::counter_kdf::CounterKdfField<'_>],
    length: usize,
    cmac: impl FnMut(&[u8]) -> Result<[u8; 16], Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    use software_key_core::counter_kdf::{
        CounterKdfError, CounterKdfOperationError, cmac_counter_kdf_with,
    };
    cmac_counter_kdf_with(fields, length, cmac).map_err(|error| match error {
        CounterKdfOperationError::Kdf(error) => Error::from(match error {
            CounterKdfError::InvalidParameters => CKR_MECHANISM_PARAM_INVALID,
            CounterKdfError::InvalidKeyLength | CounterKdfError::OutputTooLong => {
                CKR_KEY_SIZE_RANGE
            }
        }),
        CounterKdfOperationError::Cmac(error) => error,
    })
}

/// Derive into an already validated and policy-merged output object. Publication
/// belongs to the caller's public session or private scope, after success only.
pub(crate) fn derive_counter_key_with(
    base: &TokenObject,
    fields: &[software_key_core::counter_kdf::CounterKdfField<'_>],
    mut object: TokenObject,
    length: usize,
    cmac: impl FnMut(&[u8]) -> Result<[u8; 16], Error>,
) -> Result<TokenObject, Error> {
    let mut derived = counter_kdf_with(fields, length, cmac)?;
    if object.key_type == CKK_DES3 as CK_KEY_TYPE {
        for byte in derived.iter_mut() {
            *byte = (*byte & 0xfe) | u8::from((*byte & 0xfe).count_ones().is_multiple_of(2));
        }
    }
    object.material = KeyMaterial::SoftwareSecret(derived);
    object.always_sensitive = base.always_sensitive && object.sensitive;
    object.never_extractable = base.never_extractable && !object.extractable;
    object.local = false;
    object.key_gen_mechanism = Some(CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE);
    Ok(object)
}

/// Validate the base before output-template handling, preserving public error order.
pub(crate) fn counter_base_key(base: &TokenObject) -> Result<CounterCmacKey<'_>, Error> {
    require_key_mechanism(base, CKM_SP800_108_COUNTER_KDF as CK_MECHANISM_TYPE)?;
    if base.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || base.key_type != CKK_AES as CK_KEY_TYPE {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    }
    if !base.derive {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
    }
    match &base.material {
        KeyMaterial::SoftwareSecret(value) => {
            if !matches!(value.len(), 16 | 24 | 32) {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            Ok(CounterCmacKey::Software(value))
        }
        KeyMaterial::YubiHsm {
            id,
            object_type,
            algorithm,
            capabilities,
            ..
        } if *object_type == YUBIHSM_SYMMETRIC_KEY && is_yubihsm_aes(*algorithm) => {
            if !yubihsm_capability(capabilities, 0x33) {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            Ok(CounterCmacKey::YubiHsm(*id))
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

/// Authorization is for derivation, not public signing. Hardware CMAC uses
/// encrypt-ECB without exporting the base key or invoking C_Sign's policy.
pub(crate) enum CounterCmacKey<'a> {
    Software(&'a [u8]),
    YubiHsm(u16),
}

impl CounterCmacKey<'_> {
    pub(crate) fn cmac(
        &self,
        input: &[u8],
        hardware: impl FnOnce(u16) -> Result<Vec<u8>, Error>,
    ) -> Result<[u8; 16], Error> {
        match self {
            Self::Software(value) => software_key_core::software_symmetric::aes_cmac(value, input)
                .map_err(|_| CKR_KEY_SIZE_RANGE.into()),
            Self::YubiHsm(id) => {
                let mac = Zeroizing::new(hardware(*id)?);
                mac.as_slice()
                    .try_into()
                    .map_err(|_| CKR_DEVICE_ERROR.into())
            }
        }
    }
}
