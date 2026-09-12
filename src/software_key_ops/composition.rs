//! Validated, provider-independent composition of common software secret objects.
use crate::*;

#[derive(Clone, Copy)]
pub(crate) enum SecretDerivation<'a> {
    AppendKey(&'a TokenObject),
    AppendData(&'a [u8]),
    Extract(usize),
    Sha256,
}
impl SecretDerivation<'_> {
    pub(crate) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::AppendKey(_) => CKM_CONCATENATE_BASE_AND_KEY as _,
            Self::AppendData(_) => CKM_CONCATENATE_BASE_AND_DATA as _,
            Self::Extract(_) => CKM_EXTRACT_KEY_FROM_KEY as _,
            Self::Sha256 => CKM_SHA256_KEY_DERIVATION as _,
        }
    }
    pub(crate) fn validate_inputs(self, base: &TokenObject) -> Result<(), Error> {
        secret_length(base, self.mechanism())?;
        if let Self::AppendKey(other) = self {
            secret_length(other, self.mechanism())?;
        }
        Ok(())
    }
    pub(crate) fn available(self, base: &TokenObject) -> Result<usize, Error> {
        let base_length = secret_length(base, self.mechanism())?;
        let other_value = if let Self::AppendKey(other) = self {
            Some(secret_length(other, self.mechanism())?)
        } else {
            None
        };
        let available = match self {
            SecretDerivation::AppendKey(_) => {
                base_length.checked_add(other_value.ok_or(CKR_KEY_HANDLE_INVALID)?)
            }
            SecretDerivation::AppendData(data) => base_length.checked_add(data.len()),
            SecretDerivation::Extract(offset) => {
                if offset >= base_length * 8 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                Some(base_length)
            }
            SecretDerivation::Sha256 => Some(32),
        }
        .ok_or(CKR_KEY_SIZE_RANGE)?;

        Ok(available)
    }
}

pub(crate) fn secret_length(
    object: &TokenObject,
    mechanism: CK_MECHANISM_TYPE,
) -> Result<usize, Error> {
    require_key_mechanism(object, mechanism)?;
    if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS || !object.derive {
        return Err(if object.class != CKO_SECRET_KEY as CK_OBJECT_CLASS {
            CKR_KEY_TYPE_INCONSISTENT.into()
        } else {
            CKR_KEY_FUNCTION_NOT_PERMITTED.into()
        });
    }
    let length = match &object.material {
        KeyMaterial::SoftwareSecret(value) => value.len(),
        KeyMaterial::YubiHsmSessionObject { length, .. } => *length,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };
    if !(1..=1024).contains(&length) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    Ok(length)
}

pub(crate) fn secret(object: &TokenObject, mechanism: CK_MECHANISM_TYPE) -> Result<&[u8], Error> {
    secret_length(object, mechanism)?;
    let KeyMaterial::SoftwareSecret(value) = &object.material else {
        // Native material must never be exported to implement a software mechanism.
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    if !(1..=1024).contains(&value.len()) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    Ok(value)
}

/// Output type/length and nested policies are validated by the calling object
/// service before this function. No result is published until execution succeeds.
pub(crate) fn execute_secret_derivation(
    base: &TokenObject,
    operation: SecretDerivation<'_>,
    mut object: TokenObject,
    length: usize,
) -> Result<TokenObject, Error> {
    let available = operation.available(base)?;
    if length == 0 || length > available.min(1024) {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    let base_value = secret(base, operation.mechanism())?;
    let other = if let SecretDerivation::AppendKey(other) = operation {
        Some(other)
    } else {
        None
    };
    let other_value = other
        .map(|key| secret(key, operation.mechanism()))
        .transpose()?;
    if matches!(operation, SecretDerivation::Sha256) {
        object.always_sensitive = base.always_sensitive && object.sensitive;
        object.never_extractable = base.never_extractable && !object.extractable;
    } else {
        object.sensitive |= base.sensitive || other.is_some_and(|key| key.sensitive);
        object.extractable &= base.extractable && other.is_none_or(|key| key.extractable);
        object.always_sensitive =
            base.always_sensitive && other.is_none_or(|key| key.always_sensitive);
        object.never_extractable =
            base.never_extractable && other.is_none_or(|key| key.never_extractable);
    }
    let mut value = Zeroizing::new(Vec::with_capacity(length));
    match operation {
        SecretDerivation::AppendKey(_) => value.extend(
            base_value
                .iter()
                .chain(other_value.ok_or(CKR_KEY_HANDLE_INVALID)?)
                .take(length)
                .copied(),
        ),
        SecretDerivation::AppendData(data) => {
            value.extend(base_value.iter().chain(data).take(length).copied())
        }
        SecretDerivation::Sha256 => {
            let digest = Zeroizing::new(MessageDigest::Sha256.digest(base_value));
            value.extend_from_slice(&digest[..length]);
        }
        SecretDerivation::Extract(offset) => {
            // PKCS #11 numbers bits MSB first and permits wrapping at the end.
            for i in 0..length {
                let bit = (offset + i * 8) % (base_value.len() * 8);
                let index = bit / 8;
                let shift = bit % 8;
                let byte = if shift == 0 {
                    base_value[index]
                } else {
                    (base_value[index] << shift)
                        | (base_value[(index + 1) % base_value.len()] >> (8 - shift))
                };
                value.push(byte);
            }
        }
    }
    if object.key_type == CKK_DES3 as CK_KEY_TYPE {
        for byte in value.iter_mut() {
            *byte = (*byte & 0xfe) | u8::from((*byte & 0xfe).count_ones().is_multiple_of(2));
        }
    }
    object.material = KeyMaterial::SoftwareSecret(value);
    object.local = false;
    object.key_gen_mechanism = Some(operation.mechanism());
    Ok(object)
}
