//! Generic protected-secret composition; no protocol-specific layouts belong here.
use super::*;
use crate::software_key_ops::composition::{SecretDerivation, execute_secret_derivation, secret};

pub(super) fn supports(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, x if x == CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE
        || x == CKM_CONCATENATE_BASE_AND_DATA as CK_MECHANISM_TYPE
        || x == CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE
        || x == CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE)
}

enum Operation<'a> {
    AppendKey(CK_OBJECT_HANDLE),
    AppendData(&'a [u8]),
    Extract(usize),
    Sha256,
}

fn parameter<T>(mechanism: &CK_MECHANISM) -> Result<&T, Error> {
    if mechanism.ulParameterLen as usize != std::mem::size_of::<T>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    unsafe { _as_ref(mechanism.pParameter.cast::<T>()) }
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID.into())
}

fn parse(mechanism: &CK_MECHANISM) -> Result<Operation<'_>, Error> {
    Ok(match mechanism.mechanism {
        x if x == CKM_CONCATENATE_BASE_AND_KEY as CK_MECHANISM_TYPE => {
            Operation::AppendKey(*parameter::<CK_OBJECT_HANDLE>(mechanism)?)
        }
        x if x == CKM_CONCATENATE_BASE_AND_DATA as CK_MECHANISM_TYPE => {
            let data = parameter::<CK_KEY_DERIVATION_STRING_DATA>(mechanism)?;
            Operation::AppendData(
                unsafe { from_raw_parts(data.pData.cast_const(), data.ulLen as usize) }
                    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?,
            )
        }
        x if x == CKM_EXTRACT_KEY_FROM_KEY as CK_MECHANISM_TYPE => {
            Operation::Extract(*parameter::<CK_EXTRACT_PARAMS>(mechanism)? as usize)
        }
        x if x == CKM_SHA256_KEY_DERIVATION as CK_MECHANISM_TYPE => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            Operation::Sha256
        }
        _ => return Err(CKR_MECHANISM_INVALID.into()),
    })
}

pub(super) fn derive(
    session: CK_SESSION_HANDLE,
    mechanism: &CK_MECHANISM,
    base_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    output: &mut CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    let operation = parse(mechanism)?;
    let template = unsafe { from_raw_parts(template, count as usize) }?;
    validate_unique_template(template)?;
    with_session_context_mut(session, |ctx| {
        let (slot, flags, logged_in) = ctx.session_details(session)?;
        require_slot_mechanism(ctx, slot, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
        let base = ctx
            .resolve_object(base_handle)?
            .filter(|key| key.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        secret(&base, mechanism.mechanism)?;
        let other = if let Operation::AppendKey(handle) = operation {
            Some(
                ctx.resolve_object(handle)?
                    .filter(|key| key.is_visible_to(logged_in))
                    .ok_or(CKR_KEY_HANDLE_INVALID)?,
            )
        } else {
            None
        };
        let operation = match operation {
            Operation::AppendKey(_) => {
                SecretDerivation::AppendKey(other.as_ref().ok_or(CKR_KEY_HANDLE_INVALID)?)
            }
            Operation::AppendData(data) => SecretDerivation::AppendData(data),
            Operation::Extract(offset) => SecretDerivation::Extract(offset),
            Operation::Sha256 => SecretDerivation::Sha256,
        };
        operation.validate_inputs(&base)?;
        let mut merged = merge_policy_template(template, base.policy_templates.derive.as_ref())?;
        let mut merged = merge_policy_template(
            merged.as_slice(),
            other
                .as_ref()
                .and_then(|key| key.policy_templates.derive.as_ref()),
        )?;
        let template = merged.as_slice();
        // These are generated attributes, never supplied key material or history.
        if template.iter().any(|a| matches!(a.type_, x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_LOCAL as CK_ATTRIBUTE_TYPE || x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE
            || x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE || x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE)) {
            return Err(CKR_ATTRIBUTE_READ_ONLY.into());
        }
        let available = operation.available(&base)?;
        let key_type = template
            .iter()
            .find(|a| a.type_ == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
            .map(read_ulong_template_attribute)
            .transpose()
            .map_err(Error::from)?;
        let has_length = template
            .iter()
            .any(|a| a.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE);
        let default_length = if !has_length {
            match key_type {
                Some(x) if x == CKK_DES3 as CK_KEY_TYPE => 24,
                Some(_) => return Err(CKR_TEMPLATE_INCOMPLETE.into()),
                None if matches!(operation, SecretDerivation::Extract(_)) => {
                    return Err(CKR_TEMPLATE_INCOMPLETE.into());
                }
                None => available,
            }
        } else {
            available
        };
        let (mut object, length) =
            derived_secret_object(template, default_length, available.min(1024))?;
        if matches!(operation, SecretDerivation::Sha256) {
            object.always_sensitive = base.always_sensitive && object.sensitive;
            object.never_extractable = base.never_extractable && !object.extractable;
        } else {
            let sensitive = base.sensitive || other.as_ref().is_some_and(|key| key.sensitive);
            let nonextractable =
                !base.extractable || other.as_ref().is_some_and(|key| !key.extractable);
            if sensitive
                && optional_bool_template_attribute(template, CKA_SENSITIVE as CK_ATTRIBUTE_TYPE)?
                    == Some(false)
                || nonextractable
                    && optional_bool_template_attribute(
                        template,
                        CKA_EXTRACTABLE as CK_ATTRIBUTE_TYPE,
                    )? == Some(true)
            {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
            object.sensitive |= sensitive;
            object.extractable &= !nonextractable;
            object.always_sensitive =
                base.always_sensitive && other.as_ref().is_none_or(|key| key.always_sensitive);
            object.never_extractable =
                base.never_extractable && other.as_ref().is_none_or(|key| key.never_extractable);
        }
        validate_new_object_access(&object, flags, logged_in)?;
        object = execute_secret_derivation(&base, operation, object, length)?;
        *output = publish_software_secret_object(ctx, session, slot, object)?;
        Ok(())
    })
}
