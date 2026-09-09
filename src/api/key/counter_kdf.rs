use super::*;
use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat, LengthMethod};

fn parameter<T: Copy>(pointer: CK_VOID_PTR, length: CK_ULONG) -> Result<T, Error> {
    if length as usize != std::mem::size_of::<T>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    unsafe { _as_ref(pointer.cast::<T>()) }
        .copied()
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID.into())
}

fn format(width: CK_ULONG, endian: CK_BBOOL, maximum: u8) -> Result<IntegerFormat, Error> {
    if width == 0
        || width > CK_ULONG::from(maximum)
        || !width.is_multiple_of(8)
        || (endian != CK_FALSE as CK_BBOOL && endian != CK_TRUE as CK_BBOOL)
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(IntegerFormat {
        width_bits: width as u8,
        little_endian: endian == CK_TRUE as CK_BBOOL,
    })
}

fn fields(mechanism: &CK_MECHANISM) -> Result<Vec<CounterKdfField<'_>>, Error> {
    let parameters =
        parameter::<CK_SP800_108_KDF_PARAMS>(mechanism.pParameter, mechanism.ulParameterLen)?;
    // Single-output AES-CMAC is the initial supported profile. Never silently
    // ignore extra outputs or interpret another PRF as CMAC.
    if parameters.prfType != CKM_AES_CMAC as CK_MECHANISM_TYPE
        || parameters.ulAdditionalDerivedKeys != 0
        || !parameters.pAdditionalDerivedKeys.is_null()
        || !(1..=64).contains(&parameters.ulNumberOfDataParams)
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let parameters = unsafe {
        from_raw_parts(
            parameters.pDataParams.cast_const(),
            parameters.ulNumberOfDataParams as usize,
        )
    }
    .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
    let mut fields = Vec::with_capacity(parameters.len());
    let mut input_length = 0usize;
    let mut counters = 0;
    let mut lengths = 0;
    for data in parameters {
        let (field, size) = match data.type_ {
            x if x == CK_SP800_108_ITERATION_VARIABLE as CK_PRF_DATA_TYPE => {
                let counter =
                    parameter::<CK_SP800_108_COUNTER_FORMAT>(data.pValue, data.ulValueLen)?;
                let format = format(counter.ulWidthInBits, counter.bLittleEndian, 32)?;
                counters += 1;
                (
                    CounterKdfField::Counter(format),
                    usize::from(format.width_bits / 8),
                )
            }
            x if x == CK_SP800_108_DKM_LENGTH as CK_PRF_DATA_TYPE => {
                let length =
                    parameter::<CK_SP800_108_DKM_LENGTH_FORMAT>(data.pValue, data.ulValueLen)?;
                let format = format(length.ulWidthInBits, length.bLittleEndian, 64)?;
                let method = match length.dkmLengthMethod {
                    x if x == CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS as CK_ULONG => LengthMethod::Key,
                    x if x == CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS as CK_ULONG => {
                        LengthMethod::Segments
                    }
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
                };
                lengths += 1;
                (
                    CounterKdfField::Length(format, method),
                    usize::from(format.width_bits / 8),
                )
            }
            x if x == CK_SP800_108_BYTE_ARRAY as CK_PRF_DATA_TYPE => {
                if data.ulValueLen == 0 || data.ulValueLen > 65536 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
                let bytes = unsafe {
                    from_raw_parts(
                        data.pValue.cast::<u8>().cast_const(),
                        data.ulValueLen as usize,
                    )
                }
                .map_err(|_| Error::from(CKR_MECHANISM_PARAM_INVALID))?;
                (CounterKdfField::Bytes(bytes), bytes.len())
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
        };
        input_length = input_length
            .checked_add(size)
            .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        if input_length > 65536 {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        fields.push(field);
    }
    if counters != 1 || lengths > 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(fields)
}

pub(super) fn derive(
    session: CK_SESSION_HANDLE,
    mechanism: &CK_MECHANISM,
    base_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    output: &mut CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    let fields = fields(mechanism)?;
    let template = unsafe { from_raw_parts(template, count as usize) }?;
    validate_unique_template(template)?;
    with_session_context_mut(session, |ctx| {
        let (slot, flags, logged_in) = ctx.session_details(session)?;
        require_slot_mechanism(ctx, slot, mechanism.mechanism, CKF_DERIVE as CK_FLAGS)?;
        let base = ctx
            .resolve_object(base_handle)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        let key = crate::software_key_ops::counter_base_key(&base)?;
        let mut merged = merge_policy_template(template, base.policy_templates.derive.as_ref())?;
        let template = merged.as_slice();
        if template.iter().any(|a| matches!(a.type_, x if x == CKA_VALUE as CK_ATTRIBUTE_TYPE
            || x == CKA_LOCAL as CK_ATTRIBUTE_TYPE || x == CKA_KEY_GEN_MECHANISM as CK_ATTRIBUTE_TYPE
            || x == CKA_ALWAYS_SENSITIVE as CK_ATTRIBUTE_TYPE || x == CKA_NEVER_EXTRACTABLE as CK_ATTRIBUTE_TYPE)) {
            return Err(CKR_ATTRIBUTE_READ_ONLY.into());
        }
        let key_type = template
            .iter()
            .find(|a| a.type_ == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE)
            .map(read_ulong_template_attribute)
            .transpose()
            .map_err(Error::from)?;
        let requested_length = template
            .iter()
            .find(|a| a.type_ == CKA_VALUE_LEN as CK_ATTRIBUTE_TYPE)
            .map(read_ulong_template_attribute)
            .transpose()
            .map_err(Error::from)?;
        // The PRF output size does not determine the requested key size.
        let length = requested_length
            .or((key_type == Some(CKK_DES3 as CK_KEY_TYPE)).then_some(24))
            .ok_or(CKR_TEMPLATE_INCOMPLETE)? as usize;
        let (object, length) = derived_secret_object(template, length, 1024)?;
        validate_new_object_access(&object, flags, logged_in)?;
        let object = crate::software_key_ops::derive_counter_key_with(
            &base,
            &fields,
            object,
            length,
            |input| {
                key.cmac(input, |id| {
                    crate::api::crypt::yubihsm_aes_cmac(ctx, session, id, input)
                })
            },
        )?;
        *output = publish_software_secret_object(ctx, session, slot, object)?;
        Ok(())
    })
}
