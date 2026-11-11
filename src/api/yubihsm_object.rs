use crate::*;

/// Publish an already-created native object, or remove it if discovery or
/// metadata persistence fails. The native type and ID remain authoritative;
/// PKCS #11 attribute changes must not change the object being published.
pub(super) fn publish_yubihsm_created_object<S: Slot + ?Sized>(
    slot: &mut S,
    ctx: &mut crate::context::SlotState,
    slot_id: CK_SLOT_ID,
    id: u16,
    object_type: u8,
    attributes: Option<(&TokenObject, bool)>,
) -> Result<(CK_OBJECT_HANDLE, TokenObject), Error> {
    let result = (|| {
        ctx.refresh_slot_token_objects(slot, slot_id)?;
        let find = |ctx: &crate::context::SlotState, slot: &S| {
            ctx.find_token_object(slot, |object| {
                object.slot_id == Some(slot_id)
                    && attributes.is_none_or(|(requested, _)| requested.class == object.class)
                    && matches!(object.material, KeyMaterial::YubiHsm {
                        id: candidate_id, object_type: candidate_type, ..
                    } if candidate_id == id && candidate_type == object_type)
            })?
            .ok_or_else(|| Error::from(CKR_DEVICE_ERROR))
        };
        let published = find(ctx, slot)?;
        if let Some((requested, id_supplied)) = attributes {
            set_yubihsm_attributes_and_refresh(
                slot,
                ctx,
                slot_id,
                &published.1.unique_id,
                id_supplied.then_some(requested.id.as_slice()),
                (!requested.label.is_empty()).then_some(requested.label.as_str()),
                Some(requested),
            )?;
            return find(ctx, slot);
        }
        Ok(published)
    })();
    if result.is_err() {
        rollback_yubihsm_created_object(slot, ctx, slot_id, id, object_type);
    }
    result
}

/// Refresh even after a failed write, preserving the write error's precedence.
pub(super) fn set_yubihsm_attributes_and_refresh<S: Slot + ?Sized>(
    slot: &mut S,
    ctx: &mut crate::context::SlotState,
    slot_id: CK_SLOT_ID,
    unique_id: &str,
    id: Option<&[u8]>,
    label: Option<&str>,
    attributes: Option<&TokenObject>,
) -> Result<(), Error> {
    let result = ctx
        .get_slot(slot, slot_id)?
        .yubihsm_set_attributes(slot_id, unique_id, id, label, attributes);
    let refresh = ctx.refresh_slot_token_objects(slot, slot_id);
    result?;
    refresh
}

pub(super) fn rollback_yubihsm_created_object<S: Slot + ?Sized>(
    slot: &mut S,
    ctx: &mut crate::context::SlotState,
    slot_id: CK_SLOT_ID,
    id: u16,
    object_type: u8,
) {
    if let Err(error) = ctx
        .get_slot(slot, slot_id)
        .and_then(|backend| backend.yubihsm_rollback_created_object(id, object_type))
    {
        tracing::warn!(target: "pkcs11rs::storage", ?error,
            "Failed to roll back an unpublished YubiHSM object; reload required");
    }
    let _ = ctx.refresh_slot_token_objects(slot, slot_id);
}
