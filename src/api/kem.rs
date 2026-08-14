use super::key::derived_secret_object;
use super::object::{publish_software_secret_object, validate_unique_template};
use crate::*;
use ml_kem::kem::Decapsulate;
use zeroize::Zeroizing;

const ML_KEM_SHARED_SECRET_LENGTH: usize = 32;

ffi_entry_point! {
    pub fn C_EncapsulateKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        public_key: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        attribute_count: CK_ULONG,
        ciphertext: CK_BYTE_PTR,
        ciphertext_len: CK_ULONG_PTR,
        key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        map(encapsulate_key(
            session_handle,
            mechanism,
            public_key,
            templ,
            attribute_count,
            ciphertext,
            ciphertext_len,
            key,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn encapsulate_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    public_key: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG_PTR,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let mechanism = unsafe { _as_ref(mechanism) }?;
    require_ml_kem_mechanism(mechanism)?;
    let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
    validate_unique_template(templ)?;
    let ciphertext_len = unsafe { as_mut(ciphertext_len) }?;

    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        require_slot_mechanism(
            ctx,
            slot_id,
            mechanism.mechanism,
            CKF_ENCAPSULATE as CK_FLAGS,
        )?;
        let public = ctx
            .resolve_object(public_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        require_key_mechanism(&public, mechanism.mechanism)?;
        if public.class != CKO_PUBLIC_KEY as CK_OBJECT_CLASS
            || public.key_type != CKK_ML_KEM as CK_KEY_TYPE
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if !public.encapsulate {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let public_material = public.projected_public_key()?;
        let required = ml_kem_ciphertext_length(&public_material)?;
        if ciphertext.is_null() {
            *ciphertext_len = required as CK_ULONG;
            return Ok(());
        }
        if (*ciphertext_len as usize) < required {
            *ciphertext_len = required as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL.into());
        }
        let key_handle = unsafe { as_mut(key) }?;
        let output = unsafe { _from_raw_parts_mut(ciphertext, required) }?;
        let (encapsulated, shared) = ml_kem_encapsulate(&public_material)?;
        let object = ml_kem_secret_object(templ, shared, flags, logged_in, mechanism.mechanism)?;
        *key_handle = publish_software_secret_object(ctx, session_handle, slot_id, object)?;
        output.copy_from_slice(&encapsulated);
        *ciphertext_len = required as CK_ULONG;
        Ok(())
    })
}

ffi_entry_point! {
    pub fn C_DecapsulateKey(
        session_handle: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        private_key: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        attribute_count: CK_ULONG,
        ciphertext: CK_BYTE_PTR,
        ciphertext_len: CK_ULONG,
        key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        map(decapsulate_key(
            session_handle,
            mechanism,
            private_key,
            templ,
            attribute_count,
            ciphertext,
            ciphertext_len,
            key,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn decapsulate_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    private_key: CK_OBJECT_HANDLE,
    templ: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG,
    key: CK_OBJECT_HANDLE_PTR,
) -> Result<(), Error> {
    let mechanism = unsafe { _as_ref(mechanism) }?;
    require_ml_kem_mechanism(mechanism)?;
    let templ = unsafe { from_raw_parts(templ, attribute_count as usize) }?;
    validate_unique_template(templ)?;
    let ciphertext = unsafe { from_raw_parts(ciphertext, ciphertext_len as usize) }?;
    let key_handle = unsafe { as_mut(key) }?;

    with_session_context_mut(session_handle, |ctx| {
        let (slot_id, flags, logged_in) = ctx.session_details(session_handle)?;
        require_slot_mechanism(
            ctx,
            slot_id,
            mechanism.mechanism,
            CKF_DECAPSULATE as CK_FLAGS,
        )?;
        let private = ctx
            .resolve_object(private_key)?
            .filter(|object| object.is_visible_to(logged_in))
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        require_key_mechanism(&private, mechanism.mechanism)?;
        if private.class != CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            || private.key_type != CKK_ML_KEM as CK_KEY_TYPE
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if !private.decapsulate {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let KeyMaterial::SoftwarePrivate(material) = &private.material else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        let shared = ml_kem_decapsulate(material, ciphertext)?;
        let object = ml_kem_secret_object(templ, shared, flags, logged_in, mechanism.mechanism)?;
        *key_handle = publish_software_secret_object(ctx, session_handle, slot_id, object)?;
        Ok(())
    })
}

fn require_ml_kem_mechanism(mechanism: &CK_MECHANISM) -> Result<(), Error> {
    if mechanism.mechanism != CKM_ML_KEM as CK_MECHANISM_TYPE {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(())
}

fn ml_kem_ciphertext_length(public: &PublicKeyMaterial) -> Result<usize, Error> {
    match public {
        PublicKeyMaterial::MlKem { parameter_set, .. } => match *parameter_set {
            x if x == CKP_ML_KEM_512 as CK_ML_KEM_PARAMETER_SET_TYPE => Ok(768),
            x if x == CKP_ML_KEM_768 as CK_ML_KEM_PARAMETER_SET_TYPE => Ok(1088),
            x if x == CKP_ML_KEM_1024 as CK_ML_KEM_PARAMETER_SET_TYPE => Ok(1568),
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        },
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn ml_kem_encapsulate(public: &PublicKeyMaterial) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let PublicKeyMaterial::MlKem {
        parameter_set,
        public_key,
    } = public
    else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    let mut randomness = Zeroizing::new([0u8; 32]);
    getrandom::fill(randomness.as_mut()).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
    macro_rules! encapsulate {
        ($params:ty) => {{
            let encoded = ml_kem::kem::Key::<ml_kem::EncapsulationKey<$params>>::try_from(
                public_key.as_slice(),
            )
            .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
            let key = ml_kem::EncapsulationKey::<$params>::new(&encoded)
                .map_err(|_| Error::from(CKR_KEY_TYPE_INCONSISTENT))?;
            let (ciphertext, shared) =
                key.encapsulate_deterministic(&ml_kem::B32::from(*randomness));
            Ok((ciphertext.to_vec(), Zeroizing::new(shared.to_vec())))
        }};
    }
    match *parameter_set {
        x if x == CKP_ML_KEM_512 as CK_ML_KEM_PARAMETER_SET_TYPE => {
            encapsulate!(ml_kem::MlKem512)
        }
        x if x == CKP_ML_KEM_768 as CK_ML_KEM_PARAMETER_SET_TYPE => {
            encapsulate!(ml_kem::MlKem768)
        }
        x if x == CKP_ML_KEM_1024 as CK_ML_KEM_PARAMETER_SET_TYPE => {
            encapsulate!(ml_kem::MlKem1024)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn ml_kem_decapsulate(
    private: &SoftwarePrivateKeyMaterial,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    macro_rules! decapsulate {
        ($key:expr, $params:ty) => {{
            let ciphertext = ml_kem::kem::Ciphertext::<$params>::try_from(ciphertext)
                .map_err(|_| Error::from(CKR_ENCRYPTED_DATA_LEN_RANGE))?;
            Ok(Zeroizing::new($key.decapsulate(&ciphertext).to_vec()))
        }};
    }
    match private {
        SoftwarePrivateKeyMaterial::MlKem512(key) => decapsulate!(key, ml_kem::MlKem512),
        SoftwarePrivateKeyMaterial::MlKem768(key) => decapsulate!(key, ml_kem::MlKem768),
        SoftwarePrivateKeyMaterial::MlKem1024(key) => decapsulate!(key, ml_kem::MlKem1024),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn ml_kem_secret_object(
    templ: &[CK_ATTRIBUTE],
    shared: Zeroizing<Vec<u8>>,
    session_flags: CK_FLAGS,
    logged_in: bool,
    mechanism: CK_MECHANISM_TYPE,
) -> Result<TokenObject, Error> {
    let (mut object, requested_length) = derived_secret_object(
        templ,
        ML_KEM_SHARED_SECRET_LENGTH,
        ML_KEM_SHARED_SECRET_LENGTH,
        true,
    )?;
    if object.key_type == CKK_GENERIC_SECRET as CK_KEY_TYPE {
        if requested_length != ML_KEM_SHARED_SECRET_LENGTH {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
    } else if object.key_type != CKK_AES as CK_KEY_TYPE {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    validate_new_object_access(&object, session_flags, logged_in)?;
    object.material =
        KeyMaterial::SoftwareSecret(Zeroizing::new(shared[..requested_length].to_vec()));
    object.always_sensitive = false;
    object.never_extractable = false;
    object.local = false;
    object.key_gen_mechanism = Some(mechanism);
    Ok(object)
}
