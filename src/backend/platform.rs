//! Platform-protected ECDH token keys with ordinary software session objects.
use crate::platform_crypto::{
    EcdhCredential, PlatformAuthenticationCredential, PlatformCryptoError,
};
use crate::*;

pub(crate) const PLATFORM_SERIAL: &str = "PLATFORM00000001";

type NamedPlatformKey = (String, Arc<dyn EcdhCredential>);

pub(crate) struct PlatformSlot {
    // None enumerates the managed OS store. Fixtures supply native-key handles
    // through exactly the same object projection and mechanism dispatch.
    keys: Option<Vec<NamedPlatformKey>>,
    objects: RefCell<Option<Vec<TokenObject>>>,
    logged_in: bool,
}
impl PlatformSlot {
    pub(crate) fn new() -> Result<Self, Error> {
        if !cfg!(any(target_os = "macos", target_os = "ios")) {
            return Err(CKR_FUNCTION_NOT_SUPPORTED.into());
        }
        Ok(Self {
            keys: None,
            objects: RefCell::new(None),
            logged_in: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn with_keys(keys: Vec<NamedPlatformKey>) -> Self {
        Self {
            keys: Some(keys),
            objects: RefCell::new(None),
            logged_in: false,
        }
    }
    fn keys(&self) -> Result<Vec<NamedPlatformKey>, Error> {
        if let Some(keys) = &self.keys {
            return Ok(keys.clone());
        }
        crate::platform_crypto::list_platform_credentials()
            .map_err(platform_error)?
            .into_iter()
            .map(|info| {
                let PlatformAuthenticationCredential::Asymmetric(key) =
                    crate::platform_crypto::resolve_platform_credential(&info.name)
                        .map_err(platform_error)?
                else {
                    return Err(CKR_KEY_TYPE_INCONSISTENT.into());
                };
                Ok((info.name, key))
            })
            .collect()
    }
}
impl std::fmt::Debug for PlatformSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformSlot").finish_non_exhaustive()
    }
}
pub(crate) fn platform_error(error: PlatformCryptoError) -> Error {
    match error {
        PlatformCryptoError::Unsupported => CKR_FUNCTION_NOT_SUPPORTED.into(),
        PlatformCryptoError::NotFound => CKR_KEY_HANDLE_INVALID.into(),
        PlatformCryptoError::InvalidPublicKey => CKR_PUBLIC_KEY_INVALID.into(),
        PlatformCryptoError::InvalidName | PlatformCryptoError::Ambiguous => {
            CKR_TEMPLATE_INCONSISTENT.into()
        }
        _ => CKR_DEVICE_ERROR.into(),
    }
}
impl Slot for PlatformSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn kind(&self) -> SlotKind {
        SlotKind::Platform
    }
    fn physical_device_key(&self) -> Option<crate::device::PhysicalDeviceKey> {
        None
    }
    fn name(&self) -> String {
        "pkcs11rs platform slot".to_owned()
    }
    fn manufacturer(&self) -> &str {
        "pkcs11rs"
    }
    fn product(&self) -> &str {
        "Platform ECDH"
    }
    fn serial(&self) -> &str {
        PLATFORM_SERIAL
    }
    fn major(&self) -> u8 {
        1
    }
    fn minor(&self) -> u8 {
        0
    }
    fn hardware_major(&self) -> u8 {
        0
    }
    fn is_present(&self) -> bool {
        true
    }
    fn login_is_active(&self) -> bool {
        self.logged_in
    }
    fn clear_session(&mut self) {
        self.logged_in = false;
    }
    fn flags(&self) -> CK_FLAGS {
        CKF_TOKEN_PRESENT as _
    }
    fn label(&self) -> String {
        "Platform".to_owned()
    }
    fn model(&self) -> &str {
        "Platform ECDH"
    }
    fn supports_public_certificates_token_profile(&self, _slot_id: CK_SLOT_ID) -> bool {
        true
    }
    fn supports_login_user(&self) -> bool {
        true
    }
    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        if !pin.is_empty() {
            return Err(CKR_PIN_INCORRECT.into());
        }
        self.logged_in = true;
        Ok(())
    }
    fn login_without_pin(&mut self, _pinentry: &pinentry::Pinentry) -> Result<(), Error> {
        self.login(&[])
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.logged_in = false;
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(PlatformSession { slot_id, flags })
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = CKF_TOKEN_PRESENT as _;
        info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        str_pad("Platform", &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.product(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        // Empty-PIN login gates private objects; OS access control still governs key use.
        // Persistent provisioning remains in the platform management API.
        info.flags = (CKF_TOKEN_INITIALIZED
            | CKF_RNG
            | CKF_WRITE_PROTECTED
            | CKF_LOGIN_REQUIRED
            | CKF_USER_PIN_INITIALIZED) as _;
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as _;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as _;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 0;
        info.ulMinPinLen = 0;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as _;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as _;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as _;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as _;
        info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
        info.utcTime.fill(b' ');
        Ok(())
    }
    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        [CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE]
            .into_iter()
            .map(|kind| MechanismDetails {
                type_: kind as _,
                min_key_size: 256,
                max_key_size: 256,
                flags: (CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
                    as _,
            })
            .collect()
    }
    fn refresh_token_objects_before_find(&self) -> bool {
        true
    }
    fn refresh(&self) -> Result<(), Error> {
        *self.objects.borrow_mut() = None;
        Ok(())
    }
    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if let Some(objects) = self.objects.borrow().as_ref() {
            return Ok(objects.clone());
        }
        let mut objects = Vec::new();
        for (name, key) in self.keys()? {
            let public = key.public_key().map_err(platform_error)?;
            public
                .validate()
                .map_err(|_| Error::from(CKR_PUBLIC_KEY_INVALID))?;
            let SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                uncompressed,
            } = public
            else {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            };
            let id = hash(MessageDigest::Sha256, &uncompressed)?;
            let identity = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let public = PublicKeyMaterial::Ec {
                parameters: ec_curve_parameters(EcCurve::P256).to_vec(),
                public_key: uncompressed[1..].to_vec(),
            };
            for certificate in key.certificates().map_err(platform_error)? {
                if crate::certificate_chain::public_key_info(&certificate)?
                    != crate::ec_public_key_info(
                        CKK_EC as _,
                        Some(ec_curve_parameters(EcCurve::P256)),
                        &uncompressed[1..],
                    )
                    .ok_or(CKR_DATA_INVALID)?
                {
                    return Err(CKR_PUBLIC_KEY_INVALID.into());
                }
                let fingerprint = hash(MessageDigest::Sha256, &certificate)?;
                let mut object = super::traits::profile_token_object(slot_id, 0);
                object.unique_id =
                    format!("platform:{name}:{identity}:certificate:{fingerprint:x?}");
                object.class = CKO_CERTIFICATE as _;
                object.label = name.clone();
                object.id = id.clone();
                object.material = KeyMaterial::Certificate {
                    instance: [0; 16],
                    value: Zeroizing::new(certificate),
                };
                objects.push(object);
            }
            let mut private = super::traits::profile_token_object(slot_id, 0);
            private.unique_id = format!("platform:{name}:{identity}:private");
            private.class = CKO_PRIVATE_KEY as _;
            private.key_type = CKK_EC as _;
            private.label = name;
            private.id = id;
            private.private = true;
            private.derive = true;
            private.sensitive = true;
            private.always_sensitive = true;
            private.never_extractable = true;
            private.key_gen_mechanism = Some(CKM_EC_KEY_PAIR_GEN as _);
            private.allowed_mechanisms =
                Some(vec![CKM_ECDH1_DERIVE as _, CKM_ECDH1_COFACTOR_DERIVE as _]);
            private.public_key = Some(public.clone());
            private.material = KeyMaterial::PlatformPrivate(key);
            let mut projected = private.clone();
            projected.unique_id = format!("platform:{}:{identity}:public", private.label);
            projected.class = CKO_PUBLIC_KEY as _;
            projected.private = false;
            projected.derive = false;
            projected.sensitive = false;
            projected.always_sensitive = false;
            projected.never_extractable = false;
            projected.extractable = true;
            projected.allowed_mechanisms = None;
            projected.material = KeyMaterial::Public(public);
            objects.extend([projected, private]);
        }
        *self.objects.borrow_mut() = Some(objects.clone());
        Ok(objects)
    }
}
#[derive(Debug)]
struct PlatformSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}
impl BackendSession for PlatformSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
