use crate::storage::ContentReference;
use crate::*;
use std::{cell::RefCell, collections::HashMap, path::PathBuf, rc::Rc};
use zeroize::Zeroizing;

const SOFTWARE_SLOT_DESCRIPTION_PREFIX: &str = "pkcs11rs software slot: ";
const SOFTWARE_MANUFACTURER: &str = "pkcs11rs";
const SOFTWARE_MODEL: &str = "Software";

pub(crate) struct SoftwareSlot {
    name: String,
    serial: String,
    store: Option<SoftwareTokenStore>,
    public_provider: Option<crate::software_storage::SoftwarePublicStorageProvider>,
    active_public_key: Rc<RefCell<Option<Zeroizing<[u8; 32]>>>>,
    public_master_key: Option<Zeroizing<[u8; 32]>>,
    private_master_key: Option<Zeroizing<[u8; 32]>>,
    token_objects: Vec<TokenObject>,
    token_references: HashMap<String, ContentReference>,
    logged_in: bool,
}

#[derive(Debug)]
struct SoftwareSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

impl SoftwareSlot {
    #[cfg(test)]
    pub(crate) fn new(name: String, ordinal: usize) -> Self {
        Self {
            name,
            serial: format!("SOFTWARE{ordinal:08}"),
            store: None,
            public_provider: None,
            active_public_key: Rc::new(RefCell::new(None)),
            public_master_key: None,
            private_master_key: None,
            token_objects: Vec::new(),
            token_references: HashMap::new(),
            logged_in: false,
        }
    }

    pub(crate) fn new_with_storage(
        name: String,
        ordinal: usize,
        token_root: Option<PathBuf>,
        discovery_pin: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let active_public_key = Rc::new(RefCell::new(None));
        let store = token_root
            .clone()
            .map(|root| SoftwareTokenStore::open(name.clone(), root, discovery_pin.clone()))
            .transpose()?;
        let public_provider = token_root
            .map(|root| {
                crate::software_storage::SoftwarePublicStorageProvider::open(
                    name.clone(),
                    root,
                    discovery_pin,
                    active_public_key.clone(),
                )
            })
            .transpose()?;
        Ok(Self {
            name,
            serial: format!("SOFTWARE{ordinal:08}"),
            store,
            public_provider,
            active_public_key,
            public_master_key: None,
            private_master_key: None,
            token_objects: Vec::new(),
            token_references: HashMap::new(),
            logged_in: false,
        })
    }

    fn description(&self) -> String {
        format!("{SOFTWARE_SLOT_DESCRIPTION_PREFIX}{}", self.name)
    }

    fn clear_sensitive_state(&mut self) {
        self.token_objects.clear();
        self.token_references.clear();
        self.public_master_key = None;
        self.private_master_key = None;
        if let Ok(mut key) = self.active_public_key.try_borrow_mut() {
            *key = None;
        }
        self.logged_in = false;
    }
}

impl std::fmt::Debug for SoftwareSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareSlot")
            .field("name", &self.name)
            .field("serial", &self.serial)
            .field("persistent_store", &self.store.is_some())
            .field("logged_in", &self.logged_in)
            .field("token_object_count", &self.token_objects.len())
            .finish()
    }
}

impl Slot for SoftwareSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn kind(&self) -> SlotKind {
        SlotKind::Software
    }

    fn physical_device_key(&self) -> Option<crate::device::PhysicalDeviceKey> {
        None
    }

    fn native_storage_provider(&self) -> Option<&dyn crate::storage::StorageProvider> {
        self.public_provider
            .as_ref()
            .map(|provider| provider as &dyn crate::storage::StorageProvider)
    }

    fn name(&self) -> String {
        self.description()
    }

    fn manufacturer(&self) -> &str {
        SOFTWARE_MANUFACTURER
    }

    fn product(&self) -> &str {
        SOFTWARE_MODEL
    }

    fn serial(&self) -> &str {
        &self.serial
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

    fn hardware_minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        true
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(SoftwareSession { slot_id, flags })
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        crate::software_storage::validate_software_pin(pin)?;
        self.clear_sensitive_state();
        if let Some(store) = &self.store {
            let (public_master_key, private_master_key) = store.login(pin)?;
            let (objects, references) = store.load_objects(0, &private_master_key)?;
            self.public_master_key = Some(public_master_key);
            self.private_master_key = Some(private_master_key);
            *self.active_public_key.borrow_mut() = self.public_master_key.clone();
            self.token_objects = objects;
            self.token_references = references;
        }
        self.logged_in = true;
        Ok(())
    }

    fn login_so(&mut self, pin: &[u8]) -> Result<(), Error> {
        crate::software_storage::validate_software_pin(pin)?;
        self.clear_sensitive_state();
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        self.public_master_key = Some(store.login_so(pin)?);
        *self.active_public_key.borrow_mut() = self.public_master_key.clone();
        self.logged_in = true;
        Ok(())
    }

    fn logout(&mut self) -> Result<(), Error> {
        if !self.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        self.clear_sensitive_state();
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        str_pad(&self.description(), &mut info.slotDescription);
        str_pad(SOFTWARE_MANUFACTURER, &mut info.manufacturerID);
        info.flags = CKF_TOKEN_PRESENT as CK_FLAGS;
        info.hardwareVersion.major = 0;
        info.hardwareVersion.minor = 0;
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        if let Some(label) = self
            .store
            .as_ref()
            .and_then(|store| store.label().ok())
            .flatten()
        {
            info.label = label;
        } else {
            str_pad(&self.name, &mut info.label);
        }
        str_pad(SOFTWARE_MANUFACTURER, &mut info.manufacturerID);
        str_pad(SOFTWARE_MODEL, &mut info.model);
        str_pad(&self.serial, &mut info.serialNumber);
        info.flags = (CKF_RNG | CKF_LOGIN_REQUIRED) as CK_FLAGS;
        match &self.store {
            Some(store) if store.is_initialized()? => {
                info.flags |= CKF_TOKEN_INITIALIZED as CK_FLAGS;
                if store.user_pin_is_initialized()? {
                    info.flags |= CKF_USER_PIN_INITIALIZED as CK_FLAGS;
                }
            }
            None => info.flags |= CKF_TOKEN_INITIALIZED as CK_FLAGS,
            Some(_) => {}
        }
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 1024;
        info.ulMinPinLen = 8;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.hardwareVersion.major = 0;
        info.hardwareVersion.minor = 0;
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
        Ok(())
    }

    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }

    fn supports_software_private_operations(&self) -> bool {
        true
    }

    fn supports_software_secret_operations(&self) -> bool {
        true
    }

    fn supports_software_digest_operations(&self) -> bool {
        true
    }

    fn private_objects_require_login(&self) -> bool {
        true
    }

    fn refresh_token_objects_after_login(&self) -> bool {
        true
    }

    fn refresh_token_objects_after_logout(&self) -> bool {
        true
    }

    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if !self.logged_in {
            return Ok(Vec::new());
        }
        let mut objects = self.token_objects.clone();
        for object in &mut objects {
            object.slot_id = Some(slot_id);
        }
        Ok(objects)
    }

    fn backend_token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        if !self.logged_in {
            return Ok(None);
        }
        Ok(self
            .token_objects
            .iter()
            .find(|object| object.unique_id == unique_id)
            .cloned()
            .map(|mut object| {
                object.slot_id = Some(slot_id);
                object
            }))
    }

    fn store_software_private_object(
        &mut self,
        slot_id: CK_SLOT_ID,
        object: &TokenObject,
    ) -> Result<TokenObject, Error> {
        if !self.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        let master_key = self
            .private_master_key
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let (stored, reference) = store.put_object(slot_id, master_key, object)?;
        self.token_references
            .insert(stored.unique_id.clone(), reference);
        self.token_objects.push(stored.clone());
        Ok(stored)
    }

    fn destroy_software_private_object(&mut self, unique_id: &str) -> Result<(), Error> {
        if !self.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        let reference = self
            .token_references
            .get(unique_id)
            .cloned()
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        store.delete_object(&reference)?;
        self.token_references.remove(unique_id);
        self.token_objects
            .retain(|object| object.unique_id != unique_id);
        Ok(())
    }

    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        store.change_pin(old_pin, new_pin)
    }

    fn set_so_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        store.change_so_pin(old_pin, new_pin)
    }

    fn init_user_pin(&mut self, new_pin: &[u8]) -> Result<(), Error> {
        crate::software_storage::validate_software_pin(new_pin)?;
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        let public = self
            .public_master_key
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        store.init_user_pin(new_pin, public)
    }

    fn init_token(&mut self, so_pin: &[u8], label: [CK_UTF8CHAR; 32]) -> Result<(), Error> {
        self.clear_sensitive_state();
        let store = self.store.as_ref().ok_or(CKR_TOKEN_WRITE_PROTECTED)?;
        if store.is_initialized()? {
            let _ = store.login_so(so_pin)?;
        }
        if let Some(provider) = &self.public_provider {
            provider.clear()?;
        }
        let _ = store.init_token(so_pin, label)?;
        Ok(())
    }

    fn login_is_active(&self) -> bool {
        self.logged_in
    }

    fn clear_session(&mut self) {
        self.clear_sensitive_state();
    }

    fn flags(&self) -> CK_FLAGS {
        CKF_TOKEN_PRESENT as CK_FLAGS
    }

    fn label(&self) -> String {
        self.name.clone()
    }

    fn model(&self) -> &str {
        SOFTWARE_MODEL
    }
}

impl BackendSession for SoftwareSession {
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
mod tests {
    use super::*;

    #[test]
    fn metadata_identifies_a_non_hardware_slot() {
        let slot = SoftwareSlot::new(String::from("signing"), 3);
        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert_eq!(slot_info.flags, CKF_TOKEN_PRESENT as CK_FLAGS);
        assert_eq!(slot_info.flags & CKF_HW_SLOT as CK_FLAGS, 0);
        assert_eq!(
            &slot_info.slotDescription[..b"pkcs11rs software slot: signing".len()],
            b"pkcs11rs software slot: signing"
        );

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert_eq!(
            token_info.flags,
            (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED) as CK_FLAGS
        );
        assert_eq!(&token_info.label[..b"signing".len()], b"signing");
        assert_eq!(&token_info.serialNumber, b"SOFTWARE00000003");
        assert_eq!(token_info.ulMinPinLen, 8);
        assert_eq!(token_info.ulMaxPinLen, 1024);
    }

    #[test]
    fn mechanisms_are_the_exact_software_union_without_hardware_flags() {
        let slot = SoftwareSlot::new(String::from("mechanism-test"), 0);
        assert!(slot.supports_software_secret_operations());
        let mechanisms = Slot::mechanisms(&slot);
        assert_eq!(mechanisms.len(), 79);
        assert_eq!(
            mechanisms
                .iter()
                .map(|mechanism| mechanism.type_)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            mechanisms.len()
        );
        assert!(mechanisms
            .iter()
            .all(|mechanism| mechanism.flags & CKF_HW as CK_FLAGS == 0));
        assert!(mechanisms
            .iter()
            .any(|mechanism| mechanism.type_ == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE));

        for mechanism in mechanisms {
            let (min, max, flags) = match mechanism.type_ {
                x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
                    (1024, 4096, CKF_GENERATE_KEY_PAIR)
                }
                x if x == CKM_RSA_X_509 as CK_MECHANISM_TYPE => (
                    1024,
                    4096,
                    CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY,
                ),
                x if x == CKM_RSA_PKCS as CK_MECHANISM_TYPE => (
                    1024,
                    4096,
                    CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP,
                ),
                x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => (
                    1024,
                    4096,
                    CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
                ),
                x if x == CKM_RSA_AES_KEY_WRAP as CK_MECHANISM_TYPE => {
                    (1024, 4096, CKF_WRAP | CKF_UNWRAP)
                }
                x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                    || [
                        CKM_SHA1_RSA_PKCS,
                        CKM_SHA224_RSA_PKCS,
                        CKM_SHA256_RSA_PKCS,
                        CKM_SHA384_RSA_PKCS,
                        CKM_SHA512_RSA_PKCS,
                        CKM_SHA3_224_RSA_PKCS,
                        CKM_SHA3_256_RSA_PKCS,
                        CKM_SHA3_384_RSA_PKCS,
                        CKM_SHA3_512_RSA_PKCS,
                        CKM_SHA1_RSA_PKCS_PSS,
                        CKM_SHA224_RSA_PKCS_PSS,
                        CKM_SHA256_RSA_PKCS_PSS,
                        CKM_SHA384_RSA_PKCS_PSS,
                        CKM_SHA512_RSA_PKCS_PSS,
                        CKM_SHA3_224_RSA_PKCS_PSS,
                        CKM_SHA3_256_RSA_PKCS_PSS,
                        CKM_SHA3_384_RSA_PKCS_PSS,
                        CKM_SHA3_512_RSA_PKCS_PSS,
                    ]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (1024, 4096, CKF_SIGN | CKF_VERIFY)
                }
                x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => (
                    224,
                    521,
                    CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE,
                ),
                x if [
                    CKM_ECDSA,
                    CKM_ECDSA_SHA1,
                    CKM_ECDSA_SHA224,
                    CKM_ECDSA_SHA256,
                    CKM_ECDSA_SHA384,
                    CKM_ECDSA_SHA512,
                    CKM_ECDSA_SHA3_224,
                    CKM_ECDSA_SHA3_256,
                    CKM_ECDSA_SHA3_384,
                    CKM_ECDSA_SHA3_512,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    (
                        224,
                        521,
                        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE,
                    )
                }
                x if [CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (224, 521, CKF_DERIVE)
                }
                x if [CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (
                        255,
                        255,
                        CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME,
                    )
                }
                x if x == CKM_EDDSA as CK_MECHANISM_TYPE => (255, 255, CKF_SIGN | CKF_VERIFY),
                x if x == CKM_PKCS11RS_PROJECT_PUBLIC_KEY => (0, 0, CKF_DERIVE),
                x if x == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE => {
                    (1, 1024, CKF_GENERATE)
                }
                x if x == CKM_AES_KEY_GEN as CK_MECHANISM_TYPE => (16, 32, CKF_GENERATE),
                x if x == CKM_DES3_KEY_GEN as CK_MECHANISM_TYPE => (24, 24, CKF_GENERATE),
                x if x == CKM_PKCS5_PBKD2 as CK_MECHANISM_TYPE => (1, 1024, CKF_GENERATE),
                x if x == CKM_HKDF_DERIVE as CK_MECHANISM_TYPE => (20, 64, CKF_DERIVE),
                x if [
                    CKM_AES_ECB,
                    CKM_AES_CBC,
                    CKM_AES_CBC_PAD,
                    CKM_AES_CTR,
                    CKM_AES_CCM,
                    CKM_AES_GCM,
                    CKM_AES_KEY_WRAP,
                    CKM_AES_KEY_WRAP_KWP,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    let mut flags = CKF_ENCRYPT | CKF_DECRYPT;
                    if matches!(x, y if y == CKM_AES_KEY_WRAP as CK_MECHANISM_TYPE
                        || y == CKM_AES_KEY_WRAP_KWP as CK_MECHANISM_TYPE)
                    {
                        flags |= CKF_WRAP | CKF_UNWRAP;
                    }
                    (16, 32, flags)
                }
                x if [CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (24, 24, CKF_ENCRYPT | CKF_DECRYPT)
                }
                x if [CKM_AES_CMAC, CKM_AES_CMAC_GENERAL, CKM_AES_GMAC]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (16, 32, CKF_SIGN | CKF_VERIFY)
                }
                x if [
                    CKM_SHA_1_HMAC,
                    CKM_SHA_1_HMAC_GENERAL,
                    CKM_SHA224_HMAC,
                    CKM_SHA224_HMAC_GENERAL,
                    CKM_SHA256_HMAC,
                    CKM_SHA256_HMAC_GENERAL,
                    CKM_SHA384_HMAC,
                    CKM_SHA384_HMAC_GENERAL,
                    CKM_SHA512_HMAC,
                    CKM_SHA512_HMAC_GENERAL,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    (1, 1024, CKF_SIGN | CKF_VERIFY)
                }
                x if [
                    CKM_SHA_1,
                    CKM_SHA224,
                    CKM_SHA256,
                    CKM_SHA384,
                    CKM_SHA512,
                    CKM_SHA3_224,
                    CKM_SHA3_256,
                    CKM_SHA3_384,
                    CKM_SHA3_512,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    (0, 0, CKF_DIGEST)
                }
                other => panic!("unexpected software mechanism {other:#x}"),
            };
            assert_eq!(mechanism.min_key_size, min as CK_ULONG);
            assert_eq!(mechanism.max_key_size, max as CK_ULONG);
            assert_eq!(mechanism.flags, flags as CK_FLAGS);
        }
    }
}
