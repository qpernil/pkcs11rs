use crate::*;

pub(crate) fn profile_token_object(slot_id: CK_SLOT_ID, profile_id: CK_PROFILE_ID) -> TokenObject {
    let label = match profile_id as u32 {
        CKP_BASELINE_PROVIDER => "PKCS #11 Baseline Provider",
        CKP_EXTENDED_PROVIDER => "PKCS #11 Extended Provider",
        CKP_AUTHENTICATION_TOKEN => "PKCS #11 Authentication Token",
        CKP_PUBLIC_CERTIFICATES_TOKEN => "PKCS #11 Public Certificates Token",
        _ => "PKCS #11 Profile",
    };
    TokenObject {
        slot_id: Some(slot_id),
        unique_id: format!("pkcs11-profile-{profile_id:08x}"),
        class: CKO_PROFILE as CK_OBJECT_CLASS,
        key_type: 0,
        label: label.to_owned(),
        id: Vec::new(),
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: false,
        always_sensitive: false,
        never_extractable: false,
        local: true,
        key_gen_mechanism: None,
        creator_session: None,
        material: KeyMaterial::Profile { profile_id },
    }
}

pub(crate) fn profile_token_objects(
    slot_id: CK_SLOT_ID,
    extended_provider: bool,
    authentication_token: bool,
    public_certificates_token: bool,
) -> Vec<TokenObject> {
    let mut profile_ids = vec![CKP_BASELINE_PROVIDER as CK_PROFILE_ID];
    if extended_provider {
        profile_ids.push(CKP_EXTENDED_PROVIDER as CK_PROFILE_ID);
    }
    if authentication_token {
        profile_ids.push(CKP_AUTHENTICATION_TOKEN as CK_PROFILE_ID);
    }
    if public_certificates_token {
        profile_ids.push(CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID);
    }
    profile_ids
        .into_iter()
        .map(|profile_id| profile_token_object(slot_id, profile_id))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotKind {
    #[cfg(any(test, feature = "abi-tests"))]
    Synthetic,
    YubiHsm,
    Fido2,
    Ccid(CcidApplication),
}

pub(crate) trait Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn device_context(&self) -> Option<Arc<crate::device::DeviceContext>> {
        None
    }
    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
        crate::device::DeviceOperationKind::Ccid
    }
    fn kind(&self) -> SlotKind;
    fn physical_device_key(&self) -> Option<crate::device::PhysicalDeviceKey> {
        None
    }
    fn native_storage_provider(&self) -> Option<&dyn crate::storage::StorageProvider> {
        None
    }
    fn native_storage_objects_are_backend_managed(&self) -> bool {
        false
    }
    fn name(&self) -> String;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn hardware_major(&self) -> u8 {
        1
    }
    fn hardware_minor(&self) -> u8 {
        0
    }
    fn is_present(&self) -> bool;
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession>;
    fn login(&mut self, pin: &[u8]) -> Result<(), Error>;
    fn login_with_pinentry(
        &mut self,
        pin: &[u8],
        _pinentry: &pinentry::Pinentry,
    ) -> Result<(), Error> {
        self.login(pin)
    }
    fn login_without_pin(&mut self, _pinentry: &pinentry::Pinentry) -> Result<(), Error> {
        Err(CKR_ARGUMENTS_BAD.into())
    }
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn hsmauth_provisioning_connector(&self) -> Option<Rc<dyn Connector>> {
        None
    }
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn security_domain_provisioning_connector(&self) -> Option<Rc<dyn Connector>> {
        None
    }
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn yubihsm_provisioning_connector(&self) -> Option<Rc<dyn Connector>> {
        None
    }
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn create_fido2_test_credential(
        &mut self,
        _pin: &[u8],
    ) -> Result<crate::ctap::VerifiedMakeCredential, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn create_fido2_preview_sign_test_registration(
        &mut self,
        _pin: &[u8],
    ) -> Result<crate::preview_sign::PreviewSignRegistration, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn fido_preview_sign_registration(
        &mut self,
    ) -> Result<crate::preview_sign::PreviewSignRegistration, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn fido_preview_sign(
        &mut self,
        _registration: &crate::preview_sign::PreviewSignRegistration,
        _to_be_signed: &[u8],
        _additional_args_cbor: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn fido_get_assertion(
        &mut self,
        _authorization: &crate::ctap::CredentialAuthorization,
        _rp_id: &str,
        _credential_id: &[u8],
        _client_data_hash: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn login_user(&mut self, _username: &[u8], _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn supports_login_user(&self) -> bool {
        false
    }
    fn login_user_without_pin(
        &mut self,
        _username: &[u8],
        _pinentry: &pinentry::Pinentry,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn login_so(&mut self, _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_USER_TYPE_INVALID.into())
    }
    fn login_so_without_pin(&mut self, _pinentry: &pinentry::Pinentry) -> Result<(), Error> {
        Err(CKR_ARGUMENTS_BAD.into())
    }
    fn set_pin(&mut self, _old_pin: &[u8], _new_pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn set_so_pin(&mut self, _old_pin: &[u8], _new_pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn init_user_pin(&mut self, _new_pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn login_context_specific(
        &mut self,
        _pin: &[u8],
        _extended: bool,
        _rp_id: Option<&str>,
    ) -> Result<Option<crate::ctap::CredentialAuthorization>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn logout(&mut self) -> Result<(), Error>;
    fn init_slot(&mut self) -> Result<(), Error>;
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error>;
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error>;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }
    #[allow(dead_code)]
    fn set_applet_present(&self, _present: bool) {}
    fn set_discovery_error(&self, _error: &Error) {}
    fn clear_discovery_error(&self) {}
    fn clear_session(&mut self) {}
    fn supports_extended_provider_profile(&self) -> bool {
        false
    }
    fn supports_authentication_token_profile(&self) -> bool {
        self.mechanisms().iter().any(|mechanism| {
            mechanism.type_ == CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE
                && mechanism.flags & CKF_SIGN as CK_FLAGS != 0
        })
    }
    fn supports_public_certificates_token_profile(&self, _slot_id: CK_SLOT_ID) -> bool {
        false
    }
    fn supports_protected_authentication_path(&self) -> bool {
        false
    }
    fn profile_objects(&self, slot_id: CK_SLOT_ID) -> Vec<TokenObject> {
        profile_token_objects(
            slot_id,
            self.supports_extended_provider_profile(),
            self.supports_authentication_token_profile(),
            self.supports_public_certificates_token_profile(slot_id),
        )
    }
    fn backend_token_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn refresh_token_objects_after_login(&self) -> bool {
        false
    }
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let mut objects = self.profile_objects(slot_id);
        objects.extend(self.backend_token_objects(slot_id)?);
        Ok(objects)
    }
    fn invalidate_token_objects(&self) {}
    #[allow(dead_code)]
    fn backend_token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        Ok(self
            .backend_token_objects(slot_id)?
            .into_iter()
            .find(|object| object.token && object.unique_id == unique_id))
    }
    #[allow(dead_code)]
    fn token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        if let Some(object) = self
            .profile_objects(slot_id)
            .into_iter()
            .find(|object| object.unique_id == unique_id)
        {
            return Ok(Some(object));
        }
        self.backend_token_object(slot_id, unique_id)
    }
    fn session_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        MECHANISMS.to_vec()
    }
    fn supports_software_public_operations(&self) -> bool {
        true
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        let mut mechanisms = self.backend_mechanisms();
        if self.supports_software_public_operations() {
            for software in software_public_mechanisms() {
                if let Some(existing) = mechanisms
                    .iter_mut()
                    .find(|mechanism| mechanism.type_ == software.type_)
                {
                    existing.min_key_size = existing.min_key_size.min(software.min_key_size);
                    existing.max_key_size = existing.max_key_size.max(software.max_key_size);
                    existing.flags |= software.flags;
                } else {
                    mechanisms.push(software);
                }
            }
        }
        for software in SOFTWARE_DIGEST_MECHANISMS {
            if !mechanisms
                .iter()
                .any(|mechanism| mechanism.type_ == software.type_)
            {
                mechanisms.push(software);
            }
        }
        mechanisms
    }
    fn yubihsm_read_opaque(&self, _id: u16) -> Result<Vec<u8>, Error> {
        Err(CKR_USER_NOT_LOGGED_IN.into())
    }
    fn yubihsm_read_object(&self, id: u16, object_type: u8) -> Result<Vec<u8>, Error> {
        if object_type == crate::YUBIHSM_OPAQUE {
            self.yubihsm_read_opaque(id)
        } else {
            Err(CKR_ATTRIBUTE_TYPE_INVALID.into())
        }
    }
    fn yubihsm_forget_object(&self, _id: u16, _object_type: u8) -> Result<(), Error> {
        Ok(())
    }
    fn yubihsm_owned_metadata_objects(
        &self,
        _id: u16,
        _object_type: u8,
    ) -> Result<Vec<(u16, u8)>, Error> {
        Ok(Vec::new())
    }
    fn yubihsm_set_attributes(
        &self,
        _slot_id: CK_SLOT_ID,
        _unique_id: &str,
        _id: Option<&[u8]>,
        _label: Option<&str>,
    ) -> Result<(), Error> {
        Err(CKR_ATTRIBUTE_READ_ONLY.into())
    }
    fn yubihsm_persist_public_projection(
        &self,
        _slot_id: CK_SLOT_ID,
        _base_unique_id: &str,
        _projection: &TokenObject,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn yubihsm_destroy_public_projection(
        &self,
        _slot_id: CK_SLOT_ID,
        _unique_id: &str,
    ) -> Result<(), Error> {
        Err(CKR_ACTION_PROHIBITED.into())
    }
    fn hsmauth_administration(
        &mut self,
        _operation: HsmAuthAdministration<'_>,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_generate_key_pair(
        &mut self,
        _key_ref: OpenPgpKeyRef,
        _algorithm: OpenPgpAlgorithm,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_import_private_key(
        &mut self,
        _key_ref: OpenPgpKeyRef,
        _algorithm: OpenPgpAlgorithm,
        _material: &KeyMaterial,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_set_touch_policy(
        &mut self,
        _key_ref: OpenPgpKeyRef,
        _policy: u8,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_generate_key_pair(
        &mut self,
        _slot: piv::Slot,
        _algorithm: piv::Algorithm,
        _pin_policy: u8,
        _touch_policy: u8,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_import_private_key(
        &mut self,
        _slot: piv::Slot,
        _key: &piv::PrivateKeyImport,
        _pin_policy: u8,
        _touch_policy: u8,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_import_certificate(
        &mut self,
        _slot: piv::Slot,
        _certificate: &[u8],
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_delete_key(&mut self, _slot: piv::Slot) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_move_key(&mut self, _from: piv::Slot, _to: piv::Slot) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_delete_certificate(&mut self, _slot: piv::Slot) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_write_data(&mut self, _object_id: u32, _value: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_delete_data(&mut self, _object_id: u32) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn login_is_active(&self) -> bool {
        true
    }

    fn backend_session_is_active(&self) -> bool {
        false
    }

    fn ensure_backend_read_session(&self) -> Result<(), Error> {
        Ok(())
    }

    fn flags(&self) -> CK_FLAGS {
        if self.is_present() {
            (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT) as CK_FLAGS
        } else {
            (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE) as CK_FLAGS
        }
    }

    fn label(&self) -> String {
        format!("{} #{}", self.model(), self.serial())
    }

    fn model(&self) -> &str {
        self.product()
    }

    fn format_slot_info(&self, info: &mut CK_SLOT_INFO) {
        info.firmwareVersion.major = 1;
        info.firmwareVersion.minor = 0;
        info.hardwareVersion.major = self.hardware_major();
        info.hardwareVersion.minor = self.hardware_minor();
        str_pad(&self.name(), &mut info.slotDescription);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        info.flags = self.flags();
    }

    fn format_token_info(&self, info: &mut CK_TOKEN_INFO) {
        str_pad(&self.label(), &mut info.label);
        str_pad(self.manufacturer(), &mut info.manufacturerID);
        str_pad(self.model(), &mut info.model);
        str_pad(self.serial(), &mut info.serialNumber);
        info.flags =
            (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
                as CK_FLAGS;
        info.ulMaxSessionCount = 0;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 8;
        info.ulMinPinLen = 6;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.hardwareVersion.major = self.hardware_major();
        info.hardwareVersion.minor = self.hardware_minor();
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
    }
}

pub(crate) fn apply_device_versions(
    info: &mut CK_SLOT_INFO,
    identity: &crate::device::DeviceIdentity,
) {
    if let Some((major, minor)) = identity.hardware_version {
        info.hardwareVersion.major = major;
        info.hardwareVersion.minor = minor;
    }
    if let Some((major, minor, patch)) = identity.firmware_version {
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
    }
}

impl std::fmt::Debug for dyn Slot + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

pub(crate) trait BackendSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
    fn slotID(&self) -> CK_SLOT_ID;
    fn flags(&self) -> CK_FLAGS;
    #[allow(dead_code)]
    fn get_session_info(&self) -> Result<(), Error>;
    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))
    }
    fn piv_sign(
        &self,
        _slot: piv::Slot,
        _algorithm: piv::Algorithm,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn piv_decipher(
        &self,
        _slot: piv::Slot,
        _algorithm: piv::Algorithm,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_sign(
        &self,
        _key_ref: OpenPgpKeyRef,
        _input: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_decipher(&self, _input: &[u8], _raw: bool) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn openpgp_derive(
        &self,
        _key_ref: OpenPgpKeyRef,
        _algorithm: OpenPgpAlgorithm,
        _public_key: &[u8],
        _pin_policy: u8,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn yubihsm_command(&self, _command: &YubiHsmCommand) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn yubihsm_device_public_key(&self) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn security_domain_put_scp03_key_set(
        &self,
        _new_kvn: u8,
        _replace_kvn: u8,
        _keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn security_domain_delete_scp03_key_set(
        &self,
        _kvn: u8,
        _delete_last: bool,
    ) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn security_domain_scp11_administration(
        &self,
        _operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
}

pub(crate) fn session_state(flags: CK_FLAGS, role: Option<LoginRole>) -> CK_STATE {
    match (flags & CKF_RW_SESSION as CK_FLAGS != 0, role) {
        (_, Some(LoginRole::So)) => CKS_RW_SO_FUNCTIONS as CK_STATE,
        (false, Some(LoginRole::User)) => CKS_RO_USER_FUNCTIONS as CK_STATE,
        (true, Some(LoginRole::User)) => CKS_RW_USER_FUNCTIONS as CK_STATE,
        (false, None) => CKS_RO_PUBLIC_SESSION as CK_STATE,
        (true, None) => CKS_RW_PUBLIC_SESSION as CK_STATE,
    }
}

impl std::fmt::Debug for dyn BackendSession + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}
