trait Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug;
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
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session>;
    fn login(&mut self, pin: &[u8]) -> Result<(), Error>;
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
    fn login_user(&mut self, _username: &[u8], _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn login_so(&mut self, _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_USER_TYPE_INVALID.into())
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
    fn login_context_specific(&mut self, _pin: &[u8], _extended: bool) -> Result<(), Error> {
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
    fn token_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn invalidate_token_objects(&self) {}
    fn token_object(
        &self,
        slot_id: CK_SLOT_ID,
        unique_id: &str,
    ) -> Result<Option<TokenObject>, Error> {
        Ok(self
            .token_objects(slot_id)?
            .into_iter()
            .find(|object| object.token && object.unique_id == unique_id))
    }
    fn session_objects(&self, _slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(Vec::new())
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        MECHANISMS.to_vec()
    }
    fn is_yubihsm(&self) -> bool {
        false
    }
    fn is_issuer_security_domain(&self) -> bool {
        false
    }
    fn is_hsmauth(&self) -> bool {
        false
    }
    fn hsmauth_administration(
        &mut self,
        _operation: HsmAuthAdministration<'_>,
    ) -> Result<Vec<u8>, Error> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
    fn is_piv(&self) -> bool {
        false
    }
    fn is_openpgp(&self) -> bool {
        false
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
        if pinentry::is_configured() && (self.is_hsmauth() || self.is_yubihsm()) {
            info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH as CK_FLAGS;
        }
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

fn apply_connector_versions(info: &mut CK_SLOT_INFO, connector: &dyn Connector) {
    if let Some((major, minor)) = connector.hardware_version() {
        info.hardwareVersion.major = major;
        info.hardwareVersion.minor = minor;
    }
    if let Some((major, minor, patch)) = connector.firmware_version() {
        info.firmwareVersion.major = major;
        info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
    }
}

impl std::fmt::Debug for dyn Slot + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}

trait Session {
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

fn session_state(flags: CK_FLAGS, role: Option<LoginRole>) -> CK_STATE {
    match (flags & CKF_RW_SESSION as CK_FLAGS != 0, role) {
        (_, Some(LoginRole::So)) => CKS_RW_SO_FUNCTIONS as CK_STATE,
        (false, Some(LoginRole::User)) => CKS_RO_USER_FUNCTIONS as CK_STATE,
        (true, Some(LoginRole::User)) => CKS_RW_USER_FUNCTIONS as CK_STATE,
        (false, None) => CKS_RO_PUBLIC_SESSION as CK_STATE,
        (true, None) => CKS_RW_PUBLIC_SESSION as CK_STATE,
    }
}

impl std::fmt::Debug for dyn Session + '_ {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.as_debug().fmt(fmt)
    }
}
