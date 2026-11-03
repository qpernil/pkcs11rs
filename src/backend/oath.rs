use crate::oath::{self, Credential, Info};
use crate::*;

pub(crate) struct OathSlot {
    connector: Rc<dyn Connector>,
    device: Arc<crate::device::DeviceContext>,
    serial: String,
    aid: Vec<u8>,
    info: RefCell<Option<(u64, Info)>>,
    authenticated: Cell<Option<u64>>,
    metadata: RefCell<HashMap<Vec<u8>, Credential>>,
}
impl std::fmt::Debug for OathSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OathSlot")
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
impl OathSlot {
    pub(crate) fn new(
        connector: Rc<dyn Connector>,
        aid: Vec<u8>,
        device: Arc<crate::device::DeviceContext>,
    ) -> Self {
        let serial = device.identity(connector.connection_epoch()).serial;
        Self {
            connector,
            device,
            serial,
            aid,
            info: RefCell::new(None),
            authenticated: Cell::new(None),
            metadata: RefCell::new(HashMap::new()),
        }
    }
    fn info(&self) -> Result<Info, Error> {
        let epoch = self.connector.connection_epoch();
        if let Some((cached, info)) = &*self.info.borrow()
            && *cached == epoch
        {
            return Ok(info.clone());
        }
        self.metadata.borrow_mut().clear();
        let info = oath::select(self.connector.as_ref(), &self.aid)?;
        *self.info.borrow_mut() = Some((epoch, info.clone()));
        Ok(info)
    }
    fn reselect(&self) -> Result<Info, Error> {
        self.authenticated.set(None);
        self.connector.clear_secure_channel_for_login();
        let info = oath::select(self.connector.as_ref(), &self.aid)?;
        *self.info.borrow_mut() = Some((self.connector.connection_epoch(), info.clone()));
        Ok(info)
    }
    fn require_access(&self) -> Result<(), Error> {
        if self.info()?.protected() && !self.login_is_active() {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        Ok(())
    }
}
impl Slot for OathSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn device_context(&self) -> Option<Arc<crate::device::DeviceContext>> {
        Some(self.device.clone())
    }
    fn ccid_login_connector(&self) -> Option<Rc<dyn Connector>> {
        Some(self.connector.clone())
    }
    fn kind(&self) -> SlotKind {
        SlotKind::Ccid(CcidApplication::Oath)
    }
    fn name(&self) -> String {
        format!("{} OATH", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiKey OATH"
    }
    fn model(&self) -> &str {
        self.connector.product()
    }
    fn serial(&self) -> &str {
        &self.serial
    }
    fn label(&self) -> String {
        format!("OATH #{}", self.serial)
    }
    fn major(&self) -> u8 {
        self.connector.major()
    }
    fn minor(&self) -> u8 {
        self.connector.minor()
    }
    fn is_present(&self) -> bool {
        self.connector.is_present()
    }
    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }
    fn set_discovery_error(&self, e: &Error) {
        self.connector.set_discovery_error(e)
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error()
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        self.info().map(|_| ())
    }
    fn supports_public_projection(&self) -> bool {
        false
    }
    fn software_mechanism_scope(&self) -> SoftwareMechanismScope {
        SoftwareMechanismScope::None
    }
    fn token_objects_copyable(&self) -> bool {
        false
    }
    fn supports_login_user(&self) -> bool {
        true
    }
    fn refresh_token_objects_before_find(&self) -> bool {
        true
    }
    fn refresh_token_objects_after_login(&self) -> bool {
        true
    }
    fn refresh_token_objects_after_logout(&self) -> bool {
        true
    }
    fn backend_token_objects(&self, slot: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let info = self.info()?;
        if info.protected() && !self.login_is_active() {
            return Ok(Vec::new());
        }
        Ok(oath::list(self.connector.as_ref())?
            .into_iter()
            .flat_map(|mut c| {
                if let Some(known) = self.metadata.borrow().get(&c.name)
                    && known.totp == c.totp
                    && known.hash == c.hash
                {
                    c.digits = known.digits;
                    c.touch = known.touch;
                }
                if !c.totp && c.hash == 1 {
                    let mut extended = c.clone();
                    extended.extended = true;
                    vec![
                        oath::object(slot, c, info.protected()),
                        oath::object(slot, extended, info.protected()),
                    ]
                } else {
                    vec![oath::object(slot, c, info.protected())]
                }
            })
            .collect())
    }
    fn login(&mut self, pin: Option<&[u8]>, pinentry: &pinentry::Pinentry) -> Result<(), Error> {
        if pin.is_some_and(|p| p.len() > 255) {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let info = self.reselect()?;
        let prompted;
        let pin = match pin {
            Some(pin) => pin,
            None => {
                let title = self.label();
                prompted = pinentry.request(pinentry::Prompt {
                    title: &title,
                    description: "Unlock the YubiKey OATH application.",
                    label: "OATH password:",
                })?;
                prompted.as_slice()
            }
        };
        self.connector.establish_secure_channel(&self.aid)?;
        if let Err(e) = oath::authenticate(self.connector.as_ref(), &info, pin) {
            self.connector.clear_secure_channel();
            return Err(e);
        }
        self.authenticated
            .set(Some(self.connector.connection_epoch()));
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(None);
        self.connector.clear_secure_channel();
        self.info.borrow_mut().take();
        Ok(())
    }
    fn logout_role(&mut self, _: LoginRole) -> Result<(), Error> {
        self.logout()
    }
    fn set_login_role(&self, role: Option<LoginRole>) -> Result<(), Error> {
        self.connector.set_ccid_login_state(match role {
            Some(LoginRole::User) => CcidLoginState::User,
            Some(LoginRole::So) => CcidLoginState::So,
            None => CcidLoginState::Public,
        })
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get() == Some(self.connector.connection_epoch())
            && self
                .connector
                .ccid_login_state()
                .is_none_or(|s| s == CcidLoginState::User)
    }
    fn backend_session_is_active(&self) -> bool {
        false
    }
    fn clear_session(&mut self) {
        let _ = self.logout();
    }
    fn clear_lost_login(&mut self) {
        self.authenticated.set(None);
        self.info.borrow_mut().take();
        self.connector.reconcile_lost_applet_login();
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_device_versions(
            info,
            &self.device.identity(self.connector.connection_epoch()),
        );
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        let app = self.info()?;
        info.flags &= !((CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED) as CK_FLAGS);
        if app.protected() {
            info.flags |= (CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED) as CK_FLAGS;
        }
        info.ulMinPinLen = 0;
        info.ulMaxPinLen = 255;
        info.firmwareVersion.major = app.version[0];
        info.firmwareVersion.minor = app.version[1].saturating_mul(10) + app.version[2];
        Ok(())
    }
    fn supports_protected_authentication_path(&self, p: &pinentry::Pinentry) -> bool {
        p.is_configured()
    }
    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        [
            CKM_HOTP as CK_MECHANISM_TYPE,
            CKM_PKCS11RS_TOTP,
            CKM_PKCS11RS_HOTP,
        ]
        .into_iter()
        .map(|type_| MechanismDetails {
            type_,
            min_key_size: 1,
            max_key_size: 64,
            flags: (CKF_HW | CKF_SIGN) as _,
        })
        .collect()
    }
    fn open_session(&mut self, slot: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(OathSession { slot, flags })
    }
    fn oath_calculate(&mut self, c: &Credential, time: Option<u64>) -> Result<Vec<u8>, Error> {
        self.require_access()?;
        oath::calculate(self.connector.as_ref(), c, time)
    }
    fn oath_delete(&mut self, name: &[u8]) -> Result<(), Error> {
        self.require_access()?;
        oath::delete(self.connector.as_ref(), name)?;
        self.metadata.borrow_mut().remove(name);
        Ok(())
    }
    fn set_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        if old.len() > 255 || new.len() > 255 {
            return Err(CKR_PIN_LEN_RANGE.into());
        }
        let info = self.reselect()?;
        self.connector.establish_secure_channel(&self.aid)?;
        oath::authenticate(self.connector.as_ref(), &info, old)?;
        oath::change_password(self.connector.as_ref(), &info, new)?;
        self.logout()
    }
    fn create_object(
        &mut self,
        ctx: &mut crate::context::SlotState,
        session: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Option<CK_OBJECT_HANDLE>, Error> {
        let (credential, secret, counter) = oath::import_template(template)?;
        let (_, flags, logged) = ctx.session_details(self, session)?;
        if flags & CKF_RW_SESSION as CK_FLAGS == 0 {
            return Err(CKR_SESSION_READ_ONLY.into());
        }
        if let Some(a) = template
            .iter()
            .find(|a| a.type_ == CKA_PRIVATE as CK_ATTRIBUTE_TYPE)
            && crate::object::read_bool_template_attribute(a).map_err(Error::from)?
                != self.info()?.protected()
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        if self.info()?.protected() && !logged {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        self.require_access()?;
        if oath::list(self.connector.as_ref())?
            .iter()
            .any(|v| v.name == credential.name)
        {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        oath::put(self.connector.as_ref(), &credential, &secret, counter)?;
        self.metadata
            .borrow_mut()
            .insert(credential.name.clone(), credential.clone());
        ctx.refresh_slot_token_objects(self, ctx.slot_id)?;
        let object = oath::object(ctx.slot_id, credential, self.info()?.protected());
        // Resolve the native inventory handle rather than creating a shadow copy.
        ctx.token_object_handles
            .iter()
            .find(|(_, v)| v.unique_id == object.unique_id)
            .map(|(h, _)| Some(*h))
            .ok_or(CKR_DEVICE_ERROR.into())
    }
}
#[derive(Debug)]
struct OathSession {
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
}
impl BackendSession for OathSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slot
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }
    fn generate_random(&self, _: &mut [u8]) -> Result<(), Error> {
        Err(CKR_RANDOM_NO_RNG.into())
    }
}
