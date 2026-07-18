#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CcidApplication {
    Piv,
    OpenPgp,
    HsmAuth,
    GlobalPlatform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CcidConfiguration {
    application: CcidApplication,
    secure_channel: Option<SecureChannelProtocol>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureChannelProtocol {
    Scp03,
    Scp11a,
    Scp11b,
}

fn configured_ccid_configurations() -> Result<Vec<CcidConfiguration>, Error> {
    let secure_channel = configured_secure_channel_optional()?;
    let applications = match std::env::var("PKCS11RS_CCID_APPLICATIONS") {
        Ok(value) => parse_ccid_application_list(&value)?,
        Err(std::env::VarError::NotPresent) => default_ccid_applications(),
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };

    applications
        .into_iter()
        .map(|application| {
            let secure_channel = match application {
                CcidApplication::Piv
                | CcidApplication::OpenPgp
                | CcidApplication::HsmAuth
                | CcidApplication::GlobalPlatform => secure_channel,
            };
            Ok(CcidConfiguration {
                application,
                secure_channel,
            })
        })
        .collect()
}

fn parse_ccid_application_list(value: &str) -> Result<Vec<CcidApplication>, Error> {
    let mut applications = Vec::new();
    for application in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let application = parse_ccid_application(application)?;
        if !applications.contains(&application) {
            applications.push(application);
        }
    }
    if applications.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(applications)
}

fn default_ccid_applications() -> Vec<CcidApplication> {
    vec![
        CcidApplication::Piv,
        CcidApplication::OpenPgp,
        CcidApplication::HsmAuth,
        CcidApplication::GlobalPlatform,
    ]
}

fn parse_ccid_application(value: &str) -> Result<CcidApplication, Error> {
    match value.to_ascii_lowercase().as_str() {
        "piv" => Ok(CcidApplication::Piv),
        "openpgp" => Ok(CcidApplication::OpenPgp),
        "hsmauth" => Ok(CcidApplication::HsmAuth),
        "globalplatform" => Ok(CcidApplication::GlobalPlatform),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn ccid_application_label(application: CcidApplication) -> &'static str {
    match application {
        CcidApplication::Piv => "PIV",
        CcidApplication::OpenPgp => "OpenPGP",
        CcidApplication::HsmAuth => "YubiHSM Auth",
        CcidApplication::GlobalPlatform => "Issuer SD",
    }
}

fn ccid_application_aid(
    application: CcidApplication,
    _secure_channel: Option<SecureChannelProtocol>,
) -> Result<Vec<u8>, Error> {
    let (name, default) = match application {
        CcidApplication::Piv => ("PKCS11RS_PIV_AID", &piv::PIV_AID[..]),
        CcidApplication::OpenPgp => ("PKCS11RS_OPENPGP_AID", &openpgp::OPENPGP_AID[..]),
        CcidApplication::HsmAuth => (
            "PKCS11RS_HSMAUTH_AID",
            &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01][..],
        ),
        CcidApplication::GlobalPlatform => (
            "PKCS11RS_GLOBALPLATFORM_AID",
            &YUBIKEY_ISSUER_SECURITY_DOMAIN_AID[..],
        ),
    };
    configured_ccid_aid(name, default)
}

fn configured_ccid_aid(name: &str, default: &[u8]) -> Result<Vec<u8>, Error> {
    let aid = match std::env::var(name) {
        Ok(value) => parse_hex(&value)?,
        Err(std::env::VarError::NotPresent) => default.to_vec(),
        Err(std::env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(aid)
}

fn configured_secure_channel_optional() -> Result<Option<SecureChannelProtocol>, Error> {
    match std::env::var("PKCS11RS_CCID_SECURE_CHANNEL") {
        Ok(value) => parse_secure_channel(&value).map(Some),
        Err(std::env::VarError::NotUnicode(_)) => Err(CKR_ARGUMENTS_BAD.into()),
        Err(std::env::VarError::NotPresent) => Ok(None),
    }
}

fn parse_secure_channel(value: &str) -> Result<SecureChannelProtocol, Error> {
    match value.to_ascii_lowercase().as_str() {
        "scp03" => Ok(SecureChannelProtocol::Scp03),
        "scp11a" => Ok(SecureChannelProtocol::Scp11a),
        "scp11b" => Ok(SecureChannelProtocol::Scp11b),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}


#[derive(Debug)]
struct GenericPcscSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    label: &'static str,
    authenticated: Cell<bool>,
}

impl GenericPcscSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>, label: &'static str) -> Self {
        Self {
            connector,
            application_aid,
            label,
            authenticated: Cell::new(false),
        }
    }
}

impl Slot for GenericPcscSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} {}", self.connector.name(), self.label)
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        self.label
    }
    fn serial(&self) -> &str {
        self.connector.serial()
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
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PcscAppletSession {
            slotID: slot_id,
            flags,
            connector: self.connector.clone(),
        })
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        select_application(self.connector.as_ref(), &self.application_aid)
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        if let Some((major, minor, patch)) = self.connector.firmware_version() {
            info.firmwareVersion.major = major;
            info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
        }
        Ok(())
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }
}

#[derive(Debug)]
struct GlobalPlatformSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Cell<bool>,
}

impl Slot for GlobalPlatformSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} Issuer SD", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "Issuer SD"
    }
    fn model(&self) -> &str {
        "Issuer SD"
    }
    fn serial(&self) -> &str {
        self.connector.serial()
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
    fn set_applet_present(&self, present: bool) {
        self.connector.set_applet_present(present);
    }
    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }
    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }
    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
    }
    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }
    fn open_session(&mut self, slotID: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn Session> {
        Box::new(PcscAppletSession {
            slotID,
            flags,
            connector: self.connector.clone(),
        })
    }
    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)?;
        self.authenticated.set(true);
        Ok(())
    }
    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.connector.clear_secure_channel();
        Ok(())
    }
    fn init_slot(&mut self) -> Result<(), Error> {
        select_application(self.connector.as_ref(), &self.application_aid)
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        if let Some((major, minor, patch)) = self.connector.firmware_version() {
            info.firmwareVersion.major = major;
            info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PcscAppletSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
}

impl Session for PcscAppletSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let response = scp03::transmit(
                self.connector.as_ref(),
                &CommandApdu {
                    cla: 0,
                    ins: 0x84,
                    p1: 0,
                    p2: 0,
                    data: Vec::new(),
                    le: Some(chunk.len() as u32),
                    extended: false,
                },
            )?;
            if response.status != 0x9000 || response.data.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&response.data);
        }
        Ok(())
    }
}


#[derive(Debug)]
struct GlobalPlatformSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
}

impl Session for GlobalPlatformSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn slotID(&self) -> CK_SLOT_ID {
        self.slotID
    }
    fn flags(&self) -> CK_FLAGS {
        self.flags
    }
    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), Error> {
        for chunk in output.chunks_mut(256) {
            let response = self.send_apdu(
                &CommandApdu {
                    cla: 0x00,
                    ins: 0x84,
                    p1: 0x00,
                    p2: 0x00,
                    data: Vec::new(),
                    le: Some(chunk.len() as u32),
                    extended: false,
                },
                false,
            )?;
            if response.data.len() != chunk.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            chunk.copy_from_slice(&response.data);
        }
        Ok(())
    }
}

impl GlobalPlatformSession {
    fn send_apdu(&self, command: &CommandApdu, chained: bool) -> Result<ResponseApdu, Error> {
        let mut session_guard = self.session.try_borrow_mut()?;
        let result = {
            let session = session_guard.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
            if chained {
                session.transmit_chained(self.connector.as_ref(), command)
            } else {
                session.transmit(self.connector.as_ref(), command)
            }
        };
        if result.is_err() {
            *session_guard = None;
        }
        result
    }
}
