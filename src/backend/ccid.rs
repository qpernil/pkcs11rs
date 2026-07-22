#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CcidApplication {
    Piv,
    OpenPgp,
    HsmAuth,
    IssuerSecurityDomain,
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
    Scp11c,
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
                | CcidApplication::IssuerSecurityDomain => secure_channel,
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
        CcidApplication::IssuerSecurityDomain,
    ]
}

fn parse_ccid_application(value: &str) -> Result<CcidApplication, Error> {
    match value.to_ascii_lowercase().as_str() {
        "piv" => Ok(CcidApplication::Piv),
        "openpgp" => Ok(CcidApplication::OpenPgp),
        "hsmauth" => Ok(CcidApplication::HsmAuth),
        "issuer-sd" => Ok(CcidApplication::IssuerSecurityDomain),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

fn ccid_application_label(application: CcidApplication) -> &'static str {
    match application {
        CcidApplication::Piv => "PIV",
        CcidApplication::OpenPgp => "OpenPGP",
        CcidApplication::HsmAuth => "YubiHSM Auth",
        CcidApplication::IssuerSecurityDomain => "Issuer SD",
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
            &hsmauth::AID[..],
        ),
        CcidApplication::IssuerSecurityDomain => (
            "PKCS11RS_ISSUER_SD_AID",
            &DEFAULT_ISSUER_SECURITY_DOMAIN_AID[..],
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
        "scp11c" => Ok(SecureChannelProtocol::Scp11c),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}


#[derive(Debug)]
struct HsmAuthSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Cell<bool>,
    info: RefCell<Option<HsmAuthInfo>>,
}

impl HsmAuthSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        Self {
            connector,
            application_aid,
            authenticated: Cell::new(false),
            info: RefCell::new(None),
        }
    }

    fn discovered_info(&self) -> Result<HsmAuthInfo, Error> {
        let mut info = self.info.try_borrow_mut()?;
        if info.is_none() {
            *info = Some(HsmAuthClient.discover(self.connector.as_ref())?);
        }
        info.clone().ok_or(CKR_DEVICE_ERROR.into())
    }

    fn providers(&self) -> Result<Vec<HsmAuthProvider>, Error> {
        let info = self.discovered_info()?;
        Ok(info
            .credentials
            .into_iter()
            .map(|credential| HsmAuthProvider {
                connector: self.connector.clone(),
                credential,
                version: info.version,
            })
            .collect())
    }
}

impl Slot for HsmAuthSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn name(&self) -> String {
        format!("{} YubiHSM Auth", self.connector.name())
    }
    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }
    fn product(&self) -> &str {
        "YubiHSM Auth"
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
    #[cfg(all(test, not(feature = "abi-tests")))]
    fn hsmauth_provisioning_connector(&self) -> Option<Rc<dyn Connector>> {
        Some(self.connector.clone())
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
        Ok(())
    }
    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        apply_connector_versions(info, self.connector.as_ref());
        Ok(())
    }
    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        self.format_token_info(info);
        let version = self.discovered_info()?.version;
        info.firmwareVersion.major = version.0;
        info.firmwareVersion.minor = version.1.saturating_mul(10) + version.2;
        info.ulMaxPinLen = 16;
        info.ulMinPinLen = 0;
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
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        let info = self.discovered_info()?;
        let objects = hsmauth_token_objects(slot_id, &info);
        log!(
            2,
            "YubiHSM Auth slot {} exposed {} PKCS11 objects from {} credentials",
            slot_id,
            objects.len(),
            info.credentials.len()
        );
        Ok(objects)
    }
}

fn hsmauth_token_objects(slot_id: CK_SLOT_ID, info: &HsmAuthInfo) -> Vec<TokenObject> {
    let mut objects = Vec::new();
    for credential in &info.credentials {
        let id = credential.label.as_bytes().to_vec();
        objects.push(TokenObject {
            slot_id: Some(slot_id),
            unique_id: format!("hsmauth-credential:{}", credential.label),
            class: CKO_SECRET_KEY as CK_OBJECT_CLASS,
            key_type: CKK_GENERIC_SECRET as CK_KEY_TYPE,
            label: credential.label.clone(),
            id: id.clone(),
            token: true,
            private: false,
            encrypt: false,
            decrypt: false,
            sign: false,
            verify: false,
            derive: false,
            sensitive: true,
            extractable: false,
            always_sensitive: true,
            never_extractable: true,
            local: false,
            key_gen_mechanism: None,
            owner_session: None,
            material: KeyMaterial::HsmAuthCredential {
                algorithm: credential.algorithm,
                retries: credential.retries,
                touch_required: credential.touch_required,
            },
        });
        if let Some(public_key) = &credential.public_key {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("hsmauth-public:{}", credential.label),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_EC as CK_KEY_TYPE,
                label: format!("{} public key", credential.label),
                id: id.clone(),
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::HsmAuthPublic {
                    public_key: public_key.clone(),
                },
            });
        }
    }
    objects
}

#[derive(Debug)]
struct IssuerSecurityDomainSlot {
    connector: Rc<dyn Connector>,
    application_aid: Vec<u8>,
    authenticated: Cell<bool>,
    info: RefCell<Option<SecurityDomainInfo>>,
}

impl IssuerSecurityDomainSlot {
    fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        Self {
            connector,
            application_aid,
            authenticated: Cell::new(false),
            info: RefCell::new(None),
        }
    }

    fn discovered_info(&self) -> Result<SecurityDomainInfo, Error> {
        let mut info = self.info.try_borrow_mut()?;
        if info.is_none() {
            *info = Some(SecurityDomainClient.discover(self.connector.as_ref())?);
        }
        info.clone().ok_or(CKR_DEVICE_ERROR.into())
    }
}

impl Slot for IssuerSecurityDomainSlot {
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
        self.authenticated.get() && self.connector.secure_channel_is_active()
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
        Ok(())
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
    fn token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        Ok(issuer_security_domain_token_objects(
            slot_id,
            &self.discovered_info()?,
        ))
    }
    fn invalidate_token_objects(&self) {
        if let Ok(mut info) = self.info.try_borrow_mut() {
            *info = None;
        }
    }
    fn is_issuer_security_domain(&self) -> bool {
        true
    }
    fn mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }
}

const ISSUER_SECURITY_DOMAIN_APPLICATION: &str = "Issuer SD";

fn issuer_security_domain_data_object(
    slot_id: CK_SLOT_ID,
    unique_id: String,
    label: String,
    id: Vec<u8>,
    value: Vec<u8>,
) -> TokenObject {
    TokenObject {
        slot_id: Some(slot_id),
        unique_id,
        class: CKO_DATA as CK_OBJECT_CLASS,
        key_type: 0,
        label,
        id,
        token: true,
        private: false,
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        owner_session: None,
        material: KeyMaterial::IssuerSecurityDomainData {
            value,
            application: ISSUER_SECURITY_DOMAIN_APPLICATION.to_owned(),
            object_id: Vec::new(),
        },
    }
}

fn issuer_security_domain_key_name(kid: u8) -> String {
    match kid {
        security_domain::KID_SCP03 => "SCP03 K-ENC".to_string(),
        0x02 => "SCP03 K-MAC".to_string(),
        0x03 => "SCP03 K-DEK".to_string(),
        0x10 => "SCP11 CA-KLOC".to_string(),
        security_domain::KID_SCP11A => "SCP11a".to_string(),
        security_domain::KID_SCP11B => "SCP11b".to_string(),
        security_domain::KID_SCP11C => "SCP11c".to_string(),
        0x20..=0x2f => format!("SCP11 CA-KLCC {kid:02X}"),
        _ => format!("key {kid:02X}"),
    }
}

fn issuer_security_domain_token_objects(
    slot_id: CK_SLOT_ID,
    info: &SecurityDomainInfo,
) -> Vec<TokenObject> {
    let mut objects = Vec::new();
    for key in &info.keys {
        let value = key
            .components
            .iter()
            .flat_map(|component| [component.key_type, component.length])
            .collect();
        let name = issuer_security_domain_key_name(key.key_ref.kid);
        objects.push(issuer_security_domain_data_object(
            slot_id,
            format!("issuer-sd-key-{:02x}-{:02x}", key.key_ref.kid, key.key_ref.kvn),
            format!("Issuer SD {name} KVN {}", key.key_ref.kvn),
            vec![key.key_ref.kid, key.key_ref.kvn],
            value,
        ));
    }
    if let Some(value) = &info.card_recognition_data {
        objects.push(issuer_security_domain_data_object(
            slot_id,
            "issuer-sd-card-recognition".to_string(),
            "Issuer SD card recognition data".to_string(),
            vec![0x66],
            value.clone(),
        ));
    }
    if let Some(value) = &info.cplc {
        objects.push(issuer_security_domain_data_object(
            slot_id,
            "issuer-sd-cplc".to_string(),
            "Issuer SD CPLC".to_string(),
            vec![0x9f, 0x7f],
            value.clone(),
        ));
    }
    for ca in &info.ca_identifiers {
        let kind = match ca.kind {
            security_domain::CaIdentifierKind::Kloc => "KLOC",
            security_domain::CaIdentifierKind::Klcc => "KLCC",
        };
        objects.push(issuer_security_domain_data_object(
            slot_id,
            format!(
                "issuer-sd-ca-{}-{:02x}-{:02x}",
                kind.to_ascii_lowercase(),
                ca.key_ref.kid,
                ca.key_ref.kvn
            ),
            format!(
                "Issuer SD {kind} CA for KID {:02X} KVN {}",
                ca.key_ref.kid, ca.key_ref.kvn
            ),
            vec![ca.key_ref.kid, ca.key_ref.kvn],
            ca.subject_key_identifier.clone(),
        ));
    }
    for bundle in &info.certificate_bundles {
        let name = issuer_security_domain_key_name(bundle.key_ref.kid);
        for (index, certificate) in bundle.certificates.iter().enumerate() {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!(
                    "issuer-sd-certificate-{:02x}-{:02x}-{index}",
                    bundle.key_ref.kid, bundle.key_ref.kvn
                ),
                class: CKO_CERTIFICATE as CK_OBJECT_CLASS,
                key_type: CKK_EC as CK_KEY_TYPE,
                label: format!(
                    "Issuer SD {name} KVN {} certificate {}",
                    bundle.key_ref.kvn,
                    index + 1
                ),
                id: [
                    vec![bundle.key_ref.kid, bundle.key_ref.kvn],
                    (index as u16).to_be_bytes().to_vec(),
                ]
                .concat(),
                token: true,
                private: false,
                encrypt: false,
                decrypt: false,
                sign: false,
                verify: false,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                owner_session: None,
                material: KeyMaterial::IssuerSecurityDomainCertificate {
                    value: certificate.clone(),
                },
            });
        }
    }
    objects
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

    fn security_domain_put_scp03_key_set(
        &self,
        new_kvn: u8,
        replace_kvn: u8,
        keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        self.connector
            .security_domain_put_scp03_key_set(new_kvn, replace_kvn, keys)
    }

    fn security_domain_delete_scp03_key_set(
        &self,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), Error> {
        self.connector
            .security_domain_delete_scp03_key_set(kvn, delete_last)
    }

    fn security_domain_scp11_administration(
        &self,
        operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        self.connector
            .security_domain_scp11_administration(operation)
    }
}


#[derive(Debug)]
struct IssuerSecurityDomainSession {
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    connector: Rc<dyn Connector>,
    session: Rc<RefCell<Option<Scp03Session>>>,
}

impl Session for IssuerSecurityDomainSession {
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

    fn security_domain_put_scp03_key_set(
        &self,
        new_kvn: u8,
        replace_kvn: u8,
        keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        let mut session = self.session.try_borrow_mut()?;
        let channel = session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        if channel.static_dek()?.len() != 16 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        let result = SecurityDomainClient.put_scp03_key_set(
            self.connector.as_ref(),
            channel,
            new_kvn,
            replace_kvn,
            keys,
        );
        if result.is_err() {
            *session = None;
        }
        result
    }

    fn security_domain_delete_scp03_key_set(
        &self,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), Error> {
        let mut session = self.session.try_borrow_mut()?;
        let result = SecurityDomainClient.delete_scp03_key_set(
            self.connector.as_ref(),
            session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?,
            kvn,
            delete_last,
        );
        if result.is_err() {
            *session = None;
        }
        result
    }

    fn security_domain_scp11_administration(
        &self,
        operation: &Scp11Administration,
    ) -> Result<Vec<u8>, Error> {
        let mut session = self.session.try_borrow_mut()?;
        let channel = session.as_mut().ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let prepared = SecurityDomainClient.prepare_scp11_administration(channel, operation)?;
        let result = SecurityDomainClient.execute_scp11_administration(
            self.connector.as_ref(),
            channel,
            prepared,
        );
        if result.is_err() {
            *session = None;
        }
        result
    }
}

impl IssuerSecurityDomainSession {
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
