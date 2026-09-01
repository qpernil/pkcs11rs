use crate::ctap::{CredentialAuthorization, DiscoverableCredential};
#[cfg(feature = "native-hardware")]
use crate::ctap_hid::{CtapHidInit, CtapHidTransport, HidDeviceDescriptor};
use crate::device::{DeviceContext, DeviceIdentity, PhysicalDeviceKey};
use crate::*;
#[cfg(test)]
use minicbor::Encoder;
use std::time::Duration;

const NFCCTAP_MSG: u8 = 0x10;
const NFCCTAP_GETRESPONSE: u8 = 0x11;
const NFCCTAP_KEEPALIVE_STATUS: u16 = 0x9100;
const ISO7816_SUCCESS: u16 = 0x9000;
const MAX_KEEPALIVE_RESPONSES: usize = 600;
const KEEPALIVE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(crate) struct CcidCtapTransport {
    connector: Rc<dyn Connector>,
}

impl CcidCtapTransport {
    pub(crate) fn new(connector: Rc<dyn Connector>) -> Self {
        Self { connector }
    }
}

impl CtapTransport for CcidCtapTransport {
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if request.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut command = CommandApdu {
            cla: 0x80,
            ins: NFCCTAP_MSG,
            // Advertise NFCCTAP_GETRESPONSE support as specified by CTAP.
            p1: 0x80,
            p2: 0,
            data: request.to_vec(),
            le: Some(256),
            extended: false,
        };
        for _ in 0..=MAX_KEEPALIVE_RESPONSES {
            let response = self.connector.send_apdu(&command)?;
            match response.status {
                ISO7816_SUCCESS => return Ok(response.data),
                NFCCTAP_KEEPALIVE_STATUS if response.data.len() == 1 => {
                    command = CommandApdu {
                        cla: 0x80,
                        ins: NFCCTAP_GETRESPONSE,
                        p1: 0,
                        p2: 0,
                        data: Vec::new(),
                        le: Some(256),
                        extended: false,
                    };
                    std::thread::sleep(KEEPALIVE_POLL_INTERVAL);
                }
                _ => return Err(CKR_DEVICE_ERROR.into()),
            }
        }
        Err(CKR_DEVICE_ERROR.into())
    }
}

pub(crate) trait FidoEndpoint: std::fmt::Debug {
    fn transport(&self) -> Rc<dyn CtapTransport>;
    fn device_context(&self) -> Arc<DeviceContext>;
    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind;
    fn name(&self) -> String;
    fn manufacturer(&self) -> &str;
    fn product(&self) -> &str;
    fn serial(&self) -> &str;
    fn major(&self) -> u8;
    fn minor(&self) -> u8;
    fn hardware_version(&self) -> Option<(u8, u8)> {
        None
    }
    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        None
    }
    fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            manufacturer: self.manufacturer().to_owned(),
            product: self.product().to_owned(),
            serial: self.serial().to_owned(),
            hardware_version: self.hardware_version(),
            firmware_version: self.firmware_version(),
        }
    }
    fn is_present(&self) -> bool;
    fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }
    fn prepare(&self) -> Result<(), Error> {
        Ok(())
    }
    fn clear(&self) {}
    fn set_discovery_error(&self, _error: &Error) {}
    fn clear_discovery_error(&self) {}
    fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession>;
}

#[derive(Debug)]
struct CcidFidoEndpoint {
    connector: Rc<dyn Connector>,
    device: Arc<DeviceContext>,
    serial: String,
    application_aid: Vec<u8>,
    transport: Rc<CcidCtapTransport>,
}

impl CcidFidoEndpoint {
    fn new(
        connector: Rc<dyn Connector>,
        application_aid: Vec<u8>,
        device: Arc<DeviceContext>,
    ) -> Self {
        let serial = device.identity(connector.connection_epoch()).serial;
        Self {
            transport: Rc::new(CcidCtapTransport::new(connector.clone())),
            connector,
            device,
            serial,
            application_aid,
        }
    }
}

impl FidoEndpoint for CcidFidoEndpoint {
    fn transport(&self) -> Rc<dyn CtapTransport> {
        self.transport.clone()
    }

    fn device_context(&self) -> Arc<DeviceContext> {
        self.device.clone()
    }

    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
        crate::device::DeviceOperationKind::Ccid
    }

    fn name(&self) -> String {
        self.connector.name()
    }

    fn manufacturer(&self) -> &str {
        self.connector.manufacturer()
    }

    fn product(&self) -> &str {
        self.connector.product()
    }

    fn serial(&self) -> &str {
        &self.serial
    }

    fn major(&self) -> u8 {
        self.connector.major()
    }

    fn minor(&self) -> u8 {
        self.connector.minor()
    }

    fn hardware_version(&self) -> Option<(u8, u8)> {
        self.connector.hardware_version()
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.connector.firmware_version()
    }

    fn identity(&self) -> DeviceIdentity {
        self.device.identity(self.connector.connection_epoch())
    }

    fn is_present(&self) -> bool {
        self.connector.is_present()
    }

    fn refresh(&self) -> Result<(), Error> {
        self.connector.refresh()
    }

    fn prepare(&self) -> Result<(), Error> {
        self.connector
            .establish_secure_channel(&self.application_aid)
    }

    fn clear(&self) {
        self.connector.clear_secure_channel();
    }

    fn set_discovery_error(&self, error: &Error) {
        self.connector.set_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.connector.clear_discovery_error();
    }

    fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(super::ccid::PcscAppletSession {
            slotID: slot_id,
            flags,
            connector: self.connector.clone(),
        })
    }
}

#[derive(Debug)]
struct SwitchableFidoRoutes {
    ccid: Rc<dyn FidoEndpoint>,
    preferred: RefCell<Option<Rc<dyn FidoEndpoint>>>,
}

impl SwitchableFidoRoutes {
    fn active(&self) -> Rc<dyn FidoEndpoint> {
        self.preferred
            .borrow()
            .as_ref()
            .filter(|endpoint| endpoint.is_present())
            .cloned()
            .unwrap_or_else(|| self.ccid.clone())
    }
}

#[derive(Debug)]
struct SwitchableCtapTransport {
    routes: Rc<SwitchableFidoRoutes>,
}

impl CtapTransport for SwitchableCtapTransport {
    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.routes.active().transport().transact(request)
    }
}

/// One serial-owned FIDO applet with CCID as its universal route and an
/// optional preferred USB HID route. If HID is unavailable, the same slot
/// naturally falls back to CCID, including through a desktop NFC reader.
#[derive(Debug)]
pub(crate) struct SwitchableFidoEndpoint {
    routes: Rc<SwitchableFidoRoutes>,
    transport: Rc<SwitchableCtapTransport>,
    device: Arc<DeviceContext>,
    identity: DeviceIdentity,
}

impl SwitchableFidoEndpoint {
    fn new(ccid: Rc<dyn FidoEndpoint>) -> Rc<Self> {
        let device = ccid.device_context();
        let identity = ccid.identity();
        let routes = Rc::new(SwitchableFidoRoutes {
            ccid,
            preferred: RefCell::new(None),
        });
        Rc::new(Self {
            transport: Rc::new(SwitchableCtapTransport {
                routes: routes.clone(),
            }),
            routes,
            device,
            identity,
        })
    }

    pub(crate) fn prefer(&self, endpoint: Rc<dyn FidoEndpoint>) {
        *self.routes.preferred.borrow_mut() = Some(endpoint);
    }
}

impl FidoEndpoint for SwitchableFidoEndpoint {
    fn transport(&self) -> Rc<dyn CtapTransport> {
        self.transport.clone()
    }

    fn device_context(&self) -> Arc<DeviceContext> {
        self.device.clone()
    }

    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
        self.routes.active().device_operation_kind()
    }

    fn name(&self) -> String {
        self.routes.active().name()
    }

    fn manufacturer(&self) -> &str {
        &self.identity.manufacturer
    }

    fn product(&self) -> &str {
        &self.identity.product
    }

    fn serial(&self) -> &str {
        &self.identity.serial
    }

    fn major(&self) -> u8 {
        self.identity
            .firmware_version
            .map_or(0, |version| version.0)
    }

    fn minor(&self) -> u8 {
        self.identity.firmware_version.map_or(0, |version| {
            version.1.saturating_mul(10).saturating_add(version.2)
        })
    }

    fn hardware_version(&self) -> Option<(u8, u8)> {
        self.identity.hardware_version
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        self.identity.firmware_version
    }

    fn identity(&self) -> DeviceIdentity {
        self.identity.clone()
    }

    fn is_present(&self) -> bool {
        self.routes.active().is_present()
    }

    fn refresh(&self) -> Result<(), Error> {
        if let Some(preferred) = self.routes.preferred.borrow().clone()
            && preferred.refresh().is_ok()
            && preferred.is_present()
        {
            return Ok(());
        }
        self.routes.ccid.refresh()
    }

    fn prepare(&self) -> Result<(), Error> {
        self.routes.active().prepare()
    }

    fn clear(&self) {
        self.routes.active().clear();
    }

    fn set_discovery_error(&self, error: &Error) {
        self.routes.active().set_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.routes.active().clear_discovery_error();
    }

    fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        self.routes.active().open_session(slot_id, flags)
    }
}

#[derive(Debug)]
#[cfg(feature = "native-hardware")]
pub(crate) struct HidFidoEndpoint {
    descriptor: HidDeviceDescriptor,
    transport: Rc<CtapHidTransport>,
    device: Arc<DeviceContext>,
    serial: String,
    firmware_version: (u8, u8, u8),
}

#[cfg(feature = "native-hardware")]
impl HidFidoEndpoint {
    pub(crate) fn new(
        descriptor: HidDeviceDescriptor,
        transport: Rc<CtapHidTransport>,
        init: CtapHidInit,
        device_info: Option<&crate::yubikey::DeviceInfo>,
        device: Arc<DeviceContext>,
    ) -> Self {
        let serial = device_info
            .and_then(|info| info.serial.clone())
            .or_else(|| descriptor.serial().map(str::to_owned))
            .unwrap_or_else(|| "0".to_owned());
        let firmware_version = device_info
            .and_then(|info| info.version)
            .unwrap_or(init.firmware_version);
        Self {
            descriptor,
            transport,
            device,
            serial,
            firmware_version,
        }
    }
}

#[cfg(feature = "native-hardware")]
impl FidoEndpoint for HidFidoEndpoint {
    fn transport(&self) -> Rc<dyn CtapTransport> {
        self.transport.clone()
    }

    fn device_context(&self) -> Arc<DeviceContext> {
        self.device.clone()
    }

    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
        crate::device::DeviceOperationKind::Hid
    }

    fn name(&self) -> String {
        self.descriptor.name()
    }

    fn manufacturer(&self) -> &str {
        self.descriptor.manufacturer()
    }

    fn product(&self) -> &str {
        self.descriptor.product()
    }

    fn serial(&self) -> &str {
        &self.serial
    }

    fn major(&self) -> u8 {
        self.firmware_version.0
    }

    fn minor(&self) -> u8 {
        self.firmware_version
            .1
            .saturating_mul(10)
            .saturating_add(self.firmware_version.2)
    }

    fn firmware_version(&self) -> Option<(u8, u8, u8)> {
        Some(self.firmware_version)
    }

    fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            manufacturer: if self.descriptor.is_yubico() {
                String::from("Yubico")
            } else {
                self.manufacturer().to_owned()
            },
            product: self.product().to_owned(),
            serial: self.serial().to_owned(),
            hardware_version: None,
            firmware_version: Some(self.firmware_version),
        }
    }

    fn is_present(&self) -> bool {
        self.transport.is_connected()
    }

    fn refresh(&self) -> Result<(), Error> {
        if self.transport.is_connected() {
            return Ok(());
        }
        match self.descriptor.open() {
            Ok(io) => match self.transport.reconnect(Box::new(io)) {
                Ok(_) => Ok(()),
                Err(error) => {
                    self.transport.disconnect();
                    Err(error)
                }
            },
            Err(error) => {
                self.transport.disconnect();
                Err(error)
            }
        }
    }

    fn prepare(&self) -> Result<(), Error> {
        self.refresh()
    }

    fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(Fido2Session { slot_id, flags })
    }
}

#[derive(Debug)]
struct Fido2Session {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

impl BackendSession for Fido2Session {
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

#[derive(Debug)]
pub(crate) struct Fido2Slot {
    endpoint: Rc<dyn FidoEndpoint>,
    client: CtapClient,
    info: RefCell<Option<AuthenticatorInfo>>,
    credentials: RefCell<Vec<DiscoverableCredential>>,
    credential_management_authorization: RefCell<Option<CredentialAuthorization>>,
    preview_authorization: RefCell<Option<CredentialAuthorization>>,
    authenticated: Cell<bool>,
}

impl Fido2Slot {
    #[cfg(test)]
    pub(crate) fn new(connector: Rc<dyn Connector>, application_aid: Vec<u8>) -> Self {
        let device = Arc::new(DeviceContext::from_endpoint(connector.as_ref()));
        Self::new_with_device(connector, application_aid, device)
    }

    #[allow(dead_code)]
    pub(crate) fn new_with_device(
        connector: Rc<dyn Connector>,
        application_aid: Vec<u8>,
        device: Arc<DeviceContext>,
    ) -> Self {
        Self::new_with_endpoint(Rc::new(CcidFidoEndpoint::new(
            connector,
            application_aid,
            device,
        )))
    }

    pub(crate) fn new_switchable_with_device(
        connector: Rc<dyn Connector>,
        application_aid: Vec<u8>,
        device: Arc<DeviceContext>,
    ) -> (Self, Rc<SwitchableFidoEndpoint>) {
        let ccid = Rc::new(CcidFidoEndpoint::new(connector, application_aid, device));
        let endpoint = SwitchableFidoEndpoint::new(ccid);
        (Self::new_with_endpoint(endpoint.clone()), endpoint)
    }

    pub(crate) fn new_with_endpoint(endpoint: Rc<dyn FidoEndpoint>) -> Self {
        let transport = endpoint.transport();
        Self {
            endpoint,
            client: CtapClient::new(transport),
            info: RefCell::new(None),
            credentials: RefCell::new(Vec::new()),
            credential_management_authorization: RefCell::new(None),
            preview_authorization: RefCell::new(None),
            authenticated: Cell::new(false),
        }
    }

    fn discovered_info(&self) -> Result<AuthenticatorInfo, Error> {
        let mut info = self.info.try_borrow_mut()?;
        if info.is_none() {
            *info = Some(self.client.get_info().map_err(CtapError::into_pkcs11)?);
        }
        info.clone().ok_or(CKR_DEVICE_ERROR.into())
    }

    fn primary_protocol_version(&self) -> Option<String> {
        self.info
            .try_borrow()
            .ok()
            .and_then(|info| Some(info.as_ref()?.primary_version()?.to_owned()))
    }

    pub(crate) fn physical_device_key(&self) -> Option<PhysicalDeviceKey> {
        self.endpoint.identity().physical_key()
    }
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) struct ProjectedFidoKey {
    pub(crate) key_type: CK_KEY_TYPE,
    pub(crate) public_key: PublicKeyMaterial,
}

fn decode_cbor_u64(value: &[u8]) -> Option<u64> {
    let mut decoder = minicbor::Decoder::new(value);
    let decoded = decoder.u64().ok()?;
    (decoder.position() == value.len()).then_some(decoded)
}

fn decode_cbor_bytes(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = minicbor::Decoder::new(value);
    let decoded = decoder.bytes().ok()?.to_vec();
    (decoder.position() == value.len()).then_some(decoded)
}

pub(crate) fn project_cose_public_key(encoded: &[u8]) -> Option<ProjectedFidoKey> {
    let mut decoder = minicbor::Decoder::new(encoded);
    let count = decoder.map().ok()??;
    let mut kty = None;
    let mut minus_one = None;
    let mut minus_two = None;
    let mut minus_three = None;
    for _ in 0..count {
        let label = decoder.i64().ok()?;
        let target = match label {
            1 => &mut kty,
            -1 => &mut minus_one,
            -2 => &mut minus_two,
            -3 => &mut minus_three,
            _ => {
                decoder.skip().ok()?;
                continue;
            }
        };
        if target.is_some() {
            return None;
        }
        let start = decoder.position();
        decoder.skip().ok()?;
        *target = Some(&encoded[start..decoder.position()]);
    }
    if decoder.position() != encoded.len() {
        return None;
    }

    match decode_cbor_u64(kty?)? {
        1 => {
            let curve = decode_cbor_u64(minus_one?)?;
            let public_key = decode_cbor_bytes(minus_two?)?;
            if curve != 6 || public_key.len() != 32 {
                return None;
            }
            Some(ProjectedFidoKey {
                key_type: CKK_EC_EDWARDS as CK_KEY_TYPE,
                public_key: PublicKeyMaterial::Ec {
                    parameters: piv_ec_parameters(piv::Algorithm::Ed25519)?.to_vec(),
                    public_key,
                },
            })
        }
        2 => {
            let curve = decode_cbor_u64(minus_one?)?;
            let x = decode_cbor_bytes(minus_two?)?;
            let y = decode_cbor_bytes(minus_three?)?;
            let (coordinate_length, parameters): (usize, &[u8]) = match curve {
                1 => (
                    32,
                    &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                ),
                2 => (48, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
                3 => (66, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
                _ => return None,
            };
            if x.len() != coordinate_length || y.len() != coordinate_length {
                return None;
            }
            let mut public_key = Vec::with_capacity(coordinate_length * 2);
            public_key.extend(x);
            public_key.extend(y);
            Some(ProjectedFidoKey {
                key_type: CKK_EC as CK_KEY_TYPE,
                public_key: PublicKeyMaterial::Ec {
                    parameters: parameters.to_vec(),
                    public_key,
                },
            })
        }
        3 => {
            let modulus = decode_cbor_bytes(minus_one?)?;
            let public_exponent = decode_cbor_bytes(minus_two?)?;
            if modulus.is_empty() || public_exponent.is_empty() {
                return None;
            }
            Some(ProjectedFidoKey {
                key_type: CKK_RSA as CK_KEY_TYPE,
                public_key: PublicKeyMaterial::Rsa(
                    RsaPublicKey::new(
                        BigUint::from_bytes_be(&modulus),
                        BigUint::from_bytes_be(&public_exponent),
                    )
                    .ok()?,
                ),
            })
        }
        _ => None,
    }
}

fn credential_label(credential: &DiscoverableCredential) -> String {
    let user = credential
        .user_display_name
        .as_ref()
        .or(credential.user_name.as_ref())
        .map(String::as_str);
    let relying_party = credential
        .relying_party
        .name
        .as_ref()
        .or(credential.relying_party.id.as_ref())
        .map(String::as_str);
    match (relying_party, user) {
        (Some(relying_party), Some(user)) => format!("{relying_party}: {user}"),
        (Some(relying_party), None) => relying_party.to_owned(),
        (None, Some(user)) => user.to_owned(),
        (None, None) => {
            let id = hex(&credential.credential_id);
            format!("FIDO2 credential {}", &id[..id.len().min(16)])
        }
    }
}

fn fido2_token_objects(
    slot_id: CK_SLOT_ID,
    credentials: &[DiscoverableCredential],
) -> Result<Vec<TokenObject>, Error> {
    let mut objects = Vec::new();
    for credential in credentials {
        let rp_id_hash = hex(&credential.relying_party.id_hash);
        let credential_id = hex(&credential.credential_id);
        let unique_id = format!("fido2-credential:{rp_id_hash}:{credential_id}");
        let label = credential_label(credential);
        if let Some(projected) = project_cose_public_key(&credential.public_key_cose) {
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("{unique_id}:public"),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: projected.key_type,
                label: format!("{label} public key"),
                id: credential.credential_id.clone(),
                token: true,
                private: true,
                encrypt: projected.key_type == CKK_RSA as CK_KEY_TYPE,
                decrypt: false,
                sign: false,
                verify: true,
                derive: false,
                wrap: false,
                unwrap: false,
                encapsulate: false,
                decapsulate: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: false,
                key_gen_mechanism: None,
                allowed_mechanisms: None,
                wrap_with_trusted: false,
                policy_templates: crate::KeyPolicyTemplates::default(),
                creator_session: None,
                public_key: None,
                rp_id: credential.relying_party.id.clone(),
                material: KeyMaterial::Public(projected.public_key.clone()),
            });
            let private_material = KeyMaterial::FidoResidentPrivate {
                credential_id: credential.credential_id.clone(),
            };
            objects.push(TokenObject {
                slot_id: Some(slot_id),
                unique_id: format!("{unique_id}:private"),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: projected.key_type,
                label: format!("{label} private key"),
                id: credential.credential_id.clone(),
                token: true,
                private: true,
                encrypt: false,
                decrypt: false,
                sign: credential.relying_party.id.is_some(),
                verify: false,
                derive: false,
                wrap: false,
                unwrap: false,
                encapsulate: false,
                decapsulate: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: false,
                key_gen_mechanism: None,
                allowed_mechanisms: None,
                wrap_with_trusted: false,
                policy_templates: crate::KeyPolicyTemplates::default(),
                creator_session: None,
                public_key: Some(projected.public_key),
                rp_id: credential.relying_party.id.clone(),
                material: private_material,
            });
        }
        objects.push(TokenObject {
            slot_id: Some(slot_id),
            unique_id,
            class: CKO_DATA as CK_OBJECT_CLASS,
            key_type: 0,
            label,
            id: credential.credential_id.clone(),
            token: true,
            private: true,
            encrypt: false,
            decrypt: false,
            sign: false,
            verify: false,
            derive: false,
            wrap: false,
            unwrap: false,
            encapsulate: false,
            decapsulate: false,
            sensitive: false,
            extractable: false,
            always_sensitive: false,
            never_extractable: false,
            local: false,
            key_gen_mechanism: None,
            allowed_mechanisms: None,
            wrap_with_trusted: false,
            policy_templates: crate::KeyPolicyTemplates::default(),
            creator_session: None,
            public_key: None,
            rp_id: credential.relying_party.id.clone(),
            material: KeyMaterial::FidoCredential {
                rp_id_hash: credential.relying_party.id_hash,
                response_cbor: credential.response_cbor.clone(),
            },
        });
    }
    Ok(objects)
}

impl Slot for Fido2Slot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn device_context(&self) -> Option<Arc<DeviceContext>> {
        Some(self.endpoint.device_context())
    }
    fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
        self.endpoint.device_operation_kind()
    }
    fn kind(&self) -> SlotKind {
        SlotKind::Fido2
    }
    fn physical_device_key(&self) -> Option<PhysicalDeviceKey> {
        Fido2Slot::physical_device_key(self)
    }

    fn name(&self) -> String {
        match self.primary_protocol_version() {
            Some(version) => format!("{} FIDO2 ({version})", self.endpoint.name()),
            None => format!("{} FIDO2", self.endpoint.name()),
        }
    }

    fn manufacturer(&self) -> &str {
        self.endpoint.manufacturer()
    }

    fn product(&self) -> &str {
        "FIDO2"
    }

    fn model(&self) -> &str {
        self.endpoint.product()
    }

    fn label(&self) -> String {
        let serial = self.endpoint.identity().serial;
        match self.primary_protocol_version() {
            Some(version) => format!("FIDO2 {version} #{serial}"),
            None => format!("FIDO2 #{serial}"),
        }
    }

    fn serial(&self) -> &str {
        self.endpoint.serial()
    }

    fn major(&self) -> u8 {
        self.endpoint.major()
    }

    fn minor(&self) -> u8 {
        self.endpoint.minor()
    }

    fn is_present(&self) -> bool {
        self.endpoint.is_present()
    }

    fn refresh(&self) -> Result<(), Error> {
        self.endpoint.refresh()
    }

    fn set_discovery_error(&self, error: &Error) {
        self.endpoint.set_discovery_error(error);
    }

    fn clear_discovery_error(&self) {
        self.endpoint.clear_discovery_error();
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        self.endpoint.open_session(slot_id, flags)
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        self.endpoint.prepare()?;
        let result = (|| {
            let info = self.discovered_info()?;
            let supports_credential_management = info.credential_management_command().is_some();
            let supports_preview_sign = info
                .extensions
                .iter()
                .any(|extension| extension == "previewSign");
            if !supports_credential_management && !supports_preview_sign {
                return Err(Error::from(CKR_FUNCTION_NOT_SUPPORTED));
            }
            let (credentials, credential_management_authorization) =
                if supports_credential_management {
                    let authorization = self
                        .client
                        .authorize_credential_enumeration(&info, pin)
                        .map_err(CtapError::into_pkcs11)?;
                    let credentials = self
                        .client
                        .enumerate_credentials(&info, &authorization)
                        .map_err(CtapError::into_pkcs11)?;
                    (credentials, Some(authorization))
                } else {
                    (Vec::new(), None)
                };
            let preview_authorization = if supports_preview_sign {
                Some(
                    self.client
                        .authorize_preview_sign(&info, pin)
                        .map_err(CtapError::into_pkcs11)?,
                )
            } else {
                None
            };
            Ok((
                credentials,
                credential_management_authorization,
                preview_authorization,
            ))
        })();
        match result {
            Ok((credentials, credential_management_authorization, preview_authorization)) => {
                *self.credentials.get_mut() = credentials;
                *self.credential_management_authorization.get_mut() =
                    credential_management_authorization;
                *self.preview_authorization.get_mut() = preview_authorization;
                self.authenticated.set(true);
                Ok(())
            }
            Err(error) => {
                self.endpoint.clear();
                Err(error)
            }
        }
    }

    fn logout(&mut self) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        Ok(())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        let info = self.discovered_info()?;
        log!(
            2,
            "FIDO2 authenticator info on {}: versions {:?}, extensions {:?}, AAGUID {:02x?}, options {:?}, max message {:?}, PIN/UV protocols {:?}, transports {:?}, minimum PIN length {:?}",
            self.endpoint.name(),
            info.versions,
            info.extensions,
            info.aaguid,
            info.options,
            info.max_msg_size,
            info.pin_uv_auth_protocols,
            info.transports,
            info.min_pin_length
        );
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        self.format_slot_info(info);
        let identity = self.endpoint.identity();
        str_pad(&identity.manufacturer, &mut info.manufacturerID);
        if let Some((major, minor)) = identity.hardware_version {
            info.hardwareVersion.major = major;
            info.hardwareVersion.minor = minor;
        }
        if let Some((major, minor, patch)) = identity.firmware_version {
            info.firmwareVersion.major = major;
            info.firmwareVersion.minor = minor.saturating_mul(10) + patch;
        }
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        let discovered = self.discovered_info()?;
        self.format_token_info(info);
        let identity = self.endpoint.identity();
        str_pad(&self.label(), &mut info.label);
        str_pad(&identity.manufacturer, &mut info.manufacturerID);
        str_pad(&identity.product, &mut info.model);
        str_pad(&identity.serial, &mut info.serialNumber);
        info.flags = (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED) as CK_FLAGS;
        if discovered.option("clientPin") {
            info.flags |= CKF_USER_PIN_INITIALIZED as CK_FLAGS;
        }
        info.ulMaxPinLen = 63;
        info.ulMinPinLen = 4;
        Ok(())
    }

    fn set_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        self.endpoint.prepare()?;
        let result = (|| {
            self.info.get_mut().take();
            let info = self.discovered_info()?;
            if info.option("clientPin") {
                if old_pin.is_empty() {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                self.client
                    .change_pin(&info, old_pin, new_pin)
                    .map_err(CtapError::into_pkcs11)?;
            } else {
                if !old_pin.is_empty() {
                    return Err(CKR_PIN_INCORRECT.into());
                }
                self.client
                    .set_initial_pin(&info, new_pin)
                    .map_err(CtapError::into_pkcs11)?;
            }
            self.info.get_mut().take();
            Ok(())
        })();
        self.endpoint.clear();
        result
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    fn create_fido2_test_credential(
        &mut self,
        pin: &[u8],
    ) -> Result<crate::ctap::VerifiedMakeCredential, Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        self.endpoint.prepare()?;
        let result = (|| {
            let info = self.discovered_info()?;
            self.client
                .create_discoverable_test_credential(&info, pin)
                .map_err(CtapError::into_pkcs11)
        })();
        self.endpoint.clear();
        result
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    fn create_fido2_preview_sign_test_registration(
        &mut self,
        pin: &[u8],
    ) -> Result<crate::preview_sign::PreviewSignRegistration, Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        self.endpoint.prepare()?;
        let result = (|| {
            let info = self.discovered_info()?;
            self.client
                .create_preview_sign_test_registration(
                    &info,
                    pin,
                    Some(self.endpoint.serial().to_owned()),
                )
                .map_err(CtapError::into_pkcs11)
        })();
        self.endpoint.clear();
        result
    }

    #[cfg(all(test, not(feature = "abi-tests")))]
    fn delete_fido2_test_credential(
        &mut self,
        pin: &[u8],
        credential_id: &[u8],
    ) -> Result<(), Error> {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
        self.endpoint.prepare()?;
        let result = (|| {
            let info = self.discovered_info()?;
            self.client
                .delete_test_credential(&info, pin, credential_id)
                .map_err(CtapError::into_pkcs11)
        })();
        self.endpoint.clear();
        result
    }

    fn clear_session(&mut self) {
        self.authenticated.set(false);
        self.credentials.get_mut().clear();
        self.credential_management_authorization.get_mut().take();
        self.preview_authorization.get_mut().take();
        self.endpoint.clear();
    }

    fn fido_preview_sign_registration(
        &mut self,
    ) -> Result<crate::preview_sign::PreviewSignRegistration, Error> {
        let authorization = self
            .preview_authorization
            .get_mut()
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        self.client
            .create_preview_sign_registration(
                authorization,
                Some(self.endpoint.serial().to_owned()),
            )
            .map_err(CtapError::into_pkcs11)
    }

    fn fido_preview_sign(
        &mut self,
        registration: &crate::preview_sign::PreviewSignRegistration,
        to_be_signed: &[u8],
        additional_args_cbor: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let authorization = self
            .preview_authorization
            .get_mut()
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        self.client
            .preview_sign(
                authorization,
                registration,
                to_be_signed,
                additional_args_cbor,
            )
            .map_err(CtapError::into_pkcs11)
    }

    fn fido_delete_preview_credential(
        &mut self,
        registration: &crate::preview_sign::PreviewSignRegistration,
    ) -> Result<(), Error> {
        let info = self.discovered_info()?;
        let authorization = self
            .credential_management_authorization
            .get_mut()
            .as_ref()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        self.client
            .delete_credential(&info, authorization, registration.credential_id())
            .map_err(CtapError::into_pkcs11)
    }

    fn fido_get_assertion(
        &mut self,
        authorization: &CredentialAuthorization,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        self.client
            .get_assertion(authorization, rp_id, credential_id, client_data_hash)
            .map_err(CtapError::into_pkcs11)
    }

    fn login_context_specific(
        &mut self,
        pin: &[u8],
        _extended: bool,
        rp_id: Option<&str>,
    ) -> Result<Option<CredentialAuthorization>, Error> {
        let rp_id = rp_id.ok_or(CKR_FUNCTION_NOT_SUPPORTED)?;
        let info = self.discovered_info()?;
        self.client
            .authorize_assertion(&info, pin, rp_id)
            .map(Some)
            .map_err(CtapError::into_pkcs11)
    }

    fn login_is_active(&self) -> bool {
        self.authenticated.get()
    }

    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        let Ok(info) = self.discovered_info() else {
            return Vec::new();
        };
        let mut mechanisms = vec![MechanismDetails {
            type_: CKM_PKCS11RS_FIDO_ASSERTION,
            min_key_size: 0,
            max_key_size: CK_UNAVAILABLE_INFORMATION as CK_ULONG,
            flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
        }];
        if info
            .extensions
            .iter()
            .any(|extension| extension == "previewSign")
        {
            mechanisms.extend([
                MechanismDetails {
                    type_: CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
                    min_key_size: 256,
                    max_key_size: 256,
                    flags: (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS,
                },
                MechanismDetails {
                    type_: CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
                    min_key_size: 256,
                    max_key_size: 256,
                    flags: CKF_DERIVE as CK_FLAGS,
                },
                MechanismDetails {
                    type_: CKM_PKCS11RS_PREVIEW_SIGN,
                    min_key_size: 256,
                    max_key_size: 256,
                    flags: (CKF_HW | CKF_SIGN) as CK_FLAGS,
                },
                MechanismDetails {
                    type_: CKM_ECDSA as CK_MECHANISM_TYPE,
                    min_key_size: 256,
                    max_key_size: 256,
                    flags: (CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE) as CK_FLAGS,
                },
            ]);
        }
        mechanisms
    }

    fn backend_token_objects(&self, slot_id: CK_SLOT_ID) -> Result<Vec<TokenObject>, Error> {
        if !self.authenticated.get() {
            return Ok(Vec::new());
        }
        let credentials = self
            .credentials
            .try_borrow()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        fido2_token_objects(slot_id, &credentials)
    }

    fn refresh_token_objects_after_login(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::{AUTHENTICATOR_CLIENT_PIN, AUTHENTICATOR_GET_INFO, FIDO2_AID};
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Debug)]
    struct RouteTransport(u8);

    impl CtapTransport for RouteTransport {
        fn transact(&self, _request: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(vec![self.0])
        }
    }

    #[derive(Debug)]
    struct RouteEndpoint {
        present: Cell<bool>,
        kind: crate::device::DeviceOperationKind,
        marker: u8,
        device: Arc<DeviceContext>,
    }

    impl RouteEndpoint {
        fn new(
            present: bool,
            kind: crate::device::DeviceOperationKind,
            marker: u8,
            device: Arc<DeviceContext>,
        ) -> Rc<Self> {
            Rc::new(Self {
                present: Cell::new(present),
                kind,
                marker,
                device,
            })
        }
    }

    impl FidoEndpoint for RouteEndpoint {
        fn transport(&self) -> Rc<dyn CtapTransport> {
            Rc::new(RouteTransport(self.marker))
        }

        fn device_context(&self) -> Arc<DeviceContext> {
            self.device.clone()
        }

        fn device_operation_kind(&self) -> crate::device::DeviceOperationKind {
            self.kind
        }

        fn name(&self) -> String {
            format!("route {}", self.marker)
        }

        fn manufacturer(&self) -> &str {
            "Yubico"
        }

        fn product(&self) -> &str {
            "YubiKey"
        }

        fn serial(&self) -> &str {
            "12345678"
        }

        fn major(&self) -> u8 {
            5
        }

        fn minor(&self) -> u8 {
            70
        }

        fn is_present(&self) -> bool {
            self.present.get()
        }

        fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
            Box::new(Fido2Session { slot_id, flags })
        }
    }

    #[test]
    fn serial_owned_fido_route_prefers_hid_and_falls_back_to_ccid() {
        let device = Arc::new(DeviceContext::new(DeviceIdentity {
            manufacturer: "Yubico".to_owned(),
            product: "YubiKey".to_owned(),
            serial: "12345678".to_owned(),
            hardware_version: None,
            firmware_version: Some((5, 7, 0)),
        }));
        let ccid = RouteEndpoint::new(
            true,
            crate::device::DeviceOperationKind::Ccid,
            1,
            device.clone(),
        );
        let hid = RouteEndpoint::new(true, crate::device::DeviceOperationKind::Hid, 2, device);
        let endpoint = SwitchableFidoEndpoint::new(ccid);
        endpoint.prefer(hid.clone());

        assert_eq!(
            endpoint.device_operation_kind(),
            crate::device::DeviceOperationKind::Hid
        );
        assert_eq!(endpoint.transport().transact(&[0x04]).unwrap(), vec![2]);
        hid.present.set(false);
        assert_eq!(
            endpoint.device_operation_kind(),
            crate::device::DeviceOperationKind::Ccid
        );
        assert_eq!(endpoint.transport().transact(&[0x04]).unwrap(), vec![1]);
        assert_eq!(endpoint.serial(), "12345678");
    }

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<Vec<u8>>>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiKey"
        }
        fn major(&self) -> u8 {
            5
        }
        fn minor(&self) -> u8 {
            80
        }
        fn firmware_version(&self) -> Option<(u8, u8, u8)> {
            Some((5, 8, 0))
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn transmit<'a>(
            &self,
            command: &[u8],
            receive: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(command.to_vec());
            let response = self.responses.borrow_mut().pop_front().unwrap();
            receive[..response.len()].copy_from_slice(&response);
            Ok(&receive[..response.len()])
        }
    }

    fn get_info_apdu_response_with_minimum(client_pin: bool, minimum: u8) -> Vec<u8> {
        let mut response = vec![0];
        Encoder::new(&mut response)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(1)
            .unwrap()
            .str("FIDO_2_1")
            .unwrap()
            .u8(3)
            .unwrap()
            .bytes(&[0; 16])
            .unwrap()
            .u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("clientPin")
            .unwrap()
            .bool(client_pin)
            .unwrap()
            .u8(6)
            .unwrap()
            .array(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(0x0d)
            .unwrap()
            .u8(minimum)
            .unwrap();
        response.extend([0x90, 0x00]);
        response
    }

    fn get_info_apdu_response(client_pin: bool) -> Vec<u8> {
        get_info_apdu_response_with_minimum(client_pin, 4)
    }

    fn key_agreement_apdu_response() -> Vec<u8> {
        let x = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        let y = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut response = vec![0];
        Encoder::new(&mut response)
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .i8(-25)
            .unwrap()
            .i8(-1)
            .unwrap()
            .u8(1)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&x)
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&y)
            .unwrap();
        response.extend([0x90, 0x00]);
        response
    }

    #[test]
    fn ccid_transport_uses_fido_iso7816_framing() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        let connector = Rc::new(ScriptedConnector::new(vec![vec![0, 0xa0, 0x90, 0x00]]));
        let transport = CcidCtapTransport::new(connector.clone());
        assert_eq!(
            transport.transact(&[AUTHENTICATOR_GET_INFO]).unwrap(),
            [0, 0xa0]
        );
        assert_eq!(
            connector.commands.borrow()[0],
            [0x80, 0x10, 0x80, 0x00, 0x01, AUTHENTICATOR_GET_INFO, 0x00]
        );
    }

    #[test]
    fn ccid_transport_follows_ctap_keepalive_get_response() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        let connector = Rc::new(ScriptedConnector::new(vec![
            vec![0x01, 0x91, 0x00],
            vec![0, 0xa0, 0x90, 0x00],
        ]));
        let transport = CcidCtapTransport::new(connector.clone());
        assert_eq!(
            transport.transact(&[AUTHENTICATOR_GET_INFO]).unwrap(),
            [0, 0xa0]
        );
        let commands = connector.commands.borrow();
        assert_eq!(commands[0][..4], [0x80, 0x10, 0x80, 0x00]);
        assert_eq!(commands[1], [0x80, 0x11, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ccid_transport_rejects_malformed_keepalive_and_apdu_errors() {
        use crate::ctap::AUTHENTICATOR_GET_INFO;

        for response in [vec![0x91, 0x00], vec![0x6a, 0x80]] {
            let connector = Rc::new(ScriptedConnector::new(vec![response]));
            let transport = CcidCtapTransport::new(connector);
            assert!(transport.transact(&[AUTHENTICATOR_GET_INFO]).is_err());
        }
    }

    #[test]
    fn discovered_slot_reports_ctap_and_yubikey_information() {
        let mut response = vec![
            0x00, 0xa3, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x03,
            0x50,
        ];
        response.extend([0; 16]);
        response.extend([0x09, 0x81, 0x63, b'u', b's', b'b', 0x90, 0x00]);
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![response]));
        let device = Arc::new(DeviceContext::new(DeviceIdentity {
            manufacturer: String::from("Yubico"),
            product: String::from("YubiKey"),
            serial: String::from("12345678"),
            hardware_version: None,
            firmware_version: Some((5, 8, 0)),
        }));
        let mut slot = Fido2Slot::new_with_device(connector, FIDO2_AID.to_vec(), device);
        slot.init_slot().unwrap();

        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert!(
            slot_info
                .slotDescription
                .windows(b"FIDO2 (FIDO_2_1)".len())
                .any(|window| window == b"FIDO2 (FIDO_2_1)")
        );
        assert_eq!(slot_info.firmwareVersion.major, 5);
        assert_eq!(slot_info.firmwareVersion.minor, 80);

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert!(
            token_info
                .label
                .windows(b"FIDO2 FIDO_2_1 #12345678".len())
                .any(|window| window == b"FIDO2 FIDO_2_1 #12345678")
        );
        assert_eq!(
            token_info.flags,
            (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED) as CK_FLAGS
        );
        assert_eq!(token_info.ulMinPinLen, 4);
        assert_eq!(token_info.ulMaxPinLen, 63);
        let mechanisms = slot.backend_mechanisms();
        assert_eq!(mechanisms.len(), 1);
        assert_eq!(mechanisms[0].type_, CKM_PKCS11RS_FIDO_ASSERTION);
        assert_eq!(mechanisms[0].flags, (CKF_HW | CKF_SIGN) as CK_FLAGS);
        let mechanisms = slot.mechanisms();
        for unsupported in HASHED_RSA_PKCS_MECHANISMS
            .into_iter()
            .chain(HASHED_RSA_PSS_MECHANISMS)
            .chain(HASHED_ECDSA_MECHANISMS)
        {
            assert!(
                !mechanisms
                    .iter()
                    .any(|mechanism| mechanism.type_ == unsupported)
            );
        }
    }

    #[test]
    fn token_pin_bounds_cover_existing_pins_after_policy_increases() {
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![
            get_info_apdu_response_with_minimum(true, 8),
        ]));
        let slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert_eq!(token_info.ulMinPinLen, 4);
        assert_eq!(token_info.ulMaxPinLen, 63);
    }

    #[test]
    fn public_set_pin_initializes_only_an_unconfigured_fido_authenticator() {
        let connector = Rc::new(ScriptedConnector::new(vec![
            get_info_apdu_response(false),
            key_agreement_apdu_response(),
            vec![0, 0x90, 0x00],
            get_info_apdu_response(true),
        ]));
        let mut slot = Fido2Slot::new(connector.clone(), FIDO2_AID.to_vec());
        slot.set_pin(&[], "ra\u{0308}ka".as_bytes()).unwrap();

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert_ne!(token_info.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS, 0);
        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 4);
        assert_eq!(commands[0][5], AUTHENTICATOR_GET_INFO);
        assert_eq!(commands[1][5], AUTHENTICATOR_CLIENT_PIN);
        assert_eq!(commands[2][5], AUTHENTICATOR_CLIENT_PIN);
        assert_eq!(commands[3][5], AUTHENTICATOR_GET_INFO);
    }

    #[test]
    fn public_set_pin_rejects_state_mismatches_and_named_login() {
        let connector: Rc<dyn Connector> =
            Rc::new(ScriptedConnector::new(vec![get_info_apdu_response(false)]));
        let mut slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());
        assert!(matches!(
            slot.set_pin(b"old", b"new-PIN"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as CK_RV
        ));

        let connector: Rc<dyn Connector> =
            Rc::new(ScriptedConnector::new(vec![get_info_apdu_response(true)]));
        let mut slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());
        assert!(matches!(
            slot.set_pin(&[], b"new-PIN"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as CK_RV
        ));
        assert!(matches!(
            slot.login_user(0, b"alice", b"new-PIN", &[]),
            Err(Error::Generic(rv)) if rv == CKR_FUNCTION_NOT_SUPPORTED as CK_RV
        ));
        assert!(matches!(
            slot.login_so(b"new-PIN"),
            Err(Error::Generic(rv)) if rv == CKR_USER_TYPE_INVALID as CK_RV
        ));
    }

    #[test]
    fn public_set_pin_changes_an_existing_fido_pin() {
        let connector = Rc::new(ScriptedConnector::new(vec![
            get_info_apdu_response(true),
            key_agreement_apdu_response(),
            vec![0, 0x90, 0x00],
            get_info_apdu_response(true),
        ]));
        let mut slot = Fido2Slot::new(connector.clone(), FIDO2_AID.to_vec());
        slot.set_pin(b"old-PIN", b"new-PIN").unwrap();

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert_ne!(token_info.flags & CKF_USER_PIN_INITIALIZED as CK_FLAGS, 0);

        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 4);
        assert_eq!(commands[0][5], AUTHENTICATOR_GET_INFO);
        assert_eq!(commands[1][5], AUTHENTICATOR_CLIENT_PIN);
        assert_eq!(commands[2][5], AUTHENTICATOR_CLIENT_PIN);
        let mut decoder = minicbor::Decoder::new(&commands[2][6..commands[2].len() - 2]);
        assert_eq!(decoder.map().unwrap(), Some(6));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(commands[3][5], AUTHENTICATOR_GET_INFO);
    }

    #[test]
    fn get_info_failure_does_not_withdraw_a_selected_slot() {
        let connector: Rc<dyn Connector> = Rc::new(ScriptedConnector::new(vec![
            vec![0x01, 0x90, 0x00],
            vec![0x01, 0x90, 0x00],
        ]));
        let mut slot = Fido2Slot::new(connector, FIDO2_AID.to_vec());
        let error = slot.init_slot().unwrap_err();
        slot.set_discovery_error(&error);

        assert!(slot.is_present());
        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert!(
            slot_info
                .slotDescription
                .windows(b"FIDO2".len())
                .any(|window| window == b"FIDO2")
        );
        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        assert!(slot.get_token_info(&mut token_info).is_err());
    }

    #[test]
    fn discoverable_credentials_project_key_pair_and_preserve_response_data() {
        let mut public_key_cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        public_key_cose.extend([0x33; 32]);
        public_key_cose.extend([0x22, 0x58, 0x20]);
        public_key_cose.extend([0x44; 32]);
        let mut response_cbor = vec![0xa1, 0x08];
        response_cbor.extend(&public_key_cose);
        let credential = DiscoverableCredential {
            relying_party: crate::ctap::RelyingParty {
                id: Some("example.com".to_owned()),
                name: Some("Example".to_owned()),
                id_hash: [0x11; 32],
            },
            user_id: b"user-id".to_vec(),
            user_name: Some("alice".to_owned()),
            user_display_name: Some("Alice".to_owned()),
            credential_id: vec![0x22; 32],
            public_key_cose,
            cred_protect: Some(3),
            third_party_payment: Some(true),
            response_cbor: response_cbor.clone(),
        };
        let objects = fido2_token_objects(7, &[credential]).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(objects.iter().all(|object| object.slot_id == Some(7)));
        assert!(objects.iter().all(|object| object.id == [0x22; 32]));
        assert!(objects.iter().all(|object| object.private));
        assert!(objects.iter().all(|object| object.token));

        let public = objects
            .iter()
            .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
            .unwrap();
        assert_eq!(public.label, "Example: Alice public key");
        assert_eq!(public.key_type, CKK_EC as CK_KEY_TYPE);
        assert!(!public.encrypt);
        assert!(public.verify);
        assert!(!public.derive);
        assert_eq!(
            public.attribute_value(CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE),
            Some(vec![
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
            ])
        );
        let mut point = vec![0x04];
        point.extend([0x33; 32]);
        point.extend([0x44; 32]);
        assert_eq!(
            public.attribute_value(CKA_EC_POINT as CK_ATTRIBUTE_TYPE),
            der_octet_string(&point)
        );
        assert!(
            !public
                .attribute_value(CKA_PUBLIC_KEY_INFO as CK_ATTRIBUTE_TYPE)
                .unwrap()
                .is_empty()
        );

        let private = objects
            .iter()
            .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
            .unwrap();
        assert_eq!(private.label, "Example: Alice private key");
        assert_eq!(private.key_type, CKK_EC as CK_KEY_TYPE);
        assert!(private.sensitive);
        assert!(!private.extractable);
        assert!(private.always_sensitive);
        assert!(private.never_extractable);
        assert!(!private.decrypt);
        assert!(private.sign);
        assert!(!private.derive);
        assert_eq!(
            private.attribute_value(CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_TRUE as CK_BBOOL])
        );
        assert_eq!(
            private.attribute_value(CKA_DERIVE as CK_ATTRIBUTE_TYPE),
            Some(vec![CK_TRUE as CK_BBOOL])
        );
        assert_eq!(
            private.attribute_value(CKA_PKCS11RS_FIDO_RP_ID),
            Some(b"example.com".to_vec())
        );

        let data = objects
            .iter()
            .find(|object| object.class == CKO_DATA as CK_OBJECT_CLASS)
            .unwrap();
        assert_eq!(data.label, "Example: Alice");
        assert_eq!(
            data.attribute_value(CKA_APPLICATION as CK_ATTRIBUTE_TYPE),
            Some(b"FIDO2 discoverable credential".to_vec())
        );
        assert_eq!(
            data.attribute_value(CKA_OBJECT_ID as CK_ATTRIBUTE_TYPE),
            Some(vec![0x11; 32])
        );
        assert_eq!(
            data.attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
            Some(response_cbor)
        );
    }

    #[test]
    fn unsupported_cose_keys_still_produce_a_data_object() {
        let response_cbor = vec![0xa1, 0x08, 0xa1, 0x01, 0x18, 0x63];
        let credential = DiscoverableCredential {
            relying_party: crate::ctap::RelyingParty {
                id: Some("example.com".to_owned()),
                name: None,
                id_hash: [0x11; 32],
            },
            user_id: b"user-id".to_vec(),
            user_name: Some("alice".to_owned()),
            user_display_name: None,
            credential_id: vec![0x22; 32],
            public_key_cose: vec![0xa1, 0x01, 0x18, 0x63],
            cred_protect: None,
            third_party_payment: None,
            response_cbor: response_cbor.clone(),
        };
        let objects = fido2_token_objects(7, &[credential]).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].class, CKO_DATA as CK_OBJECT_CLASS);
        assert_eq!(
            objects[0].attribute_value(CKA_VALUE as CK_ATTRIBUTE_TYPE),
            Some(response_cbor)
        );
    }

    #[test]
    fn ed25519_and_rsa_cose_keys_have_lossless_projections() {
        let mut ed25519 = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        ed25519.extend([0x55; 32]);
        let projected = project_cose_public_key(&ed25519).unwrap();
        assert_eq!(projected.key_type, CKK_EC_EDWARDS as CK_KEY_TYPE);
        assert!(matches!(
            projected.public_key,
            PublicKeyMaterial::Ec { public_key, .. } if public_key == [0x55; 32]
        ));

        let mut rsa = vec![0xa3, 0x01, 0x03, 0x20, 0x59, 0x01, 0x00];
        rsa.extend([0x67; 256]);
        rsa.extend([0x21, 0x43, 0x01, 0x00, 0x01]);
        let projected = project_cose_public_key(&rsa).unwrap();
        assert_eq!(projected.key_type, CKK_RSA as CK_KEY_TYPE);
        assert!(matches!(
            projected.public_key,
            PublicKeyMaterial::Rsa(public)
                if public.n().to_bytes_be() == [0x67; 256]
                    && public.e().to_bytes_be() == [0x01, 0x00, 0x01]
        ));

        assert!(project_cose_public_key(&[0xa2, 0x01, 0x02, 0x01, 0x02]).is_none());
    }
}
