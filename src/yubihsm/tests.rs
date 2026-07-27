use super::*;
use crate::{
    configured_yubihsm_public_discovery_credential, parse_yubihsm_pkcs11_metadata, KeyMaterial,
    Slot, TokenObject, YubiHsmDiscoveryCache, YubiHsmObjectKey, YubiHsmPublicDiscoveryConfig,
    YubiHsmSessionRole, YubiHsmSlot, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PROFILE,
    CKO_PUBLIC_KEY, CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER, CKP_PUBLIC_CERTIFICATES_TOKEN,
    CKR_FUNCTION_REJECTED, CKR_USER_NOT_LOGGED_IN, CK_OBJECT_CLASS, CK_PROFILE_ID, CK_TOKEN_INFO,
    YUBIHSM_ALGO_AES128, YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION, YUBIHSM_ALGO_AES192,
    YUBIHSM_ALGO_AES256, YUBIHSM_ALGO_EC_P256, YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION,
    YUBIHSM_ALGO_OPAQUE_DATA, YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE, YUBIHSM_ALGO_RSA_2048,
    YUBIHSM_ALGO_RSA_3072, YUBIHSM_ALGO_RSA_4096, YUBIHSM_ASYMMETRIC_KEY,
    YUBIHSM_AUTHENTICATION_KEY, YUBIHSM_OPAQUE, YUBIHSM_SYMMETRIC_KEY, YUBIHSM_WRAP_KEY,
};
use std::sync::Arc;
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

const PASSWORD: &[u8] = b"password";
const HOST_CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const CARD_CHALLENGE: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
const DEVICE_STATIC_PRIVATE_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const DEVICE_EPHEMERAL_PRIVATE_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
pub(crate) const TEST_AES_KEY: [u8; 16] = [0; 16];
pub(crate) const NIST_AES_KEY_ID: u16 = 3;
const NIST_AES_128_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
pub(crate) const RFC5649_AES_KEY_ID: u16 = 4;
const RFC5649_AES_192_KEY: [u8; 24] = [
    0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e, 0xa1,
    0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
];
pub(crate) const RFC3610_AES_KEY_ID: u16 = 5;
const RFC3610_AES_128_KEY: [u8; 16] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
];
pub(crate) const NIST_GMAC_AES_KEY_ID: u16 = 6;
const NIST_GMAC_AES_128_KEY: [u8; 16] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
];
pub(crate) const RFC3394_AES_KEY_ID: u16 = 7;
const RFC3394_AES_128_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

fn test_private_key(encoded: &[u8]) -> Result<P256SecretKey, Error> {
    P256SecretKey::from_slice(encoded).map_err(|_| Error::from(CKR_DEVICE_ERROR))
}
const RFC7748_ALICE_PRIVATE_KEY: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];
const RFC7748_BOB_PRIVATE_KEY: [u8; 32] = [
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
];
pub(crate) const RFC7748_ALICE_PUBLIC_KEY: [u8; 32] = [
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
];
pub(crate) const RFC7748_BOB_PUBLIC_KEY: [u8; 32] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];
pub(crate) const RFC7748_SHARED_SECRET: [u8; 32] = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];
type InnerCommands = std::rc::Rc<RefCell<Vec<(u8, Vec<u8>)>>>;

static NEXT_TRUST_ENTRY: AtomicU64 = AtomicU64::new(1);

fn unused_trust_prefix() -> OsString {
    let id = NEXT_TRUST_ENTRY.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("pkcs11rs-yubihsm-{id}-"))
        .into_os_string()
}

pub(crate) struct TestTrustEntry {
    prefix: OsString,
    path: PathBuf,
}

impl TestTrustEntry {
    fn new() -> Self {
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let private = test_private_key(&DEVICE_STATIC_PRIVATE_KEY).unwrap();
        let point = p256_public_key(&private).unwrap();
        let public = parse_p256_public_key(&point).unwrap();
        let pem = public.to_public_key_pem(LineEnding::LF).unwrap();
        let prefix = unused_trust_prefix();
        let path = trust::entry_path(&point, Some(&prefix)).unwrap();
        fs::write(&path, pem).unwrap();
        Self { prefix, path }
    }
}

impl Drop for TestTrustEntry {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
pub(crate) struct ProtocolPeer {
    session: RefCell<Option<SecureSession>>,
    expected_host_cryptogram: Cell<Option<[u8; MAC_LENGTH]>>,
    commands: RefCell<Vec<Vec<u8>>>,
    inner_commands: InnerCommands,
    objects: RefCell<Vec<u16>>,
    metadata_objects: RefCell<HashMap<u16, (ObjectInfo, Vec<u8>)>>,
    authkey_domains: RefCell<HashMap<u16, u16>>,
    authkeys_with_get_opaque: RefCell<HashSet<u16>>,
    asymmetric_authkeys: RefCell<HashSet<u16>>,
    listed_authkeys: RefCell<HashSet<u16>>,
    x25519_private_keys: RefCell<HashMap<u16, [u8; 32]>>,
    corrupt_card_cryptogram: Cell<bool>,
    corrupt_response_mac: std::rc::Rc<Cell<bool>>,
    authenticate_payload: Vec<u8>,
    closed_sessions: Cell<usize>,
    connection_epoch: Cell<u64>,
    fail_next_put_opaque: Cell<bool>,
    fail_delete_opaque: RefCell<HashSet<u16>>,
    last_wrapped_object: RefCell<Option<ObjectInfo>>,
    product: &'static str,
    serial: &'static str,
    device_version: [u8; 3],
    device_part_number: Option<&'static [u8]>,
}

fn encode_object_info(info: &ObjectInfo) -> Vec<u8> {
    let mut encoded = vec![0; 66];
    encoded[..8].copy_from_slice(&info.capabilities);
    encoded[8..10].copy_from_slice(&info.id.to_be_bytes());
    encoded[10..12].copy_from_slice(&info.length.to_be_bytes());
    encoded[12..14].copy_from_slice(&info.domains.to_be_bytes());
    encoded[14..18].copy_from_slice(&[
        info.object_type,
        info.algorithm,
        info.sequence,
        info.origin,
    ]);
    encoded[18..18 + info.label.len()].copy_from_slice(info.label.as_bytes());
    encoded[58..].copy_from_slice(&info.delegated_capabilities);
    encoded
}

fn encode_metadata_item(encoded: &mut Vec<u8>, tag: u8, value: &[u8]) {
    encoded.push(tag);
    encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    encoded.extend_from_slice(value);
}

impl ProtocolPeer {
    fn new() -> Self {
        let mut x25519_private_keys = HashMap::new();
        x25519_private_keys.insert(7, RFC7748_ALICE_PRIVATE_KEY);
        x25519_private_keys.insert(8, RFC7748_BOB_PRIVATE_KEY);
        Self {
            session: RefCell::new(None),
            expected_host_cryptogram: Cell::new(None),
            commands: RefCell::new(Vec::new()),
            inner_commands: std::rc::Rc::new(RefCell::new(Vec::new())),
            objects: RefCell::new(vec![1]),
            metadata_objects: RefCell::new(HashMap::new()),
            authkey_domains: RefCell::new(HashMap::from([(1, 0xffff), (2, 0xffff)])),
            authkeys_with_get_opaque: RefCell::new(HashSet::from([1, 2])),
            asymmetric_authkeys: RefCell::new(HashSet::new()),
            listed_authkeys: RefCell::new(HashSet::new()),
            x25519_private_keys: RefCell::new(x25519_private_keys),
            corrupt_card_cryptogram: Cell::new(false),
            corrupt_response_mac: std::rc::Rc::new(Cell::new(false)),
            authenticate_payload: Vec::new(),
            closed_sessions: Cell::new(0),
            connection_epoch: Cell::new(0),
            fail_next_put_opaque: Cell::new(false),
            fail_delete_opaque: RefCell::new(HashSet::new()),
            last_wrapped_object: RefCell::new(None),
            product: "YubiHSM",
            serial: "16909060",
            device_version: [2, 4, 1],
            device_part_number: Some(b"78CLUFX5000P"),
        }
    }

    pub(crate) fn create_session_count(&self) -> usize {
        self.commands
            .borrow()
            .iter()
            .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
            .count()
    }

    pub(crate) fn closed_session_count(&self) -> usize {
        self.closed_sessions.get()
    }

    fn with_bad_card_cryptogram() -> Self {
        let peer = Self::new();
        peer.corrupt_card_cryptogram.set(true);
        peer
    }

    fn with_authenticate_payload(payload: Vec<u8>) -> Self {
        Self {
            authenticate_payload: payload,
            ..Self::new()
        }
    }

    fn without_extended_device_info() -> Self {
        Self {
            device_part_number: None,
            ..Self::new()
        }
    }

    fn legacy_device() -> Self {
        Self {
            device_version: [2, 3, 1],
            device_part_number: None,
            ..Self::new()
        }
    }

    fn use_asymmetric_authentication(&self, authkey_id: u16) {
        self.asymmetric_authkeys.borrow_mut().insert(authkey_id);
    }

    fn use_symmetric_authentication(&self, authkey_id: u16) {
        self.asymmetric_authkeys.borrow_mut().remove(&authkey_id);
    }

    fn list_authentication_key(&self, authkey_id: u16) {
        self.listed_authkeys.borrow_mut().insert(authkey_id);
    }

    fn add_public_certificate_pair(&self) {
        let certificate = Self::attestation_certificate(2).unwrap();
        let certificate_info = ObjectInfo {
            capabilities: [0; 8],
            id: 2,
            length: certificate.len() as u16,
            domains: 0xffff,
            object_type: YUBIHSM_OPAQUE,
            algorithm: YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
            sequence: 1,
            origin: 1,
            label: "public certificate".to_owned(),
            delegated_capabilities: [0; 8],
        };
        self.metadata_objects
            .borrow_mut()
            .insert(2, (certificate_info, certificate));

        let mut metadata = b"MDB1".to_vec();
        metadata.extend_from_slice(&[YUBIHSM_OPAQUE, 0, 2, 1]);
        encode_metadata_item(&mut metadata, 1, b"shared-id");
        encode_metadata_item(&mut metadata, 2, b"metadata certificate");
        let metadata_info = ObjectInfo {
            capabilities: [0; 8],
            id: 100,
            length: metadata.len() as u16,
            domains: 0xffff,
            object_type: YUBIHSM_OPAQUE,
            algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
            sequence: 1,
            origin: 1,
            label: "Meta object for 0x01010002".to_owned(),
            delegated_capabilities: [0; 8],
        };
        self.metadata_objects
            .borrow_mut()
            .insert(100, (metadata_info, metadata));

        let mut key_metadata = b"MDB1".to_vec();
        key_metadata.extend_from_slice(&[3, 0, 1, 1]);
        encode_metadata_item(&mut key_metadata, 1, b"shared-id");
        encode_metadata_item(&mut key_metadata, 2, b"metadata private key");
        encode_metadata_item(&mut key_metadata, 3, b"shared-id");
        encode_metadata_item(&mut key_metadata, 4, b"metadata public key");
        let key_metadata_info = ObjectInfo {
            capabilities: [0; 8],
            id: 101,
            length: key_metadata.len() as u16,
            domains: 0xffff,
            object_type: YUBIHSM_OPAQUE,
            algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
            sequence: 1,
            origin: 1,
            label: "Meta object for 0x01030001".to_owned(),
            delegated_capabilities: [0; 8],
        };
        self.metadata_objects
            .borrow_mut()
            .insert(101, (key_metadata_info, key_metadata));

        let opaque = b"cached opaque value".to_vec();
        self.metadata_objects.borrow_mut().insert(
            4,
            (
                ObjectInfo {
                    capabilities: [0; 8],
                    id: 4,
                    length: opaque.len() as u16,
                    domains: 0xffff,
                    object_type: YUBIHSM_OPAQUE,
                    algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
                    sequence: 1,
                    origin: 1,
                    label: "login-only opaque".to_owned(),
                    delegated_capabilities: [0; 8],
                },
                opaque,
            ),
        );
    }

    fn add_standalone_certificate(&self, id: u16) {
        let certificate = Self::attestation_certificate(id).unwrap();
        self.metadata_objects.borrow_mut().insert(
            id,
            (
                ObjectInfo {
                    capabilities: [0; 8],
                    id,
                    length: certificate.len() as u16,
                    domains: 0xffff,
                    object_type: YUBIHSM_OPAQUE,
                    algorithm: YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
                    sequence: 1,
                    origin: 1,
                    label: "standalone CA certificate".to_owned(),
                    delegated_capabilities: [0; 8],
                },
                certificate,
            ),
        );
    }

    fn set_authkey_domains(&self, authkey_id: u16, domains: u16) {
        self.authkey_domains
            .borrow_mut()
            .insert(authkey_id, domains);
    }

    fn remove_get_opaque(&self, authkey_id: u16) {
        self.authkeys_with_get_opaque
            .borrow_mut()
            .remove(&authkey_id);
    }

    fn x25519_derive(&self, id: u16, public_key: &[u8]) -> Result<Vec<u8>, Error> {
        let private_key = self
            .x25519_private_keys
            .borrow()
            .get(&id)
            .copied()
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if public_key.len() != 32 {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let private_key = x25519_dalek::StaticSecret::from(private_key);
        let public_key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?;
        let public_key = x25519_dalek::PublicKey::from(public_key_bytes);
        Ok(private_key.diffie_hellman(&public_key).as_bytes().to_vec())
    }

    fn aes_key(id: u16) -> &'static [u8] {
        match id {
            NIST_AES_KEY_ID => &NIST_AES_128_KEY,
            RFC5649_AES_KEY_ID => &RFC5649_AES_192_KEY,
            RFC3610_AES_KEY_ID => &RFC3610_AES_128_KEY,
            NIST_GMAC_AES_KEY_ID => &NIST_GMAC_AES_128_KEY,
            RFC3394_AES_KEY_ID => &RFC3394_AES_128_KEY,
            _ => &TEST_AES_KEY,
        }
    }

    fn attestation_certificate(id: u16) -> Result<Vec<u8>, Error> {
        let key = crate::certificate_builder::p256_key();
        Ok(crate::certificate_builder::p256_certificate(
            key.verifying_key(),
            &key,
            &format!("CN=YubiHSM key {id} attestation"),
            &format!("CN=YubiHSM key {id} attestation"),
            u32::from(id),
            true,
        ))
    }

    fn reply(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.commands.borrow_mut().push(request.to_vec());
        match request.first().copied() {
            Some(COMMAND_CREATE_SESSION) => self.create_session(request),
            Some(COMMAND_AUTHENTICATE_SESSION) => self.authenticate_session(request),
            Some(COMMAND_SESSION_MESSAGE) => self.session_message(request),
            Some(value) if value == CommandCode::GetDeviceInfo as u8 => {
                let request = Frame::parse(request)?;
                let response = match request.data.as_slice() {
                    [] => [
                        self.device_version.as_slice(),
                        &[0x01, 0x02, 0x03, 0x04, 62, 3, 0x01, 0x02],
                    ]
                    .concat(),
                    [1] => self
                        .device_part_number
                        .map(<[u8]>::to_vec)
                        .ok_or(CKR_DEVICE_ERROR)?,
                    _ => return Err(CKR_DEVICE_ERROR.into()),
                };
                Frame::new(CommandCode::GetDeviceInfo as u8 | RESPONSE_BIT, response)
                    .map(|frame| frame.encode())
            }
            Some(value) if value == CommandCode::GetDevicePublicKey as u8 => {
                let key = test_private_key(&DEVICE_STATIC_PRIVATE_KEY)?;
                let mut public = p256_public_key(&key)?;
                public[0] = EC_P256_AUTHENTICATION_ALGORITHM;
                Frame::new(
                    CommandCode::GetDevicePublicKey as u8 | RESPONSE_BIT,
                    public.to_vec(),
                )
                .map(|frame| frame.encode())
            }
            _ => Err(CKR_DEVICE_ERROR.into()),
        }
    }

    fn create_session(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let frame = Frame::parse(request)?;
        let authkey_id = frame
            .data
            .get(..2)
            .and_then(|value| value.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(CKR_DEVICE_ERROR)?;
        if !matches!(authkey_id, 1 | 2) {
            return Frame::new(COMMAND_ERROR, vec![0x0b]).map(|frame| frame.encode());
        }
        let asymmetric = self.asymmetric_authkeys.borrow().contains(&authkey_id);
        match (asymmetric, frame.data.len()) {
            (false, 10) => self.create_symmetric_session(&frame.data),
            (true, length) if length == 2 + P256_PUBLIC_KEY_LENGTH => {
                self.create_asymmetric_session(&frame.data)
            }
            _ => Frame::new(COMMAND_ERROR, vec![0x08]).map(|frame| frame.encode()),
        }
    }

    fn create_symmetric_session(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let request = Frame::new(COMMAND_CREATE_SESSION, data.to_vec())?.encode();
        let (session, expected_host_cryptogram, mut response) =
            SecureSession::peer_begin_symmetric(&request, PASSWORD, 7, CARD_CHALLENGE)?;
        *self.session.borrow_mut() = Some(session);
        self.expected_host_cryptogram
            .set(Some(expected_host_cryptogram));
        if self.corrupt_card_cryptogram.replace(false) {
            response[3 + 1 + CHALLENGE_LENGTH] ^= 0x80;
        }
        Ok(response)
    }

    fn create_asymmetric_session(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let host_ephemeral_public = parse_p256_public_key(&data[2..])?;
        let host_static_key = crate::yubico_kdf::yubico_password_p256_key(PASSWORD)?;
        let host_static_public = parse_p256_public_key(&p256_public_key(&host_static_key)?)?;
        let device_static_key = test_private_key(&DEVICE_STATIC_PRIVATE_KEY)?;
        let device_ephemeral_key = test_private_key(&DEVICE_EPHEMERAL_PRIVATE_KEY)?;
        let device_ephemeral_public = p256_public_key(&device_ephemeral_key)?;

        let ephemeral_secret = p256_ecdh(&device_ephemeral_key, &host_ephemeral_public)?;
        let static_secret = p256_ecdh(&device_static_key, &host_static_public)?;
        let session_keys = x963_session_keys(&ephemeral_secret, &static_secret);
        let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
        receipt_input.extend_from_slice(&device_ephemeral_public);
        receipt_input.extend_from_slice(&data[2..]);
        let receipt = aes_cmac(&session_keys[..16], &receipt_input)?;

        let mut counter = [0; AES_BLOCK_SIZE];
        increment_counter(&mut counter);
        *self.session.borrow_mut() = Some(SecureSession::new_peer(
            7,
            session_keys[16..32]
                .try_into()
                .map_err(|_| CKR_DEVICE_ERROR)?,
            session_keys[32..48]
                .try_into()
                .map_err(|_| CKR_DEVICE_ERROR)?,
            session_keys[48..64]
                .try_into()
                .map_err(|_| CKR_DEVICE_ERROR)?,
            counter,
            receipt,
        ));
        self.expected_host_cryptogram.set(None);

        let mut response = vec![7];
        response.extend_from_slice(&device_ephemeral_public);
        response.extend_from_slice(&receipt);
        Frame::new(COMMAND_CREATE_SESSION | RESPONSE_BIT, response).map(|frame| frame.encode())
    }

    fn authenticate_session(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut session_slot = self.session.borrow_mut();
        let session = session_slot.as_mut().ok_or(CKR_DEVICE_ERROR)?;
        let expected = self
            .expected_host_cryptogram
            .get()
            .ok_or(CKR_DEVICE_ERROR)?;
        let response =
            session.peer_authenticate_symmetric(request, &expected, &self.authenticate_payload)?;
        self.expected_host_cryptogram.set(None);
        if !session.is_valid() {
            *session_slot = None;
            self.closed_sessions.set(self.closed_sessions.get() + 1);
        }
        Ok(response)
    }

    fn session_message(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut session_slot = self.session.borrow_mut();
        let session = session_slot.as_mut().ok_or(CKR_DEVICE_ERROR)?;
        let exchange = session.peer_exchange(request, |command, data| {
            let inner = Frame::new(command, data.to_vec())?;
            self.inner_commands
                .borrow_mut()
                .push((inner.command, inner.data.clone()));
            let (response_command, response_data) = match inner.command {
                value if value == CommandCode::GetStorageInfo as u8 => {
                    (inner.command | RESPONSE_BIT, vec![0xaa, 0xbb, 0xcc])
                }
                value if value == CommandCode::GetPseudoRandom as u8 => {
                    if inner.data.len() != 2 {
                        return Err(CKR_DEVICE_ERROR.into());
                    }
                    (
                        inner.command | RESPONSE_BIT,
                        vec![0x5a; u16::from_be_bytes(inner.data.try_into().unwrap()) as usize],
                    )
                }
                value if value == CommandCode::CloseSession as u8 => {
                    (inner.command | RESPONSE_BIT, vec![])
                }
                value if value == CommandCode::ListObjects as u8 => {
                    let mut objects = Vec::new();
                    for id in self.listed_authkeys.borrow().iter() {
                        objects.extend_from_slice(&id.to_be_bytes());
                        objects.extend_from_slice(&[YUBIHSM_AUTHENTICATION_KEY, 1]);
                    }
                    for id in self.objects.borrow().iter() {
                        objects.extend_from_slice(&id.to_be_bytes());
                        objects.extend_from_slice(&[3, 1]);
                    }
                    for (id, (info, _)) in self.metadata_objects.borrow().iter() {
                        objects.extend_from_slice(&id.to_be_bytes());
                        objects.extend_from_slice(&[info.object_type, info.sequence]);
                    }
                    (inner.command | RESPONSE_BIT, objects)
                }
                value if value == CommandCode::GetObjectInfo as u8 => {
                    if inner.data.len() != 3 {
                        return Err(CKR_DEVICE_ERROR.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    if inner.data[2] == YUBIHSM_AUTHENTICATION_KEY {
                        let domains = self
                            .authkey_domains
                            .borrow()
                            .get(&id)
                            .copied()
                            .ok_or(CKR_DEVICE_ERROR)?;
                        let info = ObjectInfo {
                            capabilities: if self.authkeys_with_get_opaque.borrow().contains(&id) {
                                crate::yubihsm_capabilities(&[0])
                            } else {
                                [0; 8]
                            },
                            id,
                            length: 32,
                            domains,
                            object_type: YUBIHSM_AUTHENTICATION_KEY,
                            algorithm: if self.asymmetric_authkeys.borrow().contains(&id) {
                                YUBIHSM_ALGO_EC_P256_YUBICO_AUTHENTICATION
                            } else {
                                YUBIHSM_ALGO_AES128_YUBICO_AUTHENTICATION
                            },
                            sequence: 1,
                            origin: 1,
                            label: format!("authkey-{id}"),
                            delegated_capabilities: [0; 8],
                        };
                        (inner.command | RESPONSE_BIT, encode_object_info(&info))
                    } else if let Some((info, _)) = self
                        .metadata_objects
                        .borrow()
                        .get(&id)
                        .filter(|(info, _)| info.object_type == inner.data[2])
                    {
                        (inner.command | RESPONSE_BIT, encode_object_info(info))
                    } else if inner.data[2] != 3 {
                        return Err(CKR_DEVICE_ERROR.into());
                    } else if self.x25519_private_keys.borrow().contains_key(&id) {
                        let mut info = vec![0; 66];
                        info[7 - 0x0b / 8] |= 1 << (0x0b % 8);
                        info[8..10].copy_from_slice(&id.to_be_bytes());
                        info[10..12].copy_from_slice(&32u16.to_be_bytes());
                        info[12..14].copy_from_slice(&0xffffu16.to_be_bytes());
                        info[14..18].copy_from_slice(&[3, 56, 1, 1]);
                        info[18..26].copy_from_slice(b"test-x25");
                        (inner.command | RESPONSE_BIT, info)
                    } else {
                        let mut info = vec![0; 66];
                        for bit in [0x05usize, 0x06, 0x09, 0x0a] {
                            info[7 - bit / 8] |= 1 << (bit % 8);
                        }
                        info[8..10].copy_from_slice(&id.to_be_bytes());
                        info[10..12].copy_from_slice(&256u16.to_be_bytes());
                        info[12..14].copy_from_slice(&0xffffu16.to_be_bytes());
                        info[14..18].copy_from_slice(&[3, 9, 1, 1]);
                        info[18..26].copy_from_slice(b"test-rsa");
                        (inner.command | RESPONSE_BIT, info)
                    }
                }
                value if value == CommandCode::GetOpaque as u8 => {
                    if inner.data.len() != 2 {
                        return Err(CKR_DEVICE_ERROR.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let value = self
                        .metadata_objects
                        .borrow()
                        .get(&id)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_else(|| inner.data.clone());
                    (inner.command | RESPONSE_BIT, value)
                }
                value if value == CommandCode::GetPublicKey as u8 => {
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let algorithm = self
                        .metadata_objects
                        .borrow()
                        .get(&id)
                        .map(|(info, _)| info.algorithm);
                    if algorithm == Some(YUBIHSM_ALGO_EC_P256) {
                        let private = test_private_key(&DEVICE_STATIC_PRIVATE_KEY)?;
                        let mut response = vec![YUBIHSM_ALGO_EC_P256];
                        response.extend_from_slice(&p256_public_key(&private)?);
                        (inner.command | RESPONSE_BIT, response)
                    } else if let Some(private_key) = self.x25519_private_keys.borrow().get(&id) {
                        let private_key = x25519_dalek::StaticSecret::from(*private_key);
                        let mut key = vec![56];
                        key.extend_from_slice(
                            x25519_dalek::PublicKey::from(&private_key).as_bytes(),
                        );
                        (inner.command | RESPONSE_BIT, key)
                    } else {
                        let mut key = vec![9, 0xc5];
                        key.resize(257, 0xa5);
                        key[256] |= 1;
                        (inner.command | RESPONSE_BIT, key)
                    }
                }
                value
                    if value == CommandCode::SignAttestationCertificate as u8
                        && inner.data.len() == 4 =>
                {
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    (
                        inner.command | RESPONSE_BIT,
                        Self::attestation_certificate(id)?,
                    )
                }
                value
                    if value == CommandCode::GenerateAsymmetricKey as u8
                        || value == CommandCode::PutAsymmetricKey as u8
                        || value == CommandCode::GenerateWrapKey as u8
                        || value == CommandCode::PutPublicWrapKey as u8
                            && inner.data.len() >= 61 =>
                {
                    let requested = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let id = if requested == 0 {
                        (2..=u16::MAX)
                            .find(|candidate| {
                                !self.objects.borrow().contains(candidate)
                                    && !self.metadata_objects.borrow().contains_key(candidate)
                            })
                            .ok_or(CKR_DEVICE_MEMORY)?
                    } else {
                        requested
                    };
                    if inner.command == CommandCode::GenerateAsymmetricKey as u8
                        && inner.data.get(52) == Some(&56)
                    {
                        let private_key = match id {
                            7 => RFC7748_ALICE_PRIVATE_KEY,
                            8 => RFC7748_BOB_PRIVATE_KEY,
                            _ => {
                                let mut private_key = [0; 32];
                                getrandom::fill(&mut private_key)
                                    .map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
                                private_key
                            }
                        };
                        self.x25519_private_keys
                            .borrow_mut()
                            .insert(id, private_key);
                    }
                    let object_type = match inner.command {
                        value if value == CommandCode::GenerateWrapKey as u8 => YUBIHSM_WRAP_KEY,
                        value if value == CommandCode::PutPublicWrapKey as u8 => {
                            crate::YUBIHSM_PUBLIC_WRAP_KEY
                        }
                        _ => YUBIHSM_ASYMMETRIC_KEY,
                    };
                    let algorithm = *inner.data.get(52).ok_or(CKR_DATA_LEN_RANGE)?;
                    let length = if object_type == crate::YUBIHSM_PUBLIC_WRAP_KEY {
                        inner.data.len().checked_sub(61).ok_or(CKR_DATA_LEN_RANGE)?
                    } else {
                        match algorithm {
                            YUBIHSM_ALGO_RSA_2048 => 256,
                            YUBIHSM_ALGO_RSA_3072 => 384,
                            YUBIHSM_ALGO_RSA_4096 => 512,
                            _ => 32,
                        }
                    };
                    let label = inner.data[2..42]
                        .split(|byte| *byte == 0)
                        .next()
                        .and_then(|label| std::str::from_utf8(label).ok())
                        .ok_or(CKR_DEVICE_ERROR)?
                        .to_owned();
                    let delegated_capabilities = if matches!(
                        object_type,
                        YUBIHSM_WRAP_KEY | crate::YUBIHSM_PUBLIC_WRAP_KEY
                    ) {
                        inner
                            .data
                            .get(53..61)
                            .ok_or(CKR_DATA_LEN_RANGE)?
                            .try_into()
                            .unwrap()
                    } else {
                        [0; 8]
                    };
                    self.metadata_objects.borrow_mut().insert(
                        id,
                        (
                            ObjectInfo {
                                capabilities: inner.data[44..52].try_into().unwrap(),
                                id,
                                length: length as u16,
                                domains: u16::from_be_bytes(inner.data[42..44].try_into().unwrap()),
                                object_type,
                                algorithm,
                                sequence: 1,
                                origin: if inner.command == CommandCode::PutPublicWrapKey as u8 {
                                    2
                                } else {
                                    1
                                },
                                label,
                                delegated_capabilities,
                            },
                            if object_type == crate::YUBIHSM_PUBLIC_WRAP_KEY {
                                inner.data[61..].to_vec()
                            } else {
                                Vec::new()
                            },
                        ),
                    );
                    (inner.command | RESPONSE_BIT, id.to_be_bytes().to_vec())
                }
                value if value == CommandCode::PutOpaque as u8 => {
                    if inner.data.len() < 53 {
                        (inner.command | RESPONSE_BIT, inner.data)
                    } else if self.fail_next_put_opaque.replace(false) {
                        (COMMAND_ERROR, vec![0x0b])
                    } else {
                        let requested = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                        let id = if requested == 0 {
                            (1..=u16::MAX)
                                .find(|candidate| {
                                    !self.objects.borrow().contains(candidate)
                                        && !self.metadata_objects.borrow().contains_key(candidate)
                                })
                                .ok_or(CKR_DEVICE_MEMORY)?
                        } else {
                            requested
                        };
                        let label = inner.data[2..42]
                            .split(|byte| *byte == 0)
                            .next()
                            .and_then(|label| std::str::from_utf8(label).ok())
                            .ok_or(CKR_DEVICE_ERROR)?
                            .to_owned();
                        let value = inner.data[53..].to_vec();
                        self.metadata_objects.borrow_mut().insert(
                            id,
                            (
                                ObjectInfo {
                                    capabilities: inner.data[44..52].try_into().unwrap(),
                                    id,
                                    length: value.len() as u16,
                                    domains: u16::from_be_bytes(
                                        inner.data[42..44].try_into().unwrap(),
                                    ),
                                    object_type: YUBIHSM_OPAQUE,
                                    algorithm: inner.data[52],
                                    sequence: 1,
                                    origin: 2,
                                    label,
                                    delegated_capabilities: [0; 8],
                                },
                                value,
                            ),
                        );
                        (inner.command | RESPONSE_BIT, id.to_be_bytes().to_vec())
                    }
                }
                value if value == CommandCode::DeleteObject as u8 => {
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let object_type = inner.data[2];
                    if object_type == YUBIHSM_OPAQUE
                        && self.fail_delete_opaque.borrow().contains(&id)
                    {
                        (COMMAND_ERROR, vec![0x0b])
                    } else {
                        self.objects
                            .borrow_mut()
                            .retain(|candidate| *candidate != id);
                        let remove_metadata = self
                            .metadata_objects
                            .borrow()
                            .get(&id)
                            .is_some_and(|(info, _)| info.object_type == object_type);
                        if remove_metadata {
                            self.metadata_objects.borrow_mut().remove(&id);
                        }
                        (inner.command | RESPONSE_BIT, vec![])
                    }
                }
                value
                    if value == CommandCode::ExportWrapped as u8 && inner.data.len() >= 5
                        || (value == CommandCode::GetRsaWrappedKey as u8
                            || value == CommandCode::ExportRsaWrapped as u8)
                            && inner.data.len() >= 28 =>
                {
                    let missing_public_wrap_key =
                        if inner.command == CommandCode::ExportRsaWrapped as u8 {
                            let wrapping_key_id =
                                u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                            !self
                                .metadata_objects
                                .borrow()
                                .get(&wrapping_key_id)
                                .is_some_and(|(info, _)| {
                                    info.object_type == crate::YUBIHSM_PUBLIC_WRAP_KEY
                                })
                        } else {
                            false
                        };
                    if missing_public_wrap_key {
                        (COMMAND_ERROR, vec![0x0b])
                    } else {
                        let target_type = inner.data[2];
                        let target_id = u16::from_be_bytes(inner.data[3..5].try_into().unwrap());
                        if let Some((info, _)) = self
                            .metadata_objects
                            .borrow()
                            .get(&target_id)
                            .filter(|(info, _)| info.object_type == target_type)
                        {
                            *self.last_wrapped_object.borrow_mut() = Some(info.clone());
                        }
                        let mut wrapped = b"wrapped-object:".to_vec();
                        wrapped.push(inner.command);
                        wrapped.extend_from_slice(&inner.data);
                        (inner.command | RESPONSE_BIT, wrapped)
                    }
                }
                value if value == CommandCode::ImportWrapped as u8 && inner.data.len() > 2 => {
                    if let Some(mut info) = self.last_wrapped_object.borrow().clone() {
                        info.sequence = info.sequence.wrapping_add(1);
                        info.origin = 2;
                        self.metadata_objects
                            .borrow_mut()
                            .insert(info.id, (info.clone(), Vec::new()));
                        let [high, low] = info.id.to_be_bytes();
                        (
                            inner.command | RESPONSE_BIT,
                            [info.object_type, high, low].to_vec(),
                        )
                    } else {
                        let id = 20;
                        self.metadata_objects.borrow_mut().insert(
                            id,
                            (
                                ObjectInfo {
                                    capabilities: crate::yubihsm_capabilities(&[0x32, 0x33]),
                                    id,
                                    length: 16,
                                    domains: 0xffff,
                                    object_type: YUBIHSM_SYMMETRIC_KEY,
                                    algorithm: YUBIHSM_ALGO_AES128,
                                    sequence: 1,
                                    origin: 2,
                                    label: "AES-CCM unwrapped".to_owned(),
                                    delegated_capabilities: [0; 8],
                                },
                                Vec::new(),
                            ),
                        );
                        (
                            inner.command | RESPONSE_BIT,
                            [YUBIHSM_SYMMETRIC_KEY, 0, id as u8].to_vec(),
                        )
                    }
                }
                value if value == CommandCode::ImportRsaWrapped as u8 && inner.data.len() > 25 => {
                    if let Some(mut info) = self.last_wrapped_object.borrow().clone() {
                        let collision =
                            self.metadata_objects.borrow().get(&info.id).is_some_and(
                                |(existing, _)| existing.object_type == info.object_type,
                            );
                        if collision {
                            (COMMAND_ERROR, vec![0x0b])
                        } else {
                            info.sequence = info.sequence.wrapping_add(1);
                            info.origin = 2;
                            self.metadata_objects
                                .borrow_mut()
                                .insert(info.id, (info.clone(), Vec::new()));
                            let [high, low] = info.id.to_be_bytes();
                            (
                                inner.command | RESPONSE_BIT,
                                [info.object_type, high, low].to_vec(),
                            )
                        }
                    } else {
                        let id = 21;
                        self.metadata_objects.borrow_mut().insert(
                            id,
                            (
                                ObjectInfo {
                                    capabilities: crate::yubihsm_capabilities(&[0x32, 0x33]),
                                    id,
                                    length: 16,
                                    domains: 0xffff,
                                    object_type: YUBIHSM_SYMMETRIC_KEY,
                                    algorithm: YUBIHSM_ALGO_AES128,
                                    sequence: 1,
                                    origin: 2,
                                    label: "RSA unwrapped object".to_owned(),
                                    delegated_capabilities: [0; 8],
                                },
                                Vec::new(),
                            ),
                        );
                        (
                            inner.command | RESPONSE_BIT,
                            [YUBIHSM_SYMMETRIC_KEY, 0, id as u8].to_vec(),
                        )
                    }
                }
                value if value == CommandCode::PutRsaWrappedKey as u8 && inner.data.len() >= 58 => {
                    let object_type = inner.data[2];
                    let requested = u16::from_be_bytes(inner.data[3..5].try_into().unwrap());
                    let id = if requested == 0 { 22 } else { requested };
                    let label = inner.data[5..45]
                        .split(|byte| *byte == 0)
                        .next()
                        .and_then(|label| std::str::from_utf8(label).ok())
                        .ok_or(CKR_DEVICE_ERROR)?
                        .to_owned();
                    let info = ObjectInfo {
                        capabilities: inner.data[47..55].try_into().unwrap(),
                        id,
                        length: match inner.data[55] {
                            YUBIHSM_ALGO_AES128 => 16,
                            YUBIHSM_ALGO_AES192 => 24,
                            YUBIHSM_ALGO_AES256 => 32,
                            YUBIHSM_ALGO_RSA_2048 => 256,
                            YUBIHSM_ALGO_RSA_3072 => 384,
                            YUBIHSM_ALGO_RSA_4096 => 512,
                            _ => 32,
                        },
                        domains: u16::from_be_bytes(inner.data[45..47].try_into().unwrap()),
                        object_type,
                        algorithm: inner.data[55],
                        sequence: 1,
                        origin: 2,
                        label,
                        delegated_capabilities: [0; 8],
                    };
                    self.metadata_objects
                        .borrow_mut()
                        .insert(id, (info, Vec::new()));
                    let [high, low] = id.to_be_bytes();
                    (
                        inner.command | RESPONSE_BIT,
                        [object_type, high, low].to_vec(),
                    )
                }
                value if value == CommandCode::SignPkcs1 as u8 => {
                    (inner.command | RESPONSE_BIT, vec![0x5a; 256])
                }
                value if value == CommandCode::DecryptPkcs1 as u8 => {
                    (inner.command | RESPONSE_BIT, b"plaintext".to_vec())
                }
                value if value == CommandCode::DeriveEcdh as u8 => {
                    if inner.data.len() == 34 {
                        let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                        (
                            inner.command | RESPONSE_BIT,
                            self.x25519_derive(id, &inner.data[2..])?,
                        )
                    } else {
                        (inner.command | RESPONSE_BIT, vec![0x42; 32])
                    }
                }
                value
                    if value == CommandCode::EncryptEcb as u8
                        || value == CommandCode::DecryptEcb as u8 =>
                {
                    if inner.data.len() < 2 || !crate::is_multiple_of(inner.data.len() - 2, 16) {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let mode = if value == CommandCode::EncryptEcb as u8 {
                        Direction::Encrypt
                    } else {
                        Direction::Decrypt
                    };
                    (
                        inner.command | RESPONSE_BIT,
                        aes_ecb(Self::aes_key(id), &inner.data[2..], mode)?,
                    )
                }
                value
                    if value == CommandCode::EncryptCbc as u8
                        || value == CommandCode::DecryptCbc as u8 =>
                {
                    if inner.data.len() < 18 || !crate::is_multiple_of(inner.data.len() - 18, 16) {
                        return Err(CKR_DATA_LEN_RANGE.into());
                    }
                    let id = u16::from_be_bytes(inner.data[..2].try_into().unwrap());
                    let mode = if value == CommandCode::EncryptCbc as u8 {
                        Direction::Encrypt
                    } else {
                        Direction::Decrypt
                    };
                    (
                        inner.command | RESPONSE_BIT,
                        aes_cbc(
                            Self::aes_key(id),
                            &inner.data[2..18],
                            &inner.data[18..],
                            mode,
                        )?,
                    )
                }
                value if value == CommandCode::ResetDevice as u8 && inner.data == [0xde] => {
                    (COMMAND_ERROR, vec![0x0b])
                }
                _ => (inner.command | RESPONSE_BIT, inner.data),
            };
            Ok((response_command, response_data))
        });
        let response = match exchange {
            Ok(response) => response,
            Err(error) => {
                *session_slot = None;
                self.closed_sessions.set(self.closed_sessions.get() + 1);
                return Err(error);
            }
        };
        let mut response = response;
        if self.corrupt_response_mac.replace(false) {
            let first_mac_byte = response
                .len()
                .checked_sub(MAC_LENGTH)
                .ok_or(CKR_DEVICE_ERROR)?;
            response[first_mac_byte] ^= 0x80;
        }
        if !session.is_valid() {
            *session_slot = None;
            self.closed_sessions.set(self.closed_sessions.get() + 1);
        }
        Ok(response)
    }
}

pub(crate) fn make_yubihsm_test_slot() -> (
    Box<dyn crate::Slot>,
    InnerCommands,
    std::rc::Rc<Cell<bool>>,
    TestTrustEntry,
) {
    let peer = std::rc::Rc::new(ProtocolPeer::new());
    let commands = peer.inner_commands.clone();
    let corrupt_response_mac = peer.corrupt_response_mac.clone();
    let trust = TestTrustEntry::new();
    let mut slot = crate::YubiHsmSlot::new(
        peer,
        (2, 4, 1),
        vec![
            1, 5, 9, 12, 19, 20, 21, 22, 25, 29, 46, 48, 50, 51, 52, 53, 54, 55, 56,
        ],
    );
    slot.trust_prefix = Some(trust.prefix.clone());
    (Box::new(slot), commands, corrupt_response_mac, trust)
}

pub(crate) fn make_yubihsm_asymmetric_test_slot() -> (
    Box<dyn crate::Slot>,
    InnerCommands,
    std::rc::Rc<Cell<bool>>,
    TestTrustEntry,
) {
    let peer = std::rc::Rc::new(ProtocolPeer::new());
    peer.use_asymmetric_authentication(1);
    let commands = peer.inner_commands.clone();
    let corrupt_response_mac = peer.corrupt_response_mac.clone();
    let trust = TestTrustEntry::new();
    let mut slot = crate::YubiHsmSlot::new(
        peer,
        (2, 4, 1),
        vec![
            1, 5, 9, 12, 19, 20, 21, 22, 25, 29, 46, 48, 50, 51, 52, 53, 54, 55, 56,
        ],
    );
    slot.trust_prefix = Some(trust.prefix.clone());
    (Box::new(slot), commands, corrupt_response_mac, trust)
}

pub(crate) fn make_yubihsm_keypair_collision_test_slot() -> (
    Box<dyn crate::Slot>,
    InnerCommands,
    std::rc::Rc<Cell<bool>>,
    TestTrustEntry,
) {
    let peer = std::rc::Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    replace_metadata(
        peer.as_ref(),
        101,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        1,
        &[(3, &[0, 2]), (4, b"collision public")],
    );
    let commands = peer.inner_commands.clone();
    let corrupt_response_mac = peer.corrupt_response_mac.clone();
    let trust = TestTrustEntry::new();
    let mut slot = crate::YubiHsmSlot::new(
        peer,
        (2, 4, 1),
        vec![
            1, 2, 5, 9, 12, 19, 20, 21, 22, 25, 29, 46, 48, 50, 51, 52, 53, 54, 55, 56,
        ],
    );
    slot.trust_prefix = Some(trust.prefix.clone());
    (Box::new(slot), commands, corrupt_response_mac, trust)
}

pub(crate) fn make_yubihsm_metadata_test_slot(valid: bool) -> Box<dyn crate::Slot> {
    let peer = std::rc::Rc::new(ProtocolPeer::new());
    let mut value = b"MDB1\x03\x00\x01\x01".to_vec();
    encode_metadata_item(&mut value, 1, b"private-id");
    encode_metadata_item(&mut value, 2, b"private label");
    encode_metadata_item(&mut value, 3, b"public-id");
    encode_metadata_item(&mut value, 4, b"public label");
    if !valid {
        value[0] = b'X';
    }
    peer.metadata_objects.borrow_mut().insert(
        0x7000,
        (
            ObjectInfo {
                capabilities: [0; 8],
                id: 0x7000,
                length: value.len() as u16,
                domains: 0xffff,
                object_type: crate::YUBIHSM_OPAQUE,
                algorithm: crate::YUBIHSM_ALGO_OPAQUE_DATA,
                sequence: 1,
                origin: 1,
                label: "Meta object for 0x01030001".to_owned(),
                delegated_capabilities: [0; 8],
            },
            value,
        ),
    );
    Box::new(crate::YubiHsmSlot::new(
        peer,
        (2, 4, 1),
        vec![1, 5, 9, 12, 19, 20, 21, 22, 25],
    ))
}

pub(crate) fn make_yubihsm_imported_key_test_slot() -> Box<dyn crate::Slot> {
    let peer = std::rc::Rc::new(ProtocolPeer::new());
    peer.objects.borrow_mut().clear();
    peer.metadata_objects.borrow_mut().insert(
        2,
        (
            ObjectInfo {
                capabilities: [0; 8],
                id: 2,
                length: 256,
                domains: 0xffff,
                object_type: crate::YUBIHSM_ASYMMETRIC_KEY,
                algorithm: crate::YUBIHSM_ALGO_RSA_2048,
                sequence: 1,
                origin: 0,
                label: "imported-rsa".to_owned(),
                delegated_capabilities: [0; 8],
            },
            Vec::new(),
        ),
    );
    Box::new(crate::YubiHsmSlot::new(
        peer,
        (2, 4, 1),
        vec![crate::YUBIHSM_ALGO_RSA_2048],
    ))
}

pub(crate) fn make_yubihsm_connector_named_test_slot() -> Box<dyn crate::Slot> {
    let mut peer = ProtocolPeer::new();
    peer.product = "YubiHSM Connector";
    peer.serial = "*";
    let mut slot = crate::YubiHsmSlot::new(
        std::rc::Rc::new(peer),
        (0, 0, 0),
        vec![1, 5, 9, 12, 19, 20, 21, 22, 25],
    );
    crate::Slot::init_slot(&mut slot).unwrap();
    Box::new(slot)
}

impl Connector for ProtocolPeer {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        self.product
    }
    fn serial(&self) -> &str {
        self.serial
    }
    fn major(&self) -> u8 {
        2
    }
    fn minor(&self) -> u8 {
        4
    }
    fn is_present(&self) -> bool {
        true
    }
    fn connection_epoch(&self) -> u64 {
        self.connection_epoch.get()
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = self.reply(send_buffer)?;
        if response.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

#[derive(Debug)]
struct SymmetricHsmAuthPeer {
    serial: &'static str,
}

impl Connector for SymmetricHsmAuthPeer {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "YubiKey"
    }
    fn serial(&self) -> &str {
        self.serial
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        7
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn send_apdu(&self, command: &crate::CommandApdu) -> Result<crate::ResponseApdu, Error> {
        if command.ins != 0x03 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let context = test_tlv_value(&command.data, 0x77)?;
        let card_cryptogram = test_tlv_value(&command.data, 0x78)?;
        let password = test_tlv_value(&command.data, 0x73)?;
        if context.len() != 16
            || card_cryptogram.len() != 8
            || password != [PASSWORD, &[0; 8]].concat()
        {
            return Ok(crate::ResponseApdu {
                data: Vec::new(),
                status: 0x63c7,
            });
        }
        let static_keys = crate::yubico_password_kdf(PASSWORD)?;
        let s_enc = derive_key(&static_keys[..16], 0x04, context)?;
        let s_mac = derive_key(&static_keys[16..], 0x06, context)?;
        let s_rmac = derive_key(&static_keys[16..], 0x07, context)?;
        if card_cryptogram != derive_cryptogram(&s_mac, 0x00, context)? {
            return Ok(crate::ResponseApdu {
                data: Vec::new(),
                status: 0x6a80,
            });
        }
        Ok(crate::ResponseApdu {
            data: [s_enc, s_mac, s_rmac].concat(),
            status: 0x9000,
        })
    }
    fn send_short_apdu(&self, command: &crate::CommandApdu) -> Result<crate::ResponseApdu, Error> {
        self.send_apdu(command)
    }
    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        Err(CKR_DEVICE_ERROR.into())
    }
}

#[derive(Debug)]
struct AsymmetricHsmAuthPeer {
    ephemeral_key: P256SecretKey,
    public_key: Vec<u8>,
    fail_calculate: bool,
}

impl AsymmetricHsmAuthPeer {
    fn new() -> Self {
        let ephemeral_key = test_private_key(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ])
        .unwrap();
        let public_key = p256_public_key(&ephemeral_key).unwrap().to_vec();
        Self {
            ephemeral_key,
            public_key,
            fail_calculate: false,
        }
    }

    fn failing_calculate() -> Self {
        Self {
            fail_calculate: true,
            ..Self::new()
        }
    }
}

impl Connector for AsymmetricHsmAuthPeer {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }
    fn manufacturer(&self) -> &str {
        "Yubico"
    }
    fn product(&self) -> &str {
        "YubiKey"
    }
    fn serial(&self) -> &str {
        "87654321"
    }
    fn major(&self) -> u8 {
        5
    }
    fn minor(&self) -> u8 {
        7
    }
    fn is_present(&self) -> bool {
        true
    }
    fn buffer_size(&self) -> usize {
        4096
    }
    fn send_apdu(&self, command: &crate::CommandApdu) -> Result<crate::ResponseApdu, Error> {
        let password = test_tlv_value(&command.data, 0x73)?;
        if password != [PASSWORD, &[0; 8]].concat() {
            return Ok(crate::ResponseApdu {
                data: Vec::new(),
                status: 0x63c7,
            });
        }
        if command.ins == 0x04 {
            return Ok(crate::ResponseApdu {
                data: self.public_key.clone(),
                status: 0x9000,
            });
        }
        if command.ins != 0x03 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        if self.fail_calculate {
            return Ok(crate::ResponseApdu {
                data: Vec::new(),
                status: 0x63c7,
            });
        }
        let context = test_tlv_value(&command.data, 0x77)?;
        let device_public_key = test_tlv_value(&command.data, 0x7c)?;
        let receipt = test_tlv_value(&command.data, 0x78)?;
        if context.len() != P256_PUBLIC_KEY_LENGTH * 2
            || context[..P256_PUBLIC_KEY_LENGTH] != self.public_key
            || receipt.len() != ASYMMETRIC_RECEIPT_LENGTH
        {
            return Err(CKR_DATA_INVALID.into());
        }
        let device_ephemeral = parse_p256_public_key(&context[P256_PUBLIC_KEY_LENGTH..])?;
        let device_static = parse_p256_public_key(device_public_key)?;
        let host_static = crate::yubico_kdf::yubico_password_p256_key(PASSWORD)?;
        let ephemeral_secret = p256_ecdh(&self.ephemeral_key, &device_ephemeral)?;
        let static_secret = p256_ecdh(&host_static, &device_static)?;
        let keys = x963_session_keys(&ephemeral_secret, &static_secret);
        let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
        receipt_input.extend_from_slice(&context[P256_PUBLIC_KEY_LENGTH..]);
        receipt_input.extend_from_slice(&context[..P256_PUBLIC_KEY_LENGTH]);
        if !bool::from(aes_cmac(&keys[..16], &receipt_input)?.ct_eq(receipt)) {
            return Ok(crate::ResponseApdu {
                data: Vec::new(),
                status: 0x6a80,
            });
        }
        Ok(crate::ResponseApdu {
            data: keys[16..].to_vec(),
            status: 0x9000,
        })
    }
    fn send_short_apdu(&self, command: &crate::CommandApdu) -> Result<crate::ResponseApdu, Error> {
        self.send_apdu(command)
    }
    fn transmit<'a>(
        &self,
        _send_buffer: &[u8],
        _receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        Err(CKR_DEVICE_ERROR.into())
    }
}

fn test_tlv_value(encoded: &[u8], wanted: u8) -> Result<&[u8], Error> {
    let mut offset = 0;
    while offset < encoded.len() {
        let tag = encoded[offset];
        let first_length = *encoded.get(offset + 1).ok_or(CKR_DATA_INVALID)?;
        let (length, header_length) = if first_length <= 0x7f {
            (first_length as usize, 2)
        } else if first_length == 0x81 {
            (
                *encoded.get(offset + 2).ok_or(CKR_DATA_INVALID)? as usize,
                3,
            )
        } else {
            return Err(CKR_DATA_INVALID.into());
        };
        let value = encoded
            .get(offset + header_length..offset + header_length + length)
            .ok_or(CKR_DATA_INVALID)?;
        if tag == wanted {
            return Ok(value);
        }
        offset += header_length + length;
    }
    Err(CKR_DATA_INVALID.into())
}

#[test]
fn frame_parser_requires_exact_length() {
    assert_eq!(Frame::parse(&[0x81, 0, 1, 0xaa]).unwrap().data, [0xaa]);
    assert!(Frame::parse(&[0x81, 0, 2, 0xaa]).is_err());
    assert!(Frame::parse(&[0x81, 0, 0, 0xaa]).is_err());
}

#[test]
fn yubihsm_login_username_encodes_the_authentication_key_and_provider() {
    let login = crate::parse_hsmauth_username(b":00fFdefault@12345678").unwrap();
    assert_eq!(login.label, "default");
    assert_eq!(login.source, Some("12345678"));
    assert_eq!(login.authkey_id, 0xff);

    let login = crate::parse_hsmauth_username(":0001räksmörgås".as_bytes()).unwrap();
    assert_eq!(login.label, "räksmörgås");
    assert!(login.source.is_none());
    assert_eq!(login.authkey_id, 1);

    assert!(matches!(
        crate::parse_yubihsm_login_username(b"00fF").unwrap(),
        crate::YubiHsmLoginUsername::Direct(0xff)
    ));
}

#[test]
fn yubihsm_login_splits_username_from_password() {
    assert_eq!(
        crate::split_yubihsm_login(b"00fFpassword").unwrap(),
        (b"00fF".as_slice(), Some(PASSWORD))
    );
    assert_eq!(
        crate::split_yubihsm_login(b":0001default:pass:word").unwrap(),
        (b":0001default".as_slice(), Some(b"pass:word".as_slice()))
    );
    assert_eq!(
        crate::split_yubihsm_login(b":0001default@12345678").unwrap(),
        (b":0001default@12345678".as_slice(), None)
    );
    assert_eq!(
        crate::split_yubihsm_login(b":0001default:").unwrap(),
        (b":0001default".as_slice(), Some(b"".as_slice()))
    );
}

#[test]
fn yubihsm_login_rejects_malformed_usernames() {
    for username in [
        b"default".as_slice(),
        b":0001",
        b":xyz1default",
        b":0001default@",
        b":0001default@source@extra",
        b":0001default:source",
        b":0001default\x01",
        b"@001",
        b"@00ff",
        b"@xyz1",
    ] {
        assert!(
            crate::parse_yubihsm_login_username(username).is_err(),
            "accepted {username:?}"
        );
    }
}

#[test]
fn password_derivation_matches_yubihsm_defaults() {
    let keys = crate::yubico_password_kdf(PASSWORD).unwrap();
    assert_eq!(
        keys.as_slice(),
        [
            0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
            0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
            0x05, 0xd2, 0xce, 0x0a,
        ]
    );
}

fn public_discovery_credential(password: &str) -> Arc<YubiHsmPublicDiscoveryConfig> {
    configured_yubihsm_public_discovery_credential(Some(format!("0001{password}").into()))
        .unwrap()
        .unwrap()
}

fn hsmauth_public_discovery_credential() -> Arc<YubiHsmPublicDiscoveryConfig> {
    configured_yubihsm_public_discovery_credential(Some(
        ":0001default key@12345678:password".into(),
    ))
    .unwrap()
    .unwrap()
}

fn symmetric_hsmauth_provider(serial: &'static str) -> crate::HsmAuthProvider {
    symmetric_hsmauth_provider_with_label(serial, "default key")
}

fn symmetric_hsmauth_provider_with_label(
    serial: &'static str,
    label: &str,
) -> crate::HsmAuthProvider {
    crate::HsmAuthProvider {
        connector: Rc::new(SymmetricHsmAuthPeer { serial }).into(),
        credential: crate::HsmAuthCredential {
            label: label.to_owned(),
            algorithm: crate::HsmAuthAlgorithm::Aes128YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: None,
        },
        version: (5, 7, 1),
        trust_prefix: None,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum YubiHsmAuthFailure {
    UnknownAuthenticationKey,
    MissingCredential,
    MissingSlot,
    SecureChannel,
}

impl YubiHsmAuthFailure {
    pub(crate) fn expected_login_error(self) -> crate::CK_RV {
        match self {
            Self::SecureChannel => crate::CKR_DATA_INVALID as crate::CK_RV,
            _ => crate::CKR_PIN_INCORRECT as crate::CK_RV,
        }
    }

    pub(crate) fn failed_username(self) -> &'static [u8] {
        match self {
            Self::UnknownAuthenticationKey => b":0003default key@12345678",
            Self::MissingCredential | Self::SecureChannel => b":0001default key@12345678",
            Self::MissingSlot => b":0001default key@87654321",
        }
    }

    fn configured_public_discovery_credential(self) -> &'static str {
        match self {
            Self::UnknownAuthenticationKey => ":0003default key@12345678:password",
            Self::MissingCredential | Self::SecureChannel => ":0001default key@12345678:password",
            Self::MissingSlot => ":0001default key@87654321:password",
        }
    }
}

fn hsmauth_failure_parts(
    failure: YubiHsmAuthFailure,
) -> (Rc<ProtocolPeer>, Vec<crate::HsmAuthProvider>, &'static [u8]) {
    match failure {
        YubiHsmAuthFailure::UnknownAuthenticationKey => (
            Rc::new(ProtocolPeer::new()),
            vec![symmetric_hsmauth_provider("12345678")],
            b":0001default key@12345678",
        ),
        YubiHsmAuthFailure::MissingCredential => (
            Rc::new(ProtocolPeer::new()),
            vec![symmetric_hsmauth_provider_with_label(
                "12345678",
                "different key",
            )],
            b":0001different key@12345678",
        ),
        YubiHsmAuthFailure::MissingSlot => (
            Rc::new(ProtocolPeer::new()),
            vec![symmetric_hsmauth_provider("12345678")],
            b":0001default key@12345678",
        ),
        YubiHsmAuthFailure::SecureChannel => (
            Rc::new(ProtocolPeer::with_bad_card_cryptogram()),
            vec![symmetric_hsmauth_provider("12345678")],
            b":0001default key@12345678",
        ),
    }
}

pub(crate) fn make_yubihsm_hsmauth_login_failure_test_slot(
    failure: YubiHsmAuthFailure,
) -> Box<dyn crate::Slot> {
    let (peer, providers, _) = hsmauth_failure_parts(failure);
    Box::new(YubiHsmSlot::with_hsmauth_providers(
        peer,
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        Arc::new(crate::HsmAuthProviderRegistry::new(providers)),
    ))
}

pub(crate) fn make_yubihsm_hsmauth_public_discovery_failure_test_slot(
    failure: YubiHsmAuthFailure,
) -> (Box<dyn crate::Slot>, &'static [u8]) {
    let (peer, providers, successful_username) = hsmauth_failure_parts(failure);
    peer.add_public_certificate_pair();
    let credential = configured_yubihsm_public_discovery_credential(Some(
        failure.configured_public_discovery_credential().into(),
    ))
    .unwrap()
    .unwrap();
    let slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer,
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        Arc::new(crate::HsmAuthProviderRegistry::new(providers)),
        Some(credential),
    );
    (Box::new(slot), successful_username)
}

fn asymmetric_hsmauth_provider(peer: Rc<AsymmetricHsmAuthPeer>) -> crate::HsmAuthProvider {
    crate::HsmAuthProvider {
        connector: peer.clone().into(),
        credential: crate::HsmAuthCredential {
            label: "asymmetric".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: Some(peer.public_key.clone()),
        },
        version: (5, 7, 1),
        trust_prefix: None,
    }
}

fn public_discovery_test_slot(
    peer: Rc<ProtocolPeer>,
    credential: Arc<YubiHsmPublicDiscoveryConfig>,
) -> YubiHsmSlot {
    YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer,
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048, crate::YUBIHSM_ALGO_RSA_PKCS1_SHA256],
        Arc::new(crate::HsmAuthProviderRegistry::default()),
        Some(credential),
    )
}

fn session_role(slot: &YubiHsmSlot) -> Option<YubiHsmSessionRole> {
    slot.session.borrow().role()
}

fn session_is_active(slot: &YubiHsmSlot) -> bool {
    slot.session.borrow().is_active()
}

fn cache_test_slot(peer: Rc<ProtocolPeer>, public_discovery: bool) -> YubiHsmSlot {
    if public_discovery {
        public_discovery_test_slot(peer, public_discovery_credential("password"))
    } else {
        YubiHsmSlot::new(
            peer,
            (2, 4, 1),
            vec![YUBIHSM_ALGO_RSA_2048, crate::YUBIHSM_ALGO_RSA_PKCS1_SHA256],
        )
    }
}

fn inner_command_count(peer: &ProtocolPeer, command: CommandCode) -> usize {
    peer.inner_commands
        .borrow()
        .iter()
        .filter(|(candidate, _)| *candidate == command as u8)
        .count()
}

fn inner_object_command_count(peer: &ProtocolPeer, command: CommandCode, id: u16) -> usize {
    peer.inner_commands
        .borrow()
        .iter()
        .filter(|(candidate, data)| {
            *candidate == command as u8
                && data
                    .get(..2)
                    .is_some_and(|encoded| encoded == id.to_be_bytes())
        })
        .count()
}

fn inner_typed_object_command_count(
    peer: &ProtocolPeer,
    command: CommandCode,
    id: u16,
    object_type: u8,
) -> usize {
    peer.inner_commands
        .borrow()
        .iter()
        .filter(|(candidate, data)| {
            *candidate == command as u8
                && data.get(..3).is_some_and(|encoded| {
                    encoded[..2] == id.to_be_bytes() && encoded[2] == object_type
                })
        })
        .count()
}

fn create_session_payload_lengths(peer: &ProtocolPeer) -> Vec<usize> {
    peer.commands
        .borrow()
        .iter()
        .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
        .map(|command| Frame::parse(command).unwrap().data.len())
        .collect()
}

fn yubihsm_opaque_object(objects: &[TokenObject], id: u16) -> TokenObject {
    objects
        .iter()
        .find(|object| {
            matches!(
                object.material,
                KeyMaterial::YubiHsm {
                    id: candidate,
                    object_type: YUBIHSM_OPAQUE,
                    ..
                } if candidate == id
            )
        })
        .cloned()
        .unwrap()
}

fn exercise_lazy_opaque_value_cache(slot: &YubiHsmSlot, object: &TokenObject) -> Vec<u8> {
    let KeyMaterial::YubiHsm { id, value, .. } = &object.material else {
        panic!("expected a YubiHSM opaque object");
    };
    if let Some(value) = value.borrow().clone() {
        return value;
    }
    let payload = Slot::yubihsm_read_opaque(slot, *id).unwrap();
    *value.borrow_mut() = Some(payload.clone());
    payload
}

pub(crate) fn replace_metadata(
    peer: &ProtocolPeer,
    metadata_id: u16,
    target_type: u8,
    target_id: u16,
    target_sequence: u8,
    attributes: &[(u8, &[u8])],
) {
    let mut value = b"MDB1".to_vec();
    value.push(target_type);
    value.extend_from_slice(&target_id.to_be_bytes());
    value.push(target_sequence);
    for (tag, item) in attributes {
        encode_metadata_item(&mut value, *tag, item);
    }
    let mut objects = peer.metadata_objects.borrow_mut();
    let (info, stored) = objects.get_mut(&metadata_id).unwrap();
    info.sequence = info.sequence.wrapping_add(1);
    info.length = value.len() as u16;
    *stored = value;
}

pub(crate) fn insert_metadata(
    peer: &ProtocolPeer,
    metadata_id: u16,
    target_type: u8,
    target_id: u16,
    target_sequence: u8,
    domains: u16,
    attributes: &[(u8, &[u8])],
) {
    let mut value = b"MDB1".to_vec();
    value.push(target_type);
    value.extend_from_slice(&target_id.to_be_bytes());
    value.push(target_sequence);
    for (tag, item) in attributes {
        encode_metadata_item(&mut value, *tag, item);
    }
    peer.metadata_objects.borrow_mut().insert(
        metadata_id,
        (
            ObjectInfo {
                capabilities: [0; 8],
                id: metadata_id,
                length: value.len() as u16,
                domains,
                object_type: YUBIHSM_OPAQUE,
                algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
                sequence: 1,
                origin: 2,
                label: format!(
                    "Meta object for 0x{target_sequence:02x}{target_type:02x}{target_id:04x}"
                ),
                delegated_capabilities: [0; 8],
            },
            value,
        ),
    );
}

pub(crate) fn make_yubihsm_metadata_cache_test_slot(
    public_discovery: bool,
) -> (Box<dyn Slot>, Rc<ProtocolPeer>, InnerCommands) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let commands = peer.inner_commands.clone();
    (
        Box::new(cache_test_slot(peer.clone(), public_discovery)),
        peer,
        commands,
    )
}

#[test]
fn yubihsm_sparse_metadata_is_valid() {
    let info = ObjectInfo {
        capabilities: [0; 8],
        id: 0x7000,
        length: 0,
        domains: 1,
        object_type: YUBIHSM_OPAQUE,
        algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
        sequence: 1,
        origin: 2,
        label: "Meta object for 0x01031234".to_owned(),
        delegated_capabilities: [0; 8],
    };
    let mut value = b"MDB1\x03\x12\x34\x01".to_vec();
    encode_metadata_item(&mut value, 1, b"only-id");
    let metadata = parse_yubihsm_pkcs11_metadata(&info, &value).unwrap();
    assert_eq!(metadata.id.as_deref(), Some(b"only-id".as_slice()));
    assert_eq!(metadata.label, None);
    assert_eq!(metadata.public_id, None);
    assert_eq!(metadata.public_label, None);
}

#[test]
fn yubihsm_metadata_rejects_duplicate_and_truncated_attributes() {
    let info = ObjectInfo {
        capabilities: [0; 8],
        id: 0x7000,
        length: 0,
        domains: 1,
        object_type: YUBIHSM_OPAQUE,
        algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
        sequence: 1,
        origin: 2,
        label: "Meta object for 0x01031234".to_owned(),
        delegated_capabilities: [0; 8],
    };
    let mut duplicate = b"MDB1\x03\x12\x34\x01".to_vec();
    encode_metadata_item(&mut duplicate, 1, b"first");
    encode_metadata_item(&mut duplicate, 1, b"second");
    assert!(parse_yubihsm_pkcs11_metadata(&info, &duplicate).is_err());

    let mut truncated = b"MDB1\x03\x12\x34\x01".to_vec();
    truncated.extend_from_slice(&[2, 0, 5, b'a', b'b']);
    assert!(parse_yubihsm_pkcs11_metadata(&info, &truncated).is_err());
}

fn assert_duplicate_metadata_is_repaired(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    insert_metadata(
        &peer,
        102,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        1,
        0xffff,
        &[(1, b"conflicting-id"), (2, b"conflicting label")],
    );
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();
    let objects = Slot::token_objects(&slot, 7).unwrap();
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let public = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, [0, 1]);
    assert_eq!(private.label, "test-rsa");
    assert_eq!(public.id, [0, 1]);
    assert_eq!(public.label, "test-rsa");
    let mut related =
        Slot::yubihsm_related_metadata_object(&slot, 1, YUBIHSM_ASYMMETRIC_KEY).unwrap();
    related.sort_unstable();
    assert_eq!(related, [(101, 1), (102, 1)]);

    let command_start = peer.inner_commands.borrow().len();
    Slot::yubihsm_set_attributes(
        &slot,
        7,
        &private.unique_id,
        Some(b"repaired-id"),
        Some("repaired label"),
    )
    .unwrap();
    let commands = peer.inner_commands.borrow();
    let mutation = &commands[command_start..];
    assert_eq!(mutation[0].0, CommandCode::PutOpaque as u8);
    assert_eq!(&mutation[0].1[..2], &[0, 0]);
    let mut deleted = mutation[1..]
        .iter()
        .filter(|(command, _)| *command == CommandCode::DeleteObject as u8)
        .map(|(_, value)| u16::from_be_bytes(value[..2].try_into().unwrap()))
        .collect::<Vec<_>>();
    deleted.sort_unstable();
    assert_eq!(deleted, [101, 102]);
    drop(commands);

    let repaired = Slot::token_objects(&slot, 7).unwrap();
    let private = repaired
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let public = repaired
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, b"repaired-id");
    assert_eq!(private.label, "repaired label");
    assert_eq!(public.id, b"repaired-id");
    assert_eq!(public.label, "repaired label");
    assert_eq!(
        peer.metadata_objects
            .borrow()
            .values()
            .filter(|(info, _)| info.label == "Meta object for 0x01030001")
            .count(),
        1
    );
}

#[test]
fn yubihsm_duplicate_metadata_is_repaired_with_public_discovery_credential() {
    assert_duplicate_metadata_is_repaired(true);
}

#[test]
fn yubihsm_duplicate_metadata_is_repaired_without_public_discovery_credential() {
    assert_duplicate_metadata_is_repaired(false);
}

fn assert_metadata_replacement_is_failure_safe(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    replace_metadata(
        peer.as_ref(),
        101,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        1,
        &[
            (1, b"private-id"),
            (2, b"metadata private key"),
            (3, b"shared-id"),
            (4, b"metadata public key"),
        ],
    );
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();

    let initial = Slot::token_objects(&slot, 7).unwrap();
    let private = initial
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, b"private-id");
    assert_eq!(private.label, "metadata private key");
    let unique_id = private.unique_id.clone();

    peer.fail_next_put_opaque.set(true);
    let failed_create_start = peer.inner_commands.borrow().len();
    assert!(Slot::yubihsm_set_attributes(
        &slot,
        7,
        &unique_id,
        Some(b"failed-create-id"),
        Some("failed create"),
    )
    .is_err());
    let failed_create_commands = peer.inner_commands.borrow();
    let failed_create = &failed_create_commands[failed_create_start..];
    assert_eq!(failed_create.len(), 1);
    assert_eq!(failed_create[0].0, CommandCode::PutOpaque as u8);
    assert_eq!(&failed_create[0].1[..2], &[0, 0]);
    drop(failed_create_commands);
    assert!(peer.metadata_objects.borrow().contains_key(&101));
    let after_failed_create = Slot::token_objects(&slot, 7).unwrap();
    let private = after_failed_create
        .iter()
        .find(|object| object.unique_id == unique_id)
        .unwrap();
    assert_eq!(private.id, b"private-id");
    assert_eq!(private.label, "metadata private key");

    peer.fail_delete_opaque.borrow_mut().insert(101);
    let failed_delete_start = peer.inner_commands.borrow().len();
    assert!(Slot::yubihsm_set_attributes(
        &slot,
        7,
        &unique_id,
        Some(b"failed-delete-id"),
        Some("failed delete"),
    )
    .is_err());
    let failed_delete_commands = peer.inner_commands.borrow();
    let failed_delete = &failed_delete_commands[failed_delete_start..];
    assert_eq!(failed_delete[0].0, CommandCode::PutOpaque as u8);
    assert_eq!(&failed_delete[0].1[..2], &[0, 0]);
    assert!(failed_delete[1..].iter().any(|(command, data)| *command
        == CommandCode::DeleteObject as u8
        && u16::from_be_bytes(data[..2].try_into().unwrap()) == 101));
    drop(failed_delete_commands);

    let ambiguous = Slot::token_objects(&slot, 7).unwrap();
    let private = ambiguous
        .iter()
        .find(|object| object.unique_id == unique_id)
        .unwrap();
    assert_eq!(private.id, [0, 1]);
    assert_eq!(private.label, "test-rsa");
    assert_eq!(
        peer.metadata_objects
            .borrow()
            .values()
            .filter(|(info, _)| info.label == "Meta object for 0x01030001")
            .count(),
        2
    );

    peer.fail_delete_opaque.borrow_mut().clear();
    Slot::yubihsm_set_attributes(
        &slot,
        7,
        &unique_id,
        Some(b"recovered-id"),
        Some("recovered label"),
    )
    .unwrap();
    let recovered = Slot::token_objects(&slot, 7).unwrap();
    let private = recovered
        .iter()
        .find(|object| object.unique_id == unique_id)
        .unwrap();
    assert_eq!(private.id, b"recovered-id");
    assert_eq!(private.label, "recovered label");
    assert_eq!(
        peer.metadata_objects
            .borrow()
            .values()
            .filter(|(info, _)| info.label == "Meta object for 0x01030001")
            .count(),
        1
    );
}

#[test]
fn yubihsm_metadata_replacement_is_failure_safe_with_public_discovery_credential() {
    assert_metadata_replacement_is_failure_safe(true);
}

#[test]
fn yubihsm_metadata_replacement_is_failure_safe_without_public_discovery_credential() {
    assert_metadata_replacement_is_failure_safe(false);
}

fn assert_invalid_metadata_is_replaced(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.metadata_objects.borrow_mut().get_mut(&101).unwrap().1[0] = b'X';
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();
    let objects = Slot::token_objects(&slot, 7).unwrap();
    let private = objects
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, [0, 1]);
    assert_eq!(private.label, "test-rsa");
    assert_eq!(
        Slot::yubihsm_related_metadata_object(&slot, 1, YUBIHSM_ASYMMETRIC_KEY).unwrap(),
        [(101, 1)]
    );

    Slot::yubihsm_set_attributes(
        &slot,
        7,
        &private.unique_id,
        None,
        Some("valid replacement"),
    )
    .unwrap();
    assert!(!peer.metadata_objects.borrow().contains_key(&101));
    let repaired = Slot::token_objects(&slot, 7).unwrap();
    let private = repaired
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, [0, 1]);
    assert_eq!(private.label, "valid replacement");
}

#[test]
fn yubihsm_invalid_metadata_is_replaced_with_public_discovery_credential() {
    assert_invalid_metadata_is_replaced(true);
}

#[test]
fn yubihsm_invalid_metadata_is_replaced_without_public_discovery_credential() {
    assert_invalid_metadata_is_replaced(false);
}

#[test]
fn yubihsm_without_public_discovery_configuration_exposes_provider_profiles_only() {
    let slot = YubiHsmSlot::new(
        Rc::new(ProtocolPeer::new()),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
    );
    let objects = Slot::token_objects(&slot, 7).unwrap();
    let profile_ids = objects
        .iter()
        .filter_map(|object| match object.material {
            KeyMaterial::Profile { profile_id } => Some(profile_id),
            _ => None,
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        profile_ids,
        HashSet::from([
            CKP_BASELINE_PROVIDER as CK_PROFILE_ID,
            CKP_EXTENDED_PROVIDER as CK_PROFILE_ID,
        ])
    );
    assert!(objects
        .iter()
        .all(|object| object.class == CKO_PROFILE as CK_OBJECT_CLASS));
}

#[test]
fn yubihsm_token_pin_bounds_cover_split_and_packed_login_forms() {
    let slot = YubiHsmSlot::new(
        Rc::new(ProtocolPeer::new()),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
    );
    let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
    Slot::get_token_info(&slot, &mut token_info).unwrap();
    assert_eq!(token_info.ulMinPinLen, 0);
    assert_eq!(token_info.ulMaxPinLen, 215);
}

fn assert_lazy_cache_lifecycle(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), public_discovery);

    let prelogin = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        if public_discovery { 3 } else { 0 }
    );
    assert_eq!(
        prelogin.iter().any(|object| matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )),
        public_discovery
    );

    Slot::login(&mut slot, b"0001password").unwrap();
    let logged_in = Slot::token_objects(&slot, 7).unwrap();
    let reads_after_enumeration = inner_command_count(&peer, CommandCode::GetOpaque);
    assert_eq!(
        reads_after_enumeration,
        if public_discovery { 3 } else { 2 }
    );

    let opaque = yubihsm_opaque_object(&logged_in, 4);
    let KeyMaterial::YubiHsm { value, .. } = &opaque.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &opaque),
        b"cached opaque value"
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_after_enumeration + 1
    );

    let rebuilt = Slot::token_objects(&slot, 7).unwrap();
    let rebuilt_opaque = yubihsm_opaque_object(&rebuilt, 4);
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &rebuilt_opaque),
        b"cached opaque value"
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_after_enumeration + 1
    );

    let certificate = yubihsm_opaque_object(&rebuilt, 2);
    let expected_certificate = peer.metadata_objects.borrow().get(&2).unwrap().1.clone();
    let reads_before_certificate = inner_command_count(&peer, CommandCode::GetOpaque);
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &certificate),
        expected_certificate
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_certificate + usize::from(!public_discovery)
    );

    Slot::logout(&mut slot).unwrap();
    let logged_out = Slot::token_objects(&slot, 7).unwrap();
    let logged_out_opaque = yubihsm_opaque_object(&logged_out, 4);
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &logged_out_opaque),
        b"cached opaque value"
    );
    assert!(logged_out
        .iter()
        .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .all(|object| !object.private));
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_certificate + usize::from(!public_discovery)
    );
}

#[test]
fn yubihsm_lazy_cache_lifecycle_with_public_discovery_credential() {
    assert_lazy_cache_lifecycle(true);
}

#[test]
fn yubihsm_lazy_cache_lifecycle_without_public_discovery_credential() {
    assert_lazy_cache_lifecycle(false);
}

#[test]
fn logged_in_discovery_reads_each_native_property_only_once() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), false);

    let _ = Slot::token_objects(&slot, 7).unwrap();
    assert!(peer.inner_commands.borrow().is_empty());

    Slot::login(&mut slot, b"0001password").unwrap();
    let first = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(inner_command_count(&peer, CommandCode::ListObjects), 1);
    for (id, object_type) in [
        (1, YUBIHSM_ASYMMETRIC_KEY),
        (2, YUBIHSM_OPAQUE),
        (4, YUBIHSM_OPAQUE),
        (100, YUBIHSM_OPAQUE),
        (101, YUBIHSM_OPAQUE),
    ] {
        assert_eq!(
            inner_typed_object_command_count(&peer, CommandCode::GetObjectInfo, id, object_type),
            1
        );
    }
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetPublicKey, 1),
        1
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 100),
        1
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 101),
        1
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 2),
        0
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 4),
        0
    );
    assert_eq!(
        slot.object_cache
            .borrow()
            .native_objects
            .get(&YubiHsmObjectKey::new(YUBIHSM_ASYMMETRIC_KEY, 1))
            .unwrap()
            .metadata_sources,
        [(101, 1)]
    );
    assert_eq!(
        slot.object_cache
            .borrow()
            .native_objects
            .get(&YubiHsmObjectKey::new(YUBIHSM_OPAQUE, 2))
            .unwrap()
            .metadata_sources,
        [(100, 1)]
    );

    let first_data = yubihsm_opaque_object(&first, 4);
    let command_count = peer.inner_commands.borrow().len();
    let second = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(peer.inner_commands.borrow().len(), command_count + 1);
    assert_eq!(inner_command_count(&peer, CommandCode::ListObjects), 2);
    assert_eq!(inner_command_count(&peer, CommandCode::GetObjectInfo), 5);
    assert_eq!(inner_command_count(&peer, CommandCode::GetPublicKey), 1);
    assert_eq!(inner_command_count(&peer, CommandCode::GetOpaque), 2);

    let second_data = yubihsm_opaque_object(&second, 4);
    let (
        KeyMaterial::YubiHsm {
            value: first_value, ..
        },
        KeyMaterial::YubiHsm {
            value: second_value,
            ..
        },
    ) = (&first_data.material, &second_data.material)
    else {
        unreachable!();
    };
    assert!(Rc::ptr_eq(first_value, second_value));

    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &second_data),
        b"cached opaque value"
    );
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &first_data),
        b"cached opaque value"
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 4),
        1
    );

    let certificate = yubihsm_opaque_object(&second, 2);
    let expected_certificate = peer.metadata_objects.borrow().get(&2).unwrap().1.clone();
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &certificate),
        expected_certificate
    );
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &certificate),
        expected_certificate
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 2),
        1
    );
}

#[test]
fn public_and_user_discovery_share_one_lazy_native_object_cache() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));

    let public = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(inner_command_count(&peer, CommandCode::ListObjects), 1);
    assert_eq!(
        inner_typed_object_command_count(
            &peer,
            CommandCode::GetObjectInfo,
            1,
            YUBIHSM_AUTHENTICATION_KEY
        ),
        1
    );
    assert_eq!(
        slot.cached_authentication_algorithm(1).unwrap(),
        Some(DirectAuthenticationAlgorithm::Symmetric)
    );
    let public_data = yubihsm_opaque_object(&public, 4);
    let command_count = peer.inner_commands.borrow().len();
    let repeated_public = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(peer.inner_commands.borrow().len(), command_count);

    let repeated_data = yubihsm_opaque_object(&repeated_public, 4);
    let (
        KeyMaterial::YubiHsm {
            value: public_value,
            ..
        },
        KeyMaterial::YubiHsm {
            value: repeated_value,
            ..
        },
    ) = (&public_data.material, &repeated_data.material)
    else {
        unreachable!();
    };
    assert!(Rc::ptr_eq(public_value, repeated_value));

    let info_reads_before_login = inner_command_count(&peer, CommandCode::GetObjectInfo);
    let public_key_reads_before_login = inner_command_count(&peer, CommandCode::GetPublicKey);
    let opaque_reads_before_login = inner_command_count(&peer, CommandCode::GetOpaque);
    peer.commands.borrow_mut().clear();
    Slot::login(&mut slot, b"0001password").unwrap();
    assert_eq!(create_session_payload_lengths(&peer), [10]);

    let logged_in = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(inner_command_count(&peer, CommandCode::ListObjects), 2);
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetObjectInfo),
        info_reads_before_login + 1
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetPublicKey),
        public_key_reads_before_login
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        opaque_reads_before_login
    );
    assert_eq!(
        inner_typed_object_command_count(
            &peer,
            CommandCode::GetObjectInfo,
            1,
            YUBIHSM_AUTHENTICATION_KEY
        ),
        2
    );

    let public_unique_ids = public
        .iter()
        .filter(|object| object.class != CKO_PROFILE as CK_OBJECT_CLASS)
        .map(|object| object.unique_id.as_str())
        .collect::<HashSet<_>>();
    let logged_in_unique_ids = logged_in
        .iter()
        .map(|object| object.unique_id.as_str())
        .collect::<HashSet<_>>();
    assert!(public_unique_ids.is_subset(&logged_in_unique_ids));
    assert_eq!(logged_in.len(), logged_in_unique_ids.len());

    let logged_in_data = yubihsm_opaque_object(&logged_in, 4);
    let KeyMaterial::YubiHsm {
        value: logged_in_value,
        ..
    } = &logged_in_data.material
    else {
        unreachable!();
    };
    assert!(Rc::ptr_eq(public_value, logged_in_value));
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &logged_in_data),
        b"cached opaque value"
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 4),
        1
    );
}

#[test]
fn metadata_back_link_only_applies_to_the_current_target_sequence() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), false);
    Slot::login(&mut slot, b"0001password").unwrap();

    let initial = Slot::token_objects(&slot, 7).unwrap();
    let private = initial
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, b"shared-id");
    assert_eq!(
        Slot::yubihsm_related_metadata_object(&slot, 1, YUBIHSM_ASYMMETRIC_KEY).unwrap(),
        [(101, 1)]
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 101),
        1
    );

    replace_metadata(
        &peer,
        101,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        2,
        &[(1, b"obsolete-id"), (2, b"obsolete label")],
    );
    peer.metadata_objects
        .borrow_mut()
        .get_mut(&101)
        .unwrap()
        .0
        .label = "Meta object for 0x02030001".to_owned();
    slot.read_object_info(slot.session.as_ref(), 101, YUBIHSM_OPAQUE, None)
        .unwrap();
    assert!(
        Slot::yubihsm_related_metadata_object(&slot, 1, YUBIHSM_ASYMMETRIC_KEY)
            .unwrap()
            .is_empty()
    );

    let refreshed = Slot::token_objects(&slot, 7).unwrap();
    let private = refreshed
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private.id, [0, 1]);
    assert_eq!(private.label, "test-rsa");
    assert!(
        Slot::yubihsm_related_metadata_object(&slot, 1, YUBIHSM_ASYMMETRIC_KEY)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inner_object_command_count(&peer, CommandCode::GetOpaque, 101),
        2
    );
}

fn assert_logout_clears_private_cache(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();

    Slot::login(&mut slot, b"0001password").unwrap();
    let logged_in = Slot::token_objects(&slot, 7).unwrap();
    let private = logged_in
        .iter()
        .find(|object| object.private)
        .cloned()
        .expect("expected a private YubiHSM object");
    let public = logged_in
        .iter()
        .find(|object| {
            object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                && object.id == b"shared-id".as_slice()
        })
        .cloned()
        .expect("expected the matching public key");
    assert!(!Slot::session_objects(&slot, 7).unwrap().is_empty());
    assert!(slot
        .attestation_cache
        .borrow()
        .keys()
        .any(|(key, _)| key.object_type == YUBIHSM_ASYMMETRIC_KEY && key.id == 1));

    Slot::logout(&mut slot).unwrap();
    let logged_out = Slot::token_objects(&slot, 7).unwrap();
    assert!(logged_out.iter().all(|object| !object.private));
    assert!(logged_out
        .iter()
        .any(|object| object.unique_id == public.unique_id));
    assert!(Slot::token_object(&slot, 7, &private.unique_id)
        .unwrap()
        .is_none());
    assert!(!slot
        .object_metadata
        .borrow()
        .contains_key(&YubiHsmObjectKey::new(YUBIHSM_ASYMMETRIC_KEY, 1)));
    assert!(!slot
        .object_cache
        .borrow()
        .native_objects
        .contains_key(&YubiHsmObjectKey::new(YUBIHSM_ASYMMETRIC_KEY, 1)));
    assert!(slot
        .attestation_cache
        .borrow()
        .keys()
        .all(|(key, _)| key.object_type != YUBIHSM_ASYMMETRIC_KEY || key.id != 1));

    peer.objects.borrow_mut().clear();
    Slot::login(&mut slot, b"0002password").unwrap();
    let narrower_login = Slot::token_objects(&slot, 7).unwrap();
    assert!(narrower_login.iter().all(|object| !object.private));
    assert!(narrower_login
        .iter()
        .any(|object| object.unique_id == public.unique_id));
    Slot::logout(&mut slot).unwrap();
}

#[test]
fn yubihsm_logout_clears_private_cache_with_public_discovery_credential() {
    assert_logout_clears_private_cache(true);
}

#[test]
fn yubihsm_logout_clears_private_cache_without_public_discovery_credential() {
    assert_logout_clears_private_cache(false);
}

#[test]
fn yubihsm_forced_session_clear_removes_private_cached_objects() {
    let peer = Rc::new(ProtocolPeer::new());
    let mut slot = cache_test_slot(peer, false);
    Slot::login(&mut slot, b"0001password").unwrap();
    assert!(Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .any(|object| object.private));

    Slot::clear_session(&mut slot);
    assert!(Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .all(|object| !object.private));
}

fn assert_sequence_change_invalidates_cached_value(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();
    let initial = Slot::token_objects(&slot, 7).unwrap();
    let initial_opaque = yubihsm_opaque_object(&initial, 4);
    let initial_unique_id = initial_opaque.unique_id.clone();
    exercise_lazy_opaque_value_cache(&slot, &initial_opaque);
    let reads_before_replacement = inner_command_count(&peer, CommandCode::GetOpaque);

    let mut objects = peer.metadata_objects.borrow_mut();
    let (info, value) = objects.get_mut(&4).unwrap();
    info.sequence = 2;
    *value = b"replacement opaque value".to_vec();
    drop(objects);

    let replaced = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_replacement
    );
    assert!(!replaced
        .iter()
        .any(|object| object.unique_id == initial_unique_id));
    let replacement = yubihsm_opaque_object(&replaced, 4);
    assert_ne!(replacement.unique_id, initial_unique_id);
    let KeyMaterial::YubiHsm { value, .. } = &replacement.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &replacement),
        b"replacement opaque value"
    );
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_replacement + 1
    );
}

#[test]
fn yubihsm_sequence_change_invalidates_cache_with_public_discovery_credential() {
    assert_sequence_change_invalidates_cached_value(true);
}

#[test]
fn yubihsm_sequence_change_invalidates_cache_without_public_discovery_credential() {
    assert_sequence_change_invalidates_cached_value(false);
}

fn assert_reconnect_discards_cached_objects_and_values(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();
    let objects = Slot::token_objects(&slot, 7).unwrap();
    exercise_lazy_opaque_value_cache(&slot, &yubihsm_opaque_object(&objects, 4));
    Slot::logout(&mut slot).unwrap();
    let reads_before_reconnect = inner_command_count(&peer, CommandCode::GetOpaque);

    peer.connection_epoch.set(1);
    let reconnected_prelogin = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_reconnect + if public_discovery { 3 } else { 0 }
    );
    assert_eq!(
        reconnected_prelogin.iter().any(|object| matches!(
            object.material,
            KeyMaterial::YubiHsm {
                id: 4,
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )),
        public_discovery
    );

    Slot::login(&mut slot, b"0001password").unwrap();
    let reconnected = Slot::token_objects(&slot, 7).unwrap();
    let opaque = yubihsm_opaque_object(&reconnected, 4);
    let KeyMaterial::YubiHsm { value, .. } = &opaque.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_reconnect + if public_discovery { 3 } else { 2 }
    );
}

#[test]
fn yubihsm_reconnect_resets_cache_with_public_discovery_credential() {
    assert_reconnect_discards_cached_objects_and_values(true);
}

#[test]
fn yubihsm_reconnect_resets_cache_without_public_discovery_credential() {
    assert_reconnect_discards_cached_objects_and_values(false);
}

fn assert_explicit_eviction_removes_cached_object(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer, public_discovery);
    let _ = Slot::token_objects(&slot, 7).unwrap();
    Slot::login(&mut slot, b"0001password").unwrap();
    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::YubiHsm {
            id: 4,
            object_type: YUBIHSM_OPAQUE,
            ..
        }
    )));

    Slot::yubihsm_forget_object(&slot, 4, YUBIHSM_OPAQUE).unwrap();
    Slot::logout(&mut slot).unwrap();
    assert!(!Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .any(|object| matches!(
            object.material,
            KeyMaterial::YubiHsm {
                id: 4,
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )));
}

#[test]
fn yubihsm_explicit_eviction_with_public_discovery_credential() {
    assert_explicit_eviction_removes_cached_object(true);
}

#[test]
fn yubihsm_explicit_eviction_without_public_discovery_credential() {
    assert_explicit_eviction_removes_cached_object(false);
}

fn assert_metadata_overrides_cached_objects(public_discovery: bool) {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), public_discovery);
    let prelogin = Slot::token_objects(&slot, 7).unwrap();
    if public_discovery {
        let certificate = prelogin
            .iter()
            .find(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
            .unwrap();
        let public_key = prelogin
            .iter()
            .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
            .unwrap();
        assert_eq!(certificate.id, b"shared-id");
        assert_eq!(certificate.label, "metadata certificate");
        assert_eq!(public_key.id, b"shared-id");
        assert_eq!(public_key.label, "metadata public key");
    }

    Slot::login(&mut slot, b"0001password").unwrap();
    let initial = Slot::token_objects(&slot, 7).unwrap();
    let private_key = initial
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let public_key = initial
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let certificate = initial
        .iter()
        .find(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private_key.id, b"shared-id");
    assert_eq!(private_key.label, "metadata private key");
    assert_eq!(public_key.id, b"shared-id");
    assert_eq!(public_key.label, "metadata public key");
    assert_eq!(certificate.id, b"shared-id");
    assert_eq!(certificate.label, "metadata certificate");
    let certificate_unique_id = certificate.unique_id.clone();
    let reads_before_update = inner_command_count(&peer, CommandCode::GetOpaque);

    replace_metadata(
        &peer,
        100,
        YUBIHSM_OPAQUE,
        2,
        1,
        &[(1, b"updated-shared-id"), (2, b"updated certificate")],
    );
    replace_metadata(
        &peer,
        101,
        3,
        1,
        1,
        &[
            (1, b"updated-shared-id"),
            (2, b"updated private key"),
            (3, b"updated-shared-id"),
            (4, b"updated public key"),
        ],
    );

    let updated = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        inner_command_count(&peer, CommandCode::GetOpaque),
        reads_before_update + 2
    );
    let private_key = updated
        .iter()
        .find(|object| object.class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let public_key = updated
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    let certificate = updated
        .iter()
        .find(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(private_key.id, b"updated-shared-id");
    assert_eq!(private_key.label, "updated private key");
    assert_eq!(public_key.id, b"updated-shared-id");
    assert_eq!(public_key.label, "updated public key");
    assert_eq!(certificate.id, b"updated-shared-id");
    assert_eq!(certificate.label, "updated certificate");
    assert_eq!(certificate.unique_id, certificate_unique_id);
}

#[test]
fn yubihsm_metadata_overrides_cache_with_public_discovery_credential() {
    assert_metadata_overrides_cached_objects(true);
}

#[test]
fn yubihsm_metadata_overrides_cache_without_public_discovery_credential() {
    assert_metadata_overrides_cached_objects(false);
}

#[test]
fn yubihsm_public_discovery_exposes_all_non_private_objects_without_pkcs_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.objects.borrow_mut().push(5);
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    Slot::init_slot(&mut slot).unwrap();

    let objects = Slot::token_objects(&slot, 7).unwrap();
    let profile_ids = objects
        .iter()
        .filter_map(|object| match object.material {
            KeyMaterial::Profile { profile_id } => Some(profile_id),
            _ => None,
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        profile_ids,
        HashSet::from([
            CKP_BASELINE_PROVIDER as CK_PROFILE_ID,
            CKP_EXTENDED_PROVIDER as CK_PROFILE_ID,
            CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID,
        ])
    );

    let certificate = objects
        .iter()
        .find(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .unwrap();
    let public_key = objects
        .iter()
        .find(|object| {
            object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && object.id == certificate.id
        })
        .unwrap();
    let standalone_public_key = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && object.id == [0, 5])
        .unwrap();
    let public_data = yubihsm_opaque_object(&objects, 4);
    assert!(!certificate.private);
    assert!(!public_key.private);
    assert!(!standalone_public_key.private);
    assert!(!public_data.private);
    assert!(objects.iter().all(|object| !object.private));
    assert!(!objects
        .iter()
        .any(|object| matches!(object.material, KeyMaterial::YubiHsm { id: 100 | 101, .. })));
    let KeyMaterial::YubiHsm { value, .. } = &certificate.material else {
        panic!("expected a YubiHSM certificate");
    };
    assert!(value.borrow().is_some());
    let KeyMaterial::YubiHsm { value, .. } = &public_data.material else {
        panic!("expected public opaque data");
    };
    assert!(value.borrow().is_none());
    assert!(session_is_active(&slot));
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert!(matches!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Available { .. }
    ));
    assert!(peer.session.borrow().is_some());
    assert_eq!(peer.closed_sessions.get(), 0);
}

#[test]
fn yubihsm_public_discovery_reuses_the_yubihsm_auth_login_path() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let providers = Arc::new(crate::HsmAuthProviderRegistry::new(vec![
        symmetric_hsmauth_provider("12345678"),
    ]));
    let slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer.clone(),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        providers,
        Some(hsmauth_public_discovery_credential()),
    );

    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )
    }));
    assert_eq!(create_session_payload_lengths(&peer), [10]);
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert!(!Slot::login_is_active(&slot));
}

#[test]
fn yubihsm_public_discovery_supports_asymmetric_yubihsm_auth_credentials() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.use_asymmetric_authentication(1);
    peer.add_public_certificate_pair();
    let hsmauth = Rc::new(AsymmetricHsmAuthPeer::new());
    let providers = Arc::new(crate::HsmAuthProviderRegistry::new(vec![
        asymmetric_hsmauth_provider(hsmauth),
    ]));
    let credential = configured_yubihsm_public_discovery_credential(Some(
        ":0001asymmetric@87654321:password".into(),
    ))
    .unwrap()
    .unwrap();
    let slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer.clone(),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        providers,
        Some(credential),
    );

    assert!(Slot::token_objects(&slot, 7).unwrap().iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )
    }));
    assert_eq!(create_session_payload_lengths(&peer), [67]);
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
}

#[cfg(unix)]
#[test]
fn yubihsm_auth_public_discovery_caches_prompted_password_per_slot() {
    let _guard = crate::test::TEST_LOCK.lock().unwrap();
    let _pinentry = crate::test::TestPinentry::new("password");
    let direct_config = configured_yubihsm_public_discovery_credential(Some("0001".into()))
        .unwrap()
        .unwrap();
    assert!(direct_config.configured_password.is_none());
    let config =
        configured_yubihsm_public_discovery_credential(Some(":0001default key@12345678".into()))
            .unwrap()
            .unwrap();
    assert!(config.configured_password.is_none());
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let providers = Arc::new(crate::HsmAuthProviderRegistry::new(vec![
        symmetric_hsmauth_provider("12345678"),
    ]));
    let mut slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer.clone(),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        providers,
        Some(config.clone()),
    );
    slot.set_pinentry(Arc::new(
        crate::pinentry::Pinentry::from_environment().unwrap(),
    ));

    assert!(Slot::token_objects(&slot, 8).unwrap().iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )
    }));
    assert_eq!(peer.create_session_count(), 1);
    assert!(slot.public_discovery_password.borrow().is_some());
    assert!(config.configured_password.is_none());

    let second_peer = Rc::new(ProtocolPeer::new());
    second_peer.add_public_certificate_pair();
    let second_providers = Arc::new(crate::HsmAuthProviderRegistry::new(vec![
        symmetric_hsmauth_provider("12345678"),
    ]));
    let mut second_slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        second_peer.clone(),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        second_providers,
        Some(config),
    );
    second_slot.set_pinentry(Arc::new(
        crate::pinentry::Pinentry::from_environment().unwrap(),
    ));
    assert!(Slot::token_objects(&second_slot, 9)
        .unwrap()
        .iter()
        .any(|object| {
            matches!(
                object.material,
                KeyMaterial::Profile { profile_id }
                    if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
            )
        }));
    assert_eq!(second_peer.create_session_count(), 1);
    assert!(second_slot.public_discovery_password.borrow().is_some());
}

#[test]
fn yubihsm_auth_public_discovery_waits_for_provider_discovery() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let providers = Arc::new(crate::HsmAuthProviderRegistry::default());
    let mut slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer.clone(),
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        providers.clone(),
        Some(hsmauth_public_discovery_credential()),
    );

    assert!(
        !Slot::token_objects(&slot, 7).unwrap().iter().any(|object| {
            matches!(
                object.material,
                KeyMaterial::Profile { profile_id }
                    if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
            )
        })
    );
    assert_eq!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Unattempted
    );
    assert_eq!(peer.create_session_count(), 0);

    Slot::login(&mut slot, b"0001password").unwrap();
    assert_eq!(session_role(&slot), Some(YubiHsmSessionRole::User));
    Slot::logout(&mut slot).unwrap();

    providers
        .extend([symmetric_hsmauth_provider("12345678")])
        .unwrap();
    assert!(Slot::token_objects(&slot, 7).unwrap().iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )
    }));
    assert_eq!(peer.create_session_count(), 2);
}

#[test]
fn yubihsm_public_read_session_can_open_before_object_discovery() {
    let peer = Rc::new(ProtocolPeer::new());
    let slot = public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    assert_eq!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Unattempted
    );

    Slot::ensure_backend_read_session(&slot).unwrap();
    assert_eq!(peer.create_session_count(), 1);
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert_eq!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Unattempted
    );
}

#[test]
fn yubihsm_public_read_reopens_an_invalidated_discovery_session_once() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let slot = public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    Slot::token_objects(&slot, 7).unwrap();
    let sessions_before_read = peer.create_session_count();

    peer.corrupt_response_mac.set(true);
    assert_eq!(
        Slot::yubihsm_read_opaque(&slot, 4).unwrap(),
        b"cached opaque value"
    );
    assert_eq!(peer.create_session_count(), sessions_before_read + 1);
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert!(Slot::backend_session_is_active(&slot));
}

#[test]
fn synthetic_public_key_inherits_sparse_physical_key_metadata() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    replace_metadata(
        &peer,
        100,
        YUBIHSM_OPAQUE,
        2,
        1,
        &[(1, b"inherited-id"), (2, b"inherited certificate")],
    );
    replace_metadata(
        &peer,
        101,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        1,
        &[(1, b"inherited-id"), (2, b"inherited key")],
    );
    let slot = public_discovery_test_slot(peer, public_discovery_credential("password"));

    let objects = Slot::token_objects(&slot, 7).unwrap();
    let public_key = objects
        .iter()
        .find(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
        .unwrap();
    assert_eq!(public_key.id, b"inherited-id");
    assert_eq!(public_key.label, "inherited key");
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::Profile { profile_id }
            if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
    )));
}

#[test]
fn explicit_public_metadata_mismatch_does_not_withdraw_profile() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    replace_metadata(
        &peer,
        101,
        YUBIHSM_ASYMMETRIC_KEY,
        1,
        1,
        &[
            (1, b"shared-id"),
            (2, b"private key"),
            (3, b"different-public-id"),
            (4, b"public key"),
        ],
    );
    let slot = public_discovery_test_slot(peer, public_discovery_credential("password"));

    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::Profile { profile_id }
            if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
    )));
    assert!(objects.iter().any(|object| {
        object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS && object.id == b"shared-id"
    }));
    assert!(objects.iter().any(|object| {
        object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS && object.id == b"different-public-id"
    }));
}

#[test]
fn malformed_certificate_is_skipped_without_withdrawing_profile() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.metadata_objects.borrow_mut().insert(
        6,
        (
            ObjectInfo {
                capabilities: [0; 8],
                id: 6,
                length: 17,
                domains: 0xffff,
                object_type: YUBIHSM_OPAQUE,
                algorithm: YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
                sequence: 1,
                origin: 1,
                label: "malformed certificate".to_owned(),
                delegated_capabilities: [0; 8],
            },
            b"not a certificate".to_vec(),
        ),
    );
    let slot = public_discovery_test_slot(peer, public_discovery_credential("password"));

    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::Profile { profile_id }
            if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
    )));
    assert_eq!(
        objects
            .iter()
            .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
            .count(),
        1
    );
    assert!(!objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::YubiHsm {
            id: 6,
            object_type: YUBIHSM_OPAQUE,
            ..
        }
    )));
}

#[test]
fn public_certificate_profile_does_not_require_provisioned_certificates() {
    let peer = Rc::new(ProtocolPeer::new());
    let slot = public_discovery_test_slot(peer, public_discovery_credential("password"));

    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::Profile { profile_id }
            if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
    )));
    assert!(objects
        .iter()
        .all(|object| object.class != CKO_CERTIFICATE as CK_OBJECT_CLASS));
    assert!(objects
        .iter()
        .any(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS));
}

#[test]
fn yubihsm_public_discovery_is_conditional_per_slot() {
    let credential = public_discovery_credential("password");
    let successful_peer = Rc::new(ProtocolPeer::new());
    successful_peer.add_public_certificate_pair();
    let failing_peer = Rc::new(ProtocolPeer::with_bad_card_cryptogram());
    failing_peer.add_public_certificate_pair();
    let successful = public_discovery_test_slot(successful_peer, credential.clone());
    let failing = public_discovery_test_slot(failing_peer, credential);

    assert!(Slot::token_objects(&successful, 7)
        .unwrap()
        .iter()
        .any(|object| matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )));
    assert!(!Slot::token_objects(&failing, 8)
        .unwrap()
        .iter()
        .any(|object| matches!(
                    object.material,
                    KeyMaterial::Profile { profile_id }
                        if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )));
}

fn assert_failed_public_discovery_stays_unprofiled_after_user_login(
    mut slot: YubiHsmSlot,
    expected: YubiHsmDiscoveryCache,
) {
    assert!(!Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .any(|object| matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )));
    assert_eq!(slot.object_cache.borrow().discovery, expected);

    Slot::login_user(&mut slot, b"0001", PASSWORD).unwrap();
    assert!(Slot::login_is_active(&slot));
    assert!(!Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .any(|object| matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )));
}

#[test]
fn unknown_public_discovery_authkey_does_not_gain_a_profile_from_user_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let credential = configured_yubihsm_public_discovery_credential(Some("0003password".into()))
        .unwrap()
        .unwrap();
    let slot = public_discovery_test_slot(peer, credential);

    assert_failed_public_discovery_stays_unprofiled_after_user_login(
        slot,
        YubiHsmDiscoveryCache::Failed,
    );
}

#[test]
fn public_discovery_secure_channel_fault_does_not_gain_a_profile_from_user_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let slot = public_discovery_test_slot(peer, public_discovery_credential("wrong password"));

    assert_failed_public_discovery_stays_unprofiled_after_user_login(
        slot,
        YubiHsmDiscoveryCache::Failed,
    );
}

#[test]
fn missing_hsmauth_slot_does_not_gain_a_profile_from_user_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer,
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        Arc::new(crate::HsmAuthProviderRegistry::default()),
        Some(hsmauth_public_discovery_credential()),
    );

    assert_failed_public_discovery_stays_unprofiled_after_user_login(
        slot,
        YubiHsmDiscoveryCache::Unattempted,
    );
}

#[test]
fn missing_hsmauth_credential_does_not_gain_a_profile_from_user_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut provider = symmetric_hsmauth_provider("12345678");
    provider.credential.label = "different key".to_owned();
    let slot = YubiHsmSlot::with_hsmauth_providers_and_public_discovery(
        peer,
        (2, 4, 1),
        vec![YUBIHSM_ALGO_RSA_2048],
        Arc::new(crate::HsmAuthProviderRegistry::new(vec![provider])),
        Some(hsmauth_public_discovery_credential()),
    );

    assert_failed_public_discovery_stays_unprofiled_after_user_login(
        slot,
        YubiHsmDiscoveryCache::Unattempted,
    );
}

#[test]
fn yubihsm_public_discovery_accepts_standalone_ca_certificates() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.add_standalone_certificate(6);
    let slot = public_discovery_test_slot(peer, public_discovery_credential("password"));

    let objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(objects.iter().any(|object| matches!(
        object.material,
        KeyMaterial::Profile { profile_id }
            if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
    )));
    let certificates = objects
        .iter()
        .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .collect::<Vec<_>>();
    assert_eq!(certificates.len(), 2);
    assert!(certificates
        .iter()
        .any(|object| object.label == "standalone CA certificate"));
    assert_eq!(
        objects
            .iter()
            .filter(|object| object.class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
            .count(),
        1
    );
}

#[test]
fn yubihsm_public_discovery_requires_get_opaque_without_blocking_user_login() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.remove_get_opaque(1);
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));

    assert!(!Slot::token_objects(&slot, 7)
        .unwrap()
        .iter()
        .any(|object| matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )));
    assert!(Slot::login(&mut slot, b"0002password").is_ok());
    assert!(session_is_active(&slot));
    Slot::logout(&mut slot).unwrap();
}

#[test]
fn yubihsm_user_login_expands_the_public_object_view_without_duplicates() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    let public_objects = Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert!(Slot::backend_session_is_active(&slot));
    assert!(!Slot::login_is_active(&slot));
    let public_certificate_ids = public_objects
        .iter()
        .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .map(|object| object.unique_id.clone())
        .collect::<HashSet<_>>();
    assert_eq!(public_certificate_ids.len(), 1);
    assert!(public_objects
        .iter()
        .any(|object| object.class == CKO_DATA as CK_OBJECT_CLASS));
    assert!(public_objects.iter().all(|object| !object.private));
    let get_opaque_before_login = peer
        .inner_commands
        .borrow()
        .iter()
        .filter(|(command, _)| *command == CommandCode::GetOpaque as u8)
        .count();

    let extra_certificate = ProtocolPeer::attestation_certificate(3).unwrap();
    peer.metadata_objects.borrow_mut().insert(
        3,
        (
            ObjectInfo {
                capabilities: [0; 8],
                id: 3,
                length: extra_certificate.len() as u16,
                domains: 0xffff,
                object_type: YUBIHSM_OPAQUE,
                algorithm: YUBIHSM_ALGO_OPAQUE_X509_CERTIFICATE,
                sequence: 1,
                origin: 1,
                label: "login-only certificate".to_owned(),
                delegated_capabilities: [0; 8],
            },
            extra_certificate.clone(),
        ),
    );

    Slot::login(&mut slot, b"0001password").unwrap();
    assert!(session_is_active(&slot));
    assert_eq!(session_role(&slot), Some(YubiHsmSessionRole::User));
    assert!(Slot::backend_session_is_active(&slot));
    assert!(Slot::login_is_active(&slot));
    assert!(matches!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Available { .. }
    ));
    let logged_in_objects = Slot::token_objects(&slot, 7).unwrap();
    let get_opaque_after_login = peer
        .inner_commands
        .borrow()
        .iter()
        .filter(|(command, _)| *command == CommandCode::GetOpaque as u8)
        .count();
    assert_eq!(get_opaque_after_login, get_opaque_before_login);
    let cached_opaque = logged_in_objects
        .iter()
        .find(|object| {
            matches!(
                object.material,
                KeyMaterial::YubiHsm {
                    id: 4,
                    object_type: YUBIHSM_OPAQUE,
                    ..
                }
            )
        })
        .unwrap();
    let KeyMaterial::YubiHsm { value, .. } = &cached_opaque.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    let payload = Slot::yubihsm_read_opaque(&slot, 4).unwrap();
    *value.borrow_mut() = Some(payload);
    let get_opaque_after_attribute_read = peer
        .inner_commands
        .borrow()
        .iter()
        .filter(|(command, _)| *command == CommandCode::GetOpaque as u8)
        .count();
    assert_eq!(get_opaque_after_attribute_read, get_opaque_after_login + 1);
    let rebuilt_objects = Slot::token_objects(&slot, 7).unwrap();
    let get_opaque_after_rebuild = peer
        .inner_commands
        .borrow()
        .iter()
        .filter(|(command, _)| *command == CommandCode::GetOpaque as u8)
        .count();
    assert_eq!(get_opaque_after_rebuild, get_opaque_after_attribute_read);
    let rebuilt_opaque = rebuilt_objects
        .iter()
        .find(|object| {
            matches!(
                object.material,
                KeyMaterial::YubiHsm {
                    id: 4,
                    object_type: YUBIHSM_OPAQUE,
                    ..
                }
            )
        })
        .unwrap();
    let KeyMaterial::YubiHsm { value, .. } = &rebuilt_opaque.material else {
        unreachable!();
    };
    assert_eq!(
        value.borrow().as_deref(),
        Some(b"cached opaque value".as_slice())
    );
    let logged_in_certificate_ids = logged_in_objects
        .iter()
        .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .map(|object| object.unique_id.clone())
        .collect::<HashSet<_>>();
    assert!(public_certificate_ids.is_subset(&logged_in_certificate_ids));
    assert_eq!(logged_in_certificate_ids.len(), 2);
    assert_eq!(
        logged_in_objects
            .iter()
            .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
            .count(),
        logged_in_certificate_ids.len()
    );

    Slot::logout(&mut slot).unwrap();
    assert!(!session_is_active(&slot));
    assert_eq!(session_role(&slot), None);
    assert!(!Slot::backend_session_is_active(&slot));
    assert!(!Slot::login_is_active(&slot));
    assert!(matches!(
        slot.object_cache.borrow().discovery,
        YubiHsmDiscoveryCache::Available { .. }
    ));
    let logged_out_objects = Slot::token_objects(&slot, 7).unwrap();
    assert!(logged_out_objects.iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::YubiHsm {
                id: 4,
                object_type: YUBIHSM_OPAQUE,
                ..
            }
        )
    }));
    assert_eq!(
        logged_out_objects
            .iter()
            .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
            .count(),
        2
    );
    assert!(logged_out_objects
        .iter()
        .filter(|object| object.class == CKO_CERTIFICATE as CK_OBJECT_CLASS)
        .all(|object| !object.private));
    let login_discovered_certificate = yubihsm_opaque_object(&logged_out_objects, 3);
    let KeyMaterial::YubiHsm { value, .. } = &login_discovered_certificate.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    let sessions_before_lazy_read = peer
        .commands
        .borrow()
        .iter()
        .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
        .count();
    let closes_before_lazy_read = peer.closed_sessions.get();
    assert_eq!(
        exercise_lazy_opaque_value_cache(&slot, &login_discovered_certificate),
        extra_certificate
    );
    assert!(session_is_active(&slot));
    assert_eq!(
        session_role(&slot),
        Some(YubiHsmSessionRole::PublicDiscovery)
    );
    assert!(peer.session.borrow().is_some());
    assert_eq!(
        peer.commands
            .borrow()
            .iter()
            .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
            .count(),
        sessions_before_lazy_read + 1
    );
    assert_eq!(peer.closed_sessions.get(), closes_before_lazy_read);
}

#[test]
fn yubihsm_user_login_requires_public_discovery_domains() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.set_authkey_domains(2, 0x0001);
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    assert!(Slot::token_objects(&slot, 7).unwrap().iter().any(|object| {
        matches!(
            object.material,
            KeyMaterial::Profile { profile_id }
                if profile_id == CKP_PUBLIC_CERTIFICATES_TOKEN as CK_PROFILE_ID
        )
    }));

    let closes_before_login = peer.closed_sessions.get();
    assert!(matches!(
        Slot::login(&mut slot, b"0002password"),
        Err(Error::Generic(rv)) if rv == CKR_FUNCTION_REJECTED as _
    ));
    assert!(!session_is_active(&slot));
    assert_eq!(session_role(&slot), None);
    assert!(peer.session.borrow().is_none());
    assert_eq!(peer.closed_sessions.get(), closes_before_login + 2);
}

#[test]
fn yubihsm_logged_out_lazy_read_requires_public_discovery_credential() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot = cache_test_slot(peer.clone(), false);
    Slot::login(&mut slot, b"0001password").unwrap();
    let logged_in = Slot::token_objects(&slot, 7).unwrap();
    let certificate = yubihsm_opaque_object(&logged_in, 2);
    let KeyMaterial::YubiHsm { value, .. } = &certificate.material else {
        unreachable!();
    };
    assert!(value.borrow().is_none());
    Slot::logout(&mut slot).unwrap();

    let sessions_before_read = peer
        .commands
        .borrow()
        .iter()
        .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
        .count();
    assert!(matches!(
        Slot::yubihsm_read_opaque(&slot, 2),
        Err(Error::Generic(rv)) if rv == CKR_USER_NOT_LOGGED_IN as _
    ));
    assert_eq!(
        peer.commands
            .borrow()
            .iter()
            .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
            .count(),
        sessions_before_read
    );
}

#[test]
fn yubihsm_public_discovery_reprobes_after_slot_reinitialization() {
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    Slot::token_objects(&slot, 7).unwrap();
    let initial_sessions = peer
        .commands
        .borrow()
        .iter()
        .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
        .count();

    Slot::init_slot(&mut slot).unwrap();
    Slot::token_objects(&slot, 7).unwrap();
    let sessions_after_reinitialization = peer
        .commands
        .borrow()
        .iter()
        .filter(|command| command.first() == Some(&COMMAND_CREATE_SESSION))
        .count();
    assert_eq!(sessions_after_reinitialization, initial_sessions + 1);
}

#[test]
fn parses_device_information() {
    let peer = ProtocolPeer::new();
    let info = get_device_info(&peer).unwrap();
    assert_eq!(info.major, 2);
    assert_eq!(info.minor, 4);
    assert_eq!(info.patch, 1);
    assert_eq!(info.serial, 0x01020304);
    assert_eq!(info.log_total, 62);
    assert_eq!(info.log_used, 3);
    assert_eq!(info.algorithms, [1, 2]);
    assert_eq!(info.part_number.as_deref(), Some("78CLUFX5000P"));

    let commands = peer.commands.borrow();
    assert_eq!(Frame::parse(&commands[0]).unwrap().data, []);
    assert_eq!(Frame::parse(&commands[1]).unwrap().data, [1]);
}

#[test]
fn extended_device_information_is_optional() {
    let peer = ProtocolPeer::without_extended_device_info();
    let info = get_device_info(&peer).unwrap();
    assert_eq!(info.part_number, None);
    assert_eq!(peer.commands.borrow().len(), 2);
}

#[test]
fn legacy_device_information_omits_the_page_byte() {
    let peer = ProtocolPeer::legacy_device();
    let info = get_device_info(&peer).unwrap();
    assert_eq!((info.major, info.minor, info.patch), (2, 3, 1));
    assert_eq!(info.part_number, None);
    let commands = peer.commands.borrow();
    assert_eq!(commands.len(), 1);
    assert_eq!(Frame::parse(&commands[0]).unwrap().data, []);
}

#[test]
fn yubihsm_slot_uses_the_extended_part_number_as_model() {
    let peer = Rc::new(ProtocolPeer::new());
    let mut slot = YubiHsmSlot::new(peer, (0, 0, 0), Vec::new());
    Slot::init_slot(&mut slot).unwrap();
    assert_eq!(slot.model(), "78CLUFX5000P");
    assert_eq!(slot.label(), "YubiHSM #16909060");

    let mut info = unsafe { std::mem::zeroed::<crate::CK_TOKEN_INFO>() };
    Slot::get_token_info(&slot, &mut info).unwrap();
    assert_eq!(&info.model, b"78CLUFX5000P    ");
    assert_eq!(&info.label[..19], b"YubiHSM #16909060  ");
}

#[test]
fn authenticates_and_exchanges_encrypted_session_messages() {
    let peer = ProtocolPeer::new();
    let mut session =
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
    assert_eq!(
        session
            .send_command(&peer, &Command::get_storage_info())
            .unwrap(),
        [0xaa, 0xbb, 0xcc]
    );
    assert_eq!(
        session
            .send_command(&peer, &Command::get_pseudo_random(8))
            .unwrap(),
        [0x5a; 8]
    );
    session
        .send_command(&peer, &Command::close_session())
        .unwrap();
    assert_eq!(peer.commands.borrow().len(), 5);
}

fn wire_bytes(encoded: &str) -> Vec<u8> {
    encoded
        .split_ascii_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[derive(Debug)]
struct SecureSessionHostVectorConnector {
    exchanges: RefCell<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl Connector for SecureSessionHostVectorConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        "YubiHSM vector"
    }

    fn serial(&self) -> &str {
        "VECTOR"
    }

    fn major(&self) -> u8 {
        2
    }

    fn minor(&self) -> u8 {
        4
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        4096
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let (expected, response) = self.exchanges.borrow_mut().remove(0);
        assert_eq!(send_buffer, expected);
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

fn symmetric_secure_session_wire_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    [
        (
            "03 00 0a 00 01 01 02 03 04 05 06 07 08",
            "83 00 11 07 10 11 12 13 14 15 16 17 51 4e 41 ae a5 fd f2 71",
        ),
        (
            "04 00 11 07 57 a0 04 06 52 9b 6f e7 92 0a ce 23 a5 b3 0a 98",
            "84 00 00",
        ),
        (
            "05 00 19 07 c3 87 1b bc 77 0e bc 7b c6 20 9a af 87 c9 7e cc 9a 5d 39 8b ab 1d 50 ae",
            "85 00 19 07 d2 5b 41 8c 06 df bd 5d da 32 6f 1d db f9 86 28 5b 6f e1 39 7a 01 32 ac",
        ),
        (
            "05 00 19 07 5a df ce b4 16 42 a3 65 12 e5 00 9f 19 3e 9e 57 6a cc a1 e8 ff 25 a2 b4",
            "85 00 19 07 f8 65 e5 5f bb 04 1c ac fe 0d 36 81 bf 26 8d 97 8c 3e d6 ae 95 1b 62 2a",
        ),
        (
            "05 00 19 07 59 44 33 8f 05 cd f3 79 07 5e f6 38 00 d4 73 21 6e c6 d8 39 54 ae 23 68",
            "85 00 19 07 e8 b8 99 5f 82 1a 9c f5 68 02 cc 43 cd fc 3a 1a 99 81 e5 05 00 84 10 9b",
        ),
    ]
    .into_iter()
    .map(|(request, response)| (wire_bytes(request), wire_bytes(response)))
    .collect()
}

#[test]
fn host_secure_session_matches_fixed_wire_vectors() {
    let exchanges = symmetric_secure_session_wire_vectors();
    let connector = SecureSessionHostVectorConnector {
        exchanges: RefCell::new(exchanges),
    };
    let mut session =
        SecureSession::authenticate_with_challenge(&connector, 1, PASSWORD, HOST_CHALLENGE)
            .unwrap();
    assert_eq!(
        session
            .send_command(&connector, &Command::get_storage_info())
            .unwrap(),
        [0xaa, 0xbb, 0xcc]
    );
    assert_eq!(
        session
            .send_command(&connector, &Command::get_pseudo_random(8))
            .unwrap(),
        [0x5a; 8]
    );
    session
        .send_command(&connector, &Command::close_session())
        .unwrap();
    assert!(connector.exchanges.borrow().is_empty());
}

#[test]
fn device_secure_session_matches_fixed_wire_vectors() {
    let exchanges = symmetric_secure_session_wire_vectors();
    let (mut session, host_cryptogram, create_response) =
        SecureSession::peer_begin_symmetric(&exchanges[0].0, PASSWORD, 7, CARD_CHALLENGE).unwrap();
    assert_eq!(create_response, exchanges[0].1);
    assert_eq!(
        host_cryptogram,
        wire_bytes("57 a0 04 06 52 9b 6f e7").as_slice()
    );
    assert_eq!(
        session
            .peer_authenticate_symmetric(&exchanges[1].0, &host_cryptogram, &[])
            .unwrap(),
        exchanges[1].1
    );
    assert_eq!(
        session
            .peer_exchange(&exchanges[2].0, |command, data| {
                assert_eq!(command, CommandCode::GetStorageInfo as u8);
                assert!(data.is_empty());
                Ok((command | RESPONSE_BIT, vec![0xaa, 0xbb, 0xcc]))
            })
            .unwrap(),
        exchanges[2].1
    );
    assert_eq!(
        session
            .peer_exchange(&exchanges[3].0, |command, data| {
                assert_eq!(command, CommandCode::GetPseudoRandom as u8);
                assert_eq!(data, [0, 8]);
                Ok((command | RESPONSE_BIT, vec![0x5a; 8]))
            })
            .unwrap(),
        exchanges[3].1
    );
    assert_eq!(
        session
            .peer_exchange(&exchanges[4].0, |command, data| {
                assert_eq!(command, CommandCode::CloseSession as u8);
                assert!(data.is_empty());
                Ok((command | RESPONSE_BIT, Vec::new()))
            })
            .unwrap(),
        exchanges[4].1
    );
    assert!(!session.is_valid());
}

#[test]
fn device_secure_session_rejects_invalid_authentication_mac() {
    let exchanges = symmetric_secure_session_wire_vectors();
    let (mut session, host_cryptogram, _) =
        SecureSession::peer_begin_symmetric(&exchanges[0].0, PASSWORD, 7, CARD_CHALLENGE).unwrap();
    let mut authentication = exchanges[1].0.clone();
    *authentication.last_mut().unwrap() ^= 1;
    assert_eq!(
        session
            .peer_authenticate_symmetric(&authentication, &host_cryptogram, &[])
            .unwrap(),
        wire_bytes("7f 00 01 04")
    );
    assert!(!session.is_valid());
}

#[test]
fn device_secure_session_rejects_invalid_session_message_mac() {
    let exchanges = symmetric_secure_session_wire_vectors();
    let (mut session, host_cryptogram, _) =
        SecureSession::peer_begin_symmetric(&exchanges[0].0, PASSWORD, 7, CARD_CHALLENGE).unwrap();
    session
        .peer_authenticate_symmetric(&exchanges[1].0, &host_cryptogram, &[])
        .unwrap();
    let mut request = exchanges[2].0.clone();
    *request.last_mut().unwrap() ^= 1;
    let handled = Cell::new(false);
    assert!(matches!(
        session.peer_exchange(&request, |command, _| {
            handled.set(true);
            Ok((command | RESPONSE_BIT, Vec::new()))
        }),
        Err(Error::Generic(rv)) if rv == CKR_ENCRYPTED_DATA_INVALID as _
    ));
    assert!(!handled.get());
    assert!(!session.is_valid());
}

#[test]
fn device_public_key_uses_the_asymmetric_authentication_algorithm() {
    let peer = ProtocolPeer::new();
    let public_key = device_public_key_bytes(&peer).unwrap();
    assert_eq!(public_key[0], 0x04);
    assert!(parse_p256_public_key(&public_key).is_ok());
    let command = peer.commands.borrow();
    assert_eq!(command.len(), 1);
    assert_eq!(command[0][0], CommandCode::GetDevicePublicKey as u8);
}

#[test]
fn hsmauth_symmetric_credential_opens_a_real_yubihsm_secure_session() {
    #[cfg(unix)]
    let _guard = crate::test::TEST_LOCK.lock().unwrap();
    #[cfg(unix)]
    let _pinentry = crate::test::TestPinentry::new("password");
    let yubihsm = std::rc::Rc::new(ProtocolPeer::new());
    let provider = crate::HsmAuthProvider {
        connector: std::rc::Rc::new(SymmetricHsmAuthPeer { serial: "12345678" }).into(),
        credential: crate::HsmAuthCredential {
            label: "default key".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::Aes128YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: None,
        },
        version: (5, 4, 3),
        trust_prefix: None,
    };
    let duplicate = crate::HsmAuthProvider {
        connector: std::rc::Rc::new(SymmetricHsmAuthPeer { serial: "87654321" }).into(),
        ..provider.clone()
    };
    let mut slot = crate::YubiHsmSlot::with_hsmauth_providers(
        yubihsm.clone(),
        (2, 4, 1),
        vec![crate::YUBIHSM_ALGO_RSA_2048],
        std::sync::Arc::new(crate::HsmAuthProviderRegistry::new(vec![
            provider, duplicate,
        ])),
    );

    assert!(matches!(
        crate::Slot::login(&mut slot, b":000164656661756c74206b6579:password"),
        Err(crate::Error::Generic(value)) if value == crate::CKR_PIN_INCORRECT as crate::CK_RV
    ));
    #[cfg(unix)]
    crate::Slot::login_with_pinentry(
        &mut slot,
        b":0001default key@12345678",
        &crate::pinentry::Pinentry::from_environment().unwrap(),
    )
    .unwrap();
    #[cfg(not(unix))]
    crate::Slot::login_user(&mut slot, b":0001default key@12345678", b"password").unwrap();
    let session =
        crate::Slot::open_session(&mut slot, 91, crate::CKF_SERIAL_SESSION as crate::CK_FLAGS);
    assert!(session.get_session_info().is_ok());
    assert_eq!(
        yubihsm.inner_commands.borrow().as_slice(),
        [(CommandCode::GetStorageInfo as u8, Vec::new())]
    );
    assert_eq!(create_session_payload_lengths(&yubihsm), [10]);
}

#[test]
fn hsmauth_symmetric_failure_finishes_the_pending_yubihsm_session() {
    let yubihsm = ProtocolPeer::new();
    let provider = crate::HsmAuthProvider {
        connector: std::rc::Rc::new(SymmetricHsmAuthPeer { serial: "12345678" }).into(),
        credential: crate::HsmAuthCredential {
            label: "default key".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::Aes128YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: None,
        },
        version: (5, 7, 1),
        trust_prefix: None,
    };

    assert!(matches!(
        provider.authenticate(&yubihsm, 1, b"wrong-password"),
        Err(crate::Error::Generic(value)) if value == crate::CKR_PIN_INCORRECT as crate::CK_RV
    ));
    assert_eq!(
        yubihsm
            .commands
            .borrow()
            .iter()
            .map(|command| command[0])
            .collect::<Vec<_>>(),
        [COMMAND_CREATE_SESSION, COMMAND_AUTHENTICATE_SESSION]
    );
    assert!(yubihsm.session.borrow().is_none());
    assert_eq!(yubihsm.closed_sessions.get(), 1);
}

#[test]
fn hsmauth_asymmetric_credential_works_without_device_trust_configuration() {
    let trust_prefix = OsString::new();
    let yubihsm = std::rc::Rc::new(ProtocolPeer::new());
    yubihsm.use_asymmetric_authentication(1);
    let hsmauth = std::rc::Rc::new(AsymmetricHsmAuthPeer::new());
    let provider = crate::HsmAuthProvider {
        connector: hsmauth.clone().into(),
        credential: crate::HsmAuthCredential {
            label: "asymmetric".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
            retries: 8,
            touch_required: true,
            public_key: Some(hsmauth.public_key.clone()),
        },
        version: (5, 7, 1),
        trust_prefix: Some(trust_prefix),
    };
    let mut slot = crate::YubiHsmSlot::with_hsmauth_providers(
        yubihsm.clone(),
        (2, 4, 1),
        vec![crate::YUBIHSM_ALGO_RSA_2048],
        std::sync::Arc::new(crate::HsmAuthProviderRegistry::new(vec![provider])),
    );

    crate::Slot::login(&mut slot, b":0001asymmetric:password").unwrap();
    let session =
        crate::Slot::open_session(&mut slot, 92, crate::CKF_SERIAL_SESSION as crate::CK_FLAGS);
    assert!(session.get_session_info().is_ok());
    assert_eq!(
        yubihsm.inner_commands.borrow().as_slice(),
        [(CommandCode::GetStorageInfo as u8, Vec::new())]
    );
    assert_eq!(create_session_payload_lengths(&yubihsm), [67]);
}

#[test]
fn hsmauth_asymmetric_failure_invalidates_the_pending_yubihsm_session() {
    let trust = TestTrustEntry::new();
    let yubihsm = ProtocolPeer::new();
    yubihsm.use_asymmetric_authentication(1);
    let hsmauth = std::rc::Rc::new(AsymmetricHsmAuthPeer::failing_calculate());
    let provider = crate::HsmAuthProvider {
        connector: hsmauth.clone().into(),
        credential: crate::HsmAuthCredential {
            label: "asymmetric".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
            retries: 8,
            touch_required: true,
            public_key: Some(hsmauth.public_key.clone()),
        },
        version: (5, 7, 1),
        trust_prefix: Some(trust.prefix.clone()),
    };

    assert!(matches!(
        provider.authenticate(&yubihsm, 1, PASSWORD),
        Err(crate::Error::Generic(value)) if value == crate::CKR_PIN_INCORRECT as crate::CK_RV
    ));
    let commands = yubihsm.commands.borrow();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0][0], COMMAND_CREATE_SESSION);
    assert_eq!(commands[2][0], COMMAND_SESSION_MESSAGE);
    assert!(yubihsm.session.borrow().is_none());
    assert_eq!(yubihsm.closed_sessions.get(), 1);
}

#[test]
fn hsmauth_algorithm_mismatches_fail_without_probing() {
    let asymmetric_target = ProtocolPeer::new();
    asymmetric_target.use_asymmetric_authentication(1);
    let symmetric_provider = crate::HsmAuthProvider {
        connector: std::rc::Rc::new(SymmetricHsmAuthPeer { serial: "12345678" }).into(),
        credential: crate::HsmAuthCredential {
            label: "symmetric".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::Aes128YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: None,
        },
        version: (5, 7, 1),
        trust_prefix: None,
    };
    assert!(matches!(
        symmetric_provider.authenticate(&asymmetric_target, 1, PASSWORD),
        Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
    ));
    assert_eq!(create_session_payload_lengths(&asymmetric_target), [10]);

    let symmetric_target = ProtocolPeer::new();
    let asymmetric_peer = std::rc::Rc::new(AsymmetricHsmAuthPeer::new());
    let asymmetric_provider = crate::HsmAuthProvider {
        connector: asymmetric_peer.clone().into(),
        credential: crate::HsmAuthCredential {
            label: "asymmetric".to_owned(),
            algorithm: crate::HsmAuthAlgorithm::EcP256YubicoAuthentication,
            retries: 8,
            touch_required: false,
            public_key: Some(asymmetric_peer.public_key.clone()),
        },
        version: (5, 7, 1),
        trust_prefix: None,
    };
    assert!(matches!(
        asymmetric_provider.authenticate(&symmetric_target, 1, PASSWORD),
        Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
    ));
    assert_eq!(create_session_payload_lengths(&symmetric_target), [67]);
}

#[test]
fn authenticates_asymmetrically_and_exchanges_encrypted_session_messages() {
    let trust = TestTrustEntry::new();
    let peer = ProtocolPeer::new();
    peer.use_asymmetric_authentication(1);
    let (mut session, algorithm) = SecureSession::authenticate_direct(
        &peer,
        1,
        PASSWORD,
        Some(&trust.prefix),
        Some(DirectAuthenticationAlgorithm::Asymmetric),
    )
    .unwrap();
    assert_eq!(algorithm, DirectAuthenticationAlgorithm::Asymmetric);
    assert_eq!(
        session
            .send_command(&peer, &Command::get_storage_info())
            .unwrap(),
        [0xaa, 0xbb, 0xcc]
    );
    session
        .send_command(&peer, &Command::close_session())
        .unwrap();
    assert_eq!(peer.commands.borrow().len(), 4);
}

#[test]
fn direct_authentication_probes_symmetric_then_caches_asymmetric() {
    let trust = TestTrustEntry::new();
    let peer = ProtocolPeer::new();
    peer.use_asymmetric_authentication(1);

    let (mut session, algorithm) =
        SecureSession::authenticate_direct(&peer, 1, PASSWORD, Some(&trust.prefix), None).unwrap();
    assert_eq!(algorithm, DirectAuthenticationAlgorithm::Asymmetric);
    assert_eq!(create_session_payload_lengths(&peer), [10, 67]);
    session
        .send_command(&peer, &Command::close_session())
        .unwrap();

    peer.commands.borrow_mut().clear();
    let (mut session, algorithm) = SecureSession::authenticate_direct(
        &peer,
        1,
        PASSWORD,
        Some(&trust.prefix),
        Some(algorithm),
    )
    .unwrap();
    assert_eq!(algorithm, DirectAuthenticationAlgorithm::Asymmetric);
    assert_eq!(create_session_payload_lengths(&peer), [67]);
    session
        .send_command(&peer, &Command::close_session())
        .unwrap();
}

#[test]
fn direct_authentication_does_not_retry_after_password_failure() {
    let peer = ProtocolPeer::new();
    assert!(matches!(
        SecureSession::authenticate_direct(&peer, 1, b"wrong-password", None, None),
        Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
    ));
    assert_eq!(create_session_payload_lengths(&peer), [10]);
}

#[test]
fn direct_login_reuses_the_detected_authentication_algorithm() {
    let trust = TestTrustEntry::new();
    let peer = Rc::new(ProtocolPeer::new());
    peer.use_asymmetric_authentication(1);
    let mut slot = YubiHsmSlot::new(peer.clone(), (2, 4, 1), vec![YUBIHSM_ALGO_RSA_2048]);
    slot.trust_prefix = Some(trust.prefix.clone());

    Slot::login(&mut slot, b"0001password").unwrap();
    assert_eq!(create_session_payload_lengths(&peer), [10, 67]);
    Slot::logout(&mut slot).unwrap();
    {
        let cache = slot.object_cache.borrow();
        let authentication_key = cache
            .native_objects
            .get(&YubiHsmObjectKey::new(YUBIHSM_AUTHENTICATION_KEY, 1))
            .unwrap();
        assert_eq!(authentication_key.sequence, None);
        assert!(authentication_key.info.is_none());
        assert_eq!(
            authentication_key.inferred_authentication_algorithm,
            Some(DirectAuthenticationAlgorithm::Asymmetric)
        );
    }

    peer.commands.borrow_mut().clear();
    Slot::login(&mut slot, b"0001password").unwrap();
    assert_eq!(create_session_payload_lengths(&peer), [67]);
    Slot::logout(&mut slot).unwrap();

    peer.use_symmetric_authentication(1);
    fs::write(&trust.path, b"invalidated trust entry").unwrap();
    peer.commands.borrow_mut().clear();
    Slot::login(&mut slot, b"0001password").unwrap();
    assert_eq!(create_session_payload_lengths(&peer), [67, 10]);
    Slot::logout(&mut slot).unwrap();
}

#[test]
fn prelogin_and_user_discovery_share_the_authentication_algorithm_cache() {
    let trust = TestTrustEntry::new();
    let peer = Rc::new(ProtocolPeer::new());
    peer.add_public_certificate_pair();
    peer.use_asymmetric_authentication(2);
    peer.list_authentication_key(2);
    let mut slot =
        public_discovery_test_slot(peer.clone(), public_discovery_credential("password"));
    slot.trust_prefix = Some(trust.prefix.clone());

    Slot::token_objects(&slot, 7).unwrap();
    assert_eq!(
        slot.cached_authentication_algorithm(2).unwrap(),
        Some(DirectAuthenticationAlgorithm::Asymmetric)
    );
    {
        let cache = slot.object_cache.borrow();
        let authentication_key = cache
            .native_objects
            .get(&YubiHsmObjectKey::new(YUBIHSM_AUTHENTICATION_KEY, 2))
            .unwrap();
        assert!(authentication_key.info.is_some());
        assert_eq!(authentication_key.inferred_authentication_algorithm, None);
    }
    peer.commands.borrow_mut().clear();
    Slot::login(&mut slot, b"0002password").unwrap();
    assert_eq!(create_session_payload_lengths(&peer), [67]);
    Slot::logout(&mut slot).unwrap();

    let user_peer = Rc::new(ProtocolPeer::new());
    user_peer.use_asymmetric_authentication(2);
    user_peer.list_authentication_key(2);
    let mut user_slot = YubiHsmSlot::new(user_peer.clone(), (2, 4, 1), vec![YUBIHSM_ALGO_RSA_2048]);
    user_slot.trust_prefix = Some(trust.prefix.clone());
    Slot::login(&mut user_slot, b"0001password").unwrap();
    Slot::token_objects(&user_slot, 8).unwrap();
    Slot::logout(&mut user_slot).unwrap();
    {
        let cache = user_slot.object_cache.borrow();
        let authentication_key = cache
            .native_objects
            .get(&YubiHsmObjectKey::new(YUBIHSM_AUTHENTICATION_KEY, 2))
            .unwrap();
        assert!(authentication_key.info.is_none());
        assert_eq!(
            authentication_key.inferred_authentication_algorithm,
            Some(DirectAuthenticationAlgorithm::Asymmetric)
        );
    }
    user_peer.commands.borrow_mut().clear();
    Slot::login(&mut user_slot, b"0002password").unwrap();
    assert_eq!(create_session_payload_lengths(&user_peer), [67]);
    Slot::logout(&mut user_slot).unwrap();

    user_peer.connection_epoch.set(1);
    user_peer.commands.borrow_mut().clear();
    Slot::login(&mut user_slot, b"0002password").unwrap();
    assert_eq!(create_session_payload_lengths(&user_peer), [10, 67]);
    Slot::logout(&mut user_slot).unwrap();
}

#[test]
fn asymmetric_authentication_rejects_the_wrong_password() {
    let trust = TestTrustEntry::new();
    let peer = ProtocolPeer::new();
    peer.use_asymmetric_authentication(1);
    assert!(matches!(
        SecureSession::authenticate_direct(
            &peer,
            1,
            b"wrong-password",
            Some(&trust.prefix),
            Some(DirectAuthenticationAlgorithm::Asymmetric),
        ),
        Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
    ));
}

#[test]
fn asymmetric_authentication_rejects_an_untrusted_device_public_key() {
    let trust = TestTrustEntry::new();
    fs::write(&trust.path, b"not a public key").unwrap();
    let peer = ProtocolPeer::new();
    peer.use_asymmetric_authentication(1);
    assert!(matches!(
        SecureSession::authenticate_direct(
            &peer,
            1,
            PASSWORD,
            Some(&trust.prefix),
            Some(DirectAuthenticationAlgorithm::Asymmetric),
        ),
        Err(Error::Generic(rv)) if rv == crate::CKR_ARGUMENTS_BAD as _
    ));
}

#[test]
fn rejects_card_cryptogram_after_cleaning_up_device_session() {
    let peer = ProtocolPeer::with_bad_card_cryptogram();
    assert!(matches!(
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE),
        Err(Error::Generic(rv)) if rv == CKR_ENCRYPTED_DATA_INVALID as _
    ));
    assert_eq!(peer.commands.borrow().len(), 3);
    assert_eq!(peer.commands.borrow()[1][0], COMMAND_AUTHENTICATE_SESSION);
    assert_eq!(peer.commands.borrow()[2][0], COMMAND_SESSION_MESSAGE);
    assert_eq!(peer.closed_sessions.get(), 1);
    assert!(peer.session.borrow().is_none());
}

#[test]
fn rejects_authentication_success_responses_with_payload() {
    for payload_length in [1, MAC_LENGTH, MAC_LENGTH + 1] {
        let peer = ProtocolPeer::with_authenticate_payload(vec![0xaa; payload_length]);
        assert!(matches!(
            SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE),
            Err(Error::Generic(rv)) if rv == CKR_DEVICE_ERROR as _
        ));
        assert_eq!(peer.commands.borrow().len(), 3);
        assert_eq!(peer.closed_sessions.get(), 1);
    }
}

#[test]
fn wrong_password_is_reported_as_pin_incorrect() {
    let peer = ProtocolPeer::new();
    assert!(matches!(
        SecureSession::authenticate_with_challenge(
            &peer,
            1,
            b"wrong-password",
            HOST_CHALLENGE,
        ),
        Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
    ));
}

#[test]
fn secure_message_limits_match_supported_firmware_generations() {
    assert!(secure_message_length(3_116) <= maximum_message_size(2, 4));
    assert!(secure_message_length(3_117) > maximum_message_size(2, 4));
    assert!(secure_message_length(2_028) <= maximum_message_size(2, 3));
    assert!(secure_message_length(2_029) > maximum_message_size(2, 3));
}

#[test]
fn oversized_commands_do_not_mutate_session_state() {
    let peer = ProtocolPeer::new();
    let mut session =
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
    let counter = session.counter;
    let chaining_value = session.mac_chaining_value;
    let command = Command::raw(CommandCode::Echo, &[0; 3_117]).unwrap();
    assert!(matches!(
        session.send_command(&peer, &command),
        Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
    ));
    assert_eq!(session.counter, counter);
    assert_eq!(session.mac_chaining_value, chaining_value);
    assert_eq!(peer.commands.borrow().len(), 2);
    assert!(session.is_valid());

    let random = Command::get_pseudo_random(3_117);
    assert!(matches!(
        session.send_command(&peer, &random),
        Err(Error::Generic(rv)) if rv == CKR_DATA_LEN_RANGE as _
    ));
    assert_eq!(session.counter, counter);
    assert_eq!(session.mac_chaining_value, chaining_value);
    assert_eq!(peer.commands.borrow().len(), 2);
    assert!(session.is_valid());
}

#[test]
fn rejects_invalid_response_mac() {
    let peer = ProtocolPeer::new();
    let mut session =
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
    peer.corrupt_response_mac.set(true);
    assert!(session
        .send_command(&peer, &Command::get_storage_info())
        .is_err());
    assert!(!session.is_valid());
    let command_count = peer.commands.borrow().len();
    assert!(matches!(
        session.send_command(&peer, &Command::get_storage_info()),
        Err(Error::Generic(rv)) if rv == CKR_SESSION_CLOSED as _
    ));
    assert_eq!(peer.commands.borrow().len(), command_count);
}

#[test]
fn every_authenticated_command_crosses_the_secure_transport() {
    let peer = ProtocolPeer::new();
    let mut session =
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
    for code in commands::ALL_COMMAND_CODES.iter().copied().filter(|code| {
        !code.is_bare()
            && !code.is_session_protocol()
            && !matches!(
                code,
                CommandCode::CloseSession
                    | CommandCode::GetStorageInfo
                    | CommandCode::GetPseudoRandom
                    | CommandCode::ListObjects
                    | CommandCode::GetObjectInfo
                    | CommandCode::GetPublicKey
                    | CommandCode::GenerateAsymmetricKey
                    | CommandCode::GenerateWrapKey
                    | CommandCode::PutAsymmetricKey
                    | CommandCode::DeleteObject
                    | CommandCode::ExportWrapped
                    | CommandCode::ImportWrapped
                    | CommandCode::GetRsaWrappedKey
                    | CommandCode::PutRsaWrappedKey
                    | CommandCode::ExportRsaWrapped
                    | CommandCode::ImportRsaWrapped
                    | CommandCode::SignPkcs1
                    | CommandCode::DecryptPkcs1
                    | CommandCode::DecryptEcb
                    | CommandCode::EncryptEcb
                    | CommandCode::DecryptCbc
                    | CommandCode::EncryptCbc
            )
    }) {
        let data = [code as u8, 0xa5];
        let command = Command::raw(code, &data).unwrap();
        let response = session.send_command(&peer, &command).unwrap();
        if code == CommandCode::DeriveEcdh {
            assert_eq!(response, vec![0x42; 32]);
        } else {
            assert_eq!(response, data);
        }
    }
}

#[test]
fn device_command_errors_advance_the_session_counter() {
    let peer = ProtocolPeer::new();
    let mut session =
        SecureSession::authenticate_with_challenge(&peer, 1, PASSWORD, HOST_CHALLENGE).unwrap();
    let failing = Command::raw(CommandCode::ResetDevice, &[0xde]).unwrap();
    assert!(matches!(
        session.send_command(&peer, &failing),
        Err(Error::Generic(rv)) if rv == CKR_OBJECT_HANDLE_INVALID as _
    ));
    assert!(session.is_valid());
    let next = Command::raw(CommandCode::BlinkDevice, &[1]).unwrap();
    assert_eq!(session.send_command(&peer, &next).unwrap(), [1]);
}
