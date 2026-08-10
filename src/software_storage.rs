use crate::{
    CKR_DATA_INVALID, CKR_DEVICE_ERROR, CKR_ENCRYPTED_DATA_INVALID, CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE, EcCurve, Error, GcmParameters, KeyMaterial, SoftwarePrivateKeyMaterial,
    TokenObject, ec_curve_from_parameters, ec_curve_parameters, secure_channel_crypto,
};
use der::{
    Decode, Encode, SecretDocument, Sequence, Tag, ValueOrd,
    asn1::{Any, AnyRef, BmpString, OctetString, OctetStringRef, SetOfVec},
    referenced::RefToOwned,
};
use minicbor::{Decoder, Encoder};
use pkcs8::{
    EncryptedPrivateKeyInfoOwned, PrivateKeyInfoRef,
    pkcs5::pbes2,
    spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef, ObjectIdentifier},
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
#[cfg(unix)]
use std::fs::File;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

use crate::key_metadata::cryptoki_ulong_to_u64;
use crate::storage::{ContentReference, LocalStorageProvider, StorageError, StorageProvider};

const HEADER_PREFIX: &str = "header-";
const HEADER_SUFFIX: &str = ".cbor";
const TEMPORARY_PREFIX: &str = ".pkcs11rs-header-";
const PRIVATE_DIRECTORY: &str = "private-keys-v1";
const PUBLIC_DIRECTORY: &str = "public-objects-v1";
const PUBLIC_RECORD_SCHEMA: &str = "pkcs11rs-software-public-object";
const HEADER_SCHEMA: &str = "pkcs11rs-software-token-key";
const RECORD_SCHEMA: &str = "pkcs11rs-software-private-key";
const SECRET_RECORD_SCHEMA: &str = "pkcs11rs-software-secret-key";
const FORMAT_VERSION: u64 = 4;
const HEADER_FORMAT_VERSION: u64 = 3;
const KDF_NAME: &str = "pbkdf2-hmac-sha256";
const KDF_ITERATIONS: u32 = 10_000;
const AEAD_NAME: &str = "aes-256-gcm";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const MASTER_KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 16;
const MAX_RECORD_LENGTH: usize = 1024 * 1024;
const MIN_PIN_LENGTH: usize = 8;
const MAX_PIN_LENGTH: usize = 1024;
const EXPORT_SCRYPT_LOG_N: u8 = 14;
const EXPORT_SCRYPT_R: u32 = 8;
const EXPORT_SCRYPT_P: u32 = 1;
const EXPORT_SALT_LENGTH: usize = 16;
const EXPORT_IV_LENGTH: usize = 16;
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
const FRIENDLY_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
const LOCAL_KEY_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
// UUIDv5(URL namespace,
// "https://github.com/qpernil/pkcs11rs/software-private-key-attributes/v1").
const PKCS11RS_ATTRIBUTES_OID_VALUE: &[u8] = &[
    0x69, 0x81, 0xd7, 0xeb, 0xbb, 0xeb, 0xd5, 0xb5, 0xa2, 0xe6, 0xa7, 0xaf, 0xb0, 0x97, 0x9c, 0xde,
    0xeb, 0xa0, 0xc0, 0x3f,
];

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

type UnwrappedMasterKey = Zeroizing<[u8; MASTER_KEY_LENGTH]>;

fn stored_u64_to_cryptoki_ulong(value: u64) -> Result<crate::CK_ULONG, Error> {
    #[cfg(any(windows, target_pointer_width = "32"))]
    {
        value.try_into().map_err(|_| Error::from(CKR_DATA_INVALID))
    }
    #[cfg(all(not(windows), target_pointer_width = "64"))]
    {
        Ok(value)
    }
}

#[derive(Debug)]
pub(crate) struct SoftwarePublicStorageProvider {
    store: SoftwareTokenStore,
    records: LocalStorageProvider,
    active_key: Rc<RefCell<Option<Zeroizing<[u8; MASTER_KEY_LENGTH]>>>>,
}

impl SoftwarePublicStorageProvider {
    pub(crate) fn open(
        name: String,
        token_root: PathBuf,
        discovery_pin: Option<Vec<u8>>,
        active_key: Rc<RefCell<Option<Zeroizing<[u8; MASTER_KEY_LENGTH]>>>>,
    ) -> Result<Self, Error> {
        let records = LocalStorageProvider::open(token_root.join(PUBLIC_DIRECTORY))
            .map_err(crate::backed_object::storage_error)?;
        Ok(Self {
            store: SoftwareTokenStore::open(name, token_root, discovery_pin)?,
            records,
            active_key,
        })
    }

    fn public_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, StorageError> {
        if let Some(key) = self
            .active_key
            .try_borrow()
            .map_err(|_| StorageError::Provider(String::from("software public key is borrowed")))?
            .as_ref()
        {
            return Ok(Zeroizing::new(**key));
        }
        let discovery_pin = self
            .store
            .discovery_pin
            .as_ref()
            .ok_or(StorageError::Unavailable)?;
        let (_, encoded) = self
            .store
            .read_current_header()
            .map_err(public_storage_error)?
            .ok_or(StorageError::Unavailable)?;
        let header = decode_header(&encoded).map_err(public_storage_error)?;
        self.store
            .unwrap_master_key(
                discovery_pin.as_ref(),
                PinRole::DiscoveryPublic,
                &header.discovery_public,
            )
            .map_err(public_storage_error)
    }

    fn has_login_key(&self) -> Result<bool, StorageError> {
        Ok(self
            .active_key
            .try_borrow()
            .map_err(|_| StorageError::Provider(String::from("software public key is borrowed")))?
            .is_some())
    }

    pub(crate) fn clear(&self) -> Result<(), Error> {
        for reference in self
            .records
            .list()
            .map_err(crate::backed_object::storage_error)?
        {
            self.records
                .delete(&reference)
                .map_err(crate::backed_object::storage_error)?;
        }
        Ok(())
    }

    fn logical_objects(
        &self,
    ) -> Result<Vec<(ContentReference, ContentReference, Vec<u8>)>, StorageError> {
        let key = self.public_key()?;
        let mut objects = Vec::new();
        for physical in self.records.list()? {
            let encoded = self
                .records
                .get(&physical)?
                .ok_or(StorageError::Integrity)?;
            let logical = decode_public_record(&self.store.name, &key, &encoded)
                .map_err(public_storage_error)?;
            objects.push((ContentReference::for_object(&logical), physical, logical));
        }
        Ok(objects)
    }
}

fn public_storage_error(error: Error) -> StorageError {
    StorageError::Provider(format!("software public storage: {error:?}"))
}

impl StorageProvider for SoftwarePublicStorageProvider {
    fn supports_mutation(&self) -> bool {
        self.public_key().is_ok()
    }

    fn list(&self) -> Result<Vec<ContentReference>, StorageError> {
        if !self.store.is_initialized().map_err(public_storage_error)? {
            return Ok(Vec::new());
        }
        if let Err(error) = self.public_key() {
            if !self.has_login_key()? {
                return Ok(Vec::new());
            }
            return Err(error);
        }
        let mut references = self
            .logical_objects()?
            .into_iter()
            .map(|(logical, _, _)| logical)
            .collect::<Vec<_>>();
        references.sort();
        references.dedup();
        Ok(references)
    }

    fn get(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError> {
        if let Err(error) = self.public_key() {
            if !self.has_login_key()? {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(self
            .logical_objects()?
            .into_iter()
            .find_map(|(logical, _, object)| (&logical == reference).then_some(object)))
    }

    fn put(&self, object: &[u8]) -> Result<ContentReference, StorageError> {
        let logical = ContentReference::for_object(object);
        if self.get(&logical)?.is_some() {
            return Ok(logical);
        }
        let key = self.public_key()?;
        let encoded =
            encode_public_record(&self.store.name, &key, object).map_err(public_storage_error)?;
        self.records.put(&encoded)?;
        Ok(logical)
    }

    fn delete(&self, reference: &ContentReference) -> Result<bool, StorageError> {
        self.public_key()?;
        let physical = self
            .logical_objects()?
            .into_iter()
            .filter_map(|(logical, physical, _)| (&logical == reference).then_some(physical))
            .collect::<Vec<_>>();
        let found = !physical.is_empty();
        for reference in physical {
            self.records.delete(&reference)?;
        }
        Ok(found)
    }
}

#[derive(Debug)]
struct Header {
    generation: u64,
    label: [u8; 32],
    discovery_public: WrappedMasterKey,
    so_public: WrappedMasterKey,
    user: Option<UserWrappedMasterKeys>,
}

#[derive(Debug)]
struct UserWrappedMasterKeys {
    public: WrappedMasterKey,
    private: WrappedMasterKey,
}

#[derive(Clone, Debug)]
struct WrappedMasterKey {
    generation: u64,
    salt: [u8; SALT_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    wrapped_master_key: Vec<u8>,
}

#[derive(Clone, Copy)]
enum PinRole {
    UserPublic,
    UserPrivate,
    SoPublic,
    DiscoveryPublic,
}

impl PinRole {
    fn aad_label(self) -> &'static [u8] {
        match self {
            Self::UserPublic => b"user-public",
            Self::UserPrivate => b"user-private",
            Self::SoPublic => b"so-public",
            Self::DiscoveryPublic => b"discovery-public",
        }
    }
}

/// PKCS #8 v1 `PrivateKeyInfo`, also known as an RFC 5958
/// `OneAsymmetricKey` with version 0. The attribute field is part of the
/// standard syntax; pkcs11rs always emits it for persistent private keys.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct StoredPrivateKeyInfo {
    version: u8,
    private_key_algorithm: AlgorithmIdentifierOwned,
    private_key: OctetString,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        extensible = "true",
        optional = "true"
    )]
    attributes: Option<StoredPkcs8Attributes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
struct StoredPkcs8Attribute {
    oid: Any,
    values: SetOfVec<Any>,
}

type StoredPkcs8Attributes = SetOfVec<StoredPkcs8Attribute>;

#[derive(Debug, Eq, PartialEq)]
struct StoredAttributes {
    class: u64,
    key_type: u64,
    label: String,
    id: Vec<u8>,
    private: bool,
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    derive: bool,
    sensitive: bool,
    extractable: bool,
    always_sensitive: bool,
    never_extractable: bool,
    local: bool,
    key_gen_mechanism: Option<u64>,
    allowed_mechanisms: Option<Vec<u64>>,
    wrap_with_trusted: bool,
    wrap_template: Option<Vec<u8>>,
    unwrap_template: Option<Vec<u8>>,
    derive_template: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct SoftwareTokenStore {
    name: String,
    root: PathBuf,
    records: LocalStorageProvider,
    discovery_pin: Option<Zeroizing<Vec<u8>>>,
}

impl SoftwareTokenStore {
    pub(crate) fn open(
        name: String,
        token_root: PathBuf,
        discovery_pin: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        if let Some(pin) = &discovery_pin {
            validate_software_pin(pin)?;
        }
        let root = token_root.join(PRIVATE_DIRECTORY);
        create_private_directory(&root)?;
        let records = LocalStorageProvider::open(root.join("records"))
            .map_err(crate::backed_object::storage_error)?;
        set_private_directory_permissions(records.root())?;
        set_private_directory_permissions(&records.root().join("objects"))?;
        set_private_file_permissions(&root)?;
        set_private_file_permissions(&records.root().join("objects"))?;
        Ok(Self {
            name,
            root,
            records,
            discovery_pin: discovery_pin.map(Zeroizing::new),
        })
    }

    pub(crate) fn is_initialized(&self) -> Result<bool, Error> {
        Ok(self.current_header_path()?.is_some())
    }

    pub(crate) fn user_pin_is_initialized(&self) -> Result<bool, Error> {
        let Some((_, encoded)) = self.read_current_header()? else {
            return Ok(false);
        };
        Ok(decode_header(&encoded)?.user.is_some())
    }

    pub(crate) fn label(&self) -> Result<Option<[u8; 32]>, Error> {
        self.read_current_header()?
            .map(|(_, encoded)| decode_header(&encoded).map(|header| header.label))
            .transpose()
    }

    pub(crate) fn login(
        &self,
        pin: &[u8],
    ) -> Result<(UnwrappedMasterKey, UnwrappedMasterKey), Error> {
        validate_software_pin(pin)?;
        let Some((_, encoded)) = self.read_current_header()? else {
            return Err(crate::CKR_TOKEN_NOT_INITIALIZED.into());
        };
        let header = decode_header(&encoded)?;
        let user = header
            .user
            .as_ref()
            .ok_or(crate::CKR_USER_PIN_NOT_INITIALIZED)?;
        let public = self.unwrap_master_key(pin, PinRole::UserPublic, &user.public)?;
        let private = self.unwrap_master_key(pin, PinRole::UserPrivate, &user.private)?;
        Ok((public, private))
    }

    pub(crate) fn login_so(&self, pin: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, Error> {
        validate_software_pin(pin)?;
        let Some((_, encoded)) = self.read_current_header()? else {
            return Err(crate::CKR_TOKEN_NOT_INITIALIZED.into());
        };
        let header = decode_header(&encoded)?;
        let public = self.unwrap_master_key(pin, PinRole::SoPublic, &header.so_public)?;
        Ok(public)
    }

    fn unwrap_master_key(
        &self,
        pin: &[u8],
        role: PinRole,
        wrapped: &WrappedMasterKey,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, Error> {
        let wrapping_key = derive_wrapping_key(pin, &wrapped.salt);
        let aad = header_aad(&self.name, role, wrapped.generation);
        let plaintext = match decrypt(
            wrapping_key.as_ref(),
            &wrapped.nonce,
            &aad,
            &wrapped.wrapped_master_key,
        ) {
            Ok(plaintext) => plaintext,
            Err(Error::Generic(rv)) if rv == CKR_ENCRYPTED_DATA_INVALID as crate::CK_RV => {
                return Err(CKR_PIN_INCORRECT.into());
            }
            Err(error) => return Err(error),
        };
        let master_key: [u8; MASTER_KEY_LENGTH] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
        Ok(Zeroizing::new(master_key))
    }

    pub(crate) fn init_token(
        &self,
        so_pin: &[u8],
        label: [u8; 32],
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, Error> {
        validate_software_pin(so_pin)?;
        let generation = match self.read_current_header()? {
            Some((generation, encoded)) => {
                let header = decode_header(&encoded)?;
                let _existing =
                    self.unwrap_master_key(so_pin, PinRole::SoPublic, &header.so_public)?;
                generation.checked_add(1).ok_or(CKR_DEVICE_ERROR)?
            }
            None => 1,
        };
        for reference in self
            .records
            .list()
            .map_err(crate::backed_object::storage_error)?
        {
            self.records
                .delete(&reference)
                .map_err(crate::backed_object::storage_error)?;
        }
        let mut public_master_key = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);
        getrandom::fill(public_master_key.as_mut()).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let discovery_pin = match &self.discovery_pin {
            Some(pin) => Zeroizing::new(pin.as_slice().to_vec()),
            None => {
                let mut pin = Zeroizing::new(vec![0u8; MASTER_KEY_LENGTH]);
                getrandom::fill(pin.as_mut_slice()).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
                pin
            }
        };
        let header = Header {
            generation,
            label,
            discovery_public: wrap_master_key(
                &self.name,
                PinRole::DiscoveryPublic,
                generation,
                discovery_pin.as_ref(),
                public_master_key.as_ref(),
            )?,
            so_public: wrap_master_key(
                &self.name,
                PinRole::SoPublic,
                generation,
                so_pin,
                public_master_key.as_ref(),
            )?,
            user: None,
        };
        let encoded = encode_header(&header)?;
        self.publish_header(generation, &encoded)?;
        self.remove_old_headers(generation)?;
        Ok(public_master_key)
    }

    pub(crate) fn change_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        validate_software_pin(new_pin)?;
        let (public, private) = self.login(old_pin)?;
        let (_, encoded) = self.read_current_header()?.ok_or(CKR_DEVICE_ERROR)?;
        let mut header = decode_header(&encoded)?;
        let generation = header.generation.checked_add(1).ok_or(CKR_DEVICE_ERROR)?;
        header.generation = generation;
        header.user = Some(UserWrappedMasterKeys {
            public: wrap_master_key(
                &self.name,
                PinRole::UserPublic,
                generation,
                new_pin,
                public.as_ref(),
            )?,
            private: wrap_master_key(
                &self.name,
                PinRole::UserPrivate,
                generation,
                new_pin,
                private.as_ref(),
            )?,
        });
        self.publish_replacement_header(&header)
    }

    pub(crate) fn change_so_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Error> {
        validate_software_pin(new_pin)?;
        let public = self.login_so(old_pin)?;
        let (_, encoded) = self.read_current_header()?.ok_or(CKR_DEVICE_ERROR)?;
        let mut header = decode_header(&encoded)?;
        let generation = header.generation.checked_add(1).ok_or(CKR_DEVICE_ERROR)?;
        header.generation = generation;
        header.so_public = wrap_master_key(
            &self.name,
            PinRole::SoPublic,
            generation,
            new_pin,
            public.as_ref(),
        )?;
        self.publish_replacement_header(&header)
    }

    pub(crate) fn init_user_pin(
        &self,
        new_pin: &[u8],
        public_master_key: &[u8; MASTER_KEY_LENGTH],
    ) -> Result<(), Error> {
        validate_software_pin(new_pin)?;
        let (_, encoded) = self.read_current_header()?.ok_or(CKR_DEVICE_ERROR)?;
        let mut header = decode_header(&encoded)?;
        if header.user.is_some() {
            // The SO has no private-key wrapper and therefore cannot replace
            // a lost user credential without weakening role separation.
            return Err(crate::CKR_FUNCTION_FAILED.into());
        }
        let generation = header.generation.checked_add(1).ok_or(CKR_DEVICE_ERROR)?;
        let mut private_master_key = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);
        getrandom::fill(private_master_key.as_mut()).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        header.generation = generation;
        header.user = Some(UserWrappedMasterKeys {
            public: wrap_master_key(
                &self.name,
                PinRole::UserPublic,
                generation,
                new_pin,
                public_master_key,
            )?,
            private: wrap_master_key(
                &self.name,
                PinRole::UserPrivate,
                generation,
                new_pin,
                private_master_key.as_ref(),
            )?,
        });
        self.publish_replacement_header(&header)
    }

    fn publish_replacement_header(&self, header: &Header) -> Result<(), Error> {
        let encoded = encode_header(header)?;
        self.publish_header(header.generation, &encoded)?;
        self.remove_old_headers(header.generation)
    }

    pub(crate) fn load_objects(
        &self,
        slot_id: crate::CK_SLOT_ID,
        master_key: &[u8; MASTER_KEY_LENGTH],
    ) -> Result<(Vec<TokenObject>, HashMap<String, ContentReference>), Error> {
        let mut objects = Vec::new();
        let mut references = HashMap::new();
        for reference in self
            .records
            .list()
            .map_err(crate::backed_object::storage_error)?
        {
            let encoded = self
                .records
                .get(&reference)
                .map_err(crate::backed_object::storage_error)?
                .ok_or(CKR_DEVICE_ERROR)?;
            if encoded.len() > MAX_RECORD_LENGTH {
                return Err(CKR_DATA_INVALID.into());
            }
            let unique_id = record_unique_id(&reference);
            let object = decode_record(&self.name, slot_id, &unique_id, master_key, &encoded)?;
            references.insert(unique_id, reference);
            objects.push(object);
        }
        objects.sort_by(|left, right| left.unique_id.cmp(&right.unique_id));
        Ok((objects, references))
    }

    pub(crate) fn put_object(
        &self,
        slot_id: crate::CK_SLOT_ID,
        master_key: &[u8; MASTER_KEY_LENGTH],
        object: &TokenObject,
    ) -> Result<(TokenObject, ContentReference), Error> {
        let encoded = encode_record(&self.name, master_key, object)?;
        let reference = self
            .records
            .put(&encoded)
            .map_err(crate::backed_object::storage_error)?;
        let unique_id = record_unique_id(&reference);
        let stored = decode_record(&self.name, slot_id, &unique_id, master_key, &encoded)?;
        Ok((stored, reference))
    }

    pub(crate) fn delete_object(&self, reference: &ContentReference) -> Result<(), Error> {
        if !self
            .records
            .delete(reference)
            .map_err(crate::backed_object::storage_error)?
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(())
    }

    fn current_header_path(&self) -> Result<Option<(u64, PathBuf)>, Error> {
        let mut current: Option<(u64, PathBuf)> = None;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let Some(filename) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(CKR_DATA_INVALID.into());
            };
            if filename.starts_with(TEMPORARY_PREFIX) {
                continue;
            }
            let Some(generation) = header_generation(&filename) else {
                if filename.starts_with(HEADER_PREFIX) || filename.ends_with(HEADER_SUFFIX) {
                    return Err(CKR_DATA_INVALID.into());
                }
                continue;
            };
            if current
                .as_ref()
                .is_none_or(|(candidate, _)| generation > *candidate)
            {
                current = Some((generation, entry.path()));
            }
        }
        Ok(current)
    }

    fn read_current_header(&self) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let Some((generation, path)) = self.current_header_path()? else {
            return Ok(None);
        };
        let encoded = fs::read(path)?;
        if encoded.len() > MAX_RECORD_LENGTH {
            return Err(CKR_DATA_INVALID.into());
        }
        let header = decode_header(&encoded)?;
        if header.generation != generation {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(Some((generation, encoded)))
    }

    fn publish_header(&self, generation: u64, encoded: &[u8]) -> Result<(), Error> {
        let destination = self.root.join(header_filename(generation));
        let temporary = self.root.join(format!(
            "{TEMPORARY_PREFIX}{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<(), Error> {
            file.write_all(encoded)?;
            file.sync_all()?;
            drop(file);
            fs::hard_link(&temporary, &destination)?;
            fs::remove_file(&temporary)?;
            sync_directory(&self.root)?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove_old_headers(&self, current: u64) -> Result<(), Error> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let Some(filename) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if header_generation(&filename).is_some_and(|generation| generation < current) {
                fs::remove_file(entry.path())?;
            }
        }
        sync_directory(&self.root)
    }
}

pub(crate) fn validate_software_pin(pin: &[u8]) -> Result<(), Error> {
    if (MIN_PIN_LENGTH..=MAX_PIN_LENGTH).contains(&pin.len()) {
        Ok(())
    } else {
        Err(CKR_PIN_LEN_RANGE.into())
    }
}

fn header_filename(generation: u64) -> String {
    format!("{HEADER_PREFIX}{generation:020}{HEADER_SUFFIX}")
}

fn header_generation(filename: &str) -> Option<u64> {
    filename
        .strip_prefix(HEADER_PREFIX)?
        .strip_suffix(HEADER_SUFFIX)?
        .parse()
        .ok()
}

fn create_private_directory(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path)?;
    set_private_directory_permissions(path)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Error> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), Error> {
    Ok(())
}

fn derive_wrapping_key(pin: &[u8], salt: &[u8; SALT_LENGTH]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pin, salt, KDF_ITERATIONS, key.as_mut());
    key
}

fn encrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    crypt(key, nonce, aad, plaintext, true)
}

fn decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    crypt(key, nonce, aad, ciphertext, false).map(Zeroizing::new)
}

fn crypt(
    key: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Error> {
    let parameters = GcmParameters {
        iv: nonce.to_vec(),
        aad: aad.to_vec(),
        tag_bits: TAG_LENGTH * 8,
    };
    crate::api::aes_gcm(&parameters, input, encrypting, |blocks| {
        secure_channel_crypto::aes_ecb(key, blocks, secure_channel_crypto::Direction::Encrypt)
    })
}

fn header_aad(name: &str, role: PinRole, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_SCHEMA.len() + name.len() + 20);
    aad.extend_from_slice(HEADER_SCHEMA.as_bytes());
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(role.aad_label());
    aad.push(0);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn record_aad(name: &str, schema: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(schema.len() + name.len() + 9);
    aad.extend_from_slice(schema.as_bytes());
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    if schema == SECRET_RECORD_SCHEMA {
        aad.push(0);
        aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    }
    aad
}

fn wrap_master_key(
    name: &str,
    role: PinRole,
    generation: u64,
    pin: &[u8],
    master_key: &[u8],
) -> Result<WrappedMasterKey, Error> {
    validate_software_pin(pin)?;
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut salt).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let wrapping_key = derive_wrapping_key(pin, &salt);
    let wrapped = encrypt(
        wrapping_key.as_ref(),
        &nonce,
        &header_aad(name, role, generation),
        master_key,
    )?;
    Ok(WrappedMasterKey {
        generation,
        salt,
        nonce,
        wrapped_master_key: wrapped,
    })
}

fn decode_header(encoded: &[u8]) -> Result<Header, Error> {
    let mut decoder = Decoder::new(encoded);
    let field_count = decoder.array().map_err(|_| CKR_DATA_INVALID)?;
    if !matches!(field_count, Some(16 | 24))
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != HEADER_SCHEMA
        || decoder.u64().map_err(|_| CKR_DATA_INVALID)? != HEADER_FORMAT_VERSION
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let generation = decoder.u64().map_err(|_| CKR_DATA_INVALID)?;
    if generation == 0
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != KDF_NAME
        || decoder.u32().map_err(|_| CKR_DATA_INVALID)? != KDF_ITERATIONS
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != AEAD_NAME
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let label = decoder
        .bytes()
        .map_err(|_| CKR_DATA_INVALID)?
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let discovery_public = decode_wrapped_master_key(&mut decoder, generation)?;
    let so_public = decode_wrapped_master_key(&mut decoder, generation)?;
    let user = match decoder.bool().map_err(|_| CKR_DATA_INVALID)? {
        false => None,
        true => Some(UserWrappedMasterKeys {
            public: decode_wrapped_master_key(&mut decoder, generation)?,
            private: decode_wrapped_master_key(&mut decoder, generation)?,
        }),
    };
    if field_count != Some(if user.is_some() { 24 } else { 16 })
        || discovery_public.wrapped_master_key.len() != MASTER_KEY_LENGTH + TAG_LENGTH
        || so_public.wrapped_master_key.len() != MASTER_KEY_LENGTH + TAG_LENGTH
        || user.as_ref().is_some_and(|user| {
            user.public.wrapped_master_key.len() != MASTER_KEY_LENGTH + TAG_LENGTH
                || user.private.wrapped_master_key.len() != MASTER_KEY_LENGTH + TAG_LENGTH
        })
        || decoder.position() != encoded.len()
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let header = Header {
        generation,
        label,
        discovery_public,
        so_public,
        user,
    };
    if encode_header(&header)? != encoded {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(header)
}

fn decode_wrapped_master_key(
    decoder: &mut Decoder<'_>,
    header_generation: u64,
) -> Result<WrappedMasterKey, Error> {
    let generation = decoder.u64().map_err(|_| CKR_DATA_INVALID)?;
    if generation == 0 || generation > header_generation {
        return Err(CKR_DATA_INVALID.into());
    }
    let salt = decoder
        .bytes()
        .map_err(|_| CKR_DATA_INVALID)?
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let nonce = decoder
        .bytes()
        .map_err(|_| CKR_DATA_INVALID)?
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let wrapped_master_key = decoder.bytes().map_err(|_| CKR_DATA_INVALID)?.to_vec();
    Ok(WrappedMasterKey {
        generation,
        salt,
        nonce,
        wrapped_master_key,
    })
}

fn encode_header(header: &Header) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    let field_count = if header.user.is_some() { 24 } else { 16 };
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .array(field_count)
        .and_then(|encoder| encoder.str(HEADER_SCHEMA))
        .and_then(|encoder| encoder.u64(HEADER_FORMAT_VERSION))
        .and_then(|encoder| encoder.u64(header.generation))
        .and_then(|encoder| encoder.str(KDF_NAME))
        .and_then(|encoder| encoder.u32(KDF_ITERATIONS))
        .and_then(|encoder| encoder.str(AEAD_NAME))
        .and_then(|encoder| encoder.bytes(&header.label))
        .and_then(|encoder| encoder.u64(header.discovery_public.generation))
        .and_then(|encoder| encoder.bytes(&header.discovery_public.salt))
        .and_then(|encoder| encoder.bytes(&header.discovery_public.nonce))
        .and_then(|encoder| encoder.bytes(&header.discovery_public.wrapped_master_key))
        .and_then(|encoder| encoder.u64(header.so_public.generation))
        .and_then(|encoder| encoder.bytes(&header.so_public.salt))
        .and_then(|encoder| encoder.bytes(&header.so_public.nonce))
        .and_then(|encoder| encoder.bytes(&header.so_public.wrapped_master_key))
        .and_then(|encoder| encoder.bool(header.user.is_some()))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    if let Some(user) = &header.user {
        encoder
            .u64(user.public.generation)
            .and_then(|encoder| encoder.bytes(&user.public.salt))
            .and_then(|encoder| encoder.bytes(&user.public.nonce))
            .and_then(|encoder| encoder.bytes(&user.public.wrapped_master_key))
            .and_then(|encoder| encoder.u64(user.private.generation))
            .and_then(|encoder| encoder.bytes(&user.private.salt))
            .and_then(|encoder| encoder.bytes(&user.private.nonce))
            .and_then(|encoder| encoder.bytes(&user.private.wrapped_master_key))
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    Ok(encoded)
}

fn encode_record(
    name: &str,
    master_key: &[u8; MASTER_KEY_LENGTH],
    object: &TokenObject,
) -> Result<Vec<u8>, Error> {
    if !object.token {
        return Err(CKR_DATA_INVALID.into());
    }
    let (schema, plaintext) = match &object.material {
        KeyMaterial::SoftwarePrivate(_) => (RECORD_SCHEMA, encode_stored_private_key_info(object)?),
        KeyMaterial::SoftwareSecret(_) if object.private => {
            (SECRET_RECORD_SCHEMA, encode_stored_secret_key_info(object)?)
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    };
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let ciphertext = encrypt(
        master_key,
        &nonce,
        &record_aad(name, schema),
        plaintext.as_ref(),
    )?;
    encode_record_envelope(schema, &nonce, &ciphertext)
}

fn decode_record(
    name: &str,
    slot_id: crate::CK_SLOT_ID,
    unique_id: &str,
    master_key: &[u8; MASTER_KEY_LENGTH],
    encoded: &[u8],
) -> Result<TokenObject, Error> {
    let mut outer = Decoder::new(encoded);
    if outer.array().map_err(|_| CKR_DATA_INVALID)? != Some(4) {
        return Err(CKR_DATA_INVALID.into());
    }
    let schema = outer.str().map_err(|_| CKR_DATA_INVALID)?;
    if !matches!(schema, RECORD_SCHEMA | SECRET_RECORD_SCHEMA)
        || outer.u64().map_err(|_| CKR_DATA_INVALID)? != FORMAT_VERSION
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let nonce: [u8; NONCE_LENGTH] = outer
        .bytes()
        .map_err(|_| CKR_DATA_INVALID)?
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let ciphertext = outer.bytes().map_err(|_| CKR_DATA_INVALID)?;
    if ciphertext.len() < TAG_LENGTH || outer.position() != encoded.len() {
        return Err(CKR_DATA_INVALID.into());
    }
    if encode_record_envelope(schema, &nonce, ciphertext)? != encoded {
        return Err(CKR_DATA_INVALID.into());
    }
    let plaintext = decrypt(master_key, &nonce, &record_aad(name, schema), ciphertext)
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    if schema == SECRET_RECORD_SCHEMA {
        if !stored_secret_key_info(plaintext.as_ref()) {
            return Err(CKR_DATA_INVALID.into());
        }
        return decode_stored_secret_key_info(slot_id, unique_id, plaintext.as_ref());
    }
    if stored_secret_key_info(plaintext.as_ref()) {
        return Err(CKR_DATA_INVALID.into());
    }
    let (attributes, material) = decode_stored_private_key_info(plaintext.as_ref())?;
    let class: crate::CK_OBJECT_CLASS = stored_u64_to_cryptoki_ulong(attributes.class)?;
    let key_type: crate::CK_KEY_TYPE = stored_u64_to_cryptoki_ulong(attributes.key_type)?;
    let key_gen_mechanism: Option<crate::CK_MECHANISM_TYPE> = attributes
        .key_gen_mechanism
        .map(stored_u64_to_cryptoki_ulong)
        .transpose()?;
    let allowed_mechanisms = attributes
        .allowed_mechanisms
        .map(|mechanisms| {
            mechanisms
                .into_iter()
                .map(stored_u64_to_cryptoki_ulong)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let policy_templates = crate::KeyPolicyTemplates {
        wrap: decode_policy_template(attributes.wrap_template)?,
        unwrap: decode_policy_template(attributes.unwrap_template)?,
        derive: decode_policy_template(attributes.derive_template)?,
    };
    if class != crate::CKO_PRIVATE_KEY as crate::CK_OBJECT_CLASS || key_type != material.key_type()
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let public_key = material.public_key()?;
    Ok(TokenObject {
        slot_id: Some(slot_id),
        unique_id: unique_id.to_owned(),
        class,
        key_type,
        label: attributes.label,
        id: attributes.id,
        token: true,
        private: attributes.private,
        encrypt: attributes.encrypt,
        decrypt: attributes.decrypt,
        sign: attributes.sign,
        verify: attributes.verify,
        derive: attributes.derive,
        wrap: false,
        unwrap: false,
        sensitive: attributes.sensitive,
        extractable: attributes.extractable,
        always_sensitive: attributes.always_sensitive,
        never_extractable: attributes.never_extractable,
        local: attributes.local,
        key_gen_mechanism,
        allowed_mechanisms,
        wrap_with_trusted: attributes.wrap_with_trusted,
        policy_templates,
        creator_session: None,
        public_key: Some(public_key),
        rp_id: None,
        material: KeyMaterial::SoftwarePrivate(material),
    })
}

fn stored_secret_key_info(encoded: &[u8]) -> bool {
    let mut decoder = Decoder::new(encoded);
    decoder.array().ok().flatten() == Some(25) && decoder.str().ok() == Some(SECRET_RECORD_SCHEMA)
}

fn encode_stored_secret_key_info(object: &TokenObject) -> Result<Zeroizing<Vec<u8>>, Error> {
    let KeyMaterial::SoftwareSecret(value) = &object.material else {
        return Err(CKR_DATA_INVALID.into());
    };
    if object.class != crate::CKO_SECRET_KEY as crate::CK_OBJECT_CLASS || !object.private {
        return Err(CKR_DATA_INVALID.into());
    }
    validate_stored_secret_key(object.key_type, value.len())?;
    let mut encoded = Zeroizing::new(Vec::new());
    let mut encoder = Encoder::new(&mut *encoded);
    let encoder = encoder
        .array(25)
        .and_then(|encoder| encoder.str(SECRET_RECORD_SCHEMA))
        .and_then(|encoder| encoder.u64(FORMAT_VERSION))
        .and_then(|encoder| encoder.u64(cryptoki_ulong_to_u64(object.key_type)))
        .and_then(|encoder| encoder.str(&object.label))
        .and_then(|encoder| encoder.bytes(&object.id))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    for flag in [
        object.private,
        object.encrypt,
        object.decrypt,
        object.sign,
        object.verify,
        object.derive,
        object.wrap,
        object.unwrap,
        object.sensitive,
        object.extractable,
        object.always_sensitive,
        object.never_extractable,
        object.local,
    ] {
        encoder.bool(flag).map_err(|_| CKR_DEVICE_ERROR)?;
    }
    match object.key_gen_mechanism {
        Some(mechanism) => encoder
            .u64(cryptoki_ulong_to_u64(mechanism))
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
        None => encoder.null().map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
    };
    let allowed_mechanisms = stored_allowed_mechanisms(object.allowed_mechanisms.as_deref());
    encode_allowed_mechanisms(encoder, allowed_mechanisms.as_deref())?;
    encoder
        .bool(object.wrap_with_trusted)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let wrap_template = encode_policy_template(object.policy_templates.wrap.as_ref())?;
    let unwrap_template = encode_policy_template(object.policy_templates.unwrap.as_ref())?;
    let derive_template = encode_policy_template(object.policy_templates.derive.as_ref())?;
    encode_optional_bytes(encoder, wrap_template.as_deref())?;
    encode_optional_bytes(encoder, unwrap_template.as_deref())?;
    encode_optional_bytes(encoder, derive_template.as_deref())?;
    encoder
        .bytes(value)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn decode_stored_secret_key_info(
    slot_id: crate::CK_SLOT_ID,
    unique_id: &str,
    encoded: &[u8],
) -> Result<TokenObject, Error> {
    let mut decoder = Decoder::new(encoded);
    if decoder.array().map_err(|_| CKR_DATA_INVALID)? != Some(25)
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != SECRET_RECORD_SCHEMA
        || decoder.u64().map_err(|_| CKR_DATA_INVALID)? != FORMAT_VERSION
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let key_type = stored_u64_to_cryptoki_ulong(decoder.u64().map_err(|_| CKR_DATA_INVALID)?)?;
    let label = decoder.str().map_err(|_| CKR_DATA_INVALID)?.to_owned();
    let id = decoder.bytes().map_err(|_| CKR_DATA_INVALID)?.to_vec();
    let private = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let encrypt = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let decrypt = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let sign = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let verify = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let derive = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let wrap = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let unwrap = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let sensitive = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let extractable = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let always_sensitive = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let never_extractable = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let local = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let key_gen_mechanism =
        if decoder.datatype().map_err(|_| CKR_DATA_INVALID)? == minicbor::data::Type::Null {
            decoder.null().map_err(|_| CKR_DATA_INVALID)?;
            None
        } else {
            Some(stored_u64_to_cryptoki_ulong(
                decoder.u64().map_err(|_| CKR_DATA_INVALID)?,
            )?)
        };
    let allowed_mechanisms = decode_allowed_mechanisms(&mut decoder)?
        .map(|mechanisms| {
            mechanisms
                .into_iter()
                .map(stored_u64_to_cryptoki_ulong)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let wrap_with_trusted = decoder.bool().map_err(|_| CKR_DATA_INVALID)?;
    let policy_templates = crate::KeyPolicyTemplates {
        wrap: decode_policy_template(decode_optional_bytes(&mut decoder)?)?,
        unwrap: decode_policy_template(decode_optional_bytes(&mut decoder)?)?,
        derive: decode_policy_template(decode_optional_bytes(&mut decoder)?)?,
    };
    let value = Zeroizing::new(decoder.bytes().map_err(|_| CKR_DATA_INVALID)?.to_vec());
    validate_stored_secret_key(key_type, value.len())?;
    let object = TokenObject {
        slot_id: Some(slot_id),
        unique_id: unique_id.to_owned(),
        class: crate::CKO_SECRET_KEY as crate::CK_OBJECT_CLASS,
        key_type,
        label,
        id,
        token: true,
        private,
        encrypt,
        decrypt,
        sign,
        verify,
        derive,
        wrap,
        unwrap,
        sensitive,
        extractable,
        always_sensitive,
        never_extractable,
        local,
        key_gen_mechanism,
        allowed_mechanisms,
        wrap_with_trusted,
        policy_templates,
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: KeyMaterial::SoftwareSecret(value),
    };
    if !object.private
        || decoder.position() != encoded.len()
        || encode_stored_secret_key_info(&object)?.as_slice() != encoded
    {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(object)
}

fn validate_stored_secret_key(key_type: crate::CK_KEY_TYPE, length: usize) -> Result<(), Error> {
    let valid = if key_type == crate::CKK_AES as crate::CK_KEY_TYPE {
        matches!(length, 16 | 24 | 32)
    } else if key_type == crate::CKK_GENERIC_SECRET as crate::CK_KEY_TYPE
        || crate::is_hmac_key_type(key_type)
    {
        (1..=1024).contains(&length)
    } else {
        false
    };
    if !valid {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(())
}

fn encode_record_envelope(
    schema: &str,
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .array(4)
        .and_then(|encoder| encoder.str(schema))
        .and_then(|encoder| encoder.u64(FORMAT_VERSION))
        .and_then(|encoder| encoder.bytes(nonce))
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn encode_public_record(
    name: &str,
    master_key: &[u8; MASTER_KEY_LENGTH],
    object: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut aad = PUBLIC_RECORD_SCHEMA.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    let ciphertext = encrypt(master_key, &nonce, &aad, object)?;
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .array(4)
        .and_then(|encoder| encoder.str(PUBLIC_RECORD_SCHEMA))
        .and_then(|encoder| encoder.u64(FORMAT_VERSION))
        .and_then(|encoder| encoder.bytes(&nonce))
        .and_then(|encoder| encoder.bytes(&ciphertext))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn decode_public_record(
    name: &str,
    master_key: &[u8; MASTER_KEY_LENGTH],
    encoded: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut decoder = Decoder::new(encoded);
    if decoder.array().map_err(|_| CKR_DATA_INVALID)? != Some(4)
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != PUBLIC_RECORD_SCHEMA
        || decoder.u64().map_err(|_| CKR_DATA_INVALID)? != FORMAT_VERSION
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let nonce = decoder
        .bytes()
        .map_err(|_| CKR_DATA_INVALID)?
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    let ciphertext = decoder.bytes().map_err(|_| CKR_DATA_INVALID)?;
    if decoder.position() != encoded.len() {
        return Err(CKR_DATA_INVALID.into());
    }
    let mut aad = PUBLIC_RECORD_SCHEMA.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    decrypt(master_key, &nonce, &aad, ciphertext).map(|value| value.to_vec())
}

fn stored_allowed_mechanisms<T: Copy + Into<u64>>(mechanisms: Option<&[T]>) -> Option<Vec<u64>> {
    mechanisms.map(|mechanisms| mechanisms.iter().copied().map(Into::into).collect())
}

fn validate_allowed_mechanisms(mechanisms: &[u64]) -> Result<(), Error> {
    if mechanisms.len() > 256 || mechanisms.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(())
}

fn encode_allowed_mechanisms(
    encoder: &mut Encoder<&mut Vec<u8>>,
    mechanisms: Option<&[u64]>,
) -> Result<(), Error> {
    match mechanisms {
        Some(mechanisms) => {
            validate_allowed_mechanisms(mechanisms)?;
            encoder
                .array(mechanisms.len() as u64)
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
            for mechanism in mechanisms {
                encoder
                    .u64(*mechanism)
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
            }
        }
        None => {
            encoder.null().map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        }
    }
    Ok(())
}

fn decode_allowed_mechanisms(decoder: &mut Decoder<'_>) -> Result<Option<Vec<u64>>, Error> {
    if decoder.datatype().map_err(|_| CKR_DATA_INVALID)? == minicbor::data::Type::Null {
        decoder.null().map_err(|_| CKR_DATA_INVALID)?;
        return Ok(None);
    }
    let count = decoder
        .array()
        .map_err(|_| CKR_DATA_INVALID)?
        .ok_or(CKR_DATA_INVALID)?;
    if count > 256 {
        return Err(CKR_DATA_INVALID.into());
    }
    let mut mechanisms = Vec::with_capacity(count as usize);
    for _ in 0..count {
        mechanisms.push(decoder.u64().map_err(|_| CKR_DATA_INVALID)?);
    }
    validate_allowed_mechanisms(&mechanisms)?;
    Ok(Some(mechanisms))
}

fn encode_policy_template(
    template: Option<&crate::key_metadata::KeyAttributes>,
) -> Result<Option<Vec<u8>>, Error> {
    template
        .map(|template| {
            template
                .template_to_cbor()
                .map_err(|_| Error::from(CKR_DATA_INVALID))
        })
        .transpose()
}

fn decode_policy_template(
    encoded: Option<Vec<u8>>,
) -> Result<Option<crate::key_metadata::KeyAttributes>, Error> {
    encoded
        .map(|encoded| {
            crate::key_metadata::KeyAttributes::template_from_cbor(&encoded)
                .map_err(|_| Error::from(CKR_DATA_INVALID))
        })
        .transpose()
}

fn encode_optional_bytes(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: Option<&[u8]>,
) -> Result<(), Error> {
    match value {
        Some(value) => encoder
            .bytes(value)
            .map(|_| ())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR)),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR)),
    }
}

fn decode_optional_bytes(decoder: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, Error> {
    if decoder.datatype().map_err(|_| CKR_DATA_INVALID)? == minicbor::data::Type::Null {
        decoder.null().map_err(|_| CKR_DATA_INVALID)?;
        Ok(None)
    } else {
        decoder
            .bytes()
            .map(|value| Some(value.to_vec()))
            .map_err(|_| CKR_DATA_INVALID.into())
    }
}

fn stored_attributes(object: &TokenObject) -> Result<StoredAttributes, Error> {
    Ok(StoredAttributes {
        class: cryptoki_ulong_to_u64(object.class),
        key_type: cryptoki_ulong_to_u64(object.key_type),
        label: object.label.clone(),
        id: object.id.clone(),
        private: object.private,
        encrypt: object.encrypt,
        decrypt: object.decrypt,
        sign: object.sign,
        verify: object.verify,
        derive: object.derive,
        sensitive: object.sensitive,
        extractable: object.extractable,
        always_sensitive: object.always_sensitive,
        never_extractable: object.never_extractable,
        local: object.local,
        key_gen_mechanism: object.key_gen_mechanism.map(cryptoki_ulong_to_u64),
        allowed_mechanisms: stored_allowed_mechanisms(object.allowed_mechanisms.as_deref()),
        wrap_with_trusted: object.wrap_with_trusted,
        wrap_template: encode_policy_template(object.policy_templates.wrap.as_ref())?,
        unwrap_template: encode_policy_template(object.policy_templates.unwrap.as_ref())?,
        derive_template: encode_policy_template(object.policy_templates.derive.as_ref())?,
    })
}

fn encode_stored_attributes(attributes: &StoredAttributes) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut encoded = Zeroizing::new(Vec::new());
    let mut encoder = Encoder::new(&mut *encoded);
    let encoder = encoder
        .array(23)
        .and_then(|encoder| encoder.str(RECORD_SCHEMA))
        .and_then(|encoder| encoder.u64(FORMAT_VERSION))
        .and_then(|encoder| encoder.u64(attributes.class))
        .and_then(|encoder| encoder.u64(attributes.key_type))
        .and_then(|encoder| encoder.str(&attributes.label))
        .and_then(|encoder| encoder.bytes(&attributes.id))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    for flag in [
        attributes.private,
        attributes.encrypt,
        attributes.decrypt,
        attributes.sign,
        attributes.verify,
        attributes.derive,
        attributes.sensitive,
        attributes.extractable,
        attributes.always_sensitive,
        attributes.never_extractable,
        attributes.local,
    ] {
        encoder.bool(flag).map_err(|_| CKR_DEVICE_ERROR)?;
    }
    match attributes.key_gen_mechanism {
        Some(mechanism) => {
            encoder.u64(mechanism).map_err(|_| CKR_DEVICE_ERROR)?;
        }
        None => {
            encoder.null().map_err(|_| CKR_DEVICE_ERROR)?;
        }
    }
    encode_allowed_mechanisms(encoder, attributes.allowed_mechanisms.as_deref())?;
    encoder
        .bool(attributes.wrap_with_trusted)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encode_optional_bytes(encoder, attributes.wrap_template.as_deref())?;
    encode_optional_bytes(encoder, attributes.unwrap_template.as_deref())?;
    encode_optional_bytes(encoder, attributes.derive_template.as_deref())?;
    Ok(encoded)
}

fn decode_stored_attributes(encoded: &[u8]) -> Result<StoredAttributes, Error> {
    let mut decoder = Decoder::new(encoded);
    if decoder.array().map_err(|_| CKR_DATA_INVALID)? != Some(23)
        || decoder.str().map_err(|_| CKR_DATA_INVALID)? != RECORD_SCHEMA
        || decoder.u64().map_err(|_| CKR_DATA_INVALID)? != FORMAT_VERSION
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let attributes = StoredAttributes {
        class: decoder.u64().map_err(|_| CKR_DATA_INVALID)?,
        key_type: decoder.u64().map_err(|_| CKR_DATA_INVALID)?,
        label: decoder.str().map_err(|_| CKR_DATA_INVALID)?.to_owned(),
        id: decoder.bytes().map_err(|_| CKR_DATA_INVALID)?.to_vec(),
        private: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        encrypt: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        decrypt: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        sign: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        verify: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        derive: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        sensitive: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        extractable: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        always_sensitive: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        never_extractable: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        local: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        key_gen_mechanism: if decoder.datatype().map_err(|_| CKR_DATA_INVALID)?
            == minicbor::data::Type::Null
        {
            decoder.null().map_err(|_| CKR_DATA_INVALID)?;
            None
        } else {
            Some(decoder.u64().map_err(|_| CKR_DATA_INVALID)?)
        },
        allowed_mechanisms: decode_allowed_mechanisms(&mut decoder)?,
        wrap_with_trusted: decoder.bool().map_err(|_| CKR_DATA_INVALID)?,
        wrap_template: decode_optional_bytes(&mut decoder)?,
        unwrap_template: decode_optional_bytes(&mut decoder)?,
        derive_template: decode_optional_bytes(&mut decoder)?,
    };
    if decoder.position() != encoded.len()
        || encode_stored_attributes(&attributes)?.as_slice() != encoded
    {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(attributes)
}

fn oid_value(oid: ObjectIdentifier) -> Result<Any, Error> {
    Any::encode_from(&oid).map_err(|_| Error::from(CKR_DATA_INVALID))
}

fn pkcs11rs_attributes_oid() -> Result<Any, Error> {
    Any::new(Tag::ObjectIdentifier, PKCS11RS_ATTRIBUTES_OID_VALUE)
        .map_err(|_| Error::from(CKR_DATA_INVALID))
}

fn one_value_attribute(oid: Any, value: Any) -> Result<StoredPkcs8Attribute, Error> {
    Ok(StoredPkcs8Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).map_err(|_| CKR_DATA_INVALID)?,
    })
}

fn encode_stored_private_key_info(object: &TokenObject) -> Result<Zeroizing<Vec<u8>>, Error> {
    let KeyMaterial::SoftwarePrivate(material) = &object.material else {
        return Err(CKR_DATA_INVALID.into());
    };
    let bare = material_to_pkcs8(material)?;
    let bare_info = PrivateKeyInfoRef::from_der(bare.as_ref()).map_err(|_| CKR_DATA_INVALID)?;
    let attributes = stored_attributes(object)?;
    let encoded_attributes = encode_stored_attributes(&attributes)?;
    let mut pkcs8_attributes = Vec::with_capacity(3);

    // PKCS #9 friendlyName is BMPString and limited to 255 characters.
    // The private pkcs11rs attribute remains authoritative for labels which
    // cannot be represented there.
    if !attributes.label.is_empty() && attributes.label.chars().count() <= 255 {
        if let Ok(label) = BmpString::from_utf8(&attributes.label) {
            pkcs8_attributes.push(one_value_attribute(
                oid_value(FRIENDLY_NAME_OID)?,
                Any::encode_from(&label).map_err(|_| CKR_DATA_INVALID)?,
            )?);
        }
    }
    pkcs8_attributes.push(one_value_attribute(
        oid_value(LOCAL_KEY_ID_OID)?,
        Any::encode_from(&OctetString::new(attributes.id.clone()).map_err(|_| CKR_DATA_INVALID)?)
            .map_err(|_| CKR_DATA_INVALID)?,
    )?);
    pkcs8_attributes.push(one_value_attribute(
        pkcs11rs_attributes_oid()?,
        Any::encode_from(
            &OctetString::new(encoded_attributes.as_slice()).map_err(|_| CKR_DATA_INVALID)?,
        )
        .map_err(|_| CKR_DATA_INVALID)?,
    )?);

    let info = StoredPrivateKeyInfo {
        version: 0,
        private_key_algorithm: AlgorithmIdentifierOwned {
            oid: bare_info.algorithm.oid,
            parameters: bare_info
                .algorithm
                .parameters
                .map(|parameters| parameters.ref_to_owned()),
        },
        private_key: OctetString::new(bare_info.private_key.as_bytes())
            .map_err(|_| CKR_DATA_INVALID)?,
        attributes: Some(SetOfVec::try_from(pkcs8_attributes).map_err(|_| CKR_DATA_INVALID)?),
    };
    Ok(Zeroizing::new(
        info.to_der().map_err(|_| Error::from(CKR_DATA_INVALID))?,
    ))
}

/// Export the attributed private-key representation in a standard password-
/// encrypted PKCS #8 `EncryptedPrivateKeyInfo`.
///
/// PBES2 uses scrypt (N=16384, r=8, p=1) and AES-256-CBC with a fresh
/// 16-byte salt and IV, matching the interoperable parameters recommended by
/// RustCrypto's PKCS #5 implementation.
pub(crate) fn export_encrypted_private_key_info(
    object: &TokenObject,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let plaintext = encode_stored_private_key_info(object)?;
    let mut salt = [0; EXPORT_SALT_LENGTH];
    let mut iv = [0; EXPORT_IV_LENGTH];
    getrandom::fill(&mut salt).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    getrandom::fill(&mut iv).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let parameters = export_pbes2_parameters(&salt, iv)?;
    let encrypted_data = parameters
        .encrypt(password, plaintext.as_ref())
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let encrypted = EncryptedPrivateKeyInfoOwned {
        encryption_algorithm: parameters.into(),
        encrypted_data: OctetString::new(encrypted_data).map_err(|_| CKR_DEVICE_ERROR)?,
    };
    let document =
        SecretDocument::encode_msg(&encrypted).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

pub(crate) fn encrypted_private_key_info_len(object: &TokenObject) -> Result<usize, Error> {
    let plaintext = encode_stored_private_key_info(object)?;
    let encrypted_len = plaintext
        .len()
        .checked_div(EXPORT_IV_LENGTH)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(EXPORT_IV_LENGTH))
        .ok_or(CKR_DEVICE_ERROR)?;
    let parameters = export_pbes2_parameters(&[0; EXPORT_SALT_LENGTH], [0; EXPORT_IV_LENGTH])?;
    let encrypted = EncryptedPrivateKeyInfoOwned {
        encryption_algorithm: parameters.into(),
        encrypted_data: OctetString::new(vec![0; encrypted_len]).map_err(|_| CKR_DEVICE_ERROR)?,
    };
    let document =
        SecretDocument::encode_msg(&encrypted).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(document.as_bytes().len())
}

fn export_pbes2_parameters(
    salt: &[u8; EXPORT_SALT_LENGTH],
    iv: [u8; EXPORT_IV_LENGTH],
) -> Result<pbes2::Parameters, Error> {
    let scrypt_parameters =
        pkcs8::pkcs5::scrypt::Params::new(EXPORT_SCRYPT_LOG_N, EXPORT_SCRYPT_R, EXPORT_SCRYPT_P)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    pbes2::Parameters::generate_scrypt_aes256cbc(scrypt_parameters, salt, iv)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))
}

fn decode_stored_private_key_info(
    encoded: &[u8],
) -> Result<(StoredAttributes, SoftwarePrivateKeyMaterial), Error> {
    let info = StoredPrivateKeyInfo::from_der(encoded).map_err(|_| CKR_DATA_INVALID)?;
    if info.version != 0 || info.to_der().map_err(|_| CKR_DATA_INVALID)? != encoded {
        return Err(CKR_DATA_INVALID.into());
    }
    let pkcs8_attributes = info.attributes.as_ref().ok_or(CKR_DATA_INVALID)?;
    let mut friendly_name = None;
    let mut local_key_id = None;
    let mut stored_attributes = None;
    for attribute in pkcs8_attributes.iter() {
        if attribute.values.len() != 1 {
            return Err(CKR_DATA_INVALID.into());
        }
        let value = attribute.values.get(0).ok_or(CKR_DATA_INVALID)?;
        if attribute.oid == oid_value(FRIENDLY_NAME_OID)? {
            if friendly_name.is_some() {
                return Err(CKR_DATA_INVALID.into());
            }
            let label: String = value
                .decode_as::<BmpString>()
                .map_err(|_| CKR_DATA_INVALID)?
                .chars()
                .collect();
            friendly_name = Some(label);
        } else if attribute.oid == oid_value(LOCAL_KEY_ID_OID)? {
            if local_key_id.is_some() {
                return Err(CKR_DATA_INVALID.into());
            }
            local_key_id = Some(
                value
                    .decode_as::<OctetString>()
                    .map_err(|_| CKR_DATA_INVALID)?
                    .as_bytes()
                    .to_vec(),
            );
        } else if attribute.oid == pkcs11rs_attributes_oid()? {
            if stored_attributes.is_some() {
                return Err(CKR_DATA_INVALID.into());
            }
            let metadata = value
                .decode_as::<OctetString>()
                .map_err(|_| CKR_DATA_INVALID)?;
            stored_attributes = Some(decode_stored_attributes(metadata.as_bytes())?);
        } else {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    let attributes = stored_attributes.ok_or(CKR_DATA_INVALID)?;
    if local_key_id.as_deref() != Some(attributes.id.as_slice())
        || friendly_name
            .as_ref()
            .is_some_and(|label| label != &attributes.label)
    {
        return Err(CKR_DATA_INVALID.into());
    }
    let material = material_from_pkcs8(encoded)?;
    Ok((attributes, material))
}

fn record_unique_id(reference: &ContentReference) -> String {
    let mut id = String::from("software-private-");
    for byte in reference.digest() {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

pub(crate) fn material_to_pkcs8(
    material: &SoftwarePrivateKeyMaterial,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if let SoftwarePrivateKeyMaterial::Rsa(key) = material {
        let pkcs1 = key
            .to_pkcs1_der()
            .map_err(|_| Error::from(CKR_DATA_INVALID))?;
        let info = PrivateKeyInfoRef::new(
            AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                parameters: Some(AnyRef::NULL),
            },
            OctetStringRef::new(pkcs1.as_bytes()).map_err(|_| Error::from(CKR_DATA_INVALID))?,
        );
        let document =
            SecretDocument::encode_msg(&info).map_err(|_| Error::from(CKR_DATA_INVALID))?;
        return Ok(Zeroizing::new(document.as_bytes().to_vec()));
    }
    if let Some(curve) = material.weierstrass_curve() {
        let scalar = Zeroizing::new(material.private_value().ok_or(CKR_DATA_INVALID)?);
        return ec_pkcs8(curve, scalar.as_ref());
    }
    let (oid, value) = match material {
        SoftwarePrivateKeyMaterial::Ed25519(key) => (ED25519_OID, key.to_bytes().to_vec()),
        SoftwarePrivateKeyMaterial::X25519(key) => (X25519_OID, key.to_bytes().to_vec()),
        _ => return Err(CKR_DATA_INVALID.into()),
    };
    let value = Zeroizing::new(value);
    let inner = Zeroizing::new(
        OctetStringRef::new(value.as_ref())
            .map_err(|_| Error::from(CKR_DATA_INVALID))?
            .to_der()
            .map_err(|_| Error::from(CKR_DATA_INVALID))?,
    );
    let info = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        OctetStringRef::new(inner.as_ref()).map_err(|_| Error::from(CKR_DATA_INVALID))?,
    );
    let document = SecretDocument::encode_msg(&info).map_err(|_| Error::from(CKR_DATA_INVALID))?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

fn ec_pkcs8(curve: EcCurve, scalar: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let curve_oid: ObjectIdentifier =
        ObjectIdentifier::from_der(ec_curve_parameters(curve)).map_err(|_| CKR_DATA_INVALID)?;
    let sec1 = Zeroizing::new(
        sec1::EcPrivateKey {
            private_key: scalar,
            parameters: None,
            public_key: None,
        }
        .to_der()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?,
    );
    let info = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid: EC_PUBLIC_KEY_OID,
            parameters: Some((&curve_oid).into()),
        },
        OctetStringRef::new(sec1.as_ref()).map_err(|_| Error::from(CKR_DATA_INVALID))?,
    );
    let document = SecretDocument::encode_msg(&info).map_err(|_| Error::from(CKR_DATA_INVALID))?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

fn material_from_pkcs8(encoded: &[u8]) -> Result<SoftwarePrivateKeyMaterial, Error> {
    let info = PrivateKeyInfoRef::from_der(encoded).map_err(|_| CKR_DATA_INVALID)?;
    if info.algorithm.oid == pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
        if info.algorithm.parameters != Some(AnyRef::NULL) {
            return Err(CKR_DATA_INVALID.into());
        }
        let mut key = RsaPrivateKey::from_pkcs1_der(info.private_key.as_bytes())
            .map_err(|_| CKR_DATA_INVALID)?;
        key.precompute().map_err(|_| CKR_DATA_INVALID)?;
        return Ok(SoftwarePrivateKeyMaterial::Rsa(Box::new(key)));
    }
    if info.algorithm.oid == EC_PUBLIC_KEY_OID {
        let parameters = info.algorithm.parameters.as_ref().ok_or(CKR_DATA_INVALID)?;
        let curve_oid = parameters
            .decode_as::<ObjectIdentifier>()
            .map_err(|_| CKR_DATA_INVALID)?;
        let curve =
            ec_curve_from_parameters(curve_oid.to_der().map_err(|_| CKR_DATA_INVALID)?.as_slice())?;
        let sec1 = sec1::EcPrivateKey::from_der(info.private_key.as_bytes())
            .map_err(|_| CKR_DATA_INVALID)?;
        if sec1
            .parameters
            .and_then(|parameters| parameters.named_curve())
            .is_some_and(|embedded| embedded != curve_oid)
        {
            return Err(CKR_DATA_INVALID.into());
        }
        return material_from_ec_scalar(curve, sec1.private_key);
    }
    let value = <&OctetStringRef>::from_der(info.private_key.as_bytes())
        .map_err(|_| CKR_DATA_INVALID)?
        .as_bytes();
    let value: [u8; 32] = value
        .try_into()
        .map_err(|_| Error::from(CKR_DATA_INVALID))?;
    if info.algorithm.parameters.is_some() {
        return Err(CKR_DATA_INVALID.into());
    }
    if info.algorithm.oid == ED25519_OID {
        return Ok(SoftwarePrivateKeyMaterial::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&value),
        ));
    }
    if info.algorithm.oid == X25519_OID {
        return Ok(SoftwarePrivateKeyMaterial::X25519(
            x25519_dalek::StaticSecret::from(value),
        ));
    }
    Err(CKR_DATA_INVALID.into())
}

pub(crate) fn material_from_bare_pkcs8(
    encoded: &[u8],
) -> Result<SoftwarePrivateKeyMaterial, Error> {
    let material = material_from_pkcs8(encoded)?;
    if material_to_pkcs8(&material)?.as_slice() != encoded {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(material)
}

fn material_from_ec_scalar(
    curve: EcCurve,
    scalar: &[u8],
) -> Result<SoftwarePrivateKeyMaterial, Error> {
    macro_rules! key {
        ($variant:ident, $type:path) => {
            SoftwarePrivateKeyMaterial::$variant(
                <$type>::from_slice(scalar).map_err(|_| Error::from(CKR_DATA_INVALID))?,
            )
        };
    }
    Ok(match curve {
        EcCurve::P224 => key!(P224, p224::SecretKey),
        EcCurve::P256 => key!(P256, p256::SecretKey),
        EcCurve::P384 => key!(P384, p384::SecretKey),
        EcCurve::P521 => key!(P521, p521::SecretKey),
        EcCurve::K256 => key!(K256, k256::SecretKey),
        EcCurve::BrainpoolP256 => key!(BrainpoolP256, bp256::r1::SecretKey),
        EcCurve::BrainpoolP384 => key!(BrainpoolP384, bp384::r1::SecretKey),
        EcCurve::BrainpoolP512 => {
            key!(BrainpoolP512, crate::brainpool512::SecretKey)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CKM_RSA_PKCS_KEY_PAIR_GEN;
    use pkcs8::EncryptedPrivateKeyInfoRef;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn open_store(name: &str, root: PathBuf) -> SoftwareTokenStore {
        SoftwareTokenStore::open(
            name.to_owned(),
            root,
            Some(b"software public discovery test pin".to_vec()),
        )
        .unwrap()
    }

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pkcs11rs-software-private-test-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn object(material: SoftwarePrivateKeyMaterial) -> TokenObject {
        TokenObject {
            slot_id: Some(7),
            unique_id: String::new(),
            class: crate::CKO_PRIVATE_KEY as crate::CK_OBJECT_CLASS,
            key_type: material.key_type(),
            label: String::from("caller supplied label"),
            id: vec![0, 1, 0xfe, 0xff],
            token: true,
            private: true,
            encrypt: false,
            decrypt: material.key_type() == crate::CKK_RSA as crate::CK_KEY_TYPE,
            sign: material.key_type() != crate::CKK_EC_MONTGOMERY as crate::CK_KEY_TYPE,
            verify: false,
            derive: material.key_type() != crate::CKK_RSA as crate::CK_KEY_TYPE,
            wrap: false,
            unwrap: false,
            sensitive: true,
            extractable: false,
            always_sensitive: true,
            never_extractable: true,
            local: true,
            key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as crate::CK_MECHANISM_TYPE),
            allowed_mechanisms: None,
            wrap_with_trusted: false,
            policy_templates: crate::KeyPolicyTemplates::default(),
            creator_session: None,
            public_key: Some(material.public_key().unwrap()),
            rp_id: None,
            material: KeyMaterial::SoftwarePrivate(material),
        }
    }

    fn secret_object() -> TokenObject {
        TokenObject {
            slot_id: Some(7),
            unique_id: String::new(),
            class: crate::CKO_SECRET_KEY as crate::CK_OBJECT_CLASS,
            key_type: crate::CKK_AES as crate::CK_KEY_TYPE,
            label: String::from("persistent AES key"),
            id: vec![4, 3, 2, 1],
            token: true,
            private: true,
            encrypt: true,
            decrypt: true,
            sign: true,
            verify: true,
            derive: false,
            wrap: true,
            unwrap: true,
            sensitive: true,
            extractable: false,
            always_sensitive: true,
            never_extractable: true,
            local: true,
            key_gen_mechanism: Some(crate::CKM_AES_KEY_GEN as crate::CK_MECHANISM_TYPE),
            allowed_mechanisms: None,
            wrap_with_trusted: false,
            policy_templates: crate::KeyPolicyTemplates::default(),
            creator_session: None,
            public_key: None,
            rp_id: None,
            material: KeyMaterial::SoftwareSecret(Zeroizing::new((0u8..16).collect())),
        }
    }

    fn scalar(length: usize) -> Vec<u8> {
        let mut scalar = vec![0; length];
        scalar[length - 1] = 7;
        scalar
    }

    fn record_plaintext(
        store: &SoftwareTokenStore,
        master_key: &[u8; MASTER_KEY_LENGTH],
        encoded: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        let mut decoder = Decoder::new(encoded);
        assert_eq!(decoder.array().unwrap(), Some(4));
        assert_eq!(decoder.str().unwrap(), RECORD_SCHEMA);
        assert_eq!(decoder.u64().unwrap(), FORMAT_VERSION);
        let nonce: [u8; NONCE_LENGTH] = decoder.bytes().unwrap().try_into().unwrap();
        let ciphertext = decoder.bytes().unwrap();
        assert_eq!(decoder.position(), encoded.len());
        decrypt(
            master_key,
            &nonce,
            &record_aad(&store.name, RECORD_SCHEMA),
            ciphertext,
        )
        .unwrap()
    }

    #[test]
    fn every_software_private_material_round_trips_through_standard_pkcs8() {
        let mut rsa = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        rsa.precompute().unwrap();
        let materials = vec![
            SoftwarePrivateKeyMaterial::Rsa(Box::new(rsa)),
            SoftwarePrivateKeyMaterial::P224(p224::SecretKey::from_slice(&scalar(28)).unwrap()),
            SoftwarePrivateKeyMaterial::P256(p256::SecretKey::from_slice(&scalar(32)).unwrap()),
            SoftwarePrivateKeyMaterial::P384(p384::SecretKey::from_slice(&scalar(48)).unwrap()),
            SoftwarePrivateKeyMaterial::P521(p521::SecretKey::from_slice(&scalar(66)).unwrap()),
            SoftwarePrivateKeyMaterial::K256(k256::SecretKey::from_slice(&scalar(32)).unwrap()),
            SoftwarePrivateKeyMaterial::BrainpoolP256(
                bp256::r1::SecretKey::from_slice(&scalar(32)).unwrap(),
            ),
            SoftwarePrivateKeyMaterial::BrainpoolP384(
                bp384::r1::SecretKey::from_slice(&scalar(48)).unwrap(),
            ),
            SoftwarePrivateKeyMaterial::BrainpoolP512(
                crate::brainpool512::SecretKey::from_slice(&scalar(64)).unwrap(),
            ),
            SoftwarePrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[7; 32])),
            SoftwarePrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from([7; 32])),
        ];
        for material in materials {
            let encoded = material_to_pkcs8(&material).unwrap();
            let info = PrivateKeyInfoRef::from_der(encoded.as_ref()).unwrap();
            let decoded = material_from_pkcs8(encoded.as_ref()).unwrap();
            assert_eq!(decoded.key_type(), material.key_type());
            match (&material, &decoded) {
                (
                    SoftwarePrivateKeyMaterial::Rsa(expected),
                    SoftwarePrivateKeyMaterial::Rsa(actual),
                ) => {
                    assert_eq!(actual.n(), expected.n());
                    assert_eq!(actual.d(), expected.d());
                }
                _ => assert_eq!(decoded.private_value(), material.private_value()),
            }
            assert!(
                info.algorithm.oid == EC_PUBLIC_KEY_OID
                    || info.algorithm.oid == ED25519_OID
                    || info.algorithm.oid == X25519_OID
                    || info.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            );
        }
    }

    #[test]
    fn software_secret_record_round_trips_with_all_private_attributes() {
        let master_key = [0x5a; MASTER_KEY_LENGTH];
        let mut original = secret_object();
        original.allowed_mechanisms = Some(vec![
            crate::CKM_AES_CBC as crate::CK_MECHANISM_TYPE,
            crate::CKM_AES_GCM as crate::CK_MECHANISM_TYPE,
        ]);
        original.wrap_with_trusted = true;
        let mut wrap_policy = crate::key_metadata::KeyAttributes::new();
        wrap_policy
            .insert_template(
                u64::from(crate::CKA_KEY_TYPE),
                crate::key_metadata::KeyAttributeValue::Unsigned(u64::from(crate::CKK_AES)),
            )
            .unwrap();
        original.policy_templates.wrap = Some(wrap_policy);
        let encoded = encode_record("secret storage", &master_key, &original).unwrap();
        assert!(
            !encoded
                .windows(original.label.len())
                .any(|window| window == original.label.as_bytes())
        );
        let decoded = decode_record(
            "secret storage",
            9,
            "software-private-test",
            &master_key,
            &encoded,
        )
        .unwrap();
        assert_eq!(decoded.slot_id, Some(9));
        assert_eq!(decoded.unique_id, "software-private-test");
        assert_eq!(decoded.class, original.class);
        assert_eq!(decoded.key_type, original.key_type);
        assert_eq!(decoded.label, original.label);
        assert_eq!(decoded.id, original.id);
        assert!(decoded.token && decoded.private);
        assert!(decoded.encrypt && decoded.decrypt && decoded.sign && decoded.verify);
        assert!(decoded.wrap && decoded.unwrap);
        assert!(decoded.sensitive && !decoded.extractable);
        assert!(decoded.always_sensitive && decoded.never_extractable && decoded.local);
        assert_eq!(decoded.key_gen_mechanism, original.key_gen_mechanism);
        assert_eq!(decoded.allowed_mechanisms, original.allowed_mechanisms);
        assert!(decoded.wrap_with_trusted);
        assert_eq!(decoded.policy_templates, original.policy_templates);
        let KeyMaterial::SoftwareSecret(value) = decoded.material else {
            panic!("persistent secret record changed material type");
        };
        assert_eq!(value.as_slice(), &(0u8..16).collect::<Vec<_>>());

        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decode_record(
                "secret storage",
                9,
                "software-private-test",
                &master_key,
                &tampered,
            )
            .is_err()
        );
    }

    #[test]
    fn allowed_mechanism_encoding_is_binary_equivalent_across_platform_widths() {
        let mechanisms_32 = [1_u32, 0x0102_0304];
        let mechanisms_64 = mechanisms_32.map(u64::from);
        let stored_32 = stored_allowed_mechanisms(Some(&mechanisms_32)).unwrap();
        let stored_64 = stored_allowed_mechanisms(Some(&mechanisms_64)).unwrap();
        let mut encoded_32 = Vec::new();
        let mut encoded_64 = Vec::new();

        encode_allowed_mechanisms(&mut Encoder::new(&mut encoded_32), Some(&stored_32)).unwrap();
        encode_allowed_mechanisms(&mut Encoder::new(&mut encoded_64), Some(&stored_64)).unwrap();

        assert_eq!(stored_32, stored_64);
        assert_eq!(encoded_32, encoded_64);
        assert_eq!(encoded_32, [0x82, 0x01, 0x1a, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            decode_allowed_mechanisms(&mut Decoder::new(&encoded_32)).unwrap(),
            Some(mechanisms_64.to_vec())
        );
    }

    #[test]
    fn exported_encrypted_private_key_info_round_trips_attributed_pkcs8() {
        let material =
            SoftwarePrivateKeyMaterial::P256(p256::SecretKey::from_slice(&scalar(32)).unwrap());
        let mut original = object(material);
        original.extractable = true;
        original.never_extractable = false;
        original.allowed_mechanisms = Some(vec![crate::CKM_ECDSA as crate::CK_MECHANISM_TYPE]);
        original.wrap_with_trusted = true;
        let mut derive_policy = crate::key_metadata::KeyAttributes::new();
        derive_policy
            .insert_template(
                u64::from(crate::CKA_PRIVATE),
                crate::key_metadata::KeyAttributeValue::Boolean(true),
            )
            .unwrap();
        original.policy_templates.derive = Some(derive_policy);
        let password = b"OpenSSL compatible export password";

        let expected_len = encrypted_private_key_info_len(&original).unwrap();
        let exported = export_encrypted_private_key_info(&original, password).unwrap();
        assert_eq!(exported.len(), expected_len);
        let encrypted = EncryptedPrivateKeyInfoRef::from_der(exported.as_ref()).unwrap();
        let parameters = match &encrypted.encryption_algorithm {
            pkcs8::pkcs5::EncryptionScheme::Pbes2(parameters) => parameters,
            _ => panic!("export did not use PBES2"),
        };
        let scrypt = parameters.kdf.scrypt().unwrap();
        assert_eq!(scrypt.cost_parameter, 16_384);
        assert_eq!(scrypt.block_size, 8);
        assert_eq!(scrypt.parallelization, 1);
        assert_eq!(scrypt.salt.as_bytes().len(), 16);
        assert!(matches!(
            parameters.encryption,
            pbes2::EncryptionScheme::Aes256Cbc { iv } if iv.len() == 16
        ));

        let decrypted = encrypted.decrypt(password).unwrap();
        let info = StoredPrivateKeyInfo::from_der(decrypted.as_bytes()).unwrap();
        assert_eq!(info.attributes.as_ref().unwrap().len(), 3);
        let (attributes, material) = decode_stored_private_key_info(decrypted.as_bytes()).unwrap();
        assert_eq!(attributes.label, original.label);
        assert_eq!(attributes.id, original.id);
        assert!(attributes.extractable);
        assert_eq!(
            attributes.allowed_mechanisms,
            Some(vec![u64::from(crate::CKM_ECDSA)])
        );
        assert!(attributes.wrap_with_trusted);
        assert_eq!(
            decode_policy_template(attributes.derive_template.clone()).unwrap(),
            original.policy_templates.derive
        );
        assert_eq!(material.private_value().unwrap(), scalar(32));

        assert!(encrypted.decrypt(b"wrong export password").is_err());
    }

    #[test]
    fn login_persistence_wrong_pin_rotation_and_encrypted_attributes() {
        let directory = TestDirectory::new();
        let store = open_store("signing", directory.0.clone());
        assert!(!store.is_initialized().unwrap());
        assert!(matches!(
            store.login(b"correct horse battery staple"),
            Err(Error::Generic(rv)) if rv == crate::CKR_TOKEN_NOT_INITIALIZED as crate::CK_RV
        ));
        let label = *b"signing token                   ";
        let so_public = store
            .init_token(b"correct security officer pin", label)
            .unwrap();
        assert!(store.is_initialized().unwrap());
        assert!(!store.user_pin_is_initialized().unwrap());
        assert!(matches!(
            store.login(b"correct horse battery staple"),
            Err(Error::Generic(rv)) if rv == crate::CKR_USER_PIN_NOT_INITIALIZED as crate::CK_RV
        ));
        store
            .init_user_pin(b"correct horse battery staple", &so_public)
            .unwrap();
        let (user_public, key) = store.login(b"correct horse battery staple").unwrap();
        assert_eq!(so_public.as_ref(), user_public.as_ref());
        assert_ne!(user_public.as_ref(), key.as_ref());

        let material =
            SoftwarePrivateKeyMaterial::P256(p256::SecretKey::from_slice(&scalar(32)).unwrap());
        let original = object(material);
        let (stored, reference) = store.put_object(7, &key, &original).unwrap();
        assert_eq!(stored.label, original.label);
        assert_eq!(stored.id, original.id);
        let on_disk = store.records.get(&reference).unwrap().unwrap();
        assert!(
            !on_disk
                .windows(original.label.len())
                .any(|window| window == original.label.as_bytes())
        );
        assert!(
            !on_disk
                .windows(original.id.len())
                .any(|window| window == original.id)
        );
        let plaintext = record_plaintext(&store, &key, &on_disk);
        // The entire authenticated plaintext is an ordinary attributed PKCS
        // #8 PrivateKeyInfo/OneAsymmetricKey, suitable for placing inside a
        // future EncryptedPrivateKeyInfo export.
        PrivateKeyInfoRef::from_der(plaintext.as_ref()).unwrap();
        let info = StoredPrivateKeyInfo::from_der(plaintext.as_ref()).unwrap();
        let attributes = info.attributes.unwrap();
        assert_eq!(attributes.len(), 3);
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute.oid == oid_value(FRIENDLY_NAME_OID).unwrap())
        );
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute.oid == oid_value(LOCAL_KEY_ID_OID).unwrap())
        );
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute.oid == pkcs11rs_attributes_oid().unwrap())
        );

        drop(key);
        assert!(matches!(
            store.login(b"wrong password"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));
        let (_, key) = store.login(b"correct horse battery staple").unwrap();
        let (objects, _) = store.load_objects(9, &key).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].slot_id, Some(9));
        assert_eq!(objects[0].label, original.label);
        assert_eq!(objects[0].id, original.id);

        store
            .change_pin(
                b"correct horse battery staple",
                b"new correct horse battery staple",
            )
            .unwrap();
        assert!(matches!(
            store.login(b"correct horse battery staple"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));
        let (rotated_public, rotated_private) =
            store.login(b"new correct horse battery staple").unwrap();
        assert_eq!(rotated_private.as_ref(), key.as_ref());
        assert_eq!(store.load_objects(9, &rotated_private).unwrap().0.len(), 1);
        let so_key = store.login_so(b"correct security officer pin").unwrap();
        assert_eq!(so_key.as_ref(), rotated_public.as_ref());
        assert_ne!(so_key.as_ref(), rotated_private.as_ref());
        assert!(matches!(
            store.init_user_pin(b"reset user pin after SO login", &so_key),
            Err(Error::Generic(rv)) if rv == crate::CKR_FUNCTION_FAILED as crate::CK_RV
        ));
        assert!(store.login(b"new correct horse battery staple").is_ok());
        store
            .change_so_pin(
                b"correct security officer pin",
                b"rotated security officer pin",
            )
            .unwrap();
        assert!(matches!(
            store.login_so(b"correct security officer pin"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));
        assert_eq!(
            store
                .login_so(b"rotated security officer pin")
                .unwrap()
                .as_ref(),
            rotated_public.as_ref()
        );
        assert_eq!(
            fs::read_dir(&store.root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(header_generation)
                        .is_some()
                })
                .count(),
            1
        );
    }

    #[test]
    fn public_discovery_is_encrypted_optional_and_independent_of_login() {
        let directory = TestDirectory::new();
        let name = String::from("discovery");
        let discovery_pin = b"correct discovery password".to_vec();
        let store = SoftwareTokenStore::open(
            name.clone(),
            directory.0.clone(),
            Some(discovery_pin.clone()),
        )
        .unwrap();
        let active = Rc::new(RefCell::new(None));
        let provider = SoftwarePublicStorageProvider::open(
            name.clone(),
            directory.0.clone(),
            Some(discovery_pin),
            active.clone(),
        )
        .unwrap();
        let public = store
            .init_token(
                b"correct security officer pin",
                *b"discovery token                 ",
            )
            .unwrap();
        store
            .init_user_pin(b"correct user password", &public)
            .unwrap();
        *active.borrow_mut() = Some(Zeroizing::new(*public));

        let logical = minicbor::to_vec(("public marker", 7u8)).unwrap();
        let reference = provider.put(&logical).unwrap();
        assert_eq!(provider.get(&reference).unwrap(), Some(logical.clone()));
        for physical in provider.records.list().unwrap() {
            let encoded = provider.records.get(&physical).unwrap().unwrap();
            assert!(
                !encoded
                    .windows(b"public marker".len())
                    .any(|window| window == b"public marker")
            );
        }

        *active.borrow_mut() = None;
        assert_eq!(provider.list().unwrap(), vec![reference]);

        let wrong_active = Rc::new(RefCell::new(None));
        let wrong_discovery = SoftwarePublicStorageProvider::open(
            name.clone(),
            directory.0.clone(),
            Some(b"wrong discovery password".to_vec()),
            wrong_active,
        )
        .unwrap();
        assert!(wrong_discovery.list().unwrap().is_empty());

        let wrong_discovery_store = SoftwareTokenStore::open(
            name,
            directory.0.clone(),
            Some(b"wrong discovery password".to_vec()),
        )
        .unwrap();
        assert!(
            wrong_discovery_store
                .login_so(b"correct security officer pin")
                .is_ok()
        );
        assert!(
            wrong_discovery_store
                .login(b"correct user password")
                .is_ok()
        );
    }

    #[test]
    fn pkcs8_attributes_preserve_non_bmp_labels_and_reject_conflicts() {
        let material =
            SoftwarePrivateKeyMaterial::P256(p256::SecretKey::from_slice(&scalar(32)).unwrap());
        let mut non_bmp = object(material);
        non_bmp.label = String::from("caller 🔐 label");
        let encoded = encode_stored_private_key_info(&non_bmp).unwrap();
        let info = StoredPrivateKeyInfo::from_der(encoded.as_ref()).unwrap();
        let attributes = info.attributes.as_ref().unwrap();
        assert_eq!(attributes.len(), 2);
        assert!(
            !attributes
                .iter()
                .any(|attribute| attribute.oid == oid_value(FRIENDLY_NAME_OID).unwrap())
        );
        let (decoded, _) = decode_stored_private_key_info(encoded.as_ref()).unwrap();
        assert_eq!(decoded.label, non_bmp.label);
        assert_eq!(decoded.id, non_bmp.id);

        let material =
            SoftwarePrivateKeyMaterial::P256(p256::SecretKey::from_slice(&scalar(32)).unwrap());
        let ordinary = object(material);
        let encoded = encode_stored_private_key_info(&ordinary).unwrap();
        let mut info = StoredPrivateKeyInfo::from_der(encoded.as_ref()).unwrap();
        let mut attributes = info.attributes.take().unwrap().into_vec();
        for attribute in &mut attributes {
            if attribute.oid == oid_value(FRIENDLY_NAME_OID).unwrap() {
                *attribute = one_value_attribute(
                    oid_value(FRIENDLY_NAME_OID).unwrap(),
                    Any::encode_from(&BmpString::from_utf8("conflicting label").unwrap()).unwrap(),
                )
                .unwrap();
            }
        }
        info.attributes = Some(StoredPkcs8Attributes::try_from(attributes).unwrap());
        let conflicting = info.to_der().unwrap();
        assert!(matches!(
            decode_stored_private_key_info(&conflicting),
            Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as crate::CK_RV
        ));
    }

    #[test]
    fn name_binding_and_corrupt_current_header_fail_closed() {
        let directory = TestDirectory::new();
        let first = open_store("first", directory.0.clone());
        let first_public = first
            .init_token(
                b"one sufficiently long SO pin",
                *b"first token                     ",
            )
            .unwrap();
        first
            .init_user_pin(b"one sufficiently long pin", &first_public)
            .unwrap();
        let other_name_same_root = open_store("second", directory.0.clone());
        assert!(matches!(
            other_name_same_root.login(b"one sufficiently long pin"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));

        let (_, path) = first.current_header_path().unwrap().unwrap();
        fs::write(path, [0x81, 0x01]).unwrap();
        assert!(matches!(
            first.login(b"one sufficiently long pin"),
            Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as crate::CK_RV
        ));
    }

    #[test]
    fn headers_require_the_current_kdf_iteration_count() {
        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .array(16)
            .and_then(|encoder| encoder.str(HEADER_SCHEMA))
            .and_then(|encoder| encoder.u64(HEADER_FORMAT_VERSION))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.str(KDF_NAME))
            .and_then(|encoder| encoder.u32(600_000))
            .and_then(|encoder| encoder.str(AEAD_NAME))
            .and_then(|encoder| encoder.bytes(&[b' '; 32]))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.bytes(&[7; SALT_LENGTH]))
            .and_then(|encoder| encoder.bytes(&[8; NONCE_LENGTH]))
            .and_then(|encoder| encoder.bytes(&[9; MASTER_KEY_LENGTH + TAG_LENGTH]))
            .and_then(|encoder| encoder.u64(1))
            .and_then(|encoder| encoder.bytes(&[1; SALT_LENGTH]))
            .and_then(|encoder| encoder.bytes(&[2; NONCE_LENGTH]))
            .and_then(|encoder| encoder.bytes(&[3; MASTER_KEY_LENGTH + TAG_LENGTH]))
            .and_then(|encoder| encoder.bool(false))
            .unwrap();
        assert!(matches!(
            decode_header(&encoded),
            Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as crate::CK_RV
        ));
    }

    #[test]
    fn newest_durable_header_wins() {
        let directory = TestDirectory::new();
        let store = open_store("race", directory.0.clone());
        let race_public = store
            .init_token(
                b"one shared initialization SO pin",
                *b"race token                      ",
            )
            .unwrap();
        store
            .init_user_pin(b"one shared initialization pin", &race_public)
            .unwrap();
        let (current_public, current_private) =
            store.login(b"one shared initialization pin").unwrap();
        let (_, encoded) = store.read_current_header().unwrap().unwrap();
        let mut replacement = decode_header(&encoded).unwrap();
        let next_generation = replacement.generation + 1;
        replacement.generation = next_generation;
        replacement.user = Some(UserWrappedMasterKeys {
            public: wrap_master_key(
                &store.name,
                PinRole::UserPublic,
                next_generation,
                b"replacement pin after durable publish",
                current_public.as_ref(),
            )
            .unwrap(),
            private: wrap_master_key(
                &store.name,
                PinRole::UserPrivate,
                next_generation,
                b"replacement pin after durable publish",
                current_private.as_ref(),
            )
            .unwrap(),
        });
        let replacement = encode_header(&replacement).unwrap();
        // Model a crash after publishing generation 2 but before removing
        // generation 1, plus an abandoned partial temporary file.
        store.publish_header(next_generation, &replacement).unwrap();
        fs::write(store.root.join(format!("{TEMPORARY_PREFIX}crash")), [0x81]).unwrap();
        assert!(matches!(
            store.login(b"one shared initialization pin"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as crate::CK_RV
        ));
        assert_eq!(
            store
                .login(b"replacement pin after durable publish")
                .unwrap()
                .1
                .as_ref(),
            current_private.as_ref()
        );
        assert_eq!(
            store.current_header_path().unwrap().unwrap().0,
            next_generation
        );
    }

    #[test]
    fn malformed_records_and_short_pins_are_rejected_without_state() {
        let directory = TestDirectory::new();
        let store = open_store("malformed", directory.0.clone());
        assert!(matches!(
            store.login(b"short"),
            Err(Error::Generic(rv)) if rv == CKR_PIN_LEN_RANGE as crate::CK_RV
        ));
        assert!(!store.is_initialized().unwrap());
        assert!(matches!(
            store.change_pin(b"old sufficiently long pin", b"new sufficiently long pin"),
            Err(Error::Generic(rv))
                if rv == crate::CKR_TOKEN_NOT_INITIALIZED as crate::CK_RV
        ));
        assert!(!store.is_initialized().unwrap());
        let malformed_public = store
            .init_token(
                b"a sufficiently long SO pin",
                *b"malformed token                 ",
            )
            .unwrap();
        store
            .init_user_pin(b"a sufficiently long pin", &malformed_public)
            .unwrap();
        let key = store.login(b"a sufficiently long pin").unwrap().1;
        let malformed = minicbor::to_vec((RECORD_SCHEMA, FORMAT_VERSION)).unwrap();
        store.records.put(&malformed).unwrap();
        assert!(matches!(
            store.load_objects(1, &key),
            Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as crate::CK_RV
        ));

        let missing_header_directory = TestDirectory::new();
        let missing_header = open_store("missing-header", missing_header_directory.0.clone());
        missing_header.records.put(&malformed).unwrap();
        assert!(matches!(
            missing_header.login(b"a sufficiently long pin"),
            Err(Error::Generic(rv)) if rv == crate::CKR_TOKEN_NOT_INITIALIZED as crate::CK_RV
        ));
        assert!(!missing_header.is_initialized().unwrap());

        let malformed_header_directory = TestDirectory::new();
        let malformed_header = open_store("malformed-header", malformed_header_directory.0.clone());
        fs::write(malformed_header.root.join("header-invalid.cbor"), [0x80]).unwrap();
        assert!(matches!(
            malformed_header.login(b"a sufficiently long pin"),
            Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as crate::CK_RV
        ));
    }
}
