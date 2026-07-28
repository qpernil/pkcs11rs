//! Persistence primitives intended for a future hybrid FIDO
//! hardware/software slot.
//!
//! Providers expose opaque, immutable canonical-CBOR data items and address
//! those logical bytes by an algorithm-tagged digest. A provider may use a
//! different physical encoding only when it can reproduce the submitted
//! canonical bytes exactly. This keeps local-directory, device, and future
//! remote providers behind the same boundary without coupling storage to CTAP.
//!
//! This module is not yet connected to PKCS #11 slot discovery, configuration,
//! FIDO credential registration, key derivation, or signing.

use minicbor::{Decoder, Encoder};
use sha3::{Digest, Sha3_256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const OBJECT_DIRECTORY: &str = "objects";
const SHA3_256_NAME: &str = "sha3-256";
const SHA3_256_LENGTH: usize = 32;
const TEMPORARY_FILE_PREFIX: &str = ".pkcs11rs-";
const TEMPORARY_FILE_SUFFIX: &str = ".tmp";

/// A content-addressing algorithm supported by a [`StorageProvider`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContentHashAlgorithm {
    /// SHA3-256, producing a 32-byte digest.
    Sha3_256,
}

impl ContentHashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha3_256 => SHA3_256_NAME,
        }
    }

    fn digest_length(self) -> usize {
        match self {
            Self::Sha3_256 => SHA3_256_LENGTH,
        }
    }

    fn digest(self, object: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha3_256 => Sha3_256::digest(object).to_vec(),
        }
    }

    fn from_name(name: &str) -> Result<Self, StorageError> {
        match name {
            SHA3_256_NAME => Ok(Self::Sha3_256),
            _ => Err(StorageError::UnsupportedHashAlgorithm(name.to_owned())),
        }
    }
}

/// An algorithm-tagged reference to an immutable stored CBOR object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentReference {
    algorithm: ContentHashAlgorithm,
    digest: Vec<u8>,
}

impl ContentReference {
    /// Compute a SHA3-256 content reference for the exact object bytes.
    pub fn for_object(object: &[u8]) -> Self {
        let algorithm = ContentHashAlgorithm::Sha3_256;
        Self {
            algorithm,
            digest: algorithm.digest(object),
        }
    }

    /// Construct a validated algorithm-tagged content reference.
    pub fn new(
        algorithm: ContentHashAlgorithm,
        digest: impl Into<Vec<u8>>,
    ) -> Result<Self, StorageError> {
        let digest = digest.into();
        if digest.len() != algorithm.digest_length() {
            return Err(StorageError::InvalidReference);
        }
        Ok(Self { algorithm, digest })
    }

    /// Return the content-addressing algorithm.
    pub fn algorithm(&self) -> ContentHashAlgorithm {
        self.algorithm
    }

    /// Return the raw digest.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Encode the reference canonically as `[algorithm-name, digest]`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoded = Vec::with_capacity(self.digest.len() + self.algorithm.name().len() + 5);
        Encoder::new(&mut encoded)
            .array(2)
            .and_then(|encoder| encoder.str(self.algorithm.name()))
            .and_then(|encoder| encoder.bytes(&self.digest))
            .map_err(|_| StorageError::InvalidReference)?;
        Ok(encoded)
    }

    /// Decode and validate a canonical content reference.
    pub fn from_cbor(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder
            .array()
            .map_err(|_| StorageError::InvalidReference)?
            != Some(2)
        {
            return Err(StorageError::InvalidReference);
        }
        let algorithm = ContentHashAlgorithm::from_name(
            decoder.str().map_err(|_| StorageError::InvalidReference)?,
        )?;
        let digest = decoder
            .bytes()
            .map_err(|_| StorageError::InvalidReference)?
            .to_vec();
        if decoder.position() != encoded.len() {
            return Err(StorageError::InvalidReference);
        }
        let reference = Self::new(algorithm, digest)?;
        if reference.to_cbor()? != encoded {
            return Err(StorageError::InvalidReference);
        }
        Ok(reference)
    }

    fn filename(&self) -> String {
        format!(
            "{}-{}.cbor",
            self.algorithm.name(),
            encode_lower_hex(&self.digest)
        )
    }

    fn from_filename(filename: &str) -> Result<Self, StorageError> {
        let stem = filename
            .strip_suffix(".cbor")
            .ok_or(StorageError::InvalidReference)?;
        let (algorithm, digest) = stem
            .rsplit_once('-')
            .ok_or(StorageError::InvalidReference)?;
        let algorithm = ContentHashAlgorithm::from_name(algorithm)?;
        let digest = decode_lower_hex(digest)?;
        Self::new(algorithm, digest)
    }

    fn matches(&self, object: &[u8]) -> bool {
        self.algorithm.digest(object) == self.digest
    }
}

/// Failures produced by a storage provider.
#[derive(Debug)]
pub enum StorageError {
    /// A filesystem operation failed.
    Io(io::Error),
    /// A content reference was malformed.
    InvalidReference,
    /// A stored object's bytes did not match its content reference.
    Integrity,
    /// The object was not exactly one well-formed CBOR data item.
    InvalidCbor,
    /// A provider encountered different bytes under the same content reference.
    Conflict,
    /// A provider-specific backend operation failed.
    Provider(String),
    /// The reference uses an algorithm this implementation does not support.
    UnsupportedHashAlgorithm(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "storage I/O failed: {error}"),
            Self::InvalidReference => formatter.write_str("invalid storage content reference"),
            Self::Integrity => formatter.write_str("stored object failed its integrity check"),
            Self::InvalidCbor => formatter.write_str("stored object is not one valid CBOR item"),
            Self::Conflict => {
                formatter.write_str("different content exists under the same reference")
            }
            Self::Provider(error) => write!(formatter, "storage provider failed: {error}"),
            Self::UnsupportedHashAlgorithm(name) => {
                write!(formatter, "unsupported content hash algorithm {name}")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Persistence boundary for immutable, content-addressed CBOR objects.
pub trait StorageProvider {
    /// List all valid objects currently available, in reference order.
    fn list(&self) -> Result<Vec<ContentReference>, StorageError>;

    /// Retrieve and verify an object, returning `None` when it is absent.
    fn get(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError>;

    /// Store canonical-CBOR logical bytes idempotently and return their reference.
    ///
    /// `get` must return the exact submitted bytes. A provider may choose a
    /// lossless backend-specific physical representation.
    fn put(&self, object: &[u8]) -> Result<ContentReference, StorageError>;

    /// Delete an object, returning whether it was present.
    fn delete(&self, reference: &ContentReference) -> Result<bool, StorageError>;
}

/// A local provider backed by immutable files in an `objects` directory.
#[derive(Clone, Debug)]
pub struct LocalStorageProvider {
    root: PathBuf,
    objects: PathBuf,
    next_temporary_file: Arc<AtomicU64>,
}

impl LocalStorageProvider {
    /// Open or create a local store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        let objects = root.join(OBJECT_DIRECTORY);
        fs::create_dir_all(&objects)?;
        Ok(Self {
            root,
            objects,
            next_temporary_file: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Return the configured store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, reference: &ContentReference) -> PathBuf {
        self.objects.join(reference.filename())
    }

    fn read_verified(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.object_path(reference);
        let object = match fs::read(path) {
            Ok(object) => object,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_cbor_object(&object)?;
        if !reference.matches(&object) {
            return Err(StorageError::Integrity);
        }
        Ok(Some(object))
    }

    fn temporary_file(&self) -> Result<(PathBuf, File), StorageError> {
        loop {
            let id = self.next_temporary_file.fetch_add(1, Ordering::Relaxed);
            let path = self.objects.join(format!(
                "{TEMPORARY_FILE_PREFIX}{}-{id}{TEMPORARY_FILE_SUFFIX}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl StorageProvider for LocalStorageProvider {
    fn list(&self) -> Result<Vec<ContentReference>, StorageError> {
        let mut references = Vec::new();
        for entry in fs::read_dir(&self.objects)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let filename = entry
                .file_name()
                .into_string()
                .map_err(|_| StorageError::InvalidReference)?;
            if filename.starts_with(TEMPORARY_FILE_PREFIX)
                && filename.ends_with(TEMPORARY_FILE_SUFFIX)
            {
                continue;
            }
            if !filename.ends_with(".cbor") {
                continue;
            }
            let reference = ContentReference::from_filename(&filename)?;
            self.read_verified(&reference)?
                .ok_or(StorageError::Integrity)?;
            references.push(reference);
        }
        references.sort();
        references.dedup();
        Ok(references)
    }

    fn get(&self, reference: &ContentReference) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_verified(reference)
    }

    fn put(&self, object: &[u8]) -> Result<ContentReference, StorageError> {
        validate_cbor_object(object)?;
        let reference = ContentReference::for_object(object);
        if let Some(existing) = self.read_verified(&reference)? {
            if existing == object {
                return Ok(reference);
            }
            return Err(StorageError::Conflict);
        }

        let destination = self.object_path(&reference);
        let (temporary, mut file) = self.temporary_file()?;
        let publish = (|| -> Result<(), StorageError> {
            file.write_all(object)?;
            file.sync_all()?;
            drop(file);
            // A hard link publishes the fully written file without replacing a
            // concurrently created immutable object at the destination.
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = self
                        .read_verified(&reference)?
                        .ok_or(StorageError::Conflict)?;
                    if existing != object {
                        return Err(StorageError::Conflict);
                    }
                }
                Err(error) => return Err(error.into()),
            }
            fs::remove_file(&temporary)?;
            sync_directory(&self.objects)?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        publish?;
        Ok(reference)
    }

    fn delete(&self, reference: &ContentReference) -> Result<bool, StorageError> {
        let path = self.object_path(reference);
        match fs::remove_file(path) {
            Ok(()) => {
                sync_directory(&self.objects)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

fn validate_cbor_object(object: &[u8]) -> Result<(), StorageError> {
    let mut decoder = Decoder::new(object);
    decoder.skip().map_err(|_| StorageError::InvalidCbor)?;
    if decoder.position() != object.len() {
        return Err(StorageError::InvalidCbor);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), StorageError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), StorageError> {
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_lower_hex(encoded: &str) -> Result<Vec<u8>, StorageError> {
    if encoded.len() % 2 != 0 {
        return Err(StorageError::InvalidReference);
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = lower_hex_value(pair[0])?;
            let low = lower_hex_value(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn lower_hex_value(value: u8) -> Result<u8, StorageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StorageError::InvalidReference),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("pkcs11rs-storage-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sha3_256_reference_has_a_stable_algorithm_tag_and_digest() {
        let reference = ContentReference::for_object(&[0xf6]);
        assert_eq!(reference.algorithm(), ContentHashAlgorithm::Sha3_256);
        assert_eq!(
            encode_lower_hex(reference.digest()),
            "457aa5e41c73fcb2b2a577f74900cf69acd0483bdc62566c176f15374cfcb9a1"
        );
        assert_eq!(
            reference.filename(),
            "sha3-256-457aa5e41c73fcb2b2a577f74900cf69acd0483bdc62566c176f15374cfcb9a1.cbor"
        );
    }

    #[test]
    fn content_references_round_trip_through_canonical_cbor() {
        let reference = ContentReference::for_object(&[0xa1, 0x01, 0x61, 0x61]);
        let encoded = reference.to_cbor().unwrap();
        assert_eq!(&encoded[0..10], b"\x82\x68sha3-256");
        assert_eq!(ContentReference::from_cbor(&encoded).unwrap(), reference);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            ContentReference::from_cbor(&trailing),
            Err(StorageError::InvalidReference)
        ));
        assert!(matches!(
            ContentReference::from_cbor(b"\x82\x68sha2-256\x40"),
            Err(StorageError::UnsupportedHashAlgorithm(name)) if name == "sha2-256"
        ));
        let mut noncanonical = b"\x82\x78\x08sha3-256\x58\x20".to_vec();
        noncanonical.extend_from_slice(reference.digest());
        assert!(matches!(
            ContentReference::from_cbor(&noncanonical),
            Err(StorageError::InvalidReference)
        ));
    }

    #[test]
    fn local_provider_stores_lists_reads_and_deletes_objects() {
        let directory = TestDirectory::new();
        let provider = LocalStorageProvider::open(&directory.0).unwrap();
        let first = [0xa1, 0x01, 0x61, 0x61];
        let second = [0x82, 0x01, 0x02];

        let second_reference = provider.put(&second).unwrap();
        let first_reference = provider.put(&first).unwrap();
        assert_eq!(provider.put(&first).unwrap(), first_reference);
        let mut expected = vec![first_reference.clone(), second_reference.clone()];
        expected.sort();
        assert_eq!(provider.list().unwrap(), expected);
        assert_eq!(
            provider.get(&first_reference).unwrap(),
            Some(first.to_vec())
        );

        assert!(provider.delete(&first_reference).unwrap());
        assert!(!provider.delete(&first_reference).unwrap());
        assert_eq!(provider.get(&first_reference).unwrap(), None);
        assert_eq!(provider.list().unwrap(), vec![second_reference]);
    }

    #[test]
    fn local_provider_rejects_invalid_and_corrupt_objects() {
        let directory = TestDirectory::new();
        let provider = LocalStorageProvider::open(&directory.0).unwrap();
        assert!(matches!(provider.put(&[]), Err(StorageError::InvalidCbor)));
        assert!(matches!(
            provider.put(&[0xf6, 0xf6]),
            Err(StorageError::InvalidCbor)
        ));

        let reference = provider.put(&[0xf6]).unwrap();
        fs::write(provider.object_path(&reference), [0xf5]).unwrap();
        assert!(matches!(
            provider.get(&reference),
            Err(StorageError::Integrity)
        ));
        assert!(matches!(provider.list(), Err(StorageError::Integrity)));
    }

    #[test]
    fn local_provider_ignores_non_object_and_temporary_files() {
        let directory = TestDirectory::new();
        let provider = LocalStorageProvider::open(&directory.0).unwrap();
        fs::write(provider.objects.join("README"), b"not an object").unwrap();
        fs::write(
            provider.objects.join(".pkcs11rs-interrupted.tmp"),
            b"partial",
        )
        .unwrap();
        assert!(provider.list().unwrap().is_empty());
    }

    #[test]
    fn concurrent_identical_puts_are_idempotent() {
        let directory = TestDirectory::new();
        let provider = Arc::new(LocalStorageProvider::open(&directory.0).unwrap());
        let handles = (0..8)
            .map(|_| {
                let provider = provider.clone();
                std::thread::spawn(move || provider.put(&[0xa1, 0x01, 0x61, 0x61]).unwrap())
            })
            .collect::<Vec<_>>();
        let references = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(references
            .iter()
            .all(|reference| reference == &references[0]));
        assert_eq!(provider.list().unwrap(), vec![references[0].clone()]);
    }
}
