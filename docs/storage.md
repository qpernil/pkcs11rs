# Content-addressed CBOR storage

The public `storage` module defines persistence infrastructure for backed key
metadata. Each PKCS #11 session owns an in-memory provider, each slot owns a
token provider, and `CKA_TOKEN` selects between them for supported
provider-backed objects. It is also usable as a standalone Rust API through the
local provider. YubiHSM implements the same boundary with its internal opaque
metadata objects. `PKCS11RS_FIDO2_STORAGE` installs the local provider on FIDO
slots whose physical Yubico serial has been validated.

## Provider boundary

`StorageProvider` has four operations:

- `list` returns all valid content references in stable order;
- `get` retrieves an object and verifies its content hash;
- `put` stores one CBOR item idempotently and returns its reference;
- `delete` removes one referenced object and reports whether it existed.

Content references always identify the exact logical bytes returned by `get`.
The local provider treats object bytes as opaque and checks only that they
contain exactly one well-formed CBOR item. A device-specific provider may
additionally validate its own backing schema or translate a legacy physical
representation to canonical logical bytes. Providers do not re-encode
canonical records submitted to `put`.

The trait has no `Send` or `Sync` supertrait. A provider follows its owning
context's concurrency model: the local provider is independently thread-safe,
each memory provider is reached through its owning session context, and the
YubiHSM provider is reached through the module and slot locks that already
serialize access to its single secure-session state.

`MemoryStorageProvider` supplies the same immutable, content-addressed
semantics without filesystem persistence. A fresh instance belongs to each
session, so two equal session objects may share stored bytes without sharing
PKCS #11 handles or lifetimes. Closing the session drops its provider and all
objects created by that session.

Every slot also owns one token provider. The default is
`UnavailableStorageProvider`, whose mutation operations fail explicitly. A
backend may expose a native provider, as YubiHSM does, or slot construction may
supply another implementation. FIDO discovery selects the local provider when
`PKCS11RS_FIDO2_STORAGE` contains an absolute path and the endpoint has a
validated physical Yubico serial. Other FIDO authenticators retain the
unavailable provider rather than sharing an ambiguously addressed store.

## Backed-key metadata

The public `key_metadata` module defines the provider-neutral canonical schema
for one backing key and its potential PKCS #11 key aspects. Storage location is
not part of the record, so identical model bytes can be held by a local
provider, the YubiHSM opaque-object provider, or a future FIDO large-blob
provider.

The outer canonical CBOR map is:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.backed-key` |
| `2` | schema version `1` |
| `3` | provider identifier |
| `4` | exact provider-owned backing CBOR, wrapped as a byte string |
| `5` | map from `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`, or `CKO_SECRET_KEY` to an attribute map |

An aspect map uses numeric `CKA_*` values as keys and architecture-independent
CBOR values. Booleans are CBOR booleans, Cryptoki unsigned values and
mechanisms are CBOR unsigned integers, byte attributes are byte strings, text
attributes are text strings, mechanism lists are arrays, and nested attribute
templates are maps using the same representation. Maps are encoded in numeric
key order.

`CKA_CLASS` is represented by the aspect-map key and cannot occur inside an
attribute map. `CKA_TOKEN` is structural and is not encoded in the aspect:
the selected provider supplies the lifetime. The same canonical logical object
can therefore be held in a session memory provider or a slot token provider.
Aspect presence alone does not prove that a provider can reconstruct an
object: each provider must validate the stable material required by its backing
model. The YubiHSM backend, for example, requires a canonical public aspect
containing `CKA_PUBLIC_KEY_INFO`; an empty or identity-only public aspect does
not create a public token object.

The generic layer validates the CBOR representation and the semantic type of
every standard key attribute supported by pkcs11rs. Provider-specific
attributes use byte strings. It retains the provider-owned backing CBOR
byte-for-byte; the named provider owns that embedded schema and its semantic
validation.

The experimental [`previewSign` protocol model](preview-sign.md) supplies two
such canonical schema layers: one for exact registration material and one for
an offline-derived public key plus its algorithm-specific signing arguments.
Those protocol records can be embedded in the backing data of a backed-key
record. The PKCS #11 lifecycle writes those wrappers to the provider selected
by `CKA_TOKEN`; a derived record's registration dependency is stored before the
record that references it.

The generic object layer currently recognizes three provider identifiers:

| Provider | Logical object |
| --- | --- |
| `pkcs11rs.public-key` | RSA or EC public-key projection with normalized public material |
| `pkcs11rs.preview-sign-registration` | imported previewSign registration private object |
| `pkcs11rs.preview-sign-derived` | derived previewSign signing private object |

Unknown well-formed CBOR objects are ignored by PKCS #11 discovery. A record
that declares the `pkcs11rs.backed-key` schema but is malformed is reported as
invalid data rather than silently disappearing.

`ContentReference` is algorithm-tagged for hash agility. The currently
implemented algorithm is SHA3-256. Its canonical CBOR form is the two-element
array:

```text
["sha3-256", h'<32-byte digest>']
```

Decoding rejects indefinite or noncanonical reference encodings, wrong digest
lengths, unsupported algorithm names, and trailing CBOR data.

## Local provider

`LocalStorageProvider::open(root)` creates this layout:

```text
root/
└── objects/
    └── sha3-256-<lowercase digest>.cbor
```

For FIDO configuration, the provider root is derived as:

```text
$PKCS11RS_FIDO2_STORAGE/
└── fido2-v1/
    └── yubico-serial-<lowercase hex UTF-8 serial>/
        └── objects/
            └── sha3-256-<lowercase digest>.cbor
```

Hex encoding makes the physical identity a safe, reversible path component on
every supported platform. The version directory permits a future binding
scheme to coexist without silently reinterpreting an existing store.

Object filenames are derived only from validated references. Listing ignores
temporary files and unrelated non-CBOR files, but treats a malformed
`.cbor` filename or a referenced file with invalid CBOR or mismatched content
as an error rather than silently hiding corruption.

Publishing uses a newly created mode-`0600` temporary file on Unix, writes and
flushes the complete object with `sync_all`, and then creates the final name
with a hard link. The link cannot overwrite an existing immutable object.
Concurrent identical writes are idempotent; different bytes under the same
reference are a conflict. After publication or deletion, the objects directory
is synchronized on Unix so the directory entry reaches durable storage. On
non-Unix systems the file is synchronized, but there is currently no
directory-sync operation.

Deletion removes the content-named file. There are no tombstones, mutable
aliases, garbage collection, or reference tracking. References between future
schema objects can use the algorithm-tagged content reference, but the provider
does not interpret or traverse them.

## YubiHSM backend metadata

YubiHSM implements `StorageProvider` over pkcs11rs-owned opaque-data companion
objects. The provider's logical interface remains immutable and
content-addressed: `list` returns references for canonical records, `get`
returns their exact canonical CBOR, `put` validates and idempotently creates a
matching companion, and `delete` removes the companion identified by a
reference.

The physical records retain YubiHSM's useful back-pointer addressing. They are
labelled for the native target and can be found and understood in
`yubihsm-shell`; content references do not replace that device-level
relationship. Backend-native hardware keys also remain backend-native rather
than being reconstructed by the generic provider decoder.

The provider-owned backing inside the canonical record identifies the native
object by type, ID, sequence, and domains and records its primary PKCS #11 key
class. These fields are checked against the live target and companion label
before a record is accepted. A stale record cannot attach to a newly created
object that reuses the same ID.

Legacy `MDB1` key metadata is decoded into the canonical logical model only as
read-only compatibility input. It is selected only when no metadata in the
pkcs11rs namespace exists for the target. pkcs11rs never writes, rewrites, or
deletes MDB1 companions, including when their target is deleted; their target
sequence makes resulting orphans inert if an object ID is reused.

All new records are canonical CBOR and use the `pkcs11rs metadata 0x...` label.
MDB1 objects retain Yubico's `Meta object for 0x...` label. The separate
namespaces make ownership clear in `yubihsm-shell` listings and prevent
Yubico's PKCS #11 module from treating unfamiliar canonical CBOR as MDB1.

Provider mutation requires a secure session with the applicable YubiHSM
capabilities. Metadata replacement remains failure-safe: the new canonical
companion is written before older pkcs11rs companions are removed, and a later
update repairs ambiguity left by a failed deletion. Legacy companions are not
part of the provider's list, get, put, delete, or replacement lifecycle.
Canonical metadata can contain sparse private-key overrides and a complete
public aspect. Presence of validated public key material creates a genuine
public token object; removing that public object removes only the public aspect
and leaves the hardware private key and unrelated metadata intact.

## Current integration boundary

Provider-backed session object lifecycle is complete for public projections
and previewSign registration and derived-key objects: create/copy or derive,
read, update where permitted, refresh, and destroy all operate through the
session memory provider. The same operations use the slot provider when
`CKA_TOKEN=CK_TRUE`.

Applications can restore an exported previewSign derived private key with
`C_CreateObject` by supplying both its registration and derived-key vendor
attributes. Restoration validates the immutable content reference and the
canonical public key and signing arguments before the object enters either
provider. This manual import path is independent of automatic slot discovery.

YubiHSM installs its native provider and therefore supports persistent public
projections. FIDO slots use `UnavailableStorageProvider` unless
`PKCS11RS_FIDO2_STORAGE` is configured and discovery establishes a validated
Yubico physical serial. A configured slot loads valid backed records while its
`SlotContext` is constructed, so previewSign registration, derived signing
keys, and generic public projections reappear as token objects after
`C_Finalize`/`C_Initialize`. The provider does not invent metadata for ordinary
resident credentials or attach previewSign data to a credential merely because
their identifiers look similar.

Failure is closed: a configured object with a malformed reference, invalid
CBOR, or mismatched content digest prevents that FIDO slot from being
registered. It is never treated as an empty store. An unavailable or
unidentified FIDO slot remains usable for its hardware objects, but
provider-backed `CKA_TOKEN=CK_TRUE` creation returns
`CKR_TOKEN_WRITE_PROTECTED`.

There is no Git, HTTP, cloud, encrypted, or passkey-authenticated provider.
Because local objects are immutable content-named files, an application may
place the store in a separately managed Git repository, but pkcs11rs performs
no Git operations and defines no synchronization or merge policy.

The current token binding uses the validated physical Yubico serial and remains
provisional until positive previewSign hardware qualification. Local files are
not encrypted; access control, backup, synchronization, and private-data
protection are deployment responsibilities. The provider has no garbage
collector, so deleting backed objects can leave unreferenced dependency blobs.
The current PKCS #11 mapping is documented in [Experimental FIDO previewSign
boundary](preview-sign.md).
