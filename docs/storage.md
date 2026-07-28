# Content-addressed CBOR storage

The public `storage` module defines persistence infrastructure intended for a
future hybrid FIDO hardware/software slot. It is usable as a standalone Rust
API today, but it is not connected to PKCS #11 slot discovery, an environment
variable, resident-credential enumeration, or any signing mechanism.

## Provider boundary

`StorageProvider` is a `Send + Sync` trait with four operations:

- `list` returns all valid content references in stable order;
- `get` retrieves an object and verifies its content hash;
- `put` stores one CBOR item idempotently and returns its reference;
- `delete` removes one referenced object and reports whether it existed.

Providers treat object bytes as opaque. `put` verifies that the input contains
exactly one well-formed CBOR data item, but does not decode, re-encode,
deduplicate fields, or impose a schema. A future schema layer must produce any
required canonical representation before storing it. The exact submitted bytes
are what the content hash identifies and what `get` returns.

## Backed-key metadata

The public `key_metadata` module defines the provider-neutral canonical schema
for one backing key and its potential PKCS #11 key aspects. Storage location is
not part of the record, so identical model bytes can be held by a local
provider, a future YubiHSM opaque-object provider, or a future FIDO large-blob
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
attribute map. `CKA_TOKEN` is also structural: a persisted aspect is a token
object, while a session aspect is never submitted to a provider. Presence of
an empty public aspect therefore means that a public token projection exists
and obtains all of its attributes from the backing provider.

The generic layer validates the CBOR representation and the semantic type of
every standard key attribute supported by pkcs11rs. Provider-specific
attributes use byte strings. It retains the provider-owned backing CBOR
byte-for-byte; the named provider owns that embedded schema and its semantic
validation.

The experimental [`previewSign` protocol model](preview-sign.md) supplies two
such canonical schema layers: one for exact registration material and one for
an offline-derived public key plus its algorithm-specific signing arguments.
Those protocol records can be embedded in the backing data of a backed-key
record. Neither schema is automatically written to a provider.

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

## Current integration boundary

No storage path is read from configuration, and constructing a provider does
not create a PKCS #11 slot. The FIDO2 backend continues to expose only
credential-management response bytes obtained from an inserted authenticator
after PIN login. It does not persist those responses or registration material.

There is no Git, HTTP, cloud, encrypted, or passkey-authenticated provider.
Because local objects are immutable content-named files, an application may
place the store in a separately managed Git repository, but pkcs11rs performs
no Git operations and defines no synchronization or merge policy.

Future previewSign integration must still define configuration, ownership and
deletion semantics, token binding, private-data protection, and the PKCS #11
mapping before stored FIDO registration material can become a token or session
object. YubiHSM integration will use the same backed-key schema for metadata
opaque objects and translate legacy `MDB1` values to the canonical schema when
they are read.
