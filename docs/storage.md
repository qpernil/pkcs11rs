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

The experimental [`previewSign` protocol model](preview-sign.md) supplies two
such canonical schema layers: one for exact registration material and one for
an offline-derived public key plus its algorithm-specific signing arguments.
Neither schema is automatically written to a provider.

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

Future integration must still define configuration, ownership and deletion
semantics, token binding, private-data protection, and the PKCS #11 mapping
before stored FIDO registration material can become a token or session object.
