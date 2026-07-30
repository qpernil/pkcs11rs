# Named software slots

pkcs11rs can expose independent software tokens, but only through explicit
configuration:

```sh
export PKCS11RS_SOFTWARE_SLOTS='build signing,key exchange'
```

The comma-separated entries are token names. Leading and trailing whitespace
is removed. Every name must be nonempty, unique, valid UTF-8, and at most 32
bytes. Invalid configuration makes `C_Initialize` return
`CKR_ARGUMENTS_BAD`. When the variable is absent, the module exposes no
software slots.

Each entry creates a separate slot context with separate object handles and
sessions. The name is reported as `CK_TOKEN_INFO.label`; the slot description
is `pkcs11rs software slot: <name>`. The token model is `Software`, the
manufacturer is `pkcs11rs`, and its deterministic serial is `SOFTWARE`
followed by the zero-padded configuration-list ordinal.
`CK_SLOT_INFO.flags` contains only `CKF_TOKEN_PRESENT`; it never contains
`CKF_HW_SLOT`. Mechanism flags never contain `CKF_HW`.

The token has a random-number generator and reports `CKF_RNG |
CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED`. It has no protected
authentication path. Its minimum and maximum PIN lengths are 8 and 1024 UTF-8
bytes.

## Login and PIN initialization

`C_Login(CKU_USER)` is required before private objects can be created, found,
or used. Login state is token-wide, as required by PKCS #11.

Without `PKCS11RS_TOKEN_STORAGE`, login is an ephemeral access gate: any
well-formed PIN in the reported length range succeeds, no verifier is saved,
and persistent token-object requests remain write-protected.

With `PKCS11RS_TOKEN_STORAGE`, the first successful login atomically
initializes the software token:

1. pkcs11rs generates a random 256-bit master key and a random KDF salt.
2. The login PIN derives a wrapping key.
3. The wrapping key encrypts the master key in the first immutable header.

Before initialization, `CKF_USER_PIN_INITIALIZED` is clear. It is set after
the header is published. Simultaneous first logins race to publish the same
header generation; one wins, and the other succeeds only if its PIN unlocks
the winning header.

`C_SetPIN` in a read/write session verifies the old PIN and publishes a new
header wrapping the same master key under the new PIN. It does not rewrite
private-key records. Both PINs must satisfy the 8–1024 byte range. On an
uninitialized persistent token it returns `CKR_USER_PIN_NOT_INITIALIZED`.
`C_InitPIN`, SO login, and `C_InitToken` are not software-slot initialization
paths. A supported `C_SetPIN` attempt clears login state and releases decrypted
state whether it succeeds or fails; log in again with the new PIN after a
successful change.

## Private-key lifecycle

`C_GenerateKeyPair` and `C_CreateObject` accept session software private keys
when `CKA_TOKEN=CK_FALSE`, which is the PKCS #11 default. Each session key
belongs to the session that created it and is destroyed when that session
closes. Other logged-in sessions on the same slot can use it while its creator
remains open; another named software slot cannot.

When `PKCS11RS_TOKEN_STORAGE` is configured, those APIs also accept
`CKA_TOKEN=CK_TRUE`. The encrypted object is visible only after successful
login, survives logout and module or process restart, and is removed durably by
`C_DestroyObject`. Without storage, the same request returns
`CKR_TOKEN_WRITE_PROTECTED`.

Generation and import preserve client-supplied `CKA_LABEL` and `CKA_ID`
exactly. Slot identity comes from `CK_SLOT_INFO` and `CK_TOKEN_INFO`; pkcs11rs
does not replace object labels or IDs with the configured slot name.

Generated public counterparts use the shared public-key projection and
operation implementation. Session public keys have the same creator-session
lifetime. When `PKCS11RS_TOKEN_STORAGE` is configured, supported public token
objects are stored below a directory derived from the configured token name
and are restored when that same name is configured again. Without a configured
provider, a requested public token object fails with
`CKR_TOKEN_WRITE_PROTECTED`.

Private key material and the unwrapped master key are held only while the
token is logged in. `C_Logout`, closing the last session, `C_CloseAllSessions`,
module finalization, failed login/loading, and PIN-change error paths release
that material and clear active private-key operations.

## Encrypted storage format

Persistent private records use envelope encryption. A PIN is not applied
independently to every PKCS #8 key:

- PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 16-byte salt derives
  a 256-bit wrapping key.
- AES-256-GCM with a random 12-byte nonce and a 128-bit tag wraps the random
  256-bit master key.
- Each private record uses AES-256-GCM with a fresh 12-byte nonce and the
  master key.
- Header and record associated data include the configured software-token
  name and format context, preventing ciphertext from being moved between
  names.

Headers and record envelopes are strict canonical CBOR with explicit schema,
version, KDF, AEAD, and parameter identifiers. The complete plaintext of each
record is DER-encoded PKCS #8 `OneAsymmetricKey` version 0:

- the algorithm-specific private key is the normal PKCS #8 private-key value;
- PKCS #9 `friendlyName` mirrors `CKA_LABEL` when it fits the standard
  BMPString syntax;
- PKCS #9 `localKeyId` mirrors `CKA_ID`; and
- private OID `2.25.143450012756208704387410405620256874559` contains a
  canonical versioned encoding of all authoritative PKCS #11 attributes,
  including the exact label and ID.

The private attribute preserves labels outside PKCS #9's BMPString range.
Conflicting, duplicate, unknown, noncanonical, or malformed attributes are
rejected. This inner object can be used as the plaintext of a standard
`EncryptedPrivateKeyInfo` export in the future; this release does not add a
private-key export ABI.

An incorrect login PIN, or corruption that prevents authentication of the
wrapped master key, returns `CKR_PIN_INCORRECT` without exposing which case
occurred. Structurally malformed headers and malformed or unauthentic private
records fail closed with `CKR_DATA_INVALID`. If records exist but the header is
missing, pkcs11rs refuses to initialize a replacement master key.

## Durability and concurrency

The private directory and its subdirectories are mode `0700` on Unix; header
and record files are mode `0600`. New immutable files are written under unique
temporary names, flushed, atomically published with a hard link, and followed
by a directory sync. Deletes are also followed by a directory sync.

PIN changes use monotonically increasing immutable header generations. The
new generation is published durably before older generations are removed.
After a crash, either the old header remains current or the new, higher
generation wins; a partially written header is never selected.

Record files are immutable and content-addressed. Concurrent identical reads
are safe. Concurrent creates publish distinct nonce-bearing records.
Concurrent deletion or PIN changes are first-writer-wins at their atomic
publication point; another process may retain already-unlocked key material
until its own logout or teardown, and sees filesystem changes after its next
login/reload.

## Supported keys and operations

The private-key material and cryptographic operations are the shared typed
implementations also used by the module's projection code; the software-slot
backend does not duplicate cryptography.

- RSA: 1024 through 4096 bits in 256-bit increments; PKCS #1 v1.5, raw RSA,
  OAEP decryption, PKCS #1 signatures, and PSS signatures.
- Weierstrass EC: NIST P-224, P-256, P-384, P-521, secp256k1,
  brainpoolP256r1, brainpoolP384r1, and brainpoolP512r1; ECDSA and ECDH.
- Edwards: Ed25519 signing.
- Montgomery: X25519 key agreement.

The slot advertises these exact mechanism groups:

| Mechanisms | Key-size range | Flags |
| --- | ---: | --- |
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | 1024–4096 | `CKF_GENERATE_KEY_PAIR` |
| `CKM_RSA_X_509`, `CKM_RSA_PKCS` | 1024–4096 | `CKF_ENCRYPT \| CKF_DECRYPT \| CKF_SIGN \| CKF_VERIFY` |
| `CKM_RSA_PKCS_OAEP` | 1024–4096 | `CKF_ENCRYPT \| CKF_DECRYPT` |
| `CKM_RSA_PKCS_PSS`, hashed RSA PKCS and PSS variants for SHA-1, SHA-2, and SHA-3 | 1024–4096 | `CKF_SIGN \| CKF_VERIFY` |
| `CKM_EC_KEY_PAIR_GEN` | 224–521 | `CKF_GENERATE_KEY_PAIR \| CKF_EC_F_P \| CKF_EC_NAMEDCURVE` |
| `CKM_ECDSA` and hashed ECDSA variants for SHA-1, SHA-2, and SHA-3 | 224–521 | `CKF_SIGN \| CKF_VERIFY \| CKF_EC_F_P \| CKF_EC_NAMEDCURVE` |
| `CKM_ECDH1_DERIVE`, `CKM_ECDH1_COFACTOR_DERIVE` | 224–521 | `CKF_DERIVE` |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | 255 | `CKF_GENERATE_KEY_PAIR \| CKF_EC_NAMEDCURVE \| CKF_EC_CURVENAME` |
| `CKM_EDDSA` | 255 | `CKF_SIGN \| CKF_VERIFY` |
| `CKM_PKCS11RS_PROJECT_PUBLIC_KEY` | 0 | `CKF_DERIVE` |
| SHA-1, SHA-2, and SHA-3 digest mechanisms | 0 | `CKF_DIGEST` |

The numeric range is the envelope representable by `C_GetMechanismInfo`;
`CKA_EC_PARAMS` selects and validates the exact named curve.
