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

For a software-focused process, set `PKCS11RS_HARDWARE_DISCOVERY=0`. This
prevents automatic local USB, HID, and PC/SC/CCID discovery without affecting
the named software slots. Explicit `PKCS11RS_YUBIHSM_URLS` HTTP(S) connectors
also remain enabled because they are opt-in rather than locally discovered.
The only accepted hardware-discovery values are `0` and `1`.

Each entry creates a separate slot context with separate object handles and
sessions. The name is reported as `CK_TOKEN_INFO.label`; the slot description
is `pkcs11rs software slot: <name>`. The token model is `Software`, the
manufacturer is `pkcs11rs`, and its deterministic serial is `SOFTWARE`
followed by the zero-padded configuration-list ordinal.
`CK_SLOT_INFO.flags` contains only `CKF_TOKEN_PRESENT`; it never contains
`CKF_HW_SLOT`. Mechanism flags never contain `CKF_HW`.

The token reports `CKF_RNG | CKF_LOGIN_REQUIRED`. `C_InitToken` sets
`CKF_TOKEN_INITIALIZED`; the first `C_InitPIN` separately sets
`CKF_USER_PIN_INITIALIZED`. Software tokens have no protected authentication
path. PINs contain 8–1024 UTF-8 bytes.

## Login and PIN initialization

`C_Login(CKU_USER)` is required before private objects can be created, found,
or used. Login state is token-wide, as required by PKCS #11.

Without `PKCS11RS_TOKEN_STORAGE`, login is an ephemeral access gate: any
well-formed PIN in the reported length range succeeds, no verifier is saved,
and persistent token-object requests remain write-protected.

With storage, `C_InitToken` creates the public realm, records the supplied
32-byte label, and sets the SO PIN. With no sessions open, the caller then
opens a read/write session, logs in as SO, and calls `C_InitPIN`; this creates
an independent private master key and USER wrappers for both realms. A later
`C_InitPIN` is rejected because SO deliberately cannot unwrap the private key.
A lost USER PIN therefore requires destructive `C_InitToken` reinitialization.
Reinitialization requires the current SO PIN, is rejected while any session is
open, destroys both public and private token objects, replaces the public
master key, and returns the token to the state before its first `C_InitPIN`.

SO login unlocks only public objects. USER login unlocks public and private
objects. `C_SetPIN` preserves login: SO rewraps only the public key, while USER
rewraps both keys. It never rewrites object records.

Pre-login discovery is configured per slot with
`PKCS11RS_SOFTWARE_DISCOVERY_<HEXNAME>`, where `<HEXNAME>` is the uppercase hex
encoding of the slot name's UTF-8 bytes. Discovery is read-only and unwraps
only the public key. Without it, logout returns to profile objects only; with
it, logout restores the encrypted public-object view. The credential must be
configured when `C_InitToken` creates the token. Changing or adding it later
cannot unwrap that token's public master key; reinitialize the token to adopt
the new credential. A missing or incorrect discovery credential never blocks
SO or USER login.


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

Private key material and the unwrapped private master key are held only while
the USER role is logged in. `C_Logout`, closing the last session,
`C_CloseAllSessions`, module finalization, and failed login/loading release
that material and clear active private-key operations. PIN changes preserve
the authenticated role and its already-unwrapped keys.

## Encrypted storage format

Persistent private records use envelope encryption. A PIN is not applied
independently to every PKCS #8 key:

- PBKDF2-HMAC-SHA-256 with 10,000 iterations and independent salts derives
  discovery, SO, and USER wrapping keys.
- AES-256-GCM wraps independent random public and private master keys. SO and
  discovery have only public wrappers; USER has both.
- Public provider records and private records use fresh AES-256-GCM nonces
  under their respective master keys.
- Header and record associated data include the configured software-token
  name and format context, preventing ciphertext from being moved between
  names.

Headers and record envelopes are strict canonical CBOR with explicit schema,
version, KDF, AEAD, and parameter identifiers. Development-era formats have no
migration or compatibility path.

The complete plaintext of each record is DER-encoded PKCS #8
`OneAsymmetricKey` version 0:

- the algorithm-specific private key is the normal PKCS #8 private-key value;
- PKCS #9 `friendlyName` mirrors `CKA_LABEL` when it fits the standard
  BMPString syntax;
- PKCS #9 `localKeyId` mirrors `CKA_ID`; and
- private OID `2.25.143450012756208704387410405620256874559` contains a
  canonical versioned encoding of all authoritative PKCS #11 attributes,
  including the exact label and ID.

The private attribute preserves labels outside PKCS #9's BMPString range.
Conflicting, duplicate, unknown, noncanonical, or malformed attributes are
rejected.

## Password-encrypted PKCS #8 export

The low-level `PKCS11RS_SoftwareExportPrivateKey` extension exports an
extractable software private key as a DER-encoded PKCS #8
`EncryptedPrivateKeyInfo`. It is deliberately not part of the standard
PKCS #11 function table.

The selected session must belong to a named software slot and have an active
`CKU_USER` login. The target must be a visible software private key with
`CKA_EXTRACTABLE=CK_TRUE`. A false `CKA_EXTRACTABLE` returns
`CKR_KEY_UNEXTRACTABLE`; a hardware or applet slot returns
`CKR_FUNCTION_NOT_SUPPORTED`. This extension does not enable software private
keys or export on any hardware or applet slot.

The export password is supplied directly to the extension and can be the same
bytes the caller passed to `C_Login` if that is the desired interface. It is
not recovered from or retained by the login implementation. It must contain
8–1024 bytes. The output uses:

- PBES2;
- scrypt with `N=16384`, `r=8`, `p=1`, and a fresh 16-byte salt; and
- AES-256-CBC with a fresh 16-byte IV.

The encrypted plaintext is the complete attributed `OneAsymmetricKey`
described above, so caller-supplied `CKA_LABEL` and `CKA_ID` remain available
in its PKCS #9 and private attributes. Consumers which do not understand the
private pkcs11rs OID can still import and use the standard key material.
OpenSSL's `pkey` decode/re-encode path retains that key material but emits a
new PKCS #8 object without the input attributes. Consequently, a key
round-tripped through OpenSSL must be given its label, ID, and other PKCS #11
policy attributes again when it is imported. Copying the encrypted DER
unchanged retains all attributes.

The function follows the normal PKCS #11 output convention: pass
`pEncryptedKey=NULL` to query the DER length. A short buffer returns
`CKR_BUFFER_TOO_SMALL` and the required length.

For example, after writing the returned bytes to `exported-key.der`, OpenSSL 3
can inspect the envelope and import the key:

```sh
openssl asn1parse -inform DER -in exported-key.der -i
openssl pkey -inform DER -in exported-key.der -passin pass:'export password' \
  -out imported-key.pem
openssl pkey -in imported-key.pem -check -text -noout
```

An incorrect login PIN, or corruption that prevents authentication of the
wrapped master key, returns `CKR_PIN_INCORRECT` without exposing which case
occurred. Structurally malformed headers and malformed or unauthentic private
records fail closed with `CKR_DATA_INVALID`. If records exist but the header is
missing, pkcs11rs refuses to initialize a replacement master key.

## Durability and concurrency

The private directory and its subdirectories are mode `0700` on Unix; header
and record files are mode `0600`. New immutable files are written under unique
temporary names, flushed, atomically published with a hard link, and followed
by a directory sync. Deletes are also followed by a directory sync. Persistent
software-token storage requires a filesystem with hard-link support; local
NTFS, APFS, and common Linux filesystems are suitable, while removable
filesystems such as exFAT and network filesystems are not assumed to be.

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
