# Software secret keys, derivation, and wrapping

Named software slots provide AES, 3DES, generic-secret, and hash-specific HMAC
keys as session objects or encrypted private token objects. The user-facing
mechanism and lifecycle contract is defined in [`software.md`](software.md).

## Object and storage model

`KeyMaterial::SoftwareSecret` separates software-owned secret bytes from
transient and backend-imported material. Secret bytes, local cipher schedules,
MAC state, derived material, unwrap plaintext, and ephemeral wrapping keys use
zeroizing storage.

Session keys belong to their creating PKCS #11 session and disappear when that
session closes. Token keys require `CKA_TOKEN=CK_TRUE`,
`CKA_PRIVATE=CK_TRUE`, user login, and configured `PKCS11RS_TOKEN_STORAGE`.
Their canonical records are encrypted and authenticated under the USER-only
private master key. Publication is atomic: durable storage succeeds before a
handle becomes visible. Storage failure returns an error and never changes a
requested token object into a session object.

Logout, last-session close, `C_CloseAllSessions`, and `C_Finalize` release
loaded private material and cancel operations that hold it. Login and module
initialization restore eligible private token objects from the encrypted store.
Destruction removes the durable record and the live object.

## Symmetric and MAC operations

Software AES keys support ECB, CBC, CBC-PAD, CTR, CCM, GCM, key wrap, KWP,
CMAC, CMAC-GENERAL, and GMAC. Software 24-byte 3DES keys support generation,
ECB, CBC, and CBC-PAD. Generic and hash-specific HMAC keys support one-shot and
multipart SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 signing and
verification, including the corresponding `*_HMAC_GENERAL` mechanisms.

The mechanisms are advertised without `CKF_HW`. Length queries, short-buffer
handling, multipart state, padding validation, authenticated-decryption
failure, and terminal-operation cleanup follow the ordinary PKCS #11 operation
lifecycle.

## Key generation, import, copy, and derivation

Generation, import, copy, ECDH, Montgomery-curve agreement, HKDF, PBKDF2, and
unwrap output share one typed materialization boundary. It validates class, key type, length,
lifetime, privacy, usage, sensitivity, extractability, and policy templates;
constructs zeroizing key material; publishes either a session or token object;
and returns a handle only after the complete operation succeeds.

ECDH supports `CKD_NULL` and the SHA-1, SHA-2, and SHA-3 ANSI X9.63 KDFs with
optional shared data and multi-block expansion. Software Weierstrass, X25519,
and X448 private keys, PIV, OpenPGP, and YubiHSM sources use the same host-side output
materialization rules after their respective private-key operations.

HKDF supports SHA-1, SHA-256, SHA-384, and SHA-512 in extract-only,
expand-only, and extract-and-expand modes, with null, byte-string, or
key-object salt and caller-supplied `info`. PBKDF2 supports the standard HMAC
PRFs exposed by the module. Derivation can produce generic, AES, 3DES, or
hash-specific HMAC session keys and private token keys where the mechanism
permits that output.

Derived objects inherit the required sensitivity and extractability state from
their base key. They report `CKA_LOCAL=CK_FALSE` and identify the derivation
mechanism through `CKA_KEY_GEN_MECHANISM`.

## Wrapping and unwrapping

AES keys support RFC 3394 AES-KW and RFC 5649 AES-KWP. Software RSA keys
support PKCS #1 v1.5, OAEP, and hybrid `CKM_RSA_AES_KEY_WRAP`. The hybrid form
uses an ephemeral AES key, AES-KWP for the target, RSA-OAEP for the ephemeral
key, and the standard concatenated Cryptoki representation.

Eligible secret keys and extractable software asymmetric private keys can be
wrapped. Private keys use canonical bare PKCS #8 inside padded or hybrid
wrapping formats. Unwrap authenticates and validates the complete input before
creating an object, rejects noncanonical or attributed private-key encodings,
checks the requested key type, and treats the unwrap template as authoritative
for identity and policy. Failure leaves no object, handle, or plaintext behind.

## Policy

Software keys persist and enforce `CKA_ALLOWED_MECHANISMS`,
`CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE`, and
`CKA_WRAP_WITH_TRUSTED`. Mechanism lists are canonical and duplicate-free.
Template-valued attributes use owned, platform-independent semantic maps with
strict conflict handling. Every operation validates the active mechanism and
applicable policy before using key material or publishing persistent state.

Trusted wrapping keys require trusted-object administration, which is outside
the supported software-token administration surface. A target marked
`CKA_WRAP_WITH_TRUSTED=CK_TRUE` therefore fails closed when no trusted wrapping
key is available. Master-key cycling is also an external maintenance concern;
`C_SetPIN` rotates credential wrappers without rewriting stored private
objects.

## Qualification

Qualification covers Rust unit and PKCS #11 entry-point tests, shared-library
tests, native loading on Windows, Linux, and macOS, restart and durability
tests, malformed and unauthentic storage tests, and published AES, HMAC,
ECDH/X9.63, HKDF, AES-KW, and AES-KWP vectors.
