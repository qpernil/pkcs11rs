# Named software slots

pkcs11rs can expose independent in-memory software tokens, but only through
explicit configuration:

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
CKF_TOKEN_INITIALIZED`. It has no PIN, login requirement, or protected
authentication path. Without `PKCS11RS_TOKEN_STORAGE`, it has no persistent
token storage.

## Private-key lifecycle

`C_GenerateKeyPair` and `C_CreateObject` accept software private keys only when
`CKA_TOKEN=CK_FALSE`, which is the PKCS #11 default. Each private key belongs
to the session that created it, is usable without login, and is destroyed when
that session closes. Other sessions on the same slot can use the object while
its creator remains open; another named software slot cannot.

Generation and import preserve client-supplied `CKA_LABEL` and `CKA_ID`
exactly. Slot identity comes from `CK_SLOT_INFO` and `CK_TOKEN_INFO`; pkcs11rs
does not replace object labels or IDs with the configured slot name.

A generated private template with `CKA_TOKEN=CK_TRUE` returns
`CKR_FUNCTION_NOT_SUPPORTED`. An imported private template with
`CKA_TOKEN=CK_TRUE` returns `CKR_TEMPLATE_INCONSISTENT`. These failures are
intentional: neither `PKCS11RS_TOKEN_STORAGE` nor any hardware backend is used
as a fallback. Persistent private software keys require a future, separately
configured software-token design.

Generated public counterparts use the shared public-key projection and
operation implementation. Session public keys have the same creator-session
lifetime. When `PKCS11RS_TOKEN_STORAGE` is configured, supported public token
objects are stored below a directory derived from the configured token name
and are restored when that same name is configured again. Without a configured
provider, a requested public token object fails with
`CKR_TOKEN_WRITE_PROTECTED`.

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
