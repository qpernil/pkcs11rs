# Software AES, HMAC, derivation, and wrapping plan

Status: implementation roadmap. Completed work is called out below; later
phases still describe planned behavior.

This work is also the first design probe for the
[pure Rust provider abstraction](provider-abstraction-plan.md). New AES, HMAC,
derivation, and wrapping paths should prefer typed internal requests that can
be shared by the software and YubiHSM providers without exposing additional
PKCS #11 types through the backend boundary.

## Implemented foundation

Persistent software tokens now start with `C_InitToken` and use independent
public and private master keys. Discovery and SO credentials unwrap only the
public key; the USER credential unwraps both. Initial `C_InitPIN` creates the
private realm and cannot later be used by SO to recover a lost USER
credential. Optional per-slot discovery restores encrypted public objects
before login. Secret keys added by this plan must remain exclusively in the
private realm.

The object-model boundary for secret-key work is also implemented:
`KeyMaterial::SoftwareSecret` is distinct from transient and backend-import
secret material, `CKA_WRAP` and `CKA_UNWRAP` have explicit object fields, and
named software slots have a separate secret-operation capability. Its
mechanism set is populated only as complete operation paths are added. Existing
asymmetric storage records are unchanged.

Phase 2 session keys are implemented. Named software slots can generate or
import AES, generic, and hash-specific HMAC session keys. AES supports ECB,
CBC, CBC-PAD, CTR, CCM, GCM, key wrap, KWP, CMAC, CMAC-GENERAL, and GMAC;
HMAC supports one-shot and multipart SHA-1, SHA-256, SHA-384, and SHA-512
signing and verification. All corresponding mechanisms are advertised without
`CKF_HW`. Local cipher and MAC key schedules and intermediate plaintext copies
are zeroized.

Phase 3 persistence is also implemented. Private token AES and HMAC keys use a
distinct canonical secret record encrypted under the USER-only private master
key. Generation, import, copy, restoration, logout unloading, and durable
destruction share the asymmetric private-object storage boundary. Token secret
keys require `CKA_PRIVATE=CK_TRUE`; without configured storage their creation
fails with `CKR_TOKEN_WRITE_PROTECTED` and never falls back to session memory.

## Future master-key cycling

Add a non-PKCS #11 maintenance operation for explicit key rotation. Public
cycling rewrites every public envelope and the discovery, SO, and USER public
wrappers. Private cycling requires USER authorization, rewrites every private
envelope, and replaces only the USER private wrapper. Publish through a new
epoch/generation so interruption leaves a complete old or new realm. SO and
discovery must never participate in private cycling; `C_SetPIN` remains a
wrapper-only operation.

## Objective

Extend named software slots so AES and HMAC keys have the same lifecycle as
the existing software asymmetric keys:

- session keys stored in memory and owned by their creator session;
- encrypted persistent token keys when `PKCS11RS_TOKEN_STORAGE` is configured;
- login-gated access to private material;
- durable destruction;
- restoration after logout/login, module reinitialization, and process
  restart; and
- no fallback from a requested token object to session memory.

Once that foundation exists, use it for typed key derivation and standard key
wrapping and unwrapping.

## Existing foundation

The repository already contains most of the required primitives:

- `KeyMaterial::Secret` and `KeyMaterial::DerivedSecret` hold zeroizing byte
  strings, but they are not a complete software-secret-key lifecycle.
- `C_GenerateKey` can create a generic session secret in selected existing
  paths.
- `C_CreateObject` can parse AES and HMAC key material.
- AES mode parameter validation and AES ECB, CBC, CBC-PAD, CTR, CCM, GCM,
  key-wrap, KWP, CMAC, and GMAC logic exist for YubiHSM-backed operations.
- HMAC sign and verify dispatch exists for YubiHSM keys.
- ECDH and X25519 derivation already produce a session
  `KeyMaterial::DerivedSecret`.
- The software token store already provides PIN-wrapped public and private
  master keys, per-record AES-256-GCM encryption, canonical encoding, atomic
  publication, durable deletion, and login/logout loading boundaries.

The main gaps are object typing, capability advertisement, local operation
dispatch, and routing secrets through the encrypted software-token store.

## Design principles

1. Software secret-key capability must be explicit. Hardware and applet slots
   must not acquire a software AES or HMAC fallback merely because the module
   implements one.
2. AES and HMAC keys are `CKO_SECRET_KEY` objects. Their `CKA_KEY_TYPE`
   determines validation and permitted mechanisms.
3. Generation, import, derivation, copying, and unwrapping must use one common
   materialization path.
4. That path must decide session versus token lifetime before publishing an
   object handle.
5. Secret bytes, intermediate plaintexts, derived values, and ephemeral
   wrapping keys must be zeroized.
6. Persistent secret records must use the existing software token's master
   key and durability model.
7. A failed persistent operation must leave neither an object handle nor a
   partially published record.
8. Existing asymmetric private-key records should remain unchanged. Secret
   keys should use a separate, explicitly identified record payload.

## Target lifetime behavior

| Lifetime | `CKA_TOKEN` | Required behavior |
| --- | ---: | --- |
| Session | `CK_FALSE` | Store in memory, assign creator-session ownership, and destroy when that session closes |
| Token with configured storage | `CK_TRUE` | Encrypt under the token master key, publish durably, restore after login, and delete durably |
| Token without configured storage | `CK_TRUE` | Return `CKR_TOKEN_WRITE_PROTECTED` |

Persistent secret keys should initially require `CKA_PRIVATE=CK_TRUE`, matching
the current login-gated software-token loading boundary. Supporting public
persistent secret objects can be considered later if token objects can be
loaded independently of private login state.

## Phase 1: software secret-key object model

### Material type

Add an explicit material variant such as:

```text
KeyMaterial::SoftwareSecret(Zeroizing<Vec<u8>>)
```

Do not use `KeyMaterial::Secret` indiscriminately. That variant currently
serves transient and backend-import paths, and its extractability behavior is
not specific enough for persisted software keys.

The `TokenObject` class and key type remain authoritative:

- `CKK_AES` accepts exactly 16, 24, or 32 bytes.
- `CKK_GENERIC_SECRET` accepts a bounded, nonempty byte string.
- `CKK_SHA_1_HMAC`, `CKK_SHA256_HMAC`, `CKK_SHA384_HMAC`, and
  `CKK_SHA512_HMAC` accept bounded, nonempty byte strings.

### Attributes

Make the following attributes consistent for software secret keys:

- `CKA_VALUE`
- `CKA_VALUE_LEN`
- `CKA_PRIVATE`
- `CKA_SENSITIVE`
- `CKA_EXTRACTABLE`
- `CKA_ALWAYS_SENSITIVE`
- `CKA_NEVER_EXTRACTABLE`
- `CKA_LOCAL`
- `CKA_KEY_GEN_MECHANISM`
- `CKA_ENCRYPT`
- `CKA_DECRYPT`
- `CKA_SIGN`
- `CKA_VERIFY`
- `CKA_DERIVE`
- `CKA_WRAP`
- `CKA_UNWRAP`

Add explicit `wrap` and `unwrap` fields to `TokenObject` and
`TokenObjectTemplate`. The current `can_wrap` and `can_unwrap` behavior is
derived only from YubiHSM capabilities and cannot represent a software AES
wrapping key.

Generated secret keys should default to sensitive and nonextractable. Imported,
derived, copied, and unwrapped objects must follow Cryptoki's attribute
transition and inheritance rules. `CKA_VALUE` must never be returned when the
object's sensitivity or extractability policy forbids it.

### Capability boundary

Add a capability separate from generic software asymmetric operations, for
example:

```text
supports_software_secret_operations()
```

Named software slots enable it. Hardware and applet slots do not, unless a
backend explicitly supplies its own native AES or HMAC mechanisms.

## Phase 2: AES and HMAC session operations

### Mechanisms

Advertise the following mechanisms on named software slots without `CKF_HW`:

- `CKM_AES_KEY_GEN`
- `CKM_AES_ECB`
- `CKM_AES_CBC`
- `CKM_AES_CBC_PAD`
- `CKM_AES_CTR`
- `CKM_AES_CCM`
- `CKM_AES_GCM`
- `CKM_AES_CMAC`
- `CKM_AES_CMAC_GENERAL`
- `CKM_AES_GMAC`
- `CKM_AES_KEY_WRAP`
- `CKM_AES_KEY_WRAP_KWP`
- `CKM_GENERIC_SECRET_KEY_GEN`
- `CKM_SHA_1_HMAC`
- `CKM_SHA256_HMAC`
- `CKM_SHA384_HMAC`
- `CKM_SHA512_HMAC`

The corresponding `_HMAC_GENERAL` mechanisms can be included in this phase if
truncated HMAC is wanted immediately; otherwise they form a small follow-up.

### Generation and import

Extend `C_GenerateKey`:

- `CKM_AES_KEY_GEN` creates AES-128, AES-192, or AES-256 according to
  `CKA_VALUE_LEN`.
- `CKM_GENERIC_SECRET_KEY_GEN` creates generic or hash-specific HMAC keys.
- Entropy comes from `getrandom`.
- Caller-supplied label, ID, lifetime, privacy, usage, sensitivity, and
  extractability attributes are validated and retained.

Extend `C_CreateObject` so imported AES and HMAC material becomes
`SoftwareSecret`, with strict class, key-type, size, and usage validation.

### AES execution

Refactor the existing AES code so its mode implementations accept either:

- YubiHSM block-operation callbacks; or
- local AES-128, AES-192, or AES-256 block operations.

Reuse the current ECB, CBC, CBC-PAD, CTR, CCM, GCM, KW, KWP, CMAC, and GMAC
logic rather than implementing separate software-only modes.

Maintain existing one-shot, multipart, length-query, short-buffer, padding,
and authenticated-decryption behavior. Authentication failure must not return
unauthenticated plaintext.

### HMAC execution

Extend `C_Sign`, `C_SignUpdate`, `C_SignFinal`, `C_Verify`,
`C_VerifyUpdate`, and `C_VerifyFinal` for local HMAC keys.

Use the existing `hmac`, SHA, and `subtle` dependencies:

- perform constant-time verification;
- support output-length queries;
- reject incorrect MAC lengths distinctly from incorrect MAC values; and
- clear operation state on success, failure, logout, session close, and
  finalization.

No new Cargo dependency is expected for this phase.

## Phase 3: encrypted token persistence

Implemented for generated, imported, and copied AES and HMAC keys. Future
derivation and unwrapping paths must enter the same publication boundary.

Generalize the software-store backend operations conceptually from:

```text
store_software_private_key
destroy_software_private_key
```

to:

```text
store_software_private_object
destroy_software_private_object
```

Both asymmetric private keys and secret keys use this boundary.

### Secret record

Keep existing asymmetric PKCS #8 plaintext records unchanged. Add a distinct
canonical secret-key plaintext containing:

- a secret-record schema identifier;
- a format version;
- authoritative stored PKCS #11 attributes;
- an explicit material kind; and
- the raw secret bytes.

Encrypt the complete plaintext with the existing per-token master key and a
fresh AES-256-GCM nonce. Bind at least the token name, record schema, record
version, and material kind into associated data.

The decoder must:

- authenticate before parsing plaintext;
- reject noncanonical or trailing encodings;
- reject class, key-type, length, and attribute mismatches;
- zeroize plaintext on all paths; and
- assign a stable record-derived unique ID.

### Lifecycle routing

Audit all object-producing and object-changing entry points:

- `C_GenerateKey`
- `C_CreateObject`
- `C_CopyObject`
- `C_DestroyObject`
- `C_SetAttributeValue`
- `C_DeriveKey`
- `C_WrapKey`
- `C_UnwrapKey`

Any operation requesting `CKA_TOKEN=CK_TRUE` must publish through the encrypted
store before returning a handle. A storage failure must not fall back to a
session object.

Logout, last-session close, `C_CloseAllSessions`, and finalization must release
loaded persistent secret material and cancel operations holding cloned key
material.

## Phase 4: common derived-key materialization

Create one internal helper that accepts:

```text
validated output template + Zeroizing<derived bytes> + source policy
```

It must:

1. validate the requested output class, key type, length, and usage;
2. calculate inherited sensitivity and extractability attributes;
3. construct `SoftwareSecret`;
4. set `CKA_LOCAL=CK_FALSE`;
5. set `CKA_KEY_GEN_MECHANISM` to the derivation mechanism;
6. validate login and read/write-session requirements;
7. create either a session or token object; and
8. publish the handle only after the operation is complete.

Generation, import, and unwrapping should use the same lower-level session or
token publication helper, so lifetime semantics cannot diverge.

## Phase 5: typed ECDH derivation

Refactor the current ECDH path so its output template may request:

- `CKK_GENERIC_SECRET`
- `CKK_AES`
- `CKK_SHA_1_HMAC`
- `CKK_SHA256_HMAC`
- `CKK_SHA384_HMAC`
- `CKK_SHA512_HMAC`

Honor `CKA_VALUE_LEN`, `CKA_TOKEN`, privacy, sensitivity, extractability, and
usage attributes. Remove the current behavior that rejects token output and
then forces every derived key to be public, extractable, and generic.

Continue supporting all existing ECDH sources:

- software Weierstrass keys;
- software X25519 keys;
- PIV;
- OpenPGP; and
- YubiHSM.

The backend performs the private-key operation. Host software validates and
materializes the returned shared secret.

### ECDH KDFs

Implement in order:

1. `CKD_NULL`;
2. SHA-1 and SHA-2 X9.63 KDF variants;
3. SHA-3 X9.63 KDF variants; and
4. shared-data handling.

KDF output must be expanded or truncated exactly as Cryptoki specifies for the
requested `CKA_VALUE_LEN`. Tests must use published algorithm vectors rather
than round trips alone.

`CKM_ECDH1_COFACTOR_DERIVE` remains invalid for X25519.

## Phase 6: HKDF

Implement `CKM_HKDF_DERIVE` using the existing `hkdf` dependency:

- SHA-1, SHA-256, SHA-384, and SHA-512;
- extract-only;
- expand-only;
- extract-and-expand;
- salt supplied as bytes or by key handle;
- caller-supplied `info`; and
- generic, AES, or HMAC output objects.

The base key must have `CKA_DERIVE=CK_TRUE`, belong to the selected slot, be
visible in the current login state, and permit the requested mechanism.

This phase enables persistent generic base secrets to derive independent
session or persistent encryption and MAC keys without exposing the base or
derived bytes.

## Phase 7: AES wrapping and unwrapping

Implement standard `C_WrapKey` and `C_UnwrapKey` support for software keys:

- `CKM_AES_KEY_WRAP` using RFC 3394;
- `CKM_AES_KEY_WRAP_KWP` using RFC 5649; and
- `CKM_AES_KEY_WRAP_PAD` as a compatible padded alias if required.

Reuse the KW and KWP implementation already used by AES encrypt/decrypt.

Initially scope the wrapped target to software secret keys. Their raw
key-value representation is unambiguous and interoperable.

### Wrapping validation

Require:

- a visible wrapping key from the selected slot;
- `CKA_WRAP=CK_TRUE`;
- a compatible AES key and mechanism;
- a visible target key from the selected slot;
- `CKA_EXTRACTABLE=CK_TRUE`;
- `CKA_NEVER_EXTRACTABLE=CK_FALSE`; and
- compliance with `CKA_ALLOWED_MECHANISMS` when present.

Support the normal output-length query and short-buffer behavior. Secret
plaintext must be zeroized after wrapping.

### Unwrapping validation

Require:

- a visible unwrapping key from the selected slot;
- `CKA_UNWRAP=CK_TRUE`;
- a compatible AES key and mechanism; and
- a valid, unique output template.

Authenticate and validate the wrapped value before creating an object. Route
the resulting bytes through the common secret-key materializer so the caller
can request session or encrypted token lifetime.

A failed integrity check, invalid template, or failed token-store publication
must leave no object, handle, or plaintext behind.

## Phase 8: RSA and hybrid wrapping

### Direct RSA wrapping

Support software RSA keys with:

- `CKM_RSA_PKCS`; and
- `CKM_RSA_PKCS_OAEP`.

Use public RSA keys for wrapping and private RSA keys for unwrapping. Reuse the
existing OAEP parameter parsing, validation, padding, and unpadding code.

Initially limit direct RSA wrapping to secret keys which fit the selected RSA
mechanism and hash parameters.

### RSA-AES wrapping

Implement `CKM_RSA_AES_KEY_WRAP`:

1. generate a fresh ephemeral AES key;
2. wrap the target with AES-KWP;
3. wrap the ephemeral AES key with RSA-OAEP;
4. encode the output exactly as Cryptoki specifies; and
5. zeroize the ephemeral key and all intermediate plaintexts on every path.

Split the existing YubiHSM RSA-AES parameter parser into:

- backend-neutral Cryptoki parameter validation; and
- YubiHSM-specific command construction.

Software and YubiHSM execution can then share parameter semantics without
sharing key material.

## Phase 9: asymmetric private-key wrapping

After secret-key wrapping is stable, support extractable software asymmetric
private keys:

- encode RSA, EC, Ed25519, and X25519 as bare PKCS #8;
- wrap the PKCS #8 bytes with AES-KWP or RSA-AES wrapping;
- parse and validate PKCS #8 during unwrapping; and
- apply the unwrap template as the authoritative policy for the new object.

Do not treat attributes embedded in a wrapped private-key representation as
authoritative. The unwrap template defines the new token object's label, ID,
lifetime, privacy, sensitivity, extractability, and usage.

Public keys do not require this path because their public material is already
readable.

## Phase 10: wrapping and derivation policies

Persist and enforce:

- `CKA_ALLOWED_MECHANISMS`
- `CKA_WRAP_TEMPLATE`
- `CKA_UNWRAP_TEMPLATE`
- `CKA_DERIVE_TEMPLATE`
- `CKA_WRAP_WITH_TRUSTED`

Template-valued attributes require canonical encoding, strict merge rules, and
duplicate/conflict rejection.

Named software slots have separate Security Officer and user PIN wrappers, but
do not yet implement trusted-object administration. Therefore:

- `CKA_TRUSTED=CK_TRUE` remains unsupported initially; and
- a target requiring `CKA_WRAP_WITH_TRUSTED=CK_TRUE` must fail closed.

Trusted wrapping should not be enabled until software-token SO administration
exists.

## Security requirements

- Do not expose a software-secret capability on unrelated hardware slots.
- Do not log key bytes, derived secrets, wrapped plaintexts, or passwords.
- Use constant-time MAC and authentication-tag verification.
- Zeroize all secret intermediates and operation-state key clones.
- Authenticate wrapped or persisted data before parsing it.
- Reject cross-slot key handles.
- Reject output templates before performing irreversible persistent writes.
- Publish persistent records before publishing object handles.
- Roll back persistent records if later handle refresh or insertion fails.
- Never downgrade token lifetime to session lifetime.
- Never make a derived or unwrapped key more extractable than the source and
  mechanism permit.

## Test plan

### AES and HMAC

- NIST AES vectors for every supported key size and mode.
- RFC HMAC vectors for all supported hashes.
- One-shot and multipart operations.
- Length-query and short-buffer behavior.
- Invalid IVs, counters, padding, tags, MACs, and mechanism parameters.
- Constant-time verification paths where testable by structure.

### Lifecycle and persistence

- Generation and import for AES and HMAC.
- Session and token lifetime matrix.
- Creator-session destruction.
- Cross-session use while the creator remains open.
- Login-gated visibility.
- Logout/login and finalize/reinitialize restoration.
- Process-restart restoration.
- PIN changes without rewriting every key record.
- Durable deletion.
- Wrong PIN, corrupted record, missing header, and cross-token replay.
- Storage publication and refresh rollback.

### Derivation

- ECDH vectors for every supported curve and X25519.
- X9.63 KDF vectors for every supported digest.
- RFC 5869 HKDF vectors.
- Generic, AES, and HMAC output types.
- Session and persistent output.
- Attribute inheritance.
- Invalid peer points, lengths, KDFs, shared data, templates, and base-key
  permissions.

### Wrapping

- RFC 3394 and RFC 5649 vectors.
- RSA PKCS #1 and OAEP vectors.
- RSA-AES round trips and format validation.
- Tampered ciphertext and integrity failures.
- Extractability and usage-policy failures.
- Cross-slot rejection.
- Session and persistent unwrapped outputs.
- Asymmetric PKCS #8 wrapping after that phase is enabled.
- No residual object after unwrap or storage failure.

Add both Rust coverage and Python ABI-level lifecycle tests. Mechanism-list
tests must verify exact flags and the absence of `CKF_HW` on software
mechanisms.

## Suggested commit sequence

1. `Add software secret-key object capabilities`
2. `Add session software AES and HMAC operations`
3. `Persist software secret keys`
4. `Create typed session and token keys from ECDH`
5. `Add ECDH KDF and HKDF mechanisms`
6. `Add software AES key wrap and unwrap`
7. `Add software RSA and RSA-AES wrapping`
8. `Wrap software asymmetric private keys`
9. `Enforce wrapping and derivation policy templates`
10. `Document and qualify the complete software-key lifecycle`

Each commit should leave mechanism advertisement, implementation, and tests in
agreement. A mechanism must not be advertised before its complete required
path is available.

## Completion criteria

The roadmap is complete when a named software slot can:

1. generate or import an AES or HMAC key as either a session or encrypted token
   object;
2. use it through the advertised AES or HMAC mechanisms;
3. derive typed AES or HMAC session and token keys from ECDH or HKDF;
4. wrap and unwrap eligible secret and asymmetric keys;
5. restore persistent results after a process restart;
6. delete them durably;
7. enforce sensitivity, extractability, usage, and mechanism policies; and
8. pass the Rust, Python, platform, persistence, corruption, and published
   cryptographic-vector test suites.
