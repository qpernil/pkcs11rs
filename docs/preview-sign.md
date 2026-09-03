# Experimental FIDO previewSign boundary

`previewSign` is an experimental WebAuthn/CTAP extension for registering a
signing seed with an ordinary FIDO credential and later asking the
authenticator to sign with a key derived from that seed. The implementation in
this repository includes protocol encoding, structural response validation,
canonical persistence records, offline ARKG-P256 public-key derivation, and an
initial PKCS #11 mapping. Imported registration and derived signing-key objects
use the common storage boundary for both session and token lifetimes. There is
still no configured durable FIDO token provider or automatic restoration.

The protocol design is based on Yubico's
[previewSign extension specification](https://yubicolabs.github.io/webauthn-sign-extension/4/)
and
[Signing Extension Preview guide](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html).
Those documents describe an early-access interface, not a stable production
cryptographic API.

## Registration wire format

The extension identifier is `previewSign`. The
`authenticatorMakeCredential` extension input is:

```text
{
  3: [-65539],  # supported signing algorithms
  4: 1          # require user presence
}
```

Its canonical CBOR bytes are:

```text
a2 03 81 3a 00 01 00 02 04 01
```

The request creates a resident parent credential for the dedicated RP ID
`preview-sign.pkcs11rs.invalid`. If a PIN is supplied, the request obtains a
make-credential permission token bound to that RP ID and sends
`pinUvAuthParam` and `pinUvAuthProtocol`. No PIN fields are sent for an
authenticator without a configured PIN.

Signing uses `authenticatorGetAssertion` with the parent credential ID in the
ordinary allow-list and this exact extension input:

```text
{
  2: signing-key-handle,
  6: bytes-to-sign,
  7: bstr .cbor COSE_Sign_Args
}
```

The signed authenticator extension output is `{6: signature}`. The parent
credential ID and key `2` are intentionally different values. The CTAP parser
extracts key `6` only from authenticator data carrying the extension-data flag;
the ordinary WebAuthn assertion signature is not returned as the PKCS #11
signature.

A successful previewSign registration must contain both:

- signed extension output in the parent credential's authenticator data,
  selecting the algorithm as `{3: algorithm}`; and
- unsigned make-credential response key `6`, whose `previewSign` member is
  `{7: bstr .cbor nested-attestation-object}`.

The nested attestation object contains the generated signing-key handle, the
signing-seed COSE public key, and signed policy `{4: flags}`. The parent
credential ID and generated signing-key handle are distinct values: the former
selects the ordinary FIDO credential in a later assertion allow-list, while
the latter is passed to previewSign itself. For the current ARKG preview
algorithm, the seed COSE key is not the final derived P-256 verification key.

The parser requires definite maps, one complete CBOR item, the expected signed
and unsigned extension outputs, matching RP ID hashes and AAGUIDs, valid policy
bits, and a zero nested signature counter. It retains the exact response bytes,
including fields it does not interpret. It does not yet verify either
attestation signature or establish trust in an AAGUID.

## Canonical persistence records

`PreviewSignRegistration` encodes one canonical CBOR map:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.preview-sign.registration` |
| `2` | schema version `1` |
| `3` | RP ID |
| `4` | 32-byte client-data hash |
| `5` | exact successful make-credential CBOR response, without CTAP status |
| `6` | optional token serial routing hint |

The serial is only a routing hint. It is not treated as a cryptographic device
identity. The response supplies the parent credential ID, signing-key handle,
seed COSE public key, algorithm, policy, and AAGUID.

`PreviewSignDerivedKeyRecord` describes one offline-derived public key:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.preview-sign.derived-key` |
| `2` | schema version `1` |
| `3` | algorithm-tagged content reference to its registration |
| `4` | signing algorithm |
| `5` | derived verification key as exact COSE_Key bytes |
| `6` | optional exact algorithm-specific COSE_Sign_Args map |
| `7` | optional application label |

For the current ARKG preview, key `6` preserves the ticket and derivation
context needed by a later assertion. The storage provider treats both wrapper
types as opaque immutable CBOR blobs; it does not interpret or traverse their
reference.

The provider-neutral [`BackedKeyMetadata`](storage.md#backed-key-metadata)
record can embed these exact protocol wrappers as provider-owned backing data
and describe the corresponding private and optional public PKCS #11 aspects.
That model does not choose or configure a persistence provider. Session-only
objects are stored in the current session's memory provider; token objects use
the slot's provider.

## Offline ARKG-P256 derivation

`ArkgP256PublicSeed::from_cose` parses the generated seed COSE_Key and requires
the experimental ARKG public-key type, the preview ARKG-P256 algorithm, two
complete EC2 P-256 public points, and no trailing CBOR. The optional derived-key
algorithm is accepted only when it selects ESP256.

`PreviewSignRegistration::derive_arkg_p256` uses 32 bytes from the operating
system random source and accepts a public application context of at most 64
bytes. The deterministic `derive_arkg_p256_with_ikm` variant exists for test
vectors and callers that already manage confidential random input; it requires
at least 32 bytes. Neither API retains the input keying material.

The derivation returns:

- a normal uncompressed P-256 public point;
- an EC2 COSE_Key whose verification algorithm is ESP256 (`-9`);
- the 81-byte ARKG ticket (a 16-byte HMAC tag followed by an ephemeral
  uncompressed P-256 public point); and
- canonical COSE_Sign_Args containing the experimental split-ARKG signing
  algorithm (`-65539`), ticket, and context.

`ArkgP256DerivedKey::into_record` places the verification key and signing
arguments directly in a `PreviewSignDerivedKeyRecord`. The input keying material
does not need to be persisted: the ticket lets the authenticator reconstruct
the corresponding private-key contribution.

The implementation uses RustCrypto's native Rust P-256, SHA-256, HMAC, and HKDF
implementations. Its deterministic tests reproduce Yubico's ARKG-P256
regression vectors for the baseline derivation, independent input keying
material, and independent contexts. They also reproduce the COSE_Sign_Args
vector published in the current
[ARKG Internet-Draft](https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/).
A test-only authenticator mock holds the draft's private seed, authenticates and
opens generated tickets, reproduces the draft's exact derived private scalar,
and signs digests that are verified against the production-derived public key.
It also rejects modified tags, contexts, and malformed ephemeral points. No
private-seed operation is compiled into a normal hardware build. The
`mock-yubikey` feature includes that private side specifically to provide a
self-contained test authenticator.

## PKCS #11 mapping

The FIDO slot advertises these vendor mechanisms only when
`authenticatorGetInfo` advertises `previewSign`:

| Constant | Numeric value | Purpose |
| --- | ---: | --- |
| `CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN` | `CKM_VENDOR_DEFINED \| 0x50530001` | register the parent credential and signing seed |
| `CKM_PKCS11RS_PREVIEW_SIGN_DERIVE` | `CKM_VENDOR_DEFINED \| 0x50530002` | derive a public key, ticket, and context offline |
| `CKM_PKCS11RS_PREVIEW_SIGN` | `CKM_VENDOR_DEFINED \| 0x50530003` | request the extension signature through GetAssertion |

`C_Login` uses the authenticator's preferred supported PIN/UV protocol. When
permissioned PIN/UV tokens are available, it requests one scoped to the
dedicated previewSign RP with make-credential and get-assertion permissions.
The legacy `getPINToken` path is necessarily unscoped, but pkcs11rs uses it
only for those previewSign operations. The token is zeroized on logout, PIN
change, session-state reset, and reconnect.

The initial lifecycle is:

1. `C_GenerateKeyPair` with the vendor key-pair mechanism calls
   MakeCredential. The returned public object projects the ordinary parent
   credential public key. The private credential object is non-signing and
   exposes the canonical registration through
   `CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION`.
2. The application reads that attribute and calls `C_CreateObject` to import a
   private registration object with key type
   `CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION`. It is derivation-capable but not
   signing-capable. `CKA_TOKEN` selects session memory or slot token storage.
3. `C_DeriveKey` on the registration object performs ARKG public derivation in
   software. The mechanism parameter is the raw public context, from zero to
   64 bytes. The result is a P-256 private-key object whose public key is
   available through standard public-key information and whose complete
   wrappers are readable as
   `CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION` and
   `CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY`. Its template independently selects
   session or token lifetime.
4. `C_Sign` with `CKM_PKCS11RS_PREVIEW_SIGN` sends the parent credential ID,
   signing-key handle, 32-byte ESP256 digest, and preserved COSE_Sign_Args to
   GetAssertion. It returns the 64-byte raw P-256 `r || s` signature.
5. Destroying the generated private parent-credential object while logged in
   sends authenticated CTAP `deleteCredential`. Destroying imported
   registration or derived-key wrappers affects only their configured PKCS #11
   storage lifetime.

A saved derived signing key can be restored directly with `C_CreateObject`.
The template must contain both exact vendor attributes: the registration
wrapper and the derived-key wrapper. pkcs11rs rejects a derived wrapper by
itself, a reference to a different registration, a non-ARKG algorithm, a
non-canonical or invalid verification key, and malformed ticket/context
arguments. A successfully restored private key can be passed to
`CKM_PKCS11RS_PROJECT_PUBLIC_KEY`; the resulting ordinary public object
supports `C_Verify`.

The generated hardware credential objects are token objects owned by the FIDO
backend. Imported registration objects and derived signing keys are immutable
provider-backed objects. With `CKA_TOKEN=CK_FALSE`, they live in the creating
session's memory provider and disappear when it closes. With
`CKA_TOKEN=CK_TRUE`, creation, attribute replacement, refresh, and destruction
use the slot token provider. The default FIDO slot provider is unavailable, so
durable token creation currently fails with `CKR_TOKEN_WRITE_PROTECTED` until a
provider is supplied; it never silently degrades to module-local storage.

The in-process mock exercises this complete flow through the exported PKCS #11
entry points: login with the initial PIN `123456`, GenerateKeyPair, read and
re-import the registration attribute as a token object, derive a token signing
key, export both wrappers, destroy the signing key, reject incomplete and
mismatched restoration attempts, restore the exact signing key as a session
object, project its public key, Sign, `C_Verify`, and independently destroy the
objects. A separate test configures local FIDO storage, finalizes and
reinitializes the module, discovers the token registration and derived key
again, signs and verifies with the restored key, destroys both token objects,
and verifies after another restart that they no longer appear. Corrupt
content-addressed data is rejected rather than treated as an empty store.

## Hardware status

The complete production discovery, CTAPHID transport, CTAP, previewSign, and
PKCS #11 path has passed against `virtual-yubikey` running as a Raspberry Pi USB
gadget. The ignored Rust test and opt-in Python `ctypes` test check mechanism
discovery and PIN login, create one persistent parent credential, export and
import its registration wrapper, derive and restore two signing keys from
distinct application contexts, project their distinct public keys, sign
through the authenticator, and verify both 64-byte ECDSA signatures through
PKCS #11. Each test also rejects one signature under the other public key.

Both tests are self-cleaning. Their imported registration and derived keys are
session objects. The external Python client deletes the parent credential by
calling `C_DestroyObject` on its generated private object; the Rust test then
uses its lower-level test hook to require a second deletion to return no
credential, so a cleanup implementation that merely reports success cannot
pass. The virtual authenticator retains credentials only in runner memory; no
disk state is involved.

The test refuses to send make-credential unless `authenticatorGetInfo`
advertises `previewSign`. It is gated by `PKCS11RS_FIDO2_TEST_PIN`, and
`PKCS11RS_FIDO2_TEST_SOURCE` should identify the intended device when more than
one FIDO authenticator is attached:

```sh
PKCS11RS_FIDO2_TEST_SOURCE=12345678 \
PKCS11RS_FIDO2_TEST_PIN=123456 \
  cargo test completes_preview_sign_pkcs11_cycle_on_hardware \
    -- --ignored --nocapture
```

The external-library test loads the built `.dylib`, `.so`, or `.dll` through
Python rather than linking the Rust implementation into its test process:

```sh
PKCS11RS_RUN_HARDWARE_TESTS=1 \
PKCS11RS_FIDO2_TEST_SOURCE=12345678 \
PKCS11RS_FIDO2_TEST_PIN=123456 \
  python3 -m unittest \
    test_hardware.HardwareDiscoveryTests.test_preview_sign_two_key_cycle -v
```

This validates the full host stack against independently running virtual
firmware, not a physical previewSign-capable YubiKey. Physical-device support
requires positive vectors covering attestation trust policy, ticket lifetime
and replay behavior, and whether a validated physical serial is sufficient
routing metadata for a configured local provider.
