# Experimental FIDO previewSign boundary

`previewSign` is an experimental WebAuthn/CTAP extension for registering a
signing seed with an ordinary FIDO credential and later asking the
authenticator to sign with a key derived from that seed. The implementation in
this repository includes protocol encoding, structural response validation,
canonical persistence records, offline ARKG-P256 public-key derivation, and a
PKCS #11 mapping. Imported registration and derived signing-key objects use
the common storage boundary for both session and token lifetimes. A configured
local provider on a validated YubiKey serial supports durable token objects
and automatic restoration; see [storage](storage.md).

The protocol design is based on Yubico's
[previewSign extension specification](https://yubicolabs.github.io/webauthn-sign-extension/4/)
and
[Signing Extension Preview guide](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html).
Those documents describe an early-access interface, not a stable production
cryptographic API.

## Registration wire format

FIDO slots do not retain the PIN. User login obtains an RP-scoped administration
token for one registration or credential deletion. Another administration
operation requires a fresh user login (logout followed by login); obtaining a
signing token can also invalidate that administration token.

Derived signing keys report `CKA_ALWAYS_AUTHENTICATE = CK_TRUE`. Each signature
uses `C_SignInit`, followed by `C_Login(CKU_CONTEXT_SPECIFIC, PIN)` and `C_Sign`,
just like a regular FIDO assertion. Only the operation's scoped token is retained,
not the PIN. Length queries and short-buffer retries reuse the pending signature
result without another authenticator operation. Tokens are redacted from debug
output and cleared on logout or session cleanup; there is no automatic PIN-based
token renewal.

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

YubiKey 5.8.0 encodes the extension's P-256 signature as ASN.1 DER. The CTAP
parser converts its positive `r` and `s` integers to the 64-byte, fixed-width
`r || s` representation required by PKCS #11. The virtual authenticator uses
the same DER wire encoding through its regular FIDO signing routine.
Malformed DER, raw signatures, oversized integers, and trailing signature
data are rejected.

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
and unsigned extension outputs, matching RP ID hashes and AAGUIDs (except the explicit browser anonymization
case below), valid policy
bits, and a zero nested signature counter. It retains the exact response bytes,
including fields it does not interpret. It does not yet verify either
attestation signature or establish trust in an AAGUID.

## Canonical persistence records

`PreviewSignRegistration` uses one canonical CBOR map for new native and
browser registrations:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.preview-sign.registration` |
| `2` | schema version `3` |
| `3` | RP ID |
| `4` | 32-byte client-data hash |
| `5` | successful make-credential CBOR response without CTAP status; original for CTAP, normalized for WebAuthn |
| `6` | optional token serial routing hint |
| `7` | optional original `clientDataJSON` bytes, supplied by browser registrations |

Native registrations retain the supplied client-data hash. Browser imports retain
exact `clientDataJSON` bytes and verify their SHA-256 hash when decoding the
record. Authenticator-data and attestation-statement bytes remain unchanged in
the protocol response. The browser/server JSON envelope is an input format and
is not retained in new records; its layout and unrelated metadata do not affect
the canonical record or derived-key references.

Compatibility readers accept schema `1` (native response) and schema `2`
(browser export JSON alongside the normalized response). After validation,
legacy records retain their exact original encoding on readback and storage.
Their hashes are referenced by saved derived keys, so automatic re-encoding
would break restoration. New registrations use schema `3` regardless of entry
point; no automatic migration of existing records is performed.

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
`embedded-virtual-yubikey` feature includes that private side specifically so a
configured embedded CCID reader with the FIDO2 applet can provide a
self-contained integration target.

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
dedicated previewSign RP with make-credential and credential-management
permissions for one administration operation. Signing obtains a separate
get-assertion token through context-specific login. Legacy `getPINToken`
supports creation/assertion but cannot authorize modern credential management.
Retained tokens are zeroized on use, logout, PIN change, and session-state reset.

Registration has two entry points:

1. `C_GenerateKeyPair(CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN)` provisions a
   resident credential and signing seed. Its public handle projects the parent
   credential public key. Its private handle is a directly derivable, non-signing
   `CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION` object; no read/re-import step is
   required. Both templates must request `CKA_TOKEN=CK_TRUE`. The private template
   may use the registration key type; the historical `CKK_EC` template is accepted
   for compatibility, but the returned object has the registration key type.
2. `C_CreateObject` imports a registration through
   `CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION`. The attribute accepts canonical CBOR
   or the versioned WebAuthn export JSON described below. The private template uses
   `CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION`. Imported registrations are derivable
   and non-signing, using the same object constructor as generated registrations.
   `CKA_TOKEN` selects session memory or configured slot token storage.

After either entry point:

1. `C_DeriveKey(CKM_PKCS11RS_PREVIEW_SIGN_DERIVE)` performs ARKG public
   derivation in software. The mechanism parameter is the raw public context,
   from zero to 64 bytes. The result is a P-256 private-key object whose public
   key is available through standard public-key information and whose complete
   wrappers are readable as `CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION` and
   `CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY`. Its template independently selects
   session or token lifetime. Each derivation uses fresh randomness; save this
   derived record to reuse the same signing identity.
2. After `C_SignInit` and `C_Login(CKU_CONTEXT_SPECIFIC, PIN)`, `C_Sign` with
   `CKM_PKCS11RS_PREVIEW_SIGN` sends the parent credential ID, signing-key handle,
   32-byte ESP256 digest, and preserved COSE_Sign_Args to GetAssertion. It uses
   the registration's RP ID, including a real RP ID from a browser import, and
   returns the 64-byte raw P-256 `r || s` signature.
3. Destroying the generated registration handle after fresh user login sends
   authenticated CTAP `deleteCredential`. Only that generating handle owns
   credential-deletion authority. Destroying imported or restored registration
   and derived-key objects affects host storage only, even if their metadata
   originally came from `C_GenerateKeyPair`.

## Browser-server registration import

A cooperating RP stores both the ordinary browser registration and
`credential.getClientExtensionResults().previewSign.generatedKey`. It exposes
an authenticated export endpoint or downloadable file with this JSON shape:

```json
{
  "schema": "pkcs11rs.preview-sign.webauthn",
  "version": 1,
  "rpId": "sign.example.com",
  "credential": {
    "id": "<base64url credential ID>",
    "rawId": "<same base64url credential ID>",
    "type": "public-key",
    "response": {
      "clientDataJSON": "<base64url original clientDataJSON bytes>",
      "attestationObject": "<base64url parent attestation object>"
    },
    "clientExtensionResults": {
      "previewSign": {
        "generatedKey": {
          "keyHandle": "<base64url signing-key handle>",
          "publicKey": "<base64url seed COSE_Key>",
          "algorithm": -65539,
          "attestationObject": "<base64url signing-key attestation object>"
        }
      }
    }
  }
}
```

The [browser exporter example](../examples/preview-sign/export-registration.mjs)
constructs this package directly from the returned `PublicKeyCredential` and the
actual RP ID. Send `JSON.stringify(exportPreviewSignRegistration(credential, rpId))`
to the server for validation/storage; its export endpoint returns the same shape.

All binary fields use unpadded base64url. The RP must explicitly encode the
PreviewSign ArrayBuffer fields; ordinary registration serialization must not
silently omit the extension output. Additional standard credential/response
fields and unrelated client extensions are ignored. The outer export envelope
has exactly the four fields above; unknown envelope fields, duplicate known JSON
fields, absent PreviewSign output, invalid base64url, and malformed or
inconsistent CBOR are rejected.

The native application retrieves the JSON and passes its UTF-8 bytes directly
as `CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION` to `C_CreateObject`, with
`CKA_CLASS=CKO_PRIVATE_KEY`, `CKA_KEY_TYPE=CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION`,
`CKA_PRIVATE=CK_TRUE`, and the desired `CKA_TOKEN` lifetime. No browser connection,
second MakeCredential operation, or external CBOR conversion is required.

The importer preserves the exact client-data and attestation evidence, maps
WebAuthn string-keyed attestation maps to the internal CTAP representation without
altering authenticator-data or attestation-statement bytes, and calculates
`SHA256(clientDataJSON)`. It checks ceremony type, credential ID, RP hashes,
AAGUIDs, selected algorithm, public seed, signing handle, nested counter and
policy. Import supports ESP256-split ARKG-P256. A browser parent attestation
with `fmt="none"`, an empty attestation statement, and a zero AAGUID is accepted
without claiming that its AAGUID identifies the device. Other AAGUID mismatches
are rejected. Native CTAP registrations retain the matching-AAGUID requirement.

Import performs structural validation, not the RP's challenge/origin validation
or attestation signature/trust verification. The RP validates the ceremony before
export; callers obtain the package from their intended RP. Browser/platform
support for the experimental extension is required and is not established by
native CTAP tests.

Readback through `C_GetAttributeValue` always returns canonical registration
CBOR: schema `3` for new records, or the exact validated legacy encoding for
restored records. Persist this readback alongside a derived record: the derived
record refers to the canonical wrapper's
content hash, not the raw JSON input. To restore an existing browser-derived
identity, the server also supplies its exact derived-key record; importing the
registration alone and deriving again produces a different key.

## Restoration and persistence

A saved derived signing key can be restored directly with `C_CreateObject`.
The template must contain both exact vendor attributes: the registration
wrapper and the derived-key wrapper. pkcs11rs rejects a derived wrapper by
itself, a reference to a different registration, a non-ARKG algorithm, a
non-canonical or invalid verification key, and malformed ticket/context
arguments. A successfully restored private key can be passed to
`CKM_PKCS11RS_PROJECT_PUBLIC_KEY`; the resulting ordinary public object
supports `C_Verify`.

The generated registration and parent public handles are token objects owned
by the FIDO backend. Generation does not write the registration into host token
storage; applications can import its exported wrapper to request that lifetime.
Imported registration objects and derived signing keys are immutable
provider-backed objects. With `CKA_TOKEN=CK_FALSE`, they live in the creating
session's memory provider and disappear when it closes. With
`CKA_TOKEN=CK_TRUE`, creation, attribute replacement, refresh, and destruction
use the slot token provider. The default FIDO slot provider is unavailable, so
durable token creation currently fails with `CKR_TOKEN_WRITE_PROTECTED` until a
provider is supplied; it never silently degrades to module-local storage.

The embedded virtual YubiKey integration tests exercise this complete flow through the
exported PKCS #11 entry points: login with the initial PIN `123456`,
GenerateKeyPair, direct derivation from its returned registration, browser-shaped
JSON import as a token object, derivation of a token signing key, export of both
wrappers, destruction of the signing key, rejection of incomplete and mismatched
restoration attempts, restoration of the exact
signing key as a session object, project its public key, Sign, `C_Verify`, and
independently destroy the objects. A separate test configures local FIDO
storage with browser-shaped imported evidence, finalizes and
reinitializes the module, discovers the token registration and derived key
again, signs and verifies with the restored key, destroys both token objects,
and verifies after another restart that they no longer appear. Corrupt
content-addressed data is rejected rather than treated as an empty store.

## Hardware status

The Rust hardware cycle and external Python `ctypes` cycle pass on a physical
YubiKey 5C NFC with firmware **5.8.0**, serial **40353783**, and AAGUID
`f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5` (qualification: 2026-10-05). Both use
the serial-selected production HID FIDO2 slot and exercise registration,
wrapper export/import, two context-separated offline-derived signing keys,
public-key projection, signing, verification, wrong-key rejection, and parent
credential deletion. The Rust cycle also requires a second deletion to report
the credential absent. Both return two 64-byte PKCS #11 signatures after DER
conversion. Registration and derived wrapper lengths vary with signature
encoding and the randomly generated material.

The iOS smoke application's PreviewSign signing and ordinary ECDSA verification
also passed in the user's physical-device run on 2026-10-05. Its profile
instantiates no embedded virtual reader and supplies the explicit prototype
FIDO2 PIN `123456`. Persistence across iOS app relaunch still requires separate
qualification.

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

Physical qualification covers the two-key lifecycle through the production
HID transport and exact-serial slot selection. Each cycle requires touch for
registration and both signatures; a denied or expired touch request is a
failure, not a skip. Persistent local-provider restoration across device
reconnection and module restart still requires hardware qualification.
Attestation trust policy and ticket lifetime/replay behavior also require
separate positive and negative vectors. The experimental extension is not a
stable production cryptographic API.
