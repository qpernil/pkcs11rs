# FIDO2 support

## Verified transport boundary

FIDO CTAP defines a smart-card binding with application identifier
`A0 00 00 06 47 2F 00 01`. Selection uses `00 A4 04 00`; a selected FIDO
application normally returns `U2F_V2`. CTAP CBOR messages use
`80 10 80 00`, with the CTAP command byte followed by its CBOR parameters.
The CTAP status byte and optional CBOR response are returned with ISO 7816
status `90 00`. ISO status `91 00` is a keepalive indication and is followed
by `80 11 00 00` GET RESPONSE. The transport waits 100 ms between keepalive
polls, matching Yubico's maintained `SmartCardCtapDevice` behavior and leaving
time for user-presence interaction.

Yubico's current documentation and implementation confirm that pre-release
YubiKey firmware exposes this binding over the USB CCID interface. Earlier
production YubiKey firmware uses the USB FIDO/HID interface for FIDO2 and
cannot produce this module's FIDO2 CCID slot. FIDO over NFC also uses the
smart-card binding. Applet selection, `authenticatorGetInfo`, legacy PIN-token
login, and read-only resident-credential enumeration have been validated over
NFC on an earlier YubiKey.

Primary references:

- [FIDO Alliance CTAP 2.2 proposed standard](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Yubico `SmartCardCtapDevice` source](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/core/fido.html)
- [Yubico hardware interfaces](https://developers.yubico.com/Developer_Program/Guides/YubiKey_Hardware.html)
- [Yubico `Fido2Session` transport documentation](https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.Fido2.Fido2Session.html)

pkcs11rs implements only that CCID binding. It deliberately contains no FIDO
HID, platform WebAuthn, or alternative-transport placeholder.

## Slot discovery and compatibility probe

Set these variables to limit discovery to the FIDO application and enable
diagnostics:

```sh
export PKCS11RS_CCID_APPLICATIONS=fido2
export PKCS11RS_DEBUG=2
pkcs11-tool --module ./target/debug/libpkcs11rs.dylib --list-slots
pkcs11-tool --module ./target/debug/libpkcs11rs.dylib --show-info
```

A FIDO2 slot is created when the FIDO AID can be selected. As with the other
CCID applets, the slot remains registered if subsequent initialization or
`authenticatorGetInfo` discovery fails. In that state `C_GetSlotInfo` still
reports the reader, YubiKey identity, firmware, and the FIDO2 application
label; `C_GetTokenInfo` reports the stored discovery failure.

When GetInfo succeeds, the primary CTAP version is included in the slot
description and token label. Debug level 2 prints the reported versions,
extensions, AAGUID, options, maximum message size, PIN/UV protocols, and
transports. A discovered FIDO2 slot advertises the vendor
`CKM_PKCS11RS_FIDO_ASSERTION` signing mechanism. A device advertising the
experimental `previewSign` extension additionally exposes the explicit vendor
registration, derivation, and signing mechanisms described in
[previewSign mapping](preview-sign.md).

The ignored compatibility test is another local probe:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
  cargo test fido2_ccid_compatibility_probe -- --ignored --nocapture
```

If multiple compatible keys are attached, select one by serial number or full
slot name with `PKCS11RS_FIDO2_TEST_SOURCE`.

## Resident-credential enumeration

`C_Login(CKU_USER)` accepts the configured FIDO2 PIN. This phase supports
PIN/UV protocols 1 and 2. The client selects the first implementation it
supports from the authenticator's `pinUvAuthProtocols` list, which GetInfo
orders by decreasing authenticator preference. Protocol 1 derives one
SHA-256 key from the ECDH x-coordinate, uses AES-256-CBC with an all-zero IV,
and truncates HMAC-SHA-256 authentication parameters to 16 bytes. Protocol 2
uses separate HKDF-derived HMAC and AES keys, a fresh transmitted IV, and
32-byte authentication parameters.

On authenticators reporting `pinUvAuthToken`, the selected protocol obtains a
permission-scoped token and requests the
persistent-credential-management-read-only (`pcmr`) permission when the
authenticator reports `perCredMgmtRO`; otherwise it requests the standard
credential-management permission but sends only enumeration subcommands.
Older CTAP 2.0 and `FIDO_2_1_PRE` authenticators without `pinUvAuthToken` use
the superseded `getPINToken` ClientPIN subcommand and
`credentialMgmtPreview`. That token is not permission-scoped, but production
code still uses it only for read-only enumeration. The PIN and auth token are
never exposed through PKCS #11. The auth token is zeroized after the one
login-time enumeration, and cached credential metadata is cleared at logout.

PKCS #11's `CKU_USER` is an authorization role here, not a named FIDO account.
The ClientPIN is authenticator-wide, so successful PIN/UV token acquisition is
the FIDO verification operation underlying `C_Login`. `C_LoginUser` remains
unsupported for FIDO2 because CTAP PIN/UV authentication accepts no username.
The `user.id`, `user.name`, and `displayName` values returned with discoverable
credentials are relying-party-scoped credential metadata, not authenticator
login identities. Likewise, CTAP provides no Security Officer identity, so
`C_Login(CKU_SO)` is unsupported.

The token reports a stable 4-through-63-byte PIN envelope. Four is the CTAP
baseline minimum for an existing PIN, while 63 bytes is the protocol maximum.
An authenticator's current `minPINLength` is a policy for setting a new PIN and
may be higher than an existing PIN, so it does not raise the token-wide
minimum or reject that existing PIN during `C_Login`.

This mapping follows the distinction between
[PKCS #11 `C_Login` and `C_LoginUser`](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
and FIDO's
[authenticator-wide ClientPIN verification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html).

The resident-credential discovery and PIN-management paths issue:

- `authenticatorGetInfo`;
- `authenticatorClientPIN/getKeyAgreement`;
- `authenticatorClientPIN/setPIN` and `changePIN`;
- `authenticatorClientPIN/getPINToken` on the legacy CTAP 2.0 path;
- `authenticatorClientPIN/getPinUvAuthTokenUsingPinWithPermissions`;
- `authenticatorCredentialManagement` or
  `authenticatorCredentialManagementPreview`, using only `enumerateRPsBegin` and
  `enumerateRPsGetNextRP`;
- the same read-only credential-management command, using only
  `enumerateCredentialsBegin` and
  `enumerateCredentialsGetNextCredential`;
- `authenticatorGetAssertion` only after an application explicitly initializes
  `CKM_PKCS11RS_FIDO_ASSERTION`, performs context-specific PIN login, and calls
  `C_Sign`.

They never send make-credential through the ordinary credential objects, nor
update-user-information, delete-credential, authenticator-configuration, or
reset. Discoverable credentials and their metadata remain immutable. The
separate, application-selected previewSign vendor mechanisms do send
MakeCredential and GetAssertion; those operations cannot be reached through
ordinary credential enumeration or assertion objects.

Each sufficiently complete response becomes a private, token-resident,
immutable `CKO_DATA` object:

| Attribute | Value |
| --- | --- |
| `CKA_ID` | credential ID |
| `CKA_OBJECT_ID` | 32-byte RP ID hash |
| `CKA_LABEL` | RP and user names when available, or a credential-ID fallback |
| `CKA_APPLICATION` | `FIDO2 discoverable credential` |
| `CKA_VALUE` | authenticator credential-management response CBOR |
| `CKA_PRIVATE` | true |
| `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE` | false |

`CKA_VALUE` is the credential response body returned by
`enumerateCredentialsBegin` or `enumerateCredentialsGetNextCredential`,
without the leading CTAP success status byte. The bytes are retained exactly
as returned by the authenticator, including unknown fields. CTAP currently
defines these response fields:

| Key | Type | Meaning |
| --- | --- | --- |
| `0x06` | map | user entity |
| `0x07` | map | credential descriptor |
| `0x08` | map | COSE public key |
| `0x09` | unsigned integer | total credential count; begin response only |
| `0x0a` | unsigned integer | credential-protection policy |
| `0x0b` | bytes | large-blob key |
| `0x0c` | boolean | third-party-payment credential |

The object is private because credential enumeration requires FIDO PIN/UV
authorization. After login, an application may read all returned response
fields, including `largeBlobKey`, through `CKA_VALUE`.

When the COSE public key has a lossless PKCS #11 representation, the backend
also creates linked immutable `CKO_PUBLIC_KEY` and `CKO_PRIVATE_KEY` objects.
The data and key objects share the credential ID in `CKA_ID`. EC2 P-256,
P-384, and P-521, OKP Ed25519, and RSA public keys are projected. Other COSE
key types leave the data object available without creating misleading key
objects.

The projected public key exposes its standard EC or RSA parameters,
`CKA_PUBLIC_KEY_INFO`, and the module's ordinary software public operations.
The private object exposes no private key value. When credential management
returns the RP ID, the private object has `CKA_SIGN=true`,
`CKA_ALWAYS_AUTHENTICATE=true`, and supports only
`CKM_PKCS11RS_FIDO_ASSERTION`. If only an RP ID hash is available, the private
projection remains non-operational because GetAssertion cannot be addressed
safely.

`CKM_PKCS11RS_FIDO_ASSERTION` deliberately returns the exact successful CTAP
GetAssertion response CBOR, not only its signature field. The `C_Sign` input
must be the 32-byte `clientDataHash`. After `C_SignInit`, the application must
call `C_Login(CKU_CONTEXT_SPECIFIC)` with the FIDO PIN; this obtains one
RP-bound `ga` permission token. The next `C_Sign` sends an allow-list containing
only that credential and requests user presence. The response validator
requires the expected credential ID, RP ID hash, UP and UV flags, and a
nonempty assertion signature. A size query executes the assertion once and
caches the response so buffer sizing cannot cause a second touch. Successful
return or any device/protocol failure destroys the operation and its
authorization. Multipart signing is unsupported, and neither the PIN nor the
PIN/UV token is retained for another assertion.

The returned CBOR contains the authenticator data, ordinary WebAuthn signature,
credential descriptor, and any firmware-defined fields. An application can
verify the ordinary assertion using the linked public-key object. This is a
vendor mechanism because a CTAP assertion is a structured, RP-bound protocol
result rather than a bare PKCS #11 signature.

Authenticator support for the experimental `previewSign` extension does not
show that an arbitrary enumerated credential carries saved registration
metadata. previewSign registrations created through the vendor
`C_GenerateKeyPair` mechanism are therefore augmented in memory rather than
inferred from credential-management output. The separate [previewSign
mapping](preview-sign.md) defines the explicit registration, import,
derivation, and signing lifecycle.

An object is not created unless the RP ID hash, user ID, credential ID, and
encoded public key are all available. Object handles are reconciled from the
RP hash plus credential ID and object kind, so repeated logins retain handles
for unchanged credentials.

The ignored enumeration test is read-only but requires the FIDO2 PIN:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_TEST_PIN='your PIN' \
  cargo test fido2_read_only_resident_credential_enumeration \
  -- --ignored --nocapture
```

## Synthetic discoverable-credential hardware fixture

The ordinary resident-credential objects never send
`authenticatorMakeCredential`. A test-only hook, compiled only into Rust test
builds, can create one persistent discoverable credential so the read-only
PKCS #11 mapping can be exercised against a nonempty authenticator. The
explicit previewSign key-pair mechanism has its own production
MakeCredential operation and is unrelated to this fixture.

The fixture uses deliberately synthetic values:

| Field | Value |
| --- | --- |
| RP ID | `pkcs11rs.invalid` |
| RP name | `pkcs11rs synthetic relying party` |
| User ID | `pkcs11rs-fido2-hardware-user-v1` |
| User name | `pkcs11rs-test` |
| Display name | `pkcs11rs synthetic user` |
| Algorithm | ES256 (`-7`) |
| Discoverable | `rk=true` |

The test obtains a PIN/UV token using the authenticator's preferred supported
protocol with only the RP-bound `mc` permission, authenticates a fixed
synthetic client-data hash, sends
`authenticatorMakeCredential`, and validates the returned attested credential
ID. It then calls the exported `C_Login(CKU_USER)` path and requires the same
credential ID and display name to appear as a read-only PKCS #11 object.

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_TEST_PIN='your PIN' \
  cargo test creates_and_rediscovers_synthetic_fido2_credential \
  -- --ignored --nocapture
```

This test requires user presence, permanently writes a credential, and does
not delete it. The PIN variable itself is the execution gate. Repeated runs use
the same RP and user identifiers so authenticators that replace an existing
discoverable credential for that account need not consume another logical
account entry. The test has passed on the pre-release `FIDO_2_3` hardware
described below, and the standalone read-only enumeration test subsequently
found the resulting object.

## PIN management through PKCS #11

An application can provision the first FIDO2 PIN through `C_SetPIN` in an R/W
public session:

```c
C_SetPIN(session, NULL_PTR, 0, new_pin, new_pin_len);
```

The empty old PIN represents the authenticator's uninitialized PIN state.
Either `NULL_PTR, 0` or a non-null pointer to an empty string with length zero
is accepted, covering GUI clients that always supply a string buffer. A
nonempty old PIN on an uninitialized authenticator returns
`CKR_PIN_INCORRECT`.

Once GetInfo reports `clientPin=true`, the standard PKCS #11 change operation
maps to CTAP `changePIN`:

```c
C_SetPIN(session, old_pin, old_pin_len, new_pin, new_pin_len);
```

An empty old PIN in that state returns `CKR_PIN_INCORRECT`. The CTAP wrong-PIN
and blocked-PIN statuses map to the corresponding PKCS #11 PIN errors. This
mapping never invokes CTAP reset. `C_InitPIN` remains unsupported for FIDO2
because PKCS #11 requires it to run in an authenticated SO session, while CTAP
has no Security Officer identity.

New PINs are validated as UTF-8, normalized to Unicode NFC, checked against the
authenticator's reported `minPINLength`, and limited to CTAP's 63-byte maximum.
FIDO2 PIN login and the current PIN supplied for a change apply the same NFC
normalization before hashing. The current PIN is not checked against the
present `minPINLength`, because CTAP permits policy changes that leave an
existing PIN shorter than a newly raised minimum.

The ignored hardware test provisions through the exported `C_SetPIN` entry
point, verifies `CKF_USER_PIN_INITIALIZED`, then authenticates through
`C_Login(CKU_USER)` with the new PIN and logs out. The presence of the new-PIN
variable is the mutation gate:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_NEW_PIN='new test PIN' \
  cargo test provisions_initial_fido2_pin -- --ignored --nocapture
```

The test adds a stricter printable-ASCII input restriction for predictable
shell invocation. If multiple compatible keys are attached, set
`PKCS11RS_FIDO2_TEST_SOURCE` as described above.

Provisioning changes persistent authenticator configuration. Run this test only
against the intended test key and store the selected PIN securely. The PIN is
read from the environment, is not printed, and is held in zeroizing memory by
the test process.

The separate ignored change test calls `C_SetPIN` with the current and new PIN,
then verifies the new PIN through `C_Login(CKU_USER)`:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_TEST_PIN='current test PIN' \
PKCS11RS_FIDO2_NEW_PIN='new test PIN' \
  cargo test changes_existing_fido2_pin -- --ignored --nocapture
```

This test permanently changes the selected authenticator's PIN and does not
restore it. The change test runs only when both PIN variables are present. Both
mutation tests require printable ASCII PINs for predictable shell invocation;
production callers may use any valid UTF-8 PIN accepted by the CTAP
normalization rules.

## CBOR implementation

Protocol encoding and strict definite-length response parsing use
[`minicbor`](https://docs.rs/minicbor/latest/minicbor/), a maintained native
Rust implementation with an allocation feature and no Serde data-model
translation. This keeps integer CTAP map keys, raw embedded COSE keys, duplicate
field checks, and response bounds explicit.

## Deferred hardware and firmware questions

The initial implementation was completed without hardware. The compatibility
probe has since succeeded against a YubiKey 5C NFC running firmware 5.4.3 and
reporting `FIDO_2_0` over NFC, and against pre-release YubiKeys reporting
`FIDO_2_3` over macOS PC/SC. The 5.4.3 key exercises the legacy `getPINToken`
plus `credentialMgmtPreview` login path. On pre-release hardware, the exported
`C_SetPIN` entry point successfully provisioned the initial PIN from a non-null
zero-length old-PIN buffer and `C_Login(CKU_USER)` verified it. The test-only
makeCredential fixture then created a persistent discoverable credential, and
both its immediate PKCS #11 check and the standalone read-only enumeration test
rediscovered that object. Existing-PIN `changePIN` through `C_SetPIN` and
subsequent `C_Login` verification with the replacement PIN have also succeeded
on pre-release hardware. Additional robustness validation remains useful for:

- USB CCID selection and the `U2F_V2` selection response on each pre-release,
  FIPS, and Security Key model of interest;
- PC/SC behavior and APDU response sizes on macOS, Linux, and Windows;
- keepalive timing, cancellation, removal, reinsertion, multiple applets on one
  reader, and multiple simultaneous YubiKeys;
- additional GetInfo option combinations for `credMgmt`,
  `credentialMgmtPreview`, `pinUvAuthToken`, `perCredMgmtRO`, and mixed or
  unknown PIN/UV protocol preference lists;
- PIN retry, temporary block, permanent block, and no-PIN status mapping;
- credential responses with long or truncated RP/user fields, multiple RPs,
  empty stores, and firmware-added fields;
- persistent PIN/UV auth-token lifetime and invalidation. This implementation
  intentionally does not retain a PPUAT across PKCS #11 logins;
- `encCredStoreState` behavior on pre-release firmware and whether it should
  later be used only as a cache-invalidation hint;
- interaction with configured SCP03/SCP11 channels. Yubico documents FIDO2 SCP
  over USB CCID for pre-release firmware, but it has not been exercised here.

Yubico SDK 1.17 added the WebAuthn `previewSign` extension and explicitly warns
that the associated ARKG preview code is experimental, not production
cryptographic guidance. pkcs11rs now has an isolated request encoder,
structural registration parser, canonical
[previewSign persistence model](preview-sign.md), protocol vectors, and an
ignored capability-gated registration test. It also exposes an experimental
vendor PKCS #11 flow and a complete in-process mock. Registration and derived
metadata are not yet written to the
[content-addressed CBOR storage boundary](storage.md), so restoration after
module finalization remains deferred.

See Yubico's [SDK release notes](https://docs.yubico.com/yesdk/users-manual/getting-started/whats-new.html)
and [credential-management documentation](https://docs.yubico.com/yesdk/users-manual/application-fido2/fido2-cred-mgmt.html)
for the firmware-specific features that motivate these deferred tests.
