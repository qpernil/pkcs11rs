# Read-only FIDO2 support

## Verified transport boundary

FIDO CTAP defines a smart-card binding with application identifier
`A0 00 00 06 47 2F 00 01`. Selection uses `00 A4 04 00`; a selected FIDO
application normally returns `U2F_V2`. CTAP CBOR messages use
`80 10 80 00`, with the CTAP command byte followed by its CBOR parameters.
The CTAP status byte and optional CBOR response are returned with ISO 7816
status `90 00`. ISO status `91 00` is a keepalive indication and is followed
by `80 11 00 00` GET RESPONSE.

Yubico's current documentation and implementation confirm that YubiKey
firmware 5.8 and later exposes this binding over the USB CCID interface.
Earlier YubiKey firmware uses the USB FIDO/HID interface for FIDO2 and cannot
produce this module's FIDO2 CCID slot. FIDO over NFC also uses the smart-card
binding, but this phase has not been validated over NFC.

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
transports. The slot advertises no PKCS #11 cryptographic mechanisms.

The ignored compatibility test is another local probe:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
  cargo test fido2_ccid_compatibility_probe -- --ignored --nocapture
```

If multiple compatible keys are attached, select one by serial number or full
slot name with `PKCS11RS_FIDO2_TEST_SOURCE`.

## Resident-credential enumeration

`C_Login(CKU_USER)` accepts the configured FIDO2 PIN. This phase supports only
PIN/UV protocol 2 and obtains a permission-scoped PIN/UV auth token. It requests
the persistent-credential-management-read-only (`pcmr`) permission when the
authenticator reports `perCredMgmtRO`; otherwise it requests the standard
credential management permission but sends only enumeration subcommands. The
PIN and auth token are never exposed through PKCS #11. The auth token is
zeroized after the one login-time enumeration, and cached credential metadata
is cleared at logout.

The implementation issues only:

- `authenticatorGetInfo`;
- `authenticatorClientPIN/getKeyAgreement`;
- `authenticatorClientPIN/getPinUvAuthTokenUsingPinWithPermissions`;
- `authenticatorCredentialManagement/enumerateRPsBegin` and
  `enumerateRPsGetNextRP`;
- `authenticatorCredentialManagement/enumerateCredentialsBegin` and
  `enumerateCredentialsGetNextCredential`.

It never sends make-credential, get-assertion, update-user-information,
delete-credential, authenticator-configuration, reset, or signing commands.

Each sufficiently complete response becomes a private, token-resident,
immutable `CKO_DATA` object. It is intentionally not modeled as a PKCS #11
public or private key:

| Attribute | Value |
| --- | --- |
| `CKA_ID` | credential ID |
| `CKA_OBJECT_ID` | 32-byte RP ID hash |
| `CKA_LABEL` | display name, user name, RP name/ID, or credential-ID fallback |
| `CKA_APPLICATION` | `FIDO2 discoverable credential` |
| `CKA_VALUE` | versioned-by-schema CBOR metadata map described below |
| `CKA_PRIVATE` | true |
| `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE` | false |

`CKA_VALUE` uses integer keys:

| Key | Type | Meaning |
| --- | --- | --- |
| 1 | bytes, required | RP ID hash |
| 2 | text | RP ID |
| 3 | text | RP name |
| 4 | bytes, required | user ID |
| 5 | text | user name |
| 6 | text | user display name |
| 7 | bytes, required | credential ID |
| 8 | bytes, required | encoded COSE public-key map |
| 9 | unsigned integer | credential-protection policy |
| 10 | boolean | third-party-payment credential |

Unknown response fields are skipped. An object is not created unless the RP ID
hash, user ID, credential ID, and encoded public key are all available.
Object handles are reconciled from the RP hash plus credential ID, so repeated
logins retain handles for unchanged credentials.

The ignored enumeration test is read-only but requires the FIDO2 PIN:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_TEST_PIN='your PIN' \
  cargo test fido2_read_only_resident_credential_enumeration \
  -- --ignored --nocapture
```

## CBOR implementation

Protocol encoding and strict definite-length response parsing use
[`minicbor`](https://docs.rs/minicbor/latest/minicbor/), a maintained native
Rust implementation with an allocation feature and no Serde data-model
translation. This keeps integer CTAP map keys, raw embedded COSE keys, duplicate
field checks, and response bounds explicit.

## Deferred hardware and firmware questions

No computer or physical YubiKey was available during this implementation.
The ignored tests above are compile-checked but have not been executed.
Validation remains necessary for:

- USB CCID selection and the `U2F_V2` selection response on each YubiKey 5.8
  production, pre-release, FIPS, and Security Key model of interest;
- PC/SC behavior and APDU response sizes on macOS, Linux, and Windows;
- keepalive timing, cancellation, removal, reinsertion, multiple applets on one
  reader, and multiple simultaneous YubiKeys;
- the exact GetInfo option combinations for `credMgmt`,
  `credentialMgmtPreview`, `pinUvAuthToken`, and `perCredMgmtRO`;
- PIN retry, temporary block, permanent block, and no-PIN status mapping;
- credential responses with long or truncated RP/user fields, multiple RPs,
  empty stores, and firmware-added fields;
- persistent PIN/UV auth-token lifetime and invalidation. This implementation
  intentionally does not retain a PPUAT across PKCS #11 logins;
- `encCredStoreState` behavior on 5.8 firmware and whether it should later be
  used only as a cache-invalidation hint;
- interaction with configured SCP03/SCP11 channels. Yubico documents FIDO2 SCP
  over USB CCID for firmware 5.8+, but it has not been exercised here.

Yubico SDK 1.17 added the WebAuthn `previewSign` extension for firmware 5.8+
and explicitly warns that the associated ARKG preview code is experimental,
not production cryptographic guidance. pkcs11rs does not parse, advertise, or
invoke `previewSign`; it creates no signing objects or signing mechanisms.
Any future work must first establish a stable standardized security and key
model suitable for PKCS #11 rather than treating the preview as an ordinary
hardware private key.

See Yubico's [SDK release notes](https://docs.yubico.com/yesdk/users-manual/getting-started/whats-new.html)
and [credential-management documentation](https://docs.yubico.com/yesdk/users-manual/application-fido2/fido2-cred-mgmt.html)
for the firmware-specific features that motivate these deferred tests.
