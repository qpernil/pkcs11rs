# YubiKey OATH

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

The OATH slot exposes credentials in the YubiKey's OATH application through
native CCID on desktop and the shared smart-card transport on iOS. It is
separate from the two-slot Yubico OTP application. Discovery uses AID
`A0 00 00 05 27 21 01`; select only OATH with
`PKCS11RS_CCID_APPLICATIONS=oath`. `PKCS11RS_OATH_AID` or `ccid.aids.oath`
overrides the AID. A device serial allowlist can further restrict discovery.

OATH is included in default physical CCID discovery. The shared virtual YubiKey
core implements the same native protocol for USB and embedded virtual YubiKeys. Enable
it with `"applets": ["oath"]` in an [embedded virtual YubiKey](configuration.md#embedded-virtual-yubikeys).
The PKCS #11 OATH backend and physical-reader behavior are shared; embedded
configuration selects the virtual transport and applet only.

## Objects and mechanisms

Credentials are persistent `CKO_OTP_KEY` objects. `CKA_ID` contains the exact
credential-name bytes and `CKA_LABEL` displays that name, including any period
prefix. Handles follow the ordinary token-object discovery lifecycle.

| Credential | Key type | Signing mechanism |
| --- | --- | --- |
| RFC 4226 HOTP, HMAC-SHA1 | `CKK_HOTP` | Standard `CKM_HOTP` |
| HOTP, HMAC-SHA1/SHA256/SHA512 | `CKK_PKCS11RS_HOTP` | `CKM_PKCS11RS_HOTP` |
| TOTP, HMAC-SHA1/SHA256/SHA512 | `CKK_PKCS11RS_TOTP` | `CKM_PKCS11RS_TOTP` |

All three hashes support enumeration, import, generation, and deletion.
SHA1 HOTP retains its standard RFC 4226 object view. Every HOTP credential also
has an extended view, so an extension-aware client can find all three hashes
by selecting `CKA_KEY_TYPE=CKK_PKCS11RS_HOTP` and use `CKM_PKCS11RS_HOTP`
uniformly. Add `CKA_PKCS11RS_OATH_HASH=CKM_SHA_1`, `CKM_SHA256`, or `CKM_SHA512`
to the `C_FindObjectsInit` template to select a particular hash. SHA1 therefore
has two logical objects with the same `CKA_ID` and
label, distinct `CKA_UNIQUE_ID` values, and one shared device secret and counter.
Each view advertises only its corresponding mechanism. The standard view's
type, mechanism, and identity remain unchanged. Deleting either view deletes
the physical credential and removes both views. The view is derived during
enumeration and requires no additional credential or host persistence.

Objects are sensitive, nonextractable, noncopyable, and immutable through
`C_SetAttributeValue`. Secret reads return `CKR_ATTRIBUTE_SENSITIVE`.
`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, and `CKA_NEVER_EXTRACTABLE` are false:
OATH credentials are imported, and the device cannot establish their history
before import. `CKA_VERIFY` is false. The slot does not advertise host software
cryptography, key generation, key wrapping, or a random generator.

`CKA_OTP_FORMAT` is decimal and `CKA_OTP_USER_FRIENDLY_MODE` is true.
`CKA_PKCS11RS_OATH_HASH` identifies `CKM_SHA_1`, `CKM_SHA256`, or `CKM_SHA512`.
The application does not expose an existing credential's digit count or touch
policy through LIST. Their attributes are known after import through this
module; otherwise `CKA_OTP_LENGTH` is `CK_UNAVAILABLE_INFORMATION` and
`CKA_PKCS11RS_OATH_TOUCH_REQUIRED` is unavailable. Enumeration performs no
calculation to learn these values. Metadata is not persisted by pkcs11rs.

## Generating a code

Use `C_SignInit` with the credential handle and a mechanism containing
`CK_OTP_PARAMS`; an empty parameter array selects the defaults. The mechanism
and parameter structures are ordinary PKCS #11 structures for SHA1 HOTP.
Extended HOTP and TOTP use the same structures with the vendor mechanisms
and key types declared in
[`pkcs11rs.h`](../pkcs11rs.h).

Call `C_Sign` with a null data pointer and zero data length. The result is a
contiguous `CK_OTP_SIGNATURE_INFO`, its `CK_OTP_PARAM` array, and the code bytes.
The single output parameter is `CK_OTP_VALUE`; its length excludes a terminator.
Pointers in that structure refer into the caller's result buffer, which must
remain in place until consumed. Do not free individual components.

Length queries return a safe bound for an eight-digit result and send no
CALCULATE command. A short buffer returns `CKR_BUFFER_TOO_SMALL` without
calculating. A successful output call performs exactly one calculation;
transport errors terminate the operation without replay. This prevents normal
two-call output handling from consuming multiple HOTP counters or touch
requests. Multipart signing is unsupported.

HOTP uses the device's internal counter. Counter, PIN, challenge, and time
parameters are marked ignored and cannot override that counter. Each successful
HOTP calculation advances persistent device state. Counter reads and updates
are not supported.

TOTP accepts `CK_OTP_TIME` as fourteen UTC digits, `YYYYMMDDhhmmss`, without a
terminator. Omission uses the host clock at calculation time. The host converts
time to a step counter; the YubiKey performs the secret-dependent operation.
`CKA_OTP_TIME_INTERVAL` describes the period. Credentials without a period
prefix use 30 seconds; `60/issuer:account`, for example, uses 60 seconds, matching
Yubico's name convention. Periods are host metadata encoded in the credential
name, not an independently readable device field.

All three mechanisms accept decimal `CK_OTP_OUTPUT_FORMAT` and zero or
`CKF_USER_FRIENDLY_OTP` flags. Unsupported flags or output overrides return
`CKR_MECHANISM_PARAM_INVALID`. A touch-protected credential requires physical
touch during the output call. A device touch timeout returns
`CKR_FUNCTION_CANCELED`; calculations are not retried automatically.

## Authentication and administration

OATH credentials always have `CKA_PRIVATE=true`, `CKA_SENSITIVE=true`, and
`CKA_EXTRACTABLE=false`. USER login is required for credential discovery,
code generation, import, and deletion. Before login, the slot and mechanisms
remain discoverable, but searches return no OTP key objects. This is the
PKCS #11 provider's access policy even when the native device protocol permits
unauthenticated access. Unlike PIV and OpenPGP keys, OTP credentials have no
public-key or certificate counterpart to expose before login.

Authenticated discovery refreshes the device credential list. Subsequent
object resolution and attribute reads reuse that inventory rather than issuing
LIST for each attribute. Find initialization, successful login, import, deletion,
and explicit inventory refresh obtain a fresh list. Logout, applet reselection,
and loss of connection-bound authorization invalidate access to cached objects.
The inventory contains credential metadata, never secret key values or OTPs.

`C_GetTokenInfo` always reports `CKF_LOGIN_REQUIRED` and
`CKF_USER_PIN_INITIALIZED`. Without an application access password, the USER
credential is an explicitly empty password. When a password is installed,
`C_Login(CKU_USER)` requires that password and performs the OATH password
derivation and mutual challenge-response authentication. A null PIN pointer
requests the configured pinentry path; an explicit nonnull pointer with zero
length supplies the empty password. `C_LoginUser` with an empty username uses
the same authentication policy and default secure-channel selection.

Neither the password nor its derived access key is retained. Authentication is
bound to the current card connection and selected-applet authorization. Logout,
deselection, connection loss, and closing the last session invalidate it;
fresh authentication is required afterward. See
[authentication secret retention](authentication-secrets.md).

`C_CreateObject` requires an RW session, `CKO_OTP_KEY`, the appropriate key type,
`CKA_TOKEN=true`, `CKA_VALUE`, and a nonempty `CKA_LABEL` or `CKA_ID`. If both
name attributes are supplied they must agree. Names must be UTF-8 and at most
64 bytes after period encoding. Secrets are 1–64 bytes; short secrets are
zero-padded to the device's minimum length, which preserves HMAC semantics.
Digit counts are 6–8, defaulting to 6. The hash attribute defaults to SHA1 for
standard HOTP and TOTP. `CKK_PKCS11RS_HOTP` requires an explicit
`CKA_PKCS11RS_OATH_HASH` of `CKM_SHA_1`, `CKM_SHA256`, or `CKM_SHA512`;
a missing hash returns `CKR_TEMPLATE_INCOMPLETE`. Import rejects SHA256/SHA512
with `CKK_HOTP` using `CKR_TEMPLATE_INCONSISTENT`. The optional
touch-required attribute defaults to false.
`CKA_OTP_TIME_INTERVAL` selects a TOTP period; nondefault periods are encoded
into the name. HOTP accepts an initial `CKA_OTP_COUNTER` as an eight-byte
big-endian integer whose value fits the device's 32-bit initialization field.

Imports reject an existing name rather than invoking PUT's overwrite behavior.
An explicit `CKA_PRIVATE=false` is rejected with `CKR_TEMPLATE_INCONSISTENT`;
unsupported policy templates are rejected. Import and deletion require USER
login regardless of whether an application access password is configured.
`C_DestroyObject` deletes only its selected credential. Imported secret buffers
use zeroizing storage.

`C_SetPIN` verifies the old access password and installs or removes the new
password; an empty new password removes protection. It requires an RW session,
and configured secure-channel policy still applies. A successful change clears
local login state. Password changes affect the entire OATH application, not an
individual credential. SO login, `C_InitPIN`, and application reset are not
exposed. SCP integration uses the common CCID login and credential selection
path; OATH response fragments are collected with SEND REMAINING before
verifying the logical response MAC and decrypting, matching Yubico's client.

## Embedded virtual YubiKeys

The virtual application starts without credentials or an access password. It
supports 64 credentials, HOTP/TOTP with all three hashes, native PUT overwrite,
rename/delete/reset, password authentication and change, touch policy, and
SEND REMAINING continuation over plain CCID and SCP03/SCP11a/b/c. The provider
retains its ordinary USER-login requirement and duplicate-import protection.
Persistent virtual YubiKeys use `oath-<serial>.cbor`, shared with the USB worker, for
credentials, the application ID/access key and moving factors. OATH mutations
are flushed before responding. Authorization, plaintext passwords and session
state are not persisted by pkcs11rs; the virtual card stores its native access
key as authenticator state. The embedded connector has no physical touch
source: touch-required calculation returns `CKR_FUNCTION_CANCELED`.
See the [virtual applet contract](https://github.com/qpernil/virtual-yubikey/blob/main/docs/oath.md)
for native limits and storage behavior.

## Validation

Embedded tests use the actual shared core with native hardware compiled out:

```sh
cargo test --lib --no-default-features --features embedded-virtual-yubikey oath
```

These checks cover RFC 6238's six timestamps for each hash, all ten RFC 4226
HOTP vectors and independently calculated SHA256/SHA512 HOTP results, initial
counters, password authentication/change/removal, protected multi-response
inventory over SCP03 and SCP11a/b/c, and touch cancellation. Exported PKCS #11
checks cover imports, pre-login/logout visibility, shared SHA1 views, secret
read rejection, repeated length queries and short-buffer handling, deletion,
ordinary SCP03/SCP11b login, deselection and persistent-device restart. These
software checks are distinct from the USB and physical qualification below.

The gadget-host virtual USB gadget (5.8 profile, serial `12345678`) passes macOS
host-tool qualification with YubiKey Manager 5.9.2. The `ykman` CLI checks OATH
disable/re-enable with credential preservation, add/list/delete, all three HOTP
hashes, rename with counter continuity, and password installation/change/removal
with incorrect-password rejection. Yubico's Python SDK checks the TOTP/HOTP
vectors and fragmented LIST/CALCULATE ALL over plain USB CCID, SCP03 and SCP11b;
password installation, incorrect-password rejection, protected login, change and
removal; and application ID, password, credential and HOTP-counter persistence
across worker restart.
A touch-required calculation times out after 15 seconds without losing the CCID
connection. Temporary qualification credentials and password protection are
removed afterward.
These external-client checks qualify the virtual USB applet independently of the
PKCS #11 mapping. Native PKCS #11 USB checks additionally generate codes for all
six samples, including all six RFC 6238 timestamps per hash, repeated length
queries and short-buffer retries without extra HOTP consumption. `C_SetPIN`
installation and removal, incorrect-password rejection and protected login
preserve the six samples. A physical joystick-center touch completes `C_Sign`
with the expected RFC 6238 code; the display's slow presence-wait blink and its
completion on touch are visually confirmed. USB SCP11a/c remains outside this
qualification.

The deployed gadget-host gadget retains the same six
[public-fixture OATH samples](../examples/ios/PKCS11RSPhoneSmoke/README.md#persistent-oath-samples)
as the physical test keys. Worker restart preserves the set, and native pkcs11rs
verifies six credential identities and seven OTP object views across module
reinitialization. Provisioning creates HOTP credentials at counter zero without
calculating a code. Subsequent code generation advances their counters;
enumeration and worker restart neither advance nor reset them.

Native USB SCP11b qualification against gadget-host uses a public-key pin obtained
through authenticated SSH from the worker's persisted public certificate. Login,
seven OTP object views and RFC TOTP codes for all three hashes pass; a different
valid P-256 pin fails with `CKR_DEVICE_ERROR`.

Temporary embedded iOS profiles qualify OATH discovery, SCP11b login and all seven
sample object views in both smoke apps on iOS 27.0 Simulator and in the Swift app
on a physical iPhone running iOS 27.2. A mismatched embedded card key fails login
and exposes no authenticated OATH objects. These are inventory/authentication
checks, not iOS OTP-vector tests. The temporary embedded configuration and pin
are absent from the normal app builds.

Linux deployment checks cover native release-library initialization,
`C_GetInfo`, an empty `C_GetSlotList`, and finalization on gadget-host and build-host,
plus the embedded-feature release library on gadget-host. These ABI checks use
temporary storage, explicitly disable device discovery, and configure no
embedded devices. They qualify library loading and configuration, not additional
Linux OTP vectors or physical-device behavior. Worker build and USB qualification
are described in
[virtual-yubikey's verification limits](https://github.com/qpernil/virtual-yubikey/blob/main/docs/oath.md#verification-and-limits).

Physical USB CCID qualification on a YubiKey 5C Nano, firmware 5.7.4, covers:

- All six RFC 6238 timestamps for each of SHA1, SHA256, and SHA512.
- All ten RFC 4226 HOTP counter vectors.
- Extended SHA1/SHA256/SHA512 HOTP checked against independent HMAC calculations
  for counters 0–9, plus eight-digit results starting at counter 12345 for each hash.
- Hash-filtered extended discovery, legacy SHA1 discovery, a shared SHA1 counter
  across both views, and deletion of both views through one credential handle.
- Standard/vendor key and mechanism separation, explicit-hash validation, and
  rejection of incompatible import templates.
- Repeated length queries, short-buffer retries, multi-response enumeration, secret-read rejection,
  a 60-second period, touch-required calculation, duplicate-name protection,
  and credential cleanup.

The hardware smoke test preserves the application's password setting and uses
only UUID-namespaced credentials, removing them in `finally` and checking the
original inventory. Run it against a dedicated physical key:

```sh
cargo build --lib
python3 tools/oath_smoke.py --module target/debug/libpkcs11rs.dylib --serial SERIAL
```

Use the platform's shared-library filename on Linux or Windows. `--touch` adds
an interactive touch-required calculation. Scripted protocol tests cover
mutual-authentication success and failure, forged responses, applet/connection
login invalidation, malformed responses, response continuation, and absence of
automatic calculation replay. Exported-API tests cover private-object visibility
before login and after logout, empty-password `C_Login` and `C_LoginUser`,
token-wide authorization across sessions, last-session cleanup, and prevention
of code generation after logout. Manual iOS smoke-app runs with a physical
YubiKey 5C NFC 5.7.4 (serial `YUBIKEY_B_SERIAL`) exercise discovery, login, and
authenticated inventory over USB and NFC with the SCP11b smoke configuration.
These inventory runs do not generate OTPs or advance HOTP counters.
Password-protected physical operation and physical password changes remain
outside the verified scope, as does full OTP-vector qualification over
SCP-protected OATH or iOS/NFC.

References: [YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html),
[Yubico OATH client](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/oath.html),
[PKCS #11 OTP mechanisms](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).

The [iOS smoke apps](../examples/ios/PKCS11RSPhoneSmoke/README.md#persistent-oath-samples)
display the same OATH views in their ordinary object inventory. Their sample
provisioning helper keeps six public-fixture credentials on a dedicated test
key, verifies persistence across module reinitialization, and performs no HOTP
calculation. This persistent sample set is separate from the temporary hardware
qualification credentials removed by `oath_smoke.py`.
