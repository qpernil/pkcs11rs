# pkcs11rs

[![CI](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml)

`pkcs11rs` is a Rust PKCS #11 provider for YubiKey CCID and FIDO HID
applications, YubiHSM devices, and explicitly configured in-memory software
tokens. Hardware private-key operations remain on the device. Dedicated
software slots support login-gated session keys and, when local token storage
is configured, encrypted persistent private-key objects.

The project currently implements PKCS #11 2.40, 3.0, 3.1, and 3.2 function
tables. Unsupported entry points are present in the ABI and return the
appropriate PKCS #11 error instead of being omitted.

The minimum supported Rust version is 1.85.

## Backends

- **YubiKey PIV** over native CCID (PC/SC on desktop and CryptoTokenKit on
  iOS), including RSA,
  ECDSA, Ed25519, ECDH/X25519, certificates, metadata, attestation, PIN policy,
  and random generation.
- **YubiKey OpenPGP** over native CCID, including
  signing, RSA deciphering, ECDH, certificates, OpenPGP PIN KDFs, and random
  generation.
- **YubiHSM 2** over direct USB or the HTTP YubiHSM Connector, including
  authenticated sessions, hardware-backed asymmetric, symmetric, HMAC,
  wrapping, opaque, and authentication objects.
- **YubiHSM Auth** as a discoverable CCID applet whose credentials can
  authenticate sessions on local or remote YubiHSM slots.
- **Issuer SD** discovery with read-only key metadata, CA identifiers, CPLC,
  SCP11 certificate chains, and explicit SCP03/SCP11 administration APIs.
- **FIDO2** discovery over native USB HID and the CTAP smart-card binding over
  NFC or USB CCID where available. This includes PIN provisioning and changes,
  read-only resident-credential and public-key metadata, and an explicit
  one-shot GetAssertion mechanism after context-specific PIN
  login, with an experimental opt-in previewSign registration, offline
  derivation, and hardware-signing lifecycle on devices advertising that
  extension.
- **SCP03, SCP11a, SCP11b, and SCP11c** secure messaging for selected CCID
  applets.
- **Named software slots** created only by explicit configuration, with
  login-gated asymmetric and secret keys, plus encrypted persistent key
  objects when local token storage is configured. This includes RSA, EC,
  Ed25519, X25519, ML-DSA, ML-KEM, AES, HMAC, generic-secret, and legacy 3DES
  keys.

Hardware and firmware capabilities determine which objects and mechanisms are
available in a particular slot.

The vendor `CKM_PKCS11RS_PROJECT_PUBLIC_KEY` mechanism provides a reference
implementation of public-key projection through `C_DeriveKey`: a private key
with recoverable public metadata can produce an independent public session
object for ordinary software verification or RSA encryption. YubiHSM private
keys can additionally produce persistent public token objects backed by
pkcs11rs-owned canonical metadata. See the
[public-key projection proposal](docs/public-key-projection-proposal.md) for
the proposed standard semantics and current implementation boundary. YubiHSM
RSA wrap keys add an explicit native-public-wrap case; its complete
`C_GenerateKeyPair`, `C_CreateObject`, and `C_DeriveKey` template matrices are
documented under [RSA public wrap keys](docs/yubihsm-auth.md#rsa-public-wrap-keys).

## PKCS #11 3.2 profiles

Every present slot advertises a public, immutable, token-resident
`CKP_BASELINE_PROVIDER` object. Additional `CKO_PROFILE` objects are derived
from the backend's advertised behavior:

| Profile | Availability |
| --- | --- |
| `CKP_BASELINE_PROVIDER` | Every present slot |
| `CKP_EXTENDED_PROVIDER` | YubiHSM slots, which provide the profile's required mechanism discovery and login functions |
| `CKP_AUTHENTICATION_TOKEN` | Slots advertising signing-capable `CKM_SHA256_RSA_PKCS` |
| `CKP_PUBLIC_CERTIFICATES_TOKEN` | PIV and OpenPGP slots; YubiHSM slots only after successful configured public discovery |

Each `CKO_PROFILE` object identifies one supported profile through its
`CKA_PROFILE_ID` attribute and has a stable, distinct `CKA_UNIQUE_ID`. The
YubiHSM public-certificates profile is based on an actual authenticated
discovery result, not merely on the presence of configuration.

YubiHSM slots advertise the Extended Provider profile because the module
provides its required mechanism discovery and authentication functions. The
profile does not mandate a particular mechanism. Available wrapping mechanisms
remain limited to the YubiHSM's standard and vendor-backed adaptations and
depend on device capabilities.

## Threading

The module uses its own synchronization when `C_Initialize` permits native
locking through `CKF_OS_LOCKING_OK`. Application-provided mutex callbacks are
not used; when both callbacks and `CKF_OS_LOCKING_OK` are supplied, native
locking is selected. Each PKCS #11 slot has an independently locked child
context containing its sessions, login state, and object-handle state.
Searches and active cryptographic operations belong to their individual
sessions.

For integrations that can forward provider configuration,
`CK_C_INITIALIZE_ARGS.pReserved` accepts a direct NUL-terminated UTF-8 JSON
string. pkcs11rs reads the configuration during `C_Initialize` and does not
retain its pointer. Explicit JSON fields take precedence, while omitted fields
retain the documented environment-variable and built-in fallbacks. A null or
empty string selects environment and built-in defaults.
For compatibility with providers such as OpenSSL, a nonempty direct string
whose first non-whitespace character is not `{` is accepted as opaque
application data and ignored; JSON-looking input is validated strictly. See
[Initialization configuration](docs/configuration.md) for the complete schema,
validation rules, and C examples. `C_Finalize` still requires its
reserved argument to be null.

Initialization and finalization are nonblocking lifecycle transitions. They
return `CKR_FUNCTION_FAILED` if another PKCS #11 call is executing; ordinary
calls return `CKR_CRYPTOKI_NOT_INITIALIZED` while either transition is active.

Applet connectors on a reader share one `PcscReaderState`, which owns the card
connection, APDU capabilities, validated SCP11 trust cache, and complete APDU
exchange lock. Each device-backed PKCS #11 call creates transaction-local
selected-AID and live SCP03/SCP11 state and destroys both when the transaction
ends. PKCS #11 calls targeting different applet slots may overlap
while working with their independent slot and session state, but their card
interactions cannot: each applet selection or complete APDU exchange on one
reader holds the shared physical-reader gate. Different YubiHSMs and different
native CCID readers can execute concurrently. When Yubico's
device-information commands report the same physical serial over HID and CCID,
pkcs11rs additionally prevents its own HID and CCID operations from
overlapping. HID remains shared with other HID clients; no exclusive HID lock
is requested.

See [Architecture](docs/architecture.md) for the object graph, lifecycle
locking, session ownership, transport sharing, and cache boundaries.

## Compatibility and Validation

| Area | Status |
| --- | --- |
| PKCS #11 ABI | Function-list layouts and behavior for 2.40, 3.0, 3.1, and 3.2 are covered by Rust and Python tests. |
| Linux | The complete hardware-independent Rust and Python suites run in GitHub Actions. |
| Windows | Rust tests, Python ABI tests, and OASIS profile cases run with warnings denied on a native Windows runner. |
| macOS | The `.dylib`, Rust tests, Python ABI tests, OASIS profile cases, Clippy, generated bindings, and synthetic ABI backend are checked in GitHub Actions. |
| iOS | Release device and Apple Silicon Simulator libraries are packaged as an XCFramework in GitHub Actions. Local CCID access uses CryptoTokenKit directly from Rust. |
| MSRV | An all-features build is checked with Rust 1.85. |
| Dependencies | Advisories and accepted licenses are checked with `cargo-deny`. |
| Live hardware | Ignored and explicitly gated Rust tests cover discovery, login, PIN changes, provisioning, and selected cross-device cryptographic operations on attached YubiKey and YubiHSM devices. Python tests cover production slot and token metadata plus an independently gated, self-cleaning previewSign cycle through the dynamic-library ABI. |

CI runs the complete platform suites on 64-bit `x86_64` Linux and Windows and
`aarch64` macOS. Additional all-features compilation checks cover `aarch64`
Linux and `x86_64` macOS. Other architectures, including 32-bit targets and
Windows ARM64, are not currently qualified.

Protocol tests use deterministic mock transports and official cryptographic
test vectors where available. Live-device tests are deliberately excluded from
normal CI and are not a substitute for qualifying the exact hardware and
firmware used in a deployment.

## Prerequisites

Building requires a Rust toolchain plus the development files for:

- PC/SC
- libudev on Linux

The exact package names depend on the operating system and package manager.
Direct YubiHSM USB access uses native OS APIs through the pure-Rust `nusb`
crate: usbfs on Linux, IOKit on macOS, and WinUSB on Windows. It does not
require libusb. On Windows, the YubiHSM interface must be bound to WinUSB,
which is its default Windows USB driver binding.
The `hidapi` Rust dependency compiles its bundled hidraw backend on Linux and
its bundled IOKit backend on macOS; Windows uses its native Windows HID
backend. No separately installed `libhidapi` is required.
Remote YubiHSM Connector HTTPS uses rustls and does not require OpenSSL or
libcurl.

## Build

```sh
cargo build --locked
```

The root workspace's default members are the provider, the connector, and the
certificate-bundle authoring utility. Typical output paths are:

```text
target/debug/libpkcs11rs.so       Linux
target/debug/libpkcs11rs.dylib    macOS
target/debug/pkcs11rs.dll         Windows
target/debug/pkcs11rs-tool        Authoring utility (with .exe on Windows)
target/debug/pkcs11rs-connector   Connector daemon (with .exe on Windows)
```

`cargo build --workspace` additionally selects the internal
`pkcs11rs-local-hardware` package as a top-level workspace member; an ordinary
build already compiles it as a dependency with the features required by the
provider and connector. The separate `xtask` utility intentionally has its own
workspace and is invoked through the checked-in `cargo xtask` alias for builds
such as the iOS XCFramework and generated-binding checks.

`pkcs11rs-tool` imports canonical DER certificates or one or more PEM
`CERTIFICATE` blocks into canonical CBOR bundles and verifies bundles according
to their configured TLS, SCP11 OCE, or collection purpose. See
[Certificate-bundle authoring](docs/pkcs11rs-tool.md).

### iOS XCFramework

The PKCS #11 API is already a C ABI, so an iOS build can expose the existing
entry points and headers directly without another Rust FFI adapter. Build
static ARM64 libraries for an iPhone and Apple Silicon Simulator and package
them with the standard and pkcs11rs extension headers by running:

```sh
cargo xtask ios
```

The default output is `target/ios/PKCS11RS.xcframework`. Pass `--release` for
optimized libraries or `--output PATH` to select another XCFramework location.
The default deployment target is iOS 18.0; set `IPHONEOS_DEPLOYMENT_TARGET`
when invoking the command to override it.
The command also includes an iOS umbrella header with the platform macros
required by the standard PKCS #11 headers and a Clang module map, allowing a
Swift target that links the XCFramework to use `import PKCS11RS`. The artifact
omits the desktop native USB, HID, and PC/SC transports. It contains an
iOS-native CCID provider that loads Apple's public CryptoTokenKit framework
internally when reader discovery first runs. An embedding app therefore needs
no CryptoTokenKit linker setting, callbacks, or platform transport code.
CryptoTokenKit provides smart-card APDU transport; this backend does not expose
general USB interfaces or bulk endpoints to pkcs11rs.
Software slots and configured remote YubiHSM HTTP connectors also remain
available.

Optional NFC discovery requests one card through Apple's system UI during the
first `C_GetSlotList`, registers its applets as ordinary stable slots, and
binds those slots to the discovered serial. The logical mount retains that
identity until finalization, while PKCS #11 token presence follows whether
CryptoTokenKit currently reports the card. A retained operation can reacquire
only the same serial. USB CCID and NFC therefore share the same applet,
transaction, secure-channel, and PKCS #11 implementation rather than using an
application-supplied transport shim. The
[iOS integration guide](docs/ios-integration.md#when-the-nfc-ui-appears)
summarizes which initial and later calls can present the system NFC UI.

The [iPhone smoke-test app](examples/ios/PKCS11RSPhoneSmoke) demonstrates
linking the XCFramework from Swift while pkcs11rs itself enumerates local
CryptoTokenKit smart-card readers and transmits their APDUs. The app passes
only a direct JSON configuration string through
`CK_C_INITIALIZE_ARGS.pReserved`; it contains no CryptoTokenKit, CCID
transport, or logging callback code. It uses the
`PKCS11RS_GetObjectClassName` and `PKCS11RS_GetKeyTypeName` extensions while
rendering its object inventory. Parallel helpers provide canonical `CKM_*`,
`CKR_*`, `CKA_*`, and `CKP_*` names for mechanisms, return values, attribute
types, and profile IDs. Deprecated aliases resolve to their current canonical
names, and every returned string remains owned by the library for the lifetime
of the process.

The [iOS application integration guide](docs/ios-integration.md) gives the
complete Xcode setup, initialization, threading, lifecycle, transport, NFC,
storage, and diagnostics guidance for both Swift and Objective-C applications.
The [Objective-C smoke-test app](examples/ios/PKCS11RSObjCSmoke) demonstrates
direct calls to the same statically linked C ABI with synchronized discovery,
software-token, object-inventory, and YubiHSM Auth coverage.

### Asynchronous multi-device connector

The workspace also builds `pkcs11rs-connector`, a fully asynchronous HTTP(S)
gateway for every YubiHSM attached to the connector host over USB. It uses
Tokio and Axum for HTTP, Rustls for HTTPS and optional mutual TLS, and nusb's
native asynchronous transfers from request to physical device. The connector
hot-plug registry uses the verified USB serial as the stable remote identity.

> **Deployment status:** this daemon is currently intended for loopback,
> trusted private networks, or use behind a controlled VPN or reverse proxy.
> It is not yet Internet-grade and must not be exposed directly on a public
> interface. The remaining protocol validation, authorization, admission
> control, recovery, and operational work is tracked in the
> [connector Internet-readiness checklist](docs/connector.md#internet-readiness-work).

Start a loopback HTTP connector with:

```sh
cargo run -p pkcs11rs-connector
```

The multi-device API enumerates and addresses each device explicitly:

```text
GET  /v1/devices
GET  /v1/devices/{serial}
POST /v1/devices/{serial}/commands
```

PKCS11RS uses this API directly. Each URL in `PKCS11RS_YUBIHSM_URLS`
identifies one connector service, and each device returned with status
`available` becomes an independent PKCS #11 slot. Enumerated devices that the
connector did not claim remain visible as `unclaimed` and are ignored by the
client. PKCS11RS does not use the legacy single-device endpoints.

System sleep pauses the connector without rebuilding its HTTP listener, USB
watcher, registry, or claimed YubiHSM handles. A two-minute macOS sleep test
confirmed that the original claimed handle and a complete release/reacquire
sequence both answered a cleartext `DeviceInfo` command immediately after
wake. YubiHSM secure sessions remain subject to the device's independent
30-second inactivity timeout and must be authenticated again after expiry.

Command request and response bodies are native YubiHSM frames with
`application/octet-stream`. Each device has an independent asynchronous access
gate, so only one request at a time reaches a particular YubiHSM while requests
for different serials can proceed concurrently. The HTTP edge rejects bodies
above 8,192 bytes. After device selection, the shared local-hardware transport
validates the native frame length and enforces the firmware-specific 2,048-byte
or 3,136-byte USB limit before submission. The same hardware-boundary checks
protect direct USB access by the PKCS #11 provider.

The existing single-device YubiHSM Connector protocol remains available at
`/connector/status` and `/connector/api`. Without configuration it remembers
the serial of the first successfully discovered device and behaves as though a
client used that serial with the multi-device API. USB re-enumeration therefore
does not change the selected HSM. If that serial is absent, the legacy endpoint
reports no device instead of failing over. Select a different compatibility
device explicitly:

```sh
cargo run -p pkcs11rs-connector -- --legacy-serial 12345678
```

Enable HTTPS, and optionally require client certificates, with PEM files:

```sh
cargo run -p pkcs11rs-connector -- \
  --listen 0.0.0.0:12345 \
  --tls-certificate /etc/pkcs11rs/server-chain.pem \
  --tls-key /etc/pkcs11rs/server-key.pem \
  --tls-client-ca /etc/pkcs11rs/client-ca.pem
```

Plain HTTP defaults to loopback. A non-loopback HTTP listener requires the
explicit `--allow-insecure-http` switch. HTTPS without `--tls-client-ca`
encrypts traffic but does not authenticate clients. See
[Multi-device connector](docs/connector.md) for the API, security model, and
deployment details.

For example, using OpenSC `pkcs11-tool` on macOS:

```sh
pkcs11-tool \
  --module ./target/debug/libpkcs11rs.dylib \
  --list-slots
```

No configuration is required for normal discovery. The module probes supported
YubiHSM USB devices and the default CCID applets available through PC/SC.

Disable all automatic local hardware discovery with:

```sh
export PKCS11RS_HARDWARE_DISCOVERY=0
```

This skips direct YubiHSM USB, native FIDO HID, and native CCID reader
discovery, including PIV, OpenPGP, YubiHSM Auth, Issuer SD, and
FIDO2 applets.
It does not disable named software slots or URLs explicitly configured through
`PKCS11RS_YUBIHSM_URLS`; remote HTTP(S) connectors are already opt-in. The
setting defaults to `1`. Any value other than `0` or `1` makes
`C_Initialize` return `CKR_ARGUMENTS_BAD`. If neither software slots nor
remote connectors are configured, disabling local discovery can legitimately
leave the module with zero slots.

Add one or more independent in-memory software tokens with a comma-separated
list of names:

```sh
export PKCS11RS_SOFTWARE_SLOTS='build signing,key exchange'
```

The variable is absent by default, so no software slot is normally exposed.
Each configured name creates one present slot and is reported in
`CK_SLOT_INFO.slotDescription` and `CK_TOKEN_INFO.label`. Names are trimmed,
must be unique and nonempty, and may contain at most 32 UTF-8 bytes. An empty
entry, duplicate name, overlong name, or non-UTF-8 value makes `C_Initialize`
return `CKR_ARGUMENTS_BAD`.

Software slots never advertise `CKF_HW` or `CKF_HW_SLOT`. `C_Login(CKU_USER)`
unlocks private and secret-key operations. Session keys are removed with their
creating session. With `PKCS11RS_TOKEN_STORAGE` configured, supported
`CKA_TOKEN=CK_TRUE` public, private, AES, HMAC, generic-secret, and legacy 3DES
keys are encrypted below a name-scoped root and survive restart; without that
configuration the request returns `CKR_TOKEN_WRITE_PROTECTED` and never falls
back to session storage. Extractable software private keys can be exported
through `PKCS11RS_SoftwareExportPrivateKey` as password-encrypted,
OpenSSL-compatible PKCS #8 while a user login is active. This capability is
not enabled on any hardware or applet slot. See
[Named software slots](docs/software.md) for the exact PIN, export, storage,
format, mechanism, metadata, and lifecycle semantics.

Add remote multi-device connector services with a comma-separated URL list:

```sh
export PKCS11RS_YUBIHSM_URLS=http://hsm-a:12345,http://hsm-b:12345
```

Every attached YubiHSM enumerated by each service becomes a separate slot; a
host with two attached devices therefore needs only one configured URL.

HTTPS connectors verify the server certificate and hostname against the
Mozilla roots embedded by the locked `webpki-roots` dependency. To
authenticate the module to HTTPS connectors with one mutual-TLS identity, set
both paths:

```sh
export PKCS11RS_YUBIHSM_URLS=https://hsm-a.example:12345
export PKCS11RS_YUBIHSM_TLS_CLIENT_CERTIFICATE_BUNDLE=/etc/pkcs11rs/client-chain.cbor
export PKCS11RS_YUBIHSM_TLS_CLIENT_PRIVATE_KEY=/etc/pkcs11rs/client-key.der
```

The certificate file is a canonical CBOR certificate bundle ordered leaf
first. The key is password-encrypted PKCS #8 DER and is unlocked through the
configured `PKCS11RS_PINENTRY`. Both settings are required together;
unreadable, malformed, noncanonical, or mismatched material makes
`C_Initialize` fail. The identity is offered only to `https://` connector URLs.
Redirects are disabled whenever a client identity is configured.
Create and validate the pair with the `yubihsm-tls-client` purpose described in
[Certificate-bundle authoring](docs/pkcs11rs-tool.md).

For a connector whose server certificate is issued by a private CA, configure
a canonical CBOR certificate bundle:

```sh
export PKCS11RS_YUBIHSM_TLS_CA_CERTIFICATE_BUNDLE=/etc/pkcs11rs/connector-ca.cbor
```

The bundle replaces the embedded Mozilla roots for every configured HTTPS
connector; it is not merged with them. Every certificate in the bundle is
parsed and accepted as a trust anchor during `C_Initialize`; an empty,
malformed, or unreadable bundle fails initialization. Certificate-chain,
hostname, and IP-address verification occurs when the HTTPS connection is
made. The setting can be used with or without a client identity.
Create this bundle with the `yubihsm-tls-ca` purpose so every entry is checked
as an independent TLS trust anchor.

Remote connector slots are added alongside directly attached USB devices.
Every `C_GetSlotList` reconciles each configured connector inventory. A newly
reported serial gets a new slot; a known serial keeps its slot ID, remains
registered while absent, and becomes present again when it reappears. A
connector that is unreachable before its first successful inventory contributes
no slot yet. Successful rediscovery also replaces the slot's pooled HTTP client
so a connection left stale by network loss or host sleep is not reused.
Repeated URL entries intentionally remain separate endpoints, each with its own
slots, connector client, and YubiHSM secure session.

Direct YubiHSM USB discovery follows the same serial-based reconciliation on
every `C_GetSlotList`: a newly attached serial gets a slot, detaching it marks
that slot absent, and reattaching the same serial refreshes the existing slot's
transport even if the operating system assigned a different USB device ID.

Direct YubiHSM USB discovery follows `PKCS11RS_HARDWARE_DISCOVERY`, together
with the other local hardware discovery mechanisms. Configured remote slots
remain enabled when local hardware discovery is disabled.

Optionally expose YubiHSM public objects before PKCS #11 login with one
low-privilege discovery Authentication Key:

```sh
# Direct YubiHSM Authentication Key
export PKCS11RS_YUBIHSM_DISCOVERY='00a5service-owned-password'

# Or a YubiHSM Auth credential used with target Authentication Key 00a5
export PKCS11RS_YUBIHSM_DISCOVERY=':00a5public discovery@12345678:credential-password'
```

The credential is tried independently on every YubiHSM. The module retains all
objects whose effective `CKA_PRIVATE` is false; internal PKCS #11 metadata
companions remain hidden. The public-certificate profile is advertised only on
slots where authentication and public discovery succeed, independently of the
currently provisioned object inventory. Malformed provisioned objects are
logged and skipped individually. The discovery session is retained and reused
until login, cleanup, reconnection, or secure-session invalidation. `C_Login`
closes it and installs the user session; after `C_Logout`, the discovery session
is reopened lazily by the next public hardware read. While the profile is
active, user-login Authentication Keys must have exactly the same domains as
the discovery Authentication Key. The value accepts the same direct or
YubiHSM Auth selector as `C_Login`. The password may be omitted when
`PKCS11RS_PINENTRY` is configured; each YubiHSM slot requests it lazily and
caches it only after that slot authenticates successfully. A failed attempt
does not populate another slot's cache. CCID applets, including YubiHSM Auth
providers, are discovered before this YubiHSM discovery pass.

For an asymmetric YubiHSM Auth credential, a provisioner can also persist its
public point as an ordinary `CKO_PUBLIC_KEY` on each matching YubiHSM, using
the Authentication Key ID as `CKA_ID`. A client can compare `CKA_EC_POINT`
across the credential and YubiHSM slots, obtain the explicit target ID, and
then use the normal named `C_LoginUser` form. pkcs11rs performs the selected
login but deliberately does not hide this cross-slot matching policy inside
the provider.

See [YubiHSM public discovery](docs/yubihsm-auth.md#public-object-discovery)
for credential provisioning, metadata, caching, and logout behavior.

Enable protected password entry for YubiHSM and YubiHSM Auth login by naming a
compatible pinentry executable:

```sh
export PKCS11RS_PINENTRY=pinentry
export PKCS11RS_PINENTRY=pinentry-mac
```

Bare executable names are resolved through the process's inherited `PATH`; an
explicit path may be used to select a particular installation. Terminal
frontends on Unix use `GPG_TTY` when set and otherwise fall back to the
process's controlling terminal at `/dev/tty`. No terminal name is sent on
Windows. On macOS, `pinentry-mac` is recommended because Homebrew's plain
`pinentry` is a curses frontend.

Callers request the protected path with a null PIN pointer. Combined YubiHSM
Auth `C_Login` selectors may omit their password separator instead. See
[YubiHSM and YubiHSM Auth login](docs/yubihsm-auth.md) for the exact forms.

## Token Storage

Slots use no durable software storage by default. Set `PKCS11RS_TOKEN_STORAGE`
to an absolute path to opt into local persistence for provider-backed public
token objects on every slot with a stable physical Yubico serial:

```sh
export PKCS11RS_TOKEN_STORAGE="$HOME/.local/share/pkcs11rs"
```

The configured root is created during `C_Initialize`. Objects are separated by
physical token identity and applet, stored below a versioned directory, and
restored automatically on the next module initialization. FIDO registration
and derived signing-key records use the same provider. The older
`PKCS11RS_FIDO2_STORAGE` setting remains supported as a FIDO-only compatibility
option when `PKCS11RS_TOKEN_STORAGE` is unset.

`CKA_TOKEN=CK_FALSE` remains session-only; `CKA_TOKEN=CK_TRUE` selects the slot
provider. Tokens without a stable identity continue to return
`CKR_TOKEN_WRITE_PROTECTED` for provider-backed token-object creation.
Named software slots use the configured root for their encrypted public and
private realms. Their supported asymmetric, AES, HMAC, generic-secret, and
legacy 3DES keys can be persistent token objects. Secret keys must be private.
Other applet and hardware slots still require a private-key token request to be
fulfilled as a real device object; generic local storage never turns such a
request into a software key.

Named software-slot key material and attributes are envelope-encrypted. Other
providers may store only public objects or unencrypted private previewSign
protocol metadata. On Unix, new object files use mode `0600`, but the caller
remains responsible for protecting and backing up the configured directory.
Storage corruption is reported instead of silently ignored. The serial
binding and positive previewSign interoperability still require qualification
with compatible hardware. See [Named software slots](docs/software.md) and
[Content-addressed CBOR storage](docs/storage.md).

## CCID Configuration

The default CCID discovery set contains PIV, OpenPGP, YubiHSM Auth, Issuer SD,
and FIDO2. Each selectable applet is exposed as its own PKCS #11 slot. Native
builds enumerate readers through PC/SC on desktop platforms and CryptoTokenKit
on iOS.

Every `C_GetSlotList` enumerates the current native reader
names, but uses them only to locate candidates. PC/SC names are not portable or
persistent: implementations use different naming and disambiguation rules, and
USB re-enumeration can rename the same reader. The validated YubiKey serial
instead owns the applet topology and slot IDs for the module lifetime. A new
serial is probed once; a different PC/SC, CryptoTokenKit USB, or NFC locator for
a known serial is rebound without repeating applet discovery. Later listings
refresh presence, and real operations reconnect and reselect the slot's AID as
normal PKCS #11 transaction handling. Removing the token therefore marks its
existing slots absent without forgetting them.

pkcs11rs opens PC/SC cards with `SCARD_SHARE_SHARED`. Each device-backed
PKCS #11 call lazily begins one PC/SC transaction before its first APDU and
ends it when the call returns. The applet is reselected inside every new
transaction, so cooperative PC/SC clients can use the card between calls
without corrupting pkcs11rs's selected-applet state. On macOS, GnuPG
`scdaemon` must use its PC/SC path and shared mode to coexist; its direct CCID
driver bypasses PC/SC coordination. Native FIDO HID discovery is independent
and may still expose the authenticator. `PKCS11RS_LOG=warn` logs reader-open
failures, `debug` adds successful discovery and phase timing, and `trace` adds
per-request transport timing.
See [CCID applet configuration](docs/ccid.md#pcsc-ownership-and-external-daemons)
for the exact `scdaemon` configuration boundary.

Limit discovery to selected applets with:

```sh
export PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

See [FIDO2 support](docs/fido2.md) for the USB HID and smart-card transport
boundaries, PIN-management mapping, read-only credential mapping, and
compatibility-test commands.

Enable secure messaging for selected applets with one of:

```sh
export PKCS11RS_CCID_SECURE_CHANNEL=scp03
export PKCS11RS_CCID_SECURE_CHANNEL=scp11a
export PKCS11RS_CCID_SECURE_CHANNEL=scp11b
export PKCS11RS_CCID_SECURE_CHANNEL=scp11c
```

Detailed configuration:

- [Initialization configuration](docs/configuration.md)
- [iOS application integration for Swift and Objective-C](docs/ios-integration.md)
- [Multi-device YubiHSM connector](docs/connector.md)
- [Named software slots](docs/software.md)
- [Vendor extension API index](docs/extensions.md)
- [iPhone smoke test](examples/ios/PKCS11RSPhoneSmoke/README.md)
- [Objective-C iPhone smoke test](examples/ios/PKCS11RSObjCSmoke/README.md)
- [Software secret-key design history](docs/software-secret-keys-plan.md)
- [Provider abstraction roadmap](docs/provider-abstraction-plan.md)
- [CCID discovery, AID overrides, and diagnostics](docs/ccid.md)
- [YubiHSM and YubiHSM Auth login](docs/yubihsm-auth.md)
- [PIV backend](docs/piv.md)
- [OpenPGP backend](docs/openpgp.md)
- [SCP03](docs/scp03.md)
- [SCP11a, SCP11b, and SCP11c](docs/scp11.md)
- [Internal architecture and object graph](docs/architecture.md)
- [Certificate-bundle authoring and validation](docs/pkcs11rs-tool.md)
- [Binary object formats](docs/formats.md)
- [Content-addressed CBOR storage boundary](docs/storage.md)
- [FIDO2 and previewSign](docs/fido2.md)
- [previewSign persistence and wire format](docs/preview-sign.md)
- [Public-key projection proposal and implementation boundary](docs/public-key-projection-proposal.md)

## Diagnostics

`logging.level` in initialization JSON, or its `PKCS11RS_LOG` environment
fallback, accepts `off`, `error`, `warn`, `info`, `debug`, or `trace`. An
explicit level writes to Apple Unified Logging on iOS and standard error on
other platforms. With no configured level, pkcs11rs installs no subscriber and
participates in an ambient Rust `tracing` subscriber. Debug output explains named reader/device discovery,
applet outcomes, slot registration and retention, deduplication decisions,
phase durations, and every PKCS #11 entry point with its return value and
duration. Trace output adds API state diagnostics and per-request connector,
APDU, and transport timing.

## Testing

### Rust test prerequisites

The hardware-independent Rust test suite has the following external
requirements:

| Platform | Requirements |
| --- | --- |
| Linux | Rust 1.85 or newer, a working C compiler/linker, `pkg-config`, PC/SC development files, libudev development files, and `/bin/sh` |
| macOS | Rust 1.85 or newer, Xcode Command Line Tools, `pkg-config`, and `/bin/sh`; PC/SC and IOKit are system frameworks |
| Windows | Rust 1.85 or newer using the MSVC target, Visual Studio C++ Build Tools, and the Windows SDK; no separately installed PC/SC, HID, or libudev package is required |

For example, on Debian or Ubuntu:

```sh
sudo apt-get install build-essential pkg-config libpcsclite-dev libudev-dev
cargo test --locked
```

The first Cargo invocation needs access to the crate registry unless all
dependencies are already cached or vendored. Once the dependencies are
available, the Rust tests require no Internet access, although loopback TCP
connections must be permitted for the in-process HTTP and TLS test servers.
Unix tests use `/bin/sh` to emulate `pinentry`.

Neither normal nor all-features Rust test runs require:

- Python or a Python environment
- the OpenSSL executable or OpenSSL libraries
- OpenSC or `pkcs11-tool`
- Clang or libclang
- libusb
- a separately installed `hidapi`
- physical hardware
- a running `pcscd`

The Linux CI image additionally installs Clang, libclang, and OpenSC because
the complete validation job also checks regenerated PKCS #11 bindings and runs
the Python ABI, OpenSSL, and OpenSC tests. Those packages are not prerequisites
for the Rust test suite itself. Clang and libclang are required only when
running `cargo xtask bindings` or `cargo xtask bindings --check`.

Run the Rust test suite:

```sh
cargo test --locked
cargo test --locked --all-features
```

These default-workspace commands test the PKCS #11 provider, connector, and
`pkcs11rs-tool`. Add `--workspace` to also run the internal local-hardware
crate's package tests directly.

To test the production shared library with the operating system's native
dynamic loader, without Python, build it and run the explicit loader smoke
test:

```sh
cargo build --locked
cargo xtask load-shared-library
```

The smoke test resolves the exported PKCS #11 entry points, initializes the
module with local hardware discovery disabled, queries its slots, finalizes
it, and unloads it. It lives outside Cargo's integration-test discovery, so
ordinary and all-features `cargo test` runs do not compile a second library
test target.

Run the hardware-independent Python ABI tests:

```sh
python3 test_pkcs11.py
```

The Python ABI suite builds the shared library with its deterministic test
backend, loads the resulting `.so`, `.dylib`, or `.dll`, and exercises its
exported PKCS #11 entry points.

The four final OASIS PKCS #11 3.2 mandatory provider profile artifacts are
also executable as four separate tests against either the deterministic ABI
backend or a selected production module and slot:

```sh
python3 conformance/run_oasis.py --results target/oasis-results
```

See the [OASIS profile test runner](conformance/README.md) for individual test
commands, live-module provisioning requirements, result provenance, and the
qualification boundary.

Live hardware tests are excluded from normal test runs. Run the Python smoke
tests explicitly:

```sh
PKCS11RS_RUN_HARDWARE_TESTS=1 python3 test_hardware.py
```

Those tests remain read-only unless a mutating test's additional variables are
set. The previewSign dynamic-library test requires an exact
`PKCS11RS_FIDO2_TEST_SOURCE` serial and `PKCS11RS_FIDO2_TEST_PIN`; it creates one
parent credential, derives and exercises two signing keys, and deletes the
parent before returning. Its exact command and qualification boundary are in
[Experimental FIDO previewSign](docs/preview-sign.md#hardware-status).

Rust hardware tests are individually ignored. Run a named test rather than
the entire ignored set: several tests provision, change, or deliberately
retain persistent device objects. Each mutating test documents and checks its
own environment-variable gate; the FIDO2 tests are documented in
[FIDO2 support](docs/fido2.md), and YubiHSM Auth and SCP11 provisioning tests
are documented in their backend guides.

Running an ignored hardware test also requires the selected device, its
platform driver, and access permissions. The Rust hardware-test harness
explicitly enables local hardware discovery and ignores ordinary
`PKCS11RS_YUBIHSM_URLS`, so YubiHSM hardware tests use direct USB rather than a
configured HTTP connector. PC/SC-backed tests require the platform smart-card
service (`pcscd` on Linux). Direct YubiHSM USB tests on Windows use the default
WinUSB binding for the YubiHSM interface. These requirements do not apply to
the default `cargo test` run.

The read-only FIDO cross-interface diagnostic deliberately overlaps HID and
CCID operations on the same serial-numbered YubiKey and reports whether the
interfaces interfere:

```sh
cargo test diagnoses_yubikey_hid_ccid_cross_interface_concurrency \
  -- --ignored --nocapture
```

The corresponding protected-path test is
`serializes_yubikey_hid_ccid_cross_interface_operations`.
`pkcs11_dispatch_serializes_fido_hid_login_against_piv_ccid` additionally
exercises automatic device correlation and the exported PKCS #11 dispatch
path; it is gated by `PKCS11RS_FIDO2_TEST_PIN` and verifies that PIN once.

The direct YubiHSM USB smoke test performs only discovery and metadata reads
through `nusb`. Leave `PKCS11RS_YUBIHSM_URLS` unset so every reported YubiHSM
slot must be a directly attached USB device:

```sh
cargo test direct_yubihsm_usb_slot_reports_metadata \
  -- --ignored --nocapture
```

The direct-hardware lifecycle test covers finalize-before-initialize, repeated
initialize and finalize calls, a cycle that discovers a YubiHSM, and three
immediate initialize/finalize cycles with no intervening PKCS #11 operation:

```sh
cargo test direct_hardware_survives_initialize_finalize_orderings \
  -- --ignored --nocapture
```

The non-mutating session-expiry test enables session recreation, logs in with a
direct YubiHSM Authentication Key, waits 35 seconds without sending a device
command, and verifies that the next random-generation command recreates the
expired secure session while the PKCS #11 session remains logged in:

```sh
cargo test recreates_expired_yubihsm_session_on_hardware \
  -- --ignored --nocapture
```

The complementary default-policy test opens two PKCS #11 sessions, lets their
shared YubiHSM secure session expire, and verifies that the expiry failure logs
the entire slot out so both PKCS #11 sessions become public sessions:

```sh
cargo test expired_yubihsm_session_logs_out_every_pkcs11_session_on_hardware \
  -- --ignored --nocapture
```

It uses authentication key `0001` and password `password` by default. Override
them with `PKCS11RS_TEST_YUBIHSM_ADMIN_ID` and
`PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD`; select one device with
`PKCS11RS_TEST_YUBIHSM_SOURCE` when more than one is present.

The destructive-path YubiHSM RSA wrapping test is separately gated. It uses
only exported PKCS #11 calls to generate an exportable P-256 target and an
RSA-2048 private wrap key. It materializes the distinct YubiHSM RSA public wrap
key through `C_GenerateKeyPair`, `C_CreateObject`, and `C_DeriveKey`, restores
the wrapped target, and removes every created object before returning:

```sh
PKCS11RS_TEST_YUBIHSM_RSA_WRAP=1 \
cargo test generated_ec_key_round_trips_through_rsa_public_wrap_key_on_hardware \
  -- --ignored --nocapture
```

The test uses authentication key `0001` and password `password` by default.
Override them with `PKCS11RS_TEST_YUBIHSM_ADMIN_ID` and
`PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD`. Set
`PKCS11RS_TEST_YUBIHSM_SOURCE` to a serial number or full slot name when more
than one YubiHSM is present.

An X25519 interoperability test generates one persistent key in an empty PIV
slot and one auto-allocated persistent YubiHSM key, derives the shared secret in
both directions, and intentionally leaves both keys provisioned:

```sh
PKCS11RS_TEST_X25519_INTEROP=1 \
cargo test piv_and_yubihsm_x25519_hardware_keys_derive_the_same_secret \
  -- --ignored --nocapture
```

The test defaults to PIV `CKA_ID=24` (retired slot 20), the factory PIV
management key and PIN, and YubiHSM authentication key `0001` with password
`password`. It refuses to overwrite an occupied PIV slot. Select devices with
`PKCS11RS_TEST_PIV_SOURCE` and `PKCS11RS_TEST_YUBIHSM_SOURCE`; override the PIV
slot, management key, and PIN with `PKCS11RS_TEST_PIV_X25519_CKA_ID`,
`PKCS11RS_TEST_PIV_MANAGEMENT_KEY`, and `PKCS11RS_TEST_PIV_PIN`.

The `abi-tests` Cargo feature adds synthetic slots used by the test suite. It
is not intended for a normal module build.

## In-process mock YubiKey

The `mock-yubikey` Cargo feature builds a deterministic PKCS #11 module with
one in-process YubiKey FIDO2 applet and disables USB, HTTP, and PC/SC hardware
discovery. The mock is visible only through pkcs11rs; it does not install a
virtual reader or card.

The logical authenticator is provided by `virtual-yubikey-core` from the
[`virtual-yubikey`](https://github.com/qpernil/virtual-yubikey) repository.
The neutral `virtual-yubikey-crypto` crate from the same repository supplies
the software ECDSA, Ed25519, and ML-DSA signing and verification primitives
used by both the virtual authenticator and pkcs11rs. PKCS #11-specific
mechanism handling remains in this repository; algorithms not yet covered by
the shared crate, including the broader PKCS #11 RSA profiles, keep their local
implementations.
`pkcs11rs` follows that repository's `main` branch, while `Cargo.lock` records
the exact commit validated by this checkout. Advance the recorded revision
with:

```sh
cargo update -p virtual-yubikey-core -p virtual-yubikey-crypto
```

```sh
cargo build --release --features mock-yubikey
pkcs11-tool --module target/release/libpkcs11rs.dylib --list-slots
```

The initial PIN is `123456`. Mock device state, including PIN changes and
created credentials, lasts for the client process and survives
`C_Finalize`/`C_Initialize`; unloading the library or ending the process resets
it. The mock begins with one deterministic resident
credential and implements credential-management enumeration, RP-bound
context-specific login, a genuine ES256 GetAssertion response, and verification
through its projected public key. It also implements the complete experimental
previewSign PKCS #11 flow: credential registration, registration-attribute
export/import, offline ARKG derivation, derived-key metadata export and strict
re-import, GetAssertion signing, public-key projection, and PKCS #11
verification with the derived public key.

## Persistence boundary

Each PKCS #11 session owns an in-memory `StorageProvider`, and each slot owns a
token provider. Generic public projections and previewSign registration and
derived-key objects are encoded as canonical, content-addressed CBOR and routed
by `CKA_TOKEN`: session objects use the current session's memory provider,
while token objects use the slot provider. Slots without configured or native
storage use `UnavailableStorageProvider`, so unsupported token persistence
fails explicitly instead of silently becoming session-local. When
`PKCS11RS_TOKEN_STORAGE` is configured, slots with a stable Yubico physical
serial install separate durable local providers for each applet and
automatically restore their saved backed objects. `PKCS11RS_FIDO2_STORAGE`
retains its earlier FIDO-only behavior for compatibility. Applications can
also restore exported previewSign registration or derived-key wrappers
manually through `C_CreateObject`.

YubiHSM implements the token-provider boundary with pkcs11rs-owned opaque
metadata objects on the device. Its canonical CBOR uses the distinct
`pkcs11rs metadata ...` namespace. Legacy `MDB1` companions under Yubico's
`Meta object for ...` namespace are read-only compatibility input, used only
when no pkcs11rs metadata exists for the target; pkcs11rs never rewrites or
deletes them. A YubiHSM public token object exists only when its canonical
public aspect is explicitly present; linked public material comes from the
native key and is not duplicated in metadata. `C_GenerateKeyPair`
returns a session public key by default and persists it only when the public
template explicitly sets `CKA_TOKEN=CK_TRUE`; the same choice is available
through `CKM_PKCS11RS_PROJECT_PUBLIC_KEY`. Destroying that public object removes
only the canonical public aspect. Destroying the hardware private object first
morphs a surviving public aspect into a standalone public-key record. See
[Content-addressed CBOR storage](docs/storage.md) and
[Experimental FIDO previewSign boundary](docs/preview-sign.md) for the exact
integration limits.

`C_CopyObject` is unsupported across a YubiHSM slot, including for public keys
whose implementation backing is an internal opaque record. Such objects report
`CKA_COPYABLE=CK_FALSE`; use `C_CreateObject` to create an independent public
key explicitly.

The module has typed software private-key implementations for RSA, NIST P-224,
P-256, P-384 and P-521, secp256k1, brainpoolP256r1, brainpoolP384r1,
brainpoolP512r1, Ed25519, and X25519. They are reserved for named slots
configured by `PKCS11RS_SOFTWARE_SLOTS`; hardware and applet slots neither
advertise nor create generic software private keys. Their shared public-key
implementation remains available for projected and imported public objects.
A private template with `CKA_TOKEN=CK_TRUE` never falls back to software
session storage. Encrypted persistent software private keys exist only in an
explicitly named software slot with `PKCS11RS_TOKEN_STORAGE` configured.
The low-level `PKCS11RS_SoftwareExportPrivateKey` extension exports only
`CKA_EXTRACTABLE=CK_TRUE` software private keys after `CKU_USER` login. Its
standard PKCS #8 `EncryptedPrivateKeyInfo` uses PBES2 with scrypt and
AES-256-CBC and retains the inner PKCS #9 label and ID attributes.

## Known Limitations

- Mechanisms and objects are advertised dynamically, so availability depends
  on the selected backend, installed keys, device firmware, and policy.
- Live-hardware coverage includes discovery, authentication, provisioning,
  PIN management, and selected cryptographic interoperability paths, but it
  does not qualify every supported operation, platform, or firmware.
- OpenPGP key generation and private-key import are restricted to references
  that the card reports as empty, so PKCS #11 operations cannot overwrite an
  existing OpenPGP key. Readable OpenPGP data objects are exported read-only.
- YubiHSM native object properties are cached per slot and invalidated by object
  sequence changes and transport reconnection. A replacement with a different
  serial is discovered as a new slot by the next `C_GetSlotList`; changing the
  domains available to an authentication credential still requires module
  reinitialization.
- Secure-channel credential provisioning and trust-anchor selection are
  deployment responsibilities.
- Binary packaging, system installation, and platform-specific PKCS #11 loader
  configuration are not yet provided by this repository.

## Vendored Headers

[`pkcs11.h`](pkcs11.h), [`pkcs11f.h`](pkcs11f.h), and
[`pkcs11t.h`](pkcs11t.h) are byte-for-byte copies of the final OASIS PKCS #11
3.2 Standard header artifacts and retain the OASIS notices. The generated Rust
bindings are checked in at [`src/pkcs11.rs`](src/pkcs11.rs), so normal builds do
not require Clang or libclang.

[`pkcs11rs.h`](pkcs11rs.h) is the separately maintained public header for
vendor mechanisms, attributes, constants, and extension functions. See the
[vendor extension API index](docs/extensions.md) for ownership and usage
contracts and links to each feature's detailed documentation.

Maintainers can regenerate the bindings with `cargo xtask bindings`. This
explicit command requires Clang/libclang. Run `cargo xtask bindings --check` to
verify that the checked-in bindings match the vendored headers; CI performs the
same check.

See [Third-Party Notices](THIRD_PARTY_NOTICES.md) for provenance and licensing
details.

## References

### PKCS #11 and CCID

- [OASIS PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- [OASIS PKCS #11 Usage Guide Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/pkcs11-ug-v3.2.html)
- [OASIS PKCS #11 Profiles Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/pkcs11-profiles-v3.2.html)
- [USB-IF Smart Card CCID Specification Revision 1.1](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)

### YubiKey Applications

- [NIST SP 800-73-5 Part 2: PIV Card Application Card Command Interface](https://csrc.nist.gov/pubs/sp/800/73/pt2/5/final)
- [YubiKey PIV Application](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html)
- [OpenPGP Card Application Version 3.4.1](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
- [YubiKey OpenPGP Application](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html)

### Secure Channels and YubiHSM

- [GlobalPlatform Secure Channel Protocol '03', Amendment D Version 1.2](https://globalplatform.org/specs-library/secure-channel-protocol-03-amendment-d-v1-2/)
- [GlobalPlatform Secure Channel Protocol '11', Amendment F Version 1.4](https://globalplatform.org/specs-library/secure-channel-protocol-11-amendment-f/)
- [YubiKey SCP03 and SCP11 Specifics](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-scp.html)
- [YubiHSM 2 Command Reference](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html)

## Security Notes

- Private and secret keys are treated as non-extractable unless an operation
  explicitly produces a readable session object, such as a derived secret.
- SCP03 factory test keys are publicly known provisioning values and must not
  be treated as production credentials. See the [SCP03 documentation](docs/scp03.md).
- Secure-channel trust anchors, key provisioning, card policy, and deployment
  validation remain the responsibility of the integrator.

The project is under active development. Test the exact hardware, firmware,
mechanisms, and client software used by a deployment before relying on it in a
production environment.

Security issues should be reported according to the
[security policy](.github/SECURITY.md). This project is distributed under the
[MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option, except for third-party
material identified separately.
