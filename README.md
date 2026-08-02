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

- **YubiKey PIV** over PC/SC, including RSA, ECDSA, Ed25519, ECDH/X25519,
  certificates, metadata, attestation, PIN policy, and random generation.
- **YubiKey OpenPGP** over PC/SC, including signing, RSA deciphering, ECDH,
  certificates, OpenPGP PIN KDFs, and random generation.
- **YubiHSM 2** over direct USB or the HTTP YubiHSM Connector, including
  authenticated sessions, hardware-backed asymmetric, symmetric, HMAC,
  wrapping, opaque, and authentication objects.
- **YubiHSM Auth** as a discoverable CCID applet whose credentials can
  authenticate sessions on local or remote YubiHSM slots.
- **Issuer SD** discovery with read-only key metadata, CA identifiers, CPLC,
  SCP11 certificate chains, and explicit SCP03/SCP11 administration APIs.
- **FIDO2** discovery over native USB HID and the CTAP smart-card binding over
  NFC or USB CCID where available. This includes PIN provisioning and changes,
  read-only resident-credential metadata, software public-key operations, and
  an explicit one-shot GetAssertion mechanism after context-specific PIN
  login, with an experimental opt-in previewSign registration, offline
  derivation, and hardware-signing lifecycle on devices advertising that
  extension.
- **SCP03, SCP11a, SCP11b, and SCP11c** secure messaging for selected CCID
  applets.
- **Named software slots** created only by explicit configuration, with
  login-gated session RSA, EC, Ed25519, and X25519 private keys, plus encrypted
  persistent private keys when local token storage is configured.

Hardware and firmware capabilities determine which objects and mechanisms are
available in a particular slot.

The vendor `CKM_PKCS11RS_PROJECT_PUBLIC_KEY` mechanism provides a reference
implementation of public-key projection through `C_DeriveKey`: a private key
with recoverable public metadata can produce an independent public session
object for ordinary software verification or RSA encryption. YubiHSM private
keys can additionally produce persistent public token objects backed by
pkcs11rs-owned canonical metadata. See the
[public-key projection proposal](docs/public-key-projection-proposal.md) for
the proposed standard semantics and current implementation boundary.

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

For compatibility with OpenSSL PKCS #11 integrations, a non-null
`CK_C_INITIALIZE_ARGS.pReserved` is accepted as opaque caller configuration.
pkcs11rs neither dereferences nor retains it; module configuration continues to
come from the documented environment variables. `C_Finalize` still requires
its reserved argument to be null.

Initialization and finalization are nonblocking lifecycle transitions. They
return `CKR_FUNCTION_FAILED` if another PKCS #11 call is executing; ordinary
calls return `CKR_CRYPTOKI_NOT_INITIALIZED` while either transition is active.

Applet connectors on a reader share one `PcscReaderState`, which owns the card
connection, selected AID, APDU capabilities, SCP state, and complete APDU
exchange lock. Local operations on different applet slots can execute
concurrently; actual card exchanges on one reader are serialized. Different
YubiHSMs and different PC/SC readers can also execute concurrently. When
Yubico's device-information commands report the same physical serial over HID
and PC/SC, pkcs11rs additionally prevents its own HID and CCID operations from
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
| MSRV | An all-features build is checked with Rust 1.85. |
| Dependencies | Advisories and accepted licenses are checked with `cargo-deny`. |
| Live hardware | Ignored and explicitly gated Rust tests cover discovery, login, PIN changes, provisioning, and selected cross-device cryptographic operations on attached YubiKey and YubiHSM devices. The Python smoke test covers production slot and token metadata. |

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

The shared library is written to the Cargo target directory. Typical paths are:

```text
target/debug/libpkcs11rs.so       Linux
target/debug/libpkcs11rs.dylib    macOS
target/debug/pkcs11rs.dll         Windows
```

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

This skips direct YubiHSM USB, native FIDO HID, and PC/SC/CCID reader
discovery, including PIV, OpenPGP, YubiHSM Auth, Issuer SD, and FIDO2 applets.
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
`CKA_TOKEN=CK_TRUE` public, private, AES, HMAC, and generic-secret keys are
encrypted below a name-scoped root and survive restart; without that
configuration the request returns `CKR_TOKEN_WRITE_PROTECTED` and never falls
back to session storage. Extractable software private keys can be exported
through `PKCS11RS_SoftwareExportPrivateKey` as password-encrypted,
OpenSSL-compatible PKCS #8 while a user login is active. This capability is
not enabled on any hardware or applet slot. See
[Named software slots](docs/software.md) for the exact PIN, export, storage,
format, mechanism, metadata, and lifecycle semantics.

Add remote YubiHSM Connector instances with a comma-separated URL list:

```sh
export PKCS11RS_YUBIHSM_URLS=http://hsm-a:12345,http://hsm-b:12345
```

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

Remote connector slots are added alongside directly attached USB devices. Each
configured URL always has a slot; an unreachable connector or a connector with
no device is reported as an empty slot until the module is reinitialized.
Repeated URLs intentionally create separate slots, each with its own connector
client and YubiHSM secure session.

Disable only direct YubiHSM USB discovery while retaining other local
discovery and configured remote slots:

```sh
export PKCS11RS_YUBIHSM_USB=0
```

The setting defaults to `1`. Any value other than `0` or `1` makes
`C_Initialize` return `CKR_ARGUMENTS_BAD`.

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
private realms. Their supported asymmetric, AES, HMAC, and generic-secret keys
can be persistent token objects. Secret keys must be private. Other applet and
hardware slots still require a private-key token request to be fulfilled as a
real device object; generic local storage never turns such a request into a
software key.

Named software-slot key material and attributes are envelope-encrypted. Other
providers may store only public objects or unencrypted private previewSign
protocol metadata. On Unix, new object files use mode `0600`, but the caller
remains responsible for protecting and backing up the configured directory.
Storage corruption is reported instead of silently ignored. The serial
binding and positive previewSign interoperability still require qualification
with compatible hardware. See [Named software slots](docs/software.md) and
[Content-addressed CBOR storage](docs/storage.md).

## CCID Configuration

The default PC/SC discovery set contains PIV, OpenPGP, YubiHSM Auth, Issuer SD,
and FIDO2. Each selectable applet is exposed as its own PKCS #11
slot.

Discovery is a snapshot taken by the first `C_GetSlotList` after
`C_Initialize`. An empty reader contributes no slot. A selected applet keeps
its slot even if later initialization fails; existing slots reconnect and
reselect their own AID when sessions are opened. New readers and applets that
were absent from the original snapshot require `C_Finalize` followed by
`C_Initialize`.

pkcs11rs opens PC/SC cards with `SCARD_SHARE_EXCLUSIVE` and does not currently
use PC/SC transactions. A reader already held by another process therefore
contributes no CCID applet slots to the discovery snapshot. On macOS this
commonly includes GnuPG `scdaemon`; native FIDO HID discovery is independent
and may still expose the authenticator. `PKCS11RS_DEBUG=1` logs the reader name
when it cannot be opened, while level `2` also logs successful reader opens.
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

- [Named software slots](docs/software.md)
- [Planned software AES, HMAC, derivation, and wrapping support](docs/software-secret-keys-plan.md)
- [Planned pure Rust provider abstraction](docs/provider-abstraction-plan.md)
- [CCID discovery, AID overrides, and diagnostics](docs/ccid.md)
- [YubiHSM and YubiHSM Auth login](docs/yubihsm-auth.md)
- [PIV backend](docs/piv.md)
- [OpenPGP backend](docs/openpgp.md)
- [SCP03](docs/scp03.md)
- [SCP11a, SCP11b, and SCP11c](docs/scp11.md)
- [Internal architecture and object graph](docs/architecture.md)
- [Binary object formats](docs/formats.md)
- [Content-addressed CBOR storage boundary](docs/storage.md)

## Diagnostics

`PKCS11RS_DEBUG` is read during `C_Initialize`:

| Value | Output |
| --- | --- |
| unset or `0` | Disabled |
| `1` | Initialization and applet-discovery failures |
| `2` | API and transport diagnostics |

Other values cause `C_Initialize` to return `CKR_ARGUMENTS_BAD`.

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

Live hardware tests are excluded from normal test runs. Run the Python
read-only smoke test explicitly:

```sh
PKCS11RS_RUN_HARDWARE_TESTS=1 python3 test_hardware.py
```

Rust hardware tests are individually ignored. Run a named test rather than
the entire ignored set: several tests provision, change, or deliberately
retain persistent device objects. Each mutating test documents and checks its
own environment-variable gate; the FIDO2 tests are documented in
[FIDO2 support](docs/fido2.md), and YubiHSM Auth and SCP11 provisioning tests
are documented in their backend guides.

Running an ignored hardware test also requires the selected device, its
platform driver, and access permissions. PC/SC-backed tests require the
platform smart-card service (`pcscd` on Linux). Direct YubiHSM USB tests on
Windows use the default WinUSB binding for the YubiHSM interface. These
requirements do not apply to the default `cargo test` run.

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

The destructive-path YubiHSM RSA wrapping test is separately gated. It uses
auto-assigned object IDs, generates an exportable P-256 target and RSA-2048
wrap key, restores the wrapped target, and removes both keys before returning:

```sh
PKCS11RS_TEST_YUBIHSM_RSA_WRAP=1 \
cargo test generated_ec_key_round_trips_through_private_rsa_wrap_key_on_hardware \
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
public aspect contains validated public-key material. `C_GenerateKeyPair`
returns a session public key by default and persists it only when the public
template explicitly sets `CKA_TOKEN=CK_TRUE`; the same choice is available
through `CKM_PKCS11RS_PROJECT_PUBLIC_KEY`. Destroying that public object removes
only the canonical public aspect, while destroying the hardware private object
also removes its pkcs11rs-owned companion metadata. See
[Content-addressed CBOR storage](docs/storage.md) and
[Experimental FIDO previewSign boundary](docs/preview-sign.md) for the exact
integration limits.

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
  sequence changes. Reinitialize the module after replacing a USB device or
  changing the domains available to an authentication credential. Remote
  connector serial/version changes and reconnections invalidate their slot
  cache automatically.
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
- [YubiKey SCP03 and SCP11 Specifics](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-scp-specifics.html)
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
