# pkcs11rs

[![CI](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml)

`pkcs11rs` is a Rust PKCS #11 provider for YubiKey CCID applets and YubiHSM
devices. It exposes hardware-backed keys and certificates through the standard
Cryptoki API while keeping private key operations on the device.

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
- **FIDO2** discovery over the CTAP smart-card binding: over USB CCID on
  YubiKey firmware that exposes it there, and over NFC on compatible
  YubiKeys. This includes PIN provisioning and changes plus read-only
  resident-credential metadata and non-operational key projections after PIN
  login.
- **SCP03, SCP11a, SCP11b, and SCP11c** secure messaging for selected CCID
  applets.

Hardware and firmware capabilities determine which objects and mechanisms are
available in a particular slot.

## PKCS #11 3.2 profiles

Every present slot advertises a public, immutable, token-resident
`CKP_BASELINE_PROVIDER` object. Additional `CKO_PROFILE` objects are derived
from the backend's advertised behavior:

| Profile | Availability |
| --- | --- |
| `CKP_BASELINE_PROVIDER` | Every present slot |
| `CKP_EXTENDED_PROVIDER` | YubiHSM slots and other slots whose mechanism list satisfies the mandatory Extended Provider mechanism and flag vector |
| `CKP_AUTHENTICATION_TOKEN` | Slots advertising signing-capable `CKM_SHA256_RSA_PKCS` |
| `CKP_PUBLIC_CERTIFICATES_TOKEN` | PIV and OpenPGP slots; YubiHSM slots only after successful configured public discovery |

Each `CKO_PROFILE` object identifies one supported profile through its
`CKA_PROFILE_ID` attribute and has a stable, distinct `CKA_UNIQUE_ID`. The
YubiHSM public-certificates profile is based on an actual authenticated
discovery result, not merely on the presence of configuration.

YubiHSM slots advertise the Extended Provider profile because the module
provides its required provider behavior through the YubiHSM's standard and
vendor-backed wrapping adaptations. The profile describes the slot
implementation and does not depend on which key algorithms are currently
provisioned.

## Threading

The module uses its own synchronization when `C_Initialize` permits native
locking through `CKF_OS_LOCKING_OK`. Application-provided mutex callbacks are
not used; when both callbacks and `CKF_OS_LOCKING_OK` are supplied, native
locking is selected. Each PKCS #11 slot has an independently locked child
context containing its sessions, login state, and object-handle state.
Searches and active cryptographic operations belong to their individual
sessions.

Initialization and finalization are nonblocking lifecycle transitions. They
return `CKR_FUNCTION_FAILED` if another PKCS #11 call is executing; ordinary
calls return `CKR_CRYPTOKI_NOT_INITIALIZED` while either transition is active.

Applet connectors on a reader share one `PcscReaderState`, which owns the card
connection, selected AID, APDU capabilities, SCP state, and complete APDU
exchange lock. Local operations on different applet slots can execute
concurrently; actual card exchanges on one reader are serialized. Different
YubiHSMs and different PC/SC readers can also execute concurrently.

See [Architecture](docs/architecture.md) for the object graph, lifecycle
locking, session ownership, transport sharing, and cache boundaries.

## Compatibility and Validation

| Area | Status |
| --- | --- |
| PKCS #11 ABI | Function-list layouts and behavior for 2.40, 3.0, 3.1, and 3.2 are covered by Rust and Python tests. |
| Linux | The complete hardware-independent Rust and Python suites run in GitHub Actions. |
| Windows | Rust tests and the synthetic ABI backend are compiled with warnings denied on a native Windows runner. |
| macOS | The `.dylib`, Rust tests, Clippy, generated bindings, and synthetic ABI backend are checked in GitHub Actions. |
| MSRV | An all-features build is checked with Rust 1.85. |
| Dependencies | Advisories and accepted licenses are checked with `cargo-deny`. |
| Live hardware | Ignored and explicitly gated Rust tests cover discovery, login, PIN changes, provisioning, and selected cross-device cryptographic operations on attached YubiKey and YubiHSM devices. The Python smoke test covers production slot and token metadata. |

Protocol tests use deterministic mock transports and official cryptographic
test vectors where available. Live-device tests are deliberately excluded from
normal CI and are not a substitute for qualifying the exact hardware and
firmware used in a deployment.

## Prerequisites

Building requires a Rust toolchain plus the development files for:

- PC/SC
- libusb 1.0

The exact package names depend on the operating system and package manager.
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

Add remote YubiHSM Connector instances with a comma-separated URL list:

```sh
export PKCS11RS_YUBIHSM_URLS=http://hsm-a:12345,http://hsm-b:12345
```

Remote connector slots are added alongside directly attached USB devices. Each
configured URL always has a slot; an unreachable connector or a connector with
no device is reported as an empty slot until the module is reinitialized.
Repeated URLs intentionally create separate slots, each with its own connector
client and YubiHSM secure session.

Disable direct YubiHSM USB discovery while retaining configured remote slots:

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

Limit discovery to selected applets with:

```sh
export PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

See [FIDO2 over CCID](docs/fido2.md) for the firmware boundary, PIN-management
mapping, read-only credential mapping, and compatibility-test commands.

Enable secure messaging for selected applets with one of:

```sh
export PKCS11RS_CCID_SECURE_CHANNEL=scp03
export PKCS11RS_CCID_SECURE_CHANNEL=scp11a
export PKCS11RS_CCID_SECURE_CHANNEL=scp11b
export PKCS11RS_CCID_SECURE_CHANNEL=scp11c
```

Detailed configuration:

- [CCID discovery, AID overrides, and diagnostics](docs/ccid.md)
- [YubiHSM and YubiHSM Auth login](docs/yubihsm-auth.md)
- [PIV backend](docs/piv.md)
- [OpenPGP backend](docs/openpgp.md)
- [SCP03](docs/scp03.md)
- [SCP11a, SCP11b, and SCP11c](docs/scp11.md)
- [Internal architecture and object graph](docs/architecture.md)
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

Run the Rust test suite:

```sh
cargo test --locked
cargo test --locked --all-features
```

Run the hardware-independent Python ABI tests:

```sh
python3 test_pkcs11.py
```

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

The initial PIN is `123456`. Mock state, including PIN changes, currently lasts
only for the lifetime of the loaded module and resets when the client process
unloads or reinitializes it.

## Persistence boundary

The crate exposes a `StorageProvider` boundary and a local implementation for
immutable, content-addressed CBOR blobs. The YubiHSM backend validates this
design by exposing its internal key-metadata companions through the same
boundary, writing canonical backed-key CBOR and converting legacy metadata on
read. FIDO persistence is not yet connected to a PKCS #11 slot or
configuration variable. The experimental `previewSign` model defines canonical
registration and derived-key records, but does not automatically persist them
or expose PKCS #11 signing objects. See
[Content-addressed CBOR storage](docs/storage.md) and
[Experimental FIDO previewSign boundary](docs/preview-sign.md) for the exact
integration limits.

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
