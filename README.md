# pkcs11rs

[![CI](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/pkcs11rs/actions/workflows/ci.yml)

`pkcs11rs` is a Rust PKCS #11 provider for YubiKey CCID applets and YubiHSM
devices. It exposes hardware-backed keys and certificates through the standard
Cryptoki API while keeping private key operations on the device.

The project currently implements PKCS #11 2.40, 3.0, 3.1, and 3.2 function
tables. Unsupported entry points are present in the ABI and return the
appropriate PKCS #11 error instead of being omitted.

## Backends

- **YubiKey PIV** over PC/SC, including RSA, ECDSA, Ed25519, ECDH/X25519,
  certificates, metadata, attestation, PIN policy, and random generation.
- **YubiKey OpenPGP** over PC/SC, including signing, RSA deciphering, ECDH,
  certificates, OpenPGP PIN KDFs, and random generation.
- **YubiHSM 2** over direct USB or the HTTP YubiHSM Connector, including
  authenticated sessions, hardware-backed asymmetric, symmetric, HMAC,
  wrapping, opaque, and authentication objects.
- **YubiHSM Auth** as a discoverable CCID applet whose credentials can
  authenticate sessions on YubiHSM USB slots.
- **Issuer SD** discovery with read-only key metadata, CA identifiers, CPLC,
  SCP11 certificate chains, and explicit SCP03/SCP11 administration APIs.
- **SCP03, SCP11a, SCP11b, and SCP11c** secure messaging for selected CCID
  applets.

Hardware and firmware capabilities determine which objects and mechanisms are
available in a particular slot.

## Compatibility and Validation

| Area | Status |
| --- | --- |
| PKCS #11 ABI | Function-list layouts and behavior for 2.40, 3.0, 3.1, and 3.2 are covered by Rust and Python tests. |
| Linux | The complete hardware-independent Rust and Python suites run in GitHub Actions. |
| Windows | Rust tests and the synthetic ABI backend are compiled on a native Windows runner. |
| macOS | The module builds as a `.dylib`; it is not currently exercised by continuous integration. |
| Live hardware | Opt-in Rust and Python smoke tests verify slot and token metadata on attached YubiKey and YubiHSM devices. |

Protocol tests use deterministic mock transports and official cryptographic
test vectors where available. Live-device tests are deliberately excluded from
normal CI and are not a substitute for qualifying the exact hardware and
firmware used in a deployment.

## Prerequisites

Building requires a Rust toolchain plus the development files for:

- PC/SC
- libusb 1.0
- Clang/libclang, used by `bindgen` for the vendored PKCS #11 3.2 headers

The exact package names depend on the operating system and package manager.
Remote YubiHSM Connector HTTPS uses rustls and does not require OpenSSL or
libcurl.

## Build

```sh
cargo build
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

Disable direct YubiHSM USB discovery while retaining configured remote slots:

```sh
export PKCS11RS_YUBIHSM_USB=0
```

The setting defaults to `1`. Any value other than `0` or `1` makes
`C_Initialize` return `CKR_ARGUMENTS_BAD`.

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

The default PC/SC discovery set contains PIV, OpenPGP, YubiHSM Auth, and the
Issuer SD. Each selectable applet is exposed as its own PKCS #11
slot.

Limit discovery to selected applets with:

```sh
export PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Enable secure messaging for selected applets with one of:

```sh
export PKCS11RS_CCID_SECURE_CHANNEL=scp03
export PKCS11RS_CCID_SECURE_CHANNEL=scp11a
export PKCS11RS_CCID_SECURE_CHANNEL=scp11b
```

Detailed configuration:

- [CCID discovery, AID overrides, and diagnostics](docs/ccid.md)
- [YubiHSM and YubiHSM Auth login](docs/yubihsm-auth.md)
- [PIV backend](docs/piv.md)
- [OpenPGP backend](docs/openpgp.md)
- [SCP03](docs/scp03.md)
- [SCP11a and SCP11b](docs/scp11.md)

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
cargo test
cargo test --all-features
```

Run the hardware-independent Python ABI tests:

```sh
python3 test_pkcs11.py
```

Live hardware tests are opt-in:

```sh
PKCS11RS_RUN_HARDWARE_TESTS=1 python3 test_hardware.py
cargo test -- --ignored
```

The `abi-tests` Cargo feature adds synthetic slots used by the test suite. It
is not intended for a normal module build.

## Known Limitations

- Mechanisms and objects are advertised dynamically, so availability depends
  on the selected backend, installed keys, device firmware, and policy.
- The live-hardware suite is currently a discovery and metadata smoke test; it
  does not exercise every cryptographic operation against physical devices.
- OpenPGP key generation and private-key import are restricted to references
  that the card reports as empty, so PKCS #11 operations cannot overwrite an
  existing OpenPGP key. Readable OpenPGP data objects are exported read-only.
- Secure-channel credential provisioning and trust-anchor selection are
  deployment responsibilities.
- Binary packaging, system installation, and platform-specific PKCS #11 loader
  configuration are not yet provided by this repository.

## Vendored Headers

[`pkcs11.h`](pkcs11.h), [`pkcs11f.h`](pkcs11f.h), and
[`pkcs11t.h`](pkcs11t.h) are byte-for-byte copies of the final OASIS PKCS #11
3.2 Standard header artifacts and retain the OASIS notices. `build.rs` runs
`bindgen` against these repository inputs and writes the generated Rust
bindings to Cargo's `OUT_DIR`; generated bindings are not checked into source
control.

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
