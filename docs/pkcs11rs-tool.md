# Authoring and credential management

`pkcs11rs-tool` is the supported administration boundary for pkcs11rs. It
authors and verifies certificate bundles and, on supported platforms, manages
platform-protected YubiHSM authentication credentials.

Build it with the rest of the workspace:

```sh
cargo build --locked
```

The binary is `target/debug/pkcs11rs-tool` (`pkcs11rs-tool.exe` on Windows).
It can also be installed directly:

```sh
cargo install --locked --path tools/pkcs11rs-tool
```

Run `pkcs11rs-tool --help` for the complete command summary. Certificate-bundle
commands operate only on the files named on their command line.

## Platform credentials

The platform-credential commands use the same focused provider crate as the
PKCS #11 runtime. They never duplicate Keychain, KDF or public-key encoding
logic in the CLI:

```sh
pkcs11rs-tool platform-credential generate reserve
pkcs11rs-tool platform-credential list
pkcs11rs-tool platform-credential show-public reserve
pkcs11rs-tool platform-credential delete reserve
```

`generate` creates a non-exportable P-256 private key and prints its canonical
uncompressed SEC1 public point. `show-public` prints the same representation
for provisioning a YubiHSM Authentication Key and public projection. `list`
prints only credentials owned by pkcs11rs. `delete` requires an exact name.
None of these operations changes a YubiHSM.

On macOS, persistent Secure Enclave access requires entitlements authorized by
a development provisioning profile. Build the app-like CLI bundle through
Xcode:

```sh
cargo xtask macos-tool
target/macos-tool/debug/pkcs11rs-tool.app/Contents/MacOS/pkcs11rs-tool \
  platform-credential list
```

The bundle has no user interface; its inner executable is a normal terminal
program. Xcode signs it, embeds the provisioning profile, and grants its default
application Keychain access group. Override the repository's development team
with `PKCS11RS_APPLE_DEVELOPMENT_TEAM` or `--team TEAM`. A credential is private
to that signed host application by default. An iOS application that embeds
pkcs11rs similarly uses its own normal Xcode signing and Keychain group. Login
only resolves an existing named key; it never silently generates one.

The same build can be driven entirely from Xcode. Open
`tools/pkcs11rs-tool/macos/PKCS11RSTool.xcodeproj`, select the shared
`PKCS11RSTool` scheme, and press Run. Its build phase invokes the workspace's
locked Cargo build for the selected Debug or Release configuration before
Xcode signs the result. The Debug scheme runs `platform-credential list`, so
the Xcode console confirms that the signed CLI can reach its Keychain group.

The public Rust API and CLI are backend-neutral. Unsupported systems return an
explicit error today; a later Windows CNG/TPM implementation can implement the
same resolve and lifecycle contracts without changing selectors or commands.

## Certificate bundles

The provider accepts only canonical X.509 DER certificates and canonical CBOR
bundles. The tool may import PEM, but never emits or configures PEM.

## Inputs and output

Supply canonical DER files, PEM files containing one or more `CERTIFICATE`
blocks, or a mixture. Input-file order and PEM block order are preserved.

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose certificate-collection \
  --output certificates.cbor \
  first.der remaining-certificates.pem
```

The tool rejects empty input, malformed or noncanonical certificates,
duplicates, non-certificate PEM blocks, and text outside PEM blocks. It refuses
to replace an existing output unless `--force` is specified. Before writing,
it encodes and decodes the bundle again and requires an exact round trip.
The only output format is the canonical `.cbor` certificate-bundle object.

## Purpose profiles

Every creation and verification command requires one of these purposes:

| Purpose | Intended use | Validation |
| --- | --- | --- |
| `certificate-collection` | Project-owned reference or issuer collections | Canonical, nonempty, duplicate-free certificates with no ordering or chain semantics. |
| `yubihsm-tls-client` | `PKCS11RS_YUBIHSM_TLS_CLIENT_CERTIFICATE_BUNDLE` | Currently valid leaf-first client chain; issuer names, signatures, CA constraints, key usage, client-auth extended key usage when present, and matching encrypted private key. |
| `yubihsm-tls-ca` | `PKCS11RS_YUBIHSM_TLS_CA_CERTIFICATE_BUNDLE` | Every entry is currently valid and independently suitable as a TLS CA trust anchor. Multiple unrelated anchors are allowed. |
| `scp11-oce` | `PKCS11RS_SCP11_OCE_CERTIFICATE_BUNDLE` | Currently valid leaf-first issuer chain, P-256 OCE leaf with key-agreement usage when constrained, and matching encrypted P-256 private key. |

These profiles author the canonical CBOR files consumed by the PKCS #11
provider. The companion connector server currently reads ordinary PEM files
for `--tls-certificate`, `--tls-key`, and `--tls-client-ca`; this tool neither
generates those PEM files nor converts its CBOR output into server
configuration. In particular, a `yubihsm-tls-ca` CBOR bundle configures the
provider's trust in an HTTPS server, while the server's mTLS client trust is
the PEM CA file supplied directly to `pkcs11rs-connector`. See
[HTTP and HTTPS](connector.md#http-and-https).

The identity purposes require `--key` naming a canonical password-encrypted
PKCS #8 DER file. The tool obtains its password from the executable configured
by `PKCS11RS_PINENTRY`, exactly as the provider does:

```sh
export PKCS11RS_PINENTRY=pinentry

pkcs11rs-tool certificate-bundle create \
  --purpose yubihsm-tls-client \
  --key client-key.der \
  --output client-chain.cbor \
  client.pem intermediates.pem
```

On macOS, `pinentry-mac` may be used instead. Private-key plaintext is retained
only in zeroizing memory. Unencrypted, malformed, trailing, or noncanonical
PKCS #8 input is rejected.

When a leaf-first identity bundle contains multiple certificates and no
`--trust` option, the last certificate is used only as the terminal issuer for
path-consistency validation. This does not declare that certificate trusted.
A single-certificate identity can only be checked for leaf usage and key
matching without external trust.

To require a path to an explicitly trusted root, provide a canonical CBOR trust
bundle. It can be created from the trusted CA certificates first:

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose yubihsm-tls-ca \
  --output connector-client-roots.cbor \
  connector-client-roots.pem
```

Then use it while checking the identity:

```sh
pkcs11rs-tool certificate-bundle verify \
  --purpose yubihsm-tls-client \
  --key client-key.der \
  --trust connector-client-roots.cbor \
  client-chain.cbor
```

The explicit trust certificates must themselves satisfy the TLS CA profile.
An included self-signed certificate never becomes trusted merely because it is
included in the identity bundle. `--trust` affects validation only; it is not
embedded in or otherwise added to the generated identity bundle.

## Verifying an existing bundle

Verification decodes the file with the same strict codec used by the provider,
applies the selected purpose, and prints each certificate subject and SHA-256
fingerprint:

```sh
pkcs11rs-tool certificate-bundle verify \
  --purpose yubihsm-tls-ca \
  connector-ca.cbor
```

Canonical CBOR structure, canonical embedded DER, schema version, trailing
data, duplicates, and all rules belonging to the selected purpose are checked.
