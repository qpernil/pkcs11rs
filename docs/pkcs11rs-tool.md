# Certificate-bundle authoring

`pkcs11rs-tool` is the supported authoring and verification boundary for
pkcs11rs certificate bundles. The provider itself accepts only canonical X.509
DER certificates and canonical CBOR bundles. The tool may import PEM, but never
emits or configures PEM.

Build it with the rest of the workspace:

```sh
cargo build --locked
```

The binary is `target/debug/pkcs11rs-tool` (`pkcs11rs-tool.exe` on Windows).
It can also be installed directly:

```sh
cargo install --locked --path tools/pkcs11rs-tool
```

Run `pkcs11rs-tool --help` for the complete command summary. The utility has no
provider or hardware dependency at runtime; it operates only on the files
named on its command line.

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
