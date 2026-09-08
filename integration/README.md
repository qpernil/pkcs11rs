# External client integration tests

`run_clients.py` exercises the production PKCS #11 module through OpenSC's
`pkcs11-tool` and OpenSSL 3 with **libp11's `pkcs11prov` provider**. It does not
call the ABI through Python, use the deterministic ABI backend, or depend on
physical hardware for its default cases.

## Run

On macOS, install the external clients:

```sh
brew install opensc libp11 openssl@3
python3 integration/run_clients.py
```

The runner builds `pkcs11rs` with `--locked --no-default-features` in
`target/client-tests`. This uses the production software backend with local
hardware support excluded. Every case initializes its own temporary encrypted
token store, generates random test PINs, and deletes the store afterward.
Each external command starts a fresh process, exercising persistence and
fresh login across process boundaries. Inherited pkcs11rs configuration,
hardware endpoints, provider overrides, and debug settings are removed.

OpenSC and OpenSSL are required even for the OpenSC cases: OpenSSL's default
provider independently verifies signatures and supplies reference ciphertext.
Missing required clients or the selected provider are errors, not skipped tests.

Select a production module, explicit executables, or individual cases:

```sh
python3 integration/run_clients.py \
  --module target/debug/libpkcs11rs.dylib \
  --openssl /opt/homebrew/opt/openssl@3/bin/openssl \
  --provider /opt/homebrew/lib/ossl-modules/pkcs11prov.dylib

python3 integration/run_clients.py --client opensc
python3 integration/run_clients.py --client openssl --case test_provider_signatures
```

Use `.so` on Linux or `.dll` on Windows. A supplied module must be a production
build, without `abi-tests` or mock backends. Hardware discovery remains disabled
for software cases even when that module has native hardware support.
`--client openssl` also uses OpenSC to provision the disposable keys.

The provider configuration is specific to
[OpenSC libp11](https://github.com/OpenSC/libp11#pkcs11-provider-configuration).
The separate `openssl-projects/pkcs11-provider` implementation has different
configuration fields and is outside this suite's current provider coverage.

## Coverage

| Client | Cases |
| --- | --- |
| OpenSC | Slot/mechanism discovery and random generation |
| OpenSC | Persistent RSA and EC key generation and public-key export |
| OpenSC | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signatures, verified independently; modified messages rejected |
| OpenSC | RSA-OAEP/SHA-256 decryption of independently encrypted data |
| OpenSC | AES import, ECB/CBC/CBC-PAD encryption and decryption; block boundaries, 4 KiB boundaries, and 72 KiB messages |
| OpenSC | Wrong-PIN rejection, private-object visibility, independent public/private deletion, and PIN changes preserving key usability |
| OpenSSL/libp11 | JSON initialization through `init_args`, including rejection of an unsupported configuration version |
| OpenSSL/libp11 | Token and binary object-ID URI selection, missing-key rejection, and matching public-key export |
| OpenSSL/libp11 | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signing; independent verification and modified-message rejection |
| OpenSSL/libp11 | RSA PKCS #1 v1.5 and OAEP/SHA-256 decryption |
| OpenSSL/libp11 | RSA and EC certificate requests, independently verified and matched to the provisioned public keys |

The 12 top-level software cases include parameterized algorithm and size cases.
They cover interoperability, not every advertised mechanism or TLS application
workflow. ABI and OASIS profile coverage remain in their existing suites.

## JSON through OpenSSL

The generated provider configuration includes:

```ini
openssl_conf = openssl_init
config_diagnostics = 1
[openssl_init]
providers = providers
[providers]
default = default_provider
pkcs11 = token_provider
[default_provider]
activate = 1
[token_provider]
identity = pkcs11prov
module = $ENV::CLIENT_PROVIDER
pkcs11_module = $ENV::CLIENT_MODULE
init_args = $ENV::CLIENT_CONFIG
activate = 1
```

`CLIENT_CONFIG` contains the versioned pkcs11rs JSON. For software cases it
specifies the token name, temporary storage, disabled local discovery, and an
empty connector list. Software-slot and storage environment fallbacks are
removed from OpenSSL's environment so the test depends on `init_args` reaching
`C_Initialize`. The provider's `PKCS11_PIN` environment variable supplies the
per-fixture USER PIN. PINs are absent from command arguments and configuration
files; diagnostic output is redacted before it is retained.

## Existing hardware: public discovery only

The optional hardware mode contains no token initialization, PIN changes, key
generation, import, deletion, or reset. It selects an exact token label and can
compare an existing public key read through OpenSC and OpenSSL:

```sh
cargo build --locked -p pkcs11rs
# Set HSM_DISCOVERY to the confirmed discovery selector through your usual
# credential source; the runner never guesses a discovery password.
python3 integration/run_clients.py \
  --module target/debug/libpkcs11rs.dylib \
  --hardware-token 'YubiHSM #1238075073' \
  --hardware-public-id 1003 \
  --discovery-pin-env HSM_DISCOVERY \
  --results target/client-hardware-results.json
```

The example ID is the public projection of the `reserve` authentication key
on that lab HSM. Use the label and public `CKA_ID` from the device being tested.
The discovery selector is passed as `yubihsm.public_discovery` in OpenSSL's JSON
and through the corresponding environment fallback for OpenSC. This is the
documented, explicit public-discovery credential-retention exception; the
suite does not enable session recreation or add a login-PIN cache.

With `--client opensc`, `--hardware-public-id` is unnecessary. Without a
discovery credential, the OpenSC case checks discovery without requiring public
objects. Hardware runs need normal OS USB access, which can be unavailable
inside a sandbox.

Hardware signing and platform-credential login are not claimed by these two
public-discovery cases. Apple's `reserve` credential is scoped to the signed
pkcs11rs tool's Keychain access group; ordinary Homebrew executables do not
inherit that entitlement by loading the module. See
[platform credential hosting](../docs/pkcs11rs-tool.md#platform-credentials).

## Results and CI

`--results` defaults to `target/client-results.json`. The report contains case
and subtest failures, command exit statuses, redacted output, elapsed times,
and SHA-256 fingerprints of the module, provider, and client executables.
It retains no token store or environment dump. Commands use a 60-second timeout
and closed standard input, so an unexpected PIN prompt cannot hang a run.

Linux CI runs the OpenSC cases. macOS CI runs both clients and requires the
libp11 provider. Each job uploads its JSON report on success or failure.
Local verification covers OpenSC 0.27.1, libp11 0.4.21, and OpenSSL 3.6.4 on
macOS; the two public-discovery cases also pass on YubiHSM serial 1238075073.
