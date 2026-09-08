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

### Full upstream pkcs11test

`run_pkcs11test.py` runs the installed Google/Yubico `pkcs11test` executable
against disposable production software tokens. This external executable is not
run by `cargo test`; invoke its runner separately:

```sh
python3 integration/run_pkcs11test.py
python3 integration/run_pkcs11test.py --filter 'Init.*' --jobs 1
```

The default includes every upstream case, including upstream-disabled cases,
SO login, and token initialization (`-I`). It uses no exclusions from
`yubihsm-shell`. Each case gets a fresh encrypted token store, random PINs, and
a separate process, so a reset, failed login, or crash cannot spoil another
case. The runner builds with native hardware support disabled and supplies
neither hardware endpoints nor an arbitrary-module override. Destructive and
credential-management coverage belongs on these disposable software tokens;
the hardware client suite below uses its own restricted fixture.

The JSON report at `target/pkcs11test-results.json` records executable/module
hashes, selected case count, redacted command output, failures, legacy upstream
skip reasons, crashes, timeouts, and completion status. It is updated after each
case. Setup/report errors remain visible without aborting the other cases;
any failure or incomplete run gives a nonzero exit status. `--timeout` bounds
each command and `--jobs` controls independent fixtures (default four).
The upstream executable accepts PINs as command arguments, so ephemeral test
PINs are visible to local process inspection while it runs; persisted reports
redact them.

The verified macOS run uses the local `pkcs11test` fork at
`c3b8f4915a4313960ce0909e4589e11e6a7b6577`: **342 cases, 276 passed,
66 unsupported/skipped, zero failures, crashes, or timeouts**. This inventory
includes six parameterized encryption/decryption cancellation cases. The
[fixture contracts](../../pkcs11test/README.md#fixture-contracts) describe its
standards-based corrections and explicit key-policy requirements. These
results cover this fork and the software backend; they do not establish
cross-vendor conformance or native hardware support for every passing case.

| Skip reason | Cases |
| --- | ---: |
| Single-DES generation unavailable | 42 |
| MD5 digest unavailable | 12 |
| MD5-with-RSA unavailable | 3 |
| Combined digest/encryption API unsupported | 4 |
| Operation-state save/restore unsupported | 2 |
| Application-provided locking callbacks unsupported | 1 |
| Slot-event waiting unsupported | 1 |
| RSA sign/verify recovery unsupported | 1 |

The DES group includes 36 cipher cases, three wrap/unwrap cases, one
Tookan-derived wrap-policy case, and two dual-operation cases blocked by DES
setup. Four further dual-operation cases reach the unsupported combined API.
Triple-DES and AES are supported and tested independently. Unsupported cases
remain explicitly identified in the report rather than counted as passes.

All nine generic session data-object cases pass, including creation, independent
copying, destruction, search, multi-attribute queries, and invalid lengths.
Library tests exercise shared data/key lifetimes, cross-slot isolation, and
software crypto on mock YubiHSM, PIV, OpenPGP, FIDO2, and software slots.
Hardware ECDH results use the same copyable software-secret representation.
The 14 OpenSC/OpenSSL client cases and 11 fixture/report regressions also pass.

Against the explicit exclusion list in `yubihsm-shell` checkout
`4b0247e7857c64f134b85376335581cc198e331d`
(`pkcs11/tests/CMakeLists.txt`), 127 cases correspond to exclusions: **80 pass
and 47 skip here**. The comparison maps renamed authenticated fixtures back
to their original identities and `EncryptUpdateAfterSizeQuery` to
`EncryptModePolicing2`; the six added cancellation cases are excluded from the
comparison. Fixture corrections mean this is a comparison of exercised test
subjects, not an unchanged upstream conformance score or a code-coverage
measurement. Software tokens permit reset and credential-management tests
that do not belong in the hardware fixture.

The [PKCS #11 object-creation and session contracts](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
require imported secret/private keys to report false for `CKA_LOCAL`,
`CKA_ALWAYS_SENSITIVE`, and `CKA_NEVER_EXTRACTABLE`. Shared software objects
preserve that history through hardening and copying; current sensitivity and
extractability remain independently enforced. SO login with any read-only
session on the slot, including the calling session, returns
`CKR_SESSION_READ_ONLY_EXISTS`. RSA generation accepts zero-padded unsigned
big-endian encodings of exponent 65537 across software and hardware backends;
other exponent values remain rejected.

The [generic-secret generation specification](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.pdf)
requires `CKA_VALUE_LEN`; generation does not guess a length for incomplete
templates. Triple-length DES generation has a fixed 24-byte representation
and does not require a length attribute. Its generated bytes have odd parity,
and ECB/CBC/CBC-PAD updates emit complete blocks while preserving short-buffer
retry behavior and padded-decryption finalization.

`C_Digest` rejects completion after `C_DigestUpdate` or `C_DigestKey`, including
an empty update, and terminates that invalid operation. Single-part size
queries do not consume input or prevent subsequent multipart processing.
Digest Final after a single-part size query therefore produces the
empty-message digest. PKCS #11 3.x NULL mechanisms cancel active encryption
and decryption; the external fixture verifies that subsequent operations
report `CKR_OPERATION_NOT_INITIALIZED`. `C_WaitForSlotEvent` reports
`CKR_CRYPTOKI_NOT_INITIALIZED` before initialization and
`CKR_FUNCTION_NOT_SUPPORTED` while initialized.

Failures remain failures in the report; no blanket error-code conversion or
exclusion hides them. A newer upstream suite should have its own versioned
baseline rather than silently replacing this fork's comparison results.

Slot-based API calls initialize the slot registry even when the client has not
called `C_GetSlotList` since `C_Initialize`. The upstream invalid-reserved-pointer
test returns `CKR_ARGUMENTS_BAD` for `(void *)1`; JSON initialization remains a
supported pkcs11rs extension.

Run the fixture/report regressions without external clients or hardware:

```sh
python3 -m unittest discover -s integration -p 'test_*.py'
```

### OpenSC and OpenSSL clients

| Client | Cases |
| --- | --- |
| OpenSC | Slot/mechanism discovery and random generation |
| OpenSC | Persistent RSA and EC key generation and public-key export |
| OpenSC | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signatures, verified independently; modified messages rejected |
| OpenSC | RSA-OAEP/SHA-256 decryption of independently encrypted data |
| OpenSC | AES import, ECB/CBC/CBC-PAD encryption and decryption; block boundaries, 4 KiB boundaries, and 72 KiB messages |
| OpenSC | Public/private token data and X.509 certificate import, read, enumeration, and deletion across independent processes |
| OpenSC | Wrong-PIN rejection, private-object visibility, independent public/private deletion, and PIN changes preserving key usability |
| OpenSSL/libp11 | JSON initialization through `init_args`, including rejection of an unsupported configuration version |
| OpenSSL/libp11 | Token and binary object-ID URI selection, missing-key rejection, and matching public-key export |
| OpenSSL/libp11 | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signing; independent verification and modified-message rejection |
| OpenSSL/libp11 | RSA PKCS #1 v1.5 and OAEP/SHA-256 decryption |
| OpenSSL/libp11 | RSA and EC certificate requests, independently verified and matched to the provisioned public keys |

The 14 top-level software cases include parameterized algorithm and size cases.
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

## Hardware crypto with YubiHSM Auth

`--hardware-login-pin-env` enables nine hardware crypto cases using an existing
YubiHSM Auth credential. It exercises fresh authenticated sessions through
OpenSC and OpenSSL/libp11, with the configuration JSON passed through the
OpenSSL provider's `init_args`. It does not use a separate discovery password,
platform credential, session-recreation opt-in, or a test authentication key.

For the [shared local credential](../docs/shared-hsmauth-provisioning.md), supply
`HSM_LOGIN` through your credential input mechanism with the value
`:1006shared@37070618:<credential-password>`, then run:

```sh
cargo build --locked -p pkcs11rs
python3 integration/run_clients.py \
  --module target/debug/libpkcs11rs.dylib \
  --hardware-token 'YubiHSM #1238075073' \
  --hardware-login-pin-env HSM_LOGIN \
  --results target/client-hardware-crypto-1238075073.json
```

The same credential works on local HSM `2545354682`; select its exact token
label and a separate report filename. YubiKey `37987918` is also provisioned;
use its serial in the login selector when selecting that source. Only the
selected local HSM is used. Remote connector URLs are excluded. The runner
requires an explicit HSM Auth selector and never guesses credentials.

| Client | Hardware cases |
| --- | --- |
| OpenSC | Login and authenticated random generation |
| OpenSC | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signing with independent verification and tamper rejection |
| OpenSC | RSA-OAEP/SHA-256 decryption |
| OpenSC | AES ECB/CBC/CBC-PAD encryption and decryption, including boundary sizes through 72 KiB |
| OpenSSL/libp11 | URI selection and public-key export |
| OpenSSL/libp11 | RSA PKCS #1 v1.5, RSA-PSS, and ECDSA signing, verified independently |
| OpenSSL/libp11 | RSA PKCS #1 v1.5 and OAEP/SHA-256 decryption |
| OpenSSL/libp11 | RSA and EC certificate requests, independently verified |

This mode creates temporary RSA/EC keys and imports a public AES test vector.
Every key receives a random 128-bit PKCS #11 ID and unique label; pkcs11rs lets
the HSM allocate its underlying physical ID. Cleanup selects each test object
by ID, label, and class, checks that it disappeared, and compares the complete
visible object-URI inventory with the case's starting inventory. Cleanup runs
even after a test fails or a command times out, and cleanup failures fail the
case and appear in the JSON report. No token initialization, reset, PIN change,
or authentication-key modification is part of these tests. Do not run unrelated
object administration concurrently with the inventory comparisons.

An interrupted process or disconnected device can leave temporary objects.
Their exact IDs and labels are in the report's command records when a report
can be written. Inspect those objects before manual cleanup; do not delete
objects by ID alone. Clear the login environment variable after the run.

The hardware fixture's timeout cleanup, ownership filters, inventory checking,
and mutation restrictions have hardware-independent regressions:

```sh
python3 -m unittest discover -s integration -p 'test_*.py'
```

## Existing hardware: public discovery

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

Hardware signing is covered separately by the HSM Auth crypto mode above.
Platform-credential login is not covered. Apple's `reserve` credential is scoped to the signed
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

Hardware crypto qualification uses YubiKey 37070618's `shared` credential:

| Local HSM | Verified result |
| --- | --- |
| 1238075073 | All nine hardware cases pass in one run |
| 2545354682 | Eight cases pass in the full run; the provider-signature case passes in a separate run |

The second HSM's full run encountered `C_GetSlotList` returning
`CKR_BUFFER_TOO_SMALL` during public-key export, before the affected signature
operation. The failure remains recorded, without automatic command retries
or suppression.
The cryptographic cases require stable smart-card discovery even though the
target HSM and credential source are selected explicitly. Object cleanup and
starting-inventory comparisons pass on both HSMs.
