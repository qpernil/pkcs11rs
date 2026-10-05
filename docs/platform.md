# Platform-protected ECDH slot

Enable the platform slot explicitly:

```json
{"version": 1, "platform": {"enabled": true}}
```

The environment equivalent is `PKCS11RS_PLATFORM_ENABLED=1`. The default is
false, and an explicit JSON value overrides the environment. This setting
controls both PKCS #11 slot exposure and use of platform keys for YubiHSM
authentication. There is no hidden platform-authentication provider when the
slot is disabled. `hardware.discovery` does not control this explicitly enabled
source. The slot has no hardware serial, so `slots.serials` does not control it.

The slot is a non-removable OS token with an empty serial. macOS and iOS
use managed Secure Enclave P-256 keys and report `Secure Enclave`, with model
`macOS` or `iOS`. Windows uses the Microsoft Platform Crypto Provider (TPM)
and reports `Windows CNG`, with model `Windows`. Other operating systems return
`CKR_FUNCTION_NOT_SUPPORTED` during slot initialization.

## Windows CNG store

The Windows backend creates current-user, persisted `ECDH_P256` keys named
`pkcs11rs.yubihsm-auth.<name>`. Only this namespace and provider are enumerated;
arbitrary Windows keys and machine-wide keys are outside the managed store.
Generation refuses duplicate names and sets a zero private-key export policy.
The TPM provider uses `NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY` with
`NCRYPT_PCP_ENCRYPTION_KEY`: the TPM decrypt attribute permits ECDH, while
signature usage is excluded. Readback may also contain the documented
`NCRYPT_TPM12_PROVIDER` metadata bit (`0x00010000`); it is ignored when comparing
usage permissions. Other additional bits, including signature/storage usage,
are rejected. The software-KSP tests use the generic
`NCRYPT_KEY_USAGE_PROPERTY` agreement-only policy instead. Resolution checks
the provider-specific policy and the ECDH P-256 public projection. The provider must report hardware implementation; there is
no software fallback when a TPM or required operation is unavailable.

Windows key-store authorization follows the current user's Windows security
context and the KSP's access controls. Unlike Apple's application Keychain group,
this namespace is not an application isolation boundary. Key opening, policy
access, generation, and agreement request silent operation: native authorization
requiring UI fails rather than prompting for or retaining a Windows password,
PIN, or biometric authorization. TPM key deletion uses zero flags because some
PCP versions reject `NCRYPT_SILENT_FLAG` for that operation. There is no
Windows Hello or per-operation user-presence policy in this backend. PKCS #11
USER login remains the empty-PIN authorization gate described below.

ECDH imports the peer's validated P-256 public point into the same KSP and uses
`NCryptSecretAgreement` with `NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)`.
The exact 32-byte output is reversed from CNG's little-endian representation to
the common big-endian ECDH contract. The private scalar remains in the TPM;
the shared secret enters zeroizing module memory. This requires a Windows/TPM
provider supporting P-256 ECDH, peer-public-key import, and raw-secret derivation.
Public keys are exported directly from native keys.

Each operation reopens the managed name, checks the original public identity,
and uses that same native handle. Deletion or replacement prevents a retained
credential from resolving to a different key. Matching public certificates are
read from the current user's `MY` certificate store by complete P-256 public key;
certificate discovery does not authenticate to a private key or create keys.

Windows CI runs the lifecycle and ECDH interoperability tests with the software
KSP through a test-only provider selection. Production always selects the TPM
KSP. Hardware qualification is a separate ignored test; run it on a Windows
TPM machine with:

```sh
cargo test --locked -p platform-credential tpm_ksp_lifecycle_and_ecdh_interoperate -- --ignored
```

This test creates temporary, uniquely named managed keys and deletes them. It
checks persistence, enumeration, duplicate-name refusal, private-export denial,
ECDH and prefixed-KDF interoperability, and deletion/replacement invalidation.
A passing cross-target build or software-KSP test does not qualify a TPM model.
Unsupported Windows capabilities report the native operation and CNG status,
or the rejected implementation type, key policy, or public-blob format.
These diagnostics contain no key material or authentication secrets; unsupported
capabilities map to `CKR_FUNCTION_NOT_SUPPORTED`. If provisioning rollback also
fails, the error preserves both failures and identifies the managed name that
may remain. Explicit management deletion accepts that name even if the key's
policy or public projection is unusable.

## Objects and operations

Each managed key has a `CKO_PRIVATE_KEY` and a projected `CKO_PUBLIC_KEY`, both
`CKK_EC`, with the exact managed name as both `CKA_LABEL` and `CKA_ID`. Public objects expose `CKA_EC_POINT` and
`CKA_PUBLIC_KEY_INFO`; private objects expose their public-key information and
curve parameters without exposing their scalar. Private keys are sensitive,
non-extractable, and non-copyable. Object identity includes the name and public
key digest separately, so replacement under the same label does not rebind an
old handle.

Matching certificates in the application's accessible Apple data-protection
Keychain or the current user's Windows `MY` store are exposed as public
`CKO_CERTIFICATE` token objects. Matching uses
the complete public key, not the certificate label. Each certificate has the
managed key's label and `CKA_ID`, matching both key projections, with its DER
value readable before login and after logout. Certificates are not generated
by discovery. Multiple certificates for one key have distinct stable object
identities. The slot exposes only certificates matching its managed keys.

Native keys support P-256 `CKM_ECDH1_DERIVE` and its cofactor variant (P-256 has
cofactor one). The selective composition layer adds prefixed ECDH, one-use P-256
software generation for YubiHSM authentication, and KDF, digest-key, MAC, and
symmetric consumers for the resulting software session secret. The native
provider retains the private key, but ECDH returns the shared secret to module
memory. Sensitive buffers are zeroizing; PKCS #11 object policy
determines whether a client may read a derived value.

The slot supports common session data and certificates plus software secret
objects produced by its ECDH composition paths. It does not accept arbitrary
software private or secret session-key imports.
Persistent provisioning uses the existing `platform-credential` management
API and tools; this slot does not implement token-key generation, import,
deletion, or attribute updates through Cryptoki. It advertises write-protected
token storage while allowing read-write sessions for session objects.

The slot requires `CKU_USER` login. `C_LoginUser` also requires an empty
username. The backend accepts only an omitted or explicitly empty PIN;
nonempty PINs fail with `CKR_PIN_LEN_RANGE`, nonempty usernames are rejected,
and there is no SO role. This login establishes PKCS #11 authorization state,
without prompting for or retaining an OS password. `CKF_LOGIN_REQUIRED` and
`CKF_USER_PIN_INITIALIZED` are set, with a zero-length PIN range. Private
objects are hidden and unusable before login and after logout; public key
projections remain discoverable. Login state is shared by sessions, and closing
the last session clears it. OS access control independently governs native
key use.

On Apple platforms, Keychain access follows the signed host application's
access group and device-unlock policy. Searches refresh the
managed-key inventory. A retained Apple key checks that its managed key still
exists with the same public identity before ECDH; deletion or replacement
invalidates further use. No password is cached to recover OS authorization.

The slot advertises Baseline and Public Certificates Token. Native keys support
ECDH, not the RSA operations required by Extended Provider or Authentication
Token. Certificate lookup has no separate configuration switch, and the
profile claim does not depend on a matching certificate being installed.

## Authentication consumer

### Persistent provisioning and hardware qualification

The ignored `provisions_native_platform_credential_on_yubihsm` test provisions
an existing named native platform credential into one explicitly selected
physical YubiHSM. The shared credential API selects the native backend; the
test has no Windows-specific provisioning path. It installs the asymmetric
Authentication Key and its matching public companion, then logs in through
the platform PKCS #11 slot using both the native key's URI with explicit target
key ID and the automatic `pkcs11:` selector. Both paths verify the selected
credential and Authentication Key ID, random generation, and encrypted echo.
The test explicitly configures the bootstrap credential for public discovery
so automatic matching can inspect the target's public companion.
The test leaves the provisioning in place, reuses an exact matching installation,
and rejects conflicting identities rather than replacing them. A matching
Authentication Key with a narrower domain policy is recreated with all domains
only after verifying its label, algorithm, capabilities, delegated capabilities,
and complete native public-key binding. Its existing public companion is kept.
If recreation fails after deletion, rerunning provisions the missing key from
that verified companion. It never generates
or deletes the local platform key.

Set `PKCS11RS_PLATFORM_TEST_TARGET` to the HSM serial and
`PKCS11RS_PLATFORM_TEST_NAME` to an existing credential name. The target
Authentication Key ID is `1003` by default; override it with
`PKCS11RS_PLATFORM_TEST_ID` (hexadecimal). The installed key has all 16 domains (`0xffff`),
`get-pseudo-random` capability, and no delegated capabilities, providing a
limited credential for authentication qualification. The administrative
Authentication Key remains intact. The default bootstrap login uses factory
Authentication Key `0001` and password `password`; override
`PKCS11RS_PLATFORM_TEST_ADMIN_PIN` with the direct `AAAApassword` login format
for a configured device. This test-only public-discovery configuration keeps
the bootstrap credential available for the initialized module's lifetime;
it is cleared when the test finalizes the module. Clear any password override
after the run. Direct USB
is the default; an optional comma-separated `PKCS11RS_PLATFORM_TEST_URLS`
selects connectors. CCID applications are restricted to HSM Auth, and device
visibility is restricted to the explicitly selected HSM serial.

For example, from PowerShell in the repository root on Windows:

```powershell
$env:PKCS11RS_PLATFORM_TEST_TARGET = "HSM-SERIAL"
$env:PKCS11RS_PLATFORM_TEST_NAME = "windows-test"
cargo test --locked -p pkcs11rs --lib provisions_native_platform_credential_on_yubihsm -- --ignored --nocapture
```

The equivalent invocation on a supported desktop Unix platform is:

```sh
PKCS11RS_PLATFORM_TEST_TARGET=HSM-SERIAL \
PKCS11RS_PLATFORM_TEST_NAME=reserve \
cargo test --locked -p pkcs11rs --lib provisions_native_platform_credential_on_yubihsm -- --ignored --nocapture
```

Apple hosts require the signing and Keychain access-group authorization of the
process running the test; a credential owned by another application's Keychain
scope is not accessible simply by supplying its name.

### Credential selection

YubiHSM `C_LoginUser` resolves
`pkcs11:token=Secure%20Enclave;object=reserve;type=private?pkcs11rs-authkey=1003`
by exact `CKA_LABEL=reserve` on the enabled platform slot. The target
Authentication Key ID remains `1003`. A URI without `pkcs11rs-authkey`, such as
`pkcs11:token=Secure%20Enclave;object=reserve;type=public`, matches source public
keys against the YubiHSM's discovered public authentication-key projections.
Universal `pkcs11:` considers all eligible public credentials. Multiple matches
are ordered with the other source slots. Only asymmetric matching is automatic.

The application first performs USER login on the platform slot. The platform
backend accepts only an omitted or explicitly empty PIN. A
later YubiHSM target login can select the key only while that source login is
active, and never forwards the target PIN to the platform slot. The resolved
token key is bound through `Pkcs11Auth`. Static and ephemeral ECDH
outputs remain protected session objects throughout the common derivation
graph. Only the final working keys are read into the channel for local message
crypto. `ClientAuth` retains the source binding only when session recreation is
enabled. HSM Auth credentials use the same session ownership, with a native
Rust authentication operation on their owning slot.
See [authentication lifetimes](authentication-secrets.md).

The Apple store retains its existing `pkcs11rs.yubihsm-auth.<name>` application
tag for compatibility. Enabling or using the slot does not create or migrate
keys, and the encrypted software-token backing format is unchanged.

For Windows, the equivalent named selector is
`pkcs11:token=Windows%20CNG;object=reserve;type=private?pkcs11rs-authkey=1003`.
The provisioning API, public-key matching, source login, and session lifetime
are shared with the Apple backend.
