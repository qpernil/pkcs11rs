# Secure Enclave slot

Enable the Secure Enclave slot explicitly:

```json
{"version": 1, "platform": {"enabled": true}}
```

The environment equivalent is `PKCS11RS_PLATFORM_ENABLED=1`. The default is
false, and an explicit JSON value overrides the environment. This setting
controls both PKCS #11 slot exposure and use of platform keys for YubiHSM
authentication. There is no hidden platform-authentication provider when the
slot is disabled. `hardware.discovery` does not control this explicitly enabled
source. The slot has no hardware serial, so `slots.serials` does not control it.

The token label is `Secure Enclave`, its serial is empty, and its model is
`iOS` or `macOS` according to the build target. It is a non-removable OS token.
macOS and iOS implement it using managed Secure Enclave P-256 keys; enabling it on an unsupported platform
returns `CKR_FUNCTION_NOT_SUPPORTED` during slot initialization.
The platform slot abstraction is also intended for other operating-system key
providers. Each implementation supplies its own visible token name; a future
Windows CNG backend will therefore report `Windows CNG`, not `Secure Enclave`.

## Objects and operations

Each managed key has a `CKO_PRIVATE_KEY` and a projected `CKO_PUBLIC_KEY`, both
`CKK_EC`, with the exact managed name as both `CKA_LABEL` and `CKA_ID`. Public objects expose `CKA_EC_POINT` and
`CKA_PUBLIC_KEY_INFO`; private objects expose their public-key information and
curve parameters without exposing their scalar. Private keys are sensitive,
non-extractable, and non-copyable. Object identity includes the name and public
key digest separately, so replacement under the same label does not rebind an
old handle.

Matching certificates in the application's accessible Apple data-protection
Keychain are exposed as public `CKO_CERTIFICATE` token objects. Matching uses
the complete public key, not the certificate label. Each certificate has the
managed key's label and `CKA_ID`, matching both key projections, with its DER
value readable before login and after logout. Certificates are not generated
by discovery. Multiple certificates for one key have distinct stable object
identities. The slot exposes only certificates matching its managed keys.

Native keys support P-256 `CKM_ECDH1_DERIVE` and its cofactor variant (P-256 has
cofactor one). Native mechanism entries are merged with the common software
mechanisms using the ordinary slot rules. ECDH produces a software session
object; the common layer handles X9.63 KDFs and subsequent composition, hash,
counter-KDF, and symmetric operations. The Secure Enclave retains the private
key, but Apple's ECDH API returns the shared secret to module memory. Sensitive
buffers are zeroizing; PKCS #11 object policy determines whether a client may
read a derived value.

The slot also supports the ordinary software session keys and data objects.
Persistent provisioning uses the existing `platform-credential` management
API and tools; this slot does not implement token-key generation, import,
deletion, or attribute updates through Cryptoki. It advertises write-protected
token storage while allowing read-write sessions for session objects.

The slot requires `CKU_USER` login. `C_LoginUser` also requires an empty
username. The backend accepts an omitted or supplied PIN and ignores its value;
nonempty usernames are rejected and there is no SO role. This login establishes PKCS #11 authorization state,
without prompting for or retaining an OS password. `CKF_LOGIN_REQUIRED` and
`CKF_USER_PIN_INITIALIZED` are set, with a zero-length PIN range. Private
objects are hidden and unusable before login and after logout; public key
projections remain discoverable. Login state is shared by sessions, and closing
the last session clears it. OS access control independently governs native
key use.

Keychain access follows the signed host application's access group and
device-unlock policy. Searches refresh the
managed-key inventory. A retained Apple key checks that its managed key still
exists with the same public identity before ECDH; deletion or replacement
invalidates further use. No password is cached to recover OS authorization.

The slot advertises Baseline, Extended Provider, Authentication Token, and
Public Certificates Token with the default software mechanism set. Extended
Provider and Authentication Token include software session-key operations.
Native keys support ECDH, not signing. Certificate lookup has no separate
configuration switch, and the profile claim does not depend on a matching
certificate being installed.

## Authentication consumer

YubiHSM `C_LoginUser` resolves
`pkcs11:token=Secure%20Enclave;object=reserve;type=private?pkcs11rs-authkey=1003`
by exact `CKA_LABEL=reserve` on the enabled platform slot. The target
Authentication Key ID remains `1003`. A URI without `pkcs11rs-authkey`, such as
`pkcs11:token=Secure%20Enclave;object=reserve;type=public`, matches source public
keys against the YubiHSM's discovered public authentication-key projections.
Universal `pkcs11:` considers all eligible public credentials. Multiple matches
are ordered with the other source slots, and only the first receives the PIN.
Only asymmetric matching is automatic.

The authentication consumer performs USER login before resolving the private
key. The Secure Enclave backend accepts an omitted or supplied PIN and ignores its value,
and also accepts an already logged-in user session. The resolved token
key is bound through `Pkcs11Auth`. Static and ephemeral ECDH
outputs remain protected session objects throughout the common derivation
graph. Only the final working keys are read into the channel for local message
crypto. `ClientAuth` retains the source binding only when session recreation is
enabled. HSM Auth credentials use the same session ownership, with a native
Rust authentication operation on their owning slot.
See [authentication lifetimes](authentication-secrets.md).

The Apple store retains its existing `pkcs11rs.yubihsm-auth.<name>` application
tag for compatibility. Enabling or using the slot does not create or migrate
keys, and the encrypted software-token backing format is unchanged.
