# Platform ECDH slot

Enable the platform token explicitly:

```json
{"version": 1, "platform": {"enabled": true}}
```

The environment equivalent is `PKCS11RS_PLATFORM_ENABLED=1`. The default is
false, and an explicit JSON value overrides the environment. This setting
controls both PKCS #11 slot exposure and use of platform keys for YubiHSM
authentication. There is no hidden platform-authentication provider when the
slot is disabled. `hardware.discovery` does not control this explicitly enabled
source. A `slots.serials` allowlist must include `PLATFORM00000001`; excluding
the slot also excludes its keys from authentication lookup.

The token label is `Platform`, its model is `Platform ECDH`, and its serial is
`PLATFORM00000001`. It is a non-removable OS token. macOS and iOS implement it
using managed Secure Enclave P-256 keys; enabling it on an unsupported platform
returns `CKR_FUNCTION_NOT_SUPPORTED` during slot initialization.

## Objects and operations

Each managed key has a `CKO_PRIVATE_KEY` and a projected `CKO_PUBLIC_KEY`, both
`CKK_EC`, with the exact managed name as `CKA_LABEL` and the SHA-256 digest of the
uncompressed public point as `CKA_ID`. Public objects expose `CKA_EC_POINT` and
`CKA_PUBLIC_KEY_INFO`; private objects expose their public-key information and
curve parameters without exposing their scalar. Private keys are sensitive,
non-extractable, and non-copyable. Object identity includes the name and public
key, so replacement under the same label does not rebind an old handle.

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

The slot requires `CKU_USER` login with an empty password. `C_LoginUser` also
requires an empty username. Nonempty passwords and usernames are rejected;
there is no SO role. This login establishes PKCS #11 authorization state,
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

YubiHSM login resolves `:1003@reserve` by exact `CKA_LABEL=reserve` on the
enabled platform slot. The target Authentication Key ID remains `1003`.
Missing or duplicate private-key matches fail; lookup never chooses the first
match. `:*@reserve` and universal `:*` match source public keys against the
YubiHSM's discovered public authentication-key projections. Only asymmetric
matching is automatic.

The authentication consumer performs the same empty-PIN login before resolving
the private key, accepting an already logged-in user session. The resolved token
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
