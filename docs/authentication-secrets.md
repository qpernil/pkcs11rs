# Authentication secret retention

`pkcs11rs` does not retain ordinary login PINs or passwords for later operations
by default. This applies to secrets supplied by the application or requested
through pinentry. Authentication may produce device authorization state, scoped
tokens, or cryptographic session keys; retaining that state for its defined
lifetime is distinct from retaining the login secret to authenticate again.

## Backend behavior

- OpenPGP retains neither clear nor derived PINs. An operation requiring fresh
  verification obtains its PIN through `CKU_CONTEXT_SPECIFIC` login. See
  [OpenPGP authentication](openpgp.md).
- FIDO assertions use an operation-scoped authorization token obtained by
  context-specific login. Neither the PIN nor the token is retained for another
  assertion. Length queries and short-buffer retries reuse the completed
  operation's buffered result. See [FIDO2](fido2.md).
- FIDO previewSign uses the same per-operation signing authorization. User
  login may retain a one-shot administration token for registration or deletion,
  but not the PIN needed to obtain another token. See [previewSign](preview-sign.md).
- YubiHSM login retains only its three channel working keys as local AES bytes
  in zeroizing storage for message encryption and MAC. Successful close or
  channel invalidation drops that storage. Readable derivation outputs are
  transient; long-term credentials remain protected. This does not retain the
  login password. Transparent session recreation is an explicit exception
  described below.
- Software-token login may retain unlocked key material for the authenticated
  session. Configured public-discovery credentials are a separate exception;
  they are not a cache populated from ordinary user login.

## Explicit exceptions

### YubiHSM session recreation

`yubihsm.recreate_sessions = true`, or
`PKCS11RS_YUBIHSM_RECREATE_SESSIONS=1`, opts into retaining slot-local
reauthentication material. Direct symmetric authentication retains a protected
32-byte generic-secret credential containing the static AES pair; direct
asymmetric authentication retains a protected static ECDH shared-secret object.
These are provider-session handles. Each retained direct credential or agreement
has a dedicated owning session; handshake sessions own the transient derivation
objects. Closing the owning session deletes its session objects, and dropping
the last private-provider reference releases the temporary software slot.
Software key storage is zeroizing. No ordinary login PIN is retained to reopen
these sessions. YubiHSM Auth retains its selected provider and
credential password.
Secret material uses zeroizing storage and is dropped on logout, invalidation,
finalization, or session replacement. A platform-backed credential may instead
retain a protected-key reference. See [YubiHSM authentication](yubihsm-auth.md)
for recovery conditions and replay restrictions.

### Configured discovery credentials

Explicitly configured YubiHSM discovery passwords and software-slot
`discovery_pin` values remain available for discovery independently of ordinary
user login/logout. The YubiHSM slot configuration and software-token store hold
these secrets in zeroizing storage for their respective lifetimes. Supplying
such configuration deliberately enables credential retention; it does not
enable caching of subsequent login PINs.

A prompted YubiHSM discovery password is not added to configuration or retained
for reauthentication by default. Session recreation must be explicitly enabled
to retain the applicable reauthentication material.

See [configuration](configuration.md) and [YubiHSM discovery](yubihsm-auth.md).
Configuration inputs, environment variables, and application-owned copies have
their own lifetimes; zeroizing backend storage does not erase those copies.

## Implementation requirements

Do not add PIN/password caches or retain equivalent reusable authentication
material merely to renew a token or make a later operation convenient. Require
fresh authentication when the applicable authorization expires or is consumed.
Any additional retention exception requires explicit opt-in, documented scope
and lifetime, and tests covering both default non-retention and cleanup.

Use zeroizing storage for retained secret material and avoid exposing secrets
through logs or debug output. Zeroization limits memory residue; it is not
protection against a compromised process. Persistent encrypted keys, configured
secure-channel credentials, and authenticator-side PIN verification state are
not ordinary client login-PIN caches.
