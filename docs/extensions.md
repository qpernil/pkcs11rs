# PKCS11RS vendor extensions

[`pkcs11rs.h`](../pkcs11rs.h) is the canonical C header for identifiers and
functions outside the standard PKCS #11 function tables. Include it after, or
instead of separately including, the vendored `pkcs11.h`; it includes that
header itself. All extension functions use the platform PKCS #11 calling
convention and return ordinary `CK_RV` values unless documented otherwise.

## Constant-name helpers

The following helpers return canonical, NUL-terminated names for values known
to the current build:

- `PKCS11RS_GetMechanismName` for `CKM_*` values;
- `PKCS11RS_GetReturnValueName` for `CKR_*` values;
- `PKCS11RS_GetObjectClassName` for `CKO_*` values;
- `PKCS11RS_GetKeyTypeName` for `CKK_*` values;
- `PKCS11RS_GetAttributeTypeName` for `CKA_*` values; and
- `PKCS11RS_GetProfileIdName` for `CKP_*` values.

Each returns null for an unknown value. A non-null string is immutable,
library-owned, and valid for the lifetime of the process; callers must neither
free nor modify it. Deprecated standard aliases resolve to their current
canonical names. The iPhone smoke app demonstrates the object-class and
key-type helpers while rendering its public and authenticated inventories.

## Authenticated credential diagnostics

`PKCS11RS_GetAuthenticatedCredential` returns the RFC 7512 PKCS #11 URI of the
exact credential that established the current token login. It uses ordinary
two-call buffer semantics, and its byte count excludes a NUL terminator. The
vendor query attribute `pkcs11rs-authkey` records the target Authentication Key
ID. Direct password authentication is reported as
`pkcs11:?pkcs11rs-direct=<label>&pkcs11rs-authkey=AAAA`. The URI contains no
PIN, password, private key, derived secret, or session key. A backend that does
not expose this metadata returns
`CKR_FUNCTION_NOT_SUPPORTED`; a supported backend without an active user login
returns `CKR_USER_NOT_LOGGED_IN`.

`CKA_PKCS11RS_URI` is a read-only UTF-8 RFC 7512 URI computed for every existing
object. It contains the token label, the token serial when the label does not
already contain it, `object` for `CKA_LABEL`, `id` for every nonempty `CKA_ID`,
and the standard URI `type` for recognized object classes. URI-safe ASCII ID
bytes remain readable; delimiters, controls, and non-ASCII bytes are
percent-encoded. It describes the source object only; a target
Authentication Key query is added only to successful YubiHSM authentication
diagnostics. The attribute is included in `CKA_ATTR_TYPES` and uses ordinary
two-call attribute-buffer semantics.

## Vendor mechanisms, key types, attributes, and profiles

The header declares the pkcs11rs vendor range and the identifiers used by:

- [public-key projection](public-key-projection-proposal.md), through
  `CKM_PKCS11RS_PROJECT_PUBLIC_KEY`;
- [FIDO2 one-shot assertions](fido2.md), through
  `CKM_PKCS11RS_FIDO_ASSERTION` and `CKA_PKCS11RS_FIDO_RP_ID`;
- RFC 7512 object identification and YubiHSM client-authentication selection,
  through `CKA_PKCS11RS_URI` and the URI contract documented in
  [YubiHSM authentication](yubihsm-auth.md);
- [protected prefixed ECDH derivation](prefixed-ecdh-derive.md), through
  `CKM_PKCS11RS_PREFIXED_ECDH_DERIVE`;
- [experimental previewSign](preview-sign.md), through its key-pair generation,
  derivation, signing, registration-key type, and metadata attributes;
- Yubico AES-CCM and RSA wrapping adaptations used by
  [YubiHSM slots](yubihsm-auth.md);
- [native HSM Auth credential discovery](yubihsm-auth.md#hsm-auth-slot-discovery-and-execution),
  through `CKK_YUBICO_HSMAUTH_CREDENTIAL_SYMMETRIC`,
  `CKK_YUBICO_HSMAUTH_CREDENTIAL_ASYMMETRIC`, and the retry-count and
  touch-required attributes; and
- target YubiHSM Authentication Key metadata, through
  `CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_SYMMETRIC` and
  `CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_ASYMMETRIC`.

The separate client and target key types expose each object's role directly.
Native HSM Auth slot support is an internal backend property rather than a
vendor-defined PKCS #11 profile.

Mechanism presence and flags must still be discovered per slot with
`C_GetMechanismList` and `C_GetMechanismInfo`; inclusion in the header does not
promise that every backend, device, key, or firmware supports an identifier.

## Administrative functions

The nonstandard administration entry points are grouped by feature:

- `PKCS11RS_SecurityDomain*` provisions and removes SCP03 and SCP11 material in
  the Issuer Security Domain. See
  [SCP03 provisioning](scp03.md#issuer-sd-key-provisioning) and
  [SCP11 provisioning](scp11.md#issuer-sd-key-provisioning).
- `PKCS11RS_YubiHsmEnrollDevice*` enrolls a YubiHSM device-public-key trust
  fingerprint using a selected attestation key, Yubico's factory attestation,
  or an explicit public-key pin. See
  [YubiHSM device trust](yubihsm-auth.md#asymmetric-device-key-trust).
- `PKCS11RS_HsmAuth*` creates, updates, deletes, and resets credentials in the
  YubiHSM Auth applet. See
  [YubiHSM Auth administration](yubihsm-auth.md#yubihsm-auth-administration).
- `PKCS11RS_PlatformCredential*` generates, lists, reads the public half of, and
  deletes credentials backed by the current platform's protected key store.
  `PKCS11RS_YubiHsmProvisionPlatformCredential` idempotently installs one such
  credential in the YubiHSM behind an authenticated read/write session, while
  `PKCS11RS_YubiHsmUnprovisionPlatformCredential` safely removes its matching
  Authentication Key and public projection. See
  [platform credential login](yubihsm-auth.md#platform-credential-login-architecture)
  and [iPhone provisioning](yubihsm-auth.md#provisioning-an-iphone-platform-credential).
- `PKCS11RS_SoftwareExportPrivateKey` exports an extractable software private key
  from any slot as password-encrypted PKCS #8. See
  [software private-key export](software.md#password-encrypted-pkcs-8-export).

These calls operate on a normal PKCS #11 session handle and inherit the login,
slot, device, template, and output-buffer rules documented for the referenced
feature. They are exported symbols, not members of any standard versioned
`CK_FUNCTION_LIST`.

The `PKCS11RS_HsmAuth*` family is strictly an applet-administration surface. It
does not expose runtime Calculate Session Keys commands. Runtime YubiHSM
authentication remains an internal provider operation selected through
ordinary YubiHSM `C_Login` or `C_LoginUser` forms.
