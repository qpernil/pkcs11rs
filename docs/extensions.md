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
canonical names. The iPhone smoke app demonstrates the mechanism helper while
rendering `C_GetMechanismList` and `C_GetMechanismInfo` results.

## Vendor mechanisms, key types, and attributes

The header declares the pkcs11rs vendor range and the identifiers used by:

- [public-key projection](public-key-projection-proposal.md), through
  `CKM_PKCS11RS_PROJECT_PUBLIC_KEY`;
- [FIDO2 one-shot assertions](fido2.md), through
  `CKM_PKCS11RS_FIDO_ASSERTION` and `CKA_PKCS11RS_FIDO_RP_ID`;
- [experimental previewSign](preview-sign.md), through its key-pair generation,
  derivation, signing, registration-key type, and metadata attributes; and
- Yubico AES-CCM and RSA wrapping adaptations used by
  [YubiHSM slots](yubihsm-auth.md).

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
- `PKCS11RS_SoftwareExportPrivateKey` exports an extractable private key from a
  named software slot as password-encrypted PKCS #8. See
  [software private-key export](software.md#password-encrypted-pkcs-8-export).

These calls operate on a normal PKCS #11 session handle and inherit the login,
slot, device, template, and output-buffer rules documented for the referenced
feature. They are exported symbols, not members of any standard versioned
`CK_FUNCTION_LIST`.
