# YubiHSM and YubiHSM Auth

## Slot layout

The module exposes one slot for every selectable CCID applet, one slot for
every physical YubiHSM USB device, and one slot for each URL configured in
`PKCS11RS_YUBIHSM_URLS`. URLs are comma-separated YubiHSM Connector base URLs,
for example `http://hsm-a:12345,http://hsm-b:12345`. Remote slots are additive;
they do not disable direct USB discovery. An unreachable configured connector
is retained as an empty slot until the module is reinitialized.

Direct YubiHSM USB discovery is enabled by default. Set
`PKCS11RS_YUBIHSM_USB=0` to disable it without affecting configured HTTP
connector slots. The only accepted values are `0` and `1`.

YubiHSM Auth credentials are objects in the applet slot and authentication
methods for every present YubiHSM slot, whether reached over USB or HTTP. For
one YubiKey with all four default applets and one YubiHSM, the result is five
slots.

The YubiHSM Auth slot contains read-only metadata objects for its credentials.
Every credential is represented by a `CKO_SECRET_KEY` with key type
`CKK_GENERIC_SECRET`, no cryptographic capabilities, and no readable
`CKA_VALUE`. An asymmetric credential also has a read-only `CKO_PUBLIC_KEY`
object containing its P-256 public key. The source applet's token serial number
identifies the YubiKey that owns these objects.

The following vendor attributes are available on credential objects:

| Attribute | Value |
| --- | --- |
| `CKA_YUBICO_HSMAUTH_ALGORITHM` | YubiHSM Auth algorithm number (`38` or `39`) |
| `CKA_YUBICO_HSMAUTH_RETRIES` | Remaining credential-password retries |
| `CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED` | Whether the credential requires touch |

## YubiHSM login

An ordinary YubiHSM slot supports three `C_Login` PIN forms:

| Authentication | PIN form |
| --- | --- |
| Direct symmetric key | `AAAApassword` |
| Direct asymmetric key | `@AAAApassword` |
| YubiHSM Auth credential | `:AAAA<label>[@<source>]:<credential-password>` |

`AAAA` is the four-hex-digit ID of the authentication key on the target
YubiHSM. Credential labels are printable UTF-8 strings. For example,
credential label `default` and YubiHSM authentication-key ID `0001` use:

```text
:0001default:credential-password
```

The short YubiHSM Auth form is accepted when exactly one connected applet has
that credential label. If multiple YubiKeys contain the same label, append the
source YubiKey serial number:

```text
:0001default@12345678:credential-password
```

When a source has no serial number, its slot description is used as the source
identifier. `@` and `:` are reserved in the credential selector. The leading
colon identifies a YubiHSM Auth login, and the next four characters are always
the target YubiHSM authentication-key ID. The following colon separates the
selector from the password, so the password itself may contain colons. The
selected credential and target YubiHSM authentication key must form a
compatible symmetric or asymmetric authentication pair.

PKCS #11 3.x callers may instead pass the authentication selector and password
separately with `C_LoginUser`:

| Authentication | Username | PIN |
| --- | --- | --- |
| Direct symmetric key | `AAAA` | Password |
| Direct asymmetric key | `@AAAA` | Password |
| YubiHSM Auth credential | `:AAAA<label>[@<source>]` | Credential password |

The module asks the YubiHSM Auth applet to calculate the session keys and keeps
those keys in zeroizing memory only for the life of the authenticated YubiHSM
session. Credential passwords are not cached. The direct YubiHSM login forms
remain available even when no YubiHSM Auth applet is connected.

Asymmetric YubiHSM secure sessions may use locally pinned device keys. Set
`PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX` to the path prefix for trusted-device
files; its default is the empty string. An empty prefix disables device-key
validation, allowing asymmetric authentication without prior provisioning. Any
nonempty prefix enables validation and requires an exact entry for the
connected device. Use `./` as the prefix to keep the trust files in the current
directory while still enabling validation.

The module hashes the canonical DER SubjectPublicKeyInfo returned by the bare
`GET DEVICE PUBLIC KEY` command and loads
`<prefix><lowercase SHA-256>.pem`. The PEM file may contain either one P-256
`PUBLIC KEY` or one X.509 `CERTIFICATE` whose P-256 public key represents the
trusted device. The stored key must exactly match the device response before
the secure-session receipt is accepted. A missing, malformed, or mismatched
entry rejects authentication. Configure a nonempty prefix before calling a
device-enrollment function.

Certificate chains are not processed during login. Instead, `pkcs11rs.h`
declares three explicit enrollment functions. They require a read/write session
on a YubiHSM slot and an existing `CKU_USER` login:

- `PKCS11RS_YubiHsmEnrollDeviceAttestation` attests the internal device public
  key using the supplied attestation-key ID and reads the attesting certificate
  from the opaque object with that same ID. The certificate signature and exact
  device-key match are verified. Calling this function is the administrator's
  explicit decision to trust that on-device attestation key.
- `PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation` uses the factory attestation
  key and certificate at reserved ID `0`, then validates the complete target,
  device, Yubico intermediate, and Yubico root chain before installing the pin.
- `PKCS11RS_YubiHsmEnrollDevicePublicKey` directly pins the public key returned
  by `GET DEVICE PUBLIC KEY` without attestation.

Each function returns the 32-byte SHA-256 fingerprint used in the trust-file
name. A null output pointer queries that fixed length without installing
anything. Attestation enrollment requires the authenticating YubiHSM key to
have `sign-attestation-certificate` and `get-opaque` capabilities. Generic
attestation IDs must refer to an asymmetric key and X.509 opaque object with the
same ID. On commercial YubiHSM devices, ID `0` is reserved for the built-in
factory attestation key and preloaded certificate.

After login, the YubiHSM device public key is also exposed through ordinary
PKCS #11 discovery as a read-only `CKO_PUBLIC_KEY` named
`YubiHSM device public key`. It has no cryptographic operation capabilities,
has an empty `CKA_ID`, returns the canonical DER SubjectPublicKeyInfo through
`CKA_PUBLIC_KEY_INFO`, and uses `yubihsm-device-public` as `CKA_UNIQUE_ID`.
`CKA_EC_PARAMS` and `CKA_EC_POINT` expose the standard P-256
representation. Other YubiHSM objects retain their configured labels; an empty
hardware label receives a deterministic description containing its object type
and decimal ID.

Generated YubiHSM asymmetric keys also expose a non-token X.509 attestation
certificate object with the same `CKA_ID`. The certificate is requested from
the HSM only when a certificate-derived attribute such as `CKA_VALUE` or
`CKA_SUBJECT` is read, then cached per slot and key generation. Imported keys
do not expose this object because the YubiHSM cannot attest imported key
material. The authentication key used for login must grant the
`sign-attestation-certificate` capability for the lazy read to succeed.

Credential creation, deletion, password changes, management-key changes, and
application reset are implemented by the internal protocol client but are not
mapped to PKCS #11 operations. The applet slot is deliberately read-only.

## Asymmetric hardware provisioning test

The ignored `provisions_asymmetric_hsmauth_credential_on_yubihsm` test deletes
the configured test credential and authentication key if they already exist,
generates a fresh persistent asymmetric credential on a YubiKey, reads its
P-256 public key, installs that public key as a YubiHSM authentication key, and
verifies an actual asymmetric session. It leaves the newly provisioned pair in
place after the test.

Provisioning requires an explicit enable flag and target object ID:

```sh
PKCS11RS_TEST_PROVISION_ASYMMETRIC_HSMAUTH=1 \
PKCS11RS_TEST_YUBIHSM_AUTHKEY_ID=1234 \
cargo test provisions_asymmetric_hsmauth_credential_on_yubihsm -- --ignored --nocapture
```

The defaults are YubiHSM Auth management key
`00000000000000000000000000000000`, credential label
`pkcs11rs-asymmetric`, credential password `password`, YubiHSM administrator
key `0001` with password `password`, domain `0001`, and no operational or
delegated capabilities on the new key. Override them with:

- `PKCS11RS_TEST_HSMAUTH_MANAGEMENT_KEY`
- `PKCS11RS_TEST_HSMAUTH_LABEL`
- `PKCS11RS_TEST_HSMAUTH_CREDENTIAL_PASSWORD`
- `PKCS11RS_TEST_YUBIHSM_ADMIN_ID`
- `PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD`
- `PKCS11RS_TEST_YUBIHSM_DOMAINS`

When multiple devices are attached, select them by serial number or full device
name with `PKCS11RS_TEST_HSMAUTH_SOURCE` and `PKCS11RS_TEST_YUBIHSM_SOURCE`.
Before cleanup, an existing YubiHSM object must have the configured label and
asymmetric authentication algorithm. This prevents an accidentally reused ID
from deleting an unrelated object. Cleanup occurs only after the explicit
enable flag and target ID have been validated. The freshly generated keys are
not deleted, including after a partial provisioning failure.
