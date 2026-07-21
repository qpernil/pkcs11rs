# YubiHSM and YubiHSM Auth

## Slot layout

The module exposes one slot for every selectable CCID applet and one slot for
every physical YubiHSM USB device. YubiHSM Auth credentials are objects in the
applet slot and authentication methods for YubiHSM USB slots. For one YubiKey
with all four default applets and one YubiHSM, the result is five slots.

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
| YubiHSM Auth credential | `:<label>:<credential-password>:AAAA` |

`AAAA` is the four-hex-digit ID of the authentication key on the target
YubiHSM. Credential labels are printable UTF-8 strings. For example,
credential label `default` and YubiHSM authentication-key ID `0001` use:

```text
:default:credential-password:0001
```

The short YubiHSM Auth form is accepted when exactly one connected applet has
that credential label. If multiple YubiKeys contain the same label, append the
source YubiKey serial number:

```text
:default@12345678:credential-password:0001
```

When a source has no serial number, its slot description is used as the source
identifier. `@` and `:` are reserved in the credential selector. A credential
password may contain colons because the final colon separates the password
from the fixed-width authentication-key ID. The selected credential and target
YubiHSM authentication key must form a compatible symmetric or asymmetric
authentication pair.

The module asks the YubiHSM Auth applet to calculate the session keys and keeps
those keys in zeroizing memory only for the life of the authenticated YubiHSM
session. Credential passwords are not cached. The direct YubiHSM login forms
remain available even when no YubiHSM Auth applet is connected.

Credential creation, deletion, password changes, management-key changes, and
application reset are implemented by the internal protocol client but are not
mapped to PKCS #11 operations. The applet slot is deliberately read-only.
