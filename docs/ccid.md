# CCID applet configuration

The PC/SC transport automatically probes these CCID applets by default:

| Applet | Default AID | AID override |
| --- | --- | --- |
| PIV | `A0 00 00 03 08` | `PKCS11RS_PIV_AID` |
| OpenPGP | `D2 76 00 01 24 01` | `PKCS11RS_OPENPGP_AID` |
| YubiHSM Auth | `A0 00 00 05 27 21 07 01` | `PKCS11RS_HSMAUTH_AID` |
| Issuer SD | `A0 00 00 01 51 00 00 00` | `PKCS11RS_GLOBALPLATFORM_AID` |

Each applet is added as a separate PKCS #11 slot only when its configured AID
can be selected successfully. Initialization and object-discovery failures do
not remove an already discovered slot; they leave it enumerated with the token
marked not-present. The next refresh retries discovery.

## Allowlist

Without configuration, all four applets above are probed. Set
`PKCS11RS_CCID_APPLICATIONS` to a comma-separated allowlist when only specific
applets should be exposed:

```text
PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Accepted names are `piv`, `openpgp`, `hsmauth`, and `globalplatform`. Names are
case-insensitive and duplicates are ignored.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, or `scp11b` to use
that transport for every selected CCID applet. The secure channel is scoped to
the selected AID. Selecting another applet invalidates the previous channel,
so the module selects the requested AID and renegotiates before sending the
next protected command.

The reader connection is shared between all applet slots. The Issuer Security
Domain is the Secure Domain management applet; it is not required to use PIV,
OpenPGP, or YubiHSM Auth.

## Issuer SD objects

The Issuer SD slot reads the GlobalPlatform key-information template, card
recognition data, CPLC, supported CA identifiers, and available SCP11
certificate chains. Installed key records, CA identifiers, card recognition,
and CPLC are exposed as immutable `CKO_DATA` objects. Key records use the
two-byte KID/KVN reference as `CKA_ID`; `CKA_VALUE` contains only the reported
key-component type and length pairs, never key material. CA data-object values
contain Subject Key Identifiers. SCP11 certificate-chain entries are exposed
as immutable `CKO_CERTIFICATE` objects in the card's issuer-to-leaf order.

The slot does not advertise ordinary PKCS #11 cryptographic mechanisms. It
supports random generation through the applet's `GET CHALLENGE` command and
uses `C_Login` to establish the configured secure channel. Key import,
generation, deletion, allowlist management, and Security Domain reset are not
mapped to PKCS #11 operations.

Protocol-specific key and certificate configuration is documented in
[`scp03.md`](scp03.md) and [`scp11.md`](scp11.md).

## Diagnostics

`PKCS11RS_DEBUG` is read once during `C_Initialize` and accepts a numeric
log level:

- unset or `0`: no diagnostic output;
- `1`: initialization and applet-discovery failures only;
- `2`: all diagnostic output, including API and transport tracing.

Other values are invalid and cause `C_Initialize` to return
`CKR_ARGUMENTS_BAD`.
