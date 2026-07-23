# CCID applet configuration

The PC/SC transport automatically probes these CCID applets by default:

| Applet | Default AID | AID override |
| --- | --- | --- |
| PIV | `A0 00 00 03 08` | `PKCS11RS_PIV_AID` |
| OpenPGP | `D2 76 00 01 24 01` | `PKCS11RS_OPENPGP_AID` |
| YubiHSM Auth | `A0 00 00 05 27 21 07 01` | `PKCS11RS_HSMAUTH_AID` |
| Issuer SD | `A0 00 00 01 51 00 00 00` | `PKCS11RS_ISSUER_SD_AID` |

Each applet is added as a separate PKCS #11 slot only when its configured AID
can be selected successfully. Reader and applet discovery is a snapshot taken
on the first `C_GetSlotList` call after `C_Initialize`; discovering newly added
readers or applets requires `C_Finalize` followed by `C_Initialize`. Existing
slots still refresh token presence when a session is opened. Initialization and
object-discovery failures do not remove an already selected applet slot.

## Allowlist

Without configuration, all four applets above are probed. Set
`PKCS11RS_CCID_APPLICATIONS` to a comma-separated allowlist when only specific
applets should be exposed:

```text
PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Accepted names are `piv`, `openpgp`, `hsmauth`, and `issuer-sd`. Names are
case-insensitive and duplicates are ignored.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, `scp11b`, or `scp11c`
to use that transport for every selected CCID applet. The secure channel is
scoped to the selected AID. Selecting another applet invalidates the previous
channel, so the module selects the requested AID and renegotiates before
sending the next protected command.

The reader connection is shared between all applet slots. The Issuer SD is the
Secure Domain management applet; it is not required to use PIV,
OpenPGP, or YubiHSM Auth.

The YubiHSM Auth applet exposes credential metadata in its own slot. Those
credentials are also available as authentication providers to each ordinary
USB YubiHSM slot. They do not create additional PKCS #11 slots. See
[`yubihsm-auth.md`](yubihsm-auth.md) for the resulting slot layout and login
syntax.

## Issuer SD objects

The Issuer SD slot reads the GlobalPlatform key-information template, card
recognition data, CPLC, supported CA identifiers, and available SCP11
certificate chains. Installed key records, CA identifiers, card recognition,
and CPLC are exposed as immutable `CKO_DATA` objects. Key records use the
two-byte KID/KVN reference as `CKA_ID`; `CKA_VALUE` contains only the reported
key-component type and length pairs, never key material. Their `CKA_OBJECT_ID`
contains the KID/KVN reference. Card-recognition and CPLC objects use their
GlobalPlatform tags as `CKA_OBJECT_ID`; CA objects use the CA-list tag followed
by KID/KVN. CA data-object values contain Subject Key Identifiers. SCP11
certificate-chain entries are exposed as immutable `CKO_CERTIFICATE` objects
in the card's issuer-to-leaf order. The leaf certificate shares the key
record's KID/KVN `CKA_ID`; preceding certificates use indexed IDs.

The slot does not advertise ordinary PKCS #11 cryptographic mechanisms. It
supports random generation through the applet's `GET CHALLENGE` command and
uses `C_Login` to establish the configured secure channel. Ordinary PKCS #11
object operations remain read-only. SCP03 key-set provisioning and deletion
and typed SCP11 key and trust management are available through the explicit
administration ABI in `pkcs11rs.h`. Raw Security Domain data storage and reset
are not exposed.

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
