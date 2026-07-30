# CCID applet configuration

The PC/SC transport automatically probes these CCID applets by default:

| Applet | Default AID | AID override |
| --- | --- | --- |
| PIV | `A0 00 00 03 08` | `PKCS11RS_PIV_AID` |
| OpenPGP | `D2 76 00 01 24 01` | `PKCS11RS_OPENPGP_AID` |
| YubiHSM Auth | `A0 00 00 05 27 21 07 01` | `PKCS11RS_HSMAUTH_AID` |
| Issuer SD | `A0 00 00 01 51 00 00 00` | `PKCS11RS_ISSUER_SD_AID` |
| FIDO2 | `A0 00 00 06 47 2F 00 01` | `PKCS11RS_FIDO2_AID` |

Set `PKCS11RS_HARDWARE_DISCOVERY=0` to skip PC/SC context creation and all
CCID reader and applet probes. This global local-discovery switch also skips
native USB/HID discovery, but does not affect configured software slots or
opt-in remote YubiHSM HTTP(S) connectors.

Each applet is added as a separate PKCS #11 slot only when its configured AID
can be selected successfully. Reader and applet discovery is a snapshot taken
on the first `C_GetSlotList` call after `C_Initialize`; discovering newly added
readers or applets requires `C_Finalize` followed by `C_Initialize`. Existing
slots still refresh token presence when a session is opened. Initialization and
object-discovery failures do not remove an already selected applet slot.

An empty PC/SC reader contributes no slots to that snapshot. If a card is
later inserted, no applet slots are synthesized for it until the module is
reinitialized. Conversely, once an applet slot exists, a card removal or
replacement does not change the slot list. Opening a session makes that slot
refresh the reader connection and reselect its own AID. If the replacement
card lacks the applet, the slot remains registered but reports no usable token
and rejects communication. It does not morph into slots for other applets on
the replacement card.

## PC/SC ownership and external daemons

pkcs11rs connects to each card with `SCARD_SHARE_EXCLUSIVE`, both initially and
on reconnect. Its shared reader state serializes complete applet selections and
APDU exchanges among pkcs11rs slots, but it does not call
`SCardBeginTransaction` or `SCardEndTransaction`. This means another process
holding either a shared or exclusive PC/SC connection can prevent pkcs11rs from
opening that reader. If this happens during the initial snapshot, none of that
reader's CCID applets become slots.

On macOS, GnuPG `scdaemon` is a common competing owner. It can use either its
built-in CCID driver, which opens the USB CCID interface directly and bypasses
PC/SC, or Apple's `PCSC.framework`. A typical `~/.gnupg/scdaemon.conf`
configuration that disables the direct driver and makes GnuPG request a shared
PC/SC connection is:

```text
disable-ccid
pcsc-shared
card-timeout 5
```

Apply it to the next daemon instance with:

```sh
gpgconf --kill scdaemon
```

`disable-ccid` and `pcsc-shared` change `scdaemon`, not pkcs11rs. GnuPG
documents `pcsc-shared` as potentially unsafe because `scdaemon` still assumes
exclusive ownership and caches card state. Its current PC/SC implementation
loads the transaction entry points but does not use them around commands.
Because pkcs11rs itself still requests exclusive access, `pcsc-shared` does not
enable concurrent operation between the two programs; `card-timeout` can
merely let an idle daemon release its connection sooner. Safe coexistence
requires both clients to use shared connections, transaction-bounded
multi-APDU operations, and correct applet re-selection.

Native FIDO HID discovery does not use PC/SC and may remain available while
the CCID interface is owned by another process.

[GnuPG documents `pcsc-shared` and its warning](https://www.gnupg.org/documentation/manuals/gnupg26/scdaemon.1.html).
[The GnuPG transaction discussion](https://dev.gnupg.org/T5484) confirms the
unimplemented boundary.

## Allowlist

Without configuration, all five applets above are probed. Set
`PKCS11RS_CCID_APPLICATIONS` to a comma-separated allowlist when only specific
applets should be exposed:

```text
PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Accepted names are `piv`, `openpgp`, `hsmauth`, `issuer-sd`, and `fido2`. Names are
case-insensitive and duplicates are ignored.

The YubiKey Management applet is probed once per PC/SC device before applet
discovery. Its device-wide serial number, firmware version, hardware part
number, capabilities, and configuration metadata are cached in the shared
physical-device context and are not exposed as a separate PKCS #11 slot. The
part number is reported as the PKCS #11 token model. Applet-specific serials
remain local to their applet slot and do not overwrite the physical identity.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, `scp11b`, or `scp11c`
to use that transport for every selected CCID applet. The secure channel is
scoped to the selected AID. Selecting another applet invalidates the previous
channel, so the module selects the requested AID and renegotiates before
sending the next protected command.

The reader connection is shared between all applet slots. The Issuer SD is the
Secure Domain management applet; it is not required to use PIV,
OpenPGP, or YubiHSM Auth.

## FIDO2 smart-card binding

Pre-release YubiKey firmware may expose FIDO2 through the USB CCID smart-card
interface. Production YubiKeys normally expose FIDO2 over the separate USB
FIDO HID interface, which pkcs11rs discovers independently. FIDO over NFC uses
the smart-card binding. Applet selection, `authenticatorGetInfo`, legacy
PIN-token login, and read-only credential enumeration have also been validated
with an earlier YubiKey over NFC on macOS.

The module follows the CTAP ISO 7816 binding: it explicitly selects the FIDO2
AID, sends `authenticatorGetInfo` as `80 10 80 00` with the CTAP command byte
`04`, and follows `91 00` status updates with `80 11 00 00` GET RESPONSE
commands. A successfully selected applet is exposed as a PKCS #11 slot even if
`authenticatorGetInfo` later fails, consistent with the other CCID applets.
Its enumerated credential metadata remains immutable; `C_SetPIN` separately
supports PIN initialization and changes when GetInfo succeeds. A successful
GetInfo also enables the explicit resident-assertion mechanism. Devices
advertising the experimental `previewSign` extension expose additional vendor
registration, derivation, and signing mechanisms. Preserving the
selected slot makes discovery failures visible to diagnostics, and
token-information calls continue to report the failure. When GetInfo succeeds,
the primary CTAP version is included in the PKCS #11 slot description and
token label. The device manufacturer, model, serial number, hardware version,
and firmware version use the shared YubiKey metadata. Set
`PKCS11RS_CCID_APPLICATIONS=fido2` to restrict the PC/SC applet probe; it does
not disable native FIDO HID discovery. Set `PKCS11RS_DEBUG=2` to print the
complete reported versions, extensions, AAGUID, options, maximum message size,
PIN/UV protocols, and transports.

Read-only resident-credential enumeration is available after FIDO2 PIN login.
It creates private, immutable data objects and, where lossless, linked
public/private key projections. Public operations execute in software. A
private projection with a known RP ID supports only the explicit, one-shot
vendor GetAssertion mechanism after context-specific PIN login. Those objects
do not expose credential mutation or previewSign signing merely because the
authenticator advertises that extension. See [`fido2.md`](fido2.md) for the
object mapping and local hardware probes, and
[`preview-sign.md`](preview-sign.md) for the separate experimental lifecycle.

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

The slot advertises no key, signing, encryption, or derivation mechanisms.
The module-wide software digest mechanisms are still available because they
do not require backend key operations. The slot supports random generation
through the applet's `GET CHALLENGE` command and
uses `C_Login` with a zero-length PIN to establish the configured secure
channel. Both a null pointer and a nonnull pointer are accepted when the length
is zero; nonempty input is rejected because no caller-supplied PIN is verified.
The token consequently reports a 0-through-0 PIN range. Ordinary PKCS #11
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
- `1`: initialization and applet-discovery failures, including the PC/SC
  reader name when a reader cannot be opened;
- `2`: all diagnostic output, including successful PC/SC reader opens, API
  calls, and transport tracing.

Other values are invalid and cause `C_Initialize` to return
`CKR_ARGUMENTS_BAD`.
