# CCID applet configuration

CCID discovery uses native PC/SC on desktop platforms and native
CryptoTokenKit on iOS. Both platform implementations feed the same reader
reconciliation and applet-probing path. The following applets are probed by
default:

| Applet | Default AID | AID override |
| --- | --- | --- |
| PIV | `A0 00 00 03 08 00 00 10 00 01 00` | `PKCS11RS_PIV_AID` |
| OpenPGP | `D2 76 00 01 24 01` | `PKCS11RS_OPENPGP_AID` |
| YubiHSM Auth | `A0 00 00 05 27 21 07 01` | `PKCS11RS_HSMAUTH_AID` |
| Issuer SD | `A0 00 00 01 51 00 00 00` | `PKCS11RS_ISSUER_SD_AID` |
| FIDO2 | `A0 00 00 06 47 2F 00 01` | `PKCS11RS_FIDO2_AID` |

Set `PKCS11RS_HARDWARE_DISCOVERY=0` to skip native PC/SC or CryptoTokenKit
discovery and all CCID reader and applet probes. This global
local-discovery switch also skips native USB/HID discovery, but does not affect
configured software slots or opt-in remote YubiHSM HTTP(S) connectors.

Each applet is added as a separate PKCS #11 slot only when its configured AID
can be selected successfully. Every `C_GetSlotList` asks the selected provider
for its current reader inventory. A reader name that has not yet contributed a
slot is probed for every configured applet. This lets newly attached readers,
and cards inserted into readers that were previously empty or unavailable,
append slots without `C_Finalize`/`C_Initialize`.

Once a reader name contributes at least one slot, that reader's applet topology
and slot IDs remain stable for the module lifetime. Subsequent listings refresh
token presence for those registered slots, as does opening a session. A removed
reader or card therefore leaves its slots registered but absent; when the same
reader name returns, those slots reconnect and reselect their own AIDs. A
replacement card does not make an established reader morph into a different
set of slots. Reinitialization is required only when the caller wants to forget
that stable inventory and probe a known reader name as entirely new.

## Native iOS readers

An iOS build calls CryptoTokenKit directly through Rust Objective-C bindings.
It obtains the current `TKSmartCardSlotManager` names on every slot-list
refresh. The connector lazily starts one worker for each reader that contributes
slots. That worker owns and reuses the reader's `TKSmartCard`, serializes its
APDUs, and adapts asynchronous session and transmit completions to the
synchronous PKCS #11 call. The non-exclusive `TKSmartCard` remains
cached, but the current transport opens one exclusive CryptoTokenKit session
at the first APDU of a device-backed PKCS #11 call and ends it when that call
returns. A removed card invalidates the retained object; the worker resolves a
new card by the same reader name when it returns.
Objective-C objects retained for card I/O stay confined to the worker that
created them.

The static XCFramework loads Apple's public CryptoTokenKit framework internally
before it first enumerates readers. Applications importing `PKCS11RS` need no
CryptoTokenKit import or linker setting, reader object, callback registration,
or transport implementation.

Set `nfc.discovery` to `true` in the initialization JSON (or set
`PKCS11RS_NFC_DISCOVERY=1`) to request one NFC card during the first
`C_GetSlotList`. NFC discovery is disabled by default because it presents
Apple's system UI. Because CryptoTokenKit NFC slot names are session-scoped,
pkcs11rs scans the selected card once and binds its device serial to stable
logical slots until `C_Finalize`. Those slots then follow the ordinary USB slot
model: registration is stable while physical token presence is refreshed
independently. A replacement NFC session must verify the bound serial before
carrying APDUs. After physical removal, the next `C_GetSlotList(CK_TRUE, ...)`
asks for that serial again. Canceling the request leaves NFC absent, so HSM Auth
ignores it when the same YubiKey is connected through USB. Canceling before
discovery completes leaves no placeholder slot and is not retried by later
slot-list polling. When the last operation finishes, the NFC session immediately
becomes idle and remains available until the card is removed, the user cancels,
or another operation reuses it. The initiating `C_GetSlotList` blocks while
Apple's NFC UI is active and should therefore run on an application worker
thread. Concurrent slot-list calls are serialized and cannot open duplicate NFC
requests.

This is a smart-card APDU backend, not general USB access. iOS does not expose
the reader's USB interfaces or bulk endpoints through CryptoTokenKit.

For each device-backed PKCS #11 call, pkcs11rs lazily begins one native
smart-card transaction before the first APDU and ends it when the call returns.
This is a CryptoTokenKit smart-card session on iOS and an
`SCardBeginTransaction`/`SCardEndTransaction` pair on desktop PC/SC. Every APDU
belonging to that call therefore runs without interleaving from another
cooperative client. Because another client may select a different applet
between calls, a new transaction begins without any assumed card selection.
The first APDU selects the configured AID while the transaction is held. The
selected AID and live SCP03 or SCP11 session belong to that transaction and are
destroyed together when it ends. Validated SCP11 public-key material remains
available across transactions for the same connected card.

## PC/SC ownership and external daemons

pkcs11rs connects to each card with `SCARD_SHARE_SHARED`. Its reader worker
serializes all local APDUs and retains one PC/SC transaction across all APDUs
in a device-backed PKCS #11 call. Calls that perform no APDU do not acquire a
transaction. Low-level calls made outside a PKCS #11 operation use a one-APDU
transaction as a fallback. Another shared PC/SC client can therefore remain
connected and use the card between pkcs11rs calls. An exclusive PC/SC owner can
still prevent connection. Until the reader has contributed a slot, a later
`C_GetSlotList` retries the applet probe. If the reader already has slots, they
remain registered and report the failed connection as token absence.

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

`disable-ccid` and `pcsc-shared` change `scdaemon`, not pkcs11rs. They allow
both programs to hold shared PC/SC connections, and pkcs11rs's operations are
protected by transactions and applet re-selection. GnuPG documents
`pcsc-shared` as potentially unsafe because `scdaemon` still assumes exclusive
ownership and caches card state. Its current PC/SC implementation loads the
transaction entry points but does not use them around commands. pkcs11rs cannot
make such a peer's own multi-APDU operations atomic: another client can still
take a transaction between two unprotected `scdaemon` commands. Fully safe
coexistence requires every client to use shared connections,
transaction-bounded multi-APDU operations, and correct applet re-selection.

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

The YubiKey Management applet is probed during each applet-discovery attempt
for a native reader that has not yet contributed slots. Its
device-wide serial number, firmware version, hardware part number,
capabilities, and configuration metadata are cached in the shared
physical-device context and are not exposed as a separate PKCS #11 slot. The
part number is reported as the PKCS #11 token model. Applet-specific serials
remain local to their applet slot and do not overwrite the physical identity.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, `scp11b`, or `scp11c`
to use that transport for every selected CCID applet. A live secure channel is
owned by one native smart-card transaction. The first APDU selects the
transaction's requested AID and establishes the configured channel; ending the
transaction destroys both states. A later operation therefore selects and
authenticates again instead of trusting reader state retained between calls.

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
`PKCS11RS_CCID_APPLICATIONS=fido2` to restrict the CCID applet probe; it does
not disable native FIDO HID discovery. Set `PKCS11RS_LOG=trace` to print the
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
credentials are also available as authentication providers to every ordinary
local or remote YubiHSM slot. They do not create additional PKCS #11 slots. See
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

`PKCS11RS_LOG` is read once during `C_Initialize` and accepts `off`, `error`,
`warn`, `info`, `debug`, or `trace`. Warnings include reader and applet
discovery failures. Debug reports named reader inventories, each applet probe
and outcome, applet-to-slot registration, retained reader slots, discovery
phase timing, and every PKCS #11 entry point. Trace adds per-request transport
and APDU timing. On iOS these events go directly to Apple Unified Logging when
a log level is configured.
