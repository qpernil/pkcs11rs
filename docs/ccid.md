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
can be selected successfully. Each fresh `C_GetSlotList` enumeration asks the
selected provider for its current reader inventory. Calls within the module-wide
[configurable refresh window (500 ms by default)](architecture.md#discovery-lifecycle-and-stable-slots)
skip reconciliation. Reader names only locate candidates long
enough to identify their physical YubiKey serial. They are not stable identity:
different PC/SC implementations apply different naming and disambiguation
rules, USB re-enumeration can rename the same reader, and CryptoTokenKit NFC
slot names last only for one system NFC session.

The first encounter with a serial probes every configured applet and binds the
resulting topology and slot IDs to that serial until `C_Finalize`. Later reader
or CryptoTokenKit names that identify the same serial simply replace the
transport behind those slots, including when the YubiKey moves between NFC and
USB CCID. Applet discovery is not repeated. A normal refresh of an unchanged
connection sends no discovery APDUs; after a connection is reacquired,
pkcs11rs reads only enough YubiKey management data to validate the serial.
The first operation on an applet selects its AID. Repeated operations reuse
that selection until another applet is selected or the card reconnects.

A removed token therefore leaves its slots registered but absent. A different
serial appearing under a reused reader name does not inherit those slots; it is
identified as another token and receives its own one-time applet probe.
Reinitialization is required only when the caller wants to forget all retained
serial-owned registrations.

## Native iOS readers

An iOS build calls CryptoTokenKit directly through Rust Objective-C bindings.
It obtains the current `TKSmartCardSlotManager` names on every slot-list
refresh. Those names are transient locators; the validated serial owns the
slots. The connector lazily starts one worker for each active locator. That
worker owns and reuses the reader's `TKSmartCard`, serializes its APDUs, and
adapts asynchronous session and transmit completions to the synchronous
PKCS #11 call. Before beginning the native session it marks the card sensitive,
then retains that session while the card and connector remain valid. A removed
card invalidates the retained object and advances the connection generation;
enumeration may
resolve the same serial through the same or a different locator when it
returns.
Objective-C objects retained for card I/O stay confined to the worker that
created them.

CryptoTokenKit has no PC/SC-style exclusive reader-open mode. `makeSmartCard()`
creates an ordinary card object; exclusivity begins with `beginSession()`.
While pkcs11rs retains that session, CryptoTokenKit queues session requests
from other `TKSmartCard` objects. The sensitive flag requests a reset before
this session communicates and before the card is handed to another object.

The static XCFramework loads Apple's public CryptoTokenKit framework internally
before it first enumerates readers. Applications importing `PKCS11RS` need no
CryptoTokenKit import or linker setting, reader object, callback registration,
or transport implementation.

Set `nfc.discovery` to `true` in the initialization JSON (or set
`PKCS11RS_NFC_DISCOVERY=1`) to request one NFC card during the first
`C_GetSlotList`. The current CryptoTokenKit USB inventory is reconciled first,
and later refreshes likewise attach newly available USB routes before any
registered slot can request NFC reacquisition. NFC discovery is disabled by
default because it presents Apple's system UI. Because CryptoTokenKit NFC slot names are session-scoped,
pkcs11rs scans the selected card once and binds its device serial to stable
logical slots until `C_Finalize`. Those slots then follow the ordinary USB slot
model: registration is stable while physical token presence is refreshed
independently. A replacement NFC session must verify the bound serial before
carrying APDUs. After physical removal, the next `C_GetSlotList` refresh can
ask for that serial again; this happens before the `CK_TRUE` or `CK_FALSE`
token-present filter is applied. Canceling the request leaves NFC absent, so
HSM Auth ignores it when the same YubiKey is connected through USB. Canceling
before discovery completes leaves no placeholder slot and is not retried by
later slot-list polling. When the last operation finishes, the NFC session
immediately becomes idle and remains available until the card is removed, the
user cancels, or another operation reuses it. The initiating `C_GetSlotList`
blocks while Apple's NFC UI is active and should therefore run on an
application worker thread. Concurrent slot-list calls are serialized and
cannot open duplicate NFC requests. See
[When the NFC UI appears](ios-integration.md#when-the-nfc-ui-appears) for the
initial-discovery, reacquisition, reuse, and cancellation cases.

This is a smart-card APDU backend, not general USB access. iOS does not expose
the reader's USB interfaces or bulk endpoints through CryptoTokenKit.

One card-wide state records either no selected applet or the selected AID with
its live SCP03/SCP11 session and logical PKCS #11 login role. Selecting another
applet replaces this state: the old applet's PKCS #11 sessions remain open but
become public. Repeated operations on the same applet do not send another
SELECT. Card removal, replacement, or transport reconnection clears the whole
state. Validated SCP11 public-key material is separately cached for the same
connected card and is also discarded on reconnection.

## PC/SC ownership and external daemons

pkcs11rs connects to each desktop card with `SCARD_SHARE_EXCLUSIVE`. Its reader
worker retains that connection and serializes all local APDUs; it does not use
per-call PC/SC transactions. Another process cannot connect to the card until
the pkcs11rs connector releases it. An existing shared or exclusive owner can
therefore prevent pkcs11rs from connecting. Until the reader has contributed a
slot, a later `C_GetSlotList` retries the applet probe. If the reader already
has slots, they remain registered and report the failed connection as token
absence. PC/SC
ownership applies to the reader, not one selected applet: an exclusive client
using OpenPGP can therefore also make PIV, YubiHSM Auth, Issuer SD, and FIDO
over CCID unavailable through that reader. A separate native FIDO HID
interface does not depend on PC/SC ownership.

On macOS, GnuPG `scdaemon` is a common competing owner. It can use either its
built-in CCID driver, which opens the USB interface directly, or Apple's
`PCSC.framework`. Stop it before opening pkcs11rs:

```sh
gpgconf --kill scdaemon
```

`disable-ccid` and `pcsc-shared` change `scdaemon`, not pkcs11rs. Shared mode
does not permit coexistence with pkcs11rs's exclusive connection. The exclusive
boundary is intentional: smart-card applet selection, PIN verification, and
secure-channel state are card-global and cannot be reconstructed safely after
arbitrary traffic from another process.

Native FIDO HID discovery does not use PC/SC and may remain available while
the CCID interface is owned by another process.

[GnuPG documents `pcsc-shared` and its warning](https://www.gnupg.org/documentation/manuals/gnupg26/scdaemon.1.html).

The standalone ownership check sends no APDUs. With exactly one reader and one
inserted card, run:

```sh
cargo run --features native-hardware --bin pcsc-exclusive-test
```

If more readers are installed, pass one exact PC/SC reader name after `--`. The
check verifies that a peer is rejected while the exclusive connection is alive
and can connect after it is released.

## Allowlist

Without configuration, all five applets above are probed. Set
`PKCS11RS_CCID_APPLICATIONS` to a comma-separated allowlist when only specific
applets should be exposed:

```text
PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Accepted names are `piv`, `openpgp`, `hsmauth`, `issuer-sd`, and `fido2`. Names are
case-insensitive and duplicates are ignored.

This allowlist controls probing, including HSM Auth credential-provider
discovery. The [`slots.serials` device allowlist](configuration.md) is applied
first, using the Management serial; excluded devices receive no applet probes.
Using HSM Auth requires both an allowed helper YubiKey serial and `hsmauth`
in the applet list. This CCID setting does not disable native FIDO HID discovery.

The YubiKey Management applet is probed during each applet-discovery attempt
for a native reader that has not yet contributed slots. Its
device-wide serial number, firmware version, hardware part number,
capabilities, and configuration metadata are cached in the shared
physical-device context and are not exposed as a separate PKCS #11 slot. The
part number is reported as the PKCS #11 token model. Applet-specific serials
remain local to their applet slot and do not overwrite the physical identity.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, `scp11b`, or `scp11c`
to use that transport for every selected CCID applet. Selecting an applet
establishes the configured channel, and the live channel remains paired with
that selected AID. Selecting another applet or reconnecting destroys it.

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

The YubiHSM Auth applet exposes credential metadata in its own slot, advertised
by the credential key types. Symmetric and asymmetric credentials use
`CKK_YUBICO_HSMAUTH_CREDENTIAL_SYMMETRIC` and
`CKK_YUBICO_HSMAUTH_CREDENTIAL_ASYMMETRIC`, respectively. Those
credentials are also available as authentication providers to every ordinary
local or remote YubiHSM slot. They do not create additional PKCS #11 slots. See
[`yubihsm-auth.md`](yubihsm-auth.md) for the resulting slot layout and login
syntax.

The applet credential inventory is cached for the lifetime of one physical
connection. Repeated token-information and object-search calls reconcile from
that cache without sending inventory APDUs. A new connection epoch or a
successful credential-administration operation invalidates it. Before native
YubiHSM authentication, the cached descriptor selects the applet credential by
label. The applet operation and target secure-channel verification determine
whether that credential remains usable, without a separate inventory scan.
Call `PKCS11RS_RefreshTokenObjects` when an application explicitly requires a
live inventory. On this slot the refresh sends the YubiHSM Auth inventory
APDUs; like any real CCID operation, it can select the applet and thereby
invalidate authentication or an SCP session belonging to another applet.

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
