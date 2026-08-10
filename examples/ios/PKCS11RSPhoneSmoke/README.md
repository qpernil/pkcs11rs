# PKCS11RS iPhone smoke test

This small UIKit application links the generated `PKCS11RS.xcframework` and
passes its NUL-terminated JSON configuration directly through
`CK_C_INITIALIZE_ARGS.pReserved`. The application contains no CryptoTokenKit
import, CCID reader objects, transport callbacks, or logging callbacks; the iOS
build of pkcs11rs discovers and uses CryptoTokenKit readers and writes tracing
events to Apple Unified Logging itself. The app shows an elapsed working
indicator during discovery and then its scrollable inventory. For every
present slot the inventory opens a read-only public
session, enumerates every visible object with `C_FindObjects`, and displays its
handle, class, label, ID, and key type when available. Object class and key type
names come from the `PKCS11RS_GetObjectClassName` and
`PKCS11RS_GetKeyTypeName` helpers. YubiHSM Auth credential objects also show
their algorithm, remaining password retries, and touch policy.

The initialization JSON enables NFC discovery. At launch, the app calls
`C_Initialize` and `C_GetInfo` on its background inspection queue, but does not
enumerate slots. The first tap on **Refresh** calls `C_GetSlotList` and presents
Apple's NFC UI. Rust
selects the configured applets through the ordinary CCID connector and
registers each successful applet as a normal PKCS #11 slot. The bound tokens
remain logically present until `C_Finalize`; after the physical NFC session
ends, later operations present the UI again as needed and accept only the card
serial bound during discovery. Canceling or presenting an unrecognized card
simply omits NFC slots from that inventory and is not retried by later slot-list
polling. Restarting the app starts a fresh module lifetime and discovery
attempt. After the last operation, the NFC UI immediately displays its idle
message and remains available until the key is removed, the user cancels, or
another operation reuses the same session.
The NFC message identifies the current PKCS #11 stage, such as token discovery,
object search, attribute reading, or authentication. Generic communication
still identifies the bound YubiKey serial, and serial-guidance messages remain
stable.

Each device-backed PKCS #11 call holds one CryptoTokenKit smart-card session
across all of its APDUs. A new transaction begins without selected-applet or
live secure-channel state, so its first APDU selects the slot's AID before any
operation command. This prevents another CCID application from changing the
selected applet between pkcs11rs calls without detection. Configured SCP03 or
SCP11 channels are established inside the transaction and destroyed with it.

After the NFC UI has closed, tap **Refresh** to repeat the ordinary PKCS #11
inventory. NFC discovery itself remains latched, but the first operation on a
bound NFC token requests the same card again and verifies its serial. This is
the manual reacquisition test. Launching or foregrounding the app does not
refresh automatically, so presenting or dismissing the NFC system UI cannot
create an application-activation refresh loop.

The app's Core NFC polling list includes all applet AIDs that Rust may select.
Testing on iOS 26 found that CryptoTokenKit removes the NFC slot when the full
PIV AID is absent, even when Rust subsequently communicates only with YubiHSM
Auth. The PIV entry is therefore a CryptoTokenKit bootstrap requirement, not a
requirement that the operation or card use PIV. A short PIV AID suitable for an
APDU partial SELECT does not satisfy this requirement.

The JSON also configures a persistent software token named `iPhone smoke` and
places its storage below the app's Application Support directory. On first use,
the app recognizes exactly that owned slot by its `Software token` model and
`iPhone smoke` label, then uses the standard `CKF_TOKEN_INITIALIZED` and
`CKF_USER_PIN_INITIALIZED` flags to decide whether `C_InitToken` or the SO
login/`C_InitPIN` sequence is needed. Both profiles use the prototype PIN
`password`. These initialization calls are never applied to discovered
hardware. Before enumerating the software token's objects, the app logs in and
searches for a private `CKK_EC_MONTGOMERY` key with the stable ID
`iphone-smoke-x25519`. If it is absent, the app generates an X25519 keypair
with both objects marked as token objects. It then enumerates the authenticated
software session so both halves of the keypair appear in Inventory. Later
refreshes and process launches find the persisted private key and do not
generate another pair.

After every public object inventory is complete, the app lists all discovered
YubiHSM Auth credentials and selects the first one. For each YubiHSM slot it
compares the credential public object's `CKA_EC_POINT` with publicly discovered
`CKO_PUBLIC_KEY` objects. Exactly one matching object with a two-byte `CKA_ID`
supplies the explicit Authentication Key ID. The app then builds the
unambiguous `C_LoginUser` username `:<id><label>@<source>`, where the source is
the owning YubiKey serial (or slot description when no serial is available),
and supplies the prototype credential password `password`. Missing or
ambiguous public-key matches skip login instead of invoking hidden backend
selection. After a successful login, the app enumerates the objects again as an
authenticated user, logs out, and closes the session. On iOS the module
discovers the interactive NFC reader before ordinary USB smart-card readers so
its UI appears immediately, while still discovering every smart-card
credential provider before YubiHSM slots. The final display preserves discovery
order within each group but places YubiHSM slots after software and YubiKey
applet slots.

If discovery produces no YubiHSM Auth credential over any transport, the
inventory says so explicitly and notes that an interactive prompt may have been
canceled, a reader may be unavailable, or a presented token may not support the
applet. Credential discovery failure remains nonfatal so the app can still
display its software and YubiHSM slots.

An unreachable configured YubiHSM endpoint is an isolated discovery failure:
pkcs11rs records the failed endpoint and its outcome in Unified Logging, omits
any remote token that is not currently present, and continues returning the
persistent software token and available local CCID slots. A failure querying
one returned slot is likewise reported on that slot without aborting the
remaining inventory. Foregrounding the app retries remote discovery, so
recovery does not require reinitializing the module or recreating the software
token.

The app does not enumerate or register readers before `C_Initialize`. During
every `C_GetSlotList`, normal hardware discovery asks the Rust-native iOS
provider for the current `TKSmartCardSlotManager` inventory. pkcs11rs reads each
reader's name, ATR, and APDU limits directly. A reader that contributes slots
gets one lazy Rust worker that resolves and reuses its `TKSmartCard`.

The smoke configuration leaves `hardware.discovery` at its default of `true`.
That setting is the policy gate for native hardware discovery. A desktop build
uses PC/SC and an iOS build uses CryptoTokenKit. Both feed the same Rust reader
loop and configured CCID slot discovery.

A configured application becomes a slot only when its AID can be selected. The
result uses the existing PIV, OpenPGP, YubiHSM Auth, Issuer Security Domain, or
FIDO2-over-CCID slot implementation; no applet logic is implemented in Swift.
YubiKey FIDO2 normally uses its separate FIDO interface and therefore does not
become a CCID slot unless the configured FIDO2 AID is actually selectable.

The PKCS #11 inspection runs on a background queue. Inside pkcs11rs, the native
iOS provider adapts each synchronous transport request to CryptoTokenKit's
asynchronous session and transmit APIs and copies the completed response into
the PKCS #11 caller's buffer. The per-reader worker confines CryptoTokenKit
card I/O to one thread, serializes APDUs, and reuses its non-exclusive
`TKSmartCard`. The app uses a default-QoS serial inspection queue so its
synchronous PKCS #11 calls match the worker and blocking networking work while
remaining off the main thread. The current transport begins and ends an
exclusive CryptoTokenKit session around each complete device-backed PKCS #11
operation, acquiring it lazily at the first APDU. This provides CCID/APDU
transport, not access to arbitrary USB interfaces or bulk endpoints.

The smoke JSON requests the `debug` level, so pkcs11rs writes directly to Apple
Unified Logging under subsystem `com.nilssoncrypto.pkcs11rs`; Rust tracing
targets become log categories. View the live records in Xcode's console or in
the macOS Console app with the device selected. The elapsed `Working…`
indicator continues updating during long calls. Debug logging adds
named reader and device inventories, each applet probe and outcome, stable slot
registration and retention, deduplication decisions, phase timing, and each
PKCS #11 call with its outcome and duration. Connector payloads and responses,
per-request transport and APDU timing, and session state remain reserved for
`trace`.
The app does not modify objects on attached hardware. Its explicit YubiHSM Auth
inspection login authenticates but remains read-only. Private hardware objects
that require login are absent from the public-session view and may appear in
the authenticated view. The named software slot is the deliberate exception:
the app initializes it when necessary and creates the one persistent X25519
keypair described above.

USB discovery requires a physical iPhone or iPad with a CCID-enabled key
attached directly or through a USB-C adapter. NFC discovery likewise requires
a physical NFC-capable device and a compatible contactless smart card. A
Simulator supports neither reader.
If no hardware slot appears, confirm that the key and adapter support CCID and
that another application is not holding the smart-card session, then foreground
the smoke app again.

Build the XCFramework before opening the Xcode project:

```sh
cargo xtask ios --release
```

The app defaults to `http://192.168.1.169:12345`. Override that URL with the
`PKCS11RS_YUBIHSM_URLS` launch environment variable or change
`fallbackConnectorURL` in `PKCS11RSPhoneSmoke/App.swift`. The environment
variable is only an input to this smoke-test UI; the module itself receives the
URL through the JSON passed to `C_Initialize`.

For prototype discovery, the app also passes `yubihsm.public_discovery` as
`0001password`: authentication object ID `0001` followed by the default
password `password`. This discovery credential lets pkcs11rs authenticate to
each YubiHSM and expose the public objects visible in that credential's domains
before an ordinary PKCS #11 login. Change the literal in the smoke JSON when
the target YubiHSM does not use the factory-development credential. Do not ship
or commit a production credential in application source.

The smoke app calls `C_Initialize` at launch, but only calls `C_GetSlotList` in
response to **Refresh**. It enumerates local readers during every slot-list call
and calls `C_Finalize` only when the app terminates. Readers
first attached after initialization append their configured application slots.
Slots already allocated to a reader remain stable if it disappears; they report
no token until that reader returns. The client initially supplies room for ten
slots and retries
with the returned required count only on `CKR_BUFFER_TOO_SMALL`, so an ordinary
refresh needs one slot-list call and one connector inventory request. It uses
the same PKCS #11 buffer contract while enumerating objects. This exercises the
normal long-lived client lifecycle and connector recovery rather than
rebuilding the module on every refresh. Returning to the app after the iPhone
sleeps or after another app has been active leaves the existing inventory in
place until **Refresh** is tapped. If iOS terminated the process while it was
suspended, the next launch initializes a new module instance but still waits
for **Refresh** before enumerating slots.

The smoke app is also the manual client for a connector running on a Mac across
real Mac system sleep. The connector retains its listener, USB watcher,
registry, and claimed device handles while macOS is suspended. Bringing the
long-lived iOS app back to the foreground and tapping **Refresh** then refreshes
its remote slot inventory without a preceding `C_Finalize`/`C_Initialize` cycle
once the Mac's network interface is reachable again. Recheck this path after
changes to connector sleep behavior; the separate USB-only test is documented
in the
[connector guide](../../../docs/connector.md#usb-only-sleepwake-test).

## Future Swift client package

The smoke app now exercises enough of the Cryptoki client surface to serve as
the prototype and first integration test for a separate, vendor-neutral Swift
Package Manager wrapper. That package should consume the standard PKCS #11 C
ABI rather than introduce another pkcs11rs-specific ABI. Its initial scope
should include typed `CK_RV` errors, module initialization ownership, automatic
two-pass buffer handling, safe attribute templates, scoped sessions, logins,
searches and multipart operations, and an actor or equivalent executor for
asynchronous application use. Sensitive inputs such as PINs must have explicit
buffer lifetimes and cleanup.

The generic package should remain usable with other conforming PKCS #11
modules. A small optional pkcs11rs extension may provide typed construction of
named YubiHSM Auth login selectors without moving credential discovery or
authentication policy out of the standard object and login APIs. Refactoring
this smoke app onto the wrapper would validate the package against software,
USB CCID, NFC CryptoTokenKit, and remote YubiHSM slots before presenting it as
a general client library.

The checked-in Xcode project contains the maintainer's development team for
automatic signing. Select a different development team in Xcode when building
under another Apple developer account.
