# PKCS11RS iPhone smoke test

This small UIKit application links the generated `PKCS11RS.xcframework` and
passes `PKCS11RS_INITIALIZE_ARGS_V1` through `CK_C_INITIALIZE_ARGS.pReserved`.
The extension contains the versioned JSON configuration and a host CCID reader
enumerator plus a tracing log callback. While discovery runs, the app displays
live pkcs11rs logs, follows the newest entry, and leaves that view selected when
discovery completes. The Log/Inventory control provides access to both
scrollable views. For every
present slot the inventory also enumerates the mechanisms with
`C_GetMechanismList`, queries their key-size ranges and flags with
`C_GetMechanismInfo`, and displays names returned by
`PKCS11RS_GetMechanismName`.

The app does not enumerate or register readers before `C_Initialize`.
`C_Initialize` retains the enumerator and its context in the module. During
every `C_GetSlotList`, normal hardware discovery invokes
`enumerateCcidReadersCallback`. Swift then reads the current
`TKSmartCardSlotManager` inventory and calls the Rust-provided reader sink once
per reader with its name, ATR, APDU sizes, callback context, and
`hostCcidTransmitCallback`. The reader objects are retained until the module is
finalized.

The smoke configuration leaves `hardware.discovery` at its default of `true`.
That setting is the policy gate for both native and host-provided hardware
discovery. A native desktop build without a host enumerator uses PC/SC. A build
initialized with a host enumerator uses that provider for CCID readers. Both
providers feed the same Rust reader loop and configured CCID slot discovery.

A configured application becomes a slot only when its AID can be selected. The
result uses the existing PIV, OpenPGP, YubiHSM Auth, Issuer Security Domain, or
FIDO2-over-CCID slot implementation; no applet logic is implemented in Swift.
YubiKey FIDO2 normally uses its separate FIDO interface and therefore does not
become a CCID slot unless the configured FIDO2 AID is actually selectable.

The PKCS #11 inspection runs on a background queue. The callback adapts each
synchronous Rust transport request to CryptoTokenKit's asynchronous session and
transmit APIs, waits off the main thread, copies the response into Rust's
caller-owned buffer, and then returns the PKCS #11 status. The app retains every
reader callback context for the lifetime of the module.

The log callback copies each synchronous Rust event and coalesces any burst into
one update on the next main-loop turn without reentering PKCS #11. Actual events
therefore appear continuously without flooding the UI queue. A separate elapsed
`Working…` indicator continues updating during long calls that naturally emit
no intermediate events. The smoke JSON requests the `debug` level, which adds
named reader and device inventories, each applet probe and outcome, stable slot
registration and retention, deduplication decisions, phase timing, and each
PKCS #11 call with its outcome and duration. Connector payloads and responses,
per-request transport and APDU timing, and session state remain reserved for
`trace`.
Enumeration and inspection do not authenticate, change configuration, or
modify objects on the key.

This path requires a physical iPhone or iPad with a CCID-enabled key attached
directly or through a USB-C adapter. A Simulator cannot expose that USB reader.
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

The smoke app calls `C_Initialize` once, enumerates local readers during every
`C_GetSlotList`, and calls `C_Finalize` only when the app terminates. Readers
first attached after initialization append their configured application slots.
Slots already allocated to a reader remain stable if it disappears; they report
no token until that reader returns. The client initially supplies room for ten
slots and retries
with the returned required count only on `CKR_BUFFER_TOO_SMALL`, so an ordinary
refresh needs one slot-list call and one connector inventory request. It uses
the same PKCS #11 buffer contract with room for one hundred mechanisms per
slot. This exercises the normal long-lived client lifecycle and connector
recovery rather than rebuilding the module on every refresh. Returning to the
app after the iPhone sleeps or after another app has been active runs the same
refresh. If iOS terminated the process while it was suspended, the next launch
initializes a new module instance before refreshing.

The smoke app is also the manual client for a connector running on a Mac across
real Mac system sleep. The connector retains its listener, USB watcher,
registry, and claimed device handles while macOS is suspended. Bringing the
long-lived iOS app back to the foreground then refreshes its remote slot
inventory without a preceding `C_Finalize`/`C_Initialize` cycle once the Mac's
network interface is reachable again. Recheck this path after changes to
connector sleep behavior; the separate USB-only test is documented in the
[connector guide](../../../docs/connector.md#usb-only-sleepwake-test).

The checked-in Xcode project contains the maintainer's development team for
automatic signing. Select a different development team in Xcode when building
under another Apple developer account.
