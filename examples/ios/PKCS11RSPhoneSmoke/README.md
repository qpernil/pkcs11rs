# PKCS11RS iPhone smoke test

This small UIKit application links the generated `PKCS11RS.xcframework`,
passes a versioned JSON configuration through
`CK_C_INITIALIZE_ARGS.pReserved`, and displays the module, slot, and token
metadata returned by PKCS #11. For every present slot it also enumerates the
mechanisms with `C_GetMechanismList`, queries their key-size ranges and flags
with `C_GetMechanismInfo`, and displays canonical standard, Yubico, and
PKCS11RS mechanism names returned by `PKCS11RS_GetMechanismName`.

Build the XCFramework before opening the Xcode project:

```sh
cargo xtask ios --release
```

The app defaults to `http://192.168.1.169:12345`. Override that URL with the
`PKCS11RS_YUBIHSM_URLS` launch environment variable or change
`fallbackConnectorURL` in `PKCS11RSPhoneSmoke/App.swift`. The environment
variable is only an input to this smoke-test UI; the module itself receives the
URL through the JSON passed to `C_Initialize`.

The smoke app calls `C_Initialize` once, refreshes the connector inventory with
`C_GetSlotList` whenever it becomes active, and calls `C_Finalize` only when the
app terminates. The client initially supplies room for ten slots and retries
with the returned required count only on `CKR_BUFFER_TOO_SMALL`, so an ordinary
refresh needs one slot-list call and one connector inventory request. It uses
the same PKCS #11 buffer contract with room for one hundred mechanisms per
slot. This exercises the normal long-lived client lifecycle and connector
recovery rather than rebuilding the module on every refresh. Returning to the
app after the iPhone sleeps or after another app has been active runs the same
refresh. If iOS terminated the process while it was suspended, the next launch
initializes a new module instance before refreshing.

The physical iPhone path has been verified against a connector running on a
Mac across real Mac system sleep. On resume the connector rebuilt its listener,
USB watcher, registry, and previously managed device handles; bringing the
long-lived iOS app back to the foreground refreshed its remote slot inventory
without a preceding `C_Finalize`/`C_Initialize` cycle.

The checked-in Xcode project contains the maintainer's development team for
automatic signing. Select a different development team in Xcode when building
under another Apple developer account.
