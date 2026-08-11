# iOS application integration

pkcs11rs exposes the same standard PKCS #11 C ABI on iOS that it exposes on
Linux, macOS, and Windows. The unusual part of the iOS integration is packaging:
the module is linked into the application as a static XCFramework instead of
being discovered as a shared library at a filesystem path.

Swift and Objective-C applications can therefore call `C_Initialize`,
`C_GetSlotList`, `C_OpenSession`, and every other exported PKCS #11 entry point
directly. Applications that implement a generic PKCS #11 client may instead use
`C_GetFunctionList` or `C_GetInterface`; the ABI and function semantics are the
same either way.

## Build the XCFramework

Install the Rust device and Apple Silicon Simulator targets, then create an
optimized XCFramework from the repository root:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo xtask ios --release
```

The output is `target/ios/PKCS11RS.xcframework`. Set
`IPHONEOS_DEPLOYMENT_TARGET` before the command to override the default iOS 18.0
deployment target, or pass `--output PATH` to choose a different output path.
The XCFramework contains ARM64 device and Apple Silicon Simulator slices. It
does not contain an Intel `x86_64` Simulator slice.

## Add pkcs11rs to an Xcode target

Add `PKCS11RS.xcframework` to the application's target under **Frameworks,
Libraries, and Embedded Content**. The current artifact contains static
libraries, so link it without embedding it as a dynamic framework. Xcode reads
the bundled headers and Clang module map automatically.

Import the module from Swift:

```swift
import PKCS11RS
```

Or from Objective-C:

```objc
@import PKCS11RS;
```

No bridging header, Rust-specific adapter, CryptoTokenKit import, application
transport callback, or CryptoTokenKit linker setting is required.

## Initialize the module

pkcs11rs accepts its versioned JSON configuration as a direct NUL-terminated
UTF-8 string through `CK_C_INITIALIZE_ARGS.pReserved`. It reads but does not
retain the pointer during `C_Initialize`.

Swift:

```swift
let json = #"{"version":1,"logging":{"level":"info"},"hardware":{"discovery":true}}"#
var arguments = CK_C_INITIALIZE_ARGS()
arguments.flags = CK_FLAGS(CKF_OS_LOCKING_OK)

let result = json.withCString { bytes in
    arguments.pReserved = UnsafeMutableRawPointer(mutating: bytes)
    return C_Initialize(&arguments)
}
guard result == CKR_OK else {
    // Handle the CK_RV error.
    return
}
```

Objective-C:

```objc
static const char configuration[] =
    "{\"version\":1,\"logging\":{\"level\":\"info\"},"
    "\"hardware\":{\"discovery\":true}}";

CK_C_INITIALIZE_ARGS arguments = {0};
arguments.flags = CKF_OS_LOCKING_OK;
arguments.pReserved = (CK_VOID_PTR)configuration;

CK_RV result = C_Initialize(&arguments);
if (result != CKR_OK) {
    // Handle the CK_RV error.
}
```

A null argument uses environment variables and built-in defaults. JSON is
preferable in an iOS application because an app normally owns its configuration
and cannot rely on a shell environment. The complete schema is documented in
[Initialization configuration](configuration.md).

## Call the PKCS #11 API

The static link makes every exported C entry point directly callable. A known
pkcs11rs client does not need to obtain a function table first:

```objc
CK_INFO info = {0};
CK_RV result = C_GetInfo(&info);

CK_ULONG count = 0;
result = C_GetSlotList(CK_TRUE, NULL_PTR, &count);
```

`C_GetInfo` reports pkcs11rs as a PKCS #11 3.2 module. For generic client code,
`C_GetFunctionList` returns the standard legacy 2.40-shaped table, while
`C_GetInterface` exposes the supported 2.40, 3.0, 3.1, and 3.2 table layouts.
Common table entries and direct calls use the same implementations.

PKCS #11 variable-length output conventions still apply. Query the required
count or length, allocate a buffer, then repeat the call. Be prepared to resize
and retry on `CKR_BUFFER_TOO_SMALL` because the slot or object inventory can
change between calls.

## Keep synchronous calls off the main thread

PKCS #11 is synchronous. Reader discovery, NFC presentation, smart-card APDUs,
and remote connector requests can take noticeable time. Run calls on a serial
background queue or another executor that keeps blocking work away from the
main UI thread.

A serial queue also gives an application a simple place to own the module
lifecycle:

1. Call `C_Initialize` once.
2. Perform PKCS #11 calls for the lifetime of the process.
3. Call `C_Finalize(NULL_PTR)` when the application is actually terminating.

Do not finalize and reinitialize for every refresh. Each module lifetime owns
its sessions and stable slot IDs, and a later `C_GetSlotList` refreshes reader
and remote connector discovery.

## Available iOS backends

The XCFramework contains:

- Named software slots, including encrypted persistent objects when the app
  configures storage inside its container.
- Remote YubiHSM HTTP or HTTPS connector slots.
- Local USB CCID smart-card readers exposed by CryptoTokenKit on a physical
  iPhone or iPad.
- Optional CryptoTokenKit NFC discovery on a physical NFC-capable device.

The iOS build does not contain the desktop PC/SC, native USB, or FIDO HID
transports. CryptoTokenKit supplies smart-card APDU transport; it does not give
pkcs11rs general USB interfaces or bulk endpoints. The Simulator has neither a
USB CCID reader nor NFC, but it can exercise software slots and remote
connectors.

## NFC configuration

NFC discovery is opt-in because the first `C_GetSlotList` presents Apple's
system UI and blocks until that request completes. Enable it in the
initialization JSON:

```json
{
  "version": 1,
  "nfc": {
    "discovery": true
  }
}
```

The application also needs `NFCReaderUsageDescription` and the complete list of
ISO 7816 applet identifiers that pkcs11rs may select. Copy the maintained values
from the Swift smoke app's
[`Info.plist`](../examples/ios/PKCS11RSPhoneSmoke/PKCS11RSPhoneSmoke/Info.plist).
Run the initiating slot-list call on the background PKCS #11 queue. Cancellation
or an unrecognized card omits NFC slots from that discovery attempt rather than
failing the entire slot list.

## Network and storage configuration

When connecting to a YubiHSM connector on the local network, provide the
appropriate `NSLocalNetworkUsageDescription` in the application `Info.plist`.
Production deployments should use HTTPS and the trust configuration described
in the [connector guide](connector.md).

Persistent software-token storage must be inside the application's writable
container. An Application Support subdirectory is the normal choice. Pass its
absolute path as `storage.tokens`; do not use the desktop example paths shown in
the complete configuration schema.

Never embed production PINs, YubiHSM authentication secrets, SCP keys, or TLS
private keys in application source. The sample credentials in the Swift smoke
app are deliberately prototype-only.

## Example applications

Two checked-in UIKit applications use the same XCFramework and direct C ABI:

- [Swift iPhone smoke test](../examples/ios/PKCS11RSPhoneSmoke/README.md) is the
  comprehensive integration and hardware exercise. It covers USB CCID, NFC,
  persistent software keys, remote YubiHSM discovery, YubiHSM Auth login, object
  inventory, and long-lived application behavior.
- [Objective-C smoke test](../examples/ios/PKCS11RSObjCSmoke/README.md) is the
  compact integration example. It initializes the module, reads `CK_INFO`, and
  lists present slots and tokens on a serial background queue. It uses the same
  initialization configuration as the Swift app: the connector URL override,
  Application Support storage, software slot, public YubiHSM discovery, debug
  logging, and NFC discovery all match. In both apps, the first explicit refresh
  starts slot discovery so NFC UI is not presented automatically at launch.

Build the XCFramework before opening either Xcode project. Both projects contain
the maintainer's development team for automatic device signing; select a
different team in Xcode when building under another Apple developer account.

## Diagnostics and troubleshooting

Set `logging.level` to `error`, `warn`, `info`, `debug`, or `trace`. On iOS,
pkcs11rs writes to Apple Unified Logging under subsystem
`com.nilssoncrypto.pkcs11rs`. Inspect it from Xcode or the macOS Console app.

If a local token is missing:

- Confirm the test is running on a physical device; the Simulator has no local
  reader transport.
- Confirm the key and adapter expose a CCID smart-card interface.
- Check whether another application owns the smart-card session.
- Enable `debug` logging and call `C_GetSlotList` again after attaching or
  reinserting the device.
- For NFC, verify the usage description and applet identifier list and restart
  the app to begin a fresh module lifetime after a canceled discovery.
