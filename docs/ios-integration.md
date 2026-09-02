# iOS application integration

pkcs11rs exposes the same standard PKCS #11 C ABI on iOS as on Linux, macOS,
and Windows. This is normal PKCS #11 usage: Swift and Objective-C clients use
the standard headers, types, functions, return values, buffer conventions,
sessions, and lifecycle directly, without a pkcs11rs-specific client API or
language wrapper.

The PKCS #11 implementation, token and applet logic, sessions, and object model
come from the shared cross-platform Rust codebase. The iOS-specific differences
are packaging the module as a static XCFramework and using Apple CryptoTokenKit
for local smart-card transport. Software slots and remote YubiHSM connectors
continue to use the shared implementations.

## Prerequisites

Building the iOS XCFramework requires macOS, Xcode with the iOS SDK and Command
Line Tools, and Rust 1.85 or newer. The generated artifact supports ARM64 iPhone
and iPad devices and Apple Silicon (`arm64`) Simulator destinations; it does not
include an Intel (`x86_64`) Simulator slice.

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

No bridging header, CryptoTokenKit import, application transport callback, or
CryptoTokenKit linker setting is required.

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

The static link makes every exported C entry point directly callable. An
application linked directly against pkcs11rs does not need to obtain a function
table first:

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
and remote connector discovery. See
[Discovery lifecycle and stable slots](architecture.md#discovery-lifecycle-and-stable-slots)
for what happens during the first listing and what later listings refresh.

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

The shared Apple provider also compiles into the XCFramework and can use a
P-256 credential generated in the physical iPhone's Secure Enclave for remote
YubiHSM login. See
[Provisioning an iPhone platform credential](yubihsm-auth.md#provisioning-an-iphone-platform-credential)
for the device-local key lifecycle, public-key enrollment, trust boundaries,
login syntax, and the app-facing functions still to be added.

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
from either smoke app's synchronized `Info.plist`, such as the Swift app's
[`Info.plist`](../examples/ios/PKCS11RSPhoneSmoke/PKCS11RSPhoneSmoke/Info.plist).
Run the initiating slot-list call on the background PKCS #11 queue. Cancellation
or an unrecognized card omits NFC slots from that discovery attempt rather than
failing the entire slot list.

A CryptoTokenKit NFC slot name lasts only for its system NFC session, so it
cannot itself identify a PKCS #11 slot. USB CryptoTokenKit and PC/SC names are
also merely locators and may differ between implementations or after USB
re-enumeration. At the top layer these are all CCID smart-card endpoints.
pkcs11rs performs one identity scan and binds the discovered applet topology to
the device serial for the module lifetime. The same logical slots can therefore
move between NFC and USB CCID without repeating applet discovery:
`CKF_TOKEN_PRESENT` follows the current endpoint, while iOS NFC reacquisition
verifies the serial before carrying APDUs.

After physical removal, the next slot-list refresh can ask for the bound serial
again. Successful verification restores NFC presence. If the user cancels, the
NFC transport remains absent and YubiHSM Auth provider selection ignores it;
connecting the same YubiKey through USB therefore selects its present USB
provider without an ambiguous credential match.

### When the NFC UI appears

The system NFC UI can be opened at two distinct stages:

1. **Initial identity discovery.** When `nfc.discovery` is enabled, the first
   `C_GetSlotList` in the module lifetime first reconciles the non-interactive
   CryptoTokenKit USB inventory, then opens a generic “Hold your YubiKey”
   request. pkcs11rs reads the physical serial and probes applets before it can
   create stable slots. If that serial was already discovered over USB, NFC is
   retained only as its fallback connector and does not replace the present USB
   route. Canceling or presenting an unrecognized card at this stage creates no
   NFC slots, and ordinary later slot-list polling does not repeat this initial
   scan. Reinitialization is required for another initial discovery attempt.
2. **Reacquisition of registered slots.** After successful discovery, removal
   or an inactive CryptoTokenKit NFC session leaves the stable slots registered
   but absent. A later `C_GetSlotList` refresh, or a device-backed operation
   that reaches NFC transport preparation, can open a serial-specific request
   for the already bound YubiKey. The presented serial must match before
   presence is restored or APDUs are allowed.

The `CK_TRUE` argument to `C_GetSlotList` does not itself cause the UI. Every
slot-list call refreshes registered transports before applying the
token-present filter, so either `C_GetSlotList(CK_FALSE, ...)` or
`C_GetSlotList(CK_TRUE, ...)` can request reacquisition after removal. Calls
that merely read retained metadata without refreshing or preparing the NFC
transport do not open the UI.

On every later slot-list refresh, USB reconciliation likewise runs before
registered slots are refreshed. Moving an NFC-discovered YubiKey to USB can
therefore rebind its serial-owned slots to USB before an absent NFC route has an
opportunity to request reacquisition UI.

While the verified card and its CryptoTokenKit session remain valid, refreshes
and operations reuse that session and do not create a new system UI. If the
wrong YubiKey is presented during reacquisition, the same UI asks for its
removal and then for the bound serial; it is not a new discovery or a new
PKCS #11 slot. Canceling reacquisition leaves the existing slots absent. A
later explicit refresh may request the bound serial again.

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
private keys in application source. The sample credentials in both smoke apps
are deliberately prototype-only.

## Example applications

Two checked-in UIKit applications use the same XCFramework and direct C ABI:

- [Swift iPhone smoke test](../examples/ios/PKCS11RSPhoneSmoke/README.md) and
  [Objective-C smoke test](../examples/ios/PKCS11RSObjCSmoke/README.md) provide
  synchronized functional coverage through their respective language bindings.
  Both cover USB CCID, NFC, persistent software-token initialization,
  X25519 key generation and timed self-agreement, ML-DSA-87 key generation and
  timed sign/verify, ML-KEM-1024 key generation and timed
  encapsulation/decapsulation, remote YubiHSM discovery, explicit YubiHSM Auth
  public-key matching and login, object inventory, debug Unified Logging, and
  long-lived application behavior. Each refresh validates a nonzero,
  session-only 32-byte X25519 secret, signs and verifies a fresh 32-byte value
  from `C_GenerateRandom`, then uses the PKCS #11 3.2 KEM entry points and
  compares
  their session-only 32-byte generic secrets through `CKA_VALUE`. The tests make
  these derived secrets extractable solely for validation and do not persist
  them. The first explicit refresh starts slot discovery in both apps so NFC UI
  is not presented automatically at launch.

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
