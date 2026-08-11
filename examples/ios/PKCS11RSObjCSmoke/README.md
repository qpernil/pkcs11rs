# PKCS11RS Objective-C smoke test

This small UIKit application demonstrates the minimum integration needed to
call the statically linked PKCS #11 C ABI from Objective-C. It imports the
generated `PKCS11RS` Clang module, initializes pkcs11rs with direct JSON
configuration, reports `CK_INFO`, and lists every present slot and token.

All synchronous PKCS #11 work runs on one serial background queue. The example
uses the same initialization configuration as the Swift UIKit smoke app:
CryptoTokenKit NFC discovery, the local or overridden YubiHSM connector,
prototype public discovery, and the persistent `iPhone smoke` software token
below Application Support. The software slot produces useful output in the
Simulator even though the Simulator has no USB CCID or NFC reader.

The app initializes and displays module information at launch without listing
slots. The first tap on **Refresh** calls `C_GetSlotList` and presents Apple's
NFC UI, matching the Swift app's lifecycle.

Build the XCFramework before opening the Xcode project:

```sh
cargo xtask ios --release
```

Open `PKCS11RSObjCSmoke.xcodeproj` and run the `PKCS11RSObjCSmoke` scheme. The
project contains the maintainer's development team for automatic device
signing; select a different team when building under another Apple developer
account. The project references `target/ios/PKCS11RS.xcframework` and links it
as a static library; it does not embed a dynamic framework.

See the [iOS integration guide](../../../docs/ios-integration.md) for the shared
Swift and Objective-C integration model, configuration, lifecycle, NFC setup,
and platform limitations.
