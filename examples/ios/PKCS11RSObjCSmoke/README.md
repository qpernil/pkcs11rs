# PKCS11RS Objective-C smoke test

This small UIKit application demonstrates direct integration with the
statically linked PKCS #11 C ABI from Objective-C. It imports the generated
`PKCS11RS` Clang module, initializes pkcs11rs with direct JSON configuration,
reports `CK_INFO`, and lists every present slot, token, and public object.
Its functional smoke coverage is synchronized with the Swift UIKit app; the
difference is the client language and its direct Objective-C representation of
the same C structures, buffers, sessions, and lifecycle.

The inventory also exercises YubiHSM Auth authentication. It discovers the
credential metadata and public key through ordinary PKCS #11 objects, compares
the credential's `CKA_EC_POINT` with the public objects exposed on each YubiHSM
slot, and accepts only an unambiguous match whose `CKA_ID` is two bytes. That ID
is used in the explicit `C_LoginUser` selector `:<id><label>@<source>` with the
prototype credential password `password`. A successful login produces a
second authenticated object inventory before the app logs out. A missing or
ambiguous public-key match is reported and skips login rather than invoking
hidden backend selection.

All synchronous PKCS #11 work runs on one serial background queue. The example
uses the same initialization configuration as the Swift UIKit smoke app:
CryptoTokenKit NFC discovery, the local or overridden YubiHSM connector,
prototype public discovery, and the persistent `iPhone smoke` software token
below Application Support. The software slot produces useful output in the
Simulator even though the Simulator has no USB CCID or NFC reader.

The app recognizes exactly that owned software slot by its `Software token`
model and `iPhone smoke` label. It initializes the token and user PIN when
their standard flags require it, logs in with the prototype PIN `password`,
and creates one persistent ML-DSA-87 keypair with ID
`iphone-smoke-ml-dsa-87` when absent. It reports the generation time, then
generates a fresh 32-byte message with `C_GenerateRandom`, signs it, and
verifies it on every refresh while reporting both operation times. Later
refreshes and launches reuse the keypair. These state-changing calls are never
applied to discovered hardware.

Generation timing surrounds the complete `C_GenerateKeyPair` call, including
encrypted persistence. `C_GenerateRandom` runs outside the sign timer. Signing
includes `C_SignInit`, the signature-length query, and the output-producing
`C_Sign`; verification includes `C_VerifyInit` and `C_Verify`, and is considered
successful only when `C_Verify` returns `CKR_OK`.

The `public_discovery` prototype credential is required for the matching flow:
it lets pkcs11rs expose the public companion objects on a YubiHSM before the
ordinary PKCS #11 user login. It does not perform the cross-slot match; the
Objective-C client does that explicitly with standard object and login APIs.
Do not ship or commit a production discovery credential in application source.

The configuration requests `debug` logging. pkcs11rs writes discovery, object,
matching-related PKCS #11 calls, and `C_LoginUser` outcomes to Apple Unified
Logging under subsystem `com.nilssoncrypto.pkcs11rs`; Rust tracing targets are
the log categories. View these records in Xcode's console or the macOS Console
app with the device selected. The app's text report separately displays the
selected credential, match count, Authentication Key ID, login result, and
authenticated inventory.

The app initializes and displays module information at launch without listing
slots. The first tap on **Refresh** calls `C_GetSlotList` and presents Apple's
NFC UI, matching the Swift app's lifecycle. An elapsed `Working…` indicator
continues updating while synchronous discovery or authentication is in
progress.

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
