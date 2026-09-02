# PKCS11RS Objective-C smoke test

This small UIKit application demonstrates direct integration with the
statically linked PKCS #11 C ABI from Objective-C. It imports the generated
`PKCS11RS` Clang module, initializes pkcs11rs with direct JSON configuration,
reports `CK_INFO`, and lists every present slot, token, and public object.
Its functional smoke coverage is synchronized with the Swift UIKit app; the
difference is the client language and its direct Objective-C representation of
the same C structures, buffers, sessions, and lifecycle.

The inventory also exercises automatic YubiHSM authentication. It calls
`C_LoginUser` with the provider-independent wildcard selector `:*` and the
prototype YubiHSM Auth credential password `password` for each YubiHSM.
pkcs11rs prefers a matching credential from an attached YubiKey and falls back
to a matching platform credential, for which the supplied password is ignored.
A successful login produces a second authenticated object inventory before the
app logs out.

The platform-credential button exercises the same idempotent high-level
PKCS11RS lifecycle API as the Swift app. **Provision platform credential** uses
the connected YubiHSM Auth administrator credential for bootstrap login,
provisions every present YubiHSM, and verifies a fresh Secure Enclave-backed
login and authenticated random operation. When the local credential exists,
the button changes to **Unprovision platform credential**; that action removes
only target objects proven to match and deletes the local key only after every
present target succeeds. Conflicts are neither overwritten nor deleted.
Because iOS scopes Keychain items to the signed application, this app uses its
own `iphone-qpernil-objc` credential and Authentication Key `1005`; the Swift
app independently uses `iphone-qpernil` and `1004`. Both can therefore remain
provisioned at the same time.

All synchronous PKCS #11 work runs on one serial background queue. The example
uses the same initialization configuration as the Swift UIKit smoke app:
CryptoTokenKit NFC discovery, the local or overridden YubiHSM connector,
prototype public discovery, and the persistent `iPhone smoke` software token
below Application Support. The software slot produces useful output in the
Simulator even though the Simulator has no USB CCID or NFC reader.

The app recognizes exactly that owned software slot by its `Software token`
model and `iPhone smoke` label. It initializes the token and user PIN when
their standard flags require it, logs in with the prototype PIN `password`,
and creates persistent X25519, ML-DSA-87, and ML-KEM-1024 keypairs with IDs
`iphone-smoke-x25519`, `iphone-smoke-ml-dsa-87`, and
`iphone-smoke-ml-kem-1024` when absent. It reports each generation time. On
every refresh it times an X25519 self-agreement using the pair's own public
point, validates that the resulting shared secret is 32 bytes and nonzero, and
destroys that session object. This is a compact smoke
benchmark rather than a two-party protocol. It then generates a fresh 32-byte
message with `C_GenerateRandom`, signs it, and
verifies it while reporting both operation times. It also uses the PKCS #11 3.2
`C_EncapsulateKey` and `C_DecapsulateKey` entry points, verifies that their two
32-byte shared secrets match, and reports both operation times and the
ciphertext length. Later refreshes and launches reuse all three persistent
keypairs. These state-changing calls are never applied to discovered hardware.

Each generation timing surrounds the complete `C_GenerateKeyPair` call,
including encrypted persistence. X25519 timing surrounds only `C_DeriveKey`;
the public-point read and shared-secret validation remain outside it.
`C_GenerateRandom` runs outside the sign timer. Signing includes `C_SignInit`,
the signature-length query, and the output-producing `C_Sign`; verification
includes `C_VerifyInit` and `C_Verify`. ML-KEM encapsulation timing includes its
ciphertext-length query and the output-producing `C_EncapsulateKey`;
decapsulation timing surrounds `C_DecapsulateKey`. The shared-secret reads and
comparison occur after the timers. The X25519 output template and both ML-KEM
output templates request a 32-byte `CKK_GENERIC_SECRET` with `CKA_TOKEN` false,
`CKA_SENSITIVE` false, and `CKA_EXTRACTABLE` true so the app can validate
`CKA_VALUE`. These are session objects: successful checks destroy them
explicitly, and closing the session cleans them up on an earlier failure. Only
the three keypairs are persisted.

The `public_discovery` prototype credential is required for wildcard matching:
it lets pkcs11rs expose the public companion objects on a YubiHSM before the
ordinary PKCS #11 user login. The Objective-C client itself does not implement
credential-to-HSM matching.
Do not ship or commit a production discovery credential in application source.

The configuration requests `debug` logging. pkcs11rs writes discovery, object,
matching-related PKCS #11 calls, and `C_LoginUser` outcomes to Apple Unified
Logging under subsystem `com.nilssoncrypto.pkcs11rs`; Rust tracing targets are
the log categories. View these records in Xcode's console or the macOS Console
app with the device selected. The app's text report displays the credentials,
login result, and authenticated inventory.

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
