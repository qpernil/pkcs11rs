# PKCS11RS Objective-C smoke test

This UIKit application demonstrates direct integration with the statically
linked PKCS #11 C ABI from Objective-C. It imports the generated `PKCS11RS`
Clang module and implements the same configuration, slot ordering,
authentication flows, and functional smoke coverage as the
[Swift UIKit smoke app](../PKCS11RSPhoneSmoke/README.md). The only intentional
differences are the client language and its representation of C structures and
buffers, plus the app-scoped bundle and platform-credential identities that let
both signed apps remain installed and provisioned at the same time.

Both apps configure CryptoTokenKit NFC discovery, the local or overridden
YubiHSM connector, prototype YubiHSM public discovery, the Secure Enclave host
slot, and one persistent embedded CCID reader. The embedded reader has stable
configuration ID `iphone-smoke`, display name
`pkcs11rs embedded CCID reader`, serial `1`, and the PIV and FIDO2 applets.
Neither app configures a software slot.

The inventory opens a public session for every present slot and reports its
objects. It then retains a no-secret `C_Login(CKU_USER, NULL_PTR, 0)` session
for the Secure Enclave source slot. YubiHSM targets are processed with native
hardware session-key providers first, followed by the remaining targets. Each
target uses `C_LoginUser(CKU_USER, "pkcs11:", "password")`; successful
sessions remain open so an earlier authorized YubiHSM can supply a credential
to a later one. Retained sessions close in reverse dependency order.

Every login performed during Refresh has the same terse report format in both
apps: the PKCS #11 entry point, user type, selector when applicable, named
return value, and selected credential when available. Login secrets are
zeroized after each call.

Every slot receives the same six-entry post-quantum mechanism report:
`CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`,
`CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`,
`CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN`, and
`CKM_PKCS11RS_MLKEM768_X25519`. The report includes all mechanism flags,
`CKF_HW`, the key-size range, and whether the flags required by the smoke
operation are present.

The functional cases use persistent ML-DSA-87, ML-KEM-1024, and
`MLKEM768-X25519` keypairs. ML-DSA signs and verifies a fresh 32-byte random
message. Both KEM cases encapsulate and decapsulate, request 32-byte
nonsensitive extractable `CKK_GENERIC_SECRET` session objects, compare their
`CKA_VALUE` bytes, and destroy the session objects. The hybrid case is the
exact construction documented in
[Post-quantum hybrid key exchange](../../../docs/post-quantum-hybrid-key-exchange.md):
FIPS 203 ML-KEM-768 plus RFC 7748 X25519 with the X-Wing SHA3-256 combiner,
1216-byte public keys, 1120-byte ciphertexts, and 32-byte shared secrets.

Persistent identifiers match the Swift client: PIV IDs `5`, `6`, and `7`
for retired references `0x82`, `0x83`, and `0x84`; YubiHSM IDs `0x7e20`,
`0x7e21`, and `0x7e22`; and descriptive byte-string IDs for other
providers.

The embedded PIV flow performs public mechanism and object discovery, then
calls `C_Login(CKU_SO)` with the factory management key immediately before
provisioning any missing pairs. It always calls `C_Logout`, then
`C_Login(CKU_USER)` with factory PIN `123456`, performs signing and
decapsulation without a generation fallback, and lists the authenticated
objects. Both logins occur on every refresh even when all pairs already exist.

The embedded FIDO2 flow uses PIN `123456`. It creates or reuses the persisted
previewSign registration and ARKG-P256 derived-key wrapper, performs
`C_Login(CKU_CONTEXT_SPECIFIC)`, projects the public key, and verifies the
previewSign result with `CKM_ECDSA`. It also runs the advertised
post-quantum cases under the same user login.

The platform-credential button exercises the same idempotent lifecycle as the
Swift app: bootstrap login, provision or repair every present YubiHSM, logout,
fresh platform-backed login, and an authenticated random operation.
Unprovisioning removes only matching target objects and deletes the local key
only after all present targets succeed. Because iOS scopes Keychain items to
the signed application, the Objective-C app uses credential
`iphone-qpernil-objc` and Authentication Key `1005`; the Swift app uses
`iphone-qpernil` and `1004`.

The app initializes on a serial background queue and waits until the first
Refresh before calling `C_GetSlotList`, so NFC presentation and lifecycle
match the Swift app. The configuration requests debug logging under Apple
Unified Logging subsystem `com.nilssoncrypto.pkcs11rs`. An elapsed
`Working…` indicator remains visible while synchronous discovery or
authentication is running.

Build the shared XCFramework before opening the project:

```sh
cargo xtask ios --release
```

Open `PKCS11RSObjCSmoke.xcodeproj` and run the `PKCS11RSObjCSmoke` scheme.
The project links `target/ios/PKCS11RS.xcframework` statically and uses
automatic signing with development team `Q4X2Q59C2D` and bundle identifier
`com.nilssoncrypto.PKCS11RSObjCSmoke`. A command-line device build that may
need to create or refresh its automatic profile must pass
`-allowProvisioningUpdates`; add `-allowProvisioningDeviceRegistration` when
the target device may also need registration. Developers using another Apple
account should select their own team in Xcode.

See the [iOS integration guide](../../../docs/ios-integration.md) for the
shared integration model, lifecycle, NFC setup, and platform limitations.
