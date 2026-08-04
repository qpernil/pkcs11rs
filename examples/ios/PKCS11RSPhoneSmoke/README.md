# PKCS11RS iPhone smoke test

This small UIKit application links the generated `PKCS11RS.xcframework`,
passes a versioned JSON configuration through
`CK_C_INITIALIZE_ARGS.pReserved`, and displays the module, slot, and token
metadata returned by PKCS #11.

Build the XCFramework before opening the Xcode project:

```sh
cargo xtask ios --release
```

The app defaults to `http://192.168.1.169:12345`. Override that URL with the
`PKCS11RS_YUBIHSM_URLS` launch environment variable or change
`fallbackConnectorURL` in `PKCS11RSPhoneSmoke/App.swift`. The environment
variable is only an input to this smoke-test UI; the module itself receives the
URL through the JSON passed to `C_Initialize`.

Select a development team in Xcode before installing the app on a physical
iPhone.
