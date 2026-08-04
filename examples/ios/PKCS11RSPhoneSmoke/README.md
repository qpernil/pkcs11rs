# PKCS11RS iPhone smoke test

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

This small UIKit application links the generated `PKCS11RS.xcframework`,
passes a versioned JSON configuration through
`CK_C_INITIALIZE_ARGS.pReserved`, and displays the module, slot, and token
metadata returned by PKCS #11.

Build the XCFramework before opening the Xcode project:

```sh
cargo xtask ios --release
```

Configure the app with your connector's URL using the
`PKCS11RS_YUBIHSM_URLS` launch environment variable or change
`fallbackConnectorURL` in `PKCS11RSPhoneSmoke/App.swift`. The environment
variable is only an input to this smoke-test UI; the module itself receives the
URL through the JSON passed to `C_Initialize`.

Select a development team in Xcode before installing the app on a physical
iPhone.
