# PKCS11RS iOS CCID state tester

This dedicated, non-provisioning iPhone application validates the retained
CryptoTokenKit session and card-wide applet-login model. It configures only PIV and YubiHSM Auth;
it never selects OpenPGP and never creates, replaces, or deletes a key.

The tester needs one existing P-256 signing key with PIN policy `ONCE` in PIV
slot `9A`, `9D`, or a retired slot. It deliberately excludes `9C`/`ALWAYS` and
`9E`/`NEVER` so their policy semantics cannot mask the card-wide state being
tested. As an explicit diagnostic-only exception to the ordinary authentication
secret policy, the UI starts with Yubico's public factory-default PIV PIN
`123456` and leaves it in the secure text field for repeated operations until
the app terminates. The value is not persisted or logged, and production
pkcs11rs still receives it only during an explicit `C_Login` call and does not
cache it for later operations. Use this default only with a non-sensitive test
YubiKey: a device that still accepts the factory PIN must not hold sensitive PIV
data.

Build the current XCFramework first:

```sh
cargo xtask ios --release
open examples/ios/PKCS11RSCCIDStateTest/PKCS11RSCCIDStateTest.xcodeproj
```

Select the `PKCS11RSCCIDStateTest` scheme and a physical iPhone. The serial
field is optional, but using it makes the selected hardware explicit. Without
it, exactly one discovered YubiKey must expose both configured applets.

## USB retained-state test

Tap **Run USB retained-state test** with the test YubiKey connected over USB.
The test performs these PKCS #11 state assertions:

1. discover matching PIV and YubiHSM Auth slots;
2. log into PIV and sign;
3. call `C_GetSlotList` and sign again without another login;
4. force a live YubiHSM Auth credential-list refresh through its PKCS #11 slot;
5. verify that the old PIV session remains open but becomes public;
6. verify that signing reports `CKR_USER_NOT_LOGGED_IN`;
7. log into PIV again and sign successfully.

The run also creates a second `TKSmartCard` object. Its `beginSession`
must remain pending while pkcs11rs retains its CryptoTokenKit session, without
preventing another signature by the owner. After `C_Finalize`, the peer must
acquire the card and successfully select YubiHSM Auth.

## NFC removal and reacquisition

Select NFC and tap **Arm NFC removal test**. After the initial login and
signature succeed, remove the YubiKey from the NFC field and wait for iOS to
notice. Then tap **Resume NFC removal test** and present the same YubiKey. The
test verifies that stable
logical slots return but applet selection and login state do not survive the
new NFC transport session.

The app's NFC polling list includes the YubiKey Management AID used to bind a
physical serial before probing the explicitly configured PIV and YubiHSM Auth
applets. It does not include or probe OpenPGP.

Each button selects its required transport internally. USB tests disable NFC
discovery, and NFC tests disable ordinary USB hardware discovery. This prevents
the two transports from being mistaken for one another during the test.

## Two pkcs11rs processes

The **Prepare USB owner**, **Sign with USB owner**, and **Release USB owner**
buttons expose the three synchronization points needed by a separate process
containing another pkcs11rs instance. A second instance should start discovery
after `OWNER READY`, remain unable to acquire while the owner signs, and
discover the card after `OWNER RELEASED`. CryptoTokenKit may keep the second
probe waiting or let its short applet-discovery APDUs time out with no slots;
the test retries discovery after release in either case.

Two instances cannot be created inside this application process because the
static module has one global PKCS #11 state. On iOS, an XCUITest runner is a
suitable independent process for automating the USB case. It is intentionally
not used for NFC: the system NFC slot and UI belong to the foreground NFC
interaction, so removal and reacquisition are the meaningful external-state
boundary there.

The `PKCS11RSCCIDStateTestUITests` target implements that two-process USB
scenario. Preferably set the non-secret `PKCS11RS_TEST_YUBIKEY_SERIAL` in the
scheme's Test environment, then run `ExclusiveOwnershipTests` on the physical
iPhone. When the application appears, tap **Prepare USB owner**. The test
process deliberately never reads the app's prefilled PIN. It initializes its
own statically linked pkcs11rs instance, starts
discovery while the application retains its CryptoTokenKit session, verifies
that the second instance cannot acquire the card before the owner releases it,
and requires a fresh discovery to find the YubiHSM Auth slot afterward.
