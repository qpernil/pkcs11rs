# SCP11a iPhone smoke test

Both iOS smoke apps default to factory SCP11b. Their ordinary Issuer SD
`C_Login` also supports SCP11a when the protocol and client credential URI are
supplied through configuration. No app provisioning code or additional GUI is
required. See [SCP11 configuration](scp11.md) for the protocol and trust model.

The launch instructions below use the qualified Swift app. The Objective-C
app accepts the same environment variables, with its own bundle identifier,
host key, matching certificate, and app-container CA path.

SCP11a is qualified with Nano **37070618**, firmware **5.7.4**, and the iPhone's
existing **`iphone-qpernil` Secure Enclave credential**. Qualification includes
three fresh Mac handshakes with protected Issuer SD reads and the Swift iPhone
USB-C login with that credential.

## Prerequisites

| Component | Qualification configuration |
| --- | --- |
| Card SCP11a private key and certificate chain | KID `0x11`, KVN `1` |
| Card's trusted OCE CA public key | KID `0x10`, KVN `1` |
| Administrative recovery | Independently verified SCP03 key set, KVN `0x42` |
| Host key | Existing P-256 Secure Enclave key named `iphone-qpernil` |
| Host certificate | Matching OCE X.509 leaf in the Swift app's Keychain access group |
| Card trust | Public lab CA certificate, `root.der`, accessible in the app's data container |

The lab CA directly signs the card and host leaves, so this setup requires no
intermediate bundle. For other hierarchies, configure the separate card and OCE
intermediate bundles as described in [SCP11 configuration](scp11.md).

Nano 37070618 retains SCP03 recovery alongside SCP11a and the OCE CA. Its factory
SCP11b credential is absent to accommodate the physical credential budget.
The host private key remains in the Secure Enclave. Its certificate is public;
installing it does not install an Apple system trust root. Keychain visibility
follows the signed app's entitlements, so a different smoke-app bundle needs
its own key and matching certificate.

## Run with the provisioned Nano

Build the shared framework and signed Swift app using the
[iOS integration workflow](ios-integration.md):

```sh
cargo xtask ios --release
```

Open `examples/ios/PKCS11RSPhoneSmoke/PKCS11RSPhoneSmoke.xcodeproj` to build and
install the app. Keep the iPhone unlocked and connect Nano 37070618 by USB-C.

Copy the public lab root into the installed app's data container:

```sh
xcrun devicectl device copy to --device YOUR_IPHONE_UDID \
  --source /private/path/to/lab-state/root.der \
  --destination Documents/scp11a-root.der \
  --domain-type appDataContainer \
  --domain-identifier com.qpernil.PKCS11RSSmoke \
  --json-output /tmp/scp11a-root-copy.json
```

Use the absolute path returned in `result.file.name` as the CA setting below.
An app reinstall can change its data-container UUID, so obtain the current
path after installation. An obsolete path fails configuration loading with
`CKR_ARGUMENTS_BAD`.

In Xcode, select the scheme's **Run → Arguments → Environment Variables** and
set:

| Variable | Value |
| --- | --- |
| `PKCS11RS_CCID_SECURE_CHANNEL` | `scp11a` |
| `PKCS11RS_CCID_CLIENT_URI` | `pkcs11:` |
| `PKCS11RS_SCP11_SD_CA_CERTIFICATE` | Current absolute path to `Documents/scp11a-root.der` |
| `PKCS11RS_SCP11_KEY_VERSION` | `1` |
| `PKCS11RS_SCP11_OCE_KEY_ID` | `0x10` |
| `PKCS11RS_SCP11_OCE_KEY_VERSION` | `1` |
| `PKCS11RS_SLOTS_SERIALS` | `37070618` |
| `PKCS11RS_CCID_APPLICATIONS` | `issuer-sd` |

The serial and applet filters confine this test to the Nano's Issuer SD. The
host slot remains available independently of physical-card serial filters.
Run the app through Xcode, or use the equivalent terminal launch, replacing
the device identifier and CA path:

```sh
xcrun devicectl device process launch --device YOUR_IPHONE_UDID \
  --terminate-existing \
  --environment-variables '{
    "PKCS11RS_CCID_SECURE_CHANNEL":"scp11a",
    "PKCS11RS_CCID_CLIENT_URI":"pkcs11:",
    "PKCS11RS_SCP11_SD_CA_CERTIFICATE":"/absolute/path/in/app/container/Documents/scp11a-root.der",
    "PKCS11RS_SCP11_KEY_VERSION":"1",
    "PKCS11RS_SCP11_OCE_KEY_ID":"0x10",
    "PKCS11RS_SCP11_OCE_KEY_VERSION":"1",
    "PKCS11RS_SLOTS_SERIALS":"37070618",
    "PKCS11RS_CCID_APPLICATIONS":"issuer-sd"
  }' \
  com.qpernil.PKCS11RSSmoke
```

These settings apply to that launch; the app does not persist them.

Tap **Refresh** and check:

1. The host slot exposes the `iphone-qpernil` certificate and public key, and
   its `C_Login(CKU_USER)` succeeds. The authenticated inventory includes its
   private key projection.
2. Issuer SD `C_Login(CKU_USER)` reports `CKR_OK`.
3. Issuer SD reports secure channel **`scp11a`** and an authenticated credential
   URI identifying **`iphone-qpernil`**.

The app authorizes the host before the Issuer SD login. The unrestricted
`pkcs11:` selector prefers eligible host hardware credentials over ordinary
hardware credentials, and excludes the target card and its applets. Source
authorization and a matching OCE certificate are both required. Public
discovery does not establish SCP, and the target login does not log in to a
source PIV or OpenPGP applet automatically.

## External provisioning for a new lab card or host certificate

Use [scp11a-smoke.py](../tools/scp11a-smoke.py) with `yubikey-manager` and
`cryptography` installed. Keep its private state directory outside the
checkout, with mode `0700`; it contains the CA private key and saved SCP03
recovery keys. Preserve this state for administrative recovery and certificate
issuance. The helper refuses protected serial 10462967.

Provision only a designated lab card whose factory inventory may be replaced:

```sh
python tools/scp11a-smoke.py --state-dir /private/path/to/lab-state \
  provision --serial YOUR_LAB_CARD_SERIAL --replace-factory-scp11b
```

The command saves and independently verifies a custom SCP03 recovery set before
removing factory SCP11b. It generates the card's SCP11a key on the card, stores
its certificate chain, installs the trusted OCE CA, and verifies recovery
again. The explicit replacement flag accommodates the shared credential budget.
Restoring factory SCP11b requires an Issuer SD reset. Other applet credentials
are not part of this provisioning operation.

To certify the existing app host key, attach LLDB to the unlocked, running app
and pause it after its libraries have loaded. Import the external
[Keychain helper](../tools/scp11a_keychain.py) and export the public point:

```text
command script import /absolute/path/to/pkcs11rs/tools/scp11a_keychain.py
scp11a-export iphone-qpernil /tmp/host-public.sec1
```

Issue the OCE certificate on the Mac with the same lab CA used for the card:

```sh
python tools/scp11a-smoke.py --state-dir /private/path/to/lab-state \
  issue-host --public-key /tmp/host-public.sec1 --certificate /tmp/host.der
```

Install the certificate through LLDB and resume the app:

```text
scp11a-install iphone-qpernil /tmp/host.der
continue
```

The helper verifies that the certificate matches the existing key and installs
only that public certificate in the app's Keychain access group. It neither
creates a host key nor changes system trust. The lab certificates are valid for
one year; reissue expired certificates using the retained CA.

## Factory SCP11b scenario and failure diagnosis

Terminate the app, clear the SCP11a launch overrides, and launch normally with
a factory-provisioned SCP11b-capable YubiKey. Ensure any retained serial filter
selects that key. The default ordinary Issuer SD login establishes SCP11b using
the embedded Yubico root and published intermediates. Leave the client URI unset:
SCP11b does not authenticate a host credential.

Nano 37070618 cannot run that factory scenario with its present SCP11a-only card
identity; use another factory card or deliberately reset and reprovision its
Issuer SD. Changing the app's protocol does not change card provisioning.

An SCP11a login against a factory SCP11b-only card returns
`CKR_KEY_HANDLE_INVALID` when the requested `0x11/01` card certificate is absent.
The log identifies the SCP11 variant, KID, and KVN. There is no automatic
fallback to SCP11b. A missing source credential also returns
`CKR_KEY_HANDLE_INVALID`; inspect the host inventory and login first to distinguish
the source lookup from a missing card certificate. An unreadable CA file or a
malformed/untrusted certificate chain remains a separate validation failure.
