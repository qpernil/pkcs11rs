# Choosing pkcs11rs components

Choose components according to the application or device behavior you want to
use or test. To exercise YubiHSM workflows without owning an HSM or setting up
a Raspberry Pi, start with the connector's embedded virtual YubiHSM. To use
existing software that discovers a USB device, choose a physical device or a
virtual USB worker. For general software PKCS #11 cryptography, configure a
named software slot.

The [architecture overview](architecture.md#project-ecosystem) shows the
components and their connections. This guide explains when each is useful;
the linked references contain configuration and qualification details.

## Device and software choices

| Component | Useful when | Purpose and next step |
| --- | --- | --- |
| Physical YubiKey or FIDO authenticator | You need the physical token's key protection, user interaction, or actual firmware behavior. | Use supported applets through pkcs11rs or native clients. See [CCID applets](ccid.md) and [FIDO2](fido2.md). |
| Physical YubiHSM | You need keys protected by a physical HSM or want to qualify actual device behavior. | Access it directly over USB or through a connector. See [YubiHSM support](yubihsm-auth.md). |
| Named software slots | Your application needs PKCS #11 keys and operations without device protocols. | General-purpose software tokens with session objects and optional encrypted persistence. See [software slots](software.md). |
| Embedded virtual YubiKey | You want to exercise pkcs11rs's YubiKey applet workflows without a USB device. | An in-process reader emulates the applets and their state. See [embedded readers](configuration.md#embedded-virtual-yubikey-readers). |
| Virtual YubiKey USB worker | You want an OS-visible YubiKey-compatible device for external clients or USB integration tests. | Runs the virtual core behind CCID and FIDO HID on a Linux USB device controller. See [virtual-yubikey](https://github.com/qpernil/virtual-yubikey). |
| Connector-embedded virtual YubiHSM | You want to test YubiHSM workflows without an HSM or Raspberry Pi, including through existing connector clients. | The connector hosts the virtual core and persistent state. See [embedded HSM setup](connector.md#embedded-virtual-yubihsms). |
| Virtual YubiHSM USB worker | Your client needs USB, or you want to test discovery, framing, and disconnect/reconnect. | Runs the same virtual core as a host-visible USB HSM, accessed directly or through a connector. See [virtual-yubihsm](https://github.com/qpernil/virtual-yubihsm). |
| Experimental virtual YubiHSM I2C frontend | You are testing the I2C request/response transport. | Uses the virtual core through an explicitly configured I2C endpoint. See [I2C HSMs](connector.md#experimental-i2c-yubihsms). |

The embedded and USB virtual YubiHSMs share the device core and persistent
runtime. Their main difference is the transport and process containing the
device. A virtual device exercises the implemented compatibility surface;
its software-held keys do not acquire physical hardware protection. The
[YubiHSM deployment comparison](connector.md#choosing-a-yubihsm-deployment)
explains these choices in more detail.

## Access and administration

| Component | Useful when | Purpose and next step |
| --- | --- | --- |
| `pkcs11rs` provider | Your application or library understands PKCS #11. | Presents supported devices, applets, platform keys, and software tokens through one C ABI. See [initialization](configuration.md). |
| `pkcs11rs-connector` | A client needs network access to an HSM, or you want to host virtual HSMs without USB hardware. | HTTP(S) access to physical or virtual USB HSMs, optional I2C endpoints, and embedded virtual HSMs. One connector can serve several devices. See [connector deployment](connector.md#deployment-boundary). |
| Platform credentials and Secure Enclave or TPM key stores | You want a protected local private key for YubiHSM login, SCP11a/c host authentication, or supported ECDH operations. | `platform-credential` uses Apple Security (SecKey) and Windows CNG; Linux ESAPI is planned. See [platform credentials](platform.md). |
| YubiHSM Auth applet and `yubihsm-auth-client` | You want an HSM Auth credential to establish a YubiHSM session. | The client package implements the applet protocol; pkcs11rs owns discovery, source selection, and transport. See [HSM Auth discovery and execution](yubihsm-auth.md#hsm-auth-slot-discovery-and-execution). |
| `pkcs11rs-tool` | You need to author or validate certificate bundles or manage platform credentials. | Provides supported administration commands. See [authoring and credential management](pkcs11rs-tool.md). |
| iOS XCFramework and example apps | You are integrating PKCS #11 into Swift or Objective-C. | The examples exercise native readers, remote HSMs, software operations, and platform credentials. See [iOS integration](ios-integration.md). |

For example, a YubiKey can hold the HSM Auth credential used to log in to a
separate YubiHSM. A platform-protected key can serve the same authentication
role through the supported key provider. The target HSM may be local, behind
a connector, or virtual; see
[authentication sources](yubihsm-auth.md#generic-source-selection-and-authorization).

A platform credential can also authenticate to a card through SCP11a/c when
its authorized source exposes the matching OCE certificate and the card trusts
the issuer. See [dynamic OCE credentials](scp11.md#dynamic-oce-credentials).

## Shared implementation and USB deployment

Applications normally use these components through the provider, connector,
or device worker.

| Component | Useful when | Purpose and next step |
| --- | --- | --- |
| `software-key-core` | Providers and virtual devices need the same software key operations and durable-state helpers. | Shares cryptographic implementations while consumers retain their protocol and authorization policy. See [software-key-core](https://github.com/qpernil/software-key-core). |
| `pkcs11rs-local-hardware` | The provider and connector need consistent native YubiHSM USB behavior. | Shares blocking and asynchronous frontends over the same device implementation. See [connector architecture](architecture.md#companion-multi-device-connector). |
| `usb-gadget-supervisor` and `usb-gadget-worker` | You are running a virtual USB worker on Linux. | Separate privileged USB setup and resource lifecycle from protocol traffic and state. Embedded devices do not need them. See [supervisor architecture](https://github.com/qpernil/usb-gadget-supervisor/blob/main/docs/architecture.md). |
| Upstream [RustCrypto/signatures](https://github.com/RustCrypto/signatures) | The software providers need the ML-DSA implementation. | A cryptographic dependency, not an additional service. See [software-key-core dependencies](https://github.com/qpernil/software-key-core/blob/main/Cargo.toml). |

## Existing clients and validation

An emulator lets existing software interact with a compatible device, beyond
testing pkcs11rs itself. Select the deployment that provides the interface
that software expects.

| Client or validation component | Useful when | Interface and scope |
| --- | --- | --- |
| `yubihsm-shell` and other connector clients | You want to explore or test YubiHSM commands without writing a new client. | Point the client at a connector serving an embedded, physical USB, or virtual USB HSM. |
| Yubico Authenticator, `ykman`, and `yubico-piv-tool` | You want to test existing YubiKey software against the virtual USB device. | Use a host-visible USB worker for implemented applet workflows. The virtual YubiKey does not implement OATH or Yubico OTP. Its embedded reader is private to pkcs11rs and is not an OS-visible USB device. |
| GnuPG and FIDO clients | You want to test OpenPGP or authenticator protocol interoperability. | Use the virtual USB worker's supported OpenPGP or FIDO interfaces. |
| [pkcs11-tester](https://github.com/qpernil/pkcs11-tester) | You want a .NET development client for a PKCS #11 module. | Inspect module/slot metadata and exercise configured authentication, objects, and operations. |
| [pkcs11test](https://github.com/qpernil/pkcs11test) | You want an external PKCS #11 API test suite. | Exercises module, slot, session, object, and cryptographic contracts on a selected test token. |
| [libusb-tester](https://github.com/qpernil/libusb-tester) | You are developing USB, HTTP-bridge, or PKCS #11 experiments. | Contains separate .NET clients and interop components with explicit source configuration. |
| Integration and conformance suites | You want reproducible production-module interoperability and profile checks. | See [external client integration](../integration/README.md) and [OASIS profile validation](../conformance/README.md). |
| `xtask` and CI | You are maintaining build artifacts or checking changes across supported targets. | Build support and automated validation; see [build workflows](../README.md#build) and [testing](../README.md#testing). |
