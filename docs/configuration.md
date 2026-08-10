# Initialization configuration

pkcs11rs accepts a versioned JSON configuration through
`CK_C_INITIALIZE_ARGS.pReserved`. The pointer is the direct JSON string
described below and uses the same PKCS #11 C ABI on iOS, macOS, Linux, and
Windows.

In the direct form, the value must be a NUL-terminated UTF-8 string whose
terminator occurs within the first 64 KiB. pkcs11rs reads the string only during
the call and does not retain the pointer. A nonempty value whose first
non-whitespace character is `{` is treated as pkcs11rs JSON: the object must
contain `"version": 1`, and invalid JSON, unknown fields, or an unsupported
version makes `C_Initialize` return `CKR_ARGUMENTS_BAD`. Invalid UTF-8 or a
missing terminator also returns `CKR_ARGUMENTS_BAD`.

A nonempty value whose first non-whitespace character is not `{` is accepted
as opaque provider initialization data and ignored. This preserves
compatibility with applications such as OpenSSL that place their own text in
`pReserved`; it is not interpreted as partial or permissive pkcs11rs
configuration. JSON-looking input always receives strict validation.

A null `pReserved`, an empty string, or a whitespace-only string means that no
explicit configuration was supplied. Each missing JSON field falls back to its
existing environment variable and then its built-in default. A supplied JSON
value takes precedence over the corresponding environment variable. Empty
arrays are therefore useful for explicitly disabling configured URL or
software-slot lists, while `false` explicitly disables a switch.

## Complete schema

This example shows one valid choice for every configuration group. SCP03 direct
keys and its batch master key are mutually exclusive, and SCP11 accepts either
a public key or CA certificate.

```json
{
  "version": 1,
  "logging": {
    "level": "info"
  },
  "pinentry": "pinentry-mac",
  "hardware": {
    "discovery": true
  },
  "storage": {
    "tokens": "/var/lib/pkcs11rs",
    "fido2_compatibility": "/var/lib/pkcs11rs-fido2"
  },
  "software": {
    "slots": [
      {
        "name": "build signing",
        "discovery_pin": "a sufficiently long discovery PIN"
      }
    ]
  },
  "yubihsm": {
    "urls": ["https://connector.example:12345"],
    "recreate_sessions": false,
    "public_discovery": "0001password",
    "device_trust_prefix": "/var/lib/pkcs11rs/trusted-yubihsm-",
    "tls": {
      "client_certificate_bundle": "/etc/pkcs11rs/client-chain.cbor",
      "client_private_key": "/etc/pkcs11rs/client-key.der",
      "ca_certificate_bundle": "/etc/pkcs11rs/connector-ca.cbor"
    }
  },
  "ccid": {
    "applications": ["piv", "openpgp", "hsmauth", "issuer-sd", "fido2"],
    "secure_channel": "scp11b",
    "aids": {
      "piv": "a000000308000010000100",
      "openpgp": "d27600012401",
      "hsmauth": "a0000005272101",
      "issuer_sd": "a000000151000000",
      "fido2": "a0000006472f0001"
    }
  },
  "nfc": {
    "discovery": false
  },
  "scp03": {
    "bmk": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "key_version": 1,
    "key_id": 0,
    "security_level": 51
  },
  "scp11": {
    "sd_public_key": "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "key_version": 1,
    "oce_private_key": "/etc/pkcs11rs/oce-key.der",
    "oce_certificate_bundle": "/etc/pkcs11rs/oce-chain.cbor",
    "oce_key_version": 0,
    "oce_key_id": 0
  }
}
```

For SCP03 direct keys, replace `bmk` with `enc_key`, `mac_key`, and optionally
`dek_key`. Hexadecimal byte fields are strings without a required `0x` prefix.
For SCP11 CA trust, replace `sd_public_key` with `sd_ca_certificate` containing
the certificate path.
Numeric byte fields are JSON integers from 0 through 255. `security_level` must
be a supported SCP03 security-level bit combination. The detailed SCP rules
remain documented in [SCP03 configuration](scp03.md), and SCP11 trust and OCE
rules in [SCP11 configuration](scp11.md).

`hardware.discovery` controls every local hardware discovery mechanism,
including direct YubiHSM USB, native FIDO HID, native PC/SC, and iOS
CryptoTokenKit. It does not affect explicitly configured
`yubihsm.urls`. `yubihsm.recreate_sessions` defaults to `false`; its security
and retry semantics are described in [YubiHSM authentication](yubihsm-auth.md).

On iOS, `nfc.discovery` opts into one NFC card request during the first
`C_GetSlotList` after initialization. It defaults to `false`. Successful
discovery registers stable, applet-specific tokens that remain logically
present for the module lifetime; later operations request the same physical
card again when needed. Cancellation or an unrecognized card is an isolated
discovery miss and does not fail slot listing or retry automatically.
After an operation, the NFC session remains idle until the card is removed,
the user cancels, or another operation reuses it. This field has no effect on
other platforms. Because PKCS #11 is synchronous, the first `C_GetSlotList`
blocks until the NFC request completes; applications must make that call away
from their main UI thread.

## Environment mapping

| JSON field | Environment fallback |
| --- | --- |
| `logging.level` | `PKCS11RS_LOG` |
| `pinentry` | `PKCS11RS_PINENTRY` |
| `hardware.discovery` | `PKCS11RS_HARDWARE_DISCOVERY` |
| `storage.tokens` | `PKCS11RS_TOKEN_STORAGE` |
| `storage.fido2_compatibility` | `PKCS11RS_FIDO2_STORAGE` |
| `software.slots` | `PKCS11RS_SOFTWARE_SLOTS` and each slot's `PKCS11RS_SOFTWARE_DISCOVERY_<HEXNAME>` |
| `yubihsm.urls` | `PKCS11RS_YUBIHSM_URLS` |
| `yubihsm.recreate_sessions` | `PKCS11RS_YUBIHSM_RECREATE_SESSIONS` |
| `yubihsm.public_discovery` | `PKCS11RS_YUBIHSM_DISCOVERY` |
| `yubihsm.device_trust_prefix` | `PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX` |
| `yubihsm.tls.client_certificate_bundle` | `PKCS11RS_YUBIHSM_TLS_CLIENT_CERTIFICATE_BUNDLE` |
| `yubihsm.tls.client_private_key` | `PKCS11RS_YUBIHSM_TLS_CLIENT_PRIVATE_KEY` |
| `yubihsm.tls.ca_certificate_bundle` | `PKCS11RS_YUBIHSM_TLS_CA_CERTIFICATE_BUNDLE` |
| `ccid.applications` | `PKCS11RS_CCID_APPLICATIONS` |
| `ccid.secure_channel` | `PKCS11RS_CCID_SECURE_CHANNEL` |
| `ccid.aids.piv` | `PKCS11RS_PIV_AID` |
| `ccid.aids.openpgp` | `PKCS11RS_OPENPGP_AID` |
| `ccid.aids.hsmauth` | `PKCS11RS_HSMAUTH_AID` |
| `ccid.aids.issuer_sd` | `PKCS11RS_ISSUER_SD_AID` |
| `ccid.aids.fido2` | `PKCS11RS_FIDO2_AID` |
| `nfc.discovery` | `PKCS11RS_NFC_DISCOVERY` |
| `scp03.bmk` | `PKCS11RS_SCP03_BMK` |
| `scp03.enc_key` | `PKCS11RS_SCP03_ENC_KEY` |
| `scp03.mac_key` | `PKCS11RS_SCP03_MAC_KEY` |
| `scp03.dek_key` | `PKCS11RS_SCP03_DEK_KEY` |
| `scp03.key_version` | `PKCS11RS_SCP03_KEY_VERSION` |
| `scp03.key_id` | `PKCS11RS_SCP03_KEY_ID` |
| `scp03.security_level` | `PKCS11RS_SCP03_SECURITY_LEVEL` |
| `scp11.sd_public_key` | `PKCS11RS_SCP11_SD_PUBLIC_KEY` |
| `scp11.sd_ca_certificate` | `PKCS11RS_SCP11_SD_CA_CERTIFICATE` |
| `scp11.key_version` | `PKCS11RS_SCP11_KEY_VERSION` |
| `scp11.oce_private_key` | `PKCS11RS_SCP11_OCE_PRIVATE_KEY` |
| `scp11.oce_certificate_bundle` | `PKCS11RS_SCP11_OCE_CERTIFICATE_BUNDLE` |
| `scp11.oce_key_version` | `PKCS11RS_SCP11_OCE_KEY_VERSION` |
| `scp11.oce_key_id` | `PKCS11RS_SCP11_OCE_KEY_ID` |

`software.slots` is intentionally structured rather than reproducing the
environment variable's dynamic names. Each entry carries its own optional
`discovery_pin`. An omitted pin still falls back to that slot's legacy dynamic
environment variable.

## Direct JSON C example

```c
static const char config[] =
    "{\"version\":1,\"hardware\":{\"discovery\":false},"
    "\"yubihsm\":{\"urls\":[\"https://connector.example:12345\"]}}";

CK_C_INITIALIZE_ARGS args = {0};
args.flags = CKF_OS_LOCKING_OK;
args.pReserved = (CK_VOID_PTR)config;

CK_RV rv = C_Initialize(&args);
```

The application owns `config` and only needs to keep it alive until
`C_Initialize` returns. Passing a null argument to `C_Initialize`, rather than
a `CK_C_INITIALIZE_ARGS` structure, continues to use environment variables and
defaults exactly as before.

When `hardware.discovery` is true, desktop builds enumerate CCID readers with
PC/SC and iOS builds use CryptoTokenKit. If it is false, native local hardware
discovery does not run.

## Diagnostics

`logging.level` and its `PKCS11RS_LOG` fallback accept `off`, `error`, `warn`,
`info`, `debug`, or `trace`. An explicit level installs a module-local
subscriber. It writes to Apple Unified Logging on iOS and standard error on
other platforms. If no level is configured, pkcs11rs installs no subscriber
and its events flow to an ambient `tracing` subscriber when the Rust host has
one.

On iOS the subsystem is `com.nilssoncrypto.pkcs11rs`, and each Rust tracing
target is used as the Unified Logging category. Rust `trace` and `debug` map to
Apple `debug`, `info` maps to `info`, `warn` maps to `default`, and `error` maps
to `error`; ordinary errors are not promoted to Apple `fault`. Unified Logging
already records timestamp, level, subsystem, and category, so the formatted
message does not repeat them. Diagnostic text is submitted as public data so
it remains useful in Console and Xcode.

The iOS emitter has no C compiler or host callback dependency. It calls the
system logging ABI directly from Rust and reproduces Clang's fixed
`%{public}s` argument encoding for `_os_log_impl`. That encoded-buffer entry
point is an Apple implementation ABI rather than a documented source API; the
encoding is deliberately confined to the iOS logging adapter.

Debug output explains discovery results and slot inventory: named readers and
devices, applet probes and outcomes, stable slot registration, presence and
deduplication decisions, and phase timing. Every exported PKCS #11 call emits
debug-level entry and return events with its duration and return value. Trace
adds API state diagnostics and per-request connector, CCID, APDU, PC/SC, USB,
and CTAP HID timing. Existing warnings and diagnostics use the corresponding
standard tracing levels. New events do not include PINs, key material,
plaintext, or raw APDU contents.
