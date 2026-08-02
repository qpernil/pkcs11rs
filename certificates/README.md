# Yubico public certificates

These public certificates are runtime trust anchors and test fixtures used by
the module. Individual certificates are stored as their canonical X.509 DER.
The published intermediate collection is stored in the project's canonical
CBOR certificate-bundle format. The directory contains no private keys or
device credentials.

## YubiKey

| File | Published source | File SHA-256 |
| --- | --- | --- |
| `yubikey/yubico-attestation-root-1.der` | https://developers.yubico.com/PKI/yubico-ca-1.pem | `62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8` |
| `yubikey/yubico-fido-ca-1.der` | https://developers.yubico.com/PKI/yubico-fido-ca-1.pem | `0fa1386f80eb8713263ae5c1d84deb455bdf08aea50ab05503cefee82b092d42` |
| `yubikey/yubico-fido-ca-2.der` | https://developers.yubico.com/PKI/yubico-fido-ca-2.pem | `35f1a54b353bfb711e6d42adbeb76c0e9dead095018e6a94783ba2192fd6faad` |
| `yubikey/yubico-piv-ca-1.der` | https://developers.yubico.com/PKI/yubico-piv-ca-1.pem | `63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546` |
| `yubikey/yubico-intermediate.cbor` | https://developers.yubico.com/PKI/yubico-intermediate.pem | `66adbf87a3538250f75d7ce640bb20455d340acabb81e3a84572ca6b8ceb20a1` |

Attestation Root 1 is embedded as the factory trust anchor for YubiKey SCP11b.
The current root, the two published FIDO roots, and the published
intermediates are used to classify verified FIDO packed attestations. The PIV
root is retained as a public reference fixture and used by certificate-chain
tests.

The current and legacy YubiKey root certificate SHA-256 fingerprints are:

```text
62:76:0C:6A:6E:F9:16:79:F4:54:C8:90:2B:80:FD:00:98:25:B3:F2:5D:A9:0F:1F:BA:CE:2E:C6:58:6C:D5:A8
63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46
```

## YubiHSM

`yubihsm/yubihsm2-attestation-root.der` and
`yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.der` are the YubiHSM 2
attestation root and intermediate downloaded from:

- <https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem>
- <https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem>

Their SHA-256 fingerprints are:

```text
09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24
D7:C6:D8:F4:52:08:E2:A5:39:96:FB:5A:8F:4D:63:1B:33:EB:AB:B6:49:56:B3:7B:2A:C1:51:FB:DB:AF:4A:E9
```

Both are embedded for
`PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation`, which validates a factory
device-public-key attestation before writing the local public-key pin.

Tests pin these fingerprints, validate current validity periods, and verify
every exact-DER issuer relationship in the published bundles.
