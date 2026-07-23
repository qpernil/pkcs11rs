# Yubico public certificates

These unmodified public certificates are test fixtures and trust anchors used
by the module.

## YubiKey

| File | Published source | File SHA-256 |
| --- | --- | --- |
| `yubikey/yubico-attestation-root-1.pem` | https://developers.yubico.com/PKI/yubico-ca-1.pem | `9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887` |
| `yubikey/yubico-piv-ca-1.pem` | https://developers.yubico.com/PKI/yubico-piv-ca-1.pem | `6234f33d5f652109d265b391f2898b8ba92f62df406b684db18363f50d7c9129` |
| `yubikey/yubico-intermediate.pem` | https://developers.yubico.com/PKI/yubico-intermediate.pem | `ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1` |

The current and legacy YubiKey root certificate SHA-256 fingerprints are:

```text
62:76:0C:6A:6E:F9:16:79:F4:54:C8:90:2B:80:FD:00:98:25:B3:F2:5D:A9:0F:1F:BA:CE:2E:C6:58:6C:D5:A8
63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46
```

## YubiHSM

`yubihsm/yubihsm2-attestation-root.pem` and
`yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem` are the YubiHSM 2
attestation root and intermediate downloaded from:

- <https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem>
- <https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem>

Their SHA-256 fingerprints are:

```text
09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24
D7:C6:D8:F4:52:08:E2:A5:39:96:FB:5A:8F:4D:63:1B:33:EB:AB:B6:49:56:B3:7B:2A:C1:51:FB:DB:AF:4A:E9
```

Tests pin these fingerprints, validate current validity periods, and verify
every exact-DER issuer relationship in the published bundles.
