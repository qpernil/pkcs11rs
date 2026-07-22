# Embedded Yubico trust anchors

The certificates in this directory are public trust anchors used only by the
explicit Yubico factory-validation paths.

## YubiKey

`yubikey/yubico-attestation-root-1.pem` is Yubico Attestation Root 1, downloaded
from <https://developers.yubico.com/PKI/yubico-ca-1.pem>. Its SHA-256
fingerprint is:

```text
62:76:0C:6A:6E:F9:16:79:F4:54:C8:90:2B:80:FD:00:98:25:B3:F2:5D:A9:0F:1F:BA:CE:2E:C6:58:6C:D5:A8
```

## YubiHSM

`yubihsm/yubihsm2-attestation-root.pem` and
`yubihsm/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem` are the YubiHSM 2
attestation root and intermediate downloaded from:

- <https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem>
- <https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem>

Their SHA-256 fingerprints are, respectively:

```text
09:4A:3A:C4:93:C2:BD:CD:65:A5:4B:DF:40:19:0F:52:BB:03:F7:15:63:97:A3:FC:69:D8:AA:9A:39:2F:B7:24
D7:C6:D8:F4:52:08:E2:A5:39:96:FB:5A:8F:4D:63:1B:33:EB:AB:B6:49:56:B3:7B:2A:C1:51:FB:DB:AF:4A:E9
```
