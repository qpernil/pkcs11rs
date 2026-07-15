# SCP11b configuration

Set `PKCS11RS_YUBIKEY_BACKEND=scp11` (or `scp11b`) to establish a
GlobalPlatform SCP11b secure channel for a PC/SC YubiKey. YubiKey SCP11 support
requires firmware 5.7.2 or later.

SCP11b authenticates the card to the host. This implementation requires the
expected P-256 Security Domain public key to be pinned using exactly one of:

- `PKCS11RS_SCP11_SD_PUBLIC_KEY`: the 65-byte uncompressed SEC1 public point,
  encoded as hexadecimal;
- `PKCS11RS_SCP11_SD_CERTIFICATE`: path to a PEM or DER X.509 certificate whose
  P-256 public key is the expected `CERT.SD.ECKA` key.

The certificate file is treated as pinned configuration. The implementation
does not fetch and implicitly trust an unverified certificate from the card.
Certificate-chain validation and provisioning remain the caller's
responsibility.

Optional configuration:

- `PKCS11RS_SCP11_KEY_VERSION`: decimal or `0x` key version, default `1`;
- `PKCS11RS_SCP11_AID`: hexadecimal target application AID, default
  `A0 00 00 03 08`.

The backend implements YubiKey's SCP11b profile: NIST P-256 ephemeral key
agreement, KID `0x13`, AES-128 session keys, and the mandatory `0x33` security
level with command and response encryption and MAC authentication. The card
receipt is verified before the channel becomes active. Subsequent APDUs use the
same short, extended, command-chaining, response-chaining, counter, padding,
and MAC handling as the SCP03 backend.
