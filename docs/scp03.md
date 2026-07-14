# SCP03 configuration

The PC/SC YubiKey path selects the Security Domain with AID
`A0 00 00 01 51 00 00 00` and establishes an SCP03 channel during
`C_Login`.

Static keys are supplied as hexadecimal environment variables:

- `PKCS11RS_SCP03_ENC_KEY` (required)
- `PKCS11RS_SCP03_MAC_KEY` (required)
- `PKCS11RS_SCP03_DEK_KEY` (optional; reserved for key management)
- `PKCS11RS_SCP03_KEY_VERSION` (optional decimal or `0x` byte, default `0`)
- `PKCS11RS_SCP03_KEY_ID` (optional decimal or `0x` byte, default `0`)
- `PKCS11RS_SCP03_SECURITY_LEVEL` (optional, default `0x03`)

The supplied ENC and MAC values must already be the card-specific static
keys; the ten-byte diversification data returned by `INITIALIZE UPDATE` is
not currently passed through a diversification scheme.

Supported security levels are `0x00`, `0x01`, `0x03`, `0x11`, `0x13`,
and `0x33`. AES-128, AES-192, and AES-256 static keys are accepted. Key
values are never included in debug output, and derived session keys are
zeroized when the PKCS #11 login ends.

This implementation currently supports SCP03 S8 mode. It validates the
card's `i` parameter, verifies pseudo-random card challenges using the
three-byte sequence counter and selected Security Domain AID, and rejects
R-MAC or response-encryption levels that the card does not advertise. S16
mode is rejected until its 16-byte challenge, cryptogram, and MAC framing is
implemented.

The APDU codec supports short and extended Case 2, 3, and 4 commands. It
automatically uses extended encoding when command data exceeds 255 bytes or
when SCP03 encryption, padding, and C-MAC increase the protected data beyond
that boundary. Extended responses use the PC/SC extended receive-buffer size.
