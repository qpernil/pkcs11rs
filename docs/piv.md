# YubiKey PIV client

The default PC/SC YubiKey backend is `piv`. Set
`PKCS11RS_YUBIKEY_BACKEND=scp03` or `PKCS11RS_YUBIKEY_BACKEND=scp11` to use the
secure-channel backends documented in `docs/scp03.md` and `docs/scp11.md`.

The PIV client selects application AID `A0 00 00 03 08` and reads the firmware
version and serial number from the applet. PKCS #11 `C_Login` verifies the PIV
PIN. PINs must contain six to eight bytes and are padded to the eight-byte PIV
APDU field with `FF`. `C_Logout` reselects the application to clear card
authentication state.

The protocol layer implements:

- strict short and extended ISO 7816 APDU encoding;
- 255-byte command chaining for large PIV requests;
- `6Cxx` expected-length retries and `61xx` response chaining;
- canonical BER-TLV parsing with bounded object responses;
- PIN verification and retry queries;
- Yubico version, serial, and key metadata commands;
- PIV `GET DATA` certificate retrieval;
- `GENERAL AUTHENTICATE` signing, RSA deciphering, and EC/X25519 key agreement.

The client supports standard slots `9A`, `9C`, `9D`, and `9E`, RSA-1024 through
RSA-4096, P-256, P-384, Ed25519, and X25519 protocol identifiers. Firmware and
FIPS restrictions still apply.

RSA certificates in the four standard slots are exposed as PKCS #11 public and
private key objects. Public modulus and exponent attributes come from the X.509
certificate. `CKM_RSA_PKCS` signing uses a hardware-backed key representation:
the host creates the type-1 PKCS #1 v1.5 encoded block and the YubiKey performs
the private RSA operation. The private key is never represented as host key
material.

EC/25519 PKCS #11 objects and card-backed decrypt/derive entry points are not
yet exposed. Their PIV protocol operations are implemented, but the PKCS #11
object model still needs EC attributes and operation-state variants for them.
