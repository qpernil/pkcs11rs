# YubiKey PIV client

Common CCID applet discovery, allowlist, AID, and secure-channel configuration
is documented in [`ccid.md`](ccid.md).

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

The client supports the four standard slots (`9A`, `9C`, `9D`, `9E`), retired
key slots (`82` through `95`), and the attestation slot (`F9`). RSA-1024
through RSA-4096, P-256, P-384, Ed25519, and X25519 protocol identifiers are
recognized. Firmware and FIPS restrictions still apply.

Every discovered slot is exposed as PKCS #11 public/private key objects when
metadata or a certificate supplies a usable public key. Certificates are
exposed as `CKO_CERTIFICATE` objects with DER value, X.509 subject, issuer, and
serial-number attributes. Generated keys also produce dynamic, session-scoped
attestation certificates; the static `F9` attestation certificate is exposed
as a token object. Public-key attributes are read from metadata first, with
the X.509 certificate used as a fallback. EC named-curve and point attributes
are exposed for P-256, P-384, Ed25519, and X25519. Private key material remains
on the card. RSA-3072, RSA-4096, Ed25519, and X25519 are only exposed on
firmware 5.7 and later.

RSA raw, PKCS #1 v1.5, OAEP, PSS, and hashed RSA mechanisms are supported for
the applicable slots. The host performs padding and digest encoding while the
YubiKey performs the private RSA operation. `CKM_ECDSA` and its hashed variants
convert the card's DER signature to the PKCS #11 fixed-width `r || s` format,
while `CKM_EDDSA` returns the card's Ed25519 signature. Multipart sign and
verify operations buffer their input and use the same mechanism implementations.
`CKM_ECDH1_DERIVE` and
`CKM_ECDH1_COFACTOR_DERIVE` support `CKD_NULL` for P-256, P-384, and X25519;
the derived secret is returned as a sensitive generic secret object. This
derive surface is an extension to the current YKCS11 mechanism list.
