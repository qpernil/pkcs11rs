# YubiKey PIV client

The slot uses the [selective composition layer](architecture.md#shared-software-session-objects-and-mechanism-discovery).
It adds public-side operations, composite hashing, YubiHSM-auth ECDH support,
and consumers for secrets returned by ECDH or ML-KEM. It does not expose
unrelated software algorithms, private-key generation, or secret-key
generation. Device operations and token objects retain the native limits
described below. Native mechanisms and composed hashed-signature or prefixed-
ECDH modes carry `CKF_HW` when the long-term private-key operation remains in
the applet. Operations on a materialized host secret do not. A merged mechanism
retains `CKF_HW` when at least one operation has a hardware-held secret path.

Common CCID applet discovery, allowlist, AID, and secure-channel configuration
is documented in [`ccid.md`](ccid.md).

The PIV client selects application AID `A0 00 00 03 08` and reads the firmware
version and serial number from the applet. PKCS #11 `C_Login` verifies the PIV
PIN. PINs must contain six to eight bytes and are padded to the eight-byte PIV
APDU field with `FF`. `C_Logout` reselects the application to clear card
authentication state.

When a prompt provider is configured, the token reports
`CKF_PROTECTED_AUTHENTICATION_PATH`; a null PIN and zero length prompts for the
PIV user PIN or the hexadecimal SO management key. A slot containing only keys
whose PIN policy is `NEVER` can complete USER login without prompting.

`CK_TOKEN_INFO` reports a slot-wide PIN envelope of 6 through 64 bytes. The
lower end is the ordinary PIV PIN/PUK minimum. The upper end covers the
hexadecimal representation of an AES-256 management key accepted by
`C_Login(CKU_SO)` and SO `C_SetPIN`. Values inside that envelope remain subject
to their role-specific syntax and exact PIV limits.

The protocol layer implements:

- strict short and extended ISO 7816 APDU encoding;
- 255-byte command chaining for large PIV requests;
- `6Cxx` expected-length retries and `61xx` response chaining;
- canonical BER-TLV parsing with bounded object responses;
- PIN verification and retry queries;
- Yubico version, serial, and key metadata commands;
- PIV `GET DATA` certificate retrieval;
- `GENERAL AUTHENTICATE` signing, RSA deciphering, EC/X25519 key agreement,
  and virtual ML-KEM decapsulation.

The client supports the four standard slots (`9A`, `9C`, `9D`, `9E`) and retired
key slots (`82` through `95`). The attestation slot (`F9`) is exposed as its
static certificate object, not as a normal public/private key slot. RSA-1024
through RSA-4096, P-256, P-384, Ed25519, and X25519 protocol identifiers are
recognized. The virtual YubiKey Gadget also exposes provisional `E2`–`E4`
ML-DSA-44/65/87 and `E5`–`E7` ML-KEM-512/768/1024 identifiers. PQC mechanisms
are enabled for native keys only on the virtual Gadget, not on physical
YubiKeys. Software session-key mechanisms remain available on either slot.
Firmware and FIPS restrictions still apply.

When a slot reports the default PIN policy, `9C` uses `ALWAYS`, `9E` uses
`NEVER`, and the other standard and retired key slots use `ONCE`.

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

## Object identifiers and raw data

PIV key, certificate, and data objects use the YKCS11-compatible one-byte
`CKA_ID` mapping. Related objects therefore share an ID even though their
native PIV key references and data-object tags differ. Mapped `CKO_DATA`
objects also expose `CKA_OBJECT_ID` as the value bytes of the corresponding
PIV ASN.1 object identifier. Unmapped vendor data objects expose neither
standard attribute.

`CKA_PKCS11RS_PIV_OBJECT_TAG` (`CKA_VENDOR_DEFINED | 0x5056`) exposes the
native one-to-three-byte PIV BER-TLV object tag on every PIV `CKO_DATA` object.
For certificate containers, `CKA_VALUE` on the `CKO_CERTIFICATE` is the
uncompressed DER certificate while `CKA_VALUE` on the matching `CKO_DATA` is
the raw `70`/`71`/`FE` container returned by the card, including any stored
compression.

RSA raw, PKCS #1 v1.5, OAEP, PSS, and hashed RSA mechanisms are supported for
the applicable slots. The host performs padding and digest encoding while the
YubiKey performs the private RSA operation. `CKM_ECDSA` and its hashed variants
convert the card's DER signature to the PKCS #11 fixed-width `r || s` format,
while `CKM_EDDSA` returns the card's Ed25519 signature. Multipart sign and
verify operations buffer their input and use the same mechanism implementations.
On the virtual Gadget, `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`,
`CKM_ML_KEM_KEY_PAIR_GEN`, and `CKM_ML_KEM` use the same PKCS #11 key types,
`CKA_PARAMETER_SET` values, and sign/verify or encapsulate/decapsulate calls as
YubiHSM slots. ML-DSA signing accepts the standard `CK_SIGN_ADDITIONAL_CONTEXT`
structure, including all three hedging modes and contexts up to 255 bytes;
the client sends provisional PIV `GENERAL AUTHENTICATE` tags `88` (context) and
`89` (hedging mode). Public verification and ML-KEM encapsulation run in the
module; private signing and decapsulation run in the PIV applet. Private import
accepts a 32-byte ML-DSA or 64-byte ML-KEM `CKA_SEED`, which is sent through
the applet's private tag `09`; expanded private keys are not accepted for PIV
import. Key generation and import require management authentication. Protect
private-key import APDUs with SCP03 or SCP11 when confidentiality is required.
`CKM_ECDH1_DERIVE` and
`CKM_ECDH1_COFACTOR_DERIVE` support `CKD_NULL` for P-256, P-384, and X25519;
the derived secret is returned as a sensitive generic secret object. This
derive surface is an extension to the current YKCS11 mechanism list.

The virtual PIV extension also exposes `MLKEM768-P256`,
`MLKEM768-X25519`, and `MLKEM1024-P384` as algorithms `E8`, `E9`, and `EA`
with the construction-specific vendor key types and mechanisms documented in
[Post-quantum hybrid key exchange](post-quantum-hybrid-key-exchange.md).
Generation and import use one inseparable 32-byte seed; import tag `09` never
accepts component keys. Public projection and encapsulation run in the module,
while decapsulation remains a PIV `GENERAL AUTHENTICATE` operation. These
mechanisms are advertised only by connectors that identify the virtual PQC
extension, never by a physical PIV card based only on its firmware version.
