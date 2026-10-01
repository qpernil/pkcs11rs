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
APDU field with `FF`.

## PKCS #11 role and PIV authentication

The module keeps one logical PKCS #11 role per PIV slot: PUBLIC, SO, or USER.
Read-only versus read/write is a property of each open session. Consequently,
`C_GetSessionInfo` combines the slot role with the queried session's
`CKF_RW_SESSION` flag: PUBLIC and USER have RO and RW states, while SO is
reported only as `CKS_RW_SO_FUNCTIONS`. The role is token-wide, so every open
session on the slot observes the same role. SO login requires an RW session and
is rejected while an RO session exists.

This logical role is the only PKCS #11 authentication state retained by the
module for PIV. The PIV backend does not cache separate `PIN authenticated` or
`management key authenticated` flags, and `C_GetSessionInfo` does not probe PIN
retries or derive the role from applet state. The CCID connector has only a
selected-applet guard while a role is active; that guard is not an
authentication role and is never used to synthesize `CK_SESSION_INFO.state`.

PIV itself remains authoritative for its authentication facts. It may retain
PIN verification and management-key authentication at the same time even
though PKCS #11 exposes only one logical role. It also enforces per-key PIN
policies, including one-use `ALWAYS` verification. The module performs the
minimum PKCS #11 role checks before issuing a command: management operations
require the logical SO role, and operations on login-protected private keys
require the logical USER role. The PIV command can still fail when the applet's
corresponding authentication is absent or has been consumed.

`C_Logout` de-authenticates the active logical role before changing the slot
role to PUBLIC and releasing the connector's selected-applet guard. USER logout
uses the YubiKey 5.4.3 direct PIN de-authentication command, `VERIFY` with
`P1=FF` and `P2=80`. SO logout starts an ordinary management-key
mutual-authentication exchange and stops after receiving the card's challenge.
The module immediately discards that response and retains neither it nor the
management key, so it cannot construct a valid continuation.
While that challenge is pending, only `GENERAL AUTHENTICATE` for key reference
`9B` can continue the exchange. Any other APDU clears the pending exchange and
existing management authorization before the applet processes that APDU
normally. A wrong continuation to `9B` likewise consumes the challenge and
clears management authorization. This permits logout without retaining the
challenge, retaining the management key, or selecting another applet. The
behavior is verified on YubiKey firmware 5.2.4 and 5.7.4: a harmless
management-protected probe using an invalid key reference returns `6B00` while
authenticated and `6982` when it is the first command after SO logout.

NIST SP 800-73-5 Part 2, Section 2.4.2, requires an aborted or failed
authentication protocol to set the credential's security-status indicator to
false, and identifies the PIV Card Application Administration Key indicator as
application-local. Appendix A.2 specifies the two-command `GENERAL
AUTHENTICATE` protocol for reference `9B`. Taken together, a later APDU that is
not a valid continuation of that protocol abandons it and therefore must clear
the Administration Key security status. The standard's separate rollback rule
for interrupted `GENERAL AUTHENTICATE` APDU command chaining concerns a
different transport mechanism. Firmware 5.2.4 and 5.7.4 verify the resulting
multi-command behavior used here.

The two de-authentication paths are role-specific. PIN de-authentication does
not clear management-key authentication, while failed management authentication
does not clear PIN verification. Successful PIN and management authentication
are likewise independent and may both be active in the PIV applet even though
PKCS #11 exposes only one logical role. A failure in either de-authentication
path is logged and ignored so firmware-specific behavior cannot prevent the
logical logout. The module never falls back to selecting a management or
Yubico applet; in particular, selecting the management applet can strand a
YubiKey NEO outside PIV. A later SO or USER login establishes the requested
logical role and performs the corresponding PIV authentication.

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
while `CKM_EDDSA` returns the card's Ed25519 signature. Hash-specific RSA,
ECDSA and HashML-DSA multipart operations hash each input part in the module
and retain only the hash state; Final sends the digest or RSA DigestInfo to
the private operation. Raw mechanisms, EdDSA and pure ML-DSA retain complete
input buffers.
On the virtual Gadget, `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`, `CKM_HASH_ML_DSA`,
and all ten `CKM_HASH_ML_DSA_<hash>` variants,
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

ML-DSA `GENERAL AUTHENTICATE` requests include tag `8A` with a one-byte prehash
identifier: `0` selects pure ML-DSA; nonzero values select the NIST hash OID's
final arc, as documented in [yubihsm-post-quantum.md](yubihsm-post-quantum.md).
Tag `81` holds the complete message for pure signing or a caller-computed
digest for HashML-DSA. The applet constructs the FIPS 204 signing input without
hashing the original message. TLV framing supplies context and input lengths.
`CKM_HASH_ML_DSA` requires `CK_HASH_SIGN_ADDITIONAL_CONTEXT` and supports the
SHA-2 and SHA-3 parameters and single-part operations documented in
[software.md](software.md#ml-dsa-parameters-and-key-attributes). The
hash-specific variants accept the original message, use optional
`CK_SIGN_ADDITIONAL_CONTEXT`, and support single-part and multipart calls.
The module hashes each input part and sends only the final digest to the applet;
the wire request is the same as for client-prehashed input.

The virtual PIV extension also exposes `MLKEM768-P256`,
`MLKEM768-X25519`, and `MLKEM1024-P384` as algorithms `E8`, `E9`, and `EA`
with the construction-specific vendor key types and mechanisms documented in
[Post-quantum hybrid key exchange](post-quantum-hybrid-key-exchange.md).
Generation and import use one inseparable 32-byte seed; import tag `09` never
accepts component keys. Public projection and encapsulation run in the module,
while decapsulation remains a PIV `GENERAL AUTHENTICATE` operation. These
mechanisms are advertised only by connectors that identify the virtual PQC
extension, never by a physical PIV card based only on its firmware version.
