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

The logical role is separate from the card's authentication state. PIV can
retain PIN verification and management-key authentication simultaneously.
The backend does not retain either credential or maintain parallel hardware
authorization flags; the applet enforces whether the necessary authorization
is still active, including per-key one-use `ALWAYS` PIN policies.

PIV follows the card's administrative model: SO can generate, import, and
remove native private keys, and can find those objects and read their
non-sensitive attributes. This is an explicit PKCS #11 deviation: the standard
normally reserves private-object creation, visibility, and deletion to USER.
`CKA_PRIVATE` remains true, private key material stays unreadable, and SO
cannot use the keys for signing, decryption, or derivation. The exception does
not expose private software session objects or private objects on other
backends. Read/write session requirements still apply to token mutations.

The normal provisioning flow is `C_Login(CKU_SO, management_key)`, object
management, then `C_Logout`. Subsequent private-key use requires
`C_Login(CKU_USER, pin)`. Direct USER login while SO is active still returns
`CKR_USER_ANOTHER_ALREADY_LOGGED_IN`. Administrative APDUs can also be attempted
under USER, but PIN verification alone does not authorize them: the card
requires management-key authentication. No parallel host permission state or
retained management key substitutes for that authorization.

SO logout attempts to revoke management authorization by starting a fresh
management-key authentication exchange and leaving its challenge unanswered.
The next ordinary APDU cancels that exchange with management authorization
cleared. This does not require selecting another applet or retaining the key.
USER logout attempts the YubiKey 5.4.3 PIN de-authentication command, `VERIFY`
with `P1=FF` and `P2=80`; it does not revoke management authorization. Both
logout paths are best-effort: a device error is logged and the logical role
is cleared even when firmware rejects the command. Applet changes, card
resets, and removal also invalidate authorization; neither credential is
retained or replayed to restore it.

Logout releases the host secure channel, its authentication-source binding,
and the selected-applet guard. It does not select a different applet, avoiding
the YubiKey NEO hazard of stranding the card outside PIV by selecting the
management applet as a logout workaround.

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
YubiKeys. Native PC/SC readers identify the virtual device by the `YubiKey Gadget`
reader name; the embedded transport advertises its capability directly. Software
session-key mechanisms remain available on either slot.
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

Native key attributes are immutable (`CKA_MODIFIABLE=false`). In particular,
`C_SetAttributeValue(CKA_ID)` does not physically move a key. Use a PIV
management tool for a physical slot move; rediscovery treats the new native
location as a different object. Unique IDs include the native location,
public-key fingerprint, and public/private role, distinguishing identical key
material stored in separate slots. Imported private keys report
`CKA_ALWAYS_SENSITIVE=false` and `CKA_NEVER_EXTRACTABLE=false`, regardless of
their current hardware nonextractability.

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
accepts a 32-byte ML-DSA or 64-byte ML-KEM `CKA_SEED`, expanded private
`CKA_VALUE`, or both. Shared software-key-core validation rejects malformed
or inconsistent components. The adapter sends a retained seed through private
tag `09`, or the expanded key through private tag `0A` when no seed is present.
The virtual applet also accepts both tags and checks their consistency.
Persistence retains seedless keys in expanded form and preserves existing
seed records. Key generation and import require management authentication. Protect
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
