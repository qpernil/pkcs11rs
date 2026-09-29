# Post-quantum hybrid key exchange

PKCS11RS exposes three protocol-independent concrete hybrid PQ/T KEMs as
inseparable composite keys. This surface is a private extension because PKCS
#11 3.2 standardizes ML-KEM but does not assign hybrid KEM identifiers or
object semantics.

## Exact specification profile

The implementation is pinned to the following revisions:

- `draft-irtf-cfrg-concrete-hybrid-kems-04`, dated 6 July 2026, for the three
  concrete constructions, key derivation, serialization, encapsulation,
  decapsulation, labels, and SHA3-256 combiner;
- `draft-irtf-cfrg-hybrid-kems-12` for the generic CG hybrid KEM framework;
- `draft-connolly-cfrg-xwing-kem-10` for the byte-identical X-Wing
  `MLKEM768-X25519` instance;
- FIPS 203 for ML-KEM-768 and ML-KEM-1024;
- FIPS 202 for SHAKE256 and SHA3-256;
- SEC 1 version 2.0 uncompressed point encoding for P-256 and P-384; and
- RFC 7748 for X25519, including rejection of a non-contributory agreement.

These are not the TLS concatenation groups from RFC 10024. Each construction
has its own domain-separated combiner and returns a 32-byte shared secret.
Connector TLS remains an independent Rustls concern.

| Construction | Public key | Ciphertext | Private key | Output |
| --- | ---: | ---: | ---: | ---: |
| `MLKEM768-P256` | 1249 | 1153 | 32-byte seed | 32 |
| `MLKEM768-X25519` | 1216 | 1120 | 32-byte seed | 32 |
| `MLKEM1024-P384` | 1665 | 1665 | 32-byte seed | 32 |

Public keys are exactly `ek_PQ || ek_T`; ciphertexts are exactly
`ct_PQ || ct_T`. The traditional public/ciphertext component is a 65-byte
uncompressed P-256 point, 32-byte X25519 value, or 97-byte uncompressed P-384
point. The private object stores the draft's single 32-byte seed. Both
component private keys are derived internally and cannot be projected,
selected, imported, or used independently.

For every construction, the 32-byte result is
`SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label)`. The labels are the ASCII
bytes `MLKEM768-P256`, the six X-Wing bytes `5c 2e 2f 2f 5e 5c`, and the ASCII
bytes `MLKEM1024-P384`, respectively. For `MLKEM768-X25519`, the 32-byte
private seed is expanded with SHAKE256 to 96 bytes: the first 64 bytes are the
FIPS 203 ML-KEM-768 seed and the last 32 bytes are the RFC 7748 X25519 private
input. Encapsulation consumes 64 random bytes in the same component order:
32 bytes for ML-KEM-768 and 32 bytes for the ephemeral X25519 private input.
Thus its public key is the 1184-byte ML-KEM encapsulation key followed by the
32-byte recipient X25519 public key, and its ciphertext is the 1088-byte
ML-KEM ciphertext followed by the 32-byte ephemeral X25519 public key. This is
the exact X-Wing construction used by the implementation.

## PKCS #11 identifiers and objects

`PKCS11RS_VENDOR_BASE` is `0x50530000`. The complete assigned surface is:

| Construction | Key type | Key-pair generation | KEM operation |
| --- | --- | --- | --- |
| `MLKEM768-P256` | `CKK_PKCS11RS_MLKEM768_P256` = `CKK_VENDOR_DEFINED \| 0x50530010` | `CKM_PKCS11RS_MLKEM768_P256_KEY_PAIR_GEN` = `CKM_VENDOR_DEFINED \| 0x50530010` | `CKM_PKCS11RS_MLKEM768_P256` = `CKM_VENDOR_DEFINED \| 0x50530011` |
| `MLKEM768-X25519` | `CKK_PKCS11RS_MLKEM768_X25519` = `CKK_VENDOR_DEFINED \| 0x50530011` | `CKM_PKCS11RS_MLKEM768_X25519_KEY_PAIR_GEN` = `CKM_VENDOR_DEFINED \| 0x50530012` | `CKM_PKCS11RS_MLKEM768_X25519` = `CKM_VENDOR_DEFINED \| 0x50530013` |
| `MLKEM1024-P384` | `CKK_PKCS11RS_MLKEM1024_P384` = `CKK_VENDOR_DEFINED \| 0x50530012` | `CKM_PKCS11RS_MLKEM1024_P384_KEY_PAIR_GEN` = `CKM_VENDOR_DEFINED \| 0x50530014` | `CKM_PKCS11RS_MLKEM1024_P384` = `CKM_VENDOR_DEFINED \| 0x50530015` |

Generation mechanisms take no parameters and report
`CKF_GENERATE_KEY_PAIR`. Operation mechanisms take no parameters and report
`CKF_ENCAPSULATE | CKF_DECAPSULATE`. `C_EncapsulateKey` returns the complete
construction ciphertext and creates the requested AES or generic-secret
object. `C_DecapsulateKey` consumes that exact ciphertext and creates the same
32-byte secret object. Key type and operation mechanism must identify the same
construction; cross-construction use returns `CKR_KEY_TYPE_INCONSISTENT`.

Public `CKA_VALUE` is the combined public encoding. Private `CKA_SEED` and an
extractable private `CKA_VALUE` are the inseparable 32-byte seed. Imports
accept exactly one of those private attributes and reject any other length.
Software token persistence uses PKCS #8 with absent parameters and private
OIDs `1.3.6.1.4.1.41482.10.1`, `.10.2`, and `.10.3` in construction order.
`CKA_PUBLIC_KEY_INFO` uses the corresponding OID and the raw combined public
key in the BIT STRING.

## Backend availability

Software slots expose all three pairs without `CKF_HW`. A PIV or YubiHSM slot
exposes them only when the connector identifies the matching virtual extension;
physical devices and older virtual profiles retain their prior mechanism set
and never receive these private commands. A capable virtual-device mechanism
reports `CKF_HW` because the complete private operation and both component keys
remain inside that device.

The virtual PIV assignments are algorithms `E8`, `E9`, and `EA`. Generation
returns `7F49 { 87 ek_PQ || ek_T }`; import uses tag `09` with exactly the
32-byte seed; and `GENERAL AUTHENTICATE` takes
`7C { 82 empty, 81 ct_PQ || ct_T }` and returns
`7C { 82 secret }`, where the secret is 32 bytes. Generated key attestation
uses private SPKI OIDs `1.3.6.1.4.1.41482.11.1`, `.11.2`, and `.11.3`.

The virtual YubiHSM assignments are asymmetric algorithms `65`, `66`, and
`67`; commands `EncapsulateHybridKem` (`0x10`) and
`DecapsulateHybridKem` (`0x11`); and capabilities
`encapsulate-hybrid-kem` (`0x3d`) and `decapsulate-hybrid-kem` (`0x3e`).
Generation and import reuse the ordinary asymmetric object commands, with
exactly the 32-byte seed on import. Attestation uses private SPKI OIDs
`1.3.6.1.4.1.41482.12.1`, `.12.2`, and `.12.3`.

The device-side byte layouts, status mapping, and authorization rules are
specified in the matching `virtual-yubikey` PIV conformance document and
`virtual-yubihsm` virtual-extension document.

## Verification

The shared implementation is checked against the official draft-04 vector for
each construction. Tests also cover generation, import, public projection,
persistence, encapsulation/decapsulation equality, malformed traditional
values, non-contributory X25519, cross-construction rejection, device
capabilities, mechanism reporting, and generated-key attestation.

## References

- [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [Concrete Hybrid PQ/T Key Encapsulation Mechanisms, draft-04](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04)
- [Generic Hybrid PQ/T Key Encapsulation Mechanisms, draft-12](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12)
- [X-Wing, draft-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)
- [SEC 1 version 2.0](https://www.secg.org/sec1-v2.pdf)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
