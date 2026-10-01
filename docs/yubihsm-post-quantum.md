# Post-quantum keys on a virtual YubiHSM

PKCS11RS maps PKCS #11 ML-DSA and ML-KEM objects to the virtual YubiHSM wire
extensions while retaining the same token-object, metadata, capability,
persistence, and authenticated-session behavior as the existing asymmetric
keys. Physical YubiHSM firmware does not advertise these virtual algorithms, so
its slots do not expose or select these mechanisms.

The mapping is:

| PKCS #11 parameter set | YubiHSM algorithm |
| --- | ---: |
| ML-DSA-44 | 59 |
| ML-DSA-65 | 60 |
| ML-DSA-87 | 61 |
| ML-KEM-512 | 62 |
| ML-KEM-768 | 63 |
| ML-KEM-1024 | 64 |
| MLKEM768-P256 | 65 |
| MLKEM768-X25519 | 66 |
| MLKEM1024-P384 | 67 |

A device contributes `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`, `CKM_HASH_ML_DSA`,
`CKM_ML_KEM_KEY_PAIR_GEN`, or `CKM_ML_KEM` to the slot mechanism list only when
it reports a corresponding algorithm from 59 through 64. Normal slot-mechanism
checks, per-object usage flags, and `CKA_ALLOWED_MECHANISMS` select the transport
path without a separate command filter.

Key-pair generation uses the existing `GenerateAsymmetricKey` command. Private
seed imports use `PutAsymmetricKey`, and public projection uses `GetPublicKey`.
ML-DSA signing uses virtual command `0x0d`, preserving PKCS #11 deterministic,
required-randomization, preferred-randomization, and context semantics.
Its single wire format is `key ID (u16 BE) | hedge mode (u8) | prehash (u8) |
context length (u8) | context | input remainder`. Prehash `0` means pure;
nonzero identifiers are the final arc of the NIST hash OID (SHA-256/384/512:
1/2/3, SHA-224: 4, SHA3-224/256/384/512: 7/8/9/10, SHAKE128/256: 11/12).
The caller computes the digest. The HSM checks its length and constructs
HashML-DSA's FIPS 204 domain separator and OID. There is no input-length field.
Clients and devices must both use the explicit prehash field.
PKCS #11 `CKM_HASH_ML_DSA` accepts the SHA-2 and SHA-3 hash parameters documented
in [software.md](software.md#ml-dsa-parameters-and-key-attributes).

ML-KEM encapsulation uses command `0x0e`, whose fixed request is the key ID;
decapsulation uses command `0x0f`, whose request is the key ID followed by the
ciphertext. The shared secret is published as the requested PKCS #11 session
secret object; the ML-KEM private key never leaves the HSM.

The virtual commands use capability bits `0x3a` for ML-DSA signing, `0x3b` for
ML-KEM encapsulation, and `0x3c` for ML-KEM decapsulation. Key creation derives
these bits from the private and public templates. Persisted PKCS #11 metadata
may narrow the native permissions and allowed mechanisms but cannot grant a
capability absent from the HSM object.

Algorithms 65–67 implement the exact specification profile in
[Post-quantum hybrid key exchange](post-quantum-hybrid-key-exchange.md).
They use `EncapsulateHybridKem` (`0x10`), `DecapsulateHybridKem` (`0x11`),
and capability bits `0x3d` and `0x3e`. `PutAsymmetricKey` imports exactly the
draft's inseparable 32-byte seed; `GetPublicKey` returns the combined public
encoding. Their construction-specific mechanisms appear only when the device
reports the corresponding algorithm, so physical YubiHSM firmware retains its
ordinary mechanism surface.
