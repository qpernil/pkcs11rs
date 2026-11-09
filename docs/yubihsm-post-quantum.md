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
the ten `CKM_HASH_ML_DSA_<hash>` variants,
`CKM_ML_KEM_KEY_PAIR_GEN`, or `CKM_ML_KEM` to the slot mechanism list only when
it reports a corresponding algorithm from 59 through 64. Normal slot-mechanism
checks, per-object usage flags, and `CKA_ALLOWED_MECHANISMS` select the transport
path without a separate command filter.

Key-pair generation uses the existing `GenerateAsymmetricKey` command. Private
seed, expanded, or combined imports use `PutAsymmetricKey`, and public
projection uses `GetPublicKey`. Raw native import accepts the exact-length
seed, expanded key, or seed followed by expanded key; shared software-key-core
validation rejects malformed and inconsistent material. PKCS #11 imports accept
`CKA_SEED`, expanded `CKA_VALUE`, or both, and send a validated seed when
available or the expanded key otherwise. Device persistence uses the same
seed-preferred representation and restores existing seed records as well as
expanded-only keys. Reported object lengths remain the logical seed lengths.
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
in [software.md](software.md#ml-dsa-parameters-and-key-attributes). The
hash-specific variants hash the original message in the module, including
SHAKE128/256, and support incremental multipart signing and verification.
Update hashes each input part; Final sends only the digest to the device.
Both prehash interfaces use the same device request and perform HashML-DSA's
private-key operation inside the HSM.

PKCS #11 ML-KEM encapsulation runs locally using the public material. Native
decapsulation uses command `0x0f`, whose request is the key ID followed by the
ciphertext. The shared secret is published as the requested PKCS #11 session
secret object; the ML-KEM private key never leaves the HSM.

The virtual protocol also offers encapsulation command `0x0e` with capability
`0x3b`, but projected public operations do not use it. Native ML-DSA signing uses
`0x3a`, and ML-KEM decapsulation uses `0x3c`. Private templates map through the
[native capability mapping](yubihsm-capability-mapping.md) without permission-only
metadata. Public encapsulation defaults to enabled and honors explicit public
template restrictions independently. Stored native permission overrides are
ignored; public restrictions remain effective.

Algorithms 65–67 implement the exact specification profile in
[Post-quantum hybrid key exchange](post-quantum-hybrid-key-exchange.md).
The protocol provides `EncapsulateHybridKem` (`0x10`), `DecapsulateHybridKem` (`0x11`),
and capability bits `0x3d` and `0x3e`. PKCS #11 encapsulation runs locally; native
decapsulation uses `0x11` with capability `0x3e`. `PutAsymmetricKey` imports exactly the
draft's inseparable 32-byte seed; `GetPublicKey` returns the combined public
encoding. Their construction-specific mechanisms appear only when the device
reports the corresponding algorithm, so physical YubiHSM firmware retains its
ordinary mechanism surface.
