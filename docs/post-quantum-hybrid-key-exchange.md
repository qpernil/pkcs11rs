# Post-quantum hybrid key exchange

PKCS11RS has two separate uses for post-quantum/traditional hybrid key
exchange:

1. Connector TLS can negotiate a standardized TLS 1.3 hybrid group in the
   Rustls software stack to protect connector traffic against
   harvest-now/decrypt-later attacks.
2. PKCS #11 consumers can use a hybrid KEM mechanism to create and use one
   inseparable composite key through a software or hardware-backed slot.

The first use does not depend on the second. Connector TLS keys are ephemeral
transport state and need not be represented as PKCS #11 objects. The second
use applies when an application needs a protocol-independent hybrid KEM, TLS
offload, hardware-backed ephemeral state, or direct qualification of a slot's
hybrid implementation.

## Current status

PKCS11RS implements the PKCS #11 3.2 `CKK_ML_KEM` key type,
`CKM_ML_KEM_KEY_PAIR_GEN`, and `CKM_ML_KEM` encapsulation and decapsulation
mechanism. It does not currently expose a hybrid ML-KEM plus ECDH key type or
mechanism.

PKCS #11 3.2 standardizes ML-KEM but no post-quantum/traditional hybrid KEM.
Until a PKCS #11 specification assigns portable identifiers and object
semantics, hybrid support must use vendor-defined identifiers. Those
identifiers must not be presented as standard PKCS #11 values.

## Mechanism model

A hybrid KEM is exposed as one composite public/private key pair rather than
two independently usable component-key handles. The public object contains
the ML-KEM encapsulation key and the traditional ECDH public key. The private
object owns both private components and does not permit either component to be
used separately or with a different hybrid construction.

The normal PKCS #11 3.2 KEM API applies:

- `C_GenerateKeyPair` creates the composite key pair.
- `C_EncapsulateKey` takes the composite public key, returns the composite
  ciphertext, and creates the resulting secret-key object.
- `C_DecapsulateKey` takes the composite private key and ciphertext and creates
  the same secret-key object.

ECDH is an internal component of the KEM. The composite operation is not
exposed through `C_DeriveKey`, and the application does not retrieve and
combine independent ML-KEM and ECDH shared secrets.

## General-purpose hybrid KEMs

The protocol-independent candidates are the concrete CFRG hybrid KEMs:

| Construction | Components | Result |
| --- | --- | --- |
| `MLKEM768-P256` | ML-KEM-768 and P-256 | 32-byte combined secret |
| `MLKEM768-X25519` | ML-KEM-768 and X25519 | 32-byte combined secret |
| `MLKEM1024-P384` | ML-KEM-1024 and P-384 | 32-byte combined secret |

These constructions include their own domain-separated hybrid combiner.
`MLKEM768-P256`, for example, uses SHAKE256 during joint key generation and
SHA3-256 to combine the component results. It is therefore a complete KEM and
does not rely on a containing protocol to supply the missing KDF.

The CFRG definitions remain Internet-Drafts. Initial PKCS11RS identifiers and
encodings must therefore be explicitly experimental and versioned or kept
replaceable until the definitions become stable.

## TLS 1.3 hybrid mechanisms

RFC 10024 defines the TLS groups `X25519MLKEM768`,
`SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`. A PKCS #11 implementation can
expose corresponding vendor mechanisms through the same encapsulation and
decapsulation entry points:

- the client generates a session-only ephemeral composite key pair;
- the server encapsulates to the client public key and returns the TLS server
  key share plus a secret-key object;
- the client decapsulates the server share and obtains an equivalent
  secret-key object; and
- the TLS implementation supplies that key to the TLS 1.3 key schedule.

Unlike the general-purpose KEMs, the TLS mechanisms return the two component
secrets in the order defined by RFC 10024. For `SecP256r1MLKEM768`, this is the
64-byte value `ECDHE || ML-KEM`; for `X25519MLKEM768`, it is
`ML-KEM || X25519`. TLS performs the HKDF processing and transcript binding.
The raw concatenation is not a safe general-purpose shared key and must be
identified as TLS-specific.

TLS hybrid private keys should be nonpersistent session objects by default.
A slot must not allow one composite private key to be reused across a TLS
mechanism, a general-purpose hybrid KEM, or either standalone component
algorithm. Mechanism-specific key types are the simplest enforcement model;
an equally strong internal usage binding is acceptable if it remains visible
and enforceable across persistence, import, copy, and unwrap operations.

PKCS #11-backed TLS key exchange is a separate future integration concern. It
should expose classical TLS groups such as X25519, P-256, and P-384 through the
same provider abstraction as the hybrid groups rather than add a PQ-only TLS
path. The adapter can normalize classical `C_DeriveKey` operations and hybrid
encapsulation or decapsulation operations into the key-exchange result expected
by the TLS stack, while TLS retains negotiation, transcript processing, and its
key schedule. This common design also permits deployments to order, require,
or fall back between classical and hybrid groups through one policy surface.

The general-purpose hybrid KEM mechanisms do not depend on this TLS provider
work and should be implemented and qualified independently. TLS-specific PKCS
#11 mechanisms can be reconsidered when there is a concrete consumer and the
classical and hybrid provider model has been designed together.

## Mechanism reporting and backends

A slot advertises a hybrid mechanism only when one backend can perform the
complete construction with the required key-usage binding. A mechanism is
reported with `CKF_HW` when the backend retains the sensitive composite key
material and performs the secret operations, including when that backend is a
virtual PIV applet or virtual YubiHSM. Combining a hardware component with an
independent software component does not constitute the same hardware-backed
composite key unless the backend defines and enforces the composite object's
ownership and usage policy.

The mechanism information uses `CKF_GENERATE_KEY_PAIR` for key generation and
`CKF_ENCAPSULATE | CKF_DECAPSULATE` for the KEM operation. Encapsulation and
decapsulation create secret-key objects rather than exporting the shared
secret directly, subject to the ordinary output template and sensitivity
rules.

## Provisional YubiHSM extensions

The virtual YubiHSM `firmware-full` profile is a suitable end-to-end backend
for the experimental mechanisms. Its extension should remain explicitly
provisional and make no compatibility claim for physical YubiHSM firmware.
Algorithm identifiers, command identifiers, capability bits, object encodings,
and attestation identifiers must stay in the project's private extension space
until an applicable standard assigns them.

A composite YubiHSM object owns both private components under one object ID,
label, domain set, capability policy, origin, and lifecycle. Generation creates
both components atomically. Import, when supported, must likewise accept one
canonical composite private-key encoding and reject attempts to assemble a
composite object from independently usable component objects. Public-key
retrieval returns the canonical combined public encoding required by the
selected construction.

The YubiHSM command surface should expose complete hybrid encapsulation and
decapsulation operations rather than returning independent component secrets
for combination in PKCS11RS. General-purpose commands return the 32-byte output
of the construction's internal KDF. TLS-specific commands return the ordered
64-byte intermediate secret and the RFC 10024 peer share, leaving TLS HKDF and
transcript binding to the TLS implementation. The algorithm attached to the
object and command must prevent cross-use between these two forms.

TLS hybrid keys are normally transient. Where the virtual YubiHSM protected
session-object extension is available, PKCS11RS should map session-only TLS
composite keys to it rather than consume persistent object IDs. Persistent
hybrid objects support general-purpose KEM tests, explicit lifecycle
qualification, and protocols that require a stable recipient key.

Firmware capability discovery controls mechanism advertisement. Older or
physical YubiHSMs that do not report the extension retain their existing
mechanism set and never receive provisional commands. The connector continues
to transport opaque YubiHSM frames and does not implement or terminate the
hybrid construction.

When implemented, the private extension must be documented consistently in
PKCS11RS and `virtual-yubihsm`, including exact byte layouts, assigned values,
capabilities, object semantics, error behavior, test vectors, and the draft or
RFC revision implemented.

## Provisional PIV extensions

The virtual PIV applet can expose the same constructions as provisional PIV
algorithm identifiers, following the existing private ML-DSA and ML-KEM
extension model. One PIV key slot contains one inseparable composite key. It
does not expose the ML-KEM and ECDH private components as separate PIV keys or
allow either component to be selected by a standalone algorithm identifier.

`GENERATE ASYMMETRIC KEY PAIR` creates both components atomically and returns a
canonical combined public-key template. Private-key import, when enabled,
accepts one canonical composite encoding and applies the same algorithm and
slot policy as generation. `GENERAL AUTHENTICATE` carries the complete hybrid
ciphertext or peer share and returns the construction's combined result; it
does not return the two component secrets. The final TLV layout and algorithm
values must be specified with the same exactness as the existing private
ML-KEM extension. The current extended APDU and internal buffer model already
used for ML-KEM is the applicable transport model for the larger hybrid
public keys and ciphertexts.

PKCS11RS can perform encapsulation from the projected composite public key
without access to private card state, as it does for current PIV ML-KEM public
operations. Decapsulation and every other operation involving the composite
private key remain applet operations. A slot advertises the hybrid mechanism
with `CKF_HW` when the private composite key resides in the PIV applet and the
applet performs the complete private operation.

Generated composite keys may use the existing PIV attestation command. Until
standard composite KEM certificate identifiers and encodings are available,
their SubjectPublicKeyInfo algorithm and public-key encoding remain private,
provisional definitions and must not be represented as standard PIV or X.509
algorithms. The attestation certificate can still bind the combined public key
to the slot, applet, firmware, and policy under that explicitly experimental
profile.

Physical PIV cards that do not implement and advertise the private algorithm
retain their existing mechanism set. When implemented, the PIV algorithm
values, key templates, import format, `GENERAL AUTHENTICATE` TLVs, attestation
encoding, APDU limits, and test vectors must be documented consistently in
PKCS11RS and `virtual-yubikey`.

## Validation requirements

Implementation qualification must cover:

- independent known-answer or interoperability vectors for every composite
  encoding and combiner;
- identical encapsulation and decapsulation secret-key values;
- rejection of malformed component public keys and ciphertexts;
- rejection of standalone or cross-mechanism use of component keys;
- session-object destruction and failure cleanup;
- mechanism flags, key types, attributes, copying, persistence, import, and
  unwrap policy; and
- PIV generation, import, extended-APDU operation, persistence, and
  attestation for each advertised provisional algorithm;
- TLS interoperability with RFC 10024 peers for TLS-specific mechanisms.

Connector TLS policy, provider selection, fallback, and deployment concerns
are documented separately in [PKCS11RS multi-device connector](connector.md#post-quantum-tls-status).

## References

- [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [RFC 10024: PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html)
- [Concrete Hybrid PQ/T Key Encapsulation Mechanisms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/)
- [Generic Hybrid PQ/T Key Encapsulation Mechanisms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/)
