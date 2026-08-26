# Protected prefixed ECDH derivation

`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` maps PKCS #11 `C_DeriveKey` onto the
virtual YubiHSM `DeriveEcdhKdf` extension. It performs ECDH with a private key
held by the HSM, prefixes the raw agreement with caller-supplied material, and
applies a mandatory ANSI X9.63 KDF without exposing the HSM-computed ECDH
secret.

## Parameters and operation

[`pkcs11rs.h`](../pkcs11rs.h) declares:

```c
typedef struct CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrefixDataLen;
  CK_BYTE_PTR pPrefixData;
} CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS;
```

For the HSM-held private key `d`, peer public key `Q`, prefix `P`, shared data
`S`, and requested derived-key length `L`, the operation is:

```text
Z       = ECDH(d, Q)
block_i = Hash(P || Z || I2OSP(i, 4) || S), i = 1, 2, ...
output  = leftmost L bytes of block_1 || block_2 || ...
```

This is ANSI X9.63 over the composite secret `P || Z`. `pPrefixData` therefore
precedes the protected ECDH result, while `pSharedData` follows the four-byte
X9.63 counter. Empty prefix and shared-data fields are valid. `CKD_NULL` and
the differently ordered SP 800-56A KDF selectors are rejected.

The accepted X9.63 selectors are the ordinary SHA-1, SHA-224, SHA-256,
SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, and SHA3-512 `CKD_*_KDF`
values. The peer public value follows the same encoding rules as
`CKM_ECDH1_DERIVE`: SEC1 for short-Weierstrass curves and 32 raw bytes for
X25519.

## Availability and key policy

A YubiHSM slot advertises the mechanism only when its algorithm list contains
the virtual `ECDH KDF` extension identifier `57` and it supports at least one
eligible curve. The supported curves are P-224, P-256, P-384, P-521,
secp256k1, Brainpool P-256, P-384, P-512, and X25519.

The HSM command requires the separate `derive-ecdh-kdf` capability bit `0x38`
on both the authenticated session and the asymmetric key. Ordinary raw ECDH
continues to require `derive-ecdh` at bit `0x0b`. A PKCS #11 generation or
import template can select the protected capability by putting only
`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` in `CKA_ALLOWED_MECHANISMS`; selecting both
mechanisms gives the object both capabilities. A protected-only key rejects
`CKM_ECDH1_DERIVE`.

Discovered protected-capability keys report `CKA_DERIVE=CK_TRUE` and expose
their precise permitted derivation mechanisms through
`CKA_ALLOWED_MECHANISMS`.

## Current derived object

The virtual YubiHSM command returns the KDF output. `pkcs11rs` wraps that output
as its existing host-memory `CKK_GENERIC_SECRET` session object. Consequently:

- the object has `CKA_TOKEN=CK_FALSE` and belongs to the creating PKCS #11
  session;
- requesting `CKA_TOKEN=CK_TRUE` is rejected;
- the value is currently readable and extractable, matching the established
  hardware-ECDH compatibility-object behavior; and
- the object disappears when its creating PKCS #11 session closes.

This is a real PKCS #11 object but not a YubiHSM object. The reusable raw ECDH
secret remains inside the HSM; the final, session-specific KDF output is
visible to the trusted provider process and to the PKCS #11 caller.

## YubiHSM asymmetric-authentication mapping

For YubiHSM asymmetric authentication, the caller supplies:

```text
P    = ECDH(client-ephemeral-private, device-ephemeral-public)
Q    = device-static-public
S    = 3c 88 10
Hash = SHA-256
L    = 64
```

The 64-byte result is divided as follows:

```text
0..16   receipt key
16..32  S-ENC
32..48  S-MAC
48..64  S-RMAC
```

The receipt is:

```text
AES-CMAC(receipt-key,
         device-ephemeral-public || client-ephemeral-public)
```

After receipt verification, ordinary YubiHSM secure messaging uses `S-ENC`,
`S-MAC`, and `S-RMAC`. The implementation test generates the protected static
key through PKCS #11, provisions its public half as an asymmetric
authentication key on a second virtual YubiHSM, derives the 64 bytes through
`C_DeriveKey`, verifies the receipt, completes the secure channel, and sends an
authenticated command.

The complete follow-on calculations use the receipt as the initial MAC
chaining value `MCV`. Each command authenticates `MCV || command-frame` with
AES-CMAC under `S-MAC`, transmits the first eight MAC bytes, and replaces `MCV`
with the full 16-byte MAC. Each response authenticates
`MCV || response-frame` with AES-CMAC under `S-RMAC` and transmits its first
eight bytes without advancing `MCV`. Encrypted inner frames use ISO 7816-4
padding and AES-CBC under `S-ENC`; the IV is AES-ECB under `S-ENC` of the
request counter. A request and its response use the same IV, then the counter
advances.

## Security boundary

The source HSM performs static ECDH and the complete X9.63 KDF. Its reusable
static ECDH result never crosses the device boundary. The caller-visible
ephemeral agreement, transcript, and final keys are specific to the target's
fresh ephemeral key and therefore to that target session.

Retaining every externally visible input, the client ephemeral private key,
and all four output keys compromises the corresponding live session. It does
not enable calculation of keys for a later target session without invoking the
source HSM again. A later session changes the prefix before the unknown static
secret; SHA-256 length extension cannot replace that prefix.

This mechanism does **not** claim that the final session keys remain inside the
source HSM.

## Future protected-key composition

The main missing abstraction is a true HSM-side `C_DeriveKey`: a protected base
key plus mechanism parameters and an output template should atomically create
a new protected, chainable HSM key object instead of returning bytes. A
persistent generic-secret object type is the natural foundation for that
abstraction and is realistic for physical hardware: it is an ordinary,
non-extractable NVM object with tightly scoped derivation capabilities, not a
large or long-lived RAM allocation.

A token-output form of this mechanism could create the 64-byte generic secret
directly in virtual-YubiHSM NVM. Native `CKM_EXTRACT_KEY_FROM_KEY` could then
derive four persistent, non-extractable AES objects at bit offsets 0, 128, 256,
and 384. Existing standard PKCS #11 AES-CMAC, ECB, and CBC mechanisms could use
those objects without any key bytes leaving the HSM.

The output need not be AES. A generic secret is itself directly usable as an
HMAC or KDF base key, while a subsequent mechanism can create an AES key or
another supported symmetric key type selected by the output template. The
same foundation naturally covers these common `C_DeriveKey` families:

- ECDH and finite-field DH into a generic secret;
- HKDF and the SP 800-108 counter, feedback, and double-pipeline KDFs;
- `CKM_EXTRACT_KEY_FROM_KEY`, concatenate-base/data, and XOR-base/data
  composition;
- digest-based key derivation; and
- protocol-specific TLS derivations where their multi-output semantics can be
  mapped without exposing intermediate keys.

Password-based derivation starts from caller-supplied input rather than an
existing protected key and is closer to key generation, but it can produce the
same persistent output objects. Legacy SSL/TLS and obsolete cipher key types
should not drive the initial hardware design.

Ordinary derived token objects would remain NVM-backed, generation-tracked,
and explicitly deleted. The first useful hardware-sized subset is persistent
generic-secret output, extraction into persistent AES keys, protected ECDH,
HKDF, and SP 800-108; those primitives cover SCP11 and many
non-protocol-specific uses without baking SCP11 into the object model.

The SCP11 flow needs only one transient intermediate, so a native session
object is also realistic on constrained hardware. Each authenticated HSM
session can own one optional, zeroizing generic-secret buffer of at most 64
bytes. It has sequence zero, is never persisted, and is invisible outside that
HSM session. Authentication clears it before establishing new authority;
close, timeout, authentication failure, protocol invalidation, and reset also
clear it. `pkcs11rs` must retain the underlying HSM session for as long as its
PKCS #11 session-object handle exists. Four subsequent
`CKM_EXTRACT_KEY_FROM_KEY` calls can create ordinary persistent AES objects
without exposing the intermediate bytes. This avoids NVM session-object
ownership and orphan-cleanup machinery entirely.

For physical or older devices without native generic secrets, a separate
compatibility design may allow a non-extractable host-memory session secret to
use `CKM_EXTRACT_KEY_FROM_KEY` solely to import persistent AES token objects.
That would hide values from the PKCS #11 application but not from the trusted
provider process, and is intentionally future work rather than part of the
current mechanism.
