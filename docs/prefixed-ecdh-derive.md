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
`CKM_ECDH1_DERIVE`: SEC1 for short-Weierstrass curves, 32 raw bytes for
X25519, and 56 raw bytes for X448.

## Availability and key policy

A YubiHSM slot advertises the mechanism only when its algorithm list contains
the virtual `ECDH KDF` extension identifier `57` and it supports at least one
eligible curve. The supported curves are P-224, P-256, P-384, P-521,
secp256k1, Brainpool P-256, P-384, P-512, X25519, and X448.

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

## Derived object

The virtual YubiHSM command returns the KDF output. `pkcs11rs` stores it as an
ordinary host software secret key owned by the creating PKCS #11 session. The
template can select a supported generic-secret, AES, 3DES, or HMAC type and its
usage, sensitivity, and extractability policy. With no policy attributes, the
result is a public, nonsensitive, extractable generic-secret session object.
It can be copied and used by the common software operations. Closing its
creator destroys it; logout also destroys it when `CKA_PRIVATE=CK_TRUE`.
Persistent derived software keys require a backend that supports encrypted
software-key storage; YubiHSM slots reject that request.

The reusable raw ECDH secret remains inside the HSM. The final KDF output is
visible to the trusted provider process; the object's policy controls whether
the PKCS #11 caller can read or export it. See the
[shared session layer](architecture.md#shared-software-session-objects-and-mechanism-discovery).

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

The [SCP03/SCP11 key-operation plan](scp-key-provider/README.md) uses one protocol
implementation with interchangeable software and native key providers. The
native goal protects long-term credentials and agreement inputs during
derivation, then permits final working-key reads for local message crypto.
There is no message-crypto placement option. Generic chainable device objects
remain planned; the existing command returns KDF bytes to the host.

The [client operation matrix](scp-key-provider/operation-matrix.md) specifies
the initial generic mechanism set and distinguishes the YubiHSM and
GlobalPlatform card profiles. YubiHSM uses four asymmetric-derived keys and
imports keys through its encrypted channel, with no DEK. Card SCP11 uses the
same X9.63 construction but takes a fifth key for its administration DEK;
its receipt transcript and secure-message framing also differ.

The missing abstraction is a protected base object plus derivation parameters
and an output template atomically creating another chainable device key object.
Generic-secret intermediates, extraction into AES working keys, and the required
agreement, composition, and KDF operations should be generic building blocks,
without introducing an SCP-specific object model. Select the initial mechanism
set from the actual SCP03/SCP11 operation matrix; broader HKDF, SP 800-108,
composition, or other derivation families can use the same foundation.

Prefer bounded volatile native session objects for intermediates and working
AES keys. For the four-key construction described above, a protected 64-byte
result can feed extraction of receipt, S-ENC, S-MAC, and S-RMAC objects without
persisting ephemeral keys. For the local-message client, final KDF outputs must
permit readable working keys from creation, while long-term keys and raw
agreements remain protected; extraction cannot weaken source policy. The capacity and identifiers
must cover the complete operation graph, not assume that only the intermediate
needs session lifetime. Persistent generic-secret and AES output remain useful
for deliberate token-object requests; they are not the default channel-key
lifetime. Any persistent temporary-key fallback requires explicit deletion,
storage bounds, and crash/orphan recovery.

Native session objects must be scoped to authenticated device authority, carry
appropriate capabilities and domain policy, and be cleared on session close,
timeout, authentication replacement or failure, and protocol invalidation. The
provider must retain the native session while dependent PKCS #11 handles exist,
then invalidate those handles when their backing session is lost. Exact command
and object encoding is part of the planned implementation.

`CKA_TOKEN=CK_FALSE` alone does not promise device residence. Current hardware
ECDH outputs use the common host software session layer, which can also perform
AES and MAC operations locally. Native placement and dispatch must be explicit
for device-side derivation. Established channels use local working bytes. Existing physical firmware needs equivalent
native support before that stronger boundary can be claimed.
