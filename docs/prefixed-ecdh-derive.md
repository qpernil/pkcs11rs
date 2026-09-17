# Protected prefixed ECDH derivation

`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` performs ECDH, prefixes the raw agreement
with caller-supplied bytes, and applies a mandatory ANSI X9.63 KDF in one
PKCS #11 `C_DeriveKey` operation. Its parameters contain one peer public key
and prefix bytes; no second key handle is needed. A supporting virtual YubiHSM
executes the `DeriveEcdhKdf` extension without exposing its raw ECDH result.
Other supported ECDH sources use the module's common KDF implementation.
This mechanism is the middle of the three ordinary credential-placement paths;
see [client ECDH placement and security](client-ecdh-security.md) for their
selection order and protocol-specific security properties.

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

The common software mechanism set includes this operation. Software, host,
PIV/OpenPGP, and physical YubiHSM ECDH keys can use it when their per-key
permissions allow ECDH. A YubiHSM slot lists the mechanism when it supports an
eligible curve. Whether a particular YubiHSM key uses the native command or
provider-side composition is determined by its capability bits, not by an
algorithm marker. The supported curves are P-224, P-256, P-384, P-521,
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

With the native extension, the reusable raw ECDH secret remains inside the HSM.
With physical YubiHSM or host keys, native ECDH returns the raw agreement to
the module, which applies the KDF in zeroizing memory. It never returns the
static agreement to the authentication client. The final KDF output is
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

Existing-slot authentication first selects the native protected session-object
graph when the source can retain both agreements. Otherwise, it selects this
mechanism when the credential's computed `CKA_ALLOWED_MECHANISMS` permits it.
The client then derives and reads the ephemeral agreement `P` and supplies it as
prefix bytes for static ECDH plus KDF. If neither protected graph nor this
mechanism is available, ordinary ECDH supplies the compatibility path.
Operational failures are returned without retrying a weaker path. Direct
password authentication and recreation use the same capability selection.
Recreation retains a protected private-key credential and recomputes ECDH;
static agreements are scoped to the handshake.

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
`S-MAC`, and `S-RMAC`. The complete client test generates the protected static
key through PKCS #11 and provisions its public half as an asymmetric
Authentication Key on a second virtual YubiHSM. A total credential wildcard
resolves that source through the ordinary `C_LoginUser` client path. When both
protected session objects and literal prefix derivation are permitted, the test
verifies that the protected graph wins. Logout releases the retained source
session and its transient objects.

An environment-driven persisted-device qualification complements that isolated
regression. Separate P-256 credentials force native `DeriveEcdhKdf`, the
module's combined prefixed mechanism over raw device ECDH, and the standard
PKCS #11 operation graph. Its test-only route observer asserts which path ran
without logging secure-channel frames. All three routes complete authenticated
commands against physical YubiHSM firmware from desktop and iOS clients.

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

When the literal-prefix extension is used, the source HSM performs static ECDH
and the complete X9.63 KDF. Its reusable static ECDH result never crosses the
device boundary. The ephemeral agreement, transcript, and final keys remain
visible to the client process. The stronger protected session-object path also
keeps the ephemeral agreement inside the source device.

Retaining every externally visible input and all output keys compromises the
corresponding live session. A saved literal prefix does not establish a later
target session without the source HSM, but it can reconstruct the old session
if the client static private key is compromised later. The protected graph
prevents that staged reconstruction by never exporting the ephemeral agreement.

This mechanism does **not** claim that the final session keys remain inside the
source HSM.

## Native protected-key composition

The [SCP03/SCP11 key-provider design](scp-key-provider/README.md) uses one
protocol implementation with interchangeable software and native key providers.
The native path protects long-term credentials and agreement inputs during
derivation, then permits final working-key reads for local message crypto. There
is no message-crypto placement option. The one-shot command returns KDF bytes to
the host; the virtual YubiHSM supplies generic chainable device objects.

The [client operation matrix](scp-key-provider/operation-matrix.md) specifies
the initial generic mechanism set and distinguishes the YubiHSM and
GlobalPlatform card profiles. YubiHSM uses four asymmetric-derived keys and
imports keys through its encrypted channel, with no DEK. Card SCP11 uses the
same X9.63 construction but takes a fifth key for its administration DEK;
its receipt transcript and secure-message framing also differ.

The native abstraction takes a protected base object, mechanism parameters, and
an output template and atomically creates another chainable object. It supports
volatile P-256 generation and ECDH, generic-secret intermediates, key/data
composition, SHA-256, SP 800-108 counter KDF, extraction into AES working keys,
AES-CMAC verification, controlled reads, and deletion without an SCP-specific
object model.

Bounded volatile native session objects hold intermediates and working AES keys.
For the four-key construction described above, a protected 64-byte
result can feed extraction of receipt, S-ENC, S-MAC, and S-RMAC objects without
persisting ephemeral keys. For the local-message client, final KDF outputs must
permit readable working keys from creation, while long-term keys and raw
agreements remain protected; extraction cannot weaken source policy. Each
authenticated secure session holds at most 64 such objects. Their random,
nonzero 64-bit handles are never persisted or valid in another secure session.

Native session objects are scoped to authenticated device authority, carry
explicit readable/derive/verify policy, and are cleared on session close,
timeout, authentication replacement or failure, and protocol invalidation. The
provider retains the native session while dependent PKCS #11 handles exist,
then invalidates those handles when their backing session is lost.

`CKA_TOKEN=CK_FALSE` alone does not promise device residence. Physical YubiHSM
firmware uses the common host software session layer for outputs that it cannot
hold. A virtual device advertising actual virtual key algorithms uses explicit
native placement for the supported graph and reports those mechanisms with `CKF_HW`. Readable
outputs needing software-only operations are materialized once; protected
outputs are never downgraded. Established channels use local working bytes.
