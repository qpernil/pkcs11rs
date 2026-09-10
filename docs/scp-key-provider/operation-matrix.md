# SCP client key-provider contract

This is the operation contract for the [implementation plan](README.md), traced
against the existing SCP client. Common composition mechanisms are implemented
as described below. Direct YubiHSM symmetric/asymmetric
derivation uses `Pkcs11Auth` over the Rust handlers shared with the C API;
final working keys are read once for local message crypto. Slot preparation
supports temporary software slots and existing registered slots. Configured
selection, card derivation migration, [named credential lookup](credential-lookup.md),
and native chainable derivation remain planned.

## Actors and scope

The consumer is **pkcs11rs acting as an SCP client**. It owns the handshake,
trust decisions, message framing, counters, and application plaintext. It asks a
key provider to derive the client's channel keys, then uses final working bytes
locally for message crypto. The peer is the
YubiHSM or card/security domain receiving those messages.

```text
                         derivation / handles / final working values
SCP client in pkcs11rs ------------------------------------> key provider
          |                                                  software slot
          | protected messages                               or virtual HSM
          v
     SCP peer: target YubiHSM or card/security domain
```

The provider does not receive an instruction to run an SCP state machine. Its
commands generate, derive, and compose keys and verify the establishment receipt.
The final working outputs explicitly permit value reads; long-term credentials
and raw ECDH results remain protected. A native virtual-YubiHSM
provider needs an independently established connection and authorization: it
cannot depend on the very SCP channel whose keys it is being asked to create.
Implementing the peer role is separate work, although peer fixtures are needed
to qualify the client.

The primary target is the YubiHSM client: symmetric SCP03-compatible and
asymmetric authentication, followed by YubiHSM secure messaging. **YubiHSM has
no DEK**: key-import command payloads travel inside the encrypted channel.
The existing GlobalPlatform card client is another consumer of the same
primitives; its SCP03 S8 and SCP11a/b/c profiles are recorded separately below.
Their administration DEK must not become a requirement on the YubiHSM profile.
SCP03 S16 and unrelated protocol families remain outside this change.

## Source and existing building blocks

The trace follows the [YubiHSM client](../../src/yubihsm.rs),
[card SCP03](../../src/scp03.rs),
[SCP11](../../src/scp11.rs), [administration](../../src/security_domain.rs),
[channel ownership](../../src/connector.rs), and
[PKCS #11 derivation](../../src/api/key.rs). The shared crypto core already
implements CMAC, AES ECB/CBC, SCP03 KDF, ECDH, and X9.63 SHA-256. The PKCS #11
layer already supports AES, CMAC, P-256 generation, ECDH, and HKDF. These are
available primitives, not yet a complete protected-key operation graph.

YubiHSM `SecureSession` retains three local AES values in zeroizing storage.
Direct derivation uses the safe `Pkcs11Auth` interface to the shared Rust
handlers, without crossing the C ABI. SCP03 counter KDF creates readable final AES objects. SCP11 SHA-256
creates readable final KDF blocks; their concatenation and extracted working
AES keys are readable by inheritance. The receipt key is protected and verifies
the receipt before the three working keys are read. All scope objects are
released afterward. Protected inputs are never downgraded or read.

YubiHSM Auth supplies working bytes directly. Platform keys use native ECDH
through the platform slot and the common protected session-object graph.
Card structures retain local working keys and still use direct derivation.
Hardware ECDH outputs in public PKCS #11 operations use software session objects;
the native prefixed extension returns KDF bytes. None establishes native retention
of the entire derivation graph. Mechanism names below specify the intended
API contract; existing public mechanism tests do not constitute client adapter
integration.

Notation: `||` concatenates bytes, `BE16/BE32/BE128` encode unsigned integers
in big-endian order, and `[a:b]` selects byte offsets with an exclusive end.
Numbers written as two hexadecimal digits in layouts are literal bytes.

## YubiHSM client: establishment and all subsequent commands

The target device and the crypto provider have distinct roles, even when both
are virtual YubiHSM instances. This section traces `SecureSession` in
`src/yubihsm.rs`. Its frames are `command[1] || BE16(length) || payload`, not
card APDUs. All working keys are AES-128.

### Symmetric authentication

Bind one protected 32-byte generic-secret credential holding ENC followed by
MAC. `CKM_EXTRACT_KEY_FROM_KEY` creates two derive-only AES-128 session objects
at bit offsets 0 and 128, each with length 16. Existing token objects can be
bound through an authorized provider-session handle; name resolution is planned.
For password login,
the existing credential-input path uses PBKDF2-HMAC-SHA256 with salt `Yubico`,
10,000 iterations, and 32 output bytes, split ENC then MAC. Password processing
is an explicit input boundary; native-only operation after provisioning starts
from provider-held authentication keys. Moving password derivation into a
provider would be an additional PBKDF2 operation, not part of the minimal
post-provisioning mechanism set.

`CreateSession` exchanges eight-byte challenges `H` and `C` and returns a
session ID and card cryptogram. Using `GP` as defined below:

| Step | Secret input | Result |
| --- | --- | --- |
| Derive S-ENC | Static ENC | `GP(ENC,04,H || C,128)` |
| Derive S-MAC | Static MAC | `GP(MAC,06,H || C,128)` |
| Derive S-RMAC | Static MAC | `GP(MAC,07,H || C,128)` |
| Card cryptogram check | S-MAC | `GP(S-MAC,00,H || C,64)` |
| Host cryptogram | S-MAC | `GP(S-MAC,01,H || C,64)` |

`AuthenticateSession` carries `session ID || host cryptogram` and an eight-byte
command MAC. Its initial chain is zero; keep the full command CMAC as the next
chain. Preserve the existing authentication-response handling and cleanup of
failed handshakes. The first encrypted command uses counter one.

### Asymmetric authentication

Generate a client ephemeral P-256 key and bind its authorized static P-256
credential. Produce two protected 32-byte ECDH results:

```text
Ze = ECDH(client ephemeral private, target ephemeral public)
Zs = ECDH(client static private, target static public)
B_i = SHA256(Ze || Zs || BE32(i) || 3c 88 10), i = 1, 2
M = B_1 || B_2                       # exactly 64 bytes
Kreceipt = M[0:16]
S-ENC = M[16:32]; S-MAC = M[32:48]; S-RMAC = M[48:64]
receipt = CMAC(Kreceipt, target ephemeral public || client ephemeral public)
```

The receipt input is two uncompressed P-256 public points (65 bytes each),
without the GlobalPlatform authentication TLVs. Verify all 16 receipt bytes,
initialize the MAC chain from the verified receipt, and start counter one.
Four extracted keys suffice; there is no fifth key and no DEK. See the
[existing prefixed-ECDH mapping](../prefixed-ecdh-derive.md#yubihsm-asymmetric-authentication-mapping).

For identical agreement inputs and shared information, these are the first
four outputs of the card SCP11 construction below: requesting a fifth key
does not alter the earlier X9.63 blocks. Symmetric YubiHSM authentication also
uses the same SCP03 CMAC KDF layout and derivation constants. Receipt inputs
and secure-message processing remain specific to each protocol profile.

YubiHSM Auth helpers currently return three working keys; some platform
credential paths return KDF bytes. Preserve those explicit host-key workflows
by importing their results into the software provider scope. They do not
establish native retention of the derivation graph. A native derivation provider
instead needs protected agreement/composition objects and explicitly readable
working outputs. Message crypto always runs locally.

### Encrypted command/response exchange

All operations in this table run locally with the three working AES values;
there are no provider/API calls during an established channel's message exchange.

| Step | Key/input | Result |
| --- | --- | --- |
| IV | S-ENC, 16-byte big-endian counter | Local AES ECB of one block |
| Encrypt command | S-ENC, IV, ISO 7816 padded inner command frame | AES CBC ciphertext |
| Authenticate command | S-MAC, previous chain followed by outer frame (session ID plus ciphertext; length includes MAC) | Full CMAC becomes chain; send first eight bytes |
| Authenticate response | S-RMAC, command chain followed by response frame excluding MAC but including its length | Check first eight CMAC bytes before decryption; chain unchanged |
| Decrypt response | S-ENC, **same IV as request**, authenticated ciphertext | AES CBC; unpad and parse inner response |

Advance the counter after the completed exchange, including an authenticated
device-command error. Preserve invalidation on transport/MAC/framing failure
and rejection of oversized commands before state mutation. Never apply the
card profile's response-direction IV bit here.

Key-import commands follow this same path: their key material is part of the
encrypted inner payload. There is no separate DEK encryption step. This does
not grant permission to export an existing non-extractable provider object;
the ordinary import workflow receives new material from its caller.

## GlobalPlatform card client: SCP03 establishment

Let `H` and `C` be the eight-byte host and card challenges. Direct static ENC,
MAC, and optional DEK keys have the same AES length: 16, 24, or 32 bytes.
The configured Yubico diversification path instead uses a 32-byte BMK and
produces three 16-byte static keys from the ten-byte issuer context `I`.

For each block `i`, starting at one, define:

```text
GP(K, d, context, Lbits):
    B_i = CMAC(K, 00*11 || d || 00 || BE16(Lbits) || i[1] || context)
    result = (B_1 || B_2 || ...)[0:Lbits/8]

Diversify(BMK, label, I):
    CMAC(BMK, 01 || label[4] || 00 || I[10] || 00 80)
```

The requested length precedes the iteration counter in `GP`; the counter is
not a fixed prefix. Preserve this layout for 192- and 256-bit results too.

| Client step | Inputs | Result and proposed operation |
| --- | --- | --- |
| Acquire credentials | Configured static keys or BMK; explicit authorization | Import once into provider scope, or bind existing authorized handles |
| Diversify static keys | BMK, `I`, labels `00000001/00000002/00000003` | AES-128 ENC/MAC/DEK handles through CMAC counter KDF |
| Generate host challenge | Random source | Eight public bytes; current RNG or provider random operation |
| Check optional pseudorandom card challenge | Static ENC, constant `02`, sequence counter (3 bytes) followed by selected AID | `GP(...,64)`, eight-byte comparison value |
| Derive S-ENC | Static ENC, constant `04`, `H || C` | AES handle of static-key length, CMAC counter KDF |
| Derive S-MAC and S-RMAC | Static MAC, constants `06` and `07`, `H || C` | Two AES handles of static-key length, separate CMAC counter KDF calls |
| Check card cryptogram | S-MAC, constant `00`, `H || C` | `GP(...,64)` compared in constant time |
| Produce host cryptogram | S-MAC, constant `01`, `H || C` | `GP(...,64)`, eight public wire bytes |
| External authenticate | S-MAC, zero chain (16 bytes), `84 82 level 00 10`, host cryptogram | Full CMAC retained as chain; first eight bytes sent |

For the 64-bit public challenge/cryptogram results, one
`CKM_AES_CMAC_GENERAL` operation with output length eight and the explicit
`GP` input (`Lbits=64`, `i=1`) suffices. Do not derive a secret object and
export it merely to obtain these protocol outputs.

## GlobalPlatform card client: SCP11 establishment

All implemented variants use P-256 and AES-128. The client generates an
ephemeral EC private key with derive permission and exports only its public
point (65-byte uncompressed encoding). SCP11a/c additionally bind the client's
static OCE private key and send its public certificate chain.

| Variant | Parameter / key ID / instruction | First agreement KA1 | Second agreement KA2 |
| --- | --- | --- | --- |
| SCP11a | `01 / 11 / 82` | Client ephemeral × card ephemeral | Client static × card static |
| SCP11b | `00 / 13 / 88` | Client ephemeral × card ephemeral | Client ephemeral × card static |
| SCP11c | `03 / 15 / 82` | Client ephemeral × card ephemeral | Client static × card static |

Each agreement uses `CKM_ECDH1_DERIVE` with `CKD_NULL`, producing a protected
32-byte generic secret. Preserve leading zero bytes. Certificate validation
and trust selection remain in the client; the provider must also validate
the supplied point for its curve.

```text
Z = KA1 || KA2                         # 64 bytes, in this order
B_i = SHA256(Z || BE32(i) || 3c 88 10) # i = 1, 2, 3
M = (B_1 || B_2 || B_3)[0:80]

Kreceipt = M[0:16]
S-ENC    = M[16:32]
S-MAC    = M[32:48]
S-RMAC   = M[48:64]
DEK      = M[64:80]
```

This is X9.63 SHA-256 over **both** agreements; running the existing ECDH KDF
over one agreement is insufficient. HKDF is not part of this profile.

Protected concatenation creates `Z`; appending the public counter and shared
information then hashing the resulting protected object creates each `B_i`.
For local working-key consumption, request readable hash blocks and their
concatenation, then extract five AES-128 objects with appropriate output policy. A 96-byte intermediate
can directly supply the five slices; the unused last 16 bytes need no object.
This is a generic-mechanism construction, not a requirement to add an
SCP-specific derivation command. A later generic protected X9.63 operation can
optimize the number of calls without changing the profile.

Verify the full 16-byte CMAC under Kreceipt of
`request_data || card_ephemeral_TLV`. `request_data` contains the encoded A6
parameters and client 5F49 public-point TLV; the response contributes its
original validated 5F49 TLV. Preserve the encoded bytes, not just the EC points.
The verified receipt initializes the secure-message chain. Release Kreceipt,
agreements, ephemeral private key, and composition intermediates after their
last use. Keep S-ENC, S-MAC, S-RMAC, and DEK for the channel lifetime.
SCP11b still derives DEK, but does not gain OCE-authenticated administration.

## GlobalPlatform card client: protected traffic and administration

The following local operations apply to established card SCP03 and SCP11
channels, subject to the selected security level. SCP11 uses level `33`.

| Client step | Key and input | Operation and boundary |
| --- | --- | --- |
| Command IV | S-ENC, `BE128(counter)` | AES ECB, one block; output IV is public protocol state |
| Response IV | S-ENC, same counter with high bit of first byte set | AES ECB, one block |
| Command encryption | S-ENC, command IV, ISO 7816 padded plaintext | AES CBC without PKCS padding; return ciphertext |
| Command authentication | S-MAC, previous full chain followed by normalized header/Lc and protected data | Full CMAC; retain 16-byte chain, transmit first eight bytes |
| Response authentication | S-RMAC, command chain followed by response ciphertext/data and two-byte status | Verify eight-byte CMAC before decryption |
| Response decryption | S-ENC, response IV, authenticated ciphertext | AES CBC, then client removes ISO 7816 padding |
| SCP03 PUT KEY | DEK, caller-supplied new ENC/MAC/DEK | AES CBC, zero IV, no padding; existing workflow requires all keys to be AES-128 |
| New-key check values | Each new AES key, 16 bytes of `01` | AES ECB; first three output bytes form the KCV |
| SCP11 private-key provisioning | DEK, caller-supplied supported EC scalar | AES CBC, zero IV, no padding; retain current AES-128 DEK and block-aligned scalar constraints |

Protect each logical command before transport fragmentation. Increment its
counter once, preserve existing extended-Lc encoding, and authenticate an
assembled response before exposing plaintext. Preserve the supported empty
unprotected error-status responses. Receipt/MAC rejection, counter exhaustion,
ambiguous transport failures, or invalid framing invalidate the channel.

Provisioning accepts new secret bytes explicitly supplied by the caller; this
is an input boundary, not permission to read existing keys through `CKA_VALUE`.
The new caller-supplied keys' KCVs can be calculated locally. Fully protected
transfer of a provider-generated provisioning key would additionally need a
permitted key-wrapping operation with the exact PUT KEY wire format. That is
a separate gap from preserving the existing caller-supplied workflow; do not
pretend generic encryption exports a non-extractable key legally.

Public certificate processing, on-card key-generation commands, and admin
APDU construction stay in the client. DEK access becomes a handle operation;
the current raw `static_dek()` accessor must disappear from the consumer.

## Required generic mechanism set

| Mechanism | Required use |
| --- | --- |
| `CKM_SP800_108_COUNTER_KDF`, AES-CMAC PRF | SCP03 static diversification and working-key derivation, returning AES objects |
| `CKM_CONCATENATE_BASE_AND_KEY` | Compose KA1/KA2 and digest blocks as generic-secret objects |
| `CKM_CONCATENATE_BASE_AND_DATA` | Append the public counter/shared-info bytes to protected Z |
| `CKM_SHA256_KEY_DERIVATION` | Hash a protected generic secret into a 32-byte generic secret |
| `CKM_EXTRACT_KEY_FROM_KEY` | Produce AES-128 objects at bit offsets 0, 128, 256, 384; also 512 for card SCP11's DEK |

Use the standard concatenation, hash-derivation, and extraction semantics;
extraction's offset is in **bits**, while output `CKA_VALUE_LEN` is in bytes.
See the [OASIS mechanism definitions](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html).

For counter KDF, ordered byte-array fields surround one
`CK_SP800_108_ITERATION_VARIABLE` with an eight-bit big-endian counter and a
16-bit big-endian `CK_SP800_108_DKM_LENGTH` using `SUM_OF_KEYS`. This expresses
both layouts above, including requested length 192 rather than rounded-up
CMAC block length. `CK_SP800_108_COUNTER` is invalid in counter mode.
See [OASIS SP 800-108 mechanisms](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html).

The two concatenation mechanisms, extraction, SHA-256 key derivation, and
single-output AES-CMAC counter KDF are implemented in the common layer,
subject to the slot's software filter. Counter KDF can also use a protected
YubiHSM AES base through native AES-ECB-backed CMAC, without reading the base
value or requiring its public sign/encrypt flags. The result is a common session
object. Native chainable composition objects remain unimplemented. Mechanism
advertising does not promise where an individual operation executes.

### Implemented composition behavior

Inputs and outputs use ordinary software secret objects, including protected
session keys on hardware slots. No native key is exported for these operations.
Both key inputs must be visible in the slot and permit derivation and the
selected mechanism; both derive-template policies constrain a concatenated
result. Creation, storage, and creator-session cleanup use the common layer.

Supported base and output sizes are 1–1024 bytes, subject to key-type limits;
SHA-256 output is at most 32 bytes. Concatenation takes a requested prefix.
Extraction numbers bits from the most significant bit, accepts a starting
offset within the source, and wraps at its end; output cannot exceed source
length. An explicit variable-length key type requires `CKA_VALUE_LEN`.
Extraction also requires a length when the type is omitted. 3DES has an
implicit 24-byte size and its derived parity bits are adjusted.

Concatenation and extraction inherit sensitivity/non-extractability; conflicting
explicit templates fail. Their history flags preserve the source history
(the intersection for two inputs). SHA-256 derivation follows its separate
standard rules permitting caller-selected output protection. The YubiHSM
client requests readable final hash results for local working-key consumption;
protected-object regression graphs separately request protected hash results.
Errors publish no output object. Tests cover the standard wrapping bit-extract
example, SHA-256 known answers, policy/history rules, scope and cleanup, and
the complete protected X9.63 composition graph followed by AES-CMAC.

### Implemented CMAC counter KDF profile

`CKM_SP800_108_COUNTER_KDF` accepts an AES-128/192/256 software or YubiHSM base
key with derive permission. Both use the same CMAC callback-based KDF engine.
For YubiHSM keys, CMAC uses device AES-ECB operations; the base key is never
exported. The device key needs `encrypt-ecb` capability, but PKCS #11 authorization
requires `CKA_DERIVE` and permission for the KDF mechanism, not `CKA_SIGN`,
`CKA_ENCRYPT`, or permission for the standalone CMAC mechanism. Imported/generated
derive-only AES token keys receive that device capability; PKCS #11 metadata
preserves their narrower usage policy. Derived objects live in the common module
session layer, not native YubiHSM volatile object storage.

Two protected persistent AES keys (ENC/MAC) can therefore be counter-KDF bases
without first splitting a generic secret. This avoids reading a long-term
32-byte credential on devices without native protected extraction. The selectable
PKCS #11 authentication adapter and its paired-key lookup remain planned.

Its mechanism information reports the base-key range as
128–256 **bits**, as required by the standard; object `CKA_VALUE_LEN` and KDF
output lengths remain byte counts. It returns one ordinary typed secret object, 1–1024 bytes
subject to the output key type. Variable-length types require `CKA_VALUE_LEN`;
3DES can infer its fixed 24-byte length. Output sensitivity and extractability
come from the template/defaults, constrained by the base's derive template;
always/never history follows the standard derivation rules.

The supported PRF is `CKM_AES_CMAC`. The parameter array contains one iteration
counter, at most one DKM length, and public byte arrays in caller-specified
order. Counters support 8/16/24/32 bits, and length fields 8–64 bits in steps
of eight, with either byte order. `SUM_OF_KEYS` encodes requested bits;
`SUM_OF_SEGMENTS` encodes the generated CMAC blocks, including a discarded
suffix. A 192-bit SCP03 key therefore requires `SUM_OF_KEYS`, not 256 bits.

Input is bounded to 64 fields and 65,536 encoded bytes. Additional output-key
arrays, other PRFs, feedback/double-pipeline KDFs, optional-counter fields, and
key-handle input fields are unsupported and rejected without publishing a key.
Each SCP03 working key uses a separate derivation with its own constant, so
the supported profile covers the operation matrix without extra-output arrays.
The reusable implementation lives in software-key-core; pkcs11rs owns the
ABI parser, key policy, and publication/cleanup.

## Object policy and internal boundary

Long-term credentials, private EC keys, raw agreements, and their concatenated
KDF inputs are sensitive and non-extractable. Final SCP03 counter-KDF outputs
and SCP11 hash blocks explicitly have `CKA_SENSITIVE=false` and
`CKA_EXTRACTABLE=true`. Concatenation and extraction preserve that policy for
working-key reads. Receipt verification can strengthen its extracted key to
sensitive/non-extractable, without changing the source. All temporary objects
have session lifetime. Existing object protection is never weakened.

| Object role | Type / length | Use |
| --- | --- | --- |
| BMK | AES / 32 | Derive |
| Static ENC | AES / 16 for YubiHSM; 16, 24, 32 for cards | Derive; optional card challenge check |
| Static MAC | AES / 16, 24, 32 | Derive |
| Client EC private keys | EC / P-256 | Derive |
| Agreements, Z, digest inputs | Generic secret / 32, 64, 71 | Protected derivation |
| Final digest blocks and concatenation | Generic secret / 32, 64 (96 for cards) | Readable derivation output; no client value read |
| S-ENC | AES / profile length | Read once; local ECB/CBC encryption/decryption |
| S-MAC | AES / profile length | Read once; local cryptograms and command CMAC |
| S-RMAC | AES / profile length | Read once; local response verification |
| Kreceipt | AES / 16 | Protected full receipt verification, then destroy |
| DEK (card profiles only) | AES / profile length | Separate administration policy; static SCP03 DEK must not be treated as an exportable session key |

Preserve every mechanism's sensitivity, extractability, and history rules,
including both inputs to composition. Source derive-template restrictions must
also permit the requested outputs. Do not change general PKCS #11 rules to make
a particular SCP graph work. A policy prohibiting final value reads fails;
there is no fallback execution mode. Non-extractability alone is not protection
against a caller authorized to derive arbitrary readable outputs.

The [PKCS #11 key scope](../../src/key_scope.rs) owns session and object
handles, not key material. The [Pkcs11Auth trait](../../src/pkcs11_auth.rs)
accepts Rust templates, slices, and typed derivation parameters and returns
`Result` values. It calls the handlers shared with the C exports for every slot
kind, including full nested-template validation and ordinary authorization.

[Provider preparation](../../src/pkcs11_provider.rs) supplies either a private
nonpersistent software slot or a routing view sharing an existing slot. Calls
select that view for their synchronous duration and suppress internal tracing;
selection is thread-local and restored after nested calls or unwinding. No
public module lock is required for the prepared view. Slot and device locks
still apply, so providers must be prepared and independently authorized before
target operations; configured resolution must reject dependency cycles.

A retained direct credential or agreement has a dedicated owning session;
a separate handshake session owns temporary objects. Moving a retained result
copies it inside the module with unchanged policy before deleting the original.
Existing token credentials are bound by handle, without copying or taking
ownership of token deletion. Closing the creator session destroys its session
objects. The last private-provider reference releases the temporary slot.
Reading all three working keys consumes the handshake scope, including on a
partial read failure. Working storage uses zeroizing arrays and has no provider
handles or secret-bearing Debug implementation. Ordinary PINs are not cached;
follow the [authentication policy](../authentication-secrets.md).

Provider references and transient handles are valid only within their object
and authorization lifetimes. An established channel's exported working keys
have a separate local lifetime: provider removal cannot revoke already-read
bytes. Channel close or protocol/transport failure clears them. Authenticated
device-command errors keep the channel usable; local validation errors leave
its keys, counters, and MAC chain intact. Reconnection never silently recreates
lost working keys. Preserve transaction-scoped CCID lifetimes for card channels.

## Implementation order and acceptance checks

See the [staged plan](README.md) for implementation order: connect configured
provider selection and credential lookup, migrate card derivation, implement
native virtual-HSM derivation, then qualify full channels with local message
crypto. Instrumented tests must show final working-key reads at establishment and no
provider calls for subsequent message encryption/MAC.

The discovery-disabled Cargo suite passes with 758 main-library tests and
27 ignored. Public mechanism tests exercise protected and readable SCP03/X9.63
graphs on every slot kind. The YubiHSM fixed wire vectors exercise local working
keys; deterministic asymmetric fixtures compare the complete derivation against
an independent raw-key reference confined to tests. Persistent-source tests
verify that temporary bindings never delete the credential. Scope tests cover
policy denial, protected inputs, readable final outputs, atomic failures,
history, destruction, and stale/cross-scope handles. Channel tests cover bad
receipts/MACs, transport failure, close, and loss of local key storage without
transport activity or key recreation. See [integration](../../integration/README.md)
for the external PKCS #11/client suites.

The existing-slot regression prepares a registered YubiHSM protocol fixture,
uses its independently established login and native AES key for counter KDF,
and verifies native ECB commands without exporting the base key. It exercises
this path while the public module lock is held and confirms that closing the
authentication sessions preserves the original public session and token key.

The [complete-channel matrix](../../src/yubihsm/tests/pkcs11_auth.rs) runs both
symmetric and asymmetric authentication through the same client orchestration
for private and existing-slot preparation. The existing slot has an encrypted
software backing store, a pre-existing public-module application session, and
a protected token credential; the private slot holds its credential as a session
object without a backing store. The target is an independent virtual YubiHSM
protocol peer. Checks cover repeated encrypted echo messages, response-MAC
rejection and invalid-channel behavior, bad card cryptograms/receipts, target
session cleanup, credential reuse, unchanged source sessions/objects after each
attempt, and working-key cleanup. After releasing all auth-owned provider
references, established target channels still exchange messages using local
working keys. The existing-slot case preserves its application session and
source token credential until normal fixture teardown. No physical device is
modified by these tests.
