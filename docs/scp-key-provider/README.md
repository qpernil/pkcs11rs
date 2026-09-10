# Plan: SCP03/SCP11 derivation through PKCS #11

## Goal and boundary

Keep long-term credentials in a selected PKCS #11 token, derive channel-specific
working keys through the shared Rust PKCS #11 API, then read those final keys once and perform
message encryption, decryption, and MAC locally in the SCP client. This is one
execution path, with no message-crypto placement option.

The SCP client owns the handshake, trust decisions, public transcripts, counters,
framing, and local message crypto. The derivation provider owns the long-term
credential, protected agreement inputs, and intermediate objects. After an
established channel obtains S-ENC, S-MAC, and S-RMAC, message processing does not
call the provider. The working bytes use zeroizing storage for the channel
lifetime; they are never reusable login credentials.

The provider and the target receiving protected commands have distinct roles.
A virtual YubiHSM can supply the client's derivation operations over an
independently authorized connection. The target also performs its own end of
secure messaging. YubiHSM key imports travel inside the channel and require no
DEK. GlobalPlatform card administration has a separate DEK requirement.

Protecting long-term credentials is the main objective. Local working keys
avoid per-message provider/device round trips, but compromise of client memory
can expose that channel's keys. No performance numbers or physical isolation
are implied by software providers. A PKCS #11 session object describes lifetime,
not execution location.

## Implemented foundation

All slot kinds share common software session objects: software, YubiHSM, PIV,
OpenPGP, FIDO2, and platform ECDH. Supported software keys, data objects, derivation outputs,
and operations use this common layer. A software slot has no native mechanisms;
each hardware slot's native list is merged with a filtered software list.
The union combines operation flags and size ranges and preserves native
`CKF_HW`; this does not establish where a particular operation executes.

Public PKCS #11 entry points implement protected concatenation, bit extraction,
SHA-256 key derivation, and AES-CMAC SP 800-108 counter KDF. Existing ECDH,
EC generation, AES, and CMAC complete the required generic primitives.
Tests exercise protected and readable derivation graphs through the actual
public API on all slot kinds. See the [operation matrix](operation-matrix.md)
and [integration baseline](../../integration/README.md).

The YubiHSM client uses the ergonomic `Pkcs11Auth` session API for direct
symmetric and asymmetric derivation. Its implementation calls the same Rust
handlers as the public C entry points, including session routing, object policy,
and mechanism dispatch. It does not cross the C ABI or emit internal FFI traces.

Preparation supplies a session on either a temporary software slot or an existing
slot. The existing-slot adapter shares the backend, authorization, objects, and
handle allocator; it never copies the token or its credentials. Direct password
authentication creates an isolated, nonpersistent software slot and imports its
credential as a session object. It uses the ordinary `SoftwareSlot` without a
backing store; token-object creation remains write-protected. A dedicated
credential session and separate handshake sessions provide the required lifetimes.
Both preparation paths use the same derivation and session cleanup operations.
The enabled platform slot supports exact label lookup and public-key matching;
selection across arbitrary configured providers remains planned; native chainable
protected-object commands remain unimplemented.

The [complete-channel tests](../../src/yubihsm/tests/pkcs11_auth.rs) run the same
symmetric and asymmetric establishment sequence with a private slot and an
existing persistent software slot registered in the public module. A separate
YubiHSM protocol fixture covers native protected AES counter derivation. These
are distinct checks: complete authentication with a hardware-backed source
credential and configured source lookup still need end-to-end qualification.

## Current YubiHSM flow

Symmetric authentication binds one protected 32-byte generic secret containing
K-ENC followed by K-MAC. Protected extraction produces the two static AES
objects. Counter KDF produces three explicitly readable AES working objects.
Their values are read once into the client's zeroizing storage, and the
entire derivation scope is destroyed. Host/card cryptograms use local S-MAC.

Asymmetric authentication binds a protected P-256 private credential, generates
an ephemeral private key, and performs both ECDH agreements into protected
generic-secret objects. Their concatenation and the per-block counter/shared-info
inputs remain protected. SHA-256 derivation explicitly creates readable final
KDF blocks, which concatenate into readable material. This is necessary because
concatenation and extraction inherit source sensitivity/non-extractability.
No existing object's protection is weakened.

The receipt key is extracted as a protected AES object and verifies the complete
receipt before working keys are released. S-ENC, S-MAC, and S-RMAC are extracted
as readable AES objects and read once. The provider scope, including the
receipt key, ephemeral key, KDF blocks, and agreements, is destroyed on success
or failure. Only the final three AES values cross into message processing.

Platform credentials use native ECDH token objects and the same protected
session-object graph through `Pkcs11Auth`. Only explicitly enabled platform
slots participate in named or automatic lookup. `ClientAuth` covers temporary
direct credentials and token bindings on existing source slots. YubiHSM Auth
credentials are selected through ordinary slot objects; the owning PKCS #11
session exposes a native Rust operation for the applet protocol. That operation
returns the three working keys without entering the C FFI.
The explicit recreation policy retains the applicable credential binding;
see [authentication secrets](../authentication-secrets.md).

All YubiHSM channels use local AES ECB/CBC and CMAC. Response authentication
precedes decryption. Successful close and failed exchanges erase working keys;
authenticated device-command errors advance the channel and preserve its keys.
Local command-validation errors leave it intact. Card SCP03/SCP11 message crypto
also runs locally; their derivation graphs still need migration.

## 1. Connect configured provider selection and named lookup

Connect discovery/configuration to the existing `Pkcs11Provider::from_slot`
preparation path and `BoundKey::from_session` binding. Authorize provider sessions
before acquiring target slot/device locks. The prepared view avoids recursive
public-module locking and suppresses internal tracing; it does not remove the
need to reject direct and indirect provider dependency cycles. Preparation of a
source slot whose mutex is already held fails rather than waiting on itself.

Use the [named credential design](credential-lookup.md): one exact label within
one provider identifies a protected generic32 symmetric credential or P-256
private credential. Missing or duplicate matches, wrong types, and incompatible
output policies fail explicitly. Do not retain ordinary provider PINs to recover
lost sessions; define authorization leases and revocation before integration.

Derivation templates must permit the intended final value reads from creation.
Use `CKA_SENSITIVE=false` and `CKA_EXTRACTABLE=true` on readable outputs, and
honor all source restrictions. A provider that prohibits those outputs is
incompatible with this client path; do not silently change policy or fall back
to a different execution mode. Release intermediate objects after use and read
only final working keys in the generic path, never long-term keys. Platform ECDH outputs follow the same session-object policy.

Acceptance: the YubiHSM client completes symmetric/asymmetric authentication
through a separately configured slot. Instrumented tests show derivation and
final value reads at establishment, with no provider calls during message processing.
Tests cover missing credentials, duplicates, policy denial, failed receipts,
partial reads, source revocation, cleanup, and unchanged wire vectors.

## 2. Migrate card derivation

Route the existing card SCP03 S8 and SCP11a/b/c derivation graphs through the
same API adapter while preserving their distinct transcripts, IV direction bit,
security levels, and native smart-card transaction lifetime. Local encryption
and MAC continue to use the derived channel keys.

Card SCP11 derives a fifth key, DEK. Card SCP03 has a static administration DEK;
its access policy must be handled separately rather than exporting a long-term
key as if it were a disposable channel key. Existing caller-supplied provisioning
material and KCV calculation remain an explicit input workflow. SCP03 S16 and
unrelated protocol families are outside this plan.

Acceptance: card protocol vectors, receipt validation, provisioning, and
transaction-lifetime regressions pass. No long-term credential is exported to
implement derivation or administration.

## 3. Implement native virtual-YubiHSM derivation

Add generic protected-object commands using software-key-core: agreement,
composition, extraction, and counter/hash KDF. Reuse the same operation graph
and source policies as the software provider. The existing prefixed-ECDH command
returns KDF bytes and alone does not provide the generic chainable contract.

Provide persistent generic-secret/private-key storage with exact label lookup,
and bounded volatile intermediate/output objects. Define capabilities, domains,
policy inheritance, identifiers, atomic creation, audit behavior, expiration,
and cleanup together. Avoid NVM writes for channel establishment and teardown.
Native backing-session loss invalidates dependent handles without rebinding
stale identifiers. Only policy-permitted final working values are exported.

Map these native operations into the PKCS #11 provider. A merged mechanism list
or `CKF_HW` alone is insufficient proof of native derivation; verify object
placement and command traces. Unsupported native operations fail explicitly.
The provider needs no per-message AES/CMAC traffic for this client workflow.

## 4. Qualify complete channels with virtual-HSM derivation

Use a virtual YubiHSM as the client's derivation provider and a compatible peer
as the target. After provisioning, long-term credentials and ECDH secrets stay
behind the provider interface; only final working keys are read into the client.
Exercise establishment, multiple locally protected exchanges, and teardown for
the supported YubiHSM and card profiles.

Completion requires identical protocol results with software and native
providers; explicit policy and authorization failures; no leaked transient
objects or usable stale handles; no provider/device message-crypto calls; and
passing PKCS #11/client regressions. Reconcile commands, object policy, and
lifetime documentation in both repositories. Use disposable virtual fixtures
for destructive/exhaustion tests and keep physical devices intact.
