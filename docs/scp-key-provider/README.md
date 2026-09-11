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

Ordinary slot kinds share common software session objects: software, YubiHSM, PIV,
OpenPGP, FIDO2, and platform ECDH. Supported software keys, data objects, derivation outputs,
and operations use this common layer. A software slot has no native mechanisms;
each hardware slot's native list is merged with a filtered software list.
The union combines operation flags and size ranges and preserves native
`CKF_HW`; this does not establish where a particular operation executes.

Public PKCS #11 entry points implement protected concatenation, bit extraction,
SHA-256 key derivation, and AES-CMAC SP 800-108 counter KDF. Existing ECDH,
EC generation, AES, and CMAC complete the required generic primitives.
Tests exercise protected and readable derivation graphs through the actual
public API on ordinary slot kinds; native HSM Auth uses its dedicated operation. See the [operation matrix](operation-matrix.md)
and [integration baseline](../../integration/README.md).

The YubiHSM client uses the ergonomic `Pkcs11Auth` session API for direct
symmetric and asymmetric derivation. Its implementation calls the same Rust
handlers as the public C entry points, including session routing, object policy,
and mechanism dispatch. It does not cross the C ABI or emit internal FFI traces.

Preparation supplies a session on either a temporary software slot or an existing
slot. The existing-slot adapter shares the backend, authorization, objects, and
handle allocator; it never copies the token or its credentials. Direct password
authentication creates an isolated, nonpersistent software slot containing
two protected AES-128 keys and a protected P-256 private key, derived using
the existing Yubico password conventions. All three are session objects
owned by one preparation session; authentication selects the target key type
and uses the creation handles directly, without name lookup.
The unused credential is discarded after the attempt. The ordinary
`SoftwareSlot` is used without a backing store; token-object creation remains write-protected. A dedicated
credential session and separate handshake sessions provide the required lifetimes.
Both preparation paths use the same derivation and session cleanup operations.
Existing ordinary source slots support exact named lookup and asymmetric
public-key matching. Native HSM Auth slots use the profile and credential types
described in [named lookup](credential-lookup.md). Native chainable
protected-object commands remain unimplemented.

The [complete-channel tests](../../src/yubihsm/tests/pkcs11_auth.rs) run the same
symmetric and asymmetric establishment sequence with a private slot and an
existing persistent software slot registered in the public module. A separate
YubiHSM protocol fixture covers native protected AES counter derivation. These
are distinct checks: configured source selection is exercised with persistent
software credentials; the opt-in physical test below qualifies complete
authentication using a native YubiHSM source key. PIV and OpenPGP protocol
fixtures exercise native ECDH through their slot implementations, and host
fixtures exercise the OS-backed key interface.

## Current YubiHSM flow

Symmetric authentication binds two protected AES-128 objects, Key-ENC and
Key-MAC. Counter KDF uses the source AES objects directly and produces three
explicitly readable AES working objects. No source value read or extraction
is needed, including for native YubiHSM AES keys. The resulting working-key
values are read once into the client's zeroizing storage, and the
entire derivation scope is destroyed. Host/card cryptograms use local S-MAC.

Asymmetric authentication binds a protected P-256 private credential and generates
an ephemeral private key. Existing-slot credentials prefer
`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` when advertised and permitted by the key.
The ephemeral agreement is explicitly readable and supplied as prefix bytes;
static ECDH and X9.63 remain one operation. The static agreement is never read
by the authentication client. A supporting native HSM keeps it device-side;
physical YubiHSM and host keys use zeroizing module memory for the KDF.

If the combined mechanism is unavailable or excluded by key policy, both
agreements use protected generic-secret objects. Concatenation and public
counter/shared-info inputs remain protected; SHA-256 derivation creates readable
KDF blocks, which concatenate into readable material. No existing object's
protection is weakened, and a failed combined operation does not trigger fallback.
Direct password authentication uses the same mechanism selection. When recreation
is enabled, it retains the protected private-key credential and repeats ECDH
for each handshake; no static agreement is retained between handshakes.

The receipt key is extracted as a protected AES object and verifies the complete
receipt before working keys are released. S-ENC, S-MAC, and S-RMAC are extracted
as readable AES objects and read once. The provider scope, including the
receipt key, ephemeral key, KDF blocks, and agreements, is destroyed on success
or failure. Only the final three AES values cross into message processing.

Platform credentials use native ECDH token objects and the same mechanism
selection through `Pkcs11Auth`. Only explicitly enabled platform
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

## 1. Configured provider selection and named lookup

The YubiHSM client selects registered source slots through public credential
metadata, then authorizes exactly one selected source. Native HSM Auth slots
advertise `CKP_YUBICO_HSMAUTH`; ordinary slots provide P-256 token keys or named
AES pairs. See [source selection](../yubihsm-auth.md#generic-source-selection-and-authorization)
for selector syntax, supported sources, and login behavior.

`Pkcs11Provider::from_slot` shares the source backend, authorization and object
handles. The prepared view avoids recursive public-module locking and suppresses
internal tracing. Preparation fails if the source slot mutex is already held;
a target cannot bootstrap its source through itself. Ordinary source PINs are
not retained. Existing authorization and key bindings remain subject to source
logout, replacement and session loss.

Derivation templates permit the intended final value reads from creation,
using `CKA_SENSITIVE=false` and `CKA_EXTRACTABLE=true` while honoring source
restrictions. Incompatible policy fails without fallback. Intermediate objects
are released after use; only final working keys leave the generic derivation
path. Instrumented software-source tests cover both protocols, wrong PINs,
authorization reuse, channel recreation, and source-object preservation.
Platform and native-source tests cover public ambiguity before authorization;
native tests count password-bearing requests to verify no candidate fallback.

Remaining qualification includes additional real hardware source-to-target combinations
and provider dependency-cycle handling across retained bindings. Card protocol
migration and virtual-token-native operations follow below.

### Physical YubiHSM-to-YubiHSM regression

`yubihsm_to_yubihsm_asymmetric_authentication` is an ignored, explicitly
provisioning test. Set `PKCS11RS_CROSS_HSM_SOURCE` and
`PKCS11RS_CROSS_HSM_TARGET` to distinct local USB serials, and supply the
existing bootstrap login strings in `PKCS11RS_CROSS_HSM_SOURCE_PIN` and
`PKCS11RS_CROSS_HSM_TARGET_PIN`. If bootstrap authentication uses a YubiKey,
include its serial in the comma-separated `PKCS11RS_CROSS_HSM_HELPERS` list.
The bootstrap credentials need permission to generate/delete the temporary
source key and create/delete the target authentication key.

```sh
cargo test --lib yubihsm_to_yubihsm_asymmetric_authentication -- --ignored --nocapture
```

The test generates a sensitive, non-extractable P-256 source token key,
registers its public point as a temporary target authentication key, and logs
into the target with the explicitly named source credential. It verifies
public/private ID pairing, raw and prefixed derivation permissions, protected
random requests, and an encrypted echo. Cleanup deletes only the temporary
objects and compares both native inventories with their initial snapshots.
It never resets a device. Assertion failures also attempt cleanup; process
termination or device removal can prevent cleanup from completing.

Physical devices 1238075073 and 2545354682 passed authentication and protected
commands in both source/target directions, bootstrapped through the existing
`shared` YubiHSM Auth credential on YubiKey 37070618. Both devices' native
inventories matched their pre-test snapshots after cleanup.

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

## Future direction: external PKCS #11 sources

Explore adapting a separately loaded PKCS #11 module as an authentication
source through the `Pkcs11Auth` session contract. This is a tentative direction,
not an implemented loader or a prerequisite for the work above. Module
configuration and identity/selector syntax remain design decisions for a
concrete integration. General module aggregation and re-exposure as ordinary
pkcs11rs slots are outside this plan:
[p11-kit’s proxy module](https://p11-glue.github.io/p11-glue/p11-kit/manual/sharing.html)
already exposes the slots of multiple configured modules through one PKCS #11
interface. The proposed adapter supplies credentials for YubiHSM authentication,
without recreating that aggregation facility.

Choose derivation paths from the source's mechanisms and key permissions,
without relying on backend kind. Prefer prefixed ECDH+KDF when available;
otherwise require ordinary ECDH and the remaining composition/KDF operations.
For explicitly named AES-128 pairs (`<name>.enc` and `<name>.mac`), prefer
`CKM_SP800_108_COUNTER_KDF`. Consider an authentication-provider fallback that
constructs CMAC and the counter KDF using `CKM_AES_ECB` when counter KDF is
unavailable and the source keys permit encryption. Reuse the existing
construction used for native YubiHSM AES keys rather than duplicating crypto
in the authentication client. This provider-level fallback is future work;
the current symmetric client requires the counter-KDF mechanism.

Select a permitted path before execution; an operational failure must not
trigger a different path or weaken object policy. Long-term keys remain in the
source token. Qualify the required output policies and intermediate-object
operations explicitly rather than assuming an external module offers the
common software layer supplied by pkcs11rs.

Retain the selected source session for channel recreation without retaining
its login PIN. Target logout releases that session through normal session
closure, preserving other source sessions and their shared login. Explicit
source logout prevents recreation until fresh authorization; established
channels retain their own working keys. An external adapter must also define
module initialization/finalization ownership, threading, handle invalidation,
and protection against recursive module loading or source dependencies.

Qualify authentication against an independent module, including restricted mechanisms, shared login,
source logout, device loss, and session cleanup.
