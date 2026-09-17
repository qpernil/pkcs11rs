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
Key-MAC. Each key prefers `CKM_SP800_108_COUNTER_KDF` when the slot and key
permit derivation. Otherwise, a key that permits `CKM_AES_ECB` encryption uses
the shared CMAC/counter-KDF construction through the source session's ordinary
encryption operations. If the key also permits `CKM_AES_CBC`, one zero-IV CBC
call handles all prepared CMAC blocks after one ECB call generates the subkeys.
Otherwise, ECB operations handle each chained block. CBC errors propagate
without an ECB retry. Both paths are selected before deriving anything; ENC
and MAC may use different paths. An operational or output-policy failure is
returned without retrying the other path.

Counter-KDF operations create explicitly readable working objects, read them
once, and destroy them. The ECB construction produces working bytes directly
without importing them back into the source slot. Neither path reads or splits
the source AES values. S-ENC, S-MAC, and S-RMAC use zeroizing client storage;
partial results are dropped on failure, and the handshake session closes on
completion. Host/card cryptograms use local S-MAC. The native counter-KDF and
authentication fallback share the same CMAC/counter implementation.

Asymmetric authentication binds a protected P-256 private credential and generates
an ephemeral private key. An existing-slot credential first uses the native
protected session-object graph when the provider can retain volatile keys and
both private keys permit `CKM_ECDH1_DERIVE`. Both agreements, concatenation,
X9.63, extraction, and receipt verification then remain in the source device.

When that graph is unavailable, the client selects
`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` if the static credential permits it. The
ephemeral agreement is explicitly readable and supplied as prefix bytes; static
ECDH and X9.63 remain one operation. If neither path is available, ordinary
ECDH returns the static agreement and the common module performs the remaining
composition and KDF in zeroizing memory. Path selection finishes before any
derivation, and an operational failure does not trigger a weaker retry.
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
also runs locally; their derivation graphs use the same provider operations.

## 1. Configured provider selection and named lookup

The YubiHSM client selects registered source slots through public credential
metadata. A wildcard searches current protection tiers and uses ordinary
credentials only from source slots the application has already authorized. A
target login never submits its PIN to another ordinary token. A target-only
projection is skipped when its source contains no corresponding private key.
Native HSM Auth slots
advertise `CKP_YUBICO_HSMAUTH`; ordinary slots provide P-256 token keys or named
AES pairs. See [source selection](../yubihsm-auth.md#generic-source-selection-and-authorization)
for selector syntax, supported sources, and login behavior.

`Pkcs11Provider::from_slot` shares the source backend, authorization and object
handles. The prepared view avoids recursive public-module locking and suppresses
internal tracing. Preparation fails if the source slot mutex is already held;
a target cannot bootstrap its source through itself. The retained provider
session observes existing token-wide login state without owning or retaining
the source PIN. Existing authorization and key bindings remain subject to
source logout, replacement and session loss.

Derivation templates permit the intended final value reads from creation,
using `CKA_SENSITIVE=false` and `CKA_EXTRACTABLE=true` while honoring source
restrictions. Incompatible policy fails without fallback. Intermediate objects
are released after use; only final working keys leave the generic derivation
path. Instrumented software-source tests cover both protocols, wrong PINs,
authorization reuse, channel recreation, and source-object preservation.
Platform and native-source tests cover deterministic first-match selection;
native tests count password-bearing requests to verify that one login never
tries more than one credential. Because ordinary source authorization is an
application operation, provider lookup does not form recursive login
dependencies. Card protocol details and remaining virtual-token-native
operations follow below.

### Physical YubiHSM-to-YubiHSM regression

`yubihsm_to_yubihsm_asymmetric_authentication` and the three
`yubihsm_to_yubihsm_symmetric_*` cases are ignored, explicitly provisioning
tests. Set `PKCS11RS_CROSS_HSM_SOURCE` and
`PKCS11RS_CROSS_HSM_TARGET` to distinct HSM serials, and supply the
existing bootstrap login strings in `PKCS11RS_CROSS_HSM_SOURCE_PIN` and
`PKCS11RS_CROSS_HSM_TARGET_PIN`. If bootstrap authentication uses a YubiKey,
include its serial in the comma-separated `PKCS11RS_CROSS_HSM_HELPERS` list.
For remote HSMs, set `PKCS11RS_CROSS_HSM_URLS` to a comma-separated list of
connector URLs, for example `http://ubuntu3:12345`. Local USB and remote
connector slots participate in the same test; the source and target serials
still select the exact devices.
The bootstrap credentials need permission to generate/delete the temporary
source key (or import/delete AES keys for the symmetric cases) and
create/delete the target authentication key. Each PIN variable accepts either
the compact `C_Login` form or a complete `pkcs11:` credential URI. The URI form
is passed to `C_LoginUser` with a null PIN. A host credential such as Secure
Enclave can therefore authorize the test when the test process has the same
platform-key access group as that credential.

```sh
cargo test --lib yubihsm_to_yubihsm -- --ignored --nocapture --test-threads=1
```

The asymmetric test generates a sensitive, non-extractable P-256 source token key,
registers its public point as a temporary target authentication key, and logs
into the target with the explicitly named source credential. It verifies
public/private ID pairing, raw and prefixed derivation permissions, protected
random requests, and an encrypted echo. Each case enables session recreation,
waits 35 seconds without HSM traffic for the hardware session timeout, and
checks that the first subsequent request succeeds with USER authorization
retained. Cleanup deletes only the temporary
objects and compares both native inventories with their initial snapshots.
The tests never reset a device. Assertion failures also attempt cleanup; process
termination or device removal can prevent cleanup from completing.

The symmetric cases provision a fresh random AES-128 pair as protected source
token objects named `<label>.enc` and `<label>.mac`, and the corresponding target
authentication key. All local provisioning-key bytes are zeroized before login.
Actual PKCS #11 key policy selects the path; the test checks the selection
without forcing it or mocking slot capabilities:

| Case | CKA_DERIVE | CKA_ENCRYPT | CKA_ALLOWED_MECHANISMS |
| --- | --- | --- | --- |
| Counter KDF | true | false | SP800_108_COUNTER_KDF |
| ECB+CBC | false | true | AES_ECB, AES_CBC |
| ECB only | false | true | AES_ECB |

Native key information verifies AES-128 and the absence of export-under-wrap
capability. The import API grants native ECB/CBC encryption capabilities for
`CKA_ENCRYPT=true`; the ECB-only case excludes CBC through its persisted
PKCS #11 mechanism restriction. Source values remain unreadable through
`CKA_VALUE`. Both source and target hardware sessions can expire during the
idle period; the retained source authorization must also support recreation.

Physical devices 1238075073 and 2545354682 passed authentication and protected
commands in both source/target directions, bootstrapped through the existing
`shared` YubiHSM Auth credential on YubiKey 37070618. Both devices' native
inventories matched their pre-test snapshots after cleanup. The same test passes
with source 2545354682 on local USB and target 1238075073 reached through
`http://ubuntu3:12345`. The asymmetric path and all three symmetric paths passed
authentication and recovery after 35 seconds idle in this topology. Symmetric
selection was driven by the persisted usage flags and allowed-mechanism list.
Both inventories returned to their original 12 objects after each case.

A persistent virtual source, YubiHSM 26000001, also passed wildcard and exact
URI authentication to both physical targets. The wildcard resolved
`iphone-virtual-client` from the virtual source even though that slot also held
the two phone platform-key projections. This qualifies projection-only skipping
and token-native priority against real target firmware without modifying the
provisioned inventory.

The persisted fixture can hold P-256 credentials whose native capabilities and
`CKA_ALLOWED_MECHANISMS` force a specific asymmetric derivation placement. Its
route names describe the current security boundary:

| Route | Provider selection | Static agreement and X9.63 KDF |
| --- | --- | --- |
| `native-protected-graph` | Native session-object graph | Ephemeral key, both agreements, KDF, extraction, and receipt verification stay in the source device |
| `native-prefix-derive` | Literal prefix derive | Virtual `DeriveEcdhKdf` performs static ECDH and X9.63 in the source device |
| `module-prefix-derive` | Literal prefix derive | Raw static ECDH and X9.63 execute in zeroizing module memory |
| `basic-ecdh` | Ordinary ECDH | Raw static ECDH, composition, and X9.63 execute in zeroizing module memory |

The ignored `qualifies_persisted_virtual_client_paths` test takes the source,
targets, public-discovery credential, client credentials, and expected routes
from environment variables. Target metadata is populated through that
least-privilege discovery credential; the operational login is not used as a
substitute inventory credential. A test-only observer records the selected
route without enabling protocol-frame tracing; the test asserts the exact route
and completes an authenticated target command. Desktop, Swift iOS, and
Objective-C iOS clients have qualified all three routes from virtual YubiHSM
26000001 against physical YubiHSMs 1238075073 and 2545354682. The iOS smoke apps
remain independent of this fixture.

## 2. Card derivation

Card SCP03 S8 and SCP11a/b/c use `Pkcs11Auth` through scoped provider objects.
Their transcripts, security levels, response IV direction bit, and native
smart-card transaction lifetime remain protocol-specific. Message AES/CMAC
runs locally with the derived working keys.

SCP03 accepts AES-128/192/256 configured inputs. A temporary software provider
imports direct ENC/MAC/DEK keys or performs protected batch-master-key
diversification. Counter KDF, with the permitted ECB/CBC alternative, derives
working bytes and the optional 64-bit card challenge. The static administration
DEK stays behind a protected handle and performs zero-IV CBC wrapping through
the provider; it is never exported as a disposable working key.

SCP11 imports the configured OCE P-256 key as a protected credential and uses
separate handshake sessions for ephemeral generation and intermediate objects.
Its combined and standard ECDH paths share the generalized X9.63 operation graph
with YubiHSM authentication. The card recipe requests five AES keys and verifies
the encoded receipt transcript before reading S-ENC, S-MAC, S-RMAC, and DEK.
SCP11b uses the ephemeral private key for both agreements and does not establish
OCE authentication. Every temporary object is released on success or failure.

Provider and session ownership uses `Arc`; the module's existing slot locks
serialize backend access and provider selection remains thread-local. A retained
DEK can move with a card transaction between caller threads. Direct input
configuration remains supported; selecting card credentials by a configured
slot/label is future work. Existing authorized sources are covered at the
provider layer without copying or reading their credential values.

Validation includes fixed card vectors, AES-192/256, batch diversification,
all ECDH placement paths, failed receipts and source policies, source logout, cross-thread
DEK use and cleanup, plus virtual-YubiKey provisioning and transaction-lifetime
regressions. Caller-supplied new-key material and KCV calculation remain an
explicit administration input workflow. SCP03 S16 is outside this plan.

Physical qualification covers SCP03 and custom-CA SCP11a/b on a YubiKey,
including an SCP11a OCE private key generated on a physical YubiHSM and borrowed
through `Pkcs11Auth`. Three fresh SCP11a handshakes and protected reads pass
without exporting the native host private scalar. See the
[hardware tests and device-capacity constraints](../scp11.md#issuer-sd-key-provisioning).

## Native virtual-YubiHSM derivation

Capability `derive-session-key` enables the generic protected-object commands
implemented with software-key-core: volatile P-256 generation and ECDH,
composition, extraction, SHA-256, SP 800-108 counter KDF, AES-CMAC verification,
policy-controlled reads, and deletion. pkcs11rs maps the standard PKCS #11
operation graph to those commands and marks the covered mechanisms with
`CKF_HW`.

The client selects these commands only when the active Authentication Key grants
`derive-session-key`. Without that capability it does not issue commands
`0x79`–`0x7c`; it can use the ordinary protected-key graph when the persistent
client key allows the required ECDH operations. Sources whose policy requires
the native volatile-object graph reject authentication. The session capability
is separate from the persistent client key's `derive-ecdh` or
`derive-ecdh-kdf` capability and from the permissions granted by the target
Authentication Key.

Long-term credentials remain ordinary persistent P-256 or AES objects. The
bounded intermediate/output store contains at most 64 objects per authenticated
secure session, uses random nonzero 64-bit handles, and performs no NVM writes.
Native backing-session loss invalidates dependent PKCS #11 handles without
rebinding stale identifiers. Each operation creates its output atomically and
enforces the session, source capability, domain, and output-policy rules. Only
outputs created with readable policy can be exported.

The public PKCS #11 regression builds the complete native graph, verifies
protected values and cross-session use, forces secure-session recreation, and
checks stale handles and creator-session cleanup. The complete client regression
then provisions a persistent P-256 credential in one virtual YubiHSM and its
public half as an Authentication Key in an independent virtual target. A total
credential wildcard selects the source through the normal `Pkcs11Auth` lookup,
opens the protected target channel, repeats native derivation after forced target
session expiry, and tears it down. The source command log proves that both
establishments use `DeriveEcdhKdf` and never the raw-ECDH fallback; closing the
target login releases the source session and its transient objects while leaving
the persistent credential intact.

A readable native result that requests a software-only operation is read once
and materialized as a common software session object. Protected outputs are
never downgraded. Only final working keys are read into the client, and the
provider needs no per-message AES/CMAC traffic for this client workflow.

## Future direction: external PKCS #11 sources

Explore adapting a separately loaded PKCS #11 module as an authentication
source. Represent each selected external slot as an external-backed `Slot` with
the common pkcs11rs software overlay, so `Pkcs11Auth` can use the same operation
graph as it does for built-in PIV, OpenPGP, platform, software, and YubiHSM slots.
The external slot retains its token identity, login state, persistent objects,
and native operations. Locally generated keys and explicitly readable derived
results become ordinary pkcs11rs session objects. This is a tentative direction,
not an implemented loader or a prerequisite for the work above. Module
configuration and identity/selector syntax remain design decisions.

This adapter is a generalization of the existing native-backed slot pattern used
by PIV, OpenPGP, platform, and YubiHSM backends, rather than a separate authentication
fallback. The built-in PIV slot is the clearest precedent: its resident private
key performs native ECDH through the PIV backend, the readable agreement is
published as a common software session object, and `Pkcs11Auth` performs the
remaining composition and KDF operations without a PIV-specific authentication
path. An external-backed slot should reproduce that behavior at the slot
boundary, so no fallback outside `Pkcs11Auth` is required. The shared derive
handler currently dispatches native key material by provider; a future external
adapter should use a generic backend operation rather than add external-module
logic to authentication.

The first implementation can keep these adapters private to authentication
source resolution. General module aggregation and re-exposure through
`C_GetSlotList` are outside this plan:
[p11-kit’s proxy module](https://p11-glue.github.io/p11-glue/p11-kit/manual/sharing.html)
already exposes the slots of multiple configured modules through one PKCS #11
interface.

Choose derivation paths from the source's mechanisms and key permissions,
without relying on backend kind. Prefer a native protected session-object graph,
then prefixed ECDH+KDF, then readable raw ECDH. An external module with ordinary
ECDH and protected composition/KDF operations can retain all intermediate
objects in that module. A limited source such as a PIV
module may instead produce an explicitly readable raw ECDH result; the adapter
materializes it as a local, protected software session object and completes
concatenation, X9.63 SHA-256, extraction, and receipt verification through the
common overlay. Generate the independent ephemeral agreement locally so the
external module needs to operate only on its long-term credential. Destroy and
zeroize the transferred agreement immediately after materialization, and repeat
ECDH rather than retain it for channel recreation.

Readable raw ECDH is a compatibility fallback with a weaker isolation boundary:
the long-term private key remains in the source token, but its agreement enters
client memory. Request a non-sensitive, extractable session result and fail if
the source rejects that output policy. A source that permits neither a complete
protected graph nor readable raw ECDH is incompatible; never weaken an existing
key's policy or retry a different path after an operational failure.

For explicitly named AES-128 pairs (`<name>.enc` and `<name>.mac`), prefer
`CKM_SP800_108_COUNTER_KDF`, with the implemented AES-ECB construction as the
alternative when the key permits encryption. An external adapter must supply
the required native operations and capability checks; the common overlay
supplies its ordinary software session operations. The loader itself remains
future work.

Select a permitted path before execution; an operational failure must not
trigger a different path or weaken object policy. Long-term keys remain in the
source token. Per-key capability projection must distinguish opaque external
objects from local software session objects so the overlay does not claim it
can operate on material the adapter cannot read.

Retain the selected source session for channel recreation without retaining
its login PIN. Target logout releases that session through normal session
closure, preserving other source sessions and their shared login. Explicit
source logout prevents recreation until fresh authorization; established
channels retain their own working keys. An external adapter must also define
module initialization/finalization ownership, threading, handle invalidation,
and protection against recursive module loading or source dependencies.

Qualify authentication against an independent module, including restricted mechanisms, shared login,
source logout, device loss, and session cleanup.
