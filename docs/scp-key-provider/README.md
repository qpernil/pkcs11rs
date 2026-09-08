# Plan: complete SCP03/SCP11 with interchangeable key providers

## Goal and division of responsibility

Use one SCP03/SCP11 protocol implementation with PKCS #11 key operations,
first supplied by a software slot and then by native virtual-YubiHSM commands.
The final milestone is complete secure-channel exchanges with the virtual
YubiHSM performing all required secret-key cryptography and retaining the
intermediate and working keys behind its device interface.

This includes the actual AES encryption/decryption and CMAC for each protected
message, not only handshake derivation or receipt generation.

The SCP code owns handshake sequencing, public transcripts, trust decisions,
counters, and secure-message framing. Its key provider owns generation,
derivation, AES/MAC execution, key policy, and key lifetime. Choosing a capable
native provider must not require another implementation of the SCP protocol.
The virtual HSM supplies generic key operations, not an SCP-specific object model.

“Full SCP” here means establishment and subsequent protected request/response
traffic, including authentication, receipts or cryptograms, encryption, and
MAC verification. Initial scope preserves the supported SCP03 S8 and SCP11a,
SCP11b, and SCP11c profiles. Adding SCP03 S16 or unrelated protocol families is
separate work. This is a forward plan; the complete native workflow is not
implemented yet.

## Why both providers remain useful

This resembles TLS-oriented HSM key operations: protocol-defined derivation
and composition create protected keys that feed later cryptographic operations.
The reusable interface is key operations, so a protocol does not need a second
implementation for each provider.

Protecting long-term credentials is generally the larger benefit. Device-held
session keys additionally resist extraction and copying out of the provider
process, but they do not make an actively compromised host trustworthy: it may
still request permitted operations and normally has access to the application
plaintext. Short-lived software session keys with explicit cleanup therefore
remain a valid operating choice, not merely a test scaffold.

Full native SCP execution is the qualification goal and a stronger key-retention
option, not a requirement that every deployment use hardware for every AES/MAC
operation. Measure the command-latency and throughput costs as well as cleanup
and isolation. Native volatile keys avoid NVM churn; they do not remove transport
round trips or automatically outperform host software.

## 0. Completed foundation: common session objects on every slot

All slot kinds share the software session-object layer: named software,
YubiHSM, PIV, OpenPGP, and FIDO2. Supported session data objects, imported or
generated software keys, derivation results, and operations use that common
implementation. Hardware ECDH results are ordinary software secret keys rather
than a special synthetic-result type. This does not claim support for every
PKCS #11 object attribute or mechanism.

Supported software operations on session objects are available on every slot
by default. Implementing another mechanism in the common layer therefore
benefits all slots, including a named software slot without additional
SCP-specific backend work. A software slot has an empty native mechanism list;
its backend still supplies identity, login/PIN management, and encrypted token
storage.

Each slot contributes a native mechanism list. A per-slot policy filters the
maximum common software list before merging the two by mechanism ID. The
merge combines size ranges and operation flags and retains native `CKF_HW`.
This reports total slot capabilities; it cannot describe which individual
sizes and operations run on hardware. Actual backend limits still apply to
token objects. Keep the filter and merge easy to change as client testing
reveals compatibility constraints.

Verified foundation: 718 library tests pass, one is ignored, and all 12
OpenSC/OpenSSL client cases pass. Full pkcs11test has 230 passed, 57 skipped,
and 49 failed, with no new failures from the shared layer. The nine former
generic data-object failures pass. See the [integration baseline](../../integration/README.md)
and [architecture](../architecture.md#shared-software-session-objects-and-mechanism-discovery).

## 1. Specify the key-operation contract and required mechanisms

- Trace existing SCP03/SCP11 key generation, diversification, agreement,
  derivation, receipt/cryptogram checks, and secure messaging. Record the exact
  inputs, output key types, lengths, usage flags, and secret dependencies for
  each supported profile.
- Map those steps to existing PKCS #11 operations. Reuse ECDH/X9.63, HKDF,
  AES, and CMAC where appropriate. Identify the missing generic derivations,
  especially required CMAC-based SP 800-108 layouts, extraction of working
  keys, and composition of secret inputs. Do not implement every derivation
  family merely because it might be useful later.
- Define provider selection and ownership. The protocol uses opaque key
  handles and explicitly sensitive, non-extractable key templates. No
  intermediate secret is obtained through `CKA_VALUE` or equivalent export.
- Decide the internal calling boundary before refactoring: the secure-channel
  code must not recursively acquire an already-held slot lock or require the
  channel being established to access its own key provider. Use PKCS #11
  operation semantics without requiring unsafe re-entry through the C ABI.

Exit criterion: a reviewed operation matrix covers every secret-bearing step
in the supported profiles, including existing static-key and DEK-dependent
workflows where applicable. Every step has an implementation or a specific gap.

## 2. Complete the common software derivation primitives

Implement the identified missing `C_DeriveKey` operations in the common layer,
using the shared crypto core where the primitive belongs. Produce ordinary
typed keys whose handles feed directly into later derivations, AES, and CMAC.
Keep protocol-specific transcript layouts in the SCP consumer wherever generic
primitives suffice.

Enforce output-template validation, sensitivity/extractability inheritance,
allowed mechanisms, usage policy, length/offset bounds, and failure atomicity.
Failed derivation must leave no published key or usable partial result. Reuse
the existing creator-session, logout, and zeroization rules. Verify extraction
and composition with protected base keys as well as readable test fixtures.

Exit criterion: known-answer vectors and PKCS #11 entry-point tests pass;
representative hardware slots and named software slots expose the same common
session behavior. The full external suite is rerun, with unsupported mechanisms
and outdated expectations reported explicitly rather than hidden by exclusions.

## 3. Run the existing SCP protocols through a software slot

Replace protocol-owned raw working keys and direct secret crypto calls with
the key-operation contract. A software slot is the first complete provider;
there must not be a parallel SCP-specific software crypto implementation.
Trust validation and transport/framing retain their established responsibilities.

Bind intermediate and working objects to the secure-channel lifetime. The
current CCID channels belong to native smart-card transactions; preserve that
boundary unless a separately reviewed change deliberately alters it. Tear down
objects on successful completion, failed establishment, receipt/MAC rejection,
and transport failure. Ordinary PIN/password retention policy remains unchanged.

Exit criterion: supported SCP03 and SCP11 profiles complete establishment and
protected exchanges using only key handles for secrets. Existing protocol
vectors and transaction-lifetime tests still pass; the protocol never reads
back intermediate or working key values.

## 4. Implement protected derivation inside virtual-yubihsm

Add native commands and object support for the complete operation matrix,
reusing software-key-core primitives inside the device implementation. Native
derivations must atomically create protected, chainable device objects and
return their identifiers, not derived bytes. The existing prefixed-ECDH
command returns KDF bytes and alone does not satisfy this milestone.

Start with the [protected-key composition design](../prefixed-ecdh-derive.md#future-protected-key-composition):
generic-secret intermediates, extraction into AES working keys, protected
agreement/KDF operations, and the required symmetric derivations. Finalize the
object model against the entire SCP operation matrix before choosing its
limits. Prefer bounded, volatile native session objects for both intermediates
and AES working keys. Channel establishment and teardown should not require NVM
writes for ephemeral keys. Long-term credentials retain their appropriate
persistent storage; any persistent temporary-key fallback needs explicit
justification and cleanup.

Define capability and domain checks, delegated output permissions, attribute
inheritance, identifiers/generations, output-template validation, and audit
behavior together with each command. Device sessions, timeouts, authentication
replacement, and invalidation must have explicit cleanup semantics. If temporary
working keys are persistent, specify crash/orphan recovery and storage bounds;
if session-owned, specify capacity and loss-of-session behavior.

Exit criterion: device-command tests chain protected outputs into subsequent
derivations and crypto operations, deny export and unauthorized use, and prove
cleanup and atomic failure. No runtime secret is returned in a derivation response.

## 5. Map native operations into pkcs11rs and qualify provider selection

Map the device commands and objects to the same PKCS #11 operations used by the
software provider. Preserve device ownership and retain any native session
needed by the lifetime of its handles. Reconcile reconnect, expiration, and
session recreation with transient objects; stale handles must never silently
refer to replacement keys.

Selecting full device-side execution requires the complete native capability
set, appropriate object placement, and authorization. The merged public
mechanism list and `CKF_HW` alone cannot establish that guarantee. Keep an
explicit native-capability check and fail unsupported selection without silently
performing a missing secret operation in host software. Avoid implicit key
movement between slots or changes in execution boundary after authentication.

Exit criterion: the same protocol consumer works through either provider;
native operation traces prove that agreement, composition, derivation,
extraction, encryption/decryption, and MAC generation/verification use
device-held keys throughout, including every protected message.

### Session lifetime does not determine execution location

`CKA_TOKEN=CK_FALSE` describes session-object lifetime, not whether the key is
held by the host or the device. The current common software layer places these
keys in host memory. A physical YubiHSM slot can therefore provide fast local
session-key crypto through pkcs11rs, without implying that the AES/CMAC ran
inside the HSM.

The native provider must be able to produce and address device-held transient
keys and dispatch operations on their actual native material. Define that
placement/selection explicitly; do not infer it from `CKA_TOKEN=CK_FALSE` or
from the combined mechanism list. Full device-side execution cannot be claimed
for existing physical firmware merely because pkcs11rs supports host session
objects. Volatile native keys avoid NVM churn, but device-command latency still
needs measurement against the software provider; no hardware speed claim is
assumed by this plan.

## 6. Ultimate milestone: complete SCP through a virtual YubiHSM

Run the common SCP implementation against a compatible peer, using a virtual
YubiHSM as the provider for all required secret-key operations. Use disposable
virtual fixtures for destructive and exhaustion tests. Qualify each supported
SCP03/SCP11 profile through establishment and multiple protected exchanges,
including the relevant command/response security levels and failure paths.

The milestone is complete only when:

- The software-provider and native-provider paths both satisfy the same
  protocol vectors and peer interoperability checks.
- After credential provisioning, native intermediate and working keys remain
  device-held and non-extractable; the protocol receives only handles and
  legitimate public/protocol results such as public keys, MACs, and ciphertext.
- Unsupported native capabilities, wrong authority, tampered receipts/MACs,
  partial derivation, object exhaustion, disconnect, and timeout fail cleanly.
- Teardown leaves no usable stale handles, leaked channel keys, or unbounded
  persistent temporary objects. Traces and diagnostics contain no secrets.
- Documentation and tests in pkcs11rs and virtual-yubihsm agree on commands,
  capabilities, object policy, and lifetime. The full PKCS #11/client regression
  suites are run and remaining compatibility failures are accounted for.

At this point the virtual YubiHSM provides native device-side support from
pkcs11rs's perspective. It exercises a real device-protocol and authorization
boundary, while remaining a software device rather than physical tamper-resistant
hardware. A physical HSM implementing the required primitives could supply the
same key-provider role without changing the SCP protocol implementation.
