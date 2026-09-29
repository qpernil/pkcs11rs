# YubiHSM cluster-backed slot design

## Status

This document proposes a YubiHSM clustering architecture for `pkcs11rs`. It is
not implemented. Existing YubiHSM discovery continues to expose one PKCS #11
slot per device.

The proposal deliberately keeps clustering inside `pkcs11rs`. Each member has
an end-to-end YubiHSM secure session from the PKCS #11 process to that member;
there is no protocol-terminating proxy or Virtual YubiHSM between them.

## Goals

- Present a set of equivalent YubiHSMs as one stable PKCS #11 slot.
- Keep every persistent cluster object on every member, except while a member
  is unavailable or catching up.
- Preserve one object type and ID across all replicas.
- Route cryptographic operations to any current member that contains the
  requested object.
- Replicate generation, import, deletion, and metadata changes automatically.
- Add a member online without transporting a shared symmetric wrap key through
  an air-gapped environment.
- Retain end-to-end YubiHSM secure sessions and the existing authentication
  secret-retention policy.
- Preserve today's discovered single-device slots and their implementation
  unchanged unless explicit cluster configuration claims a device.
- Reuse existing low-level components where they already fit, without making a
  speculative common slot abstraction a prerequisite.
- Keep the generic connector layer transport-only.

## Non-goals

- General cross-vendor HSM clustering.
- Transparent cross-slot `C_CopyObject` semantics.
- Moving nonextractable PIV, OpenPGP, or unrelated token keys into a cluster.
- Hiding a protocol-terminating cluster service behind the connector API.
- Automatic write-leader election in the first implementation.
- Replicating volatile YubiHSM secure sessions, PKCS #11 session objects,
  device audit logs, device identity keys, firmware options, or other
  member-local state.
- Treating a heterogeneous set of incompatible wrapped-object formats as one
  cluster. In particular, the current Virtual YubiHSM full-object format is
  deliberately distinct from the physical YubiHSM format.

## Core model

Clustering is an opt-in slot type alongside the existing direct YubiHSM slot:

```text
PKCS #11 slots
├── existing direct YubiHSM slot
│   └── existing connector, secure session, objects, and behavior
└── configured YubiHSM cluster slot
    ├── logical token identity and cluster policy
    ├── authoritative member selection
    ├── logical object and replication state
    └── two or more configured cluster members
        ├── Connector
        ├── YubiHSM secure-session state
        ├── health and connection epoch
        ├── observed object sequence
        └── operation gate and current load
```

Without cluster configuration, discovery and publication follow the existing
direct-slot path exactly. No cluster object, policy, catalog, authority,
reserved ID, wrap-key requirement, or error path is constructed.

Explicit cluster configuration names and verifies at least two members and
publishes one logical cluster slot. Claimed members are not also exposed as
ordinary individual slots unless an explicit administrative mode requests raw
member access. Hiding the raw slots prevents applications from seeing
duplicate objects or binding themselves accidentally to one physical member.

The first implementation may duplicate some slot-level orchestration while
reusing established connector, protocol, secure-session, object-decoding, and
cryptographic helpers. Shared abstractions should be extracted only after the
cluster implementation reveals stable common behavior. Preserving the direct
slot is more important than eliminating temporary internal duplication.

## Why clustering is not a Connector responsibility

`Connector` transports opaque frames to one endpoint. It reports transport
properties and presence, but does not own YubiHSM object or authorization
semantics. A YubiHSM secure session is stateful and bound to one member:
session IDs, message counters, and channel keys cannot be redirected between
devices.

A connector-level redirector could only:

1. keep an opaque secure session pinned permanently to one member, in which
   case it cannot perform semantic routing or replication; or
2. terminate the incoming secure session and open another toward the selected
   member, in which case it becomes a trusted protocol proxy and the client no
   longer has an end-to-end session with the HSM.

`pkcs11rs` sees the operation before it is encoded and protected. It can choose
a member first and then execute the operation through that member's own secure
session. The cluster therefore belongs in a YubiHSM-aware layer above
connectors and below the logical PKCS #11 slot behavior.

## Cluster invariants

A configured cluster maintains the following invariants:

1. One configured member is authoritative for persistent mutations.
2. Every committed persistent cluster object has the same object type and ID
   on every current member.
3. Object generation and import occur only on the authoritative, up-to-date
   member.
4. Followers never introduce objects into the authority during ordinary
   reconciliation.
5. A member is eligible for general routing only after it has been reconciled
   to the current authoritative inventory.
6. A member missing a newly committed object is not eligible for operations on
   that object until replication completes.
7. Cluster infrastructure and member-local objects occupy reserved identities
   and are not exposed as ordinary application objects.
8. Only members with a compatible native wrapped-object format, cluster wrap
   key, authorization model, and required algorithm surface may be current
   members of the same mirrored cluster.

The physical YubiHSM limit of 256 resident objects is small relative to the
16-bit object-ID space. The authority may therefore allocate IDs
conservatively and avoid routine reuse. Exact allocator persistence and ID
reuse policy remain an implementation decision; correctness must not depend on
followers independently choosing IDs.

The cluster identity of an object is its object type and ID. The authority's
logical creation history determines PKCS #11 properties such as `CKA_LOCAL`;
a replica imported under wrap must not cause the logical object to appear
nonlocal merely because that particular copy has an imported device origin.

Each cluster object also has a logical generation. In normal lockstep operation,
the native YubiHSM `sequence` for its reserved ID should be equal across every
current member: the ID has undergone the same number of create/delete/recreate
cycles. Fresh enrollment therefore requires equal sequence, and an unexpected
mismatch is strong evidence of divergent history or out-of-band mutation.

Sequence equality is not by itself proof of equal key material or policy, and
repair may be an explicit exception. Deleting and reimporting only a stale
member can advance that member's native sequence while restoring the intended
logical object. The cluster therefore records both its common logical
generation and each member's native sequence. A repaired member with a
different sequence may become current only after full-object provenance,
metadata, and functional verification; the divergence remains visible in
diagnostics instead of being silently treated as normal lockstep history.

## Logical PKCS #11 token

### Identity and presence

An explicit cluster has a configured stable token label and serial independent
of any member serial. Member serials remain diagnostic and security identities.
Direct slots continue to use their existing physical-member identities.

The logical token is present when at least one eligible member can serve its
advertised read and cryptographic surface. Persistent mutation additionally
requires the authoritative member. Loss of a follower does not remove the
slot. Loss of the authority makes the slot read/crypto-capable but read-only in
the initial design.

### Objects

Object enumeration is a logical cluster inventory rather than the union of
member inventories. Each replicated object appears once. Handles resolve to a
cluster object identity, and routing selects a replica only when an operation
uses the object.

Member-local infrastructure is filtered from the application inventory. It
includes at least:

- each member's RSA private wrap key;
- temporary or retained public RSA wrap keys used to enroll members;
- the cluster AES-CCM wrap key;
- bootstrap administration credentials not intended as cluster application
  objects; and
- device identity, attestation, audit, and firmware state.

Cluster-managed Authentication Keys, wrap keys, certificates, opaque objects,
templates, asymmetric keys, symmetric keys, HMAC keys, and other exportable
object classes may be mirrored when the member format and policy support them.
Volatile native session objects remain bound to the member and secure session
that created them.

### Mechanisms and hardware flags

An explicit cluster advertises a configured compatibility profile no broader
than the intersection of its current members' usable mechanism surfaces. A
member lacking a required algorithm or wrapped-object compatibility cannot be
treated as a fully current replica for a cluster that advertises it.

The existing composition policy still applies to the logical slot. Native
member operations, public counterparts, keyless operations, hashed signing,
prefixed ECDH, and meaningful protected secret flows retain their current
semantics. A composed mode keeps `CKF_HW` when the sensitive long-term
operation occurs in the selected physical or virtual HSM. Clustering does not
turn the slot into a general software provider.

## Member secure sessions and login

Each member owns independent YubiHSM secure-session state. Encoded session
commands are never moved between members.

The logical slot shares a bounded member session rather than opening one HSM
session for every PKCS #11 application session. This preserves the existing
slot-wide login model and avoids multiplying the YubiHSM's limited session
capacity by the number of application sessions.

At `C_Login`, `pkcs11rs` authenticates every currently present member that
should become eligible. This is necessary because ordinary PINs and passwords
are not retained for later member authentication. A member that appears after
login remains ineligible for private operations until it can be authenticated
without violating that policy or until the application performs a fresh login.

The existing explicit `yubihsm.recreate_sessions` option may retain the
documented reauthentication material and recreate an individual member
session. It must not become an implicit requirement of clustering. Logout,
finalization, or invalidation destroys every member's retained channel keys and
any opt-in reauthentication material according to the existing authentication
secret-retention policy.

If one member session expires or its transport fails, that member becomes
ineligible while other authenticated members remain usable. The failed
member's session can be recreated only when existing policy permits it. Loss of
every authenticated member transitions the logical slot to its existing
invalidated-login behavior.

## Routing

The cluster slot chooses a member before creating or using a secure-session
command.
Selection considers:

- authenticated role;
- member health and connection epoch;
- current/reconciled cluster generation;
- presence of the requested object;
- mechanism compatibility;
- native-session-object ownership; and
- current member load.

Independent one-shot operations may be load-balanced. Multipart operations are
pinned when initialized and remain on that member until finalization or abort.
Native YubiHSM session objects and operations derived from them are pinned to
their creating member and secure session. Failure of that member invalidates
those volatile objects rather than attempting to recreate or transfer them.

Transport failure before command submission may select another eligible
member. An uncertain result after submission is handled according to operation
semantics:

- repeatable reads may be retried elsewhere;
- a one-shot cryptographic operation may be retried only when returning a
  second valid result is safe and no partial result escaped;
- multipart state is not replayed implicitly; and
- generate, import, mutation, and deletion are reconciled against the
  authoritative inventory rather than blindly replayed.

## Replication primitives

YubiHSM provides two relevant families of wrapped-object operations:

- Native AES-CCM full-object wrapping carries object identity and policy,
  including type, ID, domains, capabilities, label, and algorithm. It is fast
  and is the steady-state replication format.
- RSA full-object wrapping carries the same object metadata to a recipient's
  RSA wrap key. It is a hybrid construction: RSA-OAEP protects an ephemeral AES
  key and AES protects the object payload. It is used to bootstrap cluster
  infrastructure without distributing a shared symmetric key in plaintext.

RSA key-material-only wrapping, where asymmetric material is PKCS #8 and
symmetric material is raw key bytes, is useful for migration or conflict
recovery because the destination supplies a new ID and policy. It is not the
normal intra-cluster replication format because a mirrored cluster deliberately
uses the same object IDs and policy on all members.

All mirrored objects must be eligible for export under the cluster wrap key.
The cluster wrap key's delegated capabilities must cover the complete policy
of those objects. Objects that cannot satisfy this condition cannot be normal
cluster-managed persistent objects.

## Online member enrollment

Adding a clean member does not require an air-gapped environment:

1. Establish and verify the new member's device identity and administrative
   connection.
2. Generate a unique RSA private wrap key inside the new member. The private
   key never leaves that HSM.
3. Retrieve and authenticate the corresponding public key.
4. Install that public key as a Public Wrap Key on the authoritative member,
   with narrowly scoped capabilities.
5. Use RSA full-object wrapping to export the cluster AES-CCM wrap-key object
   to the new member. Its cluster-reserved ID and policy are preserved.
6. Use the shared AES wrap key and native full-object wrapping to copy the
   authoritative persistent inventory.
7. Verify the resulting object information and supported mechanism profile.
8. Authenticate an operational session to the new member and mark it current.
9. Remove any temporary public-wrap object that is not part of the retained
   membership design.

Accepting a public wrap key is a security-sensitive membership operation.
Anyone allowed to register an arbitrary public wrap key and export cluster
objects could direct exportable key material to a key they control. Enrollment
therefore requires explicit administrative authorization and verification of
the new member serial, device identity, and RSA public-key fingerprint.

## Persistent mutation

### Generation and import

Generation and plaintext import run only on the authoritative current member.
The authority assigns the final object type and ID. After successful creation:

1. export the full object under the cluster AES wrap key;
2. import the same full object into every present authenticated member;
3. verify object metadata on each destination;
4. update member replication state; and
5. expose the logical object according to the configured commit rule.

The recommended initial commit rule is `all-present`: return success after all
members that were present and current at mutation start have accepted the
object. Offline members remain stale and must catch up before routing. This
does not pretend to provide distributed transactional commit—the authority may
have created the object even if replication or the client response later
fails. A subsequent inventory reconciliation must converge the cluster.

Concurrent callers use the authority as the serialization point for object
creation and ID allocation. No follower allocates a competing ID. The first
implementation uses a statically configured authority and does not perform
automatic write failover.

### Metadata changes

YubiHSM metadata that requires object replacement follows the same authoritative
mutation path. The cluster must not expose a successful logical change while
silently leaving a current member with different effective capabilities or
domains.

### Deletion

Deletion is issued against the authority first and then against current
followers. A member that was offline during deletion is stale and is fully
reconciled before returning to service. Followers never repopulate objects
missing from the authority.

The authoritative inventory therefore prevents resurrection without requiring
ordinary followers to maintain an independent source-of-truth catalog. An
authority change is allowed only to a member proven current at the selected
cluster generation.

## Reconciliation

At only 256 resident objects, full inventory comparison and rebuild are
practical and preferable to a fragile incremental repair algorithm.

A member becomes stale after an uncertain mutation, transport loss during
replication, incompatible object sequence change, or observation of unexpected
member-local mutation. Before it becomes eligible again:

1. freeze routing to that member;
2. preserve the reserved member-local bootstrap objects;
3. compare its cluster-managed inventory with the authority;
4. delete extra or conflicting cluster-managed objects;
5. import the authoritative full-object representations for missing or replaced
   objects;
6. verify object metadata and compatibility; and
7. mark the member current at the observed cluster generation.

For a clean join or a member known to be stale, rebuilding every
cluster-managed object is acceptable and avoids relying on comparisons of
non-readable symmetric or private material. A native import collision on a
supposedly clean destination is an inconsistency signal, not a request to
allocate another ID.

## Authority, concurrency, and multiple processes

`pkcs11rs` is loaded independently into multiple application processes. Each
process may keep its own member connections, secure sessions, health samples,
and routing decisions. They must nevertheless share the same configured
authority and cluster identity.

The initial design relies on these rules:

- only the configured authority accepts application mutations;
- the authority serializes its own commands and object creation;
- replicas never create cluster application objects independently;
- reconciliation always flows from authority to followers; and
- automatic authority promotion is disabled.

This is sufficient for ordinary concurrent generation with authority-assigned
IDs, but it is not a distributed transaction manager. Operations that require
cross-process membership changes, destructive reconciliation, or authority
promotion need an administrative exclusion mechanism. A future cluster daemon
or shared lease may coordinate those control-plane operations without moving
ordinary cryptographic traffic or terminating application secure sessions.

If the authority is unavailable, existing keys remain usable on current
followers. Generation, import, metadata mutation, and deletion return an
appropriate token/device write error until the authority returns or an
administrator explicitly promotes a proven-current member.

## Attestation, origin, and audit

Replication copies key material, not the physical history of generating it on
every member. The authority can attest the original generation. A follower can
attest that its imported replica is present in that member, but must not claim
that the member generated it.

The logical `CKA_LOCAL` and generation mechanism follow the cluster operation
performed on the authority. Member-specific attestation remains bound to the
member that produced the certificate. The first implementation should route a
request for generation provenance to the authority and expose the executing
member identity in diagnostics. A later cluster attestation format could
bundle per-member evidence but is outside ordinary PKCS #11 semantics.

Native audit logs remain per member. Load-balanced operations consequently
appear in the log of the executing HSM. `pkcs11rs` diagnostics must include the
logical cluster identity, member serial, object identity, operation, and
replication result without logging secret material.

## Security boundary

Members sharing the cluster AES wrap key form one cryptographic trust domain.
A member able to import cluster objects can use those objects according to
their capabilities and domains. Removing an untrusted member requires rotating
the cluster wrap key and considering every blob previously wrapped under the
old key compromised to that former member.

The cluster does not weaken transport or HSM identity checks. Each member's
connector TLS identity, YubiHSM device identity, serial, and public-key trust
are verified independently. A healthy network endpoint with the wrong HSM is
not an interchangeable replica.

Member admission, wrap-key bootstrap, destructive reconciliation, and authority
promotion are administrative operations distinct from ordinary PKCS #11 key
use. Their credentials and authorization should be scoped accordingly.

## Discovery and configuration

The configuration model must distinguish:

- ordinary discovery sources, which continue to publish existing direct slots
  for every unclaimed device;
- explicit cluster identities;
- the expected member serial and transport locator for every member;
- the authoritative member;
- the reserved cluster AES wrap-key ID;
- the compatible mechanism/wrapped-format profile; and
- the mutation commit rule.

The exact JSON schema is deferred until implementation. It must be strict,
versioned through the existing initialization configuration, and must reject a
member claimed by more than one logical group. Cluster identity must not be
inferred merely because several devices contain a wrap key with the same ID.

Discovery may find configured members through direct USB or independent remote
HTTP connectors. Transport type does not affect membership. A member is
accepted only after its verified serial and device identity match the cluster
configuration.

## Implementation boundary

The current `YubiHsmSlot` remains the direct single-device implementation. The
cluster is introduced as a separate `YubiHsmClusterSlot` selected only by
explicit configuration. It owns logical handles, member selection, authority,
replication, reconciliation, and cluster-specific operation state.

The cluster implementation should call existing lower-level connector,
protocol, secure-session, key-policy, and response-parsing components directly
where their contracts fit. It should not begin by splitting `YubiHsmSlot` into
a new common member/group hierarchy. When both implementations need the same
substantial behavior and tests show identical semantics, that behavior can be
extracted in a later focused refactor.

Some temporary duplication in slot orchestration is acceptable. It makes the
new behavior opt-in, keeps regressions out of the established path, and gives
the eventual shared boundary evidence from two working implementations rather
than assumptions made before clustering exists.

## Implementation stages

1. **Configured cluster skeleton**
   - Add strict, explicit cluster configuration and a separate
     `YubiHsmClusterSlot`.
   - Claim configured members and publish one stable slot.
   - Leave unclaimed devices on the existing direct-slot path and suppress raw
     application slots for claimed members.
   - Add per-member health, independent secure sessions, capability
     intersection, and read-only logical object routing.
2. **Authenticated routing**
   - Authenticate present members at logical login.
   - Pin multipart and native-session-object operations.
   - Load-balance safe one-shot operations.
3. **Preprovisioned replication**
   - Use an already installed common AES wrap key.
   - Implement authoritative generation/import, `all-present` replication,
     deletion, stale-member exclusion, and full reconciliation.
4. **Online enrollment**
   - Generate the joining member's RSA wrap key.
   - Verify its public key and use RSA full-object wrapping to install the
     cluster AES wrap key.
   - Synchronize and activate the member.
5. **Operations and diagnostics**
   - Add member health, lag, authority, and reconciliation reporting to
     `pkcs11rs-tool` or a dedicated administrative interface.
   - Add explicit promotion and wrap-key rotation workflows.
6. **Evidence-based refactoring**
   - Compare the working direct and cluster implementations.
   - Extract only stable shared behavior with identical semantics and dedicated
     non-regression tests.
7. **Optional later coordination**
   - Evaluate shared leases or a control-plane daemon for automatic authority
     promotion and multi-host membership administration.

## Validation plan

The design requires deterministic tests at the semantic command layer rather
than a connector that guesses from encrypted frames.

### Direct-slot non-regression

- Run the complete existing YubiHSM unit and ABI suites against the unchanged
  direct-slot implementation.
- With no cluster configuration, verify unchanged discovery, slot/token
  identity, mechanism flags, login behavior, object handles, and return values.
- With cluster configuration present, verify that every unclaimed device still
  follows the direct path and that claimed members are not published twice.
- Verify that a direct slot requires no cluster wrap key, replication
  permission, logical catalog, or cluster administration.

### Replication

- Generate and import every supported exportable persistent object class.
- Verify identical type, ID, domains, capabilities, label, and algorithm on all
  members.
- Exercise asymmetric, symmetric, HMAC, opaque, certificate, template,
  authentication, and wrap objects where supported.
- Verify source logical origin and replica physical origin are not confused.
- Verify deletion and metadata mutation converge.

### Failure and recovery

- Lose each member before submission, after submission, during response, and
  during replication.
- Drop a mutation response after the authority committed it and verify later
  reconciliation.
- Rejoin a stale member containing missing, extra, and conflicting IDs.
- Verify a conflicting native import never causes allocation of a different
  replica ID.
- Verify read/crypto availability without the authority and write rejection
  without explicit promotion.

### Sessions and concurrency

- Use multiple PKCS #11 sessions without opening one HSM session per
  application session.
- Use multiple processes generating objects concurrently through one
  authority.
- Verify member session counters never cross connectors.
- Verify multipart operations and native session objects remain pinned.
- Verify logout and finalization clear every member session and retained
  credential according to policy.

### Enrollment and security

- Generate the RSA wrap key inside a joining HSM and prove that only its public
  key leaves the member.
- Bootstrap the AES cluster wrap key through RSA full-object wrapping.
- Reject the wrong serial, device identity, public-key fingerprint, wrap-key
  policy, or wrapped-object format.
- Verify unauthorized public-wrap-key installation cannot enroll a member.
- Verify removed members cannot decrypt blobs protected only under a rotated
  cluster wrap key.

### Hardware qualification

- Qualify physical-to-physical replication on supported firmware.
- Qualify Virtual-YubiHSM-to-Virtual-YubiHSM replication separately.
- Confirm that incompatible physical and virtual wrapped-object formats are
  rejected rather than assumed interoperable.
- Exercise mixed direct-USB and remote-HTTP transports within one compatible
  cluster while retaining end-to-end member secure sessions.

The ignored
`bootstraps_two_yubihsms_online_with_rsa_then_aes_replication` hardware test
qualifies the enrollment primitives against two explicitly selected physical
devices. It chooses unused temporary IDs across both inventories, generates
the RSA private wrap key inside the joining member, transfers only its public
key, bootstraps an AES-256-CCM wrap key through RSA full-object wrapping, and
uses native AES full-object wrapping to replicate a P-256 application key. It
then verifies matching policy and working signatures on both members and
removes every temporary object. Diagnostic output includes both members'
metadata, including their member-local origin and sequence values, but never
prints key material.

Run it only with two test HSMs whose administrator credentials authorize the
required generate, wrap, import, inspect, sign, and delete operations:

```sh
PKCS11RS_TEST_YUBIHSM_CLUSTER_BOOTSTRAP=1 \
PKCS11RS_CROSS_HSM_SOURCE=<authority-serial> \
PKCS11RS_CROSS_HSM_TARGET=<joining-member-serial> \
PKCS11RS_CROSS_HSM_SOURCE_PIN=<authentication-id-and-password> \
PKCS11RS_CROSS_HSM_TARGET_PIN=<authentication-id-and-password> \
cargo test bootstraps_two_yubihsms_online_with_rsa_then_aes_replication \
  -- --ignored --nocapture
```

The test exercises the proposed bootstrap and replication protocol; it does
not enable the not-yet-implemented cluster-backed slot.

The physical-to-physical qualification passes between YubiHSMs `1238075073`
and `2545354682` using their existing full-capability `reserve-symmetric`
Authentication Key. It verifies working replicas on both devices and restores
both native inventories exactly; no reset or credential change is part of the
test.

## Decisions captured by this proposal

- A cluster is one PKCS #11 slot, not several slots connected by a copy API.
- Clustering is a separate, explicitly configured slot implementation.
- Existing direct YubiHSM slots remain on their current implementation path.
- Common slot-level abstractions are deferred until a working cluster provides
  evidence for the correct boundary.
- Clustering is implemented in `pkcs11rs`, above connectors.
- Each member has its own end-to-end YubiHSM secure session.
- The cluster is a true mirror with common object type and ID.
- A static authoritative member handles mutations in the first version.
- RSA full-object wrapping bootstraps the shared AES wrap key online.
- Native AES full-object wrapping is the normal replication path.
- RSA key-material-only wrapping is reserved for migration and recovery.
- Current useful mechanism composition and `CKF_HW` policy remain unchanged.
- Automatic leader election and distributed transactional commit are deferred.
