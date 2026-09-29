# YubiHSM cluster-backed slot design

## Status

This document is the ready-to-implement proposal for YubiHSM clustering in
`pkcs11rs`. The design decisions required for the first implementation are
specified below; the cluster-backed slot itself is not yet implemented.
Existing YubiHSM discovery continues to expose one PKCS #11 slot per device.

The proposal deliberately keeps clustering inside `pkcs11rs`. Each member has
an end-to-end YubiHSM secure session from the PKCS #11 process to that member;
there is no protocol-terminating proxy or Virtual YubiHSM between them.

## Goals

- Present a set of equivalent YubiHSMs as one stable PKCS #11 slot.
- Keep every persistent cluster object on every member, except while a member
  is unavailable or catching up.
- Preserve one object type and ID across all replicas.
- Maintain a verified per-object replica set and route cryptographic operations
  only to members known to hold every object required by the operation.
- Replicate generation, import, deletion, and metadata changes automatically.
- Fan replication out in parallel and allow deployments to choose how many
  verified replica imports a PKCS #11 creation call waits for.
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
- Automatic authority promotion or multi-writer conflict resolution.
- Consuming one additional YubiHSM object for metadata about every mirrored
  application object.
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
    ├── one statically configured authoritative member
    ├── logical inventory from the authority
    ├── per-object verified replica sets
    ├── per-object mutation and replication queues
    └── two or more configured cluster members
        ├── Connector
        ├── YubiHSM secure-session state
        ├── health, connection epoch, and operation queue
        ├── observed object sequence
        └── current load and latency observations
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

1. One statically configured member is authoritative for every persistent
   cluster object. Its object value and policy are canonical; absence on the
   authority canonically means that the object must be absent everywhere.
2. Object generation, plaintext import, replacement, and ID allocation occur
   only on the authority. Followers never introduce an object into the
   authority during ordinary reconciliation.
3. Every fully replicated object has the same object type, ID, key material,
   and effective policy on every configured member. Member-local `origin` and
   `sequence` fields are not copied identity fields.
4. Replica eligibility is tracked per object. A member may serve one key while
   remaining pending, unavailable, or divergent for another.
5. An operation is routed to a member only when that member is verified for
   every persistent object required by the operation and can execute the
   selected mechanism path.
6. Replication acknowledgement never makes an unverified copy routable. Import
   completion, verification, and publication are one ordered state transition.
7. Cluster infrastructure and member-local objects occupy reserved identities
   and are not exposed as ordinary application objects.
8. Only members with a compatible native wrapped-object format, cluster wrap
   key, authorization model, and required algorithm surface may belong to the
   same mirrored cluster.
9. Member application objects are mutated only through the cluster slot.
   Administrative raw-member access fences that member from application
   routing until reconciliation completes.

The physical YubiHSM limit of 256 resident objects is small relative to the
16-bit object-ID space. The cluster reuses the direct YubiHSM slot's
collision-checked allocator against a fresh authority inventory, excludes all
cluster infrastructure IDs, and retries if a concurrent process wins the ID.
It does not persist an independent allocation cursor and followers never choose
application IDs. Routine reuse is avoided, but correctness does not depend on
never reusing an ID.

The cluster identity of an object is its object type and ID. The authority's
creation operation determines logical PKCS #11 properties such as `CKA_LOCAL`;
a replica imported under wrap must not cause the logical object to appear
nonlocal merely because that particular copy has an imported device origin.

The native YubiHSM `sequence` is an unsigned eight-bit, member-local reuse
counter. In normal cluster-only lockstep operation it should be equal across
members, including when it rolls over. Compare two values with serial-number
arithmetic: for `delta = a.wrapping_sub(b)`, `1..=127` means `a` is later under
the cluster assumptions, `129..=255` means `b` is later, and `128` is
ambiguous. Equality is a useful health invariant but is not proof of equal key
material: independently generated keys can have identical metadata and
sequence values, and 256 extra creations can hide a divergence.

Sequence never overrules the configured authority or selects the canonical
copy. A mismatch raises a diagnostic and requires verification or repair. When
a follower is already being repaired, is known to be behind the authority by
`d` creations, and `d` is no greater than `sequence_catch_up_limit`, the worker
performs `d` total authenticated imports of the same authority blob, deleting
the previous copy before each import. The first import repairs the material;
the remaining `d - 1` imports restore counter alignment. Every cycle ends with
the authoritative material installed before another cycle begins.

Catch-up is never performed merely to make an otherwise verified replica's
counter look tidy. A follower that is ahead, an ambiguous distance of `128`,
an unexplained history, or a distance above the configured limit receives the
required material repair but retains a sequence-divergence warning. Native
audit-log exhaustion or any failed extra cycle stops normalization without
changing which object is canonical.

## Logical PKCS #11 token

### Identity and presence

An explicit cluster has a configured stable token label and serial independent
of any member serial. Member serials remain diagnostic and security identities.
Direct slots continue to use their existing physical-member identities.

The logical token is present when at least one eligible member can serve its
advertised read and cryptographic surface. Persistent mutation additionally
requires the authoritative member. Loss of a follower does not remove the
slot. Loss of the authority makes the slot read/crypto-capable but read-only in
the initial design. After a process restart without the authority, only the
last cataloged authority inventory and followers whose receipts still validate
may be exposed. If no trustworthy authority observation is available, the slot
does not infer an inventory from follower contents and remains unavailable.

### Objects

Object enumeration is a logical cluster inventory rather than the union of
member inventories. The authority defines that inventory, each replicated
object appears once, and absence on the authority suppresses and schedules
deletion of extra follower copies. Handles resolve to a cluster object identity;
they never encode a physical member.

For every `(object type, object ID)`, the cluster maintains a replica map:

```text
authority: canonical object information and identity evidence
member 1238075073: authoritative
member 2545354682: verified
member 37070618:    pending import
```

The member state is one of `authoritative`, `unknown`, `pending`, `importing`,
`verified`, `divergent`, or `unavailable`. It includes the last observed native
sequence, connection epoch, verification method, and any queued replication
generation. Only `authoritative` and `verified` members enter the routing set
for that object. Disconnecting a member changes it to `unavailable`;
reconnecting does not restore eligibility until inventory and identity checks
complete.

An object is `fully replicated` exactly when the authority and every configured
follower are eligible for that object. This value is computed directly from
the replica map and is independent of whether the creating PKCS #11 call used a
smaller acknowledgement threshold. Cluster diagnostics expose the exact
pending, divergent, or unavailable members instead of only a cluster-wide
healthy flag.

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
Volatile native session objects are a Virtual YubiHSM extension, not a physical
YubiHSM 2 feature. When a compatible virtual cluster advertises that extension,
such objects remain bound to the member and secure session that created them.
Physical clusters use provider session objects and have no native-session-object
pinning case.

### Replica identity evidence

Matching YubiHSM object information is necessary but not sufficient. Two keys
can have the same type, ID, length, domains, capabilities, delegated
capabilities, algorithm, label, origin class, and sequence while containing
different key material.

The cluster accepts the following identity evidence:

- asymmetric keys: equality of algorithm and public key bytes;
- certificates, templates, and readable opaque objects: equality of a digest
  of the canonical value;
- symmetric, HMAC, Authentication, and wrap keys during replication:
  successful import of the exact authenticated full-object blob exported from
  the authority, followed by matching object information;
- an operation-specific cryptographic challenge when the object's capabilities
  permit a non-destructive comparison.

An import receipt is scoped to the authority object observation from which the
blob was exported. Before a queued blob is imported, the worker rechecks that
the authority's type, ID, sequence, policy, and available identity evidence
still describe that observation. A stale queued blob is discarded and the
current authority object is exported instead. This prevents delayed background
work from overwriting a newer authority generation.

The live replica map is reconstructible from the HSMs. A compact, atomically
stored host-side receipt catalog records successful imports, observed member
sequences, canonical public/value digests where available, and the authority
observation for each logical object. It contains no plaintext key material and
does not replace the authority as the source of truth. On restart, matching
receipts avoid rewriting non-readable symmetric objects. A missing,
inconsistent, or ambiguous receipt produces `unknown`, never `verified`; the
manager then obtains fresh cryptographic evidence or re-replicates from the
authority. No application labels are repurposed and no per-object opaque HSM
objects are consumed.

The catalog schema contains:

- schema version, cluster name, authority serial, ordered member serials, and
  wrap-key ID;
- a monotonically increasing host-side catalog generation;
- for each `(object type, object ID)`, the authority's stable object-information
  digest, native sequence, logical PKCS #11 attributes, and public/readable
  value digest when one exists; and
- for each member receipt, its serial, observed sequence, proof kind, and the
  catalog generation whose authority blob it imported or verified.

The host-side generation orders receipts and stale jobs; it is not written into
the HSM and does not compete with the native eight-bit sequence. Receipt updates
required for the caller's acknowledgement are durably installed before the
PKCS #11 call returns.

### Mechanisms and hardware flags

An explicit cluster advertises a stable compatibility profile no broader than
the intersection of every configured member's qualified mechanism surface.
Temporary member absence does not change the advertised mechanism list. A
member lacking a required algorithm or wrapped-object compatibility cannot be
admitted to that cluster.

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

Cluster login preserves all three existing client-authentication paths:
direct password material, a YubiHSM Auth credential, and an ordinary PKCS #11
credential used to establish the member session. Present-member authentication
is attempted in parallel. Logical login succeeds when at least one compatible
member authenticates; failures leave the affected members ineligible and are
reported diagnostically. A write still requires the authority plus enough
authenticated followers to satisfy its acknowledgement policy.

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

## Routing of non-mutating operations

The cluster chooses a member for each YubiHSM command. The command representation
declares every persistent object identity it requires and whether it references
member-bound native session state. The candidate set is the intersection of
the `verified` replica sets for every required object, further restricted by
authentication role, mechanism support, connection health, and session
ownership.

Implementation adds a semantic routing description to `YubiHsmCommand` rather
than parsing encoded command bytes. Every command is classified as one of:

- keyless and routable to any compatible member;
- read-only with one or more required persistent object identities;
- an authority-only persistent mutation; or
- pinned to a specific member and secure session by a native session-object
  handle; or
- explicitly targeted to one member for an administrative or attestation
  request.

The description also returns all referenced persistent objects, including both
objects in a native wrap command. Adding a new YubiHSM command requires an
explicit routing classification; an unknown classification is rejected rather
than defaulting to an arbitrary member.

Examples include:

- signing, decryption, MAC, and single-key derivation require one verified key;
- native wrapping requires a member verified for both the wrapping key and the
  object being wrapped;
- operations without a secret key, including random generation and safe
  keyless native operations, may use any healthy compatible member;
- `C_FindObjectsInit`, `C_FindObjects`, and `C_FindObjectsFinal` search a stable
  snapshot of the authority-derived logical index in host memory; they are not
  routed HSM operations;
- ordinary attribute reads use the same canonical cache rather than selecting
  arbitrary follower metadata; a value that genuinely requires a native read
  is fetched from the authority or a verified copy and then cached;
- software public-key operations remain local and do not consume an HSM worker;
- member-specific attestation targets the named member for that call;
  authority-generation provenance targets the authority.

Each member has an independent queue owning its secure-session command stream.
For a one-shot operation, the selector chooses the candidate with the smallest
foreground queue, then the lowest recent latency, with a rotating tie-breaker.
The exact latency estimate is diagnostic rather than a security decision.
Operations required to satisfy a caller's write acknowledgement are foreground
work. Imports for acknowledgements already satisfied and ordinary stale-member
catch-up are lower-priority background work, so a busy HSM does not delay an
otherwise satisfiable PKCS #11 call.

Most completed PKCS #11 key operations produce one YubiHSM command. Large AES
ECB/CBC inputs and composed CTR/GCM/CCM/CMAC paths may produce several chunked
commands, but their buffering, IV, counter, authentication, and multipart state
remain in `pkcs11rs`. They create no streaming state in the HSM, so successive
commands may select different verified replicas of the same key. Host state is
advanced only after the selected command succeeds.

Virtual YubiHSM native session objects are the exception. In a virtual cluster
whose qualified profile advertises the extension, they and every command that
references them are pinned to their creating member and secure session. Failure
of that member invalidates those volatile objects rather than attempting to
recreate or transfer them. A token-object derivation is a persistent mutation
and therefore executes on the authority; a native session-object derivation
may begin on any eligible virtual member and pins the resulting object there.
Physical YubiHSM firmware has no such object and therefore no equivalent
pinning path.

This is the complete meaning of pinning in the first implementation. A logical
PKCS #11 session, persistent object handle, multipart operation, or ordinary
replicated-key operation is never pinned to a member. Host-memory session
objects are not native YubiHSM session objects and create no member affinity.
Explicitly targeted attestation, enrollment, audit, or device-administration
commands choose one member for that call but establish no continuing pin.

Transport failure known to have occurred before command submission removes the
member and reruns selection. After an uncertain submission:

- repeatable reads may be retried elsewhere;
- a one-shot cryptographic operation may be retried only when no result escaped
  and producing another valid result is safe;
- a failed chunk in a host-managed multipart operation may be retried on
  another verified holder before host state advances;
- member-specific attestation is not silently moved to another member; and
- generation, import, replacement, and deletion are reconciled against the
  authority instead of replayed blindly.

If no member is verified for every required object, the operation returns the
appropriate key, token, or device availability error. Merely observing an
object with the right ID on an unverified member never makes it eligible.

Inventory maintenance is control-plane work. Authority refresh and follower
reconciliation issue `ListObjects`, `GetObjectInfo`, public-key, and readable
value commands independently of application search cursors. Refresh publishes
a new logical-index snapshot atomically; an in-progress `C_FindObjects`
continues over the snapshot with which it started.

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

The first implementation standardizes on one reserved AES-256-CCM wrap key per
cluster. It is present at the same wrap-key ID on every member, hidden from the
logical application inventory, and has only the capabilities needed to export
and import full objects and to be bootstrapped under an RSA wrap key. Its
delegated capabilities are the explicit union of policies the cluster permits
on mirrored objects; they are not an unrestricted firmware-wide default.

Cluster creation/import ensures the native `exportable-under-wrap` permission
needed for replication without treating the key as plaintext-extractable
through PKCS #11. An imported template whose requested policy cannot be
represented while retaining internal wrapped replication fails with
`CKR_TEMPLATE_INCONSISTENT`; the cluster does not silently create a primary-only
persistent object. Existing objects lacking the required native permission
must be migrated explicitly before they can enter the mirrored inventory.

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

Generation and plaintext import run only on the configured authority.
The authority assigns the final object type and ID. Mutations of the same
object are serialized within a process. Automatic ID allocation rereads the
authority and retries a collision, because another PKCS #11 process may have
allocated an ID concurrently.

Before mutating the authority, the manager verifies that enough authenticated
members are available to satisfy the configured acknowledgement threshold.
After successful creation:

1. read and cache the authority's canonical object information and available
   identity evidence;
2. export one full-object blob under the cluster AES wrap key;
3. install a replication job before allowing the caller to observe success;
4. dispatch the same blob concurrently to every eligible follower;
5. after each import, read object information, establish identity evidence,
   persist its receipt, and transition that member to `verified` atomically
   from the logical slot's perspective;
6. return from the PKCS #11 call when the configured number of follower imports
   are verified; and
7. retain the blob in memory and continue lower-priority retries until every
   configured member is verified.

`required_replica_imports` is a count of followers, not a consensus quorum. It
ranges from zero through `member_count - 1`:

- `0` acknowledges after the authority write, successful export, and queue
  installation;
- `1` acknowledges after one verified follower import, yielding two durable
  copies and serving as the default; and
- `member_count - 1` provides fully synchronous all-member replication.

Every follower import starts in parallel. The acknowledgement waits for the
first required number of verified completions, not for particular serials, so
a busy member does not determine latency when enough others respond. The
steady-state critical path is the authority operation, one AES full-object
export, the slowest import required by the threshold, and its verification.
Cluster size does not add serial import latency.

The in-memory blob is an optimization and failure-recovery aid, not the only
copy of acknowledged state. If the process exits, reconciliation re-exports
the current authority object and rebuilds missing jobs. If the authority fails
while the process remains alive, a retained blob can still complete already
queued follower imports. A bounded queue may discard a blob under pressure
only after preserving the `pending` state; the object can be exported again
from the authority. Wrapped blobs are treated as sensitive ciphertext and
zeroized when a job completes, is superseded, or is discarded.

If the authority commits but an unexpected failure prevents the configured
acknowledgement threshold, the call returns a device error with an uncertain
creation result. The authority remains canonical; the manager must not invent
a rollback that it cannot make atomic across devices. Enumeration and
reconciliation expose and replicate the authority object after recovery.

Concurrent callers use the authority as the serialization point for object
creation and ID allocation. No follower allocates a competing ID. The first
implementation uses a statically configured authority and does not perform
automatic write failover.

### Metadata changes

YubiHSM metadata that requires object replacement follows the same authoritative
mutation path. A queued job for an older authority observation is discarded
before import. The cluster must not route the changed object to a member still
holding the previous effective capabilities, domains, or key generation.

### Deletion

Deletion uses a stricter rule because returning success while a secret copy
remains on a cluster member has undesirable security semantics. The first
implementation requires every configured member to participate unless an
administrator has explicitly removed and fenced that member from the cluster.

The manager first exports a recovery blob, then deletes follower copies in
parallel, and deletes the authority copy last. The authority deletion is the
commit point:

- if the operation stops before it, the authority still defines the object as
  present and recovery restores any already-deleted followers;
- if the authority is confirmed absent, every configured follower was already
  confirmed absent and the logical object disappears; and
- if the authority response is uncertain, the manager queries it before
  deciding whether to restore followers or finalize deletion.

Pending imports for the object are cancelled before follower deletion and
per-object ordering prevents an old blob from recreating the object. The
authoritative inventory therefore prevents resurrection without storing
tombstones in YubiHSM object slots.

## Reconciliation

At only 256 resident objects, full inventory comparison is practical. Repair
still works per object so a healthy replica for one key does not remain fenced
because an unrelated key is pending.

Initialization and every member connection-epoch change run the same sequence:

1. connect to and identify configured members without publishing claimed raw
   slots;
2. load and validate the receipt catalog;
3. query the authority inventory and make it the new logical-index snapshot;
4. query follower inventories concurrently;
5. rebuild each object's replica map from live metadata, available identity
   evidence, and matching receipts;
6. publish the logical slot when at least one member can serve the validated
   inventory; and
7. enqueue missing, conflicting, unknown, and extra follower objects for
   per-object reconciliation.

If the authority is absent at initialization, step 3 uses only the last
cataloged authority snapshot and cannot add, remove, or change logical objects.
At least one follower must validate against that snapshot for the token to be
present. When the authority returns, its live inventory replaces the snapshot
and may invalidate handles to objects that no longer exist, following the same
cache-generation behavior as existing direct slots.

A member becomes stale after an uncertain mutation, transport loss during
replication, incompatible object sequence change, or observation of unexpected
member-local mutation. Before it becomes eligible again:

1. remove affected objects on that member from their verified routing sets;
2. preserve the reserved member-local bootstrap objects;
3. compare its cluster-managed inventory with the authority;
4. delete extra or conflicting cluster-managed objects;
5. import the authoritative full-object representations for missing or replaced
   objects;
6. establish the same identity evidence required for an ordinary replication;
7. record observed sequences and warn about unexpected serial-number
   divergence; and
8. mark each object verified independently.

For a clean join or a member with missing or ambiguous receipts, rebuilding
every cluster-managed object is acceptable and avoids pretending that matching
metadata proves equality of non-readable symmetric or private material. A
native import collision on a supposedly clean destination is an inconsistency
signal, not a request to allocate another ID. The conflicting object is never
used; after administrative policy permits replacement, it is deleted and the
authority's copy is imported at the same type and ID.

The receipt catalog is a cache of demonstrated replication, not an independent
desired-state database. If it is lost, the authority inventory still defines
the desired state. Publicly identifiable objects can be checked directly;
objects without sufficient identity evidence are conservatively
re-replicated. If the authority is unavailable, reconciliation pauses instead
of allowing followers to elect a value.

## Authority, concurrency, and multiple processes

`pkcs11rs` is loaded independently into multiple application processes. Each
process keeps its own member connections, secure sessions, queues, health
samples, and routing decisions. Every process must use the same configured
authority, membership, wrap-key identity, acknowledgement policy, and host-side
receipt catalog.

The initial design relies on these rules:

- only the configured authority accepts application mutations;
- the authority serializes its own commands and object creation;
- replicas never create cluster application objects independently;
- reconciliation always flows from authority to followers;
- queued replication revalidates the current authority observation before
  importing, so one process cannot replay a stale blob after another process
  replaced the object; and
- automatic authority promotion is disabled.

Auto-ID collisions caused by concurrent processes are retried against a fresh
authority inventory. Concurrent replacement or deletion of the same identity
has ordinary uncertain-result semantics and converges to the final authority
state; applications must not expect cross-process compare-and-swap semantics.
Membership changes, destructive reconciliation of an unexplained conflict,
wrap-key rotation, and authority promotion require an administrative exclusion
mechanism. The host-side catalog uses the project's atomic storage support and
a process lock on one host. Coordinating mutation from several independent
hosts is outside the first implementation; deployments must nominate one
mutation host even though other hosts may perform routed cryptographic
operations.

If the authority is unavailable, objects already verified on followers remain
usable. Generation, import, replacement, deletion, and reconciliation return
an appropriate token/device write error until the authority returns. Promotion
is an explicit administrative workflow: fence the old authority, verify that
the candidate contains every authority object using the last complete evidence
available, update configuration, and reinitialize the cluster. Automatic
promotion and promotion from ambiguous state are not part of the first
implementation.

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
- the expected member serials, resolved through existing discovery sources;
- the authoritative member;
- the reserved cluster AES wrap-key ID;
- the number of follower imports required before acknowledging creation;
- the bounded sequence catch-up policy; and
- the host-side receipt catalog.

The first implementation extends the existing strict `yubihsm` configuration
with structured `clusters` and no environment-variable shorthand:

```json
{
  "version": 1,
  "yubihsm": {
    "urls": ["https://connector.example:12345"],
    "clusters": [
      {
        "name": "production-signing",
        "token_label": "production HSM cluster",
        "token_serial": "cluster-01",
        "authority": "1238075073",
        "members": ["1238075073", "2545354682"],
        "wrap_key_id": 65533,
        "required_replica_imports": 1,
        "sequence_catch_up_limit": 8,
        "receipt_catalog": "/var/lib/pkcs11rs/production-signing.cbor"
      }
    ]
  }
}
```

All cluster fields are required except `required_replica_imports`, which
defaults to `1`, and `sequence_catch_up_limit`, which defaults to `8` and may
be set to `0` to disable extra normalization imports. Configuration validation
requires:

- a unique nonempty `name`, PKCS #11-compatible token label, and stable token
  serial;
- at least two distinct member serials;
- an authority present exactly once in `members`;
- a nonzero wrap-key ID;
- `required_replica_imports < members.len()`;
- `sequence_catch_up_limit <= 127`; and
- a receipt path not reused by another cluster in the process.

Unknown fields, duplicate members, overlapping membership, duplicate logical
token identity, or a member also claimed by another configured cluster fail
`C_Initialize` with `CKR_ARGUMENTS_BAD`. A configured value of zero is valid
and selects primary-only acknowledgement. Cluster identity is never inferred
merely because several devices contain a wrap key with the same ID.

The receipt catalog uses canonical CBOR and the existing atomic persistence
support. It is replaced durably as one generation, locked across local
processes, and contains no secret or wrapped key material. The host running
`pkcs11rs` and the catalog's filesystem permissions are inside the cluster
manager's trust boundary; parsing is nevertheless bounded and
schema-versioned, and every receipt is checked against live HSM observations
before use. Losing, corrupting, or failing to persist the catalog degrades
replicas to `unknown`; it cannot change the authoritative inventory or cause
follower data to be imported into the authority.

Discovery may find configured members through direct USB or independent remote
HTTP connectors. Transport type does not affect membership. A member is
accepted only after its verified serial and device identity match the cluster
configuration. A claimed member is withheld from ordinary direct-slot
publication even while unavailable, preventing a transient discovery failure
from exposing it later as an independent application slot. Member transport
locators continue to come from normal local discovery and `yubihsm.urls`; the
cluster configuration binds discovered connectors by verified HSM serial
rather than duplicating connector configuration. Enrollment derives and stores
the qualified mechanism and wrapped-object-format profile; every configured
member must match it before becoming eligible.

## Implementation boundary

The current `YubiHsmSlot` remains the direct single-device implementation. The
cluster is introduced as a separate `YubiHsmClusterSlot` selected only by
explicit configuration. It owns logical handles, member selection, authority,
replication, reconciliation, and cluster-specific operation state.

The initial implementation has five cluster-specific components:

- `YubiHsmClusterSlot`: logical PKCS #11 identity, inventory, handles, login,
  mechanism surface, and routing policy;
- `ClusterMemberWorker`: one owned connector, secure session, foreground and
  background queues, health, and load observations for one HSM;
- `ClusterObjectState`: the canonical authority observation and per-member
  `ReplicaState` map for one object identity;
- `ReplicationJob`: one authority observation, retained wrapped blob, required
  acknowledgement count, and per-member results; and
- `ClusterReceiptCatalog`: atomic non-secret evidence used to reconstruct
  verified replica sets after restart.

Member workers are the parallelism boundary. A YubiHSM secure session remains
owned and serialized by exactly one worker; parallel replication means sending
independent imports to independent member workers, never using one SCP session
concurrently or moving its counters between connectors. Synchronous PKCS #11
calls wait through bounded worker responses without requiring an async ABI.

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
   - Add the strict schema above, validation, receipt-catalog persistence, and
     a separate `YubiHsmClusterSlot`.
   - Claim configured members and publish one stable slot.
   - Leave unclaimed devices on the existing direct-slot path and suppress raw
     application slots for claimed members.
   - Add per-member workers, independent secure sessions, capability
     intersection, authority-derived logical inventory, and per-object replica
     maps.
2. **Authenticated routing**
   - Authenticate present members at logical login.
   - Implement verified-holder intersection for one- and two-object commands.
   - Route each stateless native command independently, pin only native session
     objects, and explicitly target member-specific administrative operations.
   - Load-balance safe one-shot operations by queue depth and observed latency.
3. **Preprovisioned replication**
   - Use an already installed common AES wrap key.
   - Implement authoritative generation/import, one-export parallel fan-out,
     configurable replica acknowledgements, retained-blob background catch-up,
     strict deletion, stale-job rejection, and full reconciliation.
   - Cover every supported mirrored object class, including identity evidence
     for objects whose key material is not readable.
4. **Online enrollment**
   - Generate the joining member's RSA wrap key.
   - Verify its public key and use RSA full-object wrapping to install the
     cluster AES wrap key.
   - Synchronize and activate the member.
5. **Operations and diagnostics**
   - Add authority, member health/load, per-object replica state, pending
     acknowledgements, sequence divergence, receipt proof, and reconciliation
     reporting to `pkcs11rs-tool` or a dedicated administrative interface.
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
- Verify identical type, ID, domains, capabilities, label, algorithm, and key
  identity on all members while accepting member-local origin and sequence.
- Exercise asymmetric, symmetric, HMAC, opaque, certificate, template,
  authentication, and wrap objects where supported.
- Construct two keys with identical metadata and prove that metadata comparison
  alone never marks the wrong material verified.
- Prove asymmetric public-key, readable-value, import-receipt, and functional
  challenge verification paths independently.
- Verify source logical origin and replica physical origin are not confused.
- Verify deletion and metadata mutation converge.
- Verify one full-object export fans out concurrently and the same blob reaches
  every follower.
- Exercise every valid `required_replica_imports` value and reject invalid
  configuration.
- Block one busy follower and verify the call returns after the fastest required
  imports while background replication later completes.
- Replace an authority object while an old blob is queued and prove the stale
  job cannot overwrite the new generation.

### Failure and recovery

- Lose each member before submission, after submission, during response, and
  during replication.
- Drop a mutation response after the authority committed it and verify later
  reconciliation.
- Rejoin a stale member containing missing, extra, and conflicting IDs.
- Verify a conflicting native import never causes allocation of a different
  replica ID.
- Lose the in-memory replication queue and rebuild it from the authority.
- Lose or corrupt the receipt catalog and prove that replicas become unknown,
  not silently verified or authoritative.
- Exercise sequence equality, forward and reverse divergence, rollover,
  the ambiguous distance of 128, and bounded known-history catch-up.
- Interrupt deletion before and after the authority-last commit point and prove
  that recovery respectively restores or completes deletion.
- Verify read/crypto availability without the authority and write rejection
  without explicit promotion.

### Sessions and concurrency

- Use multiple PKCS #11 sessions without opening one HSM session per
  application session.
- Use multiple processes generating objects concurrently through one
  authority.
- Route one-key and two-key operations only to the intersection of verified
  holder sets.
- Verify foreground acknowledgement imports outrank background catch-up without
  starving it.
- Verify queue-depth/latency selection avoids a busy member and eventually uses
  it again after recovery.
- Verify member session counters never cross connectors.
- Verify chunked and multipart host-managed operations may move safely between
  verified replicas while native session objects remain pinned.
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
prints key material. The equality assertion in this qualification applies to
its deliberately aligned lockstep IDs; cluster object identity does not depend
on sequence equality.

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
test. Creation and deletion necessarily advance member-local sequence counters
and native audit logs.

An additional manual qualification advanced the temporary object sequence on
one member at a time before replication. When the authority generated an AES
wrap object at sequence `4`, the imported follower copy received its own local
sequence `3`. In the reverse condition, an authority P-256 object at sequence
`3` imported as sequence `4` on the pre-advanced follower. Full-object wrapping
therefore does not transport the source sequence; each HSM advances its own
eight-bit counter. After the temporary counters were realigned, the complete
qualification again passed with AES sequence `6` and P-256 sequence `5` on
both members, and all temporary objects were removed.

## Decisions captured by this proposal

- A cluster is one PKCS #11 slot, not several slots connected by a copy API.
- Clustering is a separate, explicitly configured slot implementation.
- Existing direct YubiHSM slots remain on their current implementation path.
- Common slot-level abstractions are deferred until a working cluster provides
  evidence for the correct boundary.
- Clustering is implemented in `pkcs11rs`, above connectors.
- Each member has its own end-to-end YubiHSM secure session.
- The cluster is a true mirror with common object type and ID.
- A static authority defines the canonical value and policy, including
  canonical absence, for every object in the first version.
- Replica knowledge and operation routing are per object, not a single global
  current/stale flag for the whole member.
- Matching metadata is not proof of matching key material; routing requires a
  supported identity proof or a verified import receipt.
- Replica imports fan out concurrently from one AES-wrapped blob.
- Creation acknowledgement waits for a configured number of verified follower
  imports; one follower is the default and remaining copies catch up in the
  background.
- The wrapped blob remains in memory until all members verify or the job is
  reconstructed from the authority.
- Deletion requires every configured member, deletes followers in parallel,
  and deletes the authority last as the commit point.
- Native sequence is a wrapping, member-local health signal. It is compared
  with eight-bit serial arithmetic, never used to overrule the authority, and
  never accepted as proof of key identity.
- Replica receipts are stored in a compact host-side atomic catalog rather than
  application labels or per-object opaque HSM objects.
- RSA full-object wrapping bootstraps the shared AES wrap key online.
- Native AES full-object wrapping is the normal replication path.
- RSA key-material-only wrapping is reserved for migration and recovery.
- Current useful mechanism composition and `CKF_HW` policy remain unchanged.
- Every stateless non-mutating HSM command uses the least-loaded eligible
  verified holder. Only native member-local session objects are pinned;
  administrative and member-attestation calls are explicitly targeted for one
  command without creating ongoing affinity.
- Automatic leader election and distributed transactional commit are deferred.
