# Provider boundary direction

Status: current architecture direction. This document does not define a public
provider API or commit the project to publishing one.

## Decision

PKCS11RS is a Cryptoki-centered implementation. `SlotContext` and the internal
backend traits model PKCS #11 sessions, objects, mechanisms, login state, and
errors directly. They are adapter internals, not a candidate public provider
API.

Reusable behavior belongs behind focused, typed boundaries when the boundary
has a concrete second implementation or consumer. Such a component may
represent software cryptography, one protected operation, a device protocol,
canonical storage, or a physical transport. These components do not need to
share one universal `Provider` trait.

A general provider core spanning software tokens, YubiHSMs, fixed-reference
applets, and FIDO credentials is not an architectural objective. It should be
introduced only when demonstrated reuse requires it.

## Layering

```text
PKCS #11 C ABI
    -> Cryptoki runtime
        -> slot and backend adapters
            -> focused capability, protocol, crypto, storage, and transport components
                -> operating-system service, persistent store, or physical device
```

### Cryptoki runtime

The PKCS11RS runtime owns behavior whose correctness is defined by PKCS #11:

- exported symbols, versioned function tables, pointer validation, and panic
  containment;
- initialization, finalization, slot reconciliation, and handle allocation;
- session ownership, login roles, and operation lifecycles;
- object handles, search cursors, templates, attribute mutability, and error
  precedence;
- mechanism parsing, capability projection, and buffer-length behavior;
- software assistance around hardware operations when the advertised slot
  operation requires it; and
- conversion of native objects and errors into the Cryptoki model.

`SlotContext` is the common runtime boundary. Its `Slot` and `BackendSession`
implementations provide backend-specific behavior while the context retains
the shared PKCS #11 state. Because those traits are private to the adapter,
using `CK_*` types in them is not by itself unwanted leakage.

### Backend adapters

Backend adapters join the Cryptoki model to the native behavior of a software
token, YubiHSM, PIV or OpenPGP applet, or FIDO authenticator. They own the
differences that cannot be represented truthfully by a common key-store API:

- fixed references versus allocated object identifiers;
- token-wide, applet-wide, secure-session, and operation-specific
  authorization;
- native discovery, reconnect epochs, caches, and device replacement;
- device capabilities and firmware restrictions;
- native commands, object mutations, and failure semantics; and
- the relationship between native material and one or more projected PKCS #11
  objects.

Backend adapters may combine focused components, but a component does not
become a general provider merely because several adapters use it.

### Focused reusable components

The architecture uses several focused boundary shapes:

| Component | Focused responsibility | Deliberately retained by its caller |
| --- | --- | --- |
| `software-key-core` | Typed, protocol-neutral software key operations and secret ownership | Provider identity, authorization, persistence, PKCS #11 policy, and error mapping |
| `platform-credential` | Protected prefixed X9.63 and CMAC-pair capabilities plus credential lifecycle | YubiHSM session policy, selectors, provisioning policy, and Cryptoki login behavior |
| `yubihsm-auth-client` | Transport-independent YubiHSM Auth APDU and TLV exchange | Reader discovery, transport selection, target-session policy, and error projection |
| `StorageProvider` | Opaque canonical-object storage addressed by content reference | Object meaning, visibility, authentication, handles, and lifecycle policy |
| `pkcs11rs-local-hardware` | Shared blocking and asynchronous YubiHSM USB mechanics | PKCS #11 slots, connector routing, HTTP policy, and secure sessions |
| CTAP and connector traits | Protocol or transport exchange at one natural seam | Slot identity, authorization, object projection, and operation state |

Each boundary exposes a cohesive capability and leaves policy at the layer
with enough information to enforce it.

## Heterogeneous backend semantics

The supported backends do not share one honest object or authorization model.
A software token is a general key store, while PIV and OpenPGP have fixed key
references and applet policy. A YubiHSM has arbitrary native objects behind an
authenticated session and reconnect-sensitive caches. A FIDO credential can
perform a structured protocol assertion without behaving like an ordinary
private key.

Several important operations also cross possible provider boundaries. Public
projection combines native metadata with PKCS #11 object policy. Wrapping
authorizes two objects and a mechanism together. YubiHSM authentication may
use a credential supplied by another device or an operating-system service.
Physical-device coordination can span otherwise independent applet slots.

Forcing these models through one interface would produce either a
lowest-common-denominator API that is too weak for real operations or a large
interface with optional, backend-specific methods that recreates the internal
`Slot` trait under provider-neutral names. The architecture therefore uses
composition of precise capabilities instead of classification behind a single
provider object.

## Design rules for reusable boundaries

1. Extract a cohesive operation or service, not the abstract idea of a
   provider.
2. Require a real second implementation or consumer, or an immediate security
   boundary that benefits from isolation. A hypothetical backend is not
   sufficient on its own.
3. Keep Cryptoki templates, handles, sessions, mechanisms, and `CKR_*` mapping
   in PKCS11RS unless the component itself implements Cryptoki behavior.
4. Use safe, owned or lifetime-safe Rust types in independently reusable
   components. Do not expose raw pointers or borrow caller-owned FFI memory.
5. Make capabilities explicit. Never infer that a hardware backend supports a
   software fallback merely because the primitive exists in a shared crate.
6. Give secret bytes and credentials zeroizing ownership. Prefer operations on
   opaque protected keys to exporting key material.
7. Leave identity, authorization scope, reconnect behavior, and policy with
   the layer that can represent them without false semantics.
8. Keep synchronous and asynchronous execution choices local. The PKCS #11
   call boundary is synchronous, while a connector or operating-system service
   may use an asynchronous implementation internally.
9. Preserve component-specific errors until the adapter has enough context to
   apply the correct PKCS #11 error precedence.
10. Extract a crate only when independent compilation, reuse, platform
    isolation, or dependency control justifies the additional API surface.

## Next steps

### Harden the established boundaries

Add adversarial and fuzz coverage around untrusted binary inputs: CTAP CBOR,
YubiHSM frames, SCP responses, certificate bundles, canonical storage records,
and semantic PKCS #11 templates. Seed fuzz corpora from the protocol vectors
and malformed-input tests. ABI fuzzing must use valid allocated memory with
adversarial shapes and lengths rather than arbitrary invalid pointers.

Keep protocol parsing, size limits, canonical encoding, and secret
zeroization close to the focused component that owns them. Promote regression
inputs into ordinary tests when a failure is found.

### Improve internal adapters opportunistically

The size of `Slot` or `BackendSession` alone is not a reason to introduce a
public provider model. Split an internal capability when doing so removes
duplicated policy, clarifies ownership or locking, or allows materially
different backends to share a correct implementation.

Translate a `CK_*` mechanism or template into a typed operation at the point
where that translation improves validation or enables reuse. Avoid mechanical
conversions that merely move Cryptoki vocabulary behind a new type name.

### Extend focused components for concrete backends

The platform-credential crate defines a symmetric CMAC-pair capability.
Implement it when an operating-system provider can keep both keys
non-exportable and the complete YubiHSM authentication path can be qualified.
Likewise, add another protected-credential backend, such as Windows CNG or a
TPM, without changing selectors or session policy when platform requirements
and test access are available.

New protocol clients and transports should follow the YubiHSM Auth and CTAP
pattern: share the protocol state machine or exchange vocabulary while leaving
discovery and application policy with the caller.

### Prepare releasable artifacts

Add reproducible binary packaging, system installation guidance, and
platform-specific loader examples. Define a small alpha release boundary
around the C ABI and tools without making the internal Rust traits public.

### Introduce a general provider API only with evidence

A common provider core becomes appropriate if one or more of these conditions
is present:

- a non-PKCS frontend needs the same object and operation lifecycle from
  several materially different backends;
- an independently developed backend needs to integrate without importing
  PKCS11RS internals;
- two unlike backends naturally implement the same typed lifecycle without
  optional-method proliferation; or
- duplicated orchestration across adapters is a demonstrated source of
  correctness or security defects.

Any proposal must be validated against software, YubiHSM, a fixed-reference
applet, and FIDO before extraction. It must show that the shared model reduces
coupling without hiding authorization, identity, lifetime, or failure
differences.

## Non-goals

- Publishing the internal `Slot` or `BackendSession` traits.
- Making every backend look like a general-purpose key store.
- Moving PKCS #11 policy into protocol or cryptographic utility crates.
- Replacing explicit backend behavior with optional methods solely to obtain
  one common trait.
- Imposing one runtime, storage system, or authorization representation on all
  components.
- Extracting crates or FFI macros without an independent use or dependency
  boundary.

## Success criteria

The architecture succeeds when:

- PKCS11RS implements complete Cryptoki behavior without exposing unsafe FFI
  concerns to reusable components;
- shared cryptography, protocols, protected operations, storage, and
  transports can be tested independently;
- adding a backend does not require duplicating an established reusable
  component;
- capability advertisement remains exact and no backend gains false fallback
  behavior;
- authorization, object identity, reconnect state, and secret ownership remain
  explicit; and
- internal abstractions make correctness and security easier to verify rather
  than merely making the type hierarchy more uniform.
