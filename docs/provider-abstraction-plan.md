# Pure Rust provider abstraction plan

Status: long-term architecture roadmap. This document does not describe a
current public API or commit to publishing a crate.

## Objective

Define a small, safe Rust abstraction for cryptographic key providers that do
not need to implement the PKCS #11 ABI, session model, object handles,
attribute templates, or return-code rules themselves. pkcs11rs would become
an adapter from the complete Cryptoki model to that provider API.

The abstraction is valuable only if it expresses the native behavior of
substantially different providers without becoming PKCS #11 under different
names. The software token, YubiHSM, PIV, OpenPGP, and FIDO backends provide the
test cases from which to discover it.

## Intended layering

```text
PKCS #11 C ABI
    -> Cryptoki lifecycle, sessions, handles, templates, and operations
        -> pure Rust provider traits and typed requests
            -> software, YubiHSM, PIV, OpenPGP, and FIDO providers
                -> storage or physical transport
```

The PKCS #11 adapter remains responsible for:

- exported C symbols, versioned function tables, pointer validation, and panic
  containment;
- initialization, finalization, slot discovery, and concurrency;
- PKCS #11 session and operation state;
- object handles, search cursors, and buffer-length query behavior;
- attribute parsing, defaults, inheritance, consistency, and mutability;
- mapping mechanisms into typed provider requests;
- mapping provider errors into the required `CKR_*` precedence; and
- projecting provider objects into the PKCS #11 object model.

A provider remains responsible for:

- stable native object identity and discovery;
- authentication and the scope of the resulting authorization;
- native algorithms and capabilities;
- generation, import, use, and destruction of supported keys;
- persistence or hardware communication;
- enforcing restrictions that cannot safely be represented above the
  provider boundary; and
- never exporting secret material unless an explicit authorized operation
  requires it.

## Candidate Rust model

The eventual API should use owned or lifetime-safe Rust values rather than
`CK_*` types. Likely concepts include:

- `Provider`, `ProviderId`, and `ObjectId`;
- zeroizing credentials and opaque `Authorization` values;
- typed algorithm, usage, lifetime, and key-policy enums;
- object summaries separated from sensitive or expensive material;
- explicit capability discovery;
- typed generation, import, sign, verify, encrypt, decrypt, derive, wrap, and
  unwrap requests; and
- a provider error type that preserves useful distinctions without embedding
  PKCS #11 return values.

This list is a design vocabulary, not a trait definition. The interface must
be derived from implementations rather than frozen in advance.

## Design principles

1. The core provider API must be safe Rust and contain no raw pointers.
2. It must not expose PKCS #11 handles, attributes, mechanisms, sessions, or
   error constants.
3. Capabilities must be explicit; an adapter must never infer that one
   provider supports another provider's software fallback.
4. Object identity must remain stable independently of front-end handles.
5. Secret bytes and credentials must have zeroizing ownership. Prefer opaque
   provider-held keys over returning key material.
6. Authentication must express scope and lifetime without assuming the
   Cryptoki USER/SO session model.
7. Fixed-slot devices, general object stores, remote HSMs, and local software
   stores must all be representable without false behavior.
8. Vendor-specific functionality needs typed extension points rather than raw
   PKCS #11 escape hatches in the core traits.
9. Synchronous operation is sufficient initially because the PKCS #11 ABI is
   synchronous. Do not impose an async runtime on providers.
10. The abstraction must improve independent provider testing and reduce
    backend coupling in pkcs11rs even if it is never published.

## Questions the implementations must answer

- Is authentication represented by a scoped value, provider state, or both?
- How are providers whose authorization changes globally reconciled with
  authorization values held by callers?
- Which metadata is native and which belongs exclusively to the PKCS #11
  projection?
- Can one object expose several cryptographic aspects without copying its
  identity or material?
- How should fixed PIV/OpenPGP references coexist with providers that allocate
  arbitrary object identifiers?
- How are FIDO credentials represented when they support a protocol operation
  but not ordinary private-key access?
- Where are cross-object operations such as wrapping authorized and enforced?
- How are provider reconnects, device replacement, and cache epochs surfaced?
- Which errors must retain enough structure for correct PKCS #11 error
  precedence?

These questions should remain visible during refactoring; resolving them by
leaking `CK_*` values into the provider layer would defeat the objective.

## Incremental development plan

### 1. Use new key operations as a design probe

The planned software AES, HMAC, derivation, and wrapping work should introduce
typed internal requests before adding more PKCS #11-specific methods to the
backend traits. Compare the software and YubiHSM paths for every new
operation.

The proposed
[provider-backed YubiHSM authentication credentials](yubihsm-auth.md#future-provider-backed-authentication-credentials)
are a second design probe. A regular P-256 key, and later an explicit AES-128
K-ENC/K-MAC pair, should authenticate without exporting static key material or
turning provider identities into transient PKCS #11 handles. The design must
also establish authorization lifetime and deadlock-free cross-provider lock
ordering before it is implemented.

### 2. Purify one internal boundary

Move algorithm selection, provider object identity, capabilities, and errors
away from raw `CK_*` types while retaining the current PKCS #11 adapter and
tests. Do not change the external ABI.

### 3. Prove the model with unlike providers

Require at least the software provider and YubiHSM provider to implement the
same core traits. Then test the model against a fixed-slot applet and a FIDO
credential provider. A trait used only by two similar key stores is not yet a
general provider abstraction.

### 4. Separate optional runtime services

Keep provider traits small. Handle allocation, session ownership, object
projection, metadata storage, and operation buffering may become reusable
runtime components, but should not be mandatory parts of the core provider
API.

### 5. Consider workspace extraction

Only after the internal boundary is stable, split it into workspace crates.
A likely shape is a pure provider core plus a PKCS #11 adapter and its export
macros. pkcs11rs must consume those crates itself; parallel duplicate
implementations are not acceptable.

### 6. Consider public release

Publish to crates.io only when:

- at least two materially different providers use the API without PKCS #11
  leakage;
- pkcs11rs exercises it on Linux, macOS, and Windows;
- the raw ABI, Python, OpenSC, and OASIS suites still qualify the adapter;
- unsafe code is isolated and documented;
- the API has examples for a small in-memory provider and an opaque hardware
  provider;
- the licensing remains `MIT OR Apache-2.0`; and
- maintaining a stable public API will not delay pkcs11rs security work.

## Non-goals

- Replacing the complete PKCS #11 object model with an artificially smaller
  but behaviorally incompatible model.
- Making every provider support every operation or object lifetime.
- Turning physical applets into general-purpose key stores.
- Publishing the current `Slot` trait under a new name.
- Extracting an FFI macro crate before the provider abstraction has an
  independent consumer.

## Success criteria

The design succeeds when a provider can be implemented and thoroughly tested
without importing PKCS #11 bindings, while pkcs11rs can expose that provider
with correct Cryptoki behavior and without provider-specific branches in the
FFI layer. Publication is optional; a cleaner and safer internal architecture
is already a successful outcome.
