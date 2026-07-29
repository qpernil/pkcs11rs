# Public-key projection from a private-key object

## Status of this document

This document is an initial discussion draft for a possible addition to the
PKCS #11 specification. Names and numeric assignments are provisional. The
proposal has not been submitted to or adopted by the OASIS PKCS 11 Technical
Committee.

pkcs11rs includes a vendor-defined reference implementation named
`CKM_PKCS11RS_PROJECT_PUBLIC_KEY`. It creates provider-backed session objects
for all supported backends and accepts `CKA_TOKEN=true` when the slot has a
writable token provider. YubiHSM supplies a native provider that retains the
public object in pkcs11rs-owned canonical metadata on the device. It supports
software RSA private keys and PIV, OpenPGP, YubiHSM,
resident-FIDO, and previewSign private objects when their backend metadata
contains a validated RSA, EC, or Ed25519 public component. RSA encryption and
RSA, ECDSA, and EdDSA verification execute in software on the projected
object. Native public objects and provider-restored objects are normalized
through the same canonical projected-key backing before those operations, so
the cryptographic paths do not depend on backend-specific public-object
variants. Tests cover RSA projection, encryption, and verification; FIDO P-256
projection and verification of a genuine mock GetAssertion signature;
previewSign export, destruction, strict restoration, projection, signing, and
PKCS #11 verification;
matching and conflicting intrinsic attributes; non-private bases; unavailable
token storage; session cleanup; generic token creation, refresh, update, and
destruction; and YubiHSM token creation, rediscovery, material validation, and
independent destruction.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in BCP 14
[RFC 2119] and [RFC 8174] when, and only when, they appear in all capitals.

## Abstract

PKCS #11 tokens commonly retain a private-key object without retaining a
corresponding public-key object. The associated public key may nevertheless be
available from the private-key representation, a certificate, internal token
metadata, or `CKA_PUBLIC_KEY_INFO`. PKCS #11 currently has no generic operation
that converts this information into a usable `CKO_PUBLIC_KEY` object.

This document proposes a parameterless key-derivation mechanism,
provisionally named `CKM_PUBLIC_KEY_FROM_PRIVATE`. The mechanism is used with
`C_DeriveKey`; it accepts a `CKO_PRIVATE_KEY` base object and creates an
independent `CKO_PUBLIC_KEY` object for the same asymmetric key pair.

The result may be a session object or, when supported by the token, a token
object. An implementation may perform operations with a projected public key
in software. The proposal neither exposes private key material nor requires
the corresponding public key to have been persisted by the device.

## 1. Motivation

`C_GenerateKeyPair` returns both a public-key handle and a private-key handle,
but many devices persist only the private key. The public handle may be a
session object, may disappear when the module or application is restarted, or
may never be reconstructed during later object discovery.

Applications consequently encounter a private key that can sign or decrypt
but no public-key object that can:

- verify a signature through `C_Verify`;
- perform a public-key encryption operation through `C_Encrypt`;
- provide algorithm-specific public attributes;
- supply a `SubjectPublicKeyInfo`;
- be associated with a certificate through `CKA_ID`; or
- be passed to another PKCS #11 operation that requires `CKO_PUBLIC_KEY`.

PKCS #11 already recognizes the association. The private-key attribute
`CKA_PUBLIC_KEY_INFO` represents the public key associated with a private key,
and the specification recommends that private-key objects retain enough
information to recover their public keys. Reading public attributes followed
by `C_CreateObject` is not an adequate generic substitute:

- public-key reconstruction is different for each key type;
- a token may be able to use the public material without exposing every
  component through `C_GetAttributeValue`;
- a token may support derived session objects but not imported public-key
  objects;
- applications must reproduce the token's parsing and validation rules; and
- the two-call sequence does not express that the new object is the public
  projection of the supplied private object.

This is a general lifecycle problem. It occurs with conventional HSM keys,
smart-card keys, credentials whose public material is discovered from another
protocol, software-backed private objects, and key types added after an
application was written.

## 2. Design goals

The proposed operation has the following goals:

1. It is independent of a particular asymmetric algorithm.
2. It produces a normal PKCS #11 public-key object.
3. It never releases private key material.
4. It allows a portable session-object result.
5. It allows persistence when the implementation has suitable storage.
6. It preserves ordinary PKCS #11 templates, object ownership, visibility,
   and error handling.
7. It requires the implementation to establish that the projected public key
   corresponds to the base private key.
8. It does not require an ABI change or a new Cryptoki function.

## 3. Proposed identifiers

The following names are provisional and require assignments by the PKCS 11
Technical Committee:

```c
#define CKM_PUBLIC_KEY_FROM_PRIVATE  /* value to be assigned */
```

No mechanism-parameter structure is defined.

An implementation advertises the mechanism with `CKF_DERIVE`. The
`ulMinKeySize` and `ulMaxKeySize` fields describe the range of supported base
key sizes using the existing conventions for each supported key type. Where a
single numeric range would be misleading because the implementation supports
multiple key families with different size conventions, this proposal
recommends zero for both fields. Whether that recommendation is consistent
with all existing mechanism-info requirements is an open issue.

## 4. Mechanism definition

`CKM_PUBLIC_KEY_FROM_PRIVATE` is a mechanism for projecting the public
component associated with an asymmetric private-key object.

It is invoked as:

```c
CK_MECHANISM mechanism = {
    CKM_PUBLIC_KEY_FROM_PRIVATE,
    NULL_PTR,
    0
};

rv = C_DeriveKey(
    session,
    &mechanism,
    privateKey,
    publicTemplate,
    publicTemplateCount,
    &publicKey
);
```

`pParameter` MUST be `NULL_PTR` and `ulParameterLen` MUST be zero. Otherwise,
the operation SHALL return `CKR_MECHANISM_PARAM_INVALID`.

### 4.1 Base-key requirements

The base object:

- MUST have `CKA_CLASS` equal to `CKO_PRIVATE_KEY`;
- MUST describe an asymmetric key type for which the implementation can
  construct the corresponding public-key representation;
- MUST have `CKA_DERIVE` equal to `CK_TRUE`; and
- MUST be visible to the calling session under the ordinary PKCS #11 object
  visibility and login rules.

The mechanism does not imply that every private key of a key type supported by
the slot is projectable. For example, an older device object may lack required
public metadata even though newer objects of the same type retain it.

If `CKA_DERIVE` is `CK_FALSE`, the operation SHALL return
`CKR_KEY_FUNCTION_NOT_PERMITTED`. If the base object is not a private key or
uses a key type to which this mechanism cannot be applied, the operation SHALL
return `CKR_KEY_TYPE_INCONSISTENT`.

### 4.2 Output object

On success, the operation creates exactly one independent
`CKO_PUBLIC_KEY` object. The result:

- MUST represent the public key corresponding to the base private key;
- MUST have the same `CKA_KEY_TYPE` as the base key;
- MUST contain the public attributes required by that key type;
- MUST have a valid `CKA_PUBLIC_KEY_INFO` when that attribute is supported for
  the key type;
- MUST have `CKA_LOCAL` equal to `CK_FALSE`, as required for objects created by
  `C_DeriveKey`; and
- MUST receive a `CKA_UNIQUE_ID` according to the existing `C_DeriveKey`
  rules.

The result is a distinct PKCS #11 object, not an alias for the private-key
handle. Destroying either object MUST NOT destroy the other. A session result
MUST remain usable for its normal session-object lifetime if the base object
is subsequently destroyed or becomes invisible. An implementation therefore
MUST materialize or otherwise retain sufficient public information in the
result rather than requiring later access to the base private key.

The implementation MAY derive the public value mathematically, retrieve an
authenticated public representation stored by the token, use a previously
validated `CKA_PUBLIC_KEY_INFO`, or use another method that establishes the
association. It MUST NOT accept unvalidated public material whose
correspondence to the base private key is unknown.

### 4.3 Output template

The template follows the ordinary rules for `C_DeriveKey` and public-key
objects. If the base object has a `CKA_DERIVE_TEMPLATE`, that template is
merged with the application template according to the existing
`C_DeriveKey` rules. A conflict between them causes
`CKR_TEMPLATE_INCONSISTENT`.

- If `CKA_CLASS` is present, it MUST be `CKO_PUBLIC_KEY`.
- If `CKA_KEY_TYPE` is present, it MUST equal the base key's `CKA_KEY_TYPE`.
- `CKA_TOKEN` selects token or session lifetime using the ordinary PKCS #11
  rules. Its default remains the standard default for a new object.
- `CKA_PRIVATE` controls the visibility of the resulting public-key object
  using the ordinary object rules.
- Public-operation attributes such as `CKA_ENCRYPT`, `CKA_VERIFY`,
  `CKA_VERIFY_RECOVER`, `CKA_WRAP`, and `CKA_ENCAPSULATE` are supplied by the
  template or take their ordinary defaults. The implementation MUST reject
  combinations that the key type or implementation cannot support.
- Descriptive and association attributes such as `CKA_LABEL`, `CKA_ID`,
  `CKA_SUBJECT`, and application-defined attributes are supplied by the
  template or take their ordinary defaults.

The mechanism contributes the intrinsic public-key attributes. A template
value that conflicts with an intrinsic value SHALL cause
`CKR_TEMPLATE_INCONSISTENT`. Intrinsic values include, as applicable:

- RSA modulus and public exponent;
- DSA, Diffie-Hellman, and elliptic-curve domain parameters and public value;
- elliptic-curve parameters and encoded public point;
- Edwards-curve and Montgomery-curve parameters and public value;
- public values required by post-quantum signature or encapsulation key
  types; and
- `CKA_PUBLIC_KEY_INFO`.

The mechanism does not automatically copy the base object's `CKA_ID`,
`CKA_LABEL`, policy attributes, or public-operation flags. Applications that
want the projected object associated with the same certificate SHOULD supply
the base key's `CKA_ID`. Automatically copying association metadata when it is
absent from the template is an open issue discussed below.

### 4.4 Session and token objects

With `CKA_TOKEN` equal to `CK_FALSE`, an implementation MAY create a public
session object backed by host memory even when the private key remains on a
hardware device. Cryptoki exposes logical token behavior and does not require
public operations to execute in the same physical component as private
operations.

If a requested public operation is enabled on the result, the implementation
MUST implement it according to the corresponding mechanism specification.
For example, a projected RSA public key with `CKA_ENCRYPT` equal to `CK_TRUE`
may implement `C_Encrypt` in software.

With `CKA_TOKEN` equal to `CK_TRUE`, the implementation MUST retain the public
object with normal token-object semantics. It may store the public key in the
device, in implementation-managed metadata, or through another storage
facility belonging to the logical token. If it cannot provide token-object
lifetime, it MUST reject the template rather than silently creating a session
object.

### 4.5 Authorization and release of public information

The operation is subject to the visibility and authorization requirements of
the base private object. If the private object is not visible to the calling
session, no projection can be performed.

The resulting object follows its own `CKA_PRIVATE` setting. In particular, an
application may project a public object while logged in and request
`CKA_PRIVATE` equal to `CK_FALSE`. That object may remain visible after logout
for its remaining lifetime. This is an intentional release of public
information, not an extraction of private key material.

An implementation with a policy that prohibits such release MAY reject the
template. It MUST NOT silently change `CKA_PRIVATE`, `CKA_TOKEN`, or requested
public-operation attributes.

`CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`, and
`CKA_NEVER_EXTRACTABLE` do not apply to a `CKO_PUBLIC_KEY` result. The
sensitivity and extractability of the base private key MUST NOT prevent
projection by themselves.

### 4.6 Failure behavior

No object is created when the operation fails.

In addition to the errors generally applicable to `C_DeriveKey`, the following
conditions have the indicated results:

| Condition | Result |
| --- | --- |
| Non-null or non-empty mechanism parameter | `CKR_MECHANISM_PARAM_INVALID` |
| Base is not `CKO_PRIVATE_KEY` | `CKR_KEY_TYPE_INCONSISTENT` |
| Unsupported base key type | `CKR_KEY_TYPE_INCONSISTENT` |
| `CKA_DERIVE` is `CK_FALSE` | `CKR_KEY_FUNCTION_NOT_PERMITTED` |
| Required public information is unavailable for this base object | `CKR_KEY_FUNCTION_NOT_PERMITTED` |
| Template requests a non-public class or different key type | `CKR_TEMPLATE_INCONSISTENT` |
| Template conflicts with an intrinsic public-key value | `CKR_TEMPLATE_INCONSISTENT` |
| Requested token lifetime cannot be provided | existing token/template error appropriate to the implementation |

The distinction between an unsupported key type and a supported key type whose
particular object lacks recoverable public information allows an application
to distinguish a structural mismatch from an object-specific limitation.

Adding `CKR_KEY_FUNCTION_NOT_PERMITTED` to the return values applicable to
`C_DeriveKey` may be required if the base function's return-value list remains
exhaustive.

## 5. Examples

### 5.1 Reconstructing a verification object

An application discovers an EC private token object after restarting. No
corresponding public-key object is present. It creates a public session object:

```c
CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
CK_BBOOL ckFalse = CK_FALSE;
CK_BBOOL ckTrue = CK_TRUE;
CK_ATTRIBUTE publicTemplate[] = {
    { CKA_CLASS,   &publicClass, sizeof(publicClass) },
    { CKA_TOKEN,   &ckFalse,     sizeof(ckFalse) },
    { CKA_PRIVATE, &ckFalse,     sizeof(ckFalse) },
    { CKA_VERIFY,  &ckTrue,      sizeof(ckTrue) }
};

CK_OBJECT_HANDLE publicKey;
CK_RV rv = C_DeriveKey(
    session,
    &mechanism,
    privateKey,
    publicTemplate,
    sizeof(publicTemplate) / sizeof(publicTemplate[0]),
    &publicKey
);
```

The application can then use `publicKey` with `C_Verify` or read its
`CKA_PUBLIC_KEY_INFO`. Closing the session destroys the projection but not the
private token object.

### 5.2 Persisting a public projection

An implementation that has token metadata storage accepts
`CKA_TOKEN=CK_TRUE`. The resulting public key is rediscovered after module
restart even if the physical device persists only the private component.

An implementation without suitable storage rejects that request. It does not
pretend that a host-memory object is a persistent token object.

The pkcs11rs reference implementation routes generic token projections through
the slot's `StorageProvider`. Slots without token storage reject the request.
Its YubiHSM provider stores a validated `CKA_PUBLIC_KEY_INFO` and the supported
public-object policy attributes in a canonical metadata aspect owned by
pkcs11rs. Legacy Yubico metadata and identity-only canonical aspects do not
establish object existence. Destroying the public token object removes only
that aspect; the hardware private key and its unrelated metadata remain.

### 5.3 Protocol-backed private key

A private-key object represents a credential exposed by a protocol other than
native PKCS #11. The protocol supplies an authenticated public key but its
signing operation remains device-bound. Projection creates an ordinary public
session object. Public operations execute locally while private signing
continues through the protocol.

This example does not require a new PKCS #11 key type if the projected public
key has an existing standard representation.

## 6. Alternatives considered

### 6.1 `C_GetAttributeValue` followed by `C_CreateObject`

An application can read `CKA_PUBLIC_KEY_INFO`, parse it, build an
algorithm-specific public template, and call `C_CreateObject`. This remains a
useful fallback but is not equivalent:

- it requires algorithm-specific application code;
- the implementation may support projection without supporting public-key
  import;
- it may expose a representation that an implementation could otherwise keep
  internal;
- correspondence and policy validation are split between calls; and
- it does not provide a single discoverable capability.

### 6.2 `C_CopyObject`

`C_CopyObject` copies an object within the same object class. Changing a
private-key object into a public-key object is not an ordinary copy and would
conflict with immutable class and key attributes.

### 6.3 `C_GenerateKeyPair`

`C_GenerateKeyPair` creates new key material. Public projection must retain the
identity of an existing private key and therefore is not key-pair generation.

### 6.4 A new Cryptoki function

A dedicated function such as `C_ProjectPublicKey` could avoid describing the
operation as derivation and could define capability reporting independently of
`CKA_DERIVE`. It would require a new function-list version, interface changes,
and substantially more integration work than a mechanism used through an
existing object-creation function.

The mechanism approach should be preferred unless standards review finds that
the established semantics of `C_DeriveKey` or `CKA_DERIVE` cannot accommodate
projection.

### 6.5 Public operations directly on private-key handles

Allowing `C_Verify` or `C_Encrypt` to accept `CKO_PRIVATE_KEY` would remove the
need for another handle, but it would blur the established class-specific
operation model. It also would not provide a public object for attribute
access, certificate association, APIs that explicitly require
`CKO_PUBLIC_KEY`, or controlled session and token lifetime.

## 7. Security considerations

The mechanism releases only public key material. It MUST NOT make any private
attribute readable or weaken the base key's private operations.

The association between the base private key and projected public key is
security-critical. Implementations MUST validate imported
`CKA_PUBLIC_KEY_INFO` as already required by PKCS #11 and MUST NOT project
unauthenticated metadata merely because it carries the same object identifier
or label.

Incorrect public projection can cause applications to encrypt to the wrong
key, accept an incorrect verification identity, or issue a certificate for a
key that the private object does not control. Implementations should prefer a
mathematical derivation or authenticated device representation. A
sign-and-verify correspondence check is acceptable where supported.

Creating a non-private public object from a private object may reveal that the
private key exists and may release public metadata after logout. Applications
and implementations requiring concealment can set `CKA_PRIVATE=CK_TRUE` or
reject a public projection according to token policy.

A software-backed public object does not reduce the protection of the private
key. Applications should nevertheless treat mechanism and attribute reporting
as part of the logical token's trusted computing base.

## 8. Compatibility and deployment

The proposal adds one mechanism without changing existing function
signatures. Older applications ignore it. Applications discover support
through `C_GetMechanismList` and `C_GetMechanismInfo`.

A vendor can deploy the behavior before standard assignment using a
vendor-defined mechanism value. Such an implementation should retain the same
parameter and template semantics so applications can migrate by substituting
the standardized mechanism identifier.

Supporting the mechanism does not require support for every asymmetric key
type or every private-key object. Implementations should document applicable
key types and use the object-specific failure behavior in Section 4.6.

## 9. Open issues

### 9.1 Is `C_DeriveKey` the right operation?

Mathematically, a public key is derived from private key material. Operationally,
this proposal creates another representation of an existing key pair rather
than fresh cryptographic keying material. The existing `C_DeriveKey` signature,
template, lifetime rules, and atomic object creation are an excellent fit, but
the Technical Committee should confirm that this use is consistent with the
intended abstraction.

### 9.2 Meaning of `CKA_DERIVE`

Requiring `CKA_DERIVE=CK_TRUE` preserves the existing permission model.
Applications may currently interpret that attribute primarily as support for
key agreement or a KDF, however. Setting it merely to advertise public
projection could therefore surprise existing applications.

Possible resolutions include:

1. confirm that public projection is derivation and use `CKA_DERIVE`;
2. define a new per-key capability attribute specifically for projection; or
3. define a dedicated Cryptoki function outside `C_DeriveKey`.

The first option has the smallest API and implementation cost. If selected,
the specification should state explicitly that `CKA_DERIVE` grants use only
of derivation mechanisms that are otherwise applicable to that object; it does
not imply that every derivation mechanism advertised by the slot can use the
key.

### 9.3 Association metadata

Copying `CKA_ID` by default would naturally preserve the association among a
private key, public key, and certificate. Existing derivation mechanisms do not
generally imply that descriptive metadata is inherited. The current draft
therefore requires the application to supply association metadata explicitly.

The Technical Committee should decide whether omitted `CKA_ID`, `CKA_LABEL`,
or `CKA_SUBJECT` values should instead be copied from the base object.

### 9.4 Mechanism-info key sizes

The mechanism may cover key families whose size fields have different
meanings. The Technical Committee should decide whether `ulMinKeySize` and
`ulMaxKeySize` should report numeric extrema, zero, or a restricted set of
key-type-independent values.

### 9.5 Failure for unavailable public material

This draft uses `CKR_KEY_FUNCTION_NOT_PERMITTED` when the mechanism supports
the key type but a particular private object lacks enough information to
recover its public key. A new return value would be more precise but would
increase the scope of the proposal.

### 9.6 Token-object persistence

Allowing `CKA_TOKEN=CK_TRUE` follows ordinary `C_DeriveKey` behavior and
supports implementations with metadata storage. A stricter initial mechanism
could require a session result to guarantee portability. The broader behavior
is preferred because a token can already accept or reject token-object
templates according to its capabilities.

## 10. Conformance requirements

A conforming implementation of `CKM_PUBLIC_KEY_FROM_PRIVATE` MUST include
tests demonstrating:

- rejection of non-null or non-empty parameters;
- rejection of non-private base objects;
- enforcement of `CKA_DERIVE`;
- exact correspondence between base and projected keys;
- rejection of conflicting intrinsic attributes;
- correct session-object destruction;
- independence of the result from the base object's lifetime;
- logout behavior for both public and private projected objects;
- standard public operations enabled by the result's template;
- no release of private attributes; and
- correct failure when token lifetime is requested but unavailable.

Algorithm-specific tests SHOULD cover every supported key type. At least one
test SHOULD reconstruct a public session object after rediscovery of a
persistent private key for which no persistent public-key object exists.

## 11. References

- [PKCS #11 Specification Version 3.2][pkcs11-32]
- [PKCS #11 Usage Guide Version 3.2][pkcs11-ug-32]
- [RFC 2119: Key words for use in RFCs to Indicate Requirement Levels][rfc2119]
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words][rfc8174]

[pkcs11-32]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
[pkcs11-ug-32]: https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/pkcs11-ug-v3.2.html
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
