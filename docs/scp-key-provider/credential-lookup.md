# Proposed named SCP credential lookup

This is the next storage/selection layer for the [SCP key-provider plan](README.md).
It is a design, not an implemented configuration format. The YubiHSM client
derives channel keys through the `Pkcs11Auth` Rust session API,
then reads the final working AES keys for local message crypto; its configured input paths use password-derived credentials,
YubiHSM Auth, or platform credentials. A resolver must connect stored token
objects to the existing slot/session adapter without extracting long-term values.

## One name identifies one credential object

Resolve `(provider identity, credential name, protocol profile)` before opening
the target secure channel. Provider identity selects one token independently
of the target device. The name is an exact `CKA_LABEL` match within that token,
with `CKA_TOKEN=true` and the expected class/type. Names are not globally unique.
Use standard `C_FindObjects` semantics where the provider is a PKCS #11 token;
a native adapter can use its device's object enumeration and label fields.

| Profile | Persistent credential | Required operation |
| --- | --- | --- |
| YubiHSM symmetric | One `CKO_SECRET_KEY`, `CKK_GENERIC_SECRET`, 32 bytes: K-ENC followed by K-MAC | Protected extraction of two 16-byte AES session objects, followed by counter KDF |
| YubiHSM asymmetric | One `CKO_PRIVATE_KEY`, `CKK_EC`, P-256 | ECDH into a protected generic-secret session object |

Validate protection, key type/size or curve, derive permission, allowed
mechanisms, and all applicable output-template restrictions before sending
`CreateSession`. Long-term bindings and agreement inputs stay protected. Final working outputs
are private session objects explicitly permitting value reads. SCP03 counter
KDF creates readable AES outputs; SCP11 creates readable hash blocks before
concatenation/extraction, preserving the mechanism inheritance rules. Unimplemented policy features
must fail explicitly; a resolver must not strip a source's restrictions to
make it usable. The session adapter forwards nested policy templates to the
same validation and merging handlers used by the C API.

A missing name returns a missing-credential error. Multiple matches return an
ambiguity error; never pick the first enumeration result. A matching label with
an incompatible type/profile is a configuration error, not a request to try
password authentication. PKCS #11 does not make labels unique, so provisioning
must check collisions as well as lookup. Device label-length/encoding limits
must be applied explicitly, without truncation or normalization that aliases
names. Key bytes must never participate in name matching.

The target Authentication Key ID remains a separate setting: it identifies
the peer's matching authentication record, not the client's stored credential.
Changing a credential name must not silently change that target ID.

## Binding, authorization, and lifetime

Resolve and authorize the provider independently of the target channel. Never
acquire a second public slot lock underneath an existing target slot lock or
bootstrap a provider through the channel it is helping establish. Reject direct
and indirect provider dependency cycles.

The resolver returns an opaque key reference tied to the provider's identity,
object instance, and authorization lifetime during establishment. A binding shares access to an
existing object; it does not copy its value, create a weaker object, or take
ownership of deleting the persistent credential. Scope cleanup destroys only
channel-owned temporary and working objects.

A future resolver needs an authorization lease or equivalent revocation check:
logout, provider disconnect, replacement, or session loss must invalidate
bindings and dependent derivation operations. After final working keys have
been read, the established target channel uses its own local lifetime; removing
the derivation provider cannot revoke those already exported keys. The existing
in-module retained-reference primitive alone is not a complete token-login revocation mechanism. Do not
retain a login PIN/password to renew that lease. Preserve the explicit existing
session-recreation exception and its documented scope.

Resolve once per authentication attempt. Do not repeatedly search by name for
every message. A deleted/replaced object or lost provider invalidates the bound
instance; an old handle must never silently bind to a replacement with the same
label. A fresh authorized attempt may resolve the name again. Avoid claiming
`CKA_ID` or a numeric device ID is a permanent instance identifier when the
provider can reuse it.

## Storage and execution

The software token can persist these standard object types using its existing
encrypted store. The virtual YubiHSM needs protected generic-secret storage and
volatile derivation outputs in addition to its EC private-key support. Its
native adapter must preserve the same lookup and authorization semantics.
This generic32 profile requires protected splitting. A physical YubiHSM cannot
split an opaque generic32 credential while keeping its value protected; a native
symmetric profile needs separate AES ENC/MAC token keys and direct counter KDF.
That lookup profile remains to be defined. Native counter KDF itself is supported.

Message encryption and CMAC execute locally using final working keys read once
at establishment. There is no alternate execution mode. A source policy that
prohibits the required readable outputs must fail explicitly, without weakening
existing objects or switching providers. Scope cleanup destroys derivation
objects; the established channel owns and zeroizes its local working bytes.

## Acceptance checks and implementation order

1. Implement exact provider-scoped lookup and duplicate/missing/type errors,
   initially against an authorized software token with provisioned fixtures.
2. Bind stored symmetric and P-256 credentials to the existing derivation
   graphs; exercise repeated authentication while preserving source objects.
3. Add revocation, object replacement, cross-provider isolation, and dependency
   cycle tests. Verify cleanup after receipt rejection and partial derivation.
4. Implement the virtual-device storage and native protected-object commands;
   run the same lookup and channel tests through its actual device interface.

Choose the user-facing configuration syntax with the resolver implementation,
reusing existing provider/slot selectors rather than introducing another
independent discovery scheme.
