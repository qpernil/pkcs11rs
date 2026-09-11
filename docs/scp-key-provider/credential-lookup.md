# Named SCP credential lookup

YubiHSM authentication selects credentials from enabled PKCS #11 source slots.
Ordinary source keys feed the shared `Pkcs11Auth` Rust session API. Native HSM
Auth slots advertise `CKP_YUBICO_HSMAUTH` and use their session-bound native
operation. Both paths keep long-term values out of the client's message code;
final working AES keys are read once for local secure messaging. See
[YubiHSM authentication](../yubihsm-auth.md) for selector syntax and the
[SCP key-provider plan](README.md) for remaining card and virtual-device work.

## One name identifies one credential

The explicit selector `:AAAA<label>@<source serial>` identifies a target
Authentication Key ID, credential name, and source token. Asymmetric public
matching also supports `:*` and narrower wildcard selectors. A platform key uses
the same syntax: `:AAAA<label>@host`. Names are not
globally unique; a serial collision or duplicate matching credential is an
ambiguity, not permission to choose the first result.

| Credential | Source objects | Pairing |
| --- | --- | --- |
| Ordinary symmetric | Two token `CKO_SECRET_KEY`, `CKK_AES`, 16 bytes each | Exact labels `<name>.enc` and `<name>.mac`; `CKA_ID` is not compared |
| Ordinary asymmetric | Token `CKO_PRIVATE_KEY`, `CKK_EC`, P-256, with a public projection for automatic selection | Public and private keys must have both identical `CKA_LABEL` and identical `CKA_ID`, including empty IDs |
| Native HSM Auth symmetric | Token `CKO_SECRET_KEY`, `CKK_YUBICO_HSMAUTH_SYMMETRIC` | Exact credential label |
| Native HSM Auth asymmetric | Token `CKO_SECRET_KEY`, `CKK_YUBICO_HSMAUTH_ASYMMETRIC`, plus P-256 public projection | Credential and projection share both `CKA_LABEL` and `CKA_ID` |

Target YubiHSM Authentication Key records share the vendor authentication key
types, but their slots do not advertise `CKP_YUBICO_HSMAUTH`. They remain
non-operational metadata and are excluded from native source discovery.

Every existing-source lookup requires `CKA_TOKEN=true` and the expected object
class/type. Symmetric keys require explicit selection: each role must resolve
to exactly one AES-128 key. Different native IDs are valid for the two roles.
Missing keys return `CKR_KEY_HANDLE_INVALID`; duplicate matches return
`CKR_TEMPLATE_INCONSISTENT`. A name matching both an ordinary asymmetric key and
symmetric roles is ambiguous. No failure causes password-based protocol fallback.

A directly supplied password prepares both credential types as protected
session objects in a temporary software slot. Preparation retains the handles
returned by key creation and uses them directly, without searching by label.
It releases the unused type after selecting the target authentication protocol.

The target Authentication Key ID identifies the peer's authentication record;
it is independent of the source objects' IDs and labels. Automatic asymmetric
matching compares public points with the target's public token projections;
the matching projection's two-byte ID supplies the target Authentication Key ID.

## Selection and authorization

Enumeration uses public objects and never submits a password to discover which
source is suitable. A unique source credential and target ID must be selected
before authorization. Explicit source/name selection can defer private lookup
until that source is authorized; hidden credentials cannot participate in public
wildcard matching. Slots without matching token credentials contribute no
candidate, regardless of their backend kind.

An ordinary source session reuses existing USER authorization, otherwise uses
the selected source's ordinary login when `CKF_LOGIN_REQUIRED` is set. Platform
uses an empty PIN. No other source is tried after a failed login. Source PIN
length and policy belong to the selected provider. Native HSM Auth credentials
use their credential password in the native operation; their slot has no USER
login. SO management authorization remains separate.

Native discovery uses the advertised profile followed by explicit searches for
the two credential key types. Further native authentication protocols can define
their own profiles, key types, and operations without changing ordinary key
selection. The source index contains weak slot references and capabilities,
not a separate credential inventory.

## Binding and lifetime

Resolve once per authentication attempt. A bound reference keeps the selected
provider session and object handle; it does not copy the long-term value or
own deletion of a persistent credential. Derivation checks key type/size,
permissions, mechanism restrictions, and output policy through the same handlers
as the public API. Handshake scopes own transient objects and release them on
success or failure.

Logout, provider loss, deletion, or detectable replacement invalidates a binding.
An old handle must not silently resolve a new object with the same label. Native
HSM Auth inventory can detect asymmetric replacement by public key; it cannot
distinguish replacement of a symmetric credential under the same label because
the applet supplies no symmetric-key fingerprint. Neither `CKA_ID` nor a reusable
native object ID is a permanent object-instance identifier.

Established channels own their exported working keys, so removal of the source
cannot revoke an already established channel. Source PINs are not cached for
recreation. The explicit session-recreation option retains only the documented
source bindings or native credential password; see the
[authentication secret policy](../authentication-secrets.md).

Releasing a retained ordinary credential closes its owning source session;
it does not explicitly log out the source token. Closing the last source
session logs it out, while other sessions retain their shared authorization.
Another caller's explicit source logout invalidates authorization for
recreation; the client does not silently log the source back in.

A YubiHSM cannot bootstrap its own source authentication through the target
channel. Initial discovery rejects a busy source instead of silently omitting
it and potentially hiding ambiguity. Dependency-cycle handling across retained
provider bindings remains a qualification item; avoid mutually dependent
source/target authentication chains.

## Storage and remaining qualification

The software token persists ordinary AES and EC credentials in its encrypted
store. Physical YubiHSM AES keys can supply counter KDF without exporting their
values; derived session objects use the common in-module layer. Native
virtual-YubiHSM protected generic-secret storage and volatile derivation outputs
remain part of the virtual-device plan.

Regression tests cover exact names, independent symmetric IDs, asymmetric
label-and-ID pairing, public ambiguity without login, selected-source failure
without fallback, private and persistent software sources, recreation, and
cleanup. Remaining work includes retained-binding dependency cycles and native
virtual-device execution of the same channel tests over its device interface.
