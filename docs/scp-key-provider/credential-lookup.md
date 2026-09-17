# Named SCP credential lookup

YubiHSM authentication selects credentials from enabled PKCS #11 source slots.
Ordinary source keys feed the shared `Pkcs11Auth` Rust session API. Native HSM
Auth slots expose dedicated credential key types and use their session-bound
native operation. Both paths keep long-term values out of the client's
message code; final working AES keys are read once for local secure messaging.
See [YubiHSM authentication](../yubihsm-auth.md) for selector syntax and the
[SCP key-provider plan](README.md) for remaining card and virtual-device work.

## RFC 7512 credential selectors

`C_LoginUser` uses an RFC 7512 PKCS #11 URI as its username. Standard path
attributes select the source slot and object:

| URI attribute | PKCS #11 value |
| --- | --- |
| `token` | `CK_TOKEN_INFO.label` |
| `serial` | `CK_TOKEN_INFO.serialNumber` |
| `manufacturer` | `CK_TOKEN_INFO.manufacturerID` |
| `model` | `CK_TOKEN_INFO.model` |
| `object` | `CKA_LABEL` |
| `id` | `CKA_ID`; URI-safe ASCII remains readable and delimiters, controls, and non-ASCII bytes are percent-encoded |
| `type` | `CKA_CLASS`: `public`, `private`, or `secret-key` for authentication keys |

Omitted attributes are wildcards. The vendor query attribute
`pkcs11rs-authkey=AAAA` explicitly selects the target YubiHSM Authentication
Key ID. Without it, pkcs11rs compares eligible public source keys with public
projections on the target and obtains the target ID from the matching
projection. `object` always means `CKA_LABEL`; it is not a separate credential
name namespace.

Examples:

```text
pkcs11:
pkcs11:token=PIV%20%2337070618;object=Authentication;id=%9A;type=private?pkcs11rs-authkey=1003
pkcs11:token=Secure%20Enclave;object=reserve;type=public
pkcs11:token=HSM%20Auth%20%2337987918;object=client;id=client;type=private?pkcs11rs-authkey=0001
pkcs11:?pkcs11rs-direct=phone-client&pkcs11rs-authkey=0001
```

The direct form derives both symmetric and asymmetric credentials from the
password and labels the temporary objects from `pkcs11rs-direct`. It is
algorithm-neutral; the target Authentication Key determines which path is
used. `pin-value` and `pin-source` are rejected because the PIN/password is the
separate `C_LoginUser` argument.

Existing objects expose a computed `CKA_PKCS11RS_URI` that can be used as an
exact source selector. Its formatter includes `serial` only when the token
label does not already contain that serial, and includes `id` whenever
`CKA_ID` is nonempty. The URI excludes
`pkcs11rs-authkey`, because that identifies a separate object on the target
YubiHSM.

| Credential | Source objects | Pairing |
| --- | --- | --- |
| Ordinary symmetric | Two token `CKO_SECRET_KEY`, `CKK_AES`, 16 bytes each | `<name>.enc` is the credential identity; its exact `<name>.mac` companion is required; `CKA_ID` is not compared |
| Ordinary asymmetric | Token `CKO_PRIVATE_KEY`, `CKK_EC`, P-256, with a public projection for automatic selection | Public and private keys must have both identical `CKA_LABEL` and identical `CKA_ID`, including empty IDs |
| Native HSM Auth symmetric | Token `CKO_SECRET_KEY`, `CKK_YUBICO_HSMAUTH_CREDENTIAL_SYMMETRIC` | Exact credential label; `CKA_ID` uses the same stable label bytes |
| Native HSM Auth asymmetric | Token `CKO_PRIVATE_KEY`, `CKK_YUBICO_HSMAUTH_CREDENTIAL_ASYMMETRIC`, plus P-256 public projection | Credential and projection share both the label and label-derived `CKA_ID` |

Target YubiHSM Authentication Key records use
`CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_SYMMETRIC` and
`CKK_YUBICO_YUBIHSM_AUTHENTICATION_KEY_ASYMMETRIC`. These distinct target-only
types make the records non-operational metadata and exclude them from native
credential discovery.

Every existing-source lookup requires `CKA_TOKEN=true` and the expected object
class/type. Symmetric keys require explicit selection with the ENC object's
full `CKA_LABEL`, such as `object=client.enc;type=secret-key`. Pair resolution
then requires exactly one AES-128 ENC object and its MAC companion. A base name
or the `.mac` label does not identify the pair. Different native IDs are valid
for the two roles.
Each AES key must permit either counter-KDF derivation or AES-ECB encryption.
CBC encryption permission is optional: when both the slot and key allow it,
the ECB-based construction batches CMAC chaining into one zero-IV CBC call.
The former is preferred; the latter constructs CMAC/counter KDF through source
session encryption without exporting the long-term key. Explicit permission to
encrypt is sufficient for this alternative; it does not enable `C_DeriveKey`.
Missing keys return `CKR_KEY_HANDLE_INVALID`. A broad selector can match more
than one credential; the first candidate in the global protection order is
selected. The target PIN is never sent to an ordinary source. No failure causes
password-based protocol fallback or a retry with another source.

A directly supplied password prepares both credential types as protected
session objects in a temporary software slot. Preparation retains the handles
returned by key creation and uses them directly, without searching by label.
It releases the unused type after selecting the target authentication protocol.

The target Authentication Key ID identifies the peer's authentication record;
it is independent of the source objects' IDs and labels. Automatic asymmetric
matching compares public points with the target's public token projections;
the matching projection's two-byte ID supplies the target Authentication Key ID.

## Selection and authorization

Enumeration uses public objects to discover candidate sources. Wildcard lookup
searches native HSM Auth first, then
ordinary slots ordered by their backend-provided protection tier: token-native
derivation, platform hardware, other hardware-held credentials, and software. It
uses current slot capabilities for this order and opens sources lazily. Ordinary
slots whose USER role is not already authorized are skipped. A public
credential/target-ID match resolves the paired private key without changing the
source login state. Target-only public projections are skipped when no private
key exists. A selector containing `pkcs11rs-authkey` can resolve hidden private
or symmetric objects only in an already-authorized source; hidden credentials
cannot participate in automatic public matching.
Slots without matching token credentials contribute no candidate, regardless
of their backend kind.

An application authorizes each ordinary source with a separate `C_Login` or
`C_LoginUser` operation and that source's own PIN policy. The PIN supplied to
the target YubiHSM login is ignored for ordinary EC and AES credentials; it may
therefore be null. Native HSM Auth credentials instead consume that PIN as the
credential password in their native operation, and direct authentication uses
it to derive the temporary credential. The HSM Auth slot has no USER login. SO
management authorization remains separate.

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
values; derived session objects use the common in-module layer. A virtual
YubiHSM advertising actual virtual key algorithms can keep the supported
derivation graph in protected volatile objects owned by its authenticated secure session.

Regression tests cover exact names, independent symmetric IDs, asymmetric
label-and-ID pairing, deterministic first-match wildcard selection, one-attempt
failure, private and persistent software sources, recreation, and cleanup.
Remaining work includes retained-binding dependency cycles and complete channel
tests using a virtual YubiHSM as the derivation provider.
