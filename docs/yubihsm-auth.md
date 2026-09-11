# YubiHSM and YubiHSM Auth

For additive provisioning of the same symmetric credential onto multiple
YubiKeys and local HSMs, see [shared HSM Auth provisioning](shared-hsmauth-provisioning.md).

Symmetric HSM Auth login obtains its eight-byte host challenge from the
credential's applet before creating the HSM session. Firmware 5.7.1 and later
also requires the credential password on that challenge request; earlier
firmware receives the request without a password. The applet then derives
session keys for that challenge, and the host verifies the HSM cryptogram using
the returned session MAC key. The symmetric calculation APDU omits the response
tag used for asymmetric receipts. A failed
challenge request does not create an HSM session. Login retains the resulting
session keys under the [authentication secret policy](authentication-secrets.md).

## Secure-channel working keys

YubiHSM channels retain S-ENC, S-MAC, and S-RMAC as local AES bytes in
zeroizing storage. Message encryption/decryption and CMAC run directly in the
client, with no provider calls or placement option. The full command MAC
maintains chaining; the response's eight-byte MAC is verified before decryption.
Closing or invalidating the channel immediately clears all three working keys.

Symmetric authentication binds two protected AES-128 objects, Key-ENC and
Key-MAC. For each key it prefers `CKM_SP800_108_COUNTER_KDF`, requiring
`CKA_DERIVE=true` and permission for that mechanism. If unavailable for that key,
it uses `CKM_AES_ECB` with `CKA_ENCRYPT=true` to construct CMAC and counter KDF.
When the same key also permits `CKM_AES_CBC` encryption, CMAC uses one ECB
operation to generate its subkeys and one unpadded CBC operation with a zero IV
for the complete prepared message. Without CBC permission, chaining uses ECB
block operations. CBC selection checks both slot support and key permissions;
a CBC failure is returned without retrying through ECB.
Explicit mechanism restrictions apply to either path. ENC and MAC may choose
different paths; both are checked before the first derivation. Failures during
execution, including incompatible output policies, never trigger a retry through
the alternative mechanism.

The counter-KDF path creates explicitly readable working objects; the ECB path
produces the working bytes directly without creating output objects in the
source token. The source AES values are neither read nor split. Direct
asymmetric authentication uses the same capability-based prefixed ECDH/KDF or
protected standard composition path as an existing source credential.
The receipt key remains protected and verifies the receipt before the working
keys are read. All derivation objects are destroyed on completion or failure.
Long-term credential and raw agreement values are never read into message code.
Readability is chosen in output templates; existing protected objects cannot be
weakened to make an export succeed.

Native YubiHSM Auth supplies working bytes directly. Ordinary source slots,
including platform, use the PKCS #11 derivation path. Both feed the same local
working-key storage, without adding an ordinary login-password cache.

Derivation uses `Pkcs11Auth`, an ergonomic Rust session API sharing the handlers
behind the public C exports. Preparation supplies either a temporary software
slot for direct credentials or a session view sharing an existing slot's
backend, objects, and login state. Internal calls avoid C FFI tracing and the
public module lock. Existing slot/device locking and authorization still apply.
Configured source selection uses public credential discovery and exact named lookup. See the
[SCP key-provider plan](scp-key-provider/README.md) for preparation, session
ownership, card derivation, and native virtual-HSM support.

## Slot layout

YubiHSM slots provide the [common software session-object layer](architecture.md#shared-software-session-objects-and-mechanism-discovery).
Session-key creation and operations use host software; persistent device keys
retain the native capabilities and authentication requirements described here.
Mechanism discovery merges the native list with the filtered software list.

The module exposes one slot for every selectable CCID applet, one slot for
every physical YubiHSM USB device, and one slot for every device enumerated by
each URL configured in `PKCS11RS_YUBIHSM_URLS`. URLs are comma-separated
multi-device connector base URLs. For example:
`http://hsm-a:12345,http://hsm-b:12345`.

Plain HTTP is appropriate only for loopback or a separately protected private
network. The companion `pkcs11rs-connector` daemon is not yet hardened for
direct public-Internet exposure even when its current HTTPS or mTLS support is
enabled. See the
[connector deployment boundary and Internet-readiness checklist](connector.md#deployment-boundary)
before operating a remote connector service.

Each returned serial creates a separate slot, so one connector host with two
attached YubiHSMs produces two slots from one URL. Each fresh `C_GetSlotList`
enumeration reconciles configured HTTP inventories and direct USB inventory by
serial. Calls within the module-wide
[configurable refresh window (500 ms by default)](architecture.md#discovery-lifecycle-and-stable-slots)
skip reconciliation. A
new serial gets a new slot; an absent serial keeps its stable slot ID and
becomes present again when rediscovered. Remote slots are additive; they do
not disable direct USB discovery. An unreachable connector contributes no new
slots and marks its registered slots absent for that refresh. The URL scheme
selects plain HTTP or rustls-backed HTTPS.

The optional [`slots.serials` allowlist](configuration.md) discards other
devices once identified, before HSM object or applet discovery. When using
YubiHSM Auth, include both the target HSM serial and the helper YubiKey's
Management serial; excluded YubiKeys do not contribute credentials.

HTTPS verifies the server certificate and hostname against the Mozilla root
snapshot embedded through the locked `webpki-roots` dependency. It does not
use the operating-system trust store. Configure mutual TLS with:

```sh
export PKCS11RS_YUBIHSM_TLS_CLIENT_CERTIFICATE_BUNDLE=/etc/pkcs11rs/client-chain.cbor
export PKCS11RS_YUBIHSM_TLS_CLIENT_PRIVATE_KEY=/etc/pkcs11rs/client-key.der
```

The certificate bundle uses the canonical CBOR format documented in
[`formats.md`](formats.md) and orders certificates leaf first. The private key
is a password-encrypted PKCS #8 DER object matching the leaf certificate.
`PKCS11RS_PINENTRY` must be configured so the key can be unlocked during
`C_Initialize`. The two variables form one module-wide client identity and must
either both be absent or both be present. Invalid, unreadable, noncanonical, or
mismatched material fails initialization instead of falling back to
unauthenticated TLS. The identity is offered only to configured `https://`
URLs, and redirects are disabled while it is configured. Client authentication
does not alter server verification.

Use the `yubihsm-tls-client` purpose of
[`pkcs11rs-tool`](pkcs11rs-tool.md) to create the bundle and validate it with
the encrypted private key.

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose yubihsm-tls-client \
  --key /etc/pkcs11rs/client-key.der \
  --output /etc/pkcs11rs/client-chain.cbor \
  client.pem intermediates.pem
```

For HTTPS servers issued by a private CA, set:

```sh
export PKCS11RS_YUBIHSM_TLS_CA_CERTIFICATE_BUNDLE=/etc/pkcs11rs/connector-ca.cbor
```

This canonical CBOR certificate bundle replaces, rather than extends, the
embedded Mozilla roots for every configured HTTPS connector. An empty,
malformed, noncanonical, or unreadable bundle fails initialization. It may be
configured independently of the client identity. Server certificate-chain and
hostname or IP-address verification remain mandatory.
Use the tool's `yubihsm-tls-ca` purpose to require every imported certificate
to be independently suitable as a TLS trust anchor.

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose yubihsm-tls-ca \
  --output /etc/pkcs11rs/connector-ca.cbor \
  connector-roots.pem
```

The exact bundle schema and the distinction between import and storage formats
are documented in [`formats.md`](formats.md).

Direct YubiHSM USB discovery follows `hardware.discovery` and its
`PKCS11RS_HARDWARE_DISCOVERY` environment fallback. Disabling local hardware
discovery also disables native FIDO HID and native CCID discovery, but does not
disable explicitly configured remote HTTP(S) connector
slots. Direct USB access uses usbfs on Linux, IOKit on macOS, and WinUSB on
Windows through `nusb`; it does not require libusb.

YubiHSM Auth credentials are objects in the applet slot and authentication
methods for every present YubiHSM slot, whether reached over USB or HTTP. For
one YubiKey with all five default applets and one YubiHSM, the result is six
slots.

The YubiHSM Auth slot contains read-only metadata objects for its credentials.
Every credential is represented by a `CKO_SECRET_KEY` with key type
`CKK_YUBICO_HSMAUTH_SYMMETRIC` or `CKK_YUBICO_HSMAUTH_ASYMMETRIC`,
no ordinary cryptographic capabilities, and no readable `CKA_VALUE`. An asymmetric credential also has a read-only `CKO_PUBLIC_KEY`
object containing its P-256 public key. The source applet's token serial number
identifies the YubiKey that owns these objects.

The following vendor attributes are available on credential objects:

| Attribute | Value |
| --- | --- |
| `CKA_YUBICO_HSMAUTH_RETRIES` | Remaining credential-password retries |
| `CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED` | Whether the credential requires touch |

### Authentication-key public-material boundary

Client credentials on a YubiKey and Authentication Keys on the target YubiHSM
have different roles but share algorithm-specific PKCS #11 key types. All
entries below use object class `CKO_SECRET_KEY`:

| Location and role | `CKA_KEY_TYPE` |
| --- | --- |
| YubiKey HSM Auth slot: symmetric client credential | `CKK_YUBICO_HSMAUTH_SYMMETRIC` |
| YubiKey HSM Auth slot: asymmetric client credential | `CKK_YUBICO_HSMAUTH_ASYMMETRIC` |
| Target YubiHSM slot: symmetric Authentication Key record | `CKK_YUBICO_HSMAUTH_SYMMETRIC` |
| Target YubiHSM slot: asymmetric Authentication Key record | `CKK_YUBICO_HSMAUTH_ASYMMETRIC` |

The key type identifies the authentication algorithm, not the available
operation. The target-side Authentication Key projection is non-operational
metadata; its slot does not advertise `CKP_YUBICO_HSMAUTH`. Native client
discovery and authentication require that profile, so matching key types on a
target HSM do not make it a native credential source.
The YubiHSM command interface does not provide the target Authentication Key's
public half:
[`GET PUBLIC KEY`](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#get-public-key-command)
accepts only Asymmetric Key and Wrap Key objects. Sending that command for an
Authentication Key is rejected by the device.

An asymmetric credential in a separate YubiHSM Auth slot can expose its own
long-term public key, and that key may have been provisioned into a matching
YubiHSM Authentication Key. It is nevertheless a different slot object. A
provisioner can persist the same material on the YubiHSM slot as an ordinary
standalone `CKO_PUBLIC_KEY`, with its `CKA_ID` set to the Authentication Key
object ID. Generic YubiHSM object persistence stores that public object in an
internal opaque record, and public discovery exposes it before user login.

The ordinary PKCS #11 objects let clients compare the credential and
YubiHSM-slot `CKA_EC_POINT` values themselves. Alternatively, the `C_LoginUser`
wildcard selector `:*` performs that same comparison inside pkcs11rs for the
target slot. It compares publicly discoverable P-256 credentials from ordinary
source slots and native HSM Auth slots with two-byte `CKA_ID` target projections.
Exactly one credential/projection pair must match. Multiple source credentials
or target IDs are ambiguous (`CKR_TEMPLATE_INCONSISTENT`); no password is tried.
An absent match returns `CKR_USER_TYPE_INVALID`. The stored object records the relationship established by provisioning;
the subsequent authenticated session is the final cryptographic verification.
If a future YubiHSM firmware version makes the Authentication Key public half
readable, a native public projection can replace the companion without changing
the matching model.

## Public object discovery

Every profile is represented by a public, immutable, token-resident
`CKO_PROFILE` object with a stable, distinct `CKA_UNIQUE_ID` and the
corresponding `CKA_PROFILE_ID`:

| Profile | When advertised |
| --- | --- |
| `CKP_BASELINE_PROVIDER` | Every present YubiHSM slot |
| `CKP_EXTENDED_PROVIDER` | The merged mechanism set satisfies the Extended Provider requirements |
| `CKP_AUTHENTICATION_TOKEN` | The merged mechanism set supports RSA-2048 `CKM_SHA256_RSA_PKCS` signing |
| `CKP_PUBLIC_CERTIFICATES_TOKEN` | Public discovery is configured for that slot |

Profile eligibility uses the merged native and software session mechanisms.
The common software layer supplies RSA-2048 signing and `CKM_RSA_PKCS`
wrap/unwrap on session keys, including on physical YubiHSM slots. This satisfies
the mechanism requirements of the mandatory Extended Provider and Authentication
Token cases. Native token-key operations still depend on device capabilities;
merged `CKF_HW` flags do not promise hardware support for every operation or
key size. Public Certificates eligibility requires public-discovery
configuration, independently of the current objects or discovery result.
See [profile qualification](../conformance/README.md).

Profile objects cannot be modified, copied, or destroyed. Configure a direct
YubiHSM credential or a YubiHSM Auth credential to enable pre-login
public-object discovery:

```sh
# Direct YubiHSM Authentication Key
export PKCS11RS_YUBIHSM_DISCOVERY='00a5service-owned-password'

# YubiHSM Auth credential used with target Authentication Key 00a5
export PKCS11RS_YUBIHSM_DISCOVERY=':00a5public discovery@12345678:credential-password'
```

The value uses one of the same selectors as YubiHSM `C_Login`. Direct
authentication is `AAAApassword`, where `AAAA` is exactly four hexadecimal
digits and the password is 8 through 64 UTF-8 bytes. Named source authentication
is `:AAAAlabel[@source]:password`. For native YubiHSM Auth, the credential
password is at most 16 UTF-8 bytes; ordinary source slots enforce their own PIN
policy. The optional source identifies the source token when labels are not
unique. An explicit trailing colon supplies an empty password. See
[generic source selection](#generic-source-selection-and-authorization).

The password may be omitted when `PKCS11RS_PINENTRY` is configured. Public
discovery requests it lazily after selecting a unique authentication source.
The selector is global configuration, but prompting and authentication are
slot-local. A successful slot retains its authenticated discovery session, not
the prompted password, by default. Only explicit session recreation retains
slot-local reauthentication material: protected objects for direct authentication,
token bindings for ordinary sources, or the binding and credential password for
native YubiHSM Auth. Each slot may prompt independently;
without recreation, reconnecting may require another prompt. A prompted password
is not added to the discovery configuration or cached for another slot. Direct
configuration consisting of only the four-digit Authentication Key ID uses the
same behavior. Without pinentry, the password must be explicit. A malformed or
incomplete value makes `C_Initialize` return `CKR_ARGUMENTS_BAD`.

An explicitly configured discovery password remains available in the slot's
zeroizing configuration storage independently of session recreation or user
logout. This is a configured credential, not a cache of a prompted login secret.
See the [authentication secret retention policy](authentication-secrets.md).

CCID applets and their YubiHSM Auth credentials are enumerated before the module
performs YubiHSM public discovery. The same configured credential is then tried
independently against each local and remote YubiHSM. A missing provider or
authentication failure affects only that slot and does not interfere with
ordinary user login. Provider discovery may be retried before the slot records
a definitive discovery result.

The discovery Authentication Key must have `get-opaque`. Its domains must
exactly match the domains of every YubiHSM Authentication Key accepted by
`C_Login` while the public-certificates profile is active; a login using an
Authentication Key with different domains returns `CKR_FUNCTION_REJECTED`.
Certificates and their matching asymmetric keys must have equal PKCS #11
`CKA_ID` values, either from their common YubiHSM object ID or from valid
metadata records. Provision these credentials in domains containing only data
suitable for this service-owned public view.

The profile represents operational support rather than the current object
inventory. It is advertised after the discovery credential authenticates and
the public view can be enumerated, even when no certificates are provisioned.
Malformed metadata, certificate values, public keys, and other object-local
representations are logged and skipped without withdrawing the profile or
discarding other valid public objects. Authentication, authorization, list,
read, and transport failures still make discovery unavailable for that slot.

After successful authentication, the module enumerates the credential-visible
objects. `LIST OBJECTS` seeds one native cache entry per object type and ID with
the listed sequence. Object information, public keys, and opaque values then
populate that entry only when needed. A later list with a different sequence
replaces the entry and discards every previously cached property.

PKCS #11 metadata opaque objects are read because their sparse `CKA_ID` and
`CKA_LABEL` overrides affect object construction, matching, searches, and later
operations. Metadata companions remain internal. Before PKCS #11 login the
module exposes every constructed object whose effective `CKA_PRIVATE` is false,
including X.509 certificates, physical public keys, explicitly persisted
public projections, and public data and template objects. X.509 opaque values
are read immediately for certificate validation; other opaque values remain
lazy. A certificate or readable hardware-private public component does not by
itself create a separate public token object.

The slot retains one native-object cache and one PKCS #11 object set shared by
pre-login and post-login enumeration. Discovery and ordinary user sessions
enrich the same native entries and upsert PKCS #11 projections by stable
`CKA_UNIQUE_ID`; there are no separate discovery and login views. Equal
Authentication Key domains ensure that user enumeration cannot add objects
outside the discovery credential's view.

The slot owns one YubiHSM secure session. Initial public discovery retains its
authenticated session, and later uncached public reads reuse it. `C_Login`
closes that session and replaces it with the user session. `C_Logout` closes the
user session; the next public hardware read lazily authenticates with the
discovery credential and retains the resulting session again. If no discovery
credential is configured, a logged-out hardware read returns
`CKR_USER_NOT_LOGGED_IN`. Loss of a user session is reconciled as PKCS #11
logout and is never silently treated as continued user authentication.

YubiHSM secure sessions expire after 30 seconds without a session command. By
default, an explicit YubiHSM `0x03` (`invalid session`) response therefore
invalidates the backend session and logs out the PKCS #11 user. Set
`yubihsm.recreate_sessions` to `true`, or
`PKCS11RS_YUBIHSM_RECREATE_SESSIONS=1`, to opt into transparent recovery. On
that explicit response only, the module authenticates again and replays the
interrupted command once. It never recreates or replays after an ambiguous
transport, framing, encryption, or response-MAC failure, and it does not run a
keepalive or background timer.

While opted in, direct symmetric authentication retains its two protected
AES-128 credential objects. Direct asymmetric authentication retains its protected
P-256 private-key credential and recomputes ECDH for each handshake. Static
agreement values are never retained for recreation. These
are opaque references to zeroizing in-module objects. YubiHSM Auth
authentication retains the selected provider and its zeroizing credential
password; recreation invokes the applet's session-key calculation again. A
credential requiring touch therefore waits for touch in the ordinary applet
command path, with no special keepalive or presence handling. All retained
reauthentication material is dropped when the session is logged out,
invalidated, finalized, or replaced.

Later reconstructions of the same YubiHSM object type, ID, and sequence reuse
the shared cache cell. Logout retains public objects and successful public
property reads, but removes every private object and the metadata and
attestation state that could reconstruct it. The next user login enumerates its
private view again.

Successful PKCS #11 mutations update or evict the corresponding cached
objects. Module reinitialization clears the object, metadata, attestation, and
opaque-value caches and retries public discovery. Reinitialize the module after
changing the domains visible to an authentication credential. Direct USB
rediscovery of the same serial and remote transport recovery advance the
connection epoch, clear the affected slot's caches, and retry public discovery
automatically. A different direct USB serial becomes a new slot. A configured
remote endpoint that cannot complete its initial inventory contributes no slot
until a later `C_GetSlotList` succeeds. Modern connector discovery uses only
`claimed` inventory entries: `filtered`, `legacy_only`, and `unclaimed` devices
remain visible in the connector inventory but contribute no PKCS #11 slot.

The retained discovery session has a distinct transport role from the PKCS #11
user-login session and is never used for private or mutating operations.
Public-object mutation still requires an ordinary user login and a read/write
PKCS #11 session. The password is not logged. A plaintext service configuration
is acceptable when protected by normal file permissions; do not commit the
credential.

### PKCS #11 metadata

YubiHSM PKCS #11 metadata objects are internal opaque-data companions and are
never exposed as PKCS #11 objects. Metadata may contain any subset of the
primary object's `CKA_ID` and `CKA_LABEL`, usage-flag restrictions, and
`CKA_ALLOWED_MECHANISMS`. Import, generation, and template-based unwrap preserve
these PKCS #11 restrictions when native capabilities cannot express them exactly.
For example, native AES-ECB capability supports encryption, CMAC, and counter
derivation; separate PKCS #11 flags can prohibit individual uses. Rediscovery
intersects stored usage flags with native capabilities, and mechanism selection
also checks the stored allowed list. An explicitly empty list permits no
mechanisms; an absent list imposes no additional restriction. Keys without this
metadata retain the native capability mapping; existing objects and identity
metadata require no migration. Restrictions lost during an earlier import cannot
be reconstructed. Canonical metadata may additionally
contain an explicit public aspect with sparse public-object attribute deltas.
The linked native key supplies the public material, so its SPKI is not
duplicated in metadata. Public-aspect presence represents a real public token
object even when no attribute delta is required. Valid overrides apply
regardless of whether the target was first seen by public discovery, user
login, or a successful mutation.

Metadata is linked from the target's native cache entry. The companion's
contents identify the target object type, ID, and sequence, while its own
sequence identifies the current companion incarnation. A link contributes
attribute overrides only when its target sequence matches the target entry;
this prevents reused object IDs from inheriting obsolete attributes.
Domains must also match. Invalid metadata is hidden. Canonical metadata is
authoritative whenever any pkcs11rs-namespaced companion exists; legacy
metadata is considered only in its absence. Multiple valid companions within
the selected namespace are ambiguous until an attribute update resolves the
pkcs11rs namespace. `C_SetAttributeValue` first submits the new value under one
canonical companion's existing ID and exact policy. A device that accepts
replacement updates that companion directly. An Object Exists response selects
a create-before-delete fallback; other failures preserve the existing
companions. Creating an object automatically creates metadata when requested
attributes cannot be encoded by the native YubiHSM object. Metadata is not
created when native attributes suffice, and
setting the final override back to its native value deletes an otherwise empty
record. A private and its linked public aspect share one record.

`CKM_PKCS11RS_PROJECT_PUBLIC_KEY` with `CKA_TOKEN=CK_TRUE` creates or replaces
the canonical public aspect for an asymmetric or RSA wrap key. The object is
rediscovered by stable hardware identity and its public key is checked against
the current hardware response before it is exposed. `C_GenerateKeyPair`
returns a session public object unless its public template explicitly requests
`CKA_TOKEN=CK_TRUE`, in which case it uses the same persistence path. Destroying
the public object removes only the public aspect and does not delete the
hardware private key or legacy metadata. If removing the aspect would otherwise
reveal a legacy record, pkcs11rs retains an empty canonical shadow so legacy
input cannot silently regain authority.

Deleting the private key first preserves the public object's lifetime.
pkcs11rs reads the native public material, removes the private aspect, and
morphs the same physical metadata-object ID into a standalone
`pkcs11rs.public-key` record before deleting the hardware key. The public
handle is rebound to that standalone backing. This transition consumes no
additional steady-state YubiHSM object and remains possible at the device's
256-object limit.

### RSA public wrap keys

A native YubiHSM RSA public wrap key is a separate object type from the
ordinary public projection of a private RSA wrap key. pkcs11rs selects that
native type only from an explicit `CKA_WRAP=CK_TRUE` request. An omitted
Boolean attribute has its normal PKCS #11 default of `CK_FALSE`, so omitting
`CKA_WRAP` and supplying `CKA_WRAP=CK_FALSE` have the same result.

`CKA_TOKEN=CK_TRUE` is required for a native public wrap key because the
YubiHSM object is persistent. An omitted or false `CKA_TOKEN` requests a
session object. `C_CreateObject` accepts this with either value of `CKA_WRAP`
and creates a software public key; native generation and projection paths
retain their additional template constraints described below.

`C_CreateObject` has no private source key from which to infer intent. Its RSA
public-key template is interpreted as follows:

| `CKA_WRAP` | `CKA_TOKEN` | PKCS #11 object | Device representation | Relationship |
| --- | --- | --- | --- | --- |
| Absent or false | Absent/false | Ordinary session `CKO_PUBLIC_KEY` | Session-memory backed public material | Standalone |
| Absent or false | True | Ordinary token `CKO_PUBLIC_KEY` | Internal opaque `pkcs11rs.public-key` record | Standalone |
| True | Absent/false | Software wrap-capable session `CKO_PUBLIC_KEY` | Session-memory backed public material | Standalone |
| True | True | Wrap-capable token `CKO_PUBLIC_KEY` | Native `YUBIHSM_PUBLIC_WRAP_KEY` | Standalone |

Thus `CKA_WRAP=CK_FALSE` never means “probably a public wrap key.” It is an
ordinary RSA public key, because PKCS #11 provides no other provenance in
`C_CreateObject`.

For `C_DeriveKey` with `CKM_PKCS11RS_PROJECT_PUBLIC_KEY`, both the template and
the base key are known:

| Base private object | `CKA_WRAP` | `CKA_TOKEN` | Resulting public object | Device representation and relationship |
| --- | --- | --- | --- | --- |
| Any projectable private key | Absent or false | Absent/false | Ordinary session `CKO_PUBLIC_KEY` | Session-memory projection; no persistent object |
| Native YubiHSM asymmetric or RSA wrap key | Absent or false | True | Ordinary token `CKO_PUBLIC_KEY` | Canonical metadata public aspect linked to the base hardware object |
| Native RSA wrap key | True | Absent/false | None: `CKR_TEMPLATE_INCONSISTENT` | None |
| Native RSA wrap key | True | True | Wrap-capable token `CKO_PUBLIC_KEY` | Separate native `YUBIHSM_PUBLIC_WRAP_KEY`; not a metadata aspect |
| Any other private key | True | Either | None: `CKR_TEMPLATE_INCONSISTENT` | None |

The ordinary token projection in the second row remains synthetic and
metadata-backed even when its base is a native private wrap key. Only the
explicit true/true row materializes the distinct native public wrap object.
“Linked” describes its backing and validation source, not a shared PKCS #11
lifetime: the projected public key is a genuine token object with its own
identity. It can be found and destroyed independently, and destroying it
removes only the canonical public aspect without destroying the private
hardware key.

For RSA `C_GenerateKeyPair`, the public template describes the returned public
object and the private template describes the generated hardware key:

| Public `CKA_WRAP` | Public `CKA_TOKEN` | Private `CKA_UNWRAP` | Private object created | Public object returned |
| --- | --- | --- | --- | --- |
| Absent or false | Absent/false | Absent or false | Native `YUBIHSM_ASYMMETRIC_KEY` | Ordinary session `CKO_PUBLIC_KEY` projection |
| Absent or false | True | Absent or false | Native `YUBIHSM_ASYMMETRIC_KEY` | Ordinary metadata-backed token `CKO_PUBLIC_KEY` aspect linked to the private key |
| Absent or false | Absent/false | True | Native `YUBIHSM_WRAP_KEY` with RSA algorithm | Ordinary session `CKO_PUBLIC_KEY` projection |
| Absent or false | True | True | Native `YUBIHSM_WRAP_KEY` with RSA algorithm | Ordinary metadata-backed token `CKO_PUBLIC_KEY` aspect linked to the private wrap key |
| True | Absent/false | Either | None: `CKR_TEMPLATE_INCONSISTENT` | None |
| True | True | Absent or true | Native `YUBIHSM_WRAP_KEY` with RSA algorithm | Separate native `YUBIHSM_PUBLIC_WRAP_KEY`, exposed as a wrap-capable token `CKO_PUBLIC_KEY` |
| True | True | False | None: `CKR_TEMPLATE_INCONSISTENT` | None |

On successful public-wrap generation pkcs11rs makes the private key
unwrap-capable. `CKA_WRAP` on the private template and `CKA_UNWRAP` on the
public template are inconsistent. Wrap-key generation is RSA-only and rejects
ordinary sign, verify, encrypt, decrypt, or derive capabilities on either half.

The native public object is used with `C_WrapKey` and
`CKM_YUBICO_RSA_WRAP`; the native private wrap key is used with `C_UnwrapKey`.
Applications can discover the public object normally with
`C_FindObjects*`, inspect it with `C_GetAttributeValue`, and remove it with
`C_DestroyObject`. Destroying it does not implicitly destroy its separately
represented private wrap key.

All three persistent public forms therefore have independent PKCS #11
lifecycles. A metadata-backed projection is linked to a private key only for
material validation, a public key imported by `C_CreateObject` has standalone
opaque backing, and a public wrap key has a standalone native YubiHSM object.

`C_CopyObject` is unsupported for every object presented through a YubiHSM
slot and returns `CKR_ACTION_PROHIBITED`; those objects report
`CKA_COPYABLE=CK_FALSE`. This slot-wide rule does not vary according to whether
an object's physical backing happens to be native hardware or an internal
opaque record. Applications create another independent public object explicitly
with `C_CreateObject`.

`C_SetAttributeValue` remains supported for mutable attributes. Native objects
store `CKA_ID` and `CKA_LABEL` deltas in canonical metadata, linked public
projections store those deltas in their public aspect, and standalone public
token keys replace their own internal `pkcs11rs.public-key` record while
preserving the PKCS #11 handle. Session public-key updates remain in memory.

Companions have canonical `pkcs11rs.backed-key` logical contents. The
provider-owned backing binds the target domains and primary key class, and
private/public aspects hold their sparse attributes. The YubiHSM backend
implements the content-addressed `StorageProvider` interface over these
companions while retaining their device-native back-pointer labels and
validation.

Legacy `MDB1` key metadata is converted to the canonical logical model on the
fly only when no pkcs11rs metadata exists for the target. It is read-only
compatibility input: pkcs11rs never writes, rewrites, or deletes legacy
companions. Legacy public ID and label fields remain identity compatibility
data and never create a public token object. pkcs11rs-owned records use canonical CBOR
and the `pkcs11rs metadata 0x...` namespace. MDB1 records retain Yubico's
`Meta object for 0x...` convention. This prevents Yubico's PKCS #11 module
from treating unfamiliar canonical CBOR as MDB1 and makes ownership apparent
in `yubihsm-shell` listings. See
[Content-addressed CBOR storage](storage.md#yubihsm-backend-metadata) for the
shared schema and backend behavior.

Normal PKCS #11 operations deliberately do not normalize legacy metadata.
Inspection, migration, and removal belong to separate maintenance tooling with
an explicit apply step; that tooling is outside the runtime compatibility path.

## YubiHSM login

An ordinary YubiHSM slot supports three `C_Login` PIN forms:

| Authentication | PIN form |
| --- | --- |
| Direct authentication key | `AAAApassword` |
| Named native HSM Auth or ordinary token credential | `:AAAA<label>[@<source>]:<source-password>` |
| Platform-protected asymmetric credential | `:AAAA<name>@host` |

`AAAA` is the four-hex-digit ID of the authentication key on the target
YubiHSM. Credential labels are printable UTF-8 strings. For example,
credential label `default` and YubiHSM authentication-key ID `0001` use:

```text
:0001default:credential-password
```

The short named form requires a unique publicly discoverable credential.
For native HSM Auth, if multiple YubiKeys contain the same label, append the
source YubiKey serial number:

```text
:0001default@12345678:credential-password
```

The source identifier is the token serial exposed by its slot. `@` and `:` are
reserved in the credential selector. The leading
colon identifies a provider-routed login, and the next four characters are
always the target YubiHSM authentication-key ID. The following colon separates
the source selector from its password, so the password itself may contain
colons. The selected credential and target YubiHSM authentication key must form
a compatible symmetric or asymmetric authentication pair.

The host slot uses the same credential-label and source-serial selection.
For example, `:1003reserve@host` selects `CKA_LABEL=reserve` on the
enabled Secure Enclave slot and target Authentication Key `1003`. Its ordinary
login requires an empty PIN. Packed discovery configuration supplies that PIN
with a trailing colon: `:1003reserve@host:`. No platform-specific
selector interpretation or password prompting rule is needed.

Direct authentication prepares both password-derived credential types in one
private software slot before opening the secure channel: two protected
AES-128 `CKK_AES` objects for Key-ENC and Key-MAC, and a protected P-256
`CKK_EC` private key. All three are session objects. The AES pair uses labels
`direct.enc` and `direct.mac`; preparation retains the creation handles and
uses them directly. Preparation retains no password copy. The existing Yubico provisioning derivations are preserved; they do not
provide domain separation between the two credential types. The unused key is
discarded after the attempt. Explicit session recreation retains only the
selected AES pair or P-256 private-key credential, as described above.

For direct authentication, the module first checks the ordinary `algorithm`
field in cached Authentication Key object information. If object information
has never been read, a previous successful session probe may instead supply an
inferred algorithm hint. Only when neither is available does the module probe
with the symmetric `CREATE SESSION` request first. If the YubiHSM immediately
rejects that request with its wrong-length status, the module retries with the
asymmetric request. A cached algorithm is used immediately; if its request
receives the same wrong-length status, the entry is stale and the module tries
the other algorithm. Successful authentication retains an inferred hint when
needed. A later `GET OBJECT INFO` makes the normal object property authoritative.
Reconnection clears both with the rest of the slot's object cache.

When `PKCS11RS_PINENTRY` is configured, the password and its separating colon
may be omitted to request it through pinentry:

```text
:0001default@12345678
```

Direct symmetric authentication uses the same convention. Exactly four
hexadecimal digits select the Authentication Key and request its password
through pinentry:

```text
0001
```

Appending the password keeps the noninteractive direct form, for example
`0001password`. Because a direct password is at least eight bytes, the exact
four-character form is unambiguous.

The form `:0001default@12345678:` still supplies an explicitly empty password
and does not open pinentry.

PKCS #11 3.x callers may instead pass the authentication selector and password
separately with `C_LoginUser`:

| Authentication | Username | PIN |
| --- | --- | --- |
| Direct authentication key | `AAAA` | Password |
| Named token credential | `:AAAA<label>[@<source>]` | Source token PIN or native credential password |
| Any matching credential | `:*` | Selected source PIN or native credential password |
| Matching named credential | `:*<label>[@<source>]` | Selected source PIN or native credential password |
| Platform-protected credential | `:AAAA<name>@host` | Null pointer and zero length |
| Matching platform credential projection | `:*<name>@host` | Null pointer and zero length |

The wildcard form is available only through `C_LoginUser`, whose session
identifies the target YubiHSM slot. It requires successful public discovery on
that slot. pkcs11rs compares each eligible credential's long-term public point
with the slot's persisted public projections; the matching projection's
two-byte `CKA_ID` supplies the Authentication Key ID. Bare `:*` considers
publicly matching native HSM Auth and ordinary P-256 credentials. Labels and
source serials narrow the search, including `@host` for the platform
slot. The result must be exactly one credential/target-ID pair.
Zero matches returns `CKR_USER_TYPE_INVALID`; multiple matches return
`CKR_TEMPLATE_INCONSISTENT` before any source authorization. The selected
source's authorization error is returned directly, without trying another key.
Wildcards are not accepted as public discovery credentials because that would
make discovery circular.

Passing a null PIN pointer and zero PIN length to `C_LoginUser` requests the
password through pinentry while retaining the username as the authentication
selector. A nonnull pointer with zero length remains an explicitly empty
password.

The YubiHSM token reports a stable 0-through-215-byte PIN envelope. The minimum
comes from a separated `C_LoginUser` YubiHSM Auth credential password, which
may be empty. The maximum covers the legacy packed `C_Login` form with its
largest authentication selector and credential password. Exact direct,
YubiHSM Auth, split, and packed parsers remain authoritative within that broad
envelope.

The module asks the YubiHSM Auth applet to calculate the session keys and keeps
those keys in zeroizing memory only for the life of the authenticated YubiHSM
session. Login credential passwords are not retained by default. They are retained
in zeroizing memory for the authenticated session only when session recreation
is explicitly enabled. The direct YubiHSM login forms remain available even
when no YubiHSM Auth applet is connected. Explicitly configured discovery
passwords have a separate configuration lifetime, as described in the
[authentication secret retention policy](authentication-secrets.md).

### Asymmetric device-key trust

Asymmetric YubiHSM secure sessions may use locally pinned device keys. Set
`PKCS11RS_YUBIHSM_DEVICE_TRUST_PREFIX` to the path prefix for trusted-device
files; its default is the empty string. An empty prefix disables device-key
validation, allowing asymmetric authentication without prior provisioning. Any
nonempty prefix enables validation and requires an exact entry for the
connected device. Use `./` as the prefix to keep the trust files in the current
directory while still enabling validation.

The module hashes the canonical DER SubjectPublicKeyInfo returned by the bare
`GET DEVICE PUBLIC KEY` command and loads
`<prefix><lowercase SHA-256>.cbor`. Enrollment writes one strict canonical CBOR
array containing the schema `pkcs11rs.yubihsm-device-trust`, format version,
entry kind, 32-byte SubjectPublicKeyInfo fingerprint, and canonical DER
payload. The payload is either one P-256 SubjectPublicKeyInfo or one X.509
attestation certificate whose P-256 public key represents the trusted device.
The decoder rejects unknown kinds, noncanonical records, trailing data,
fingerprint mismatches, and noncanonical DER before comparing the stored key
with the device response. A missing, malformed, or mismatched entry rejects
authentication. Configure a nonempty prefix before calling a device-enrollment
function.

The canonical record is:

```cbor-diag
[
  "pkcs11rs.yubihsm-device-trust",
  1,
  1 / 2,
  h'<32-byte SubjectPublicKeyInfo SHA-256>',
  h'<canonical DER SubjectPublicKeyInfo or certificate>'
]
```

Entry kind `1` carries a SubjectPublicKeyInfo and kind `2` carries an
attestation certificate.

Certificate chains are not processed during login. Instead, `pkcs11rs.h`
declares three explicit enrollment functions. They require a read/write session
on a YubiHSM slot and an existing `CKU_USER` login:

- `PKCS11RS_YubiHsmEnrollDeviceAttestation` attests the internal device public
  key using the supplied attestation-key ID and reads the attesting certificate
  from the opaque object with that same ID. The certificate signature and exact
  device-key match are verified. Calling this function is the administrator's
  explicit decision to trust that on-device attestation key.
- `PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation` uses the factory attestation
  key and certificate at reserved ID `0`, then validates the complete target,
  device, Yubico intermediate, and Yubico root chain before installing the pin.
- `PKCS11RS_YubiHsmEnrollDevicePublicKey` directly pins the public key returned
  by `GET DEVICE PUBLIC KEY` without attestation.

Each function returns the 32-byte SHA-256 fingerprint used in the trust-file
name. A null output pointer queries that fixed length without installing
anything. Attestation enrollment requires the authenticating YubiHSM key to
have `sign-attestation-certificate` and `get-opaque` capabilities. Generic
attestation IDs must refer to an asymmetric key and X.509 opaque object with the
same ID. On commercial YubiHSM devices, ID `0` is reserved for the built-in
factory attestation key and preloaded certificate.

After login, the YubiHSM device public key is also exposed through ordinary
PKCS #11 discovery as a read-only `CKO_PUBLIC_KEY` named
`YubiHSM device public key`. It has no cryptographic operation capabilities,
has an empty `CKA_ID`, returns the canonical DER SubjectPublicKeyInfo through
`CKA_PUBLIC_KEY_INFO`, and uses `yubihsm-device-public` as `CKA_UNIQUE_ID`.
`CKA_EC_PARAMS` and `CKA_EC_POINT` expose the standard P-256
representation. Other YubiHSM objects retain their configured labels; an empty
hardware label receives a deterministic description containing its object type
and decimal ID.

Generated YubiHSM asymmetric keys also expose a non-token X.509 attestation
certificate object with the same `CKA_ID`. The certificate is requested from
the HSM only when a certificate-derived attribute such as `CKA_VALUE` or
`CKA_SUBJECT` is read, then cached per slot and key generation. Imported keys
do not expose this object because the YubiHSM cannot attest imported key
material. The authentication key used for login must grant the
`sign-attestation-certificate` capability for the lazy read to succeed.

## YubiHSM Auth administration

The YubiHSM Auth slot uses `C_Login` roles as follows:

- `CKU_USER` is unsupported (`CKR_USER_TYPE_INVALID`). The slot clears
  `CKF_LOGIN_REQUIRED` and `CKF_USER_PIN_INITIALIZED`. A native authentication
  call takes the selected credential's password directly; no dummy login or
  software session-key authorization is involved.
- `CKU_SO` establishes the same transport and interprets the supplied PIN as
  the YubiHSM Auth management password. The resulting 16-byte management key
  is retained in zeroizing per-slot memory until logout, device removal,
  application reset, or module finalization.

`C_SetPIN` is intentionally unsupported on YubiHSM Auth slots. A slot can
expose multiple credential labels, while the PKCS #11 operation is slot-wide
and has no credential selector. Use the proprietary label-addressed
administration functions below for credential passwords, or the management
password function for the applet-wide management key.

With pinentry configured, `C_Login` with `CKU_SO`, a null PIN pointer, and zero
PIN length obtains the management password through pinentry. `CKU_USER` never
prompts because it has no PIN of its own.

Yubico's password input convention is used for both management and credential
passwords. A printable UTF-8 value of at most 16 bytes is padded on the right
with zero bytes. Exactly 32 hexadecimal characters provide the raw 16-byte
value. Other lengths and malformed hexadecimal values are rejected. The token
reports the management-password envelope of 0 through 32 bytes, including
the raw hexadecimal form. Each login role and
administration call still enforces its own syntax.

The YubiHSM Auth slot advertises no ordinary cryptographic mechanisms and rejects
software private/secret key imports. Its public data and certificate backing
storage remain available when configured.

## Protected password entry

Set `PKCS11RS_PINENTRY` to the pinentry executable name or path:

```sh
export PKCS11RS_PINENTRY=pinentry
export PKCS11RS_PINENTRY=pinentry-mac
```

Bare executable names are resolved through the process's inherited `PATH`. An
explicit path, such as `/opt/homebrew/bin/pinentry-mac`, may instead be used to
select a particular installation. The value names one executable and cannot
contain command-line arguments. Terminal frontends on Unix use `GPG_TTY` when
set and otherwise fall back to the process's controlling terminal at
`/dev/tty`. No terminal name is sent on Windows. On macOS, use `pinentry-mac`
for a native dialog that does not require a controlling terminal.

The variable is read during `C_Initialize`; leaving it unset disables
interactive prompting, and an empty value makes initialization return
`CKR_ARGUMENTS_BAD`. When enabled, YubiHSM and YubiHSM Auth token information
includes `CKF_PROTECTED_AUTHENTICATION_PATH`.

The module starts one configured process per prompt and communicates through
the Assuan protocol over pipes. Prompts are serialized, secrets are never
placed in process arguments or environment variables, and returned passwords
are held in zeroizing memory only for the login call. Pinentry cancellation
returns `CKR_CANCEL`; startup or protocol failures return
`CKR_FUNCTION_FAILED`.

`pkcs11rs.h` declares proprietary administration functions. Every function
requires a read/write session on the YubiHSM Auth slot with an active `CKU_SO`
login:

- `PKCS11RS_HsmAuthPutSymmetricCredential` imports explicit 16-byte ENC and
  MAC keys.
- `PKCS11RS_HsmAuthPutDerivedSymmetricCredential` applies Yubico's YubiHSM
  password KDF: PBKDF2-HMAC-SHA256 with salt `Yubico`, 10,000 iterations, and
  32 output bytes split into ENC and MAC.
- `PKCS11RS_HsmAuthPutAsymmetricCredential` imports a raw 32-byte P-256 private
  scalar.
- `PKCS11RS_HsmAuthPutDerivedAsymmetricCredential` derives the static YubiHSM
  client P-256 key by applying the same KDF to the derivation password plus a
  counter byte, advancing the counter until the output is a valid scalar.
- `PKCS11RS_HsmAuthGenerateAsymmetricCredential` asks the YubiKey to generate
  the private key internally.
- `PKCS11RS_HsmAuthDeleteCredential` deletes one credential by label.
- `PKCS11RS_HsmAuthChangeCredentialPassword` changes one credential password
  using the retained management key.
- `PKCS11RS_HsmAuthChangeManagementPassword` changes the applet management
  key and updates the retained SO state.
- `PKCS11RS_HsmAuthReset` resets the complete YubiHSM Auth application and
  ends the login.

Asymmetric creation functions return the 65-byte uncompressed SEC1 public
point. Passing a null public-key pointer queries this fixed size without
creating a credential. Successful mutations refresh the applet's PKCS #11
metadata objects.

The password KDF and its deterministic P-256 construction are used only for
authentication to a YubiHSM. They are not used for YubiKey CCID SCP03 or
SCP11, the applet management password, or credential access passwords.
Management-key authentication is performed by the first mutating APDU rather
than by `C_Login`; if the device rejects the retained key, the SO login is
cleared so the caller can retry. Reset is destructive and removes every
YubiHSM Auth credential.

## Platform-protected authentication credentials

Platform keys are ordinary PKCS #11 token keys on the configurable
[platform ECDH slot](platform.md). Enable `platform.enabled=true` or
`PKCS11RS_PLATFORM_ENABLED=1`; a serial allowlist must also include
`host`. Disabled or filtered slots cannot supply authentication
credentials. The slot projects each managed key as private and public P-256
objects with matching `CKA_LABEL` and `CKA_ID`.

On macOS and iOS, the existing management API resolves permanent Secure Enclave
keys tagged `pkcs11rs.yubihsm-auth.<name>` in the signed host application's
Keychain access group. Login never creates a missing key. Management tooling
and the iOS provisioning workflows remain separate from authentication; they
use the existing names and storage without migration.

### HSM Auth slot discovery and execution

The slot advertises Baseline and `CKP_YUBICO_HSMAUTH`. The latter is a
vendor-defined capability profile, independent of whether any credentials are
provisioned. Its contract is:

- Public, read-only `CKO_SECRET_KEY` credential metadata with key type
  `CKK_YUBICO_HSMAUTH_SYMMETRIC` or `CKK_YUBICO_HSMAUTH_ASYMMETRIC`.
- Asymmetric credentials expose a companion P-256 public key matched by both
  `CKA_LABEL` and `CKA_ID`.
- The session-bound native authentication operation accepts the credential
  handle, target, authentication-key ID, and credential password. Credential
  keys cannot perform ordinary AES or ECDH operations.
- Login requirements remain described by the ordinary token flags. This
  implementation has no USER login; SO management authorization is separate.

Profile and key-type constants are published in `pkcs11rs.h`. Discovery selects
supporting slots by profile, then searches explicitly for the two key types;
it does not infer the native protocol from device names or backend kinds.
The slot also claims Public Certificates when token backing storage is enabled.
This storage can hold public certificates and matching public keys; the claim
does not require them to be provisioned already.

Asymmetric credentials and their companion EC public-key objects have identical
`CKA_LABEL` and `CKA_ID` values. Automatic matching uses
these public objects, while symmetric credentials require explicit selection.

Authentication lookup searches the slot objects through a `ProviderSession`.
The module keeps weak references to registered source slots, not an independent
credential registry. Serial filters apply before opening a source session.
Object searches refresh the applet inventory. The native authentication operation
also refreshes it before validating the selected handle, so deletion or
asymmetric replacement invalidates an old binding. The applet provides no
symmetric-key fingerprint; replacing a symmetric credential under the same label
cannot be distinguished from the existing credential by inventory alone.

The credential remains a token object throughout authentication. The native
Rust operation uses a PKCS #11 session and object handle, plus the target HSM,
authentication-key ID and credential password. It performs the existing
challenge, receipt and session-key protocol without claiming ordinary ECDH or
AES support on the applet credential. No vendor derivation mechanism is defined
for this operation.

### Generic source selection and authorization

The named form `:<authkey-id><label>@<source-serial>` also selects ordinary
PKCS #11 token credentials, including platform credentials selected with
`:<authkey-id><label>@host`. A P-256 credential uses its exact label; a
symmetric credential consists of AES-128 keys `<label>.enc` and `<label>.mac`.
Public/private asymmetric pairing requires both matching labels and matching
`CKA_ID` values, including empty IDs. The AES roles are paired only by their
exact names; their IDs may differ.
Symmetric credentials require an explicit source serial and target key ID.
Generic selectors accept credential labels up to 128 UTF-8 bytes; each backend
still enforces its own provisioning limits. The source token's PIN belongs in
the password field. For a YubiHSM source,
that PIN uses its own combined-login syntax, including its source authentication
key ID, independently of the target ID in the outer selector.

Selection uses public metadata before source authorization. Published matches
take precedence over hypothetical hidden keys on other applets. With no public
match, a hidden key or AES pair requires one explicitly selected source slot;
a serial shared by several possible source applets is insufficient. Configure
discovery/applet filters to limit candidates if necessary. No password is used
to distinguish candidates. A prompt identifies the selected source first.

An ordinary source session reuses existing USER authorization, or calls the
shared Rust `C_Login` handler when `CKF_LOGIN_REQUIRED` is set. Platform uses its
empty-PIN login. Only after authorization are private keys resolved and checked
for type, identity, and derivation permission. Native HSM Auth instead consumes
its credential password in the native operation. A failed authorization ends the
request; there is no candidate fallback or automatic password retry.

| Source slot | Applicable credential and authorization |
| --- | --- |
| Temporary direct software slot | Password-derived protected session keys; private preparation establishes authorization |
| Configured software slot | Persistent P-256 key or named AES pair; normal token USER PIN; public discovery needed for automatic matching |
| Platform | Public P-256 projection; empty-PIN USER login and OS key-use policy |
| PIV / OpenPGP | P-256 key capable of ECDH; normal PIN and per-key policy, including any fresh-authentication requirement |
| YubiHSM | P-256 key or AES pair; source HSM login and native key capabilities; public discovery for automatic matching |
| HSM Auth profile | Dedicated symmetric/asymmetric credential types; native per-credential password |
| FIDO2 / Issuer Security Domain | Searched normally; no special slot exclusion. Their usual objects do not supply a suitable token credential; any selected key must satisfy the same operation and permission checks. |

Ordinary PINs are not retained. The explicit session-recreation option retains
the selected credential binding and source session, subject to revocation;
native HSM Auth additionally retains its credential password only under that
existing opt-in. Failed recreation invalidates the target session instead of
repeatedly trying the password. Established channels use their exported working
keys independently of later source logout.

### Platform credential login architecture

`ClientAuth` owns authentication material bound to a PKCS #11 source session.
Direct-password authentication creates a private software slot and session
objects; platform and YubiHSM Auth authentication select token objects from
existing slots. Platform and direct-password credentials use the shared
Cryptoki Rust handlers. YubiHSM Auth uses the session's native
`hsmauth_authenticate` operation, which validates the selected credential handle
and invokes the existing applet protocol. Internal calls do not enter the C FFI.
The host slot knows only ECDH, object identity, and OS key access; it contains
no SCP protocol logic.

```text
YubiHSM login selector
    -> enabled host slot: find label / match public-key projection
    -> bound P-256 token key
    -> Pkcs11Auth: ECDH, protected session objects, common KDF graph
    -> receipt verification and final working-key reads
    -> YubiHSM secure channel: local encryption and MAC
```

#### Login selection

`:1003reserve@host` selects the target Authentication Key ID `1003` and exactly
`CKA_LABEL=reserve` on the host slot. `C_LoginUser` supplies this username
with a null PIN pointer and zero PIN length; the packed `C_Login` form is also
supported. The selected host slot requires an empty PIN.

`:*reserve@host` matches that key's public point against the target HSM's discovered
public authentication-key projections. Universal `:*` enumerates the enabled
source slot's public-key objects and finds their matching private objects by
both label and ID. Missing private-key matches return `CKR_KEY_HANDLE_INVALID`;
duplicate matches return `CKR_TEMPLATE_INCONSISTENT`. No matching target projection returns
`CKR_USER_TYPE_INVALID`. A disabled or unavailable source contributes no
candidate. An explicit selector with no matching source returns
`CKR_PIN_INCORRECT` before attempting authentication, as for any source slot.

The source label, source public key, target Authentication Key ID, and device
trust are distinct. Public projection selects a candidate; the target HSM
enforces capabilities and domains. Device trust is validated before static
ECDH. Connector TLS trust remains independent.

#### Provider boundary

The platform key capability is `EcdhCredential`: public-key access and ordinary
P-256 ECDH. The `platform-credential` crate retains its prefixed-X9.63 convenience
method and compatibility trait name for existing external consumers. The
PKCS #11 slot uses ordinary ECDH behind the combined prefixed-KDF mechanism;
the authentication client prefers that combined operation when available.

Apple returns the ECDH secret from the Secure Enclave to the module. The module
uses it for the combined KDF in zeroizing memory, or stores it as a protected
session object for ordinary ECDH; the private scalar remains
in the Secure Enclave. The native key checks its managed identity before use,
so deletion or replacement does not silently keep an obsolete binding usable.
OS authorization governs the operation; the PKCS #11 platform source slot
requires empty-PIN login to access private objects.

#### Asymmetric handshake

The source slot generates a fresh software ephemeral P-256 session key and
performs derivation through `Pkcs11Auth`. It prefers the combined prefixed-ECDH
mechanism when advertised and permitted by the selected key, passing the
readable ephemeral agreement as prefix bytes. The static agreement remains
inside the combined operation. Otherwise, protected agreement objects,
concatenation, and SHA-256 implement the same X9.63 graph. An operational failure
does not select a different path:

```text
SHA-256(Z_ephemeral || Z_static || counter || shared_info)

bytes  0..16  receipt key
bytes 16..32  S-ENC
bytes 32..48  S-MAC
bytes 48..64  S-RMAC
```

Explicitly readable final KDF outputs permit the intended working-key reads
without weakening source objects. A protected verify-only receipt key validates
the complete receipt before releasing S-ENC, S-MAC, and S-RMAC to the channel.
Trust, derivation, or receipt failure cleans up the handshake's objects and
attempts to close the pending HSM session.

#### Established session and lifetime

Established channels own their three working AES keys in zeroizing memory and
perform message encryption and MAC locally. Handshake sessions release all
intermediate objects. The platform token key remains owned by the OS store.

With session recreation disabled, the credential binding is released after
establishment. With `yubihsm.recreate_sessions=true`, `ClientAuth` retains
the bound token key, its provider session, and device-trust configuration until
logout, invalidation, finalization, or replacement. Only an explicit invalid
session response triggers one new handshake and one replay; ambiguous transport
or authentication failures never trigger replay. No platform private-key bytes
or password are retained.

### Provisioning an iPhone platform credential

A Secure Enclave credential is generated and provisioned entirely inside the
iPhone smoke applications through PKCS11RS. There is one supported application
flow: the user connects an already authorized YubiKey when bootstrap
administration is required and presses **Provision platform credential**. No
public-key export, QR code, enrollment file, or separate desktop provisioner
participates in this flow.

The button performs these operations:

1. Generate the device-local platform credential if it does not already exist.
   The Apple provider creates a permanent P-256 private key in the Secure
   Enclave, tagged as `pkcs11rs.yubihsm-auth.<name>`, protected as
   `AccessibleWhenUnlockedThisDeviceOnly`, and scoped to the smoke
   application's Keychain access group.
2. Enumerate the configured or discovered YubiHSM slots. The application uses
   a locally connected, already provisioned YubiHSM Auth credential to open an
   administrative session on each present target. This existing authority is
   the unavoidable bootstrap authorization for adding a new client identity.
3. Ask PKCS11RS to read the platform public key internally and provision it as
   a new asymmetric Authentication Key with the selected ID, capabilities,
   delegated capabilities, and domains. The private key and public-key bytes
   never cross the Swift or Objective-C application boundary.
4. Create the corresponding public projection under the same two-byte ID so
   later pre-login discovery can resolve the credential. Provisioning creates
   the harmless public projection first, then the Authentication Key, and
   removes the projection if the second operation fails. It never overwrites
   an existing object ID implicitly.
5. Close the bootstrap session and authenticate again with the newly created
   platform credential. An authenticated operation must succeed before the UI
   reports that target as provisioned.

Provisioning is atomic per target as far as the device protocol allows, but is
not a distributed transaction across several HSMs. The smoke application keeps
an explicit result for every target, permits a failed target to be retried, and
does not roll back a successfully verified credential on another target.

The operation is deliberately idempotent. A repeated button press reuses the
same named platform key. An Authentication Key and projection whose visible
policy and public material exactly match the request produce `already
provisioned`; a matching projection left by an interrupted first attempt is
completed and produces `repaired`. A pre-existing Authentication Key without
its projection is not repaired because its public half cannot be read through
the portable protocol and therefore cannot be proven to match. Any differing
object or projection at the requested identity is an explicit conflict. No
retry overwrites or rotates key material implicitly.

The button is a two-state lifecycle control. Its label is **Provision platform
credential** when the named local credential is absent and **Unprovision
platform credential** when it is present. Unprovisioning authenticates to every
currently present YubiHSM target, asks
`PKCS11RS_YubiHsmUnprovisionPlatformCredential` to verify that the public
projection at the requested ID exactly matches the named platform key, and only
then removes that Authentication Key and projection. The operation is
idempotent when both target objects are already absent. It refuses to delete an
Authentication Key that cannot be bound to the platform credential through its
projection because the Authentication Key public half is not portably
readable.

After all present targets succeed, the application deletes the named local
Secure Enclave credential. If any target fails, or no target is present, the
local credential is retained so the operation can be retried. This is not a
global registry of every HSM on which the credential may ever have been
installed: an unavailable or unconfigured target cannot be modified by the
application.

For example, the result can be presented as:

```text
Virtual YubiHSM       provisioned   login verified
YubiHSM target 1      provisioned   login verified
YubiHSM target 2      provisioned   login verified
```

The two checked-in iOS smoke applications implement the same behavior. Their
UI code remains a thin orchestrator; credential storage, public-key handling,
YubiHSM commands, cleanup, and login verification belong to shared PKCS11RS
code. Each app has its own Keychain scope and therefore provisions an
independent identity: the Swift app uses `iphone-qpernil` with Authentication
Key `1004`, while the Objective-C app uses `iphone-qpernil-objc` with
Authentication Key `1005`. Provisioning or removing one does not alter the
other.

For an Authentication Key assigned ID `1004`, explicit login is:

```text
username = ":1004iphone-qpernil@host"
PIN pointer = NULL
PIN length = 0
```

Once public discovery can read the projection, the equivalent resolved form is:

```text
username = ":*iphone-qpernil@host"
PIN pointer = NULL
PIN length = 0
```

The resolved form follows the platform credential login architecture above:
the private key is not involved in discovery, the Secure Enclave performs the
static ECDH operation, derived intermediates are zeroized, and the established
session receives exactly the policy of the provisioned Authentication Key.

The static PKCS11RS library executes inside the iOS application and therefore
uses that application's code-signing identity and Keychain entitlements. The
same stable application identity and access group must be used by later builds
that need to resolve the credential. The current access control requires an
unlocked device and private-key usage, but does not request biometric presence
for every login; biometric policy is a separate product decision.

The Apple provider and all four Rust lifecycle operations compile for iOS and
are exported as `PKCS11RS_PlatformCredentialGenerate`,
`PKCS11RS_PlatformCredentialList`,
`PKCS11RS_PlatformCredentialGetPublicKey`, and
`PKCS11RS_PlatformCredentialDelete`. The button uses the high-level
`PKCS11RS_YubiHsmProvisionPlatformCredential` and
`PKCS11RS_YubiHsmUnprovisionPlatformCredential` operations. Both require a
read/write session with an active administrative login. Provisioning accepts
the target ID, label, domains, capabilities, and delegated capabilities;
PKCS11RS reads or generates the named platform credential internally and
returns whether the target was provisioned, already provisioned, or repaired.
Unprovisioning accepts the credential name and target ID and validates the
public binding before deletion. The lifecycle functions use ordinary PKCS #11
two-call output-buffer conventions where applicable and never return private
material.

## Asymmetric hardware provisioning test

The ignored `provisions_asymmetric_hsmauth_credential_on_yubihsm` and
`provisions_touch_required_asymmetric_hsmauth_credential_on_yubihsm` tests
delete their configured test credential and matching authentication key if
they already exist, generate one fresh persistent asymmetric credential on a
YubiKey, read its P-256 public key, install that public key as a YubiHSM
authentication key on every configured or locally discovered YubiHSM, persist
a companion `CKO_PUBLIC_KEY` with the Authentication Key ID, verify that
public discovery can read the companion, and verify an actual asymmetric
session with each HSM.
The second test requires a physical touch during each authentication. Both
leave the newly provisioned credential, keys, and companions in place.

Provisioning requires an explicit enable flag and target object ID:

```sh
PKCS11RS_TEST_PROVISION_ASYMMETRIC_HSMAUTH=1 \
PKCS11RS_TEST_YUBIHSM_AUTHKEY_ID=1234 \
cargo test provisions_asymmetric_hsmauth_credential_on_yubihsm -- --ignored --nocapture
```

The touch-required variant is independently enabled and uses a separate target
ID and label:

```sh
PKCS11RS_TEST_PROVISION_TOUCH_ASYMMETRIC_HSMAUTH=1 \
PKCS11RS_TEST_YUBIHSM_TOUCH_AUTHKEY_ID=1235 \
cargo test provisions_touch_required_asymmetric_hsmauth_credential_on_yubihsm -- --ignored --nocapture
```

The defaults are YubiHSM Auth management key
`00000000000000000000000000000000`, credential label
`pkcs11rs-asymmetric` (`pkcs11rs-asymmetric-touch` for the touch-required
variant), credential password `password`, YubiHSM administrator key `0001`
with password `password`, all YubiHSM domains (`0xffff`), and no operational
or delegated capabilities on the new key. Override the remaining defaults
with:

- `PKCS11RS_TEST_HSMAUTH_MANAGEMENT_KEY`
- `PKCS11RS_TEST_HSMAUTH_LABEL`
- `PKCS11RS_TEST_HSMAUTH_TOUCH_LABEL`
- `PKCS11RS_TEST_HSMAUTH_CREDENTIAL_PASSWORD`
- `PKCS11RS_TEST_YUBIHSM_ADMIN_ID`
- `PKCS11RS_TEST_YUBIHSM_ADMIN_PASSWORD`

Set `PKCS11RS_TEST_REUSE_ASYMMETRIC_HSMAUTH_CREDENTIAL=1` to provision from an
existing named asymmetric credential instead of deleting and regenerating it.
For example, an existing credential named `scp11` can be installed on every
discovered YubiHSM with:

```sh
PKCS11RS_TEST_PROVISION_ASYMMETRIC_HSMAUTH=1 \
PKCS11RS_TEST_REUSE_ASYMMETRIC_HSMAUTH_CREDENTIAL=1 \
PKCS11RS_TEST_HSMAUTH_LABEL=scp11 \
PKCS11RS_TEST_YUBIHSM_AUTHKEY_ID=1234 \
cargo test provisions_asymmetric_hsmauth_credential_on_yubihsm -- --ignored --nocapture
```

The named credential must already exist on the selected YubiHSM Auth applet,
must be asymmetric P-256, and must have the touch policy expected by the chosen
test variant. The test never mutates or removes a reused credential.

When multiple YubiKeys are attached, select the credential-bearing key by
serial number or full device name with `PKCS11RS_TEST_HSMAUTH_SOURCE`. Every
configured HTTP(S) or locally discovered USB YubiHSM is a provisioning target.
Before cleanup begins on
any device, the test authenticates to every target and requires every existing
object at the configured ID to have the configured label and asymmetric
authentication algorithm. This prevents an accidentally reused ID from
deleting an unrelated object and avoids starting a multi-HSM update that fails
basic preflight on a later target. Cleanup occurs only after the explicit
enable flag and target ID have been validated. Existing companion public
objects with the selected label and ID are replaced through ordinary PKCS #11
object operations. The freshly generated keys are not deleted, including after
a partial provisioning failure.
