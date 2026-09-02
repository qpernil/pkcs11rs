# Architecture

pkcs11rs separates the process-wide PKCS #11 lifecycle, independently locked
slot state, session-owned operations, backend behavior, and physical
transports. The current ownership graph is:

```text
MODULE_CONTEXT: RwLock<Option<ModuleContext>>
└── ModuleContext
    ├── process configuration and shared services
    ├── global handle counters
    └── slot_contexts: RwLock<SlotContextRegistry>
        ├── slot ID -> Arc<Mutex<SlotContext>>
        │   └── SlotContext
        │       ├── Box<dyn Slot>
        │       ├── slot login role
        │       ├── token StorageProvider
        │       ├── token and session object handles
        │       └── session handle -> SessionContext
        │           ├── Box<dyn BackendSession>
        │           ├── memory StorageProvider
        │           ├── find operation
        │           ├── digest operation
        │           ├── encrypt/decrypt operation
        │           └── sign/verify operation
        └── session handle -> owning slot ID
```

## Module lifecycle and locking

`MODULE_CONTEXT` is the lifecycle state. `None` means that Cryptoki is not
initialized; `Some(ModuleContext)` means it is initialized. Ordinary API calls
retain a shared read guard for their full duration. `C_Initialize` and
`C_Finalize` use the exclusive write guard, so neither transition can race an
active call.

Lifecycle calls use nonblocking lock acquisition. A concurrent lifecycle
transition returns `CKR_FUNCTION_FAILED`; an ordinary call that overlaps a
transition returns `CKR_CRYPTOKI_NOT_INITIALIZED`. A poisoned lifecycle or
slot lock is reported as `CKR_MUTEX_BAD`.

The registry lock protects lazy slot discovery and session-handle routing.
Operations release it before locking the selected `SlotContext`, avoiding one
global lock around backend work. Each slot mutex serializes mutable token state
shared by its sessions. Operation state itself lives in `SessionContext`, so
two sessions do not share an in-progress find, digest, encrypt, decrypt, sign,
or verify operation.

Backend slots contain an `Rc`-based graph for slot-local state. That graph is
confined behind its `SlotContext` mutex. State shared between slots uses
synchronized `Arc` handles instead.

## Discovery lifecycle and stable slots

`C_Initialize` creates the module context from configuration, but normal slot
discovery begins lazily when the application first calls `C_GetSlotList`.
That first listing establishes the initial slot registry:

- configured software slots are created and their stored objects are loaded;
- current PC/SC or CryptoTokenKit readers are enumerated, their configured
  applet AIDs are probed, and each recognized applet becomes a separate slot;
- native FIDO HID devices are enumerated and reconciled with equivalent CCID
  FIDO applets using the validated physical serial. One serial-owned FIDO slot
  prefers HID when its CCID route has no configured secure-channel protocol,
  but retains CCID as its fallback when HID is unavailable, such as after the
  YubiKey moves to a desktop NFC reader. CCID remains preferred when a protocol
  is configured because HID cannot provide SCP03 or SCP11. HID is otherwise
  preferred because it is the common USB transport across FIDO authenticators,
  has broader hardware coverage in pkcs11rs, and
  remains available independently of PC/SC reader ownership. No secure
  channel is active during this reconciliation; it is established lazily for
  a subsequent operation;
- on iOS, opt-in NFC discovery makes its single initial card request, scans a
  stable serial, and registers the recognized applets against that serial; and
- direct USB and configured HTTP YubiHSM inventories are reconciled and all
  registered transports and presence states are refreshed.

Later `C_GetSlotList` calls refresh the established model rather than repeating
the complete initial pass. Reader inventory is enumerated again, but reader
names are only transient locators. A newly encountered locator is identified
by its physical serial: a known serial is rebound to its existing slots without
re-probing applets, while a new serial is probed once and may append slots. USB
and HTTP YubiHSM inventories are reconciled again, and registered transports
are refreshed. Provider-wide
native FIDO HID enumeration is initial-only, and the initial NFC identity scan
is not repeated; a registered NFC transport may still reacquire and verify its
bound serial when a slot-list refresh or device operation needs the card. The
[iOS integration guide](ios-integration.md#when-the-nfc-ui-appears) distinguishes
the exact UI triggers from the no-prompt reuse path.

An inventory provider reports an opaque, provider-defined identity and current
presence. Reconciliation combines that identity with the provider instance:
known identities retain their PKCS #11 slot IDs while absent, reappearing
identities reuse those slots, and new identities receive new slots. Successful
slot registration is therefore stable until `C_Finalize`, while token presence
is dynamic. `C_GetSlotList(CK_FALSE, ...)` includes retained absent slots;
`C_GetSlotList(CK_TRUE, ...)` includes only slots currently reporting
`CKF_TOKEN_PRESENT`. Initial CCID/HID reconciliation selects routes before the
resulting slot list is exposed; later route availability does not change the
serial-owned FIDO slot ID.

`C_Finalize` drops the registry. A later initialization constructs a new one,
so slot IDs are stable only within one initialize/finalize lifetime. Whether a
slot reports `CKF_REMOVABLE_DEVICE` remains PKCS #11 backend metadata and is
not part of discovery identity.

Configured HTTP inventories use configuration-entry ordinal as their provider
instance and YubiHSM serial as their stable slot ID, so duplicate configured
URLs remain independent. Direct YubiHSM USB inventory uses the device serial;
reattachment replaces the transport behind the existing slot even when the OS
assigns a new USB device ID. Inventory requests and new-slot HSM initialization
run without holding the slot-registry write lock; only registry snapshots and
final insertion use it. Native PC/SC or iOS CryptoTokenKit reader inventory is
enumerated on every listing, so newly attached serials can append applet slots
and known serials can acquire a different transport locator. Existing PC/SC
and HID slots refresh their transports on every listing. Native
HID provider-wide new-device inventory is still created only during module
initialization.

## Slots, backends, and mechanisms

`SlotContext` implements the behavior common to every PKCS #11 slot: session
ownership, login role, object handles, and dispatch. Its boxed `Slot`
implementation supplies the device- or applet-specific token metadata,
objects, login behavior, mechanisms, random generation, and backend sessions.

Backend mechanism lists describe complete slot operations. An operation may
combine software preprocessing, such as hashing, with a hardware private-key
command. Standalone software digest mechanisms belong only to software slots;
hardware slots expose software-assisted composite mechanisms only when the
operation uses a key in that slot. Software public-key processing adds a
public-operation flag only to a mechanism already exposed with its paired private operation:
`CKF_SIGN` enables `CKF_VERIFY`, and `CKF_DECRYPT` enables `CKF_ENCRYPT`. It does
not introduce a mechanism that the backend's private keys cannot perform. The
public-projection mechanism remains available because it is itself an operation
on a private key. Generic software private-key support is an explicit slot
capability and is disabled for all
hardware and applet slots. The typed implementation covers RSA, every
Weierstrass curve supported by the hardware backends (NIST
P-224/P-256/P-384/P-521, secp256k1, and brainpoolP256r1/P384r1/P512r1),
Ed25519, Ed448, X25519, and X448. `PKCS11RS_SOFTWARE_SLOTS` creates one independent
`SoftwareSlot` and `SoftwareSession` backend for each configured name. These
slots have no transport or hardware flags. They use token-wide user login to
gate private material. A configured generic token-storage root is scoped by
software-token name and supplies an encrypted, master-key-protected PKCS #8
store for persistent software private keys in addition to supported
non-private backed objects. `CKA_TOKEN=CK_TRUE` never falls back to session
storage, and no hardware or applet slot enables this store. FIDO2 adds an explicit vendor
GetAssertion mechanism for operational resident credentials; it cannot be
confused with a bare EC or RSA signing mechanism because its input and
structured output are separately defined.

Reusable protocol-neutral signing, verification, key serialization, and raw
key-agreement operations live in the sibling `software-key-core` crate.
pkcs11rs retains mechanism parsing, attribute and authorization policy,
persistence, operation state, and `CKR_*` error mapping. Device protocol cores
retain their identifiers, wire encodings, and device-specific policy.

The `abi-tests` feature uses synthetic slots that identify the real backend
kind they model. Production dispatch therefore does not contain a generic
test-slot branch.

## CCID applet topology

One physical native CCID reader has one shared `PcscReaderState`. Every
selected applet gets a separate logical PKCS #11 slot
and a slot-local connector facade, while all facades share:

- the card connection, complete APDU-exchange lock, and APDU capabilities;
- a connection-epoch-scoped physical `DeviceContext`;
- validated SCP11 public-key caches that remain valid for that connection.

Calls on different applet slots may overlap while using their independent slot
and session state, but their interactions with one physical reader are
serialized for the complete device-backed PKCS #11 operation. On desktop the
reader worker lazily enters a PC/SC transaction at the first APDU and retains
it through the operation; on iOS the analogous boundary is a CryptoTokenKit
smart-card session. The first APDU in every operation reselects its AID and
establishes the configured secure channel. The transaction itself owns the
selected AID and live SCP03 or SCP11 session; ending it destroys that entire
state. Only validated SCP11 public-key material survives the boundary.

Native PC/SC and native iOS CryptoTokenKit produce the same internal transport
records. A reader or CryptoTokenKit slot name is only an enumeration locator,
never PKCS #11 identity. PC/SC implementations use different naming and
disambiguation rules, USB re-enumeration may change a name, and CryptoTokenKit
NFC names are session-scoped. pkcs11rs therefore reads the YubiKey management
serial and makes that serial own the stable applet topology and slot IDs.

The first encounter with a serial probes its configured applet AIDs once. A
later locator for the same serial is attached to those existing slots without
repeating applet discovery; this includes movement between NFC and USB CCID.
An established connection performs no discovery APDUs during an ordinary
refresh. After reconnection, pkcs11rs reads only enough management information
to validate the serial, and each real operation reselects its applet as part of
normal transaction handling. Removal marks the serial's slots absent, while a
different serial at a reused locator is treated as a different token. See
[CCID applet configuration](ccid.md).

The native iOS connector starts a worker lazily for each retained reader. The
worker confines its retained `TKSmartCard` and all of that card's session and
transmit operations to one thread, reuses the card while it remains valid, and
serializes APDU requests. Retaining that card object does not claim exclusive
access. Reader enumeration itself still uses the current
`TKSmartCardSlotManager` inventory on every slot-list refresh. CryptoTokenKit
provides smart-card APDU transport rather than general USB bulk access.

The desktop connector likewise gives each reader a worker that owns its PC/SC
card handle. Reader workers share the provider's PC/SC context; transactions on
different readers remain independent. Connections use `SCARD_SHARE_SHARED`.
The worker keeps the borrowed PC/SC transaction object on its own stack while
it services all APDU requests for one high-level operation, which avoids both
unsafe self-references and transaction gaps between APDUs.

A future refinement may allow selected PKCS #11 multipart lifecycles, such as
`C_FindObjectsInit` through `C_FindObjectsFinal`, to retain one smart-card
transaction across calls. The present boundary remains one PKCS #11 function
call. A longer boundary requires an explicit lease, timeout, and abandoned-
operation cleanup so an application cannot hold PC/SC or the NFC UI while it
is idle indefinitely.

## FIDO transports

`Fido2Slot` owns a transport-independent FIDO endpoint and the shared CTAP
client. A CCID endpoint wraps the ISO 7816 CTAP binding and its optional secure
channel. A USB HID endpoint wraps a CTAPHID channel over `hidapi`. Both deliver
the same `command byte || CBOR` request and `status byte || CBOR` response to
the CTAP client, so PIN/UV, credential-management, assertion, previewSign, and
object-projection code is shared.

USB HID discovery selects Usage Page `0xF1D0`, Usage `0x01`, allocates a
channel with `CTAPHID_INIT`, requires the CBOR capability, and then runs
`authenticatorGetInfo`. Yubico device information is read through the
read-only vendor command before the slot is registered. If the same serial is
already represented by a successfully selected smart-card FIDO applet, that
same serial-owned slot prefers native HID when no secure-channel protocol is
configured and falls back to CCID when HID is unavailable. An explicitly
configured CCID secure-channel protocol reverses that preference because HID
cannot provide SCP03 or SCP11.
HID is the common USB transport across FIDO authenticators and has broader
hardware validation in pkcs11rs. It is also independent of PC/SC reader
ownership: another process holding the reader exclusively can prevent access
to every CCID applet, even when that process is using a different applet, while
the native HID interface may remain usable.
Unknown or unvalidated identities remain separate rather than being merged.
Applet serials remain applet metadata and cannot overwrite the physical
device identity used for correlation. A native HID authenticator absent from
initial module discovery creates no slot; a previously discovered endpoint can
reopen the same device and allocate a fresh channel after reinsertion. FIDO
over CCID follows the dynamic reader inventory described above, so a FIDO
applet on a newly discovered reader can append a slot later.

When `PKCS11RS_TOKEN_STORAGE` is configured, a stable physical Yubico serial
selects a versioned local token provider separately for each applet. Stored
canonical backed objects are decoded and reconciled during slot construction.
`PKCS11RS_FIDO2_STORAGE` remains a FIDO-only compatibility setting. An endpoint
without a stable identity retains an unavailable provider, so durable objects
cannot accidentally cross tokens or applets.

The validated Yubico physical serial also associates the HID endpoint with the
shared PC/SC `DeviceContext`, even when the FIDO CCID applet is unavailable or
its slot is removed by transport deduplication. PKCS #11 operations through
those HID and CCID views cannot overlap. HID-to-HID access remains shareable;
pkcs11rs does not request `CTAPHID_LOCK` or an operating-system-exclusive HID
open, and cannot serialize unrelated browser or process access. PC/SC uses a
shared connection and transaction-bounded operations, so other cooperative
PC/SC clients can remain connected and run between pkcs11rs calls. An exclusive
owner can still prevent discovery or reconnection, and a direct USB CCID client
bypasses PC/SC coordination entirely.

CTAPHID report exchange is also serialized inside each FIDO slot. A response
on an invalid channel causes one fresh channel allocation and retry because
the authenticator rejected the original request. I/O failures and timeouts are
not retried, since a mutating or signing operation may have executed before
the connection failed. HID has no SCP03 or SCP11 layer; configured CCID secure
channels apply only to the smart-card endpoint.

## YubiHSM transports and caches

Each YubiHSM slot owns one secure-session role at a time: retained public
discovery or ordinary PKCS #11 user login. Public and private enumeration
enrich one native object cache rather than maintaining competing views.
Object-type, ID, and sequence identify a native cache entry; sequence changes
discard stale derived properties.

USB and HTTP are connector implementations behind the same backend boundary.
Each configured HTTP service URL is discovered through `/v1/devices`; every
returned serial becomes its own slot and routes commands through that serial's
endpoint. All slots from one configured service entry share its HTTP agent and
connection pool, while duplicate configuration entries remain independent.
Endpoint transport recovery advances a shared connection epoch; individual
device disappearance or version changes advance device state separately. The
YubiHSM slot observes the combined epoch and clears device-bound object,
metadata, attestation, inferred authentication-algorithm, and public-discovery
state.

YubiHSM Auth applet connectors are shared with YubiHSM slots through
synchronized provider handles. Credential selectors identify the target
YubiHSM authentication-key ID, optional applet credential and source, and
password separately; public-discovery runtime state is held by the target
YubiHSM slot, not globally.

An asymmetric credential's public point may be persisted as an ordinary public
object on each matching YubiHSM, with the Authentication Key ID in `CKA_ID`.
The optional `C_LoginUser` wildcard selector asks the target YubiHSM slot to
compare those public projections with available asymmetric YubiHSM Auth
credentials. The comparison uses the slot context's merged public token-object
view, including generic persisted objects as well as backend-native objects.
Each matching projection supplies an Authentication Key ID, and the candidates
are tried in discovery order until one authenticates. Duplicate projections for
the same credential are therefore valid candidates rather than an ambiguity.
No match returns `CKR_USER_TYPE_INVALID`; rejection after an actual credential
attempt returns the authentication error. This resolution depends on successful
public discovery and does not change explicit selector behavior.

## Companion multi-device connector

The `pkcs11rs-connector` executable is a separate Cargo package rather than a
server embedded in the PKCS #11 provider. It owns the Tokio and Axum runtime,
the server-side Rustls configuration, an nusb hot-plug registry, and one
asynchronous command gate per attached YubiHSM. Different physical serials can
execute concurrently; a single device processes one complete request at a
time.

The provider and daemon share `pkcs11rs-local-hardware`. Its default blocking
frontend uses nusb's blocking waits and introduces no Tokio runtime into a
process that loads the PKCS #11 library. The daemon enables the optional
`async-tokio` frontend. Both frontends share device construction, connection
state, endpoints, complete-write checks, dynamic zero-length-packet decisions,
and response copying; only waiting for USB completion differs. Portable builds
and the iOS XCFramework omit the native local-hardware crate. The iOS build has
a native CryptoTokenKit CCID provider, while remote HTTP(S) connector slots
remain available to the provider.

The daemon is currently a private-network component, not a public security
boundary. It implements TLS and optional mTLS, bounded request bodies and
global in-flight admission, firmware-aware frame validation, serial routing,
per-device serialization, hot-plug discovery, preservation of its listener and
claimed USB handles across system suspend, and recovery after an uncertain USB
failure. A failed command is never replayed; its handle is discarded and a
later request reopens the same transient USB device, verifies its serial, and
claims it inside the per-device gate before submitting a new command. The
daemon deliberately has no complete-handler deadline that could race an active
USB command. Device-aware client authorization, accepted TCP connection limits,
and per-client fairness remain future work. See the [connector deployment
boundary and Internet-readiness checklist](connector.md#deployment-boundary)
for the authoritative status.

## Failure boundaries

Applet selection establishes slot identity. A later applet initialization or
object-discovery error does not delete that slot; token operations report the
stored or refreshed failure. Malformed individual device objects are skipped
where a backend can safely preserve the rest of the inventory.

Hardware-independent tests exercise protocol codecs, official vectors,
malformed responses, cache invalidation, reconnect behavior, login variants,
and the synthetic ABI. Ignored hardware tests remain the boundary for exact
reader, device, firmware, touch, and persistent-mutation validation.
