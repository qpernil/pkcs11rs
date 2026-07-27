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
        │       ├── token and session object handles
        │       └── session handle -> SessionContext
        │           ├── Box<dyn BackendSession>
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

## Slots, backends, and mechanisms

`SlotContext` implements the behavior common to every PKCS #11 slot: session
ownership, login role, object handles, and dispatch. Its boxed `Slot`
implementation supplies the device- or applet-specific token metadata,
objects, login behavior, mechanisms, random generation, and backend sessions.

Backend mechanism lists describe hardware operations. The default `Slot`
implementation augments them with the module's software digest mechanisms,
whose active state is still stored in the calling session. Read-only FIDO2 is
the exception: it explicitly reports an empty mechanism list so its projected
credential keys cannot be mistaken for operational keys.

The `abi-tests` feature uses synthetic slots that identify the real backend
kind they model. Production dispatch therefore does not contain a generic
test-slot branch.

## PC/SC applet topology

One physical PC/SC reader has one shared `PcscReaderState`. Every selected
applet gets a separate logical PKCS #11 slot and a slot-local connector facade,
while all facades share:

- the card connection and complete APDU-exchange lock;
- the current selected AID and APDU capabilities;
- the device identity and connection epoch;
- the active secure-channel state and relevant certificate caches.

Logical work on different applet slots may proceed concurrently, but a
physical reader performs only one complete applet selection or APDU exchange
at a time. Selecting an applet invalidates a secure channel belonging to
another AID; the next protected operation reselects its AID and establishes
the appropriate channel.

Discovery is a snapshot. Only applets selected during the first
`C_GetSlotList` after initialization become slots. Existing slots can reconnect
and reselect their AID after card removal, but the slot registry does not
morph to match a replacement card. See [CCID applet configuration](ccid.md).

## YubiHSM transports and caches

Each YubiHSM slot owns one secure-session role at a time: retained public
discovery or ordinary PKCS #11 user login. Public and private enumeration
enrich one native object cache rather than maintaining competing views.
Object-type, ID, and sequence identify a native cache entry; sequence changes
discard stale derived properties.

USB and HTTP are connector implementations behind the same backend boundary.
HTTP slots are created from configured URLs even when initially unavailable.
After the first successful HTTP status request, transport recovery or a
serial/version change advances a connection epoch. The YubiHSM slot observes
that epoch and clears device-bound object, metadata, attestation, inferred
authentication-algorithm, and public-discovery state.

YubiHSM Auth applet connectors are shared with YubiHSM slots through
synchronized provider handles. Credential selectors identify the target
YubiHSM authentication-key ID, optional applet credential and source, and
password separately; public-discovery runtime state is held by the target
YubiHSM slot, not globally.

## Failure boundaries

Applet selection establishes slot identity. A later applet initialization or
object-discovery error does not delete that slot; token operations report the
stored or refreshed failure. Malformed individual device objects are skipped
where a backend can safely preserve the rest of the inventory.

Hardware-independent tests exercise protocol codecs, official vectors,
malformed responses, cache invalidation, reconnect behavior, login variants,
and the synthetic ABI. Ignored hardware tests remain the boundary for exact
reader, device, firmware, touch, and persistent-mutation validation.
