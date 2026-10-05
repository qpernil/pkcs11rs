# Linux TPM2 platform credential plan

## Status and scope

This is a proposed backend, not implemented Linux support. The current
`platform-credential` crate selects native providers on macOS, iOS, and Windows.
Linux credential operations return `Unsupported`, and enabling its platform slot
fails with `CKR_FUNCTION_NOT_SUPPORTED`. Installing TPM libraries does not change
that behavior. Ordinary Linux PKCS #11 slots and hardware transports are separate.

The proposed backend implements the existing named P-256 credential lifecycle
and ordinary ECDH contract through TPM 2.0. The public Rust API, CLI commands,
PKCS #11 source authorization, and YubiHSM provisioning and authentication paths
remain platform-neutral. TPM 1.2, symmetric platform credentials, PCR-bound boot
policies, and an external PKCS #11 module are outside the initial scope.

## Design fit

The shared abstraction is a named protected P-256 key exposing public-key access
and ECDH, with explicit lifecycle operations. A Linux TPM backend fits that
provider boundary alongside Apple Secure Enclave and Windows CNG.

The native APIs do not provide identical management facilities:

| Backend | Native key operation | Naming, persistence, and access management |
| --- | --- | --- |
| Apple | Security framework with Secure Enclave keys | Application-accessible Keychain and its OS access policy |
| Windows | CNG with the Microsoft Platform Crypto Provider | Current-user persisted key names and KSP access controls |
| Proposed Linux | ESAPI with TPM 2.0 commands | Persistent TPM keys, backend-managed public records, Linux permissions, and explicitly defined TPM authorization |

ESAPI is a lower-level native interface than the Apple and Windows key-store
APIs. It supplies TPM objects and sessions, not an equivalent current-user named
credential store. The Linux backend must provide that management layer before
it exposes the same contract. This is compatible with keeping platform details
inside `platform-credential`; consumers need no Linux-specific API.

## Native stack

Use the Rust [`tss-esapi`](https://github.com/parallaxsecond/rust-tss-esapi)
wrapper over the C libraries provided by
[`tpm2-tss`](https://github.com/tpm2-software/tpm2-tss):

```text
platform-credential Linux backend
    -> tss-esapi Rust wrapper
    -> libtss2-esys and related tpm2-tss libraries
    -> TCTI device transport
    -> Linux TPM driver/resource manager
    -> TPM 2.0
```

ESAPI (Enhanced System API, also called ESYS) maps TPM commands into C calls,
handles authorization sessions, and tracks native object metadata. TCTI is the
transport interface beneath it. The proposed production transport is a local
TPM device, normally `/dev/tpmrm0`, using the kernel resource manager. A separate
TPM resource-manager daemon is not required for that transport.

This adds native C-library dependencies; the Rust wrapper does not replace the
TPM stack. `tpm2-tools` provides optional diagnostic commands, not the runtime
API. `tpm2-pkcs11` provides a separate Cryptoki module and is not required by this
design. FAPI is another, higher-level API in `tpm2-tss`; this plan uses ESAPI to
control the key template, identity binding, and raw ECDH contract directly.

On Ubuntu, development files and related runtime libraries are installed with:

```sh
sudo apt install libtss2-dev pkg-config
pkg-config --modversion tss2-esys
ldconfig -p | grep libtss2-esys
ls -l /dev/tpm*
```

The ESAPI header is `/usr/include/tss2/tss2_esys.h`. Library locations use the
distribution's architecture directory, such as `/usr/lib/x86_64-linux-gnu/` or
`/usr/lib/aarch64-linux-gnu/`. Runtime package names vary by Ubuntu release.
These commands inspect or install the stack; they do not provision a credential.

## PC and Raspberry Pi requirements

The same backend should support Linux AMD64 and ARM64. A PC needs a TPM 2.0
exposed by its kernel driver; a Raspberry Pi typically needs an attached TPM
module and its appropriate wiring, driver, and device-tree configuration.
[Infineon's setup guide](https://github.com/Infineon/optiga-tpm-explorer/blob/master/Setup%20Guide.md)
describes attached TPMs on Raspberry Pi 3, 4, and 5. Installing ESAPI alone
does not provide TPM hardware.

Qualify each device for P-256 key creation, peer-point validation,
`TPM2_ECDH_ZGen`, and persistent-object capacity. The application needs access to
the TPM device and its managed credential directory. Normal operation should not
require root once device access and TPM authorization are configured. Generation
and deletion require the appropriate hierarchy authorization independently of
Linux device permissions. Hierarchy administration and device setup remain
separate operations.

Production must not silently select a software simulator when a device is
unavailable. Use `swtpm` only through an explicit test configuration. A local
TPM device path alone is not evidence of a discrete hardware TPM: virtual
machines may expose a virtual TPM. Report the qualified device context without
claiming hardware attestation or equivalent protection across implementations.

## Virtual machines and simulator testing

A Linux VM can expose `/dev/tpm0` and `/dev/tpmrm0` when its hypervisor provides a
TPM 2.0 device. Check the guest's device nodes and
`/sys/class/tpm/tpm0/tpm_version_major`; installing the TSS libraries does not
create a device. With `tpm2-tools` installed, an explicit read-only probe is:

```sh
tpm2_getcap -T device:/dev/tpmrm0 properties-fixed
```

Device-node absence means that the guest is not seeing a TPM, not that the host
necessarily lacks physical TPM hardware. Host TPM detection, host Secure Boot,
and the guest's virtual TPM are separate checks.

[VMware's vTPM documentation](https://www.vmware.com/docs/vsphere-virtual-tpm-vtpm-questions-answers)
describes vTPM provisioning through vCenter-managed VM Encryption and a key
provider. A standalone ESXi installation does not supply that provisioning
workflow. A physical host TPM is not required for a VMware vTPM and is not passed
through to the guest. Enabling host Secure Boot alone does not add a guest TPM.

For development without an exposed device, run
[`swtpm`](https://github.com/stefanberger/swtpm) inside the Linux VM and select its
TCTI explicitly in the test harness. Simulator tests should exercise the same
ESAPI key lifecycle without requiring vCenter or Pi TPM hardware. Simulator
state and VM/vTPM snapshots are copyable; these tests establish functional
behavior, not physical non-exportability or resistance to restoring TPM state.

## Key lifecycle and identity

Generate an unrestricted P-256 ECDH key with TPM-generated sensitive material,
`fixedTPM`, `fixedParent`, and decrypt usage. Exclude signing and duplication.
Verify the returned public template and complete public point before accepting
the credential. The selected scheme must permit `TPM2_ECDH_ZGen`.

### Storage parent and persistent child keys

The proposed initial store uses randomly generated child keys persisted in TPM
nonvolatile memory. Create an application-managed primary storage parent under
the owner hierarchy, using versioned, stable creation parameters and a defined
application-specific derivation input. Recreate it on demand for child creation;
the parent need not consume an additional persistent allocation. A storage
parent protects child private material and is not itself the ECDH credential.
Recreating the parent does not recreate a randomly generated child.

Use `TPM2_Create` and `TPM2_Load`, then `TPM2_EvictControl` to persist the child.
The wrapped private output is temporary process data: keep it in zeroizing
storage, discard it after persistence or failure, and never write it to the
credential store, logs, or backups. Do not export or persist reloadable key
contexts. Audit native-library response buffers and copies before claiming
complete cleanup. The plaintext
private scalar remains inside the TPM, but a reloadable wrapped representation
does pass through host memory during generation. `TPM2_CreateLoaded`, where
supported, combines creation and loading but still returns wrapped private
output for an ordinary child; it does not provide a no-output creation mode.
See [the TPM command specification, sections 12.1 and 12.9](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf)
and [persistent-object management](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_evictcontrol.1/).

Store only the managed name, persistent handle, complete public key and TPM
Name, parent identity and creation parameters, and record-format version in the
user-owned directory. Backing up these records must not back up private blobs
or reloadable key contexts. A record backup can locate an existing TPM key but
cannot recover a deleted random child.

Persistent storage is finite and shared with other TPM users. Discover available
capacity, reserve handles without replacing existing objects, and fail explicitly
when capacity is exhausted. Do not fall back to private-blob files. Define handle
allocation, locking across processes and users, and recovery of interrupted
generation before implementation. Keep a transaction record sufficient to
identify a newly persisted key before publishing its credential name. Recovery
must verify recorded identity and ownership before removing an orphan; never
reclaim an unfamiliar persistent object merely because its handle is in a chosen
range.

TPM clearing, hierarchy-seed changes, missing or replaced persistent objects,
and corrupted records must fail explicitly. Qualify parent reproducibility
across normal restarts and handle firmware changes without accepting a changed
identity. Parent provisioning, hierarchy authorization, and the final storage
location remain implementation decisions. Do not take ownership of unrelated
TPM objects or clear the TPM during setup or tests.

### Deletion and recovery boundaries

Deleting a credential must evict its identity-verified persistent TPM object,
release backend-owned transient copies and session resources, and remove its
managed record. Serialize deletion with backend operations so a retained
credential cannot continue ECDH using an old binding. Eviction failure must not
be reported as successful deletion or hidden by removing the local record.
Make interrupted deletion recoverable, including eviction that succeeds before
the record update. Close ESAPI references to persistent objects; flush only
backend-owned transient objects and sessions, without disturbing unrelated users.

The intended deletion guarantee depends on retaining no reloadable copies.
Neither `fixedTPM` nor `fixedParent` prevents restoration of a saved wrapped blob
under its original parent on the same TPM. They restrict migration. A wrapped-file
store therefore does not meet this proposal's deletion objective when backups
can restore the key. Do not claim that deleting a file securely erases its copies,
or that TPM eviction invalidates saved contexts held outside this backend or
prevents rollback of a VM/vTPM snapshot.

A directly derived primary ECDH key with retained creation inputs is also
unsuitable for that objective: it can be recreated after eviction. Persisting a
primary key with random creation inputs that are discarded could avoid wrapped
private output, but would place deletion's recovery boundary on those inputs.
That alternative is not the proposed baseline and needs separate qualification.

HSM access revocation remains independent of platform-key deletion. Removing
the corresponding authentication object through the normal HSM object-mutation
path revokes new authentication on that HSM, even if a platform key survives.
Provisioning on other HSMs and already established secure-channel sessions have
their own lifetimes; local key deletion is not a global revocation operation.

### Managed identity

Keep the shared name-validation contract. Valid names can contain filesystem
separators, so use an encoded or hashed storage identifier rather than placing
the raw name into a path. Use owner-only directories and files, locking, and
atomic publication. Refuse duplicate names and preserve unrelated records.

Implement generate/list/public/delete and credential resolution without changing
the API. Every ECDH operation reads the managed record, resolves its persistent
object, verifies the originally bound public identity and TPM Name, and uses
that same resolved key. A handle alone is not an identity: deletion, replacement,
or reuse must invalidate retained credentials. Release ESAPI references and
backend-owned transient handles and sessions on success and error paths.

## ECDH and authorization

Validate the peer's complete P-256 public point and invoke `TPM2_ECDH_ZGen`.
Normalize the returned point's X coordinate to exactly 32 big-endian bytes,
including leading-zero padding. The existing composition layer performs KDFs
and creates protected session objects. The private scalar remains TPM-protected;
the shared secret enters zeroizing module memory, as with the Apple and Windows
backends. Qualify authorization-session parameter protection for this exchange.

Preserve empty-PIN PKCS #11 USER login as the source authorization gate. It does
not verify a Linux account password or supply TPM hierarchy authorization.
Linux device permissions, credential-file permissions, and TPM authorization
policy are separate controls; they do not imply application isolation merely
because a name is in the managed namespace.

Define the initial key and parent authorization policy explicitly. Do not cache
Linux passwords, TPM authorization values, or reusable PINs to make reopening
convenient. Any retention exception requires explicit opt-in and the scope,
lifetime, cleanup, and tests specified by
[the authentication secret policy](authentication-secrets.md).

Serialize ESAPI operations with safe context ownership compatible with the
existing `Send + Sync` credential traits. Credential objects should retain
identity and store references rather than live ESAPI handle bindings. Do not add
unchecked `Send`/`Sync` implementations around native contexts.

## Build integration and qualification

Propose an optional Linux-only Cargo feature for the native dependency, forwarded
consistently through the provider and tool. Linux builds without that feature
must retain their existing dependency requirements and explicit unsupported
platform behavior. Enabling the backend still requires `platform.enabled=true`.
Finalize the feature name, native-library version requirements, token label,
model, and configuration before exposing them as supported interfaces.

Qualification should cover:

- Simulator lifecycle, restart persistence, duplicate names, corrupted public
  records, and deletion/replacement invalidation, including persistent-handle
  reuse and retained credential references.
- Public-record backup and restore cannot recover a deleted random child;
  recreating its storage parent does not recreate that child. Demonstrate why a
  retained private blob would defeat this guarantee only in an isolated fixture.
- Persistent capacity exhaustion, collision avoidance, concurrent operations,
  interrupted generation/deletion, eviction failures, and cleanup of owned
  resources without altering unrelated TPM objects. Verify that generation
  persists no private blobs or reloadable contexts and review memory cleanup.
- ECDH and prefixed-KDF interoperability, leading-zero secrets, and rejection of
  invalid peer points, key policies, or parent bindings.
- Existing platform-slot object visibility, empty-PIN login, protected-secret
  handling, and normal provider object-mutation paths.
- Ignored, explicitly selected hardware tests on a PC and an attached Pi TPM,
  without TPM clearing or unrelated-object manipulation.
- The existing platform-neutral HSM provisioning test with explicit and
  automatic selectors, public discovery, and encrypted channel operations.

Simulator CI does not qualify a hardware model. Record device-specific results
and limitations in [the platform documentation](platform.md) only after they
are verified. Associated certificate discovery can initially return no
certificates; a Linux certificate-store contract requires separate definition.
