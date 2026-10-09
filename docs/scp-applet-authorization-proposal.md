# SCP requirements and applet key authorization

## Status and purpose

This is a firmware and virtual-device design proposal. The policy fields,
internal interfaces, and examples below are proposed, not supported YubiKey
commands or implemented `pkcs11rs` configuration. No numeric APDU, TLV, or
PKCS #11 attribute assignments are specified here.

The proposal has two independently useful parts:

1. A minimal per-applet policy that requires protected SCP communication while
   preserving ordinary applet authentication.
2. Per-key authorization rules that accept an authenticated SCP credential as
   an alternative to, or an additional requirement alongside, applet
   authentication.

The first part needs no client identity or changes to key authorization. It can
accept SCP03 and every supported SCP11 variant, including factory SCP11b. The
second part uses the same credential-reference rule for SCP03, SCP11a, and
SCP11c. SCP11b supplies channel protection but never client authorization.

## Current implementation boundary

`pkcs11rs` selects SCP through configuration or a provider credential URI.
Ordinary `C_Login`, and `C_LoginUser` with an empty username, use configured
credentials; a nonempty username can select a provider credential. Applet PIN
verification remains separate. Public discovery does not establish SCP. These
are host policies and do not prevent another client using plaintext where the
device permits it. See [CCID login](ccid.md#login-selected-secure-channels) and
[SCP11 configuration](scp11.md).

The USB virtual YubiKey and embedded virtual readers use the same
`virtual-yubikey-core`. Its common APDU router unwraps SCP before dispatching to
an applet. The channel implementation has an OCE-authenticated indication used
for Issuer SD administration, but it does not expose a general principal to
PIV or other applets. The core has no configurable per-applet SCP requirement
or per-key SCP authorization policy. Relevant implementation locations are
`virtual-yubikey/crates/virtual-yubikey-core/src/lib.rs`, `secure_channel.rs`,
and `security_domain.rs`.

Physical YubiKeys expose SCP as a transport layer; Yubico documents that SCP03
authentication does not itself assign applet permissions. FIPS 5.7.4 devices
have fixed NFC requirements: PIV, OpenPGP, and YubiHSM Auth require SCP, while
OATH requires it for selected modifying commands. A general configurable
per-applet rule is not documented in the reviewed public interfaces.
[Yubico SCP description](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-scp.html),
[FIPS firmware requirements](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-140-3.html).

This proposal changes device enforcement and applet authorization. It does not
claim that enabling an emulator policy provides FIPS certification.

## Separate transport protection from authorization

| Established protocol | Can satisfy `require_scp`? | Credential that can authorize the client |
| --- | --- | --- |
| SCP03 | Yes | Authenticated installed SCP03 key set |
| SCP11a | Yes | Installed OCE trust key used to validate the authenticated host |
| SCP11b | Yes | None; the host has no authenticated long-term credential |
| SCP11c | Yes | Installed OCE trust key used to validate the authenticated host |

All accepted channels must provide command and response authentication and
encryption. A CLA secure-messaging bit, a pending handshake, or a certificate
upload alone satisfies neither requirement.

SCP11b is sufficient when the requirement is to protect a PIN or other sensitive
traffic, without authenticating the host at the SCP layer. Ordinary applet
authentication still authorizes the operation. Hosts should validate the card
certificate chain or an explicitly provisioned card public key before sending
sensitive data; the card cannot determine whether the host performed that
validation. `pkcs11rs` already performs this validation in certificate mode.

SCP03 authentication identifies everyone who possesses the shared key set. It
cannot distinguish individual clients sharing that set. An SCP11a/c grant tied
to an OCE CA likewise authorizes the set of clients that can authenticate under
that CA, subject to its certificate validation and allowlist policy. These are
credential-group identities unless a rule further restricts the client key.

## Stage 1: the minimal `require_scp` policy

### Persistent setting

Add one persistent boolean to an applet's security settings:

```text
require_scp = false | true
```

Existing devices and old emulator records default to `false`. Enabling the
setting requires that applet's existing administrator authorization, through a
fully protected channel. Disabling it requires the same authorization; an
unauthenticated client cannot relax the policy. Reject unsupported settings
instead of silently accepting them.

The initial setting applies to every transport that reaches the applet, not
just CCID. For applets with alternate routes, either carry verified SCP
protection there or reject affected operations through those routes. For
example, a FIDO applet-wide SCP requirement must not leave USB HID as an
unprotected bypass. A later transport selector could express NFC-only rules,
but is unnecessary for the minimal implementation.

### Public bootstrap exception

Keep a small, explicit allowlist of operations available without SCP:

- Applet selection and the public identity/capability reads necessary to
  discover the applet and its SCP requirement.
- Public Issuer SD certificate, key-reference, and CA-identifier reads needed
  to establish a channel.
- The protocol's handshake and host-certificate upload commands.
- The narrowly defined Issuer SD factory-recovery mechanism.

List exact commands, parameters, and data objects for each applet. Do not exempt
all `GET DATA` commands or everything categorized as a read: cryptographic
results and credential material can be sensitive. Discovery must remain free
of PIN verification and other commands that consume ordinary login retries.

For the minimal flag, every other command requires verified protection. This
includes PIN verification and changes, key use, key generation/import/deletion,
credential provisioning, policy updates, and applet administration. A future
per-operation transport policy may selectively protect sensitive operations,
but a single flag with a bounded public bootstrap is easier to enforce.

Public discovery can therefore enumerate several applets without a handshake
for each one. The client establishes SCP when beginning protected use of the
selected applet, following the existing lazy-login model.

### Dispatch implementation

Put the transport check in the common APDU path, after complete command
reassembly and successful secure-message verification, and before applet
dispatch. In the virtual core, this is the boundary between
`SecureChannel::process` and `VirtualYubiKey::dispatch_apdu`.

Conceptually:

```text
command, context = channel.process_and_verify(received_command)
if command is an exact permitted bootstrap operation:
    handle_bootstrap(command)
else:
    if selected_applet.require_scp and not context.fully_protected:
        return security_status_not_satisfied
    dispatch_to_applet(command, context)
```

Bootstrap operations have their own validation and retry rules. The allowlist
does not bypass authentication required to mutate SD state. Protocol recovery
must remain reachable independently of lost credentials, as described below.

An unprotected operational command is rejected before its body reaches the
applet. It must not decrement PIN retries, change state, perform cryptography,
or consume a pending presence grant. Use `6982` for an unmet security condition;
use `6A80` for malformed policy encoding and `6985` for an incompatible policy
transition, subject to the target applet's established conventions.

Rejecting a command never switches to plaintext or weakens the active policy.
A protected rejection follows the implementation's SCP error-response rules;
policy enforcement must not bypass the normal response-protection path.

Command-fragment acknowledgements carry no applet authority. Bind response
continuation to the originating command and its channel generation. A plaintext
`GET RESPONSE` must not retrieve decrypted output buffered for a protected
operation; any transport-level continuation allowed by the implementation must
preserve the original ciphertext and integrity protection.

### Minimal result

Enabling `require_scp` on PIV makes protected communication necessary while
leaving its PIN, management-key, touch, and key-use policies intact. Factory
SCP11b can satisfy the flag without any OCE provisioning. This is a useful
standalone feature even if per-key SCP authorization is never implemented.

## Stage 2: one authorization rule for SCP03, SCP11a, and SCP11c

### Bind a grant to an installed SD credential

Use the same external policy shape for every client-authenticating mode:

```text
scp_credential = { kid, kvn, allowed_protocols }
```

For SCP03, the reference identifies the entire installed AES key set, using the
SD's normalized key-set reference rather than individual ENC/MAC/DEK grants.
The current client uses KID `00`; public inventory also describes the individual
keys. The policy API must normalize these representations consistently.

For SCP11a/c, the reference identifies the installed trusted OCE public-key
entry, such as an OCE CA key. It does not identify the card's private key at
KID `11` or `15`. Selecting a card key does not establish which host is
authorized. The SCP implementation records the OCE trust entry actually used
to validate the host and exposes that verified reference to the applet.

`allowed_protocols` can permit SCP03 for a symmetric reference or SCP11a,
SCP11c, or both for a compatible OCE reference. Reject mismatched key types,
SCP11b authorization rules, and references to absent or blocked credentials.
No separately assigned client key ID, new certificate extension, or extra
credential-provisioning ceremony is required.

This reference-based rule grants authority to the credential group. If a
deployment needs one specific SCP11 client, an optional additional predicate
can match its validated leaf public key. A canonical P-256 public-key digest
can represent that predicate; it must be computed from normalized key material,
not arbitrary certificate DER, subjects, SKI extensions, URIs, or a
client-asserted identifier. Renewal with the same public key preserves the
match; rotation to another public key requires an explicit policy update.

### Prevent slot reuse from inheriting permissions

KID/KVN is the user-facing reference, but it is insufficient as a durable
binding. Internally assign each installed credential an unpredictable instance
identifier, scoped by an SD instance identifier. Resolve KID/KVN to those
instances when an authorized administrator creates the grant.

The administrator does not configure those identifiers. They are persistent
implementation metadata, generated independently of secret key bytes and
never reused after deletion, replacement, or SD reset. Do not publish a hash of
symmetric secret material as an identifier.

On credential deletion or replacement, invalidate its grants and active
authorization contexts. Installing a new key at the same KID/KVN does not
restore them, even if the new record carries the same caller-supplied CA
identifier. Renewing associated certificates without replacing the trust key
need not replace its credential instance; changing trust or allowlist policy
must still invalidate affected live sessions and trigger revalidation.

Store policies with applet/key state. A missing credential disables the bound
grant; it does not delete the applet key or implicitly change its authentication
expression to a weaker one. Dangling references can be removed later, but must
remain denied after a crash even before cleanup completes.

### Immutable authorization context

Replace the boolean-only protected indication at the applet boundary with a
read-only, firmware-created context containing:

```text
channel_generation
selected_applet
protocol and negotiated protection
current_command_verified
authenticated_sd_credential_instance, if any
validated_client_public_key, if any
trust/policy revision
```

Session keys and DEKs are not part of the applet-visible context. Applets cannot
construct or upgrade a context, and APDU payloads cannot assert its fields.

For SCP03, expose the credential only after successful host authentication and
verification of the operational command's C-MAC. For SCP11a/c, certificate
validation identifies a candidate host key, but uploading a certificate or
receiving a card receipt does not prove host possession. The current core's
administration path relies on the subsequent protected command's verified
C-MAC as that proof. Publish authorization only when that proof succeeds.
For SCP11b, the authenticated-client credential remains absent.

The context is bound to the exact selected applet and command. A valid MAC
under another channel or an earlier channel generation cannot authorize it.

### Per-key expressions

Keep channel requirements independent of the authentication expression. A key
policy can describe these choices:

| Authentication expression | Meaning |
| --- | --- |
| Existing applet authentication | SCP protects transport but grants no additional permission |
| Existing authentication OR matching SCP credential | Either explicit path may authorize this key operation |
| Existing authentication AND matching SCP credential | Both conditions must hold in the same permitted scope |
| Matching SCP credential only | The named SCP credential replaces ordinary authentication for this operation |

An applet-wide `require_scp` is an additional condition on every expression;
an OR branch cannot bypass it. A per-key `require_scp` can later tighten one
key without requiring it for the whole applet.

Rules name exact operations: sign, decrypt, derive, import, generate, delete,
read a protected object, change policy, or administer the applet. Granting
signing does not imply deletion, export, PIN changes, management-key changes,
or Issuer SD administration. Existing algorithm restrictions, nonexportability,
usage restrictions, and touch requirements remain enforced. Changing a PIN
requirement is an explicit policy action, not a side effect of establishing SCP.

For an initial reference implementation, support the minimal channel flag and
then add named SCP grants for PIV sign/decrypt/derive. Broader administration
rules and more elaborate combinations can follow after those boundaries are
qualified.

### Illustrative policy

This example is a proposed device policy, not valid initialization JSON for
the current library. KID `20`/KVN `1` denotes a provisioned OCE trust key;
slot `9C` denotes a PIV signing key.
KID strings in this illustrative encoding are hexadecimal.

```json
{
  "policy_version": 1,
  "applet": "piv",
  "require_scp": true,
  "keys": {
    "9C": {
      "sign": {
        "authentication": "applet_or_scp",
        "scp_credentials": [
          {"kid": "20", "kvn": 1, "allowed_protocols": ["scp11a"]}
        ],
        "preserve_touch_policy": true
      }
    }
  }
}
```

With SCP11b, the normal PIV PIN path can satisfy this policy, but the SCP grant
cannot. With SCP11a authenticated through the named OCE trust entry, the SCP
branch can authorize signing without treating every PIV key as PIN-verified.
A comparable SCP03 rule names the installed custom key set and permits only
`scp03`. An SCP11c rule uses the same shape with `scp11c` explicitly enabled.

## Authorization lifetime and protocol differences

Authorization exists only while the current verified channel, selected applet,
credential instance, and policy revision remain valid. Clear it on selection
changes that end the channel, disconnect, reconnect, failed establishment,
invalid secure messaging, credential block/delete/replace, trust changes,
policy changes, and SD or applet reset. Beginning a replacement handshake must
clear the prior context before processing new credentials.

Reestablishing SCP can recreate its own credential-based authority after fresh
proof and a fresh policy check. It must not restore ordinary applet PIN
authorization or consume a retained PIN. Per-operation authentication and touch
remain per-operation unless an explicit new policy changes their semantics.
Keep session keys in zeroizing storage and follow the existing
[authentication secret retention policy](authentication-secrets.md).

SCP11c uses a static card key and supports offline scripting. Do not assume that
its successful establishment implies live user interaction, card-side forward
secrecy, or application-level freshness across separately established sessions.
Rules requiring those properties should exclude SCP11c. A deployment permitting
offline administrative scripts needs an explicit applet-level replay policy,
such as persistent script sequence numbers, separate from message counters
inside one SCP session.

Certificate validity and revocation follow the supported validator and device
time model. Do not promise wall-clock expiry enforcement on hardware without a
trusted clock. Credential removal, allowlist changes, policy revisions, and
session invalidation must remain enforceable independently of wall-clock time.

## Provisioning, administration, and recovery

### Safe policy provisioning

1. Install and verify the intended SCP credential using existing SD management.
2. Authenticate as the applet administrator through a protected channel.
3. Resolve the chosen KID/KVN to its credential instance and install a versioned
   policy atomically with the applet or key record.
4. Read back the effective policy and test both allowed and denied operations.
5. Remove temporary provisioning credentials only after verifying the intended
   operational and recovery paths.

Managing SD keys must not automatically grant the ability to edit an applet's
authorization policy. Conversely, an applet signing grant must not authorize
SD administration. Broad CA trust grants must be explicit: every qualifying
client under that CA otherwise receives the permitted operation.

Policy updates are authenticated administrative actions. Prevent a client from
granting itself wider rights solely because it possesses a key-use grant.
Optional dedicated policy-administrator grants can be added with separately
provisioned authority; they are not implied by a successful SCP handshake.

Card keys, OCE trust keys, certificate chains, and applet policy records are
different storage objects. Physical 5.7.4 qualification suggests a shared
three-credential-entry budget; certificate data has separate storage limits.
SCP11a card key + OCE trust key + SCP11b card key is a candidate layout when
SCP03 is removed, but that exact physical layout has not been qualified.
See [provisioning results](scp11.md#issuer-sd-key-provisioning). Policy records
should add metadata rather than consume additional cryptographic key slots.

### Reset behavior

Yubico's unauthenticated SD recovery exhausts installed keys and restores default
SCP03 plus a fresh attestable SCP11b identity. It clears SD credentials and
associated data, not PIV keys or other applet credentials.
[Yubico reset implementation](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/securitydomain.html#SecurityDomainSession.reset).

The proposed policies must preserve that separation:

- An SD reset retains applet keys, normal PINs, and applet/key policy records.
- A new SD instance invalidates every old credential-reference grant. Factory
  keys must never acquire rights attached to deleted credentials.
- Public factory SCP03 keys cannot be provisioned as key-authorization grants.
  This also applies if the same factory key material is imported under another
  KID/KVN; changing a reference does not make a public credential secret.
  They may satisfy a transport flag where allowed by the firmware, but do not
  provide secrecy against observers who know those keys. Factory SCP11b is
  the preferred transport-only path.
- A retained `require_scp` flag can be satisfied by restored factory SCP11b,
  allowing the original PIN or administrator path where the policy permits it.
- A key configured for SCP-only authorization remains inaccessible if its
  credential disappears. Do not silently enable PIN access. Recovery then
  needs an explicitly provisioned administrator path; absent that, the applet
  can require reset and loss of its keys. SD recovery alone is not recovery of
  every applet authorization policy.

Applet reset follows that applet's established credential and key erasure
semantics and removes its custom policies. Fixed firmware/FIPS requirements
cannot be relaxed by resetting a user-configurable flag. A genuine whole-device
reset retains its documented scope.

### Persistence and races

Use persistent SD and credential instance identifiers to deny stale references
without relying on a transaction spanning every applet file. Commit credential
invalidation before acknowledging deletion; unfinished grant cleanup is safe
because instance resolution already fails. On SD reset, commit the new SD
instance before publishing restored factory credentials. Power-loss recovery
must never revive an old instance through an automatic repair path.

Serialize policy changes, credential changes, and command authorization with
dispatch. A pending user-presence operation must carry the channel and policy
generations and recheck them before completing. No sign or administration
operation may finish using a grant invalidated while it waited for touch.

## Host integration and compatibility

Expose a public capability indicating policy support and a nonsecret effective
policy summary. Policy writes and sensitive policy details require explicit
administrative authority. Define a bounded, versioned vendor command/data-object
format rather than repurposing a standard GlobalPlatform object with different
semantics. Keep existing SCP handshake wire formats unchanged.

For `pkcs11rs`, the minimal flag fits the existing login path: discovery stays
public, configuration selects SCP11b or another supported protocol, and login
establishes SCP before sending a PIN. Required-channel failures must never
trigger automatic plaintext fallback.

Per-key SCP authorization needs explicit backend capability and policy discovery.
The current `C_Login`/`C_LoginUser` behavior must remain the default. On a device
implementing the proposal, an explicitly selected SCP credential and the key's
policy may permit operation without an applet PIN. A PKCS #11 session role is
not a blanket claim that every key is authorized: the backend must check the
operation's effective policy and preserve per-key restrictions. Existing
`CKA_ALWAYS_AUTHENTICATE` semantics cannot silently disappear; advertise and
implement any alternate authorization mapping consistently.

Source-provider login remains distinct from target authorization. Retain only
the source binding and live channel state permitted by the existing lifetime
policy, and do not cache a target PIN to emulate SCP authorization.

Implement enforcement and persistence in `virtual-yubikey-core` so USB and
embedded variants agree. Keep primitive cryptography and certificate validation
in `software-key-core`; keep host credential selection, card trust, and PKCS #11
role mapping in `pkcs11rs`. Reconcile implementation documentation in both
repositories when this proposal is implemented. Real YubiKeys require firmware
support; a host-only change cannot enforce a device policy against other clients.

## Qualification and acceptance criteria

The reference implementation should demonstrate:

1. Plaintext discovery and certificate acquisition still work; protected-only
   operational commands are rejected without consuming PIN retries or changing
   state. SCP03 and SCP11a/b/c can each satisfy the channel flag at full protection.
2. SCP11b never creates an authenticated-client grant, including when its card
   certificate chains to a trusted factory root.
3. SCP03 grants bind the authenticated custom key set. SCP11a/c grants bind the
   OCE trust entry actually used. Optional client-key predicates distinguish
   different valid leaves under the same CA.
4. Forged IDs, CLA bits, partial handshakes, uploaded certificates without host
   proof, bad C-MACs, malformed chains, and protocol/key-type mismatches are
   rejected before applet operations.
5. OR, AND, and SCP-only expressions authorize only their named key operations;
   signing grants cannot modify policy, delete keys, remove touch, or administer SD.
6. Deletion, replacement at the same KID/KVN, credential blocking, CA/allowlist
   changes, applet selection, connection loss, and SD reset invalidate the
   appropriate grants. Restart and interrupted persistence writes do not revive
   them. SD reset preserves PIV keys and never gives factory SCP03 their rights.
7. Applet PIN recovery works only where explicitly permitted. SCP-only policy
   loss remains denied; applet reset is tested separately from SD recovery.
8. Chained commands, response continuation, pending touch, and concurrent policy
   changes cannot bypass the check. Alternate transport paths obey the same
   applet policy or reject protected-only operations.
9. Session recreation obtains fresh channel proof and checks current policy,
   without restoring unrelated PIN authorization or replaying failed operations.
10. Direct core vectors, embedded PKCS #11 tests, and USB CCID qualification agree.
    Physical enforcement tests require firmware implementing these vendor policies.

The first deliverable should be the applet flag, public capability/readback,
administrative configuration, shared-router enforcement, persistence, and reset
tests. The next deliverable should add uniform credential-reference grants and
PIV key-use authorization. Optional client-key restrictions, transport selectors,
additional applets, and dedicated policy-administrator grants can extend that
same design without changing the distinction between channel protection and
client authorization.
