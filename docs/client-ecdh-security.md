# Client ECDH placement and security

Asymmetric YubiHSM authentication and GlobalPlatform SCP11 derive working
keys from two P-256 agreements. The protocol fixes the mathematical inputs;
the client provider determines where the ephemeral private key and intermediate
agreements exist. `pkcs11rs` selects the strongest available placement before
starting the derivation and does not retry a weaker path after an operational
failure.

The final AES working keys are read into zeroizing process memory because secure
message encryption and authentication run in the client. Capturing those keys
compromises that live session under every placement. The stronger placements
limit what an earlier host-memory capture contributes to reconstruction of old
sessions after a later long-term-key compromise.

## Selection order

Native YubiHSM Auth is the highest-security source for YubiHSM authentication.
When a selected credential is available through that applet, the applet
generates and retains its ephemeral P-256 private key, holds the static client
credential, performs both agreements and the KDF, verifies the target receipt,
and returns only the final working keys. Native HSM Auth credentials are
searched before ordinary source-slot credentials.

Ordinary PKCS #11 credentials use these three paths, in order:

| Order | Path | Ephemeral placement | Agreement and KDF placement | Host-visible secret material |
| --- | --- | --- | --- | --- |
| 1 | Protected session graph | The source device generates a volatile, non-exportable P-256 key | Both agreements, concatenation, X9.63 KDF, extraction, and receipt verification remain in the source device | Verified final working keys |
| 2 | Literal prefix derive | The client generates the ephemeral key and agreement | The source device receives the ephemeral agreement as prefix bytes, performs static ECDH, and completes X9.63 | Ephemeral private key, ephemeral agreement, and final working keys |
| 3 | Basic ECDH | The client generates the ephemeral key; the source protects only its long-term private key | The source returns its raw static agreement; the client performs concatenation, X9.63, and receipt verification | Ephemeral private key, both agreements, and final working keys |

All three paths calculate the same logical construction:

```text
keys = X9.63-SHA-256(first-agreement || second-agreement, shared-info)
```

“Prefix derive” describes that construction as well as the second path's
literal-byte API. In the protected session graph, the first agreement is the
prefix mathematically, but it remains a protected object handle rather than
prefix bytes in host memory.

The protected graph is selected only when the source session provides native
volatile objects and both private-key sources permit ordinary ECDH. Otherwise,
the client selects `CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` when the credential
permits it. Basic ECDH is the final compatibility path. An advertised path that
fails is returned as an error; failure never triggers a less-protected retry.

Native volatile objects are scoped to their authenticated source session. Raw
agreements are non-readable, receipt keys are verify-only, and working keys
become readable only after successful receipt verification. Closing, losing,
or invalidating the source session destroys the objects and zeroizes their
values.

## Exact capability and mechanism decisions

Native YubiHSM Auth is selected by credential type rather than an ordinary
cryptographic mechanism. A matching HSM Auth slot object has
`CKO_PRIVATE_KEY` / `CKK_YUBICO_HSMAUTH_ASYMMETRIC`; the slot intentionally
advertises no general ECDH mechanism. The client invokes the slot's native
`hsmauth_authenticate` operation. Public matching searches native HSM Auth
credentials before ordinary PKCS #11 source slots.

For an ordinary source credential, the protected graph is selected when all of
these conditions hold before the first derivation operation:

- the authenticated provider session reports native volatile-session support;
- the generated ephemeral private key permits `CKM_ECDH1_DERIVE`; and
- the selected static credential permits `CKM_ECDH1_DERIVE`, including its
  `CKA_DERIVE` and `CKA_ALLOWED_MECHANISMS` policy.

On virtual YubiHSM this native support is discovered through algorithm 61
(`session-key-derivation`) and capability bit `0x39` (`derive-session-key`) on
the active Authentication Key. A persistent P-256 source additionally needs
ordinary `derive-ecdh` capability bit `0x0b`. The graph maps
`CKM_EC_KEY_PAIR_GEN`, `CKM_ECDH1_DERIVE`,
`CKM_CONCATENATE_BASE_AND_KEY`, `CKM_CONCATENATE_BASE_AND_DATA`,
`CKM_SHA256_KEY_DERIVATION`, `CKM_EXTRACT_KEY_FROM_KEY`, and
`CKM_AES_CMAC`/`CKM_AES_CMAC_GENERAL` to native volatile-object commands.

If that graph is unavailable, the literal-prefix path is selected when
`can_derive` succeeds for `CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` on the static
credential. That check includes slot mechanism advertisement, `CKA_DERIVE`,
and `CKA_ALLOWED_MECHANISMS`. A virtual YubiHSM executes it through algorithm
57 (`ecdh-kdf`), command `DeriveEcdhKdf` (`0x78`), and capability bit `0x38`
(`derive-ecdh-kdf`) on both the authenticated session and persistent source
key.

The final path requires `CKM_ECDH1_DERIVE` on the long-term credential. The
provider requests a readable raw agreement, immediately materializes it as a
zeroizing local session object, and performs the remaining concatenation,
X9.63 SHA-256, extraction, and receipt verification with the module's common
mechanisms.

Mechanism discovery chooses the path; backend names do not. `CKF_HW` describes
native coverage for discovery and diagnostics, but the selector relies on the
active provider-session capability and per-key operation policy because a
merged slot mechanism can contain both hardware and software operations.

### Physical YubiHSM firmware

A physical YubiHSM exposes its standard P-256 `DeriveEcdh` operation through
`CKM_ECDH1_DERIVE` and capability bit `0x0b`. It does not implement the virtual
algorithm 61 session-object command family or its volatile handles. It also
does not implement virtual command `0x78`.

For such a device, pkcs11rs generates the ephemeral P-256 key in its common
software session layer, asks the YubiHSM to perform ECDH with the protected
long-term private key, receives the raw static agreement, and performs
concatenation, X9.63 SHA-256, key extraction, and receipt verification in the
module. These module operations expose standard PKCS #11 session-object
behavior to the authentication code, but they do not imply that those objects
reside in physical YubiHSM memory. The long-term private scalar remains in the
YubiHSM; the agreements and final working keys enter zeroizing host memory.

## Protocol use

The notation below uses `e` for an ephemeral private key, `s` for a static
private key, and uppercase letters for the corresponding public keys. `OCE`
is the SCP11 off-card entity, `SD` is the card Security Domain, `C` is the
YubiHSM client, and `D` is the target YubiHSM.

| Protocol | First agreement | Second agreement | Authentication and forward secrecy |
| --- | --- | --- | --- |
| SCP11a | `ECDH(eOCE, ESD)` (`ShSee`) | `ECDH(sOCE, SSD)` (`ShSss`) | Mutual authentication. Both peers contribute one-use ephemeral keys, so erased ephemerals provide forward secrecy against later static-key compromise. |
| SCP11b | `ECDH(eOCE, ESD)` (`ShSee`) | `ECDH(eOCE, SSD)` (`ShSes`) | Authenticates the SD only. Both peers contribute one-use ephemeral keys, so it provides forward secrecy, but there is no long-term OCE credential. |
| SCP11c | `ECDH(eOCE, SSD)` (`ShSes`) | `ECDH(sOCE, SSD)` (`ShSss`) | Mutual authentication for offline scripts. The SD has no ephemeral key, so compromise of its static key reconstructs recorded sessions and prepared scripts may be replayed subject to SCP11c rules. |
| YubiHSM asymmetric authentication | `ECDH(eC, ED)` | `ECDH(sC, SD)` | Same two-ephemeral plus static-static agreement shape as SCP11a. It is a YubiHSM protocol, not an SCP11 wire profile. |

The protected session graph is useful for all four constructions:

- For SCP11a and YubiHSM authentication, it keeps the client ephemeral,
  `ShSee`, `ShSss`, and the KDF input outside host memory. If host memory was
  captured before a later client-static-key compromise, the capture does not
  contain `ShSee` with which to reconstruct an old session.
- For SCP11b, the ephemeral private key is the OCE's only private input and is
  used for both agreements. The protected graph keeps that input and both
  agreements in the source device. It does not add OCE authentication.
- For SCP11c, it protects the OCE ephemeral and both client-side agreements.
  It can protect an old session against later compromise of only the OCE static
  key, but it cannot supply the missing SD ephemeral or give SCP11c general
  forward secrecy.

The literal-prefix path keeps the reusable static agreement inside a device,
which is sufficient to prevent a saved host snapshot from establishing a later
SCP11a-like session by itself. It does not provide the stronger staged-compromise
property: a captured ephemeral agreement combined with a later-compromised
client static key reconstructs the old KDF input. Basic ECDH has the weakest
boundary because the static agreement also enters host memory.

For SCP11b there is no client static credential on which to perform the usual
literal prefix operation. Without protected session-key generation and ECDH,
both client agreements are therefore host-side. Anyone may initiate an SCP11b
session with the real card by design; the protocol authenticates only the card.

Card authentication additionally requires validation of the SD certificate or
static public key and verification of the receipt. Placement of the client
ephemeral key cannot compensate for an untrusted card key. Similarly, none of
these paths protects a session whose final working keys are captured from the
live client.
