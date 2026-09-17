# YubiHSM firmware and provider capabilities

The YubiHSM integration has three capability layers. Keeping them separate is
important because only the first layer describes commands implemented by the
device.

## 1. Firmware profile

A firmware profile defines the algorithms, commands, and capability bits that
a Virtual YubiHSM exposes on the YubiHSM protocol. All virtual transports use
the same `virtual-yubihsm-core` build, so USB, I2C, an embedded connector, and
the in-process qualification transport do not create different kinds of HSM.

There are three deployment profiles:

| Cargo feature | Firmware surface | Intended use |
| --- | --- | --- |
| `firmware-yubihsm2` | YubiHSM 2-compatible baseline, without virtual extension commands | Compatibility with a physical YubiHSM command surface |
| `firmware-secure-channel` | Baseline plus prefixed ECDH and protected native session objects | Client-side secure-channel credentials whose ephemeral private keys and intermediate agreements should remain in the device |
| `firmware-full` | Secure-channel profile plus extended curves, ML-DSA, ML-KEM, and direct RSA wrapping | Fully featured virtual deployments and interoperability work |

`firmware-full` is the default for the standalone Virtual YubiHSM binaries.
Select either of the other profiles with `--no-default-features`. The connector
does not embed a virtual device by default; selecting one of these three
features both enables the embedded runtime and chooses its firmware profile.

Two additional features, `test-firmware-prefixed-ecdh` and
`test-firmware-session-objects`, deliberately expose only one secure-channel
extension. They are CI fixtures used to prove fallback ordering. They are not
deployment profiles.

The resulting count is therefore three deployment profiles and two test-only
fixtures. The four transports do not multiply that count, and provider-side
composition below is selected from key location and policy rather than another
firmware build matrix.

The configurability serves three concrete purposes:

1. The baseline profile catches accidental dependencies on virtual-only
   commands and algorithms.
2. The secure-channel profile provides the smallest device extension that
   protects client-side SCP11 ephemeral and intermediate secrets.
3. The full profile supports post-quantum and extended-algorithm experiments
   without suggesting that physical YubiHSM firmware implements them.

Persisted object state is portable between profiles. On restore, the running
firmware profile filters algorithms, command-audit entries, algorithm-toggle
entries, and extension capability bits. A state file therefore cannot make a
restricted build advertise a command that was not compiled into it.

## 2. Provider-side objects and composition

`pkcs11rs` can provide behavior that is not a single YubiHSM firmware command.
This layer is independent of the firmware profile.

There are two distinct kinds of PKCS #11 session object:

- A **native session object** is held inside a Virtual YubiHSM secure session
  and addressed through the `SessionObject` command. Its private value and
  intermediate derivation results remain behind the virtual device boundary.
- A **provider session object** is held in the `pkcs11rs` process. It is used
  for software keys, readable derivation results, and operations that the
  selected device does not implement as native session objects.

The provider can also compose a PKCS #11 operation from narrower HSM
primitives. For example, a mode or KDF may use HSM AES operations while the
provider performs framing, counters, hashing, or other public-data processing.
The long-term key can remain in the HSM even though the complete operation is
not one firmware command. Other operations involving software or readable
session keys execute entirely in provider memory.

These facilities remain useful with a physical YubiHSM. They are therefore not
part of a virtual firmware profile and do not cause virtual extension commands
to be sent to a physical device.

## 3. PKCS #11 mechanisms

The mechanism list is the provider's API surface, not a copy of the firmware
command registry. The implementation selected for a mechanism depends on the
slot, the key's location, its capabilities, and `CKA_ALLOWED_MECHANISMS`:

```text
PKCS #11 mechanism
    -> native YubiHSM command
    -> virtual-firmware command
    -> protected composition around HSM primitives
    -> provider operation on a software or readable session object
```

Consequently, seeing a mechanism in `C_GetMechanismList` does not by itself
mean that a physical YubiHSM has a matching command. Per-key policy determines
whether that mechanism is usable for a particular object. Firmware discovery
uses device algorithms and object capability bits; it does not use invented
algorithm markers or speculative command probes.

For HSM-backed SCP11 client authentication, the provider chooses one path
before deriving either agreement:

1. native session-object generation and ECDH;
2. prefixed ECDH with a host-held ephemeral agreement;
3. basic ECDH with provider-side composition.

An operation failure in the selected path is not retried through a weaker path.
The two test-only firmware profiles exist specifically to verify these choices.
