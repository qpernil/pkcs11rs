# YubiHSM PKCS #11 permission mapping

Persistent native keys use **hardware permission granularity**. Creation maps
usage attributes and `CKA_ALLOWED_MECHANISMS` to native capability bits. Discovery
maps those bits back to usage attributes and the mechanisms the provider can
execute. The requested permission list is not saved in a companion object.

This is an intentional PKCS #11 behavioral deviation: an explicitly false usage
flag or an omitted mechanism can become available when it shares a native
capability with a requested operation. Applications must inspect the returned
attributes if they need to know the effective policy. Software session keys
retain their exact template restrictions. Native keys ignore stored permission
overrides, with a diagnostic. Public projections retain their own restrictions.
Discovery does not delete or rewrite records.

The HSM enforces native commands, authentication-key permissions and domains.
The provider additionally checks key type, usage, advertised mechanisms and any
public-object restrictions. A mechanism implemented by composing native
commands is not a separate hardware permission. Normalization never bypasses
the HSM's delegated-capability checks or retries creation with greater rights.

## Creation and rediscovery

1. With no `CKA_ALLOWED_MECHANISMS`, map true usage flags using the defaults below.
2. With a list, select the capabilities needed for the listed mechanisms and
   requested operations. Multiple entries contribute the union of their bits.
   Entries not applicable to the key's type/usage contribute no bits. An active
   operation with no native mapping fails with `CKR_TEMPLATE_INCONSISTENT`.
3. Preserve exportability independently: `CKA_EXTRACTABLE` enables
   `exportable-under-wrap` (`0x10`) on private/secret keys. A key's allowed
   mechanisms govern operations *with* that key, not exporting it as a target.
4. Create the object and read its actual native capabilities. Returned usage
   flags are derived from those capabilities, including shared-operation effects.
5. `CKA_ALLOWED_MECHANISMS` is computed from the key's effective usage, native
   command permissions and the slot's advertised mechanisms. It is not a copy
   of the input list. Unsupported firmware algorithms remain unavailable.

The reported list is sorted and duplicate-free. Adding provider support for
another mechanism using already-granted native primitives can expand that list
without rewriting the key; it is not a frozen copy of the creation template.

An explicitly empty list is distinct from an omitted list. For AES/HMAC it
produces a key with no operational capability bits and no usable mechanisms.
For native private keys it is rejected: the provider's intrinsic
`CKM_PKCS11RS_PROJECT_PUBLIC_KEY` operation cannot be disabled by native bits.
A linked public projection can store an explicitly empty list as a software
restriction. Native private keys do not create a restriction-only companion.

Creation emits a normalization diagnostic when requested usage differs from
native usage or an explicit mechanism list is mapped. Diagnostics contain no
key material, PINs, or passwords. Identity overrides and generation provenance
can still require metadata; this policy only removes permission-only records.

## Default usage-to-capability mapping

Capability numbers below are hexadecimal bit indices, not command opcodes.
Flags that do not apply to the native object type do not grant capabilities.

| Native key | Requested attribute | Native capability bits |
| --- | --- | --- |
| RSA asymmetric | `SIGN` | `05` sign-pkcs + `06` sign-pss |
| RSA asymmetric | `DECRYPT` | `09` decrypt-pkcs + `0a` decrypt-oaep |
| Weierstrass EC | `SIGN` | `07` sign-ecdsa |
| EC / Montgomery | `DERIVE` | `0b` derive-ecdh |
| Edwards | `SIGN` | `08` sign-eddsa |
| AES | `ENCRYPT` | `33` encrypt-ecb + `35` encrypt-cbc |
| AES | `DECRYPT` | `32` decrypt-ecb + `34` decrypt-cbc |
| AES | `SIGN`, `VERIFY`, or `DERIVE` | `33` encrypt-ecb |
| HMAC | `SIGN` / `VERIFY` | `16` sign-hmac / `17` verify-hmac |
| RSA or AES-CCM wrap key | `WRAP` / `UNWRAP` | `0c` export-wrapped / `0d` import-wrapped |
| AES-CCM wrap key | `ENCRYPT` / `DECRYPT` | `25` wrap-data / `26` unwrap-data |
| Native RSA public wrap key | `WRAP` | `0c` export-wrapped |
| ML-DSA extension | `SIGN` | `3a` |
| ML-KEM extension | `ENCAPSULATE` / `DECAPSULATE` | `3b` / `3c` |
| Hybrid KEM extension | `ENCAPSULATE` / `DECAPSULATE` | `3d` / `3e` |

In the reverse direction, either bit of a default pair is sufficient for the
corresponding broad usage flag. Individual mechanisms still require their own
bits. AES `33` also enables the broad `DECRYPT` flag because CTR/GCM decryption
uses the encryption primitive. It does **not** permit ECB/CBC decryption without
`32`/`34`. AES sign, verify and counter derivation all follow `33`.

## Mechanism-to-native-command mapping

The input list selects these capabilities instead of the default bundles.
All names in the mechanism column have the `CKM_` prefix unless stated otherwise.

| Mechanism family | Operation | Required bits |
| --- | --- | --- |
| `RSA_PKCS`, hash-specific RSA PKCS signatures | Sign | `05` |
| `RSA_PKCS_PSS`, hash-specific RSA PSS signatures | Sign | `06` |
| `RSA_PKCS` | Decrypt | `09` |
| `RSA_PKCS_OAEP` | Decrypt | `0a` |
| `RSA_PKCS`, `RSA_PKCS_OAEP` on RSA wrap keys | Unwrap | `0d` |
| `RSA_AES_KEY_WRAP`, `YUBICO_RSA_WRAP` | Wrap / unwrap | `0c` / `0d` |
| `ECDSA`, hash-specific ECDSA | Sign | `07` |
| `EDDSA` | Sign | `08` |
| `ECDH1_DERIVE`, `ECDH1_COFACTOR_DERIVE` | Derive | `0b` |
| `PKCS11RS_PREFIXED_ECDH_DERIVE` | Derive | `38` |
| `AES_ECB`, `AES_KEY_WRAP`, `AES_KEY_WRAP_KWP` | Encrypt / decrypt | `33` / `32` |
| `AES_CBC`, `AES_CBC_PAD` | Encrypt / decrypt | `35` / `34` |
| `AES_CTR`, `AES_GCM` | Encrypt or decrypt | `33` |
| `AES_CCM` | Encrypt or decrypt | Both `33` and `35` |
| `AES_CMAC`, `AES_CMAC_GENERAL`, `AES_GMAC` | Sign or verify | `33` |
| `SP800_108_COUNTER_KDF` | Derive | `33` |
| Matching SHA HMAC and HMAC-GENERAL | Sign / verify | `16` / `17` |
| `YUBICO_AES_CCM_WRAP` | Wrap / unwrap / encrypt / decrypt | `0c` / `0d` / `25` / `26` |
| ML-DSA, HashML-DSA and hash-specific variants | Sign | `3a` |
| `ML_KEM` | Decapsulate | `3c` |
| Construction-specific hybrid KEM mechanisms | Decapsulate | `3e` |

Protected derivation and post-quantum bits require the corresponding virtual
firmware extensions. See [capability layers](yubihsm-capability-layers.md) and
[post-quantum mechanisms](yubihsm-post-quantum.md). Raw private RSA `RSA_X_509`
has no native mapping here. AES key-wrap encryption/decryption composes ECB
primitives; this does not turn an ordinary native AES key into a native wrapping
object for `C_WrapKey`/`C_UnwrapKey`.

Examples of the resulting granularity:

- RSA `SHA256_RSA_PKCS_PSS` signing permits the supported PSS family, including
  raw PSS and other advertised hashes. It does not grant PKCS#1 v1.5 signing.
- AES CBC encryption alone permits CBC and CBC-PAD encryption, without granting
  ECB, CMAC, or counter derivation.
- AES GCM decryption requires ECB encryption. It consequently also permits
  ECB/CTR/GCM encryption, CTR decryption, CMAC/GMAC sign and verify, and counter
  derivation. CBC and CCM remain unavailable without their additional bits.
- HMAC signing permits the matching full and GENERAL mechanisms but does not
  grant HMAC verification, which has its own native bit.

## Independent public objects

Projected public permissions default to all implemented operations for the key
algorithm: RSA verification and encryption; EC, Edwards and ML-DSA verification;
and ML-KEM/hybrid KEM encapsulation. Montgomery public keys provide public material
but have no operation permission of their own. Slot mechanism advertisement still
bounds what applications can invoke. Public operations execute locally from public
material, including KEM encapsulation; no private signing, decryption, or
encapsulation capability is granted or required for them.

The public template takes precedence. Omitted permissions use these defaults;
explicit matching values need no attribute delta; explicit restrictions are
stored in the public aspect. `CKA_ALLOWED_MECHANISMS` restricts public mechanisms,
including an empty list. A list equal to the effective default is omitted when
saving a projection. Unsupported true usage requests fail with
`CKR_TEMPLATE_INCONSISTENT`. Public visibility and provenance remain independent
of the private object. Public imports on a YubiHSM slot use the same operation
defaults; their standalone record carries their software policy.

Native RSA public wrapping keys are separate native objects. Wrapping keys held
inside the HSM uses native commands and capabilities, including `export-wrapped`;
it is not a default operation of an ordinary public projection.

Deleting the private key converts a linked public object into a standalone stored
public record, preserving material, identity, and effective public restrictions.
Generated ordinary asymmetric keys imply both halves without a companion;
non-generated imports imply private-only. Metadata records deviations from
those presence defaults and from native ID/label values. See the
[object lifecycle](yubihsm-auth.md#pkcs-11-metadata).

## Stored metadata and validation

Missing public permission fields, including in older records, use the algorithm
defaults; explicitly stored public restrictions are honored.

Native primary permission flags and mechanism lists are ignored, including old
explicitly empty lists. The reader logs this fallback and does not write to the
HSM. An explicit metadata save removes those obsolete fields and deletes an
otherwise unnecessary companion. Public permission overrides remain effective;
identity, provenance and public presence are preserved. This is a deliberate
policy change for old native restriction records, not a claim that their former
software restrictions remain enforced.

A native wrapped-object import carries device capabilities; companions are not
part of that blob. Template-based imports that create native keys use the mapping
above. Standalone software/public records retain their own policy.

Native token-key usage flags and `CKA_ALLOWED_MECHANISMS` are read-only after
creation. `C_SetAttributeValue` supports ID/label overrides, not capability
changes or new software permission restrictions on an immutable native key.

Tests cover the forward bitmaps, effective reverse mechanisms, shared primitive
effects, independent public defaults and restrictions, empty-list handling,
obsolete native permissions, public survival after private deletion, and capacity
after logout/login. Capacity tests prove
that AES usage and mechanism normalization do not create companions. These run
against the virtual core with realistic object/page budgets; they do not modify
physical devices.

```sh
cargo test --locked --lib --all-features native_mapping -- --test-threads=1
cargo test --locked --lib --all-features yubihsm_capacity -- --test-threads=1 --nocapture
```

Yubico documents its own [PKCS #11 capability mappings](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-tools-pkcs11.html).
The native-granularity principle is similar; pkcs11rs additionally exposes
composed AES operations and virtual firmware extensions described above.
