# Experimental FIDO previewSign boundary

`previewSign` is an experimental WebAuthn/CTAP extension for registering a
signing seed with an ordinary FIDO credential and later asking the
authenticator to sign with a key derived from that seed. The implementation in
this repository includes protocol encoding, structural response validation,
canonical persistence records, and offline ARKG-P256 public-key derivation. It
does not yet expose a PKCS #11 slot, object, derivation mechanism, or signing
mechanism.

The protocol design is based on Yubico's
[previewSign extension specification](https://yubicolabs.github.io/webauthn-sign-extension/4/)
and
[Signing Extension Preview guide](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html).
Those documents describe an early-access interface, not a stable production
cryptographic API.

## Registration wire format

The extension identifier is `previewSign`. The
`authenticatorMakeCredential` extension input used by the ignored hardware
test is:

```text
{
  3: [-65539],  # supported signing algorithms
  4: 1          # require user presence
}
```

Its canonical CBOR bytes are:

```text
a2 03 81 3a 00 01 00 02 04 01
```

The request creates a resident parent credential for the dedicated RP ID
`preview-sign.pkcs11rs.invalid`. If a PIN is supplied, the request obtains a
make-credential permission token bound to that RP ID and sends
`pinUvAuthParam` and `pinUvAuthProtocol`. No PIN fields are sent for an
authenticator without a configured PIN.

A successful previewSign registration must contain both:

- signed extension output in the parent credential's authenticator data,
  selecting the algorithm as `{3: algorithm}`; and
- unsigned make-credential response key `6`, whose `previewSign` member is
  `{7: bstr .cbor nested-attestation-object}`.

The nested attestation object contains the generated signing-key handle, the
signing-seed COSE public key, and signed policy `{4: flags}`. The parent
credential ID and generated signing-key handle are distinct values: the former
selects the ordinary FIDO credential in a later assertion allow-list, while
the latter is passed to previewSign itself. For the current ARKG preview
algorithm, the seed COSE key is not the final derived P-256 verification key.

The parser requires definite maps, one complete CBOR item, the expected signed
and unsigned extension outputs, matching RP ID hashes and AAGUIDs, valid policy
bits, and a zero nested signature counter. It retains the exact response bytes,
including fields it does not interpret. It does not yet verify either
attestation signature or establish trust in an AAGUID.

## Canonical persistence records

`PreviewSignRegistration` encodes one canonical CBOR map:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.preview-sign.registration` |
| `2` | schema version `1` |
| `3` | RP ID |
| `4` | 32-byte client-data hash |
| `5` | exact successful make-credential CBOR response, without CTAP status |
| `6` | optional token serial routing hint |

The serial is only a routing hint. It is not treated as a cryptographic device
identity. The response supplies the parent credential ID, signing-key handle,
seed COSE public key, algorithm, policy, and AAGUID.

`PreviewSignDerivedKeyRecord` describes one offline-derived public key:

| Key | Value |
| --- | --- |
| `1` | schema string `pkcs11rs.preview-sign.derived-key` |
| `2` | schema version `1` |
| `3` | algorithm-tagged content reference to its registration |
| `4` | signing algorithm |
| `5` | derived verification key as exact COSE_Key bytes |
| `6` | optional exact algorithm-specific COSE_Sign_Args map |
| `7` | optional application label |

For the current ARKG preview, key `6` preserves the ticket and derivation
context needed by a later assertion. The storage provider treats both wrapper
types as opaque immutable CBOR blobs; it does not interpret or traverse their
reference.

## Offline ARKG-P256 derivation

`ArkgP256PublicSeed::from_cose` parses the generated seed COSE_Key and requires
the experimental ARKG public-key type, the preview ARKG-P256 algorithm, two
complete EC2 P-256 public points, and no trailing CBOR. The optional derived-key
algorithm is accepted only when it selects ESP256.

`PreviewSignRegistration::derive_arkg_p256` uses 32 bytes from the operating
system random source and accepts a public application context of at most 64
bytes. The deterministic `derive_arkg_p256_with_ikm` variant exists for test
vectors and callers that already manage confidential random input; it requires
at least 32 bytes. Neither API retains the input keying material.

The derivation returns:

- a normal uncompressed P-256 public point;
- an EC2 COSE_Key whose verification algorithm is ESP256 (`-9`);
- the 81-byte ARKG ticket (a 16-byte HMAC tag followed by an ephemeral
  uncompressed P-256 public point); and
- canonical COSE_Sign_Args containing the experimental split-ARKG signing
  algorithm (`-65539`), ticket, and context.

`ArkgP256DerivedKey::into_record` places the verification key and signing
arguments directly in a `PreviewSignDerivedKeyRecord`. The input keying material
does not need to be persisted: the ticket lets the authenticator reconstruct
the corresponding private-key contribution.

The implementation uses RustCrypto's native Rust P-256, SHA-256, HMAC, and HKDF
implementations. Its deterministic tests reproduce Yubico's ARKG-P256
regression vectors for the baseline derivation, independent input keying
material, and independent contexts. They also reproduce the COSE_Sign_Args
vector published in the current
[ARKG Internet-Draft](https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/).
A test-only authenticator mock holds the draft's private seed, authenticates and
opens generated tickets, reproduces the draft's exact derived private scalar,
and signs digests that are verified against the production-derived public key.
It also rejects modified tags, contexts, and malformed ephemeral points. No
private-seed operation is compiled into the production API.

## Hardware status

Positive hardware validation is deferred. The connected pre-release YubiKey
used during development did not advertise `previewSign` in
`authenticatorGetInfo`. A one-time forced make-credential probe returned CTAP
success but omitted both required previewSign outputs, so the device had
ignored the unknown extension and created only an ordinary persistent FIDO
credential. The probe must not be interpreted as previewSign support and is
not repeated by the reusable hardware test.

The ignored test now refuses to send a make-credential request unless GetInfo
advertises `previewSign`. It is additionally gated by the presence of
`PKCS11RS_FIDO2_TEST_PIN`; set that variable to an empty value only for an
authenticator with no PIN:

```sh
PKCS11RS_CCID_APPLICATIONS=fido2 \
PKCS11RS_FIDO2_TEST_PIN='' \
  cargo test creates_preview_sign_registration -- --ignored --nocapture
```

Open hardware questions include positive registration vectors from a
compatible pre-release device, attestation verification and trust policy,
end-to-end ARKG derivation interoperability, ticket lifetime and replay
properties, whether token serial is sufficient routing metadata, and the
eventual PKCS #11 mechanism and object model.
